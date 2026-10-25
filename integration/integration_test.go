//go:build integration

// Package integration runs the bw binary against a disposable Vaultwarden
// container. Run with:
//
//	go test -tags integration ./integration/
//
// Requires podman or docker (override with BW_TEST_RUNTIME) and pulls
// docker.io/vaultwarden/server (override with BW_TEST_IMAGE).
package integration

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/internal/testutil"
)

var (
	serverURL string
	certFile  string
	bwBinary  string
)

func runtimeBin() string {
	if r := os.Getenv("BW_TEST_RUNTIME"); r != "" {
		return r
	}
	for _, r := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(r); err == nil {
			return r
		}
	}
	return ""
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// writeCert creates a self-signed certificate for localhost/127.0.0.1.
func writeCert(dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o644)
}

func TestMain(m *testing.M) {
	rt := runtimeBin()
	if rt == "" {
		fmt.Println("skipping integration tests: no podman/docker")
		os.Exit(0)
	}
	tmp, err := os.MkdirTemp("", "bw-it-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)
	tlsDir := filepath.Join(tmp, "tls")
	_ = os.Mkdir(tlsDir, 0o755)
	if err := writeCert(tlsDir); err != nil {
		panic(err)
	}
	certFile = filepath.Join(tlsDir, "cert.pem")

	bwBinary = filepath.Join(tmp, "bw")
	if out, err := exec.Command("go", "build", "-o", bwBinary, "../cmd/bw").CombinedOutput(); err != nil {
		fmt.Println(string(out))
		panic(err)
	}

	image := os.Getenv("BW_TEST_IMAGE")
	if image == "" {
		image = "docker.io/vaultwarden/server:latest"
	}
	port := freePort()
	name := fmt.Sprintf("bw-it-%d", port)
	args := []string{"run", "-d", "--rm", "--name", name, "-p", fmt.Sprintf("127.0.0.1:%d:443", port),
		"-v", tlsDir + ":/ssl:ro,Z", "-e", "ROCKET_PORT=443", "-e", `ROCKET_TLS={certs="/ssl/cert.pem",key="/ssl/key.pem"}`,
		"-e", "SIGNUPS_ALLOWED=true", "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true",
		"-e", "LOGIN_RATELIMIT_MAX_BURST=1000", "-e", "LOGIN_RATELIMIT_SECONDS=1",
		"-e", fmt.Sprintf("DOMAIN=https://localhost:%d", port), image}
	if out, err := exec.Command(rt, args...).CombinedOutput(); err != nil {
		fmt.Println(string(out))
		panic(err)
	}
	defer exec.Command(rt, "rm", "-f", name).Run()

	serverURL = fmt.Sprintf("https://localhost:%d", port)
	os.Setenv("SSL_CERT_FILE", certFile)
	pool := x509.NewCertPool()
	pemData, _ := os.ReadFile(certFile)
	pool.AppendCertsFromPEM(pemData)
	hc := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	ready := false
	for range 60 {
		if resp, err := hc.Get(serverURL + "/alive"); err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(time.Second)
	}
	if !ready {
		panic("vaultwarden did not start")
	}
	code := m.Run()
	exec.Command(rt, "rm", "-f", name).Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

// cli is a bw instance with its own data directory and session.
type cli struct {
	t               *testing.T
	dir             string
	session         string
	email, password string
}

func newCLI(t *testing.T) *cli {
	c := &cli{t: t, dir: t.TempDir()}
	c.ok("config", "server", serverURL)
	return c
}

func (c *cli) run(stdin string, args ...string) (string, string, int) {
	c.t.Helper()
	cmd := exec.Command(bwBinary, args...)
	cmd.Env = append(os.Environ(), "BITWARDENCLI_APPDATA_DIR="+c.dir, "SSL_CERT_FILE="+certFile, "BW_SESSION="+c.session, "BW_NOINTERACTION=true")
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		c.t.Fatal(err)
	}
	return out.String(), errb.String(), code
}

func (c *cli) ok(args ...string) string {
	c.t.Helper()
	out, errs, code := c.run("", args...)
	if code != 0 {
		c.t.Fatalf("bw %v failed (%d): %s%s", args, code, out, errs)
	}
	return out
}

func (c *cli) fail(want string, args ...string) {
	c.t.Helper()
	out, errs, code := c.run("", args...)
	if code == 0 || !strings.Contains(out+errs, want) {
		c.t.Fatalf("bw %v: want failure containing %q, got %d %s%s", args, want, code, out, errs)
	}
}

func (c *cli) json(v any, args ...string) {
	c.t.Helper()
	if err := json.Unmarshal([]byte(c.ok(args...)), v); err != nil {
		c.t.Fatalf("bw %v: %v", args, err)
	}
}

func account(t *testing.T, email, password string) *cli {
	t.Helper()
	if err := testutil.Register(serverURL, email, password); err != nil {
		t.Fatal(err)
	}
	c := newCLI(t)
	c.email, c.password = email, password
	c.session = c.ok("login", email, password, "--raw")
	if len(c.session) != 88 {
		t.Fatalf("unexpected session %q", c.session)
	}
	return c
}

func TestAuthLifecycle(t *testing.T) {
	c := account(t, "auth@example.com", "Auth-Pass-1")
	if out := c.ok("unlock", "--check"); out != "Vault is unlocked!" {
		t.Fatalf("got %q", out)
	}
	c.fail("You are already logged in as auth@example.com.", "login", "auth@example.com", "x")
	var st map[string]any
	c.json(&st, "status")
	if st["status"] != "unlocked" || st["userEmail"] != "auth@example.com" {
		t.Fatalf("status %v", st)
	}
	c.ok("lock")
	c.fail("Vault is locked.", "list", "items")
	c.fail("Invalid master password.", "unlock", "wrong")
	c.session = c.ok("unlock", "Auth-Pass-1", "--raw")
	c.ok("list", "items")
	c.ok("logout")
	c.fail("You are not logged in.", "list", "items")
}

// seed fills the account's vault with testutil.Session.Seed data and syncs.
func (c *cli) seed() {
	c.t.Helper()
	s, err := testutil.Login(serverURL, c.email, c.password)
	if err != nil {
		c.t.Fatal(err)
	}
	if err := s.Seed(); err != nil {
		c.t.Fatal(err)
	}
	c.ok("sync")
}

// itemID returns the id of the item with the given name.
func (c *cli) itemID(name string) string {
	c.t.Helper()
	var it map[string]any
	c.json(&it, "get", "item", name)
	return it["id"].(string)
}

func TestReadItems(t *testing.T) {
	c := account(t, "items@example.com", "Items-Pass-1")
	c.seed()
	id := c.itemID("GitHub")

	if pw := c.ok("get", "password", "github.com"); pw != "pw2" {
		t.Fatalf("password %q", pw)
	}
	if u := c.ok("get", "username", id); u != "alice" {
		t.Fatalf("username %q", u)
	}
	if totp := c.ok("get", "totp", "GitHub"); len(totp) != 6 {
		t.Fatalf("totp %q", totp)
	}
	if n := c.ok("get", "notes", "Doc"); n != "secret note" {
		t.Fatalf("notes %q", n)
	}
	var item map[string]any
	c.json(&item, "get", "item", id)
	if hist := item["passwordHistory"].([]any); len(hist) != 1 || hist[0].(map[string]any)["password"] != "pw1" {
		t.Fatalf("history %v", hist)
	}
	var folder map[string]any
	c.json(&folder, "get", "folder", "Work")
	var list []map[string]any
	c.json(&list, "list", "items", "--folderid", folder["id"].(string))
	if len(list) != 1 {
		t.Fatalf("folder filter: %d", len(list))
	}
	c.json(&list, "list", "items", "--folderid", "null")
	if len(list) != 2 {
		t.Fatalf("no-folder filter: %d", len(list))
	}
	c.json(&list, "list", "items", "--url", "https://github.com/settings")
	if len(list) != 1 {
		t.Fatalf("url filter: %d", len(list))
	}
	c.fail("Not found.", "get", "item", "nothing-matches-this")
	for _, cmd := range []string{"create", "edit", "delete", "import"} {
		c.fail("Invalid command: "+cmd, cmd, "item", "x")
	}
}

func TestAttachments(t *testing.T) {
	const email, password = "files@example.com", "Files-Pass-1"
	c := account(t, email, password)
	c.seed()
	id := c.itemID("Doc")
	s, err := testutil.Login(serverURL, email, password)
	if err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("attachment-data-", 1000)
	if err := s.AddAttachment(id, "hello.txt", []byte(content)); err != nil {
		t.Fatal(err)
	}
	c.ok("sync")
	if got := c.ok("get", "attachment", "hello.txt", "--itemid", id, "--raw"); got != content {
		t.Fatalf("attachment mismatch (%d bytes)", len(got))
	}
	c.fail("Not a login.", "get", "password", "Doc")

	file := filepath.Join(t.TempDir(), "vault.zip")
	c.ok("export", "--format", "zip", "--output", file)
	zr, err := zip.OpenReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var got []string
	for _, f := range zr.File {
		got = append(got, f.Name)
	}
	if want := "data.json,attachments/,attachments/Doc/hello.txt"; strings.Join(got, ",") != want {
		t.Fatalf("zip entries %v, want %s", got, want)
	}
}

func TestExport(t *testing.T) {
	a := account(t, "exp@example.com", "Exp-Pass-1")
	a.seed()
	dir := t.TempDir()

	var plain struct {
		Folders []struct{ Name string } `json:"folders"`
		Items   []struct {
			Name  string `json:"name"`
			Login *struct {
				Password string `json:"password"`
			} `json:"login"`
		} `json:"items"`
	}
	file := filepath.Join(dir, "plain.json")
	a.ok("export", "--format", "json", "--output", file)
	readJSON(t, file, &plain)
	if len(plain.Folders) != 1 || len(plain.Items) != 3 {
		t.Fatalf("plain export: %+v", plain)
	}

	var protected struct {
		PasswordProtected bool   `json:"passwordProtected"`
		Salt              string `json:"salt"`
		KdfType           int    `json:"kdfType"`
		KdfIterations     int    `json:"kdfIterations"`
		Data              string `json:"data"`
	}
	file = filepath.Join(dir, "protected.json")
	a.ok("export", "--format", "encrypted_json", "--password", "filepw", "--output", file)
	readJSON(t, file, &protected)
	km, err := crypto.DeriveKDF([]byte("filepw"), []byte(protected.Salt), crypto.KDFParams{Type: protected.KdfType, Iterations: protected.KdfIterations})
	if err != nil {
		t.Fatal(err)
	}
	clear, err := crypto.DecryptString(crypto.StretchKey(km), protected.Data)
	if err != nil || !protected.PasswordProtected || !strings.Contains(clear, `"password": "pw2"`) {
		t.Fatalf("protected export: %v", err)
	}

	csv := a.ok("export", "--format", "csv", "--output", filepath.Join(dir, "x.csv"))
	if !strings.HasPrefix(csv, "Saved ") {
		t.Fatalf("csv export: %q", csv)
	}
}

func readJSON(t *testing.T, file string, v any) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}
