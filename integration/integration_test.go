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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

	"github.com/yangxiang/bw/internal/testutil"
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
	t       *testing.T
	dir     string
	session string
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

func enc(v any) string {
	b, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(b)
}

func account(t *testing.T, email, password string) *cli {
	t.Helper()
	if err := testutil.Register(serverURL, email, password); err != nil {
		t.Fatal(err)
	}
	c := newCLI(t)
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

func TestItemsFoldersAndHistory(t *testing.T) {
	c := account(t, "items@example.com", "Items-Pass-1")
	var folder map[string]any
	c.json(&folder, "create", "folder", enc(map[string]string{"name": "Work"}))
	item := map[string]any{"type": 1, "name": "GitHub", "folderId": folder["id"], "notes": "n",
		"login": map[string]any{"username": "alice", "password": "pw1", "uris": []map[string]any{{"uri": "https://github.com/login"}},
			"totp": "JBSWY3DPEHPK3PXP"}}
	var created map[string]any
	c.json(&created, "create", "item", enc(item))
	id := created["id"].(string)

	if pw := c.ok("get", "password", "github.com"); pw != "pw1" {
		t.Fatalf("password %q", pw)
	}
	if u := c.ok("get", "username", id); u != "alice" {
		t.Fatalf("username %q", u)
	}
	if totp := c.ok("get", "totp", "GitHub"); len(totp) != 6 {
		t.Fatalf("totp %q", totp)
	}
	var list []map[string]any
	c.json(&list, "list", "items", "--folderid", folder["id"].(string))
	if len(list) != 1 {
		t.Fatalf("folder filter: %d", len(list))
	}
	c.json(&list, "list", "items", "--url", "https://github.com/settings")
	if len(list) != 1 {
		t.Fatalf("url filter: %d", len(list))
	}

	created["login"].(map[string]any)["password"] = "pw2"
	var edited map[string]any
	c.json(&edited, "edit", "item", id, enc(created))
	hist := edited["passwordHistory"].([]any)
	if len(hist) != 1 || hist[0].(map[string]any)["password"] != "pw1" {
		t.Fatalf("history %v", hist)
	}

	c.ok("delete", "item", id)
	c.json(&list, "list", "items", "--trash")
	if len(list) != 1 {
		t.Fatalf("trash: %d", len(list))
	}
	c.fail("You may not edit a deleted item.", "edit", "item", id, enc(created))
	c.ok("restore", "item", id)
	c.ok("delete", "item", id, "--permanent")
	c.fail("Not found.", "get", "item", id)
}

func TestAttachmentsAndSends(t *testing.T) {
	c := account(t, "files@example.com", "Files-Pass-1")
	var item map[string]any
	c.json(&item, "create", "item", enc(map[string]any{"type": 2, "name": "Doc", "secureNote": map[string]int{"type": 0}}))
	file := filepath.Join(t.TempDir(), "hello.txt")
	content := strings.Repeat("attachment-data-", 1000)
	_ = os.WriteFile(file, []byte(content), 0o600)
	c.ok("create", "attachment", "--file", file, "--itemid", item["id"].(string))
	if got := c.ok("get", "attachment", "hello.txt", "--itemid", item["id"].(string), "--raw"); got != content {
		t.Fatalf("attachment roundtrip mismatch (%d bytes)", len(got))
	}

	var send map[string]any
	c.json(&send, "send", "-n", "Secret", "--password", "spw", "top secret")
	other := newCLI(t)
	other.fail("Password required", "receive", send["accessUrl"].(string))
	if got := other.ok("receive", send["accessUrl"].(string), "--password", "spw"); got != "top secret" {
		t.Fatalf("receive %q", got)
	}
	other.fail("Invalid password", "receive", send["accessUrl"].(string), "--password", "nope")
	c.ok("send", "delete", send["id"].(string))
}

func TestExportImportRoundTrip(t *testing.T) {
	a := account(t, "exp@example.com", "Exp-Pass-1")
	a.ok("create", "folder", enc(map[string]string{"name": "F"}))
	a.ok("create", "item", enc(map[string]any{"type": 1, "name": "L", "login": map[string]any{"username": "u", "password": "p"}}))
	a.ok("create", "item", enc(map[string]any{"type": 3, "name": "C", "card": map[string]any{"number": "4111111111111111"}}))
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.json")
	protected := filepath.Join(dir, "protected.json")
	a.ok("export", "--format", "json", "--output", plain)
	a.ok("export", "--format", "encrypted_json", "--password", "filepw", "--output", protected)

	b := account(t, "imp@example.com", "Imp-Pass-1")
	b.ok("import", "bitwardenjson", plain)
	pwFile := filepath.Join(dir, "pw")
	_ = os.WriteFile(pwFile, []byte("filepw\n"), 0o600)
	b.ok("import", "bitwardenjson", protected, "--passwordfile", pwFile)
	var items []map[string]any
	b.json(&items, "list", "items")
	if len(items) != 4 {
		t.Fatalf("expected 4 imported items, got %d", len(items))
	}
	var folders []map[string]any
	b.json(&folders, "list", "folders")
	if len(folders) != 3 { // F twice (different exports) + No Folder
		t.Fatalf("folders %v", folders)
	}
}

func TestServe(t *testing.T) {
	c := account(t, "serve@example.com", "Serve-Pass-1")
	port := freePort()
	cmd := exec.Command(bwBinary, "serve", "--port", fmt.Sprint(port))
	cmd.Env = append(os.Environ(), "BITWARDENCLI_APPDATA_DIR="+c.dir, "SSL_CERT_FILE="+certFile, "BW_SESSION="+c.session)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	var resp *http.Response
	var err error
	for range 50 {
		if resp, err = http.Get(base + "/status"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	post := func(path string, body any) map[string]any {
		b, _ := json.Marshal(body)
		r, err := http.Post(base+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return out
	}
	if r := post("/object/folder", map[string]string{"name": "Via API"}); r["success"] != true {
		t.Fatalf("create folder: %v", r)
	}
	if r := post("/lock", nil); r["success"] != true {
		t.Fatalf("lock: %v", r)
	}
	if r := post("/object/folder", map[string]string{"name": "x"}); r["success"] != false || r["message"] != "Vault is locked." {
		t.Fatalf("expected locked: %v", r)
	}
	if r := post("/unlock", map[string]string{"password": "Serve-Pass-1"}); r["success"] != true {
		t.Fatalf("unlock: %v", r)
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/status", nil)
	req.Header.Set("Origin", "https://evil.example")
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != http.StatusForbidden {
		t.Fatalf("origin protection: %v %v", r, err)
	}
}
