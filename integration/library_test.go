//go:build integration

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/internal/testutil"
	"github.com/oneryx/bw/totp"
	"github.com/oneryx/bw/vault"
)

// TestLibrary drives bw.Client directly, the way a GUI client would.
func TestLibrary(t *testing.T) {
	ctx := context.Background()
	const email, password = "lib@example.com", "Lib-Pass-1"
	if err := testutil.Register(serverURL, email, password); err != nil {
		t.Fatal(err)
	}
	store := bw.MemoryStore()
	c, err := bw.New(bw.Options{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetServerConfig(bw.ServerConfig{Base: serverURL}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Items(bw.ItemFilter{}); !errors.Is(err, bw.ErrNotLoggedIn) {
		t.Fatalf("want ErrNotLoggedIn, got %v", err)
	}
	if err := c.Login(ctx, bw.LoginOptions{Email: email, Password: "wrong"}); err == nil {
		t.Fatal("login with a wrong password succeeded")
	}
	if err := c.Login(ctx, bw.LoginOptions{Email: email, Password: password}); err != nil {
		t.Fatal(err)
	}
	if s := c.Status(); s.Status != bw.StatusUnlocked || s.UserEmail != email {
		t.Fatalf("status %+v", s)
	}

	folder, err := c.CreateFolder(ctx, "Work")
	if err != nil {
		t.Fatal(err)
	}
	pw, user, uri := "pw1", "alice", "https://github.com/login"
	item, err := c.CreateItem(ctx, &vault.Cipher{
		Type: vault.TypeLogin, Name: "GitHub", FolderID: &folder.ID,
		Login: &vault.Login{Username: &user, Password: &pw, URIs: []vault.LoginURI{{URI: &uri}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	found, err := c.FindItem("github", nil)
	if err != nil || found.ID != item.ID || *found.Login.Password != "pw1" {
		t.Fatalf("find: %v %+v", err, found)
	}
	if items, err := c.Items(bw.ItemFilter{URL: "https://github.com/settings"}); err != nil || len(items) != 1 {
		t.Fatalf("url filter: %v %d", err, len(items))
	}
	pw2 := "pw2"
	found.Login.Password = &pw2
	updated, err := c.UpdateItem(ctx, found)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.PasswordHistory) != 1 || updated.PasswordHistory[0].Password != "pw1" {
		t.Fatalf("history %+v", updated.PasswordHistory)
	}
	if _, err := c.AddAttachment(ctx, item.ID, "a.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	withAtt, err := c.Item(item.ID)
	if err != nil || len(withAtt.Attachments) != 1 {
		t.Fatalf("attachment: %v", err)
	}
	if data, err := c.Attachment(ctx, item.ID, withAtt.Attachments[0].ID); err != nil || string(data) != "hello" {
		t.Fatalf("attachment content %q %v", data, err)
	}

	// A session key lets another client (e.g. another process) unlock.
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	other, err := bw.New(bw.Options{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if other.Unlocked() {
		t.Fatal("new client must start locked")
	}
	if err := other.UnlockWithSession(session); err != nil {
		t.Fatal(err)
	}
	if items, err := other.Items(bw.ItemFilter{}); err != nil || len(items) != 1 {
		t.Fatalf("other client items: %v %d", err, len(items))
	}

	text := "top secret"
	s, err := c.CreateSend(ctx, &vault.DecryptedSend{Send: vault.Send{
		Type: vault.SendTypeText, Name: "S", Text: &vault.SendText{Text: &text},
		DeletionDate: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}, "spw", nil)
	if err != nil {
		t.Fatal(err)
	}
	url := c.SendBaseURL() + s.AccessID + "/" + vault.URLKey(s.KeyMaterial)
	if _, err := c.ReceiveSend(ctx, url, bw.ReceiveOptions{}); !errors.Is(err, bw.ErrSendPasswordRequired) {
		t.Fatalf("want ErrSendPasswordRequired, got %v", err)
	}
	got, err := c.ReceiveSend(ctx, url, bw.ReceiveOptions{Password: "spw"})
	if err != nil || *got.Text.Text != text {
		t.Fatalf("receive: %v", err)
	}

	data, name, err := c.Export(ctx, bw.ExportOptions{Format: "json"})
	if err != nil || !strings.HasSuffix(name, ".json") || !strings.Contains(string(data), "GitHub") {
		t.Fatalf("export %s: %v", name, err)
	}

	if err := c.Lock(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Items(bw.ItemFilter{}); !errors.Is(err, bw.ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	if err := c.Unlock("wrong"); !errors.Is(err, bw.ErrInvalidPassword) {
		t.Fatalf("want ErrInvalidPassword, got %v", err)
	}
	if err := c.Unlock(password); err != nil {
		t.Fatal(err)
	}
	if err := c.Logout(); err != nil {
		t.Fatal(err)
	}
	if c.LoggedIn() {
		t.Fatal("still logged in")
	}
}

// TestLibraryTwoFactor completes an authenticator login through
// TwoFactorRequiredError.Submit, and through the CLI flags.
func TestLibraryTwoFactor(t *testing.T) {
	ctx := context.Background()
	const email, password = "lib2fa@example.com", "Lib-2fa-Pass-1"
	secret := enableTOTP(t, email, password)
	c, err := bw.New(bw.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetServerConfig(bw.ServerConfig{Base: serverURL}); err != nil {
		t.Fatal(err)
	}
	err = c.Login(ctx, bw.LoginOptions{Email: email, Password: password})
	var tf *bw.TwoFactorRequiredError
	if !errors.As(err, &tf) || len(tf.Providers) != 1 || tf.Providers[0] != bw.TwoFactorAuthenticator {
		t.Fatalf("want authenticator 2FA, got %v", err)
	}
	if err := tf.Submit(ctx, bw.TwoFactorAuthenticator, "000000"); err == nil {
		t.Fatal("wrong code accepted")
	}
	code := nextCode(t, secret)
	if err := tf.Submit(ctx, bw.TwoFactorAuthenticator, code); err != nil {
		t.Fatal(err)
	}
	if !c.Unlocked() {
		t.Fatal("vault should be unlocked after login")
	}

	// The CLI flags path, with a second account.
	const email2 = "cli2fa@example.com"
	secret2 := enableTOTP(t, email2, password)
	cl := newCLI(t)
	cl.fail("Code is required.", "login", email2, password)
	code2 := nextCode(t, secret2)
	if out := cl.ok("login", email2, password, "--method", "0", "--code", code2, "--raw"); len(out) != 88 {
		t.Fatalf("session %q", out)
	}
}

// enableTOTP registers an account with authenticator 2FA and returns the secret.
func enableTOTP(t *testing.T, email, password string) string {
	t.Helper()
	if err := testutil.Register(serverURL, email, password); err != nil {
		t.Fatal(err)
	}
	s, err := testutil.Login(serverURL, email, password)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.EnableTOTP(email, password)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

// nextCode returns the code of the next time step: enabling 2FA consumed the
// current one, and the server rejects reused codes.
func nextCode(t *testing.T, secret string) string {
	t.Helper()
	p, err := totp.Parse(secret)
	if err != nil {
		t.Fatal(err)
	}
	return p.Code(time.Now().Add(time.Duration(p.Period) * time.Second))
}
