package bw

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/internal/state"
	"github.com/oneryx/bw/vault"
)

const (
	idGitHub  = "11111111-1111-4111-8111-111111111111"
	idGitLab  = "22222222-2222-4222-8222-222222222222"
	idNote    = "33333333-3333-4333-8333-333333333333"
	idDeleted = "44444444-4444-4444-8444-444444444444"
	idOrg     = "55555555-5555-4555-8555-555555555555"
	folderID  = "66666666-6666-4666-8666-666666666666"
	orgID     = "77777777-7777-4777-8777-777777777777"
)

func ptr[T any](v T) *T { return &v }

// testClient returns an unlocked client whose cached vault holds:
//
//	GitHub  login in folder Work, github.com, attachments a.txt and a.txt.bak
//	GitLab  login without folder, gitlab.com, no password
//	Note    secure note with notes
//	Old     deleted login (github.com)
//	OrgItem login owned by an organization whose key is unavailable, so its
//	        name decrypts to vault.DecryptError
func testClient(t *testing.T) *Client {
	t.Helper()
	key := crypto.GenerateSymmetricKey()
	enc := func(s string) *string {
		e, err := crypto.EncryptString(key, s)
		if err != nil {
			t.Fatal(err)
		}
		return &e
	}
	login := func(id, name, user, pw, uri string) vault.Cipher {
		c := vault.Cipher{ID: id, Type: vault.TypeLogin, Name: *enc(name), RevisionDate: "2026-01-01T00:00:00Z",
			Login: &vault.Login{Username: enc(user), URIs: []vault.LoginURI{{URI: enc(uri)}}}}
		if pw != "" {
			c.Login.Password = enc(pw)
		}
		return c
	}
	gh := login(idGitHub, "GitHub", "alice", "pw", "https://github.com/login")
	gh.FolderID = ptr(folderID)
	gh.Attachments = []vault.Attachment{{ID: "att1", FileName: *enc("a.txt")}, {ID: "att2", FileName: *enc("a.txt.bak")}}
	gl := login(idGitLab, "GitLab", "bob", "", "https://gitlab.com")
	note := vault.Cipher{ID: idNote, Type: vault.TypeSecureNote, Name: *enc("Note"), Notes: enc("secret"),
		SecureNote: &vault.SecureNote{}}
	old := login(idDeleted, "Old", "carol", "pw0", "https://github.com")
	old.DeletedDate = ptr("2026-01-02T00:00:00Z")
	org := login(idOrg, "OrgItem", "dave", "pw1", "https://example.com")
	org.OrganizationID = ptr(orgID)
	org.CollectionIDs = []string{"col"}

	data := map[string]any{
		"profile": map[string]any{},
		"folders": []vault.Folder{{ID: folderID, Name: *enc("Work")}},
		"ciphers": []vault.Cipher{gh, gl, note, old, org},
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	c.st.Account = &state.Account{
		UserID: "user", Email: "a@example.com",
		Tokens: state.Tokens{AccessToken: "token", ExpiresAt: time.Now().Add(time.Hour)},
		Vault:  raw,
	}
	c.userKey = key
	return c
}

func names(cs []*vault.Cipher) string {
	var n []string
	for _, c := range cs {
		n = append(n, c.Name)
	}
	return strings.Join(n, ",")
}

func TestItems(t *testing.T) {
	c := testClient(t)
	cases := []struct {
		f    ItemFilter
		want string
	}{
		{ItemFilter{}, "OrgItem,GitHub,GitLab,Note"}, // "[error: …]" sorts first
		{ItemFilter{Trash: true}, "Old"},
		{ItemFilter{Search: "git"}, "GitHub,GitLab"},
		{ItemFilter{Search: "github", Trash: true}, "Old"},
		{ItemFilter{FolderID: folderID}, "GitHub"},
		{ItemFilter{FolderID: "null"}, "OrgItem,GitLab,Note"},
		{ItemFilter{FolderID: "notnull"}, "GitHub"},
		{ItemFilter{FolderID: "null", Search: "git"}, "GitLab"},
		{ItemFilter{OrganizationID: orgID}, "OrgItem"},
		{ItemFilter{FolderID: folderID, OrganizationID: "notnull"}, "OrgItem,GitHub"},
		{ItemFilter{CollectionID: "col"}, "OrgItem"},
		{ItemFilter{CollectionID: "null"}, "GitHub,GitLab,Note"},
		{ItemFilter{URL: "https://www.github.com/x"}, "GitHub"},
		{ItemFilter{URL: "https://github.com", Trash: true}, ""},
		{ItemFilter{Archived: true}, ""},
	}
	for _, tc := range cases {
		items, err := c.Items(tc.f)
		if err != nil {
			t.Fatal(err)
		}
		got := strings.ReplaceAll(names(items), vault.DecryptError, "OrgItem")
		if got != tc.want {
			t.Errorf("%+v: got %q want %q", tc.f, got, tc.want)
		}
	}
	// Items of an organization without a key show the decrypt error placeholder.
	org, err := c.Item(idOrg)
	if err != nil || org.Name != vault.DecryptError {
		t.Errorf("org item: %v %q", err, org.Name)
	}
}

func TestFindItem(t *testing.T) {
	c := testClient(t)
	hasPassword := func(ci *vault.Cipher) bool { return ci.Login != nil && ci.Login.Password != nil }
	if it, err := c.FindItem(strings.ToUpper(idGitHub), nil); err != nil || it.Name != "GitHub" {
		t.Errorf("by id: %v %v", it, err)
	}
	if it, err := c.FindItem("gitlab", nil); err != nil || it.Name != "GitLab" {
		t.Errorf("by search: %v %v", it, err)
	}
	var mr *MultipleResultsError
	if _, err := c.FindItem("git", nil); !errors.As(err, &mr) || !slices.Equal(mr.IDs, []string{idGitHub, idGitLab}) {
		t.Errorf("ambiguous: %v", err)
	}
	if it, err := c.FindItem("git", hasPassword); err != nil || it.Name != "GitHub" {
		t.Errorf("filtered: %v %v", it, err)
	}
	// Like the official CLI, the filter only narrows ambiguous searches.
	if it, err := c.FindItem("gitlab", hasPassword); err != nil || it.Name != "GitLab" {
		t.Errorf("single result: %v %v", it, err)
	}
	if _, err := c.FindItem("old", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted items are not searched: %v", err)
	}
	if _, err := c.FindItem(idDeleted, nil); err != nil {
		t.Errorf("deleted items are found by id: %v", err)
	}
}

func TestFindAttachment(t *testing.T) {
	c := testClient(t)
	if _, att, err := c.FindAttachment("github", "A.TXT"); err != nil || att.ID != "att1" {
		t.Errorf("exact name: %v %v", att, err)
	}
	if _, att, err := c.FindAttachment("github", "att2"); err != nil || att.ID != "att2" {
		t.Errorf("by id: %v %v", att, err)
	}
	var mr *MultipleResultsError
	if _, _, err := c.FindAttachment("github", "a.t"); !errors.As(err, &mr) {
		t.Errorf("ambiguous: %v", err)
	}
	if _, _, err := c.FindAttachment("gitlab", "a.txt"); err == nil || err.Error() != "No attachments available for this item." {
		t.Errorf("no attachments: %v", err)
	}
}

func TestExportJSON(t *testing.T) {
	c := testClient(t)
	data, name, err := c.Export(context.Background(), ExportOptions{Format: "json"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "bitwarden_export_") || !strings.HasSuffix(name, ".json") {
		t.Errorf("file name %s", name)
	}
	var doc struct {
		Folders []struct{ Name string }
		Items   []struct{ Name string }
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Folders) != 1 || len(doc.Items) != 3 {
		t.Errorf("export: %s", data)
	}
	csv, _, err := c.Export(context.Background(), ExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := "folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp\r\n" +
		"Work,,login,GitHub,,,0,,https://github.com/login,alice,pw,\r\n" +
		",,login,GitLab,,,0,,https://gitlab.com,bob,,\r\n" +
		",,note,Note,secret,,0,,,,,"
	if string(csv) != want {
		t.Errorf("csv:\n%q\nwant\n%q", csv, want)
	}
	if _, _, err := c.Export(context.Background(), ExportOptions{Format: "xml"}); err == nil {
		t.Error("unsupported format accepted")
	}
}

func TestSessionAndLock(t *testing.T) {
	c := testClient(t)
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	c.userKey = nil
	if _, err := c.Items(ItemFilter{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
	if err := c.UnlockWithSession("bogus"); !errors.Is(err, ErrLocked) {
		t.Fatalf("bogus session: %v", err)
	}
	if err := c.UnlockWithSession(session); err != nil || !c.Unlocked() {
		t.Fatalf("session unlock: %v", err)
	}
	if err := c.Lock(); err != nil {
		t.Fatal(err)
	}
	if err := c.UnlockWithSession(session); !errors.Is(err, ErrLocked) {
		t.Fatalf("lock must invalidate the session: %v", err)
	}
}

func TestJWTClaims(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u1","email":"a@b.c"}`))
	if sub, email := jwtClaims("x." + payload + ".y"); sub != "u1" || email != "a@b.c" {
		t.Errorf("got %q %q", sub, email)
	}
	if sub, _ := jwtClaims("garbage"); sub != "" {
		t.Errorf("garbage: %q", sub)
	}
}
