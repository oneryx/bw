package importer

import (
	"os"
	"testing"

	"github.com/yangxiang/bw/internal/vault"
)

func parse(t *testing.T, format, file string, org bool) *Result {
	t.Helper()
	data, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{}
	if org {
		o.OrganizationID = "org"
	}
	r, err := Get(format, o).Parse(string(data))
	if err != nil || !r.Success {
		t.Fatalf("%s: %v %+v", format, err, r)
	}
	return r
}

func d(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func TestChrome(t *testing.T) {
	r := parse(t, "chromecsv", "chrome.csv", false)
	if len(r.Ciphers) != 3 {
		t.Fatalf("got %d", len(r.Ciphers))
	}
	if c := r.Ciphers[1]; c.Name != "com.example.app" || d(c.Login.URIs[0].URI) != "androidapp://com.example.app" {
		t.Fatalf("android entry: %s %s", c.Name, d(c.Login.URIs[0].URI))
	}
	if c := r.Ciphers[0]; d(c.Notes) != "a note" || d(c.Login.Password) != "pass1" {
		t.Fatalf("first: %+v", c)
	}
}

func TestFirefox(t *testing.T) {
	r := parse(t, "firefoxcsv", "firefox.csv", false)
	if len(r.Ciphers) != 2 || r.Ciphers[0].Name != "mozilla.org" || r.Ciphers[1].Name != "accounts.example.net" {
		t.Fatalf("got %d %v", len(r.Ciphers), r.Ciphers[0].Name)
	}
}

func TestKeePassXCSV(t *testing.T) {
	r := parse(t, "keepassxcsv", "keepassx.csv", false)
	if len(r.Ciphers) != 3 {
		t.Fatalf("got %d ciphers", len(r.Ciphers))
	}
	var names []string
	for _, f := range r.Folders {
		names = append(names, f.Name)
	}
	if len(names) != 3 || names[0] != "Email" || names[1] != "Root" || names[2] != "Email/Work" {
		t.Fatalf("folders %v", names)
	}
	if d(r.Ciphers[1].Login.URIs[0].URI) != "http://bank.com" {
		t.Fatalf("uri fixup: %s", d(r.Ciphers[1].Login.URIs[0].URI))
	}
}

func TestKeePass2XML(t *testing.T) {
	r := parse(t, "keepass2xml", "keepass2.xml", false)
	if len(r.Ciphers) != 3 || len(r.Folders) != 2 {
		t.Fatalf("got %d ciphers %d folders", len(r.Ciphers), len(r.Folders))
	}
	sub := r.Ciphers[1]
	if sub.Name != "Sub Entry" || d(sub.Login.Totp) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("sub entry %+v", sub)
	}
	var hidden, text int
	for _, f := range sub.Fields {
		if f.Type == 1 {
			hidden++
		} else {
			text++
		}
	}
	if hidden != 1 || text != 1 || d(sub.Notes) != "Long: line1\nline2\n" {
		t.Fatalf("fields %d/%d notes %q", hidden, text, d(sub.Notes))
	}
	if r.Folders[1].Name != "Sub Group/Deeper" || r.Ciphers[2].Name != "Deep & Entry" {
		t.Fatalf("nested: %v %s", r.Folders, r.Ciphers[2].Name)
	}
	if XMLRejectsEntities := parseXML(`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`); XMLRejectsEntities != nil {
		t.Fatal("external entities must be rejected")
	}
}

func TestLastPass(t *testing.T) {
	r := parse(t, "lastpasscsv", "lastpass.csv", false)
	if len(r.Ciphers) != 4 {
		t.Fatalf("got %d", len(r.Ciphers))
	}
	card := r.Ciphers[1]
	if card.Type != vault.TypeCard || d(card.Card.ExpMonth) != "1" || d(card.Card.ExpYear) != "2030" ||
		d(card.Card.Number) != "4111111111111111" || d(card.Notes) != "card notes\nmore notes" {
		t.Fatalf("card %+v %+v notes %q", card, card.Card, d(card.Notes))
	}
	id := r.Ciphers[3]
	if id.Type != vault.TypeIdentity || d(id.Identity.FirstName) != "Jim" || len(id.Fields) != 2 {
		t.Fatalf("identity %+v fields %d", id.Identity, len(id.Fields))
	}
	if !r.Ciphers[0].Favorite || len(r.Folders) != 1 || r.Folders[0].Name != "Folder/Sub" {
		t.Fatalf("folder/fav: %v %v", r.Ciphers[0].Favorite, r.Folders)
	}
}

func TestOrganizationMovesFoldersToCollections(t *testing.T) {
	r := parse(t, "keepassxcsv", "keepassx.csv", true)
	if len(r.Folders) != 0 || len(r.Collections) != 3 || len(r.CollectionRelationships) != 3 {
		t.Fatalf("folders %d collections %d rels %d", len(r.Folders), len(r.Collections), len(r.CollectionRelationships))
	}
}
