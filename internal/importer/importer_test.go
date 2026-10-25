package importer

import (
	"os"
	"testing"
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

func TestOrganizationMovesFoldersToCollections(t *testing.T) {
	r := parse(t, "keepassxcsv", "keepassx.csv", true)
	if len(r.Folders) != 0 || len(r.Collections) != 3 || len(r.CollectionRelationships) != 3 {
		t.Fatalf("folders %d collections %d rels %d", len(r.Folders), len(r.Collections), len(r.CollectionRelationships))
	}
}
