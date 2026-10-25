package vault

import (
	"strings"
	"testing"
)

func s(v string) *string { return &v }

func TestCollate(t *testing.T) {
	names := []string{"item10", "Item2", "apple", "Äpfel", "_x", "1st", "banana"}
	SortBy(names, func(n string) string { return n })
	got := strings.Join(names, ",")
	want := "_x,1st,Äpfel,apple,banana,Item2,item10" // ICU base collation: Ä sorts as a
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestSearchCiphers(t *testing.T) {
	cs := []*Cipher{
		{ID: "11111111-aaaa-4aaa-8aaa-111111111111", Name: "Email Work MyCompany", Type: TypeLogin, Notes: s("Archived"),
			Login: &Login{Username: s("alice@mycompany.com"), URIs: []LoginURI{{URI: s("https://mail.example.org/x")}}}},
		{ID: "22222222-bbbb-4bbb-8bbb-222222222222", Name: "Café", Type: TypeSecureNote},
		{ID: "33333333-cccc-4ccc-8ccc-333333333333", Name: "Visa", Type: TypeCard, Card: &Card{Brand: s("Visa"), Number: s("378282246310005")}},
	}
	cases := map[string]int{
		"email work": 1, "alice mycompany": 1, "alice archived": 1, "work email": 1, "mycomp mail": 1,
		"cafe": 1, "example.org": 1, "11111111": 1, "*10005": 1, "nomatch": 0, "a": 3,
	}
	for q, n := range cases {
		if got := len(SearchCiphers(cs, q)); got != n {
			t.Errorf("%q: got %d want %d", q, got, n)
		}
	}
}

func TestMatchesURL(t *testing.T) {
	c := &Cipher{Type: TypeLogin, Login: &Login{URIs: []LoginURI{{URI: s("https://accounts.google.com/login")}}}}
	if !c.MatchesURL("https://mail.google.com/", nil, MatchDomain) {
		t.Fatal("domain match expected")
	}
	if c.MatchesURL("https://script.google.com/", nil, MatchDomain) {
		t.Fatal("blacklisted host must not match")
	}
	if c.MatchesURL("https://google.com.evil.net/", nil, MatchDomain) {
		t.Fatal("different registrable domain must not match")
	}
	host := MatchHost
	c.Login.URIs[0].Match = &host
	if c.MatchesURL("https://mail.google.com/", nil, MatchDomain) {
		t.Fatal("host match must be exact")
	}
	re := MatchRegex
	c.Login.URIs = []LoginURI{{URI: s(`^https://.*\.example\.com/`), Match: &re}}
	if !c.MatchesURL("https://a.EXAMPLE.com/x", nil, MatchDomain) {
		t.Fatal("case-insensitive regex expected")
	}
}
