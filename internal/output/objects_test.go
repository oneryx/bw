package output

import (
	"testing"

	"github.com/oneryx/bw/vault"
)

func s(v string) *string { return &v }

func TestItemOutputShape(t *testing.T) {
	c := &vault.Cipher{ID: "id", Type: vault.TypeLogin, Name: "n", RevisionDate: "2026-10-25T05:54:56.752301Z",
		Login: &vault.Login{Username: s("u"), URIs: []vault.LoginURI{{URI: s("https://x")}}}}
	got := JSON(ItemOutput(c), "")
	want := `{"type":1,"name":"n","favorite":false,"reprompt":0,"id":"id","collectionIds":[],"object":"item","fields":[],"login":{"uris":[{"uri":"https://x"}],"fido2Credentials":[],"username":"u","passwordRevisionDate":null},"passwordHistory":[],"revisionDate":"2026-10-25T05:54:56.752Z","attachments":[]}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
