package state

import (
	"path/filepath"
	"testing"
)

func TestEnvironmentURLs(t *testing.T) {
	e := Environment{Base: "https://vault.example.com/ ", Identity: "https://id.example.com/"}
	if got := e.APIURL(); got != "https://vault.example.com/api" {
		t.Errorf("api %s", got)
	}
	if got := e.IdentityURL(); got != "https://id.example.com" {
		t.Errorf("identity %s", got)
	}
	if got := (Environment{}).WebVaultURL(); got != "https://vault.bitwarden.com" {
		t.Errorf("cloud web vault %s", got)
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "sub", "data.json")}
	s, err := Load(store)
	if err != nil || s.DeviceID == "" {
		t.Fatalf("load empty: %v %+v", err, s)
	}
	s.Environment.Base = "https://x"
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := Load(store)
	if err != nil || again.DeviceID != s.DeviceID || again.Environment.Base != "https://x" {
		t.Fatalf("reload: %v %+v", err, again)
	}
}
