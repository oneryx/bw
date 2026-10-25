package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oneryx/bw/internal/state"
)

func TestParseError(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{400, `{"message":"m","validationErrors":{"f":["first"]}}`, "first"},
		{400, `{"errorModel":{"message":"model"},"message":"m"}`, "model"},
		{400, `{"error":"invalid_grant","error_description":"desc"}`, "desc"},
		{404, ``, "Not found."},
		{401, `not json`, "Unauthorized."},
		{500, ``, "Server returned 500 Internal Server Error"},
	}
	for _, tc := range cases {
		if got := parseError(tc.status, []byte(tc.body)).Message; got != tc.want {
			t.Errorf("%d %s: got %q want %q", tc.status, tc.body, got, tc.want)
		}
	}
}

func TestGetRefreshesTokenAndRejectsHTTP(t *testing.T) {
	var refreshed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			refreshed = r.FormValue("grant_type") == "refresh_token"
			w.Write([]byte(`{"access_token":"new","expires_in":3600}`))
		case "/api/thing":
			if r.Header.Get("Authorization") != "Bearer new" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write([]byte(`{"v":1}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tokens := &state.Tokens{AccessToken: "old", RefreshToken: "r", ExpiresAt: time.Now()}
	c := &Client{Env: state.Environment{Base: srv.URL}, Tokens: tokens}
	var out struct{ V int }
	if err := c.Get(context.Background(), "/thing", &out); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("plain http must be refused, got %v", err)
	}
	c.AllowHTTP = true
	if err := c.Get(context.Background(), "/thing", &out); err != nil || out.V != 1 {
		t.Fatalf("get: %v %+v", err, out)
	}
	if !refreshed || tokens.AccessToken != "new" || tokens.RefreshToken != "r" {
		t.Fatalf("refresh: %v %+v", refreshed, tokens)
	}
}
