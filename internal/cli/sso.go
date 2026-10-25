package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/yangxiang/bw/internal/generator"
)

// openBrowser mirrors platformUtilsService.launchUri.
func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
}

// ssoState returns a random 64-character alphanumeric string (state / PKCE verifier).
func ssoRandom() string {
	return generator.Password(generator.PasswordOptions{Length: 64, Uppercase: true, Lowercase: true, Number: true, MinNumber: 1, Ambiguous: true})
}

func splitState(s string) (base, identifier string) {
	base, identifier, _ = strings.Cut(s, "_identifier=")
	return base, identifier
}

const (
	ssoSuccessPage = "<html><head><title>Success | Bitwarden CLI</title></head><body>" +
		"<h1>Successfully authenticated with the Bitwarden CLI</h1>" +
		"<p>You may now close this tab and return to the terminal.</p></body></html>"
	ssoFailurePage = "<html><head><title>Failed | Bitwarden CLI</title></head><body>" +
		"<h1>Something went wrong logging into the Bitwarden CLI</h1>" +
		"<p>You may now close this tab and return to the terminal.</p></body></html>"
)

// ssoAuthorize runs the browser based SSO flow and returns the authorization
// code, PKCE verifier and redirect URI for the token request.
func ssoAuthorize(webVault, orgIdentifier string) (code, verifier, redirectURI string, err error) {
	state := ssoRandom()
	verifier = ssoRandom()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	var ln net.Listener
	for port := 8065; port <= 8070; port++ {
		if ln, err = net.Listen("tcp", "localhost:"+strconv.Itoa(port)); err == nil {
			redirectURI = "http://localhost:" + strconv.Itoa(port)
			break
		}
	}
	if ln == nil {
		return "", "", "", errors.New("no free port for the SSO callback (8065-8070)")
	}
	type result struct {
		code string
		ok   bool
	}
	done := make(chan result, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		c, got := q.Get("code"), q.Get("state")
		w.Header().Set("Content-Type", "text/html")
		gotBase, _ := splitState(got)
		wantBase, _ := splitState(state)
		if c != "" && got != "" && gotBase == wantBase {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, ssoSuccessPage)
			select {
			case done <- result{c, true}:
			default:
			}
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, ssoFailurePage)
		select {
		case done <- result{"", false}:
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	ssoURL := webVault + "/#/sso?clientId=cli&redirectUri=" + url.QueryEscape(redirectURI) +
		"&state=" + state + "&codeChallenge=" + challenge
	if orgIdentifier != "" {
		ssoURL += "&identifier=" + url.QueryEscape(orgIdentifier)
	}
	fmt.Fprintln(os.Stderr, "Opening your browser to log in with SSO. If it does not open, visit:\n"+ssoURL)
	openBrowser(ssoURL)

	select {
	case r := <-done:
		if !r.ok {
			return "", "", "", errors.New("Something went wrong. Try again.")
		}
		return r.code, verifier, redirectURI, nil
	case <-time.After(10 * time.Minute):
		return "", "", "", errors.New("Something went wrong. Try again.")
	}
}
