// Package api is a minimal client for the Bitwarden/Vaultwarden HTTP API.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/oneryx/bw/internal/state"
)

// ClientVersion is reported to the server; Vaultwarden gates some features
// (e.g. cipher keys, archive) on the client version.
const ClientVersion = "2026.9.0"

// DeviceType returns the Bitwarden device type for the CLI on this OS.
func DeviceType() int {
	switch runtime.GOOS {
	case "windows":
		return 23
	case "darwin":
		return 24
	default:
		return 25
	}
}

func deviceName() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	default:
		return runtime.GOOS
	}
}

// Client talks to the configured server.
type Client struct {
	HTTP     *http.Client
	Env      state.Environment
	DeviceID string
	// Tokens points at the persisted tokens; refreshed in place.
	Tokens *state.Tokens
	// Persist is called after tokens were refreshed.
	Persist func() error
	// AllowHTTP permits plain http:// server URLs.
	AllowHTTP bool
	// Debug, when set, receives a trace of HTTP traffic (including secrets).
	Debug io.Writer
}

// Error is an API error response.
type Error struct {
	Status  int
	Message string
	// ErrorCode is the OAuth "error" value for identity errors (e.g. invalid_grant).
	ErrorCode string
	Body      []byte
}

func (e *Error) Error() string { return e.Message }

// errorBody covers both the API ErrorResponse and the identity error formats.
type errorBody struct {
	Message          string              `json:"message"`
	ValidationErrors map[string][]string `json:"validationErrors"`
	Error            string              `json:"error"`
	ErrorDescription string              `json:"error_description"`
	ErrorModel       *struct {
		Message string `json:"message"`
	} `json:"errorModel"`
}

func parseError(status int, body []byte) *Error {
	e := &Error{Status: status, Body: body}
	var b errorBody
	if json.Unmarshal(body, &b) == nil {
		e.ErrorCode = b.Error
		// Mirrors ErrorResponse.getSingleMessage(): first validation error wins.
		for _, msgs := range b.ValidationErrors {
			if len(msgs) > 0 {
				e.Message = msgs[0]
				break
			}
		}
		if e.Message == "" && b.ErrorModel != nil {
			e.Message = b.ErrorModel.Message
		}
		if e.Message == "" {
			e.Message = b.Message
		}
		if e.Message == "" {
			e.Message = b.ErrorDescription
		}
	}
	if e.Message == "" {
		switch status {
		case http.StatusNotFound:
			e.Message = "Not found."
		case http.StatusUnauthorized, http.StatusForbidden:
			e.Message = "Unauthorized."
		default:
			e.Message = fmt.Sprintf("Server returned %d %s", status, http.StatusText(status))
		}
	}
	return e
}

// ErrInsecureURL mirrors the official InsecureUrlNotAllowedError.
var ErrInsecureURL = errors.New("Insecure URL not allowed. All URLs must use HTTPS.")

// checkURL rejects non-HTTPS URLs unless AllowHTTP is set, like the official CLI.
func (c *Client) checkURL(u string) error {
	if strings.HasPrefix(u, "https://") || c.AllowHTTP {
		return nil
	}
	return ErrInsecureURL
}

// defaultHTTPClient is used when Client.HTTP is nil.
var defaultHTTPClient = &http.Client{Timeout: 5 * time.Minute}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTPClient
}

func (c *Client) setCommonHeaders(req *http.Request) {
	req.Header.Set("Bitwarden-Client-Name", "cli")
	req.Header.Set("Bitwarden-Client-Version", ClientVersion)
	req.Header.Set("Device-Type", strconv.Itoa(DeviceType()))
	req.Header.Set("User-Agent", "Bitwarden_CLI/"+ClientVersion+" (bw-go)")
}

// --- identity ---

// PreloginResponse holds the KDF settings for an email.
type PreloginResponse struct {
	Kdf            int  `json:"kdf"`
	KdfIterations  int  `json:"kdfIterations"`
	KdfMemory      *int `json:"kdfMemory"`
	KdfParallelism *int `json:"kdfParallelism"`
}

// Prelogin fetches the KDF settings for email.
func (c *Client) Prelogin(ctx context.Context, email string) (*PreloginResponse, error) {
	var out PreloginResponse
	err := c.send(ctx, http.MethodPost, c.Env.IdentityURL()+"/accounts/prelogin", map[string]string{"email": email}, &out, false)
	return &out, err
}

// TokenResponse is the identity /connect/token success response.
type TokenResponse struct {
	AccessToken           string `json:"access_token"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	Key                   string `json:"Key"`
	PrivateKey            string `json:"PrivateKey"`
	Kdf                   int    `json:"Kdf"`
	KdfIterations         int    `json:"KdfIterations"`
	KdfMemory             *int   `json:"KdfMemory"`
	KdfParallelism        *int   `json:"KdfParallelism"`
	ResetMasterPassword   bool   `json:"ResetMasterPassword"`
	ForcePasswordReset    bool   `json:"ForcePasswordReset"`
	UserDecryptionOptions *struct {
		HasMasterPassword bool `json:"HasMasterPassword"`
	} `json:"UserDecryptionOptions"`
}

// TwoFactorRequired is returned when the server asks for a second factor.
type TwoFactorRequired struct {
	// Providers maps provider type to its (possibly null) parameters.
	Providers map[string]json.RawMessage
}

func (t *TwoFactorRequired) Error() string { return "Two-step login required." }

// Token performs an identity token request with the given form values.
func (c *Client) Token(ctx context.Context, form url.Values) (*TokenResponse, error) {
	form.Set("deviceType", strconv.Itoa(DeviceType()))
	form.Set("deviceIdentifier", c.DeviceID)
	form.Set("deviceName", deviceName())
	if err := c.checkURL(c.Env.IdentityURL()); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Env.IdentityURL()+"/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	c.setCommonHeaders(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	if u := form.Get("username"); u != "" {
		req.Header.Set("Auth-Email", base64.RawURLEncoding.EncodeToString([]byte(u)))
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var tf struct {
			TwoFactorProviders2 map[string]json.RawMessage `json:"TwoFactorProviders2"`
		}
		if json.Unmarshal(body, &tf) == nil && len(tf.TwoFactorProviders2) > 0 {
			return nil, &TwoFactorRequired{Providers: tf.TwoFactorProviders2}
		}
		return nil, parseError(resp.StatusCode, body)
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// SetTokens stores the tokens from a token response.
func SetTokens(t *state.Tokens, tr *TokenResponse) {
	t.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		t.RefreshToken = tr.RefreshToken
	}
	t.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
}

// refresh renews the access token using the refresh token or API key.
func (c *Client) refresh(ctx context.Context) error {
	form := url.Values{}
	switch {
	case c.Tokens.RefreshToken != "":
		form.Set("grant_type", "refresh_token")
		form.Set("client_id", "cli")
		form.Set("refresh_token", c.Tokens.RefreshToken)
	case c.Tokens.ClientID != "":
		form.Set("grant_type", "client_credentials")
		form.Set("scope", "api")
		form.Set("client_id", c.Tokens.ClientID)
		form.Set("client_secret", c.Tokens.ClientSecret)
	default:
		return errors.New("Access token expired. Please log in again.")
	}
	tr, err := c.Token(ctx, form)
	if err != nil {
		return err
	}
	SetTokens(c.Tokens, tr)
	if c.Persist != nil {
		return c.Persist()
	}
	return nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	if c.Tokens == nil || c.Tokens.AccessToken == "" {
		return "", errors.New("You are not logged in.")
	}
	if time.Until(c.Tokens.ExpiresAt) < 5*time.Minute {
		if err := c.refresh(ctx); err != nil {
			return "", err
		}
	}
	return c.Tokens.AccessToken, nil
}

// --- generic requests ---

// send performs a JSON request against an absolute URL.
func (c *Client) send(ctx context.Context, method, u string, body, out any, auth bool) error {
	if err := c.checkURL(u); err != nil {
		return err
	}
	var rd io.Reader
	contentType := ""
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		c.debugf("request body: %s\n", buf)
		rd, contentType = bytes.NewReader(buf), "application/json; charset=utf-8"
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	c.setCommonHeaders(req)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if auth {
		tok, err := c.accessToken(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	c.debugf("%s %s -> %d\n%s\n", method, u, resp.StatusCode, data)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseError(resp.StatusCode, data)
	}
	if out != nil && len(data) > 0 {
		if raw, ok := out.(*json.RawMessage); ok {
			*raw = append((*raw)[:0], data...)
			return nil
		}
		return json.Unmarshal(data, out)
	}
	return nil
}

// Do performs an authenticated JSON request against the API base URL.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	return c.send(ctx, method, c.Env.APIURL()+path, body, out, true)
}

// Get performs an authenticated GET.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodGet, path, nil, out)
}

// Download fetches an absolute URL (attachment files); auth is added
// only for URLs on the API host.
func (c *Client) Download(ctx context.Context, u string) ([]byte, error) {
	if err := c.checkURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.setCommonHeaders(req)
	if strings.HasPrefix(u, c.Env.APIURL()) {
		if tok, err := c.accessToken(ctx); err == nil {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseError(resp.StatusCode, data)
	}
	return data, nil
}

// SendAnonymous performs an unauthenticated request against the API base URL.
func (c *Client) SendAnonymous(ctx context.Context, method, path string, body, out any) error {
	return c.send(ctx, method, c.Env.APIURL()+path, body, out, false)
}

// debugf traces HTTP traffic to Debug (may print secrets).
func (c *Client) debugf(format string, args ...any) {
	if c.Debug != nil {
		fmt.Fprintf(c.Debug, "[bwgo] "+format, args...)
	}
}
