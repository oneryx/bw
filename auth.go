package bw

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oneryx/bw/internal/api"
	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/internal/state"
)

// TwoFactorProvider identifies a two-step login method.
type TwoFactorProvider int

// Two-step login providers supported by this library.
const (
	TwoFactorAuthenticator TwoFactorProvider = 0
	TwoFactorEmail         TwoFactorProvider = 1
)

// String returns the provider name shown to users.
func (p TwoFactorProvider) String() string {
	switch p {
	case TwoFactorAuthenticator:
		return "Authenticator App"
	case TwoFactorEmail:
		return "Email"
	}
	return "Unknown (" + strconv.Itoa(int(p)) + ")"
}

// supportedProviders is the order providers are offered in.
var supportedProviders = []TwoFactorProvider{TwoFactorAuthenticator, TwoFactorEmail}

// TwoFactor is a two-step login code.
type TwoFactor struct {
	Provider TwoFactorProvider
	Code     string
}

// LoginOptions select the login method: Email and Password for a master
// password login, or ClientID and ClientSecret for a personal API key.
type LoginOptions struct {
	Email    string
	Password string

	ClientID     string
	ClientSecret string

	// TwoFactor optionally supplies a two-step login code up front.
	TwoFactor *TwoFactor
}

// TwoFactorRequiredError is returned by Login when the server asks for a
// second factor. Call Submit with a code from one of the Providers to
// complete the login.
type TwoFactorRequiredError struct {
	// Providers lists the methods enabled for the account that this library
	// supports. It may be empty.
	Providers []TwoFactorProvider

	c *Client
	p *pendingLogin
}

func (e *TwoFactorRequiredError) Error() string { return "Two-step login required." }

// SendEmail asks the server to email a login code (TwoFactorEmail). Only
// available for master password logins.
func (e *TwoFactorRequiredError) SendEmail(ctx context.Context) error {
	e.c.mu.Lock()
	defer e.c.mu.Unlock()
	if e.p.email == "" {
		return errors.New("Email codes are only available for master password logins.")
	}
	body := map[string]string{"email": e.p.email, "masterPasswordHash": e.p.pwHash, "deviceIdentifier": e.c.st.DeviceID}
	return e.c.api().SendAnonymous(ctx, http.MethodPost, "/two-factor/send-email-login", body, nil)
}

// Submit completes the login with a two-step login code. A rejected code
// returns ErrTwoFactorFailed (or the server's error).
func (e *TwoFactorRequiredError) Submit(ctx context.Context, provider TwoFactorProvider, code string) error {
	e.c.mu.Lock()
	defer e.c.mu.Unlock()
	e.p.setTwoFactor(provider, code)
	tr, err := e.c.api().Token(ctx, e.p.form)
	var tf *api.TwoFactorRequired
	if errors.As(err, &tf) {
		return ErrTwoFactorFailed
	}
	if err != nil {
		return e.p.mapError(err)
	}
	return e.c.finishLogin(ctx, e.p, tr)
}

// pendingLogin is a token request awaiting completion.
type pendingLogin struct {
	form      url.Values
	apiKey    bool
	email     string
	pwHash    string
	masterKey []byte
	kdf       state.KDF
	clientID  string
	secret    string
	webVault  string
}

func (p *pendingLogin) setTwoFactor(provider TwoFactorProvider, code string) {
	p.form.Set("twoFactorToken", code)
	p.form.Set("twoFactorProvider", strconv.Itoa(int(provider)))
	p.form.Set("twoFactorRemember", "0")
}

func (p *pendingLogin) mapError(err error) error {
	var ae *api.Error
	if errors.As(err, &ae) {
		if p.apiKey && ae.ErrorCode == "invalid_client" {
			return errors.New("client_id or client_secret is incorrect. Try again.")
		}
		if strings.HasPrefix(ae.Message, "Username or password is incorrect") {
			host := p.webVault
			if u, perr := url.Parse(p.webVault); perr == nil {
				host = u.Host
			}
			return fmt.Errorf("Invalid master password. Confirm your email is correct and your account was created on %s.", host)
		}
	}
	return err
}

// Login logs into an account and downloads the vault. After a master
// password login the vault is unlocked; after an API key login it stays
// locked until Unlock. If the account uses two-step login and
// opts.TwoFactor is nil, a *TwoFactorRequiredError is returned.
func (c *Client) Login(ctx context.Context, opts LoginOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.Account != nil {
		return fmt.Errorf("You are already logged in as %s.", c.st.Account.Email)
	}
	p := &pendingLogin{form: url.Values{}, webVault: c.st.Environment.WebVaultURL()}
	switch {
	case opts.ClientID != "" || opts.ClientSecret != "":
		if strings.TrimSpace(opts.ClientID) == "" {
			return errors.New("client_id is required.")
		}
		if opts.ClientSecret == "" {
			return errors.New("client_secret is required.")
		}
		if !strings.HasPrefix(opts.ClientID, "user") {
			return errors.New("Invalid API Key; Organization API Key currently not supported")
		}
		p.apiKey, p.clientID, p.secret = true, opts.ClientID, opts.ClientSecret
		p.form.Set("grant_type", "client_credentials")
		p.form.Set("scope", "api")
		p.form.Set("client_id", opts.ClientID)
		p.form.Set("client_secret", opts.ClientSecret)
	default:
		email := opts.Email
		if strings.TrimSpace(email) == "" {
			return errors.New("Email address is required.")
		}
		if !strings.Contains(email, "@") {
			return errors.New("Email address is invalid.")
		}
		if opts.Password == "" {
			return errors.New("Master password is required.")
		}
		pre, err := c.api().Prelogin(ctx, email)
		if err != nil {
			return err
		}
		p.kdf = state.KDF{Type: pre.Kdf, Iterations: pre.KdfIterations, Memory: pre.KdfMemory, Parallelism: pre.KdfParallelism}
		if p.masterKey, err = crypto.MasterKey(opts.Password, email, kdfParams(p.kdf)); err != nil {
			return err
		}
		p.email = email
		p.pwHash = crypto.MasterPasswordHash(p.masterKey, opts.Password)
		p.form.Set("grant_type", "password")
		p.form.Set("scope", "api offline_access")
		p.form.Set("client_id", "cli")
		p.form.Set("username", email)
		p.form.Set("password", p.pwHash)
	}
	if opts.TwoFactor != nil {
		p.setTwoFactor(opts.TwoFactor.Provider, opts.TwoFactor.Code)
	}

	tr, err := c.api().Token(ctx, p.form)
	var tf *api.TwoFactorRequired
	if errors.As(err, &tf) {
		if opts.TwoFactor != nil {
			return ErrTwoFactorFailed
		}
		e := &TwoFactorRequiredError{c: c, p: p}
		for _, prov := range supportedProviders {
			if _, ok := tf.Providers[strconv.Itoa(int(prov))]; ok {
				e.Providers = append(e.Providers, prov)
			}
		}
		return e
	}
	if err != nil {
		return p.mapError(err)
	}
	return c.finishLogin(ctx, p, tr)
}

// jwtClaims extracts the user id and email from an access token.
func jwtClaims(token string) (sub, email string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", ""
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", ""
	}
	var cl struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	_ = json.Unmarshal(b, &cl)
	return cl.Sub, cl.Email
}

// finishLogin stores the account from a successful token response and syncs.
func (c *Client) finishLogin(ctx context.Context, p *pendingLogin, tr *api.TokenResponse) error {
	if c.st.Account != nil {
		return fmt.Errorf("You are already logged in as %s.", c.st.Account.Email)
	}
	userID, email := jwtClaims(tr.AccessToken)
	kdf := p.kdf
	if p.apiKey {
		kdf = state.KDF{Type: tr.Kdf, Iterations: tr.KdfIterations, Memory: tr.KdfMemory, Parallelism: tr.KdfParallelism}
	} else {
		email = p.email
	}
	var uk *crypto.SymmetricKey
	if !p.apiKey {
		var err error
		if uk, err = crypto.DecryptUserKey(p.masterKey, tr.Key); err != nil {
			return errors.New("Legacy encryption is no longer supported. Please contact support to recover your account.")
		}
	}
	acc := &state.Account{
		UserID:        userID,
		Email:         strings.ToLower(strings.TrimSpace(email)),
		KDF:           kdf,
		EncUserKey:    tr.Key,
		EncPrivateKey: tr.PrivateKey,
	}
	api.SetTokens(&acc.Tokens, tr)
	if p.apiKey {
		acc.Tokens.ClientID, acc.Tokens.ClientSecret = p.clientID, p.secret
	}
	c.st.Account, c.userKey = acc, uk
	if err := c.save(); err != nil {
		return err
	}
	if err := c.sync(ctx, true); err != nil {
		return fmt.Errorf("Syncing failed: %w", err)
	}
	return nil
}

// Sync downloads the vault. Without force, the download is skipped when the
// server reports no changes since the last sync.
func (c *Client) Sync(ctx context.Context, force bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireAuthed(); err != nil {
		return err
	}
	return c.sync(ctx, force)
}

func (c *Client) sync(ctx context.Context, force bool) error {
	acc := c.st.Account
	cl := c.api()
	if !force && acc.LastSync != nil && len(acc.Vault) > 0 {
		var ms int64
		if err := cl.Get(ctx, "/accounts/revision-date", &ms); err == nil && ms > 0 {
			if !time.UnixMilli(ms).After(*acc.LastSync) {
				now := time.Now()
				acc.LastSync = &now
				return c.save()
			}
		}
	}
	var raw json.RawMessage
	if err := cl.Get(ctx, "/sync?excludeDomains=true", &raw); err != nil {
		return err
	}
	var profile struct {
		Profile struct {
			Key        string `json:"key"`
			PrivateKey string `json:"privateKey"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		return err
	}
	if profile.Profile.Key != "" {
		acc.EncUserKey = profile.Profile.Key
	}
	if profile.Profile.PrivateKey != "" {
		acc.EncPrivateKey = profile.Profile.PrivateKey
	}
	acc.Vault = raw
	now := time.Now()
	acc.LastSync = &now
	return c.save()
}
