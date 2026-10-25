// Package bw is a client library for Vaultwarden (and Bitwarden-compatible)
// password manager servers. It powers the bw command line tool and can be
// embedded in other applications such as GUI clients.
//
// A Client keeps its configuration, tokens and the encrypted vault cache in a
// Store. Vault data stays encrypted at rest; it is decrypted in memory once
// the client is unlocked with the master password.
//
//	c, err := bw.New(bw.Options{Store: bw.FileStore("/path/to/data.json")})
//	if err != nil { ... }
//	if !c.LoggedIn() {
//		_ = c.SetServerConfig(bw.ServerConfig{Base: "https://vault.example.com"})
//		err = c.Login(ctx, bw.LoginOptions{Email: email, Password: password})
//		var tf *bw.TwoFactorRequiredError
//		if errors.As(err, &tf) {
//			err = tf.Submit(ctx, bw.TwoFactorAuthenticator, code)
//		}
//	} else {
//		err = c.Unlock(password)
//	}
//	items, err := c.Items(bw.ItemFilter{Search: "github"})
//
// All methods are safe for concurrent use.
package bw

import (
	"encoding/base64"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/oneryx/bw/internal/api"
	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/internal/state"
	"github.com/oneryx/bw/vault"
)

// Store persists the client state (configuration, tokens and the encrypted
// vault cache) as an opaque blob. Load returns (nil, nil) when nothing has
// been saved yet.
type Store interface {
	Load() ([]byte, error)
	Save(data []byte) error
}

// FileStore returns a Store keeping the state in a JSON file (written
// atomically with owner-only permissions).
func FileStore(path string) Store { return state.FileStore{Path: path} }

// MemoryStore returns a Store that keeps the state in memory only.
func MemoryStore() Store { return &memoryStore{} }

type memoryStore struct {
	mu   sync.Mutex
	data []byte
}

func (m *memoryStore) Load() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.data...), nil
}

func (m *memoryStore) Save(b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append([]byte(nil), b...)
	return nil
}

// Options configure a Client.
type Options struct {
	// Store holds the persisted state. Defaults to MemoryStore().
	Store Store
	// HTTPClient is used for all requests. Defaults to a client with a
	// five minute timeout.
	HTTPClient *http.Client
	// AllowInsecureHTTP permits plain http:// server URLs.
	AllowInsecureHTTP bool
	// DebugLog, when set, receives a trace of HTTP traffic. The trace
	// contains secrets.
	DebugLog io.Writer
}

// Client is a connection to a Vaultwarden account.
type Client struct {
	mu   sync.Mutex
	opts Options
	st   *state.State
	// userKey is the decrypted user key while the vault is unlocked.
	userKey *crypto.SymmetricKey
	// vault caches the opened vault; reset whenever the cache changes.
	vault *vault.Vault
}

// New loads the state from opts.Store and returns a locked client.
func New(opts Options) (*Client, error) {
	if opts.Store == nil {
		opts.Store = MemoryStore()
	}
	st, err := state.Load(opts.Store)
	if err != nil {
		return nil, err
	}
	return &Client{opts: opts, st: st}, nil
}

// api returns an API client bound to the persisted state.
func (c *Client) api() *api.Client {
	a := &api.Client{
		HTTP: c.opts.HTTPClient, Env: c.st.Environment, DeviceID: c.st.DeviceID,
		Persist: c.st.Save, AllowHTTP: c.opts.AllowInsecureHTTP, Debug: c.opts.DebugLog,
	}
	if c.st.Account != nil {
		a.Tokens = &c.st.Account.Tokens
	}
	return a
}

func (c *Client) httpClient() *http.Client {
	if c.opts.HTTPClient != nil {
		return c.opts.HTTPClient
	}
	return http.DefaultClient
}

// save persists the state and drops the opened vault.
func (c *Client) save() error {
	c.vault = nil
	return c.st.Save()
}

func (c *Client) requireAuthed() error {
	if c.st.Account == nil || c.st.Account.Tokens.AccessToken == "" {
		return ErrNotLoggedIn
	}
	return nil
}

// open returns the decrypted vault, or ErrLocked / ErrNotLoggedIn.
func (c *Client) open() (*vault.Vault, error) {
	if err := c.requireAuthed(); err != nil {
		return nil, err
	}
	if c.userKey == nil {
		return nil, ErrLocked
	}
	if c.vault == nil {
		v, err := vault.Open(c.st.Account.Vault, c.userKey, c.st.Account.EncPrivateKey)
		if err != nil {
			return nil, err
		}
		c.vault = v
	}
	return c.vault, nil
}

func (c *Client) userID() string {
	if c.st.Account == nil {
		return ""
	}
	return c.st.Account.UserID
}

// ServerConfig holds the server URLs. Base is the URL of a self-hosted
// installation; the other URLs override individual services. When all are
// empty the Bitwarden cloud is used.
type ServerConfig struct {
	Base          string
	WebVault      string
	API           string
	Identity      string
	Icons         string
	Notifications string
	Events        string
	KeyConnector  string
}

// ServerConfig returns the configured server URLs.
func (c *Client) ServerConfig() ServerConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ServerConfig(c.st.Environment)
}

// SetServerConfig changes the server URLs. It fails with ErrLogoutRequired
// while an account is logged in.
func (c *Client) SetServerConfig(cfg ServerConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.Account != nil {
		return ErrLogoutRequired
	}
	c.st.Environment = state.Environment(cfg)
	return c.save()
}

// WebVaultURL returns the effective web vault URL.
func (c *Client) WebVaultURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.Environment.WebVaultURL()
}

// Vault status values reported by Status.
const (
	StatusUnauthenticated = "unauthenticated"
	StatusLocked          = "locked"
	StatusUnlocked        = "unlocked"
)

// Status describes the client state.
type Status struct {
	ServerURL string
	LastSync  *time.Time
	UserEmail string
	UserID    string
	// Status is StatusUnauthenticated, StatusLocked or StatusUnlocked.
	Status string
}

// Status returns the server, account and lock state.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Status{ServerURL: c.st.Environment.Base, Status: StatusUnauthenticated}
	if acc := c.st.Account; acc != nil {
		s.UserEmail, s.UserID, s.LastSync = acc.Email, acc.UserID, acc.LastSync
		s.Status = StatusLocked
		if c.userKey != nil {
			s.Status = StatusUnlocked
		}
	}
	return s
}

// LoggedIn reports whether an account is logged in.
func (c *Client) LoggedIn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requireAuthed() == nil
}

// Unlocked reports whether the vault is unlocked.
func (c *Client) Unlocked() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requireAuthed() == nil && c.userKey != nil
}

// Email returns the email of the logged in account.
func (c *Client) Email() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.Account == nil {
		return ""
	}
	return c.st.Account.Email
}

// LastSync returns the time of the last successful sync, if any.
func (c *Client) LastSync() *time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.Account == nil {
		return nil
	}
	return c.st.Account.LastSync
}

// --- unlocking ---

func kdfParams(k state.KDF) crypto.KDFParams {
	p := crypto.KDFParams{Type: k.Type, Iterations: k.Iterations}
	if k.Memory != nil {
		p.Memory = *k.Memory
	}
	if k.Parallelism != nil {
		p.Parallelism = *k.Parallelism
	}
	return p
}

// Unlock derives the user key from the master password and keeps it in
// memory. Nothing is persisted; see NewSession.
func (c *Client) Unlock(password string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireAuthed(); err != nil {
		return err
	}
	acc := c.st.Account
	mk, err := crypto.MasterKey(password, acc.Email, kdfParams(acc.KDF))
	if err != nil {
		return err
	}
	uk, err := crypto.DecryptUserKey(mk, acc.EncUserKey)
	if err != nil {
		return ErrInvalidPassword
	}
	c.userKey, c.vault = uk, nil
	return nil
}

// NewSession stores the user key protected by a fresh random session key
// and returns that key (base64). Any previous session key becomes invalid.
// A later process can unlock with UnlockWithSession, which is how the CLI's
// BW_SESSION works. The vault must be unlocked.
func (c *Client) NewSession() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.open(); err != nil {
		return "", err
	}
	sk := crypto.GenerateSymmetricKey()
	enc, err := crypto.Encrypt(sk, c.userKey.Bytes())
	if err != nil {
		return "", err
	}
	c.st.Account.SessionUserKey = enc.String()
	if err := c.save(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sk.Bytes()), nil
}

// UnlockWithSession unlocks the vault with a session key from NewSession.
// It returns ErrLocked if the key is not valid.
func (c *Client) UnlockWithSession(sessionKey string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireAuthed(); err != nil {
		return err
	}
	if c.st.Account.SessionUserKey == "" || sessionKey == "" {
		return ErrLocked
	}
	raw, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		return ErrLocked
	}
	sk, err := crypto.NewSymmetricKey(raw)
	if err != nil {
		return ErrLocked
	}
	uk, err := crypto.DecryptKey(sk, c.st.Account.SessionUserKey)
	if err != nil {
		return ErrLocked
	}
	c.userKey, c.vault = uk, nil
	return nil
}

// Lock forgets the user key and invalidates the stored session key.
func (c *Client) Lock() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireAuthed(); err != nil {
		return err
	}
	c.userKey = nil
	c.st.Account.SessionUserKey = ""
	return c.save()
}

// Logout removes the account and its cached data.
func (c *Client) Logout() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireAuthed(); err != nil {
		return err
	}
	c.st.Account, c.userKey = nil, nil
	return c.save()
}
