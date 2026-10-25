// Package state holds the persisted configuration, tokens and the encrypted
// vault cache.
package state

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Environment holds the configured server URLs.
type Environment struct {
	Base          string `json:"base,omitempty"`
	WebVault      string `json:"webVault,omitempty"`
	API           string `json:"api,omitempty"`
	Identity      string `json:"identity,omitempty"`
	Icons         string `json:"icons,omitempty"`
	Notifications string `json:"notifications,omitempty"`
	Events        string `json:"events,omitempty"`
	KeyConnector  string `json:"keyConnector,omitempty"`
}

// KDF describes the account's key derivation settings.
type KDF struct {
	Type        int  `json:"type"` // 0 = PBKDF2-SHA256, 1 = Argon2id
	Iterations  int  `json:"iterations"`
	Memory      *int `json:"memory,omitempty"`      // MiB, Argon2id only
	Parallelism *int `json:"parallelism,omitempty"` // Argon2id only
}

// Tokens are the OAuth tokens returned by the identity server.
type Tokens struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt"`
	// API key credentials are kept so the access token can be renewed when
	// no refresh token is issued (client_credentials grant).
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
}

// Account is the logged in user.
type Account struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
	KDF    KDF    `json:"kdf"`
	Tokens Tokens `json:"tokens"`
	// User key protected by the master key (EncString).
	EncUserKey string `json:"encUserKey,omitempty"`
	// RSA private key protected by the user key (EncString).
	EncPrivateKey string `json:"encPrivateKey,omitempty"`
	// User key protected by the current session key; removed on lock.
	SessionUserKey string `json:"sessionUserKey,omitempty"`
	// Last sync response from the server, still encrypted.
	Vault    json.RawMessage `json:"vault,omitempty"`
	LastSync *time.Time      `json:"lastSync,omitempty"`
}

// State is the content of data.json.
type State struct {
	Environment Environment `json:"environment"`
	DeviceID    string      `json:"deviceId"`
	Account     *Account    `json:"account,omitempty"`

	store Store
}

// Store persists the serialized state. Load returns (nil, nil) when nothing
// has been saved yet.
type Store interface {
	Load() ([]byte, error)
	Save(data []byte) error
}

// Load reads the state from store, creating defaults (including a device id)
// if it is empty.
func Load(store Store) (*State, error) {
	s := &State{store: store}
	b, err := store.Load()
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, err
		}
	}
	if s.DeviceID == "" {
		s.DeviceID = uuid.NewString()
		if err := s.Save(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Save persists the state.
func (s *State) Save() error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return s.store.Save(b)
}

// FileStore keeps the state in a JSON file with owner-only permissions.
type FileStore struct{ Path string }

func (f FileStore) Load() ([]byte, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// Save writes the file atomically.
func (f FileStore) Save(b []byte) error {
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(f.Path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

const (
	cloudWebVault = "https://vault.bitwarden.com"
	cloudAPI      = "https://api.bitwarden.com"
	cloudIdentity = "https://identity.bitwarden.com"
	cloudIcons    = "https://icons.bitwarden.net"
	cloudNotif    = "https://notifications.bitwarden.com"
	cloudEvents   = "https://events.bitwarden.com"
)

func trimURL(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }

func (e Environment) pick(explicit, suffix, cloud string) string {
	if explicit != "" {
		return trimURL(explicit)
	}
	if e.Base != "" {
		return trimURL(e.Base) + suffix
	}
	return cloud
}

func (e Environment) WebVaultURL() string { return e.pick(e.WebVault, "", cloudWebVault) }
func (e Environment) APIURL() string      { return e.pick(e.API, "/api", cloudAPI) }
func (e Environment) IdentityURL() string { return e.pick(e.Identity, "/identity", cloudIdentity) }
func (e Environment) IconsURL() string    { return e.pick(e.Icons, "/icons", cloudIcons) }
func (e Environment) EventsURL() string   { return e.pick(e.Events, "/events", cloudEvents) }
func (e Environment) NotificationsURL() string {
	return e.pick(e.Notifications, "/notifications", cloudNotif)
}

// UpsertVaultObject inserts or replaces an object (by "id") in a list of the
// cached sync data, e.g. kind "ciphers", "folders", "collections" or "sends".
func (a *Account) UpsertVaultObject(kind string, obj json.RawMessage) error {
	return a.editVaultList(kind, func(list []json.RawMessage) ([]json.RawMessage, error) {
		id, err := objectID(obj)
		if err != nil {
			return nil, err
		}
		for i, it := range list {
			if oid, _ := objectID(it); oid == id {
				list[i] = obj
				return list, nil
			}
		}
		return append(list, obj), nil
	})
}

// DeleteVaultObject removes the object with id from a cached list.
func (a *Account) DeleteVaultObject(kind, id string) error {
	return a.editVaultList(kind, func(list []json.RawMessage) ([]json.RawMessage, error) {
		out := list[:0]
		for _, it := range list {
			if oid, _ := objectID(it); oid != id {
				out = append(out, it)
			}
		}
		return out, nil
	})
}

func objectID(obj json.RawMessage) (string, error) {
	var v struct {
		ID string `json:"id"`
	}
	err := json.Unmarshal(obj, &v)
	return v.ID, err
}

func (a *Account) editVaultList(kind string, f func([]json.RawMessage) ([]json.RawMessage, error)) error {
	top := map[string]json.RawMessage{}
	if len(a.Vault) > 0 {
		if err := json.Unmarshal(a.Vault, &top); err != nil {
			return err
		}
	}
	var list []json.RawMessage
	if raw, ok := top[kind]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &list); err != nil {
			return err
		}
	}
	list, err := f(list)
	if err != nil {
		return err
	}
	if list == nil {
		list = []json.RawMessage{}
	}
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	top[kind] = b
	a.Vault, err = json.Marshal(top)
	return err
}
