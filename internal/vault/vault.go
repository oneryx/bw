package vault

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yangxiang/bw/internal/crypto"
)

// DecryptError is the placeholder the official clients show for undecryptable values.
const DecryptError = "[error: cannot decrypt]"

// SyncData is the subset of the /sync response the CLI uses.
type SyncData struct {
	Profile struct {
		ID            string                `json:"id"`
		Email         string                `json:"email"`
		Name          string                `json:"name"`
		Key           string                `json:"key"`
		PrivateKey    string                `json:"privateKey"`
		Organizations []ProfileOrganization `json:"organizations"`
		AccountKeys   *struct {
			PublicKeyEncryptionKeyPair *struct {
				PublicKey         string `json:"publicKey"`
				WrappedPrivateKey string `json:"wrappedPrivateKey"`
			} `json:"publicKeyEncryptionKeyPair"`
		} `json:"accountKeys"`
	} `json:"profile"`
	Folders     []Folder          `json:"folders"`
	Collections []Collection      `json:"collections"`
	Ciphers     []Cipher          `json:"ciphers"`
	Sends       []json.RawMessage `json:"sends"`
	Domains     *struct {
		EquivalentDomains       [][]string `json:"equivalentDomains"`
		GlobalEquivalentDomains []struct {
			Domains  []string `json:"domains"`
			Excluded bool     `json:"excluded"`
		} `json:"globalEquivalentDomains"`
	} `json:"domains"`
}

// Vault gives decrypted access to the synced data.
type Vault struct {
	Data    SyncData
	UserKey *crypto.SymmetricKey
	orgKeys map[string]*crypto.SymmetricKey
	private *rsa.PrivateKey
}

// Open parses the stored sync data and unwraps the organization keys.
func Open(raw json.RawMessage, userKey *crypto.SymmetricKey, encPrivateKey string) (*Vault, error) {
	v := &Vault{UserKey: userKey, orgKeys: map[string]*crypto.SymmetricKey{}}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &v.Data); err != nil {
			return nil, fmt.Errorf("corrupt vault cache, run `bw sync -f`: %w", err)
		}
	}
	if encPrivateKey == "" {
		encPrivateKey = v.Data.Profile.PrivateKey
	}
	if encPrivateKey != "" {
		if der, err := crypto.DecryptBytes(userKey, encPrivateKey); err == nil {
			v.private, _ = crypto.ParsePrivateKey(der)
		}
	}
	for _, o := range v.Data.Profile.Organizations {
		if o.Key == "" || v.private == nil {
			continue
		}
		if b, err := crypto.DecryptRSA(v.private, o.Key); err == nil {
			if k, err := crypto.NewSymmetricKey(b); err == nil {
				v.orgKeys[o.ID] = k
			}
		}
	}
	return v, nil
}

// PrivateKey returns the user's RSA private key, if available.
func (v *Vault) PrivateKey() *rsa.PrivateKey { return v.private }

// PublicKey returns the SPKI DER public key of the user.
func (v *Vault) PublicKey() ([]byte, error) {
	if v.private == nil {
		return nil, errors.New("private key unavailable")
	}
	return crypto.PublicKeyDER(v.private)
}

// OrgKey returns the key for an organization.
func (v *Vault) OrgKey(orgID string) (*crypto.SymmetricKey, error) {
	k, ok := v.orgKeys[orgID]
	if !ok {
		return nil, errors.New("No encryption key for this organization.")
	}
	return k, nil
}

// KeyFor returns the organization key or the user key.
func (v *Vault) KeyFor(orgID *string) (*crypto.SymmetricKey, error) {
	if orgID != nil && *orgID != "" {
		return v.OrgKey(*orgID)
	}
	return v.UserKey, nil
}

// CipherKey returns the key protecting the cipher's fields (per-item key if present).
func (v *Vault) CipherKey(c *Cipher) (*crypto.SymmetricKey, error) {
	k, err := v.KeyFor(c.OrganizationID)
	if err != nil {
		return nil, err
	}
	if c.Key != nil && *c.Key != "" {
		return crypto.DecryptKey(k, *c.Key)
	}
	return k, nil
}

// Decrypt returns a decrypted copy of the cipher.
func (v *Vault) Decrypt(c *Cipher) *Cipher {
	out := c.Clone()
	key, err := v.CipherKey(c)
	_ = out.strings(func(p *string) error {
		if *p == "" {
			return nil
		}
		if err != nil {
			*p = DecryptError
			return nil
		}
		s, derr := crypto.DecryptString(key, *p)
		if derr != nil {
			s = DecryptError
		}
		*p = s
		return nil
	})
	return out
}

// Ciphers returns all decrypted ciphers sorted like the official clients.
func (v *Vault) Ciphers() []*Cipher {
	out := make([]*Cipher, 0, len(v.Data.Ciphers))
	for i := range v.Data.Ciphers {
		out = append(out, v.Decrypt(&v.Data.Ciphers[i]))
	}
	SortCiphers(out)
	return out
}

// RawCipher returns the encrypted cipher with the given id.
func (v *Vault) RawCipher(id string) *Cipher {
	for i := range v.Data.Ciphers {
		if v.Data.Ciphers[i].ID == id {
			return &v.Data.Ciphers[i]
		}
	}
	return nil
}

func (v *Vault) decryptName(key *crypto.SymmetricKey, s string) string {
	if s == "" {
		return s
	}
	d, err := crypto.DecryptString(key, s)
	if err != nil {
		return DecryptError
	}
	return d
}

// Folders returns decrypted folders sorted by name.
func (v *Vault) Folders() []Folder {
	out := make([]Folder, 0, len(v.Data.Folders))
	for _, f := range v.Data.Folders {
		f.Name = v.decryptName(v.UserKey, f.Name)
		out = append(out, f)
	}
	sortBy(out, func(f Folder) string { return f.Name })
	return out
}

// Collections returns decrypted collections sorted by name.
func (v *Vault) Collections() []Collection {
	out := make([]Collection, 0, len(v.Data.Collections))
	for _, c := range v.Data.Collections {
		k, err := v.OrgKey(c.OrganizationID)
		if err != nil {
			continue
		}
		c.Name = v.decryptName(k, c.Name)
		out = append(out, c)
	}
	sortBy(out, func(c Collection) string { return c.Name })
	return out
}

// DecryptCollectionName decrypts a collection name with its organization key.
func (v *Vault) DecryptCollectionName(orgID, name string) string {
	k, err := v.OrgKey(orgID)
	if err != nil {
		return DecryptError
	}
	return v.decryptName(k, name)
}

// Organizations returns the user's organizations sorted by name.
func (v *Vault) Organizations() []ProfileOrganization {
	out := append([]ProfileOrganization(nil), v.Data.Profile.Organizations...)
	sortBy(out, func(o ProfileOrganization) string { return o.Name })
	return out
}

// EncryptCipher returns an encrypted copy of a decrypted cipher, using its
// per-item key when present. URI checksums are recomputed.
func (v *Vault) EncryptCipher(c *Cipher) (*Cipher, error) {
	out := c.Clone()
	if out.Login != nil {
		for i := range out.Login.URIs {
			u := &out.Login.URIs[i]
			u.URIChecksum = nil
			if u.URI != nil {
				sum := sha256.Sum256([]byte(*u.URI))
				s := base64.StdEncoding.EncodeToString(sum[:])
				u.URIChecksum = &s
			}
		}
	}
	key, err := v.CipherKey(out)
	if err != nil {
		return nil, err
	}
	err = out.strings(func(p *string) error {
		e, err := crypto.EncryptString(key, *p)
		*p = e
		return err
	})
	return out, err
}
