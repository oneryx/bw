package bw

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/vault"
)

// syncData is the subset of the /sync response the client uses.
type syncData struct {
	Profile struct {
		PrivateKey    string                      `json:"privateKey"`
		Organizations []vault.ProfileOrganization `json:"organizations"`
	} `json:"profile"`
	Folders     []vault.Folder     `json:"folders"`
	Collections []vault.Collection `json:"collections"`
	Ciphers     []vault.Cipher     `json:"ciphers"`
	Domains     *struct {
		EquivalentDomains       [][]string `json:"equivalentDomains"`
		GlobalEquivalentDomains []struct {
			Domains  []string `json:"domains"`
			Excluded bool     `json:"excluded"`
		} `json:"globalEquivalentDomains"`
	} `json:"domains"`
}

// openVault gives decrypted access to the cached sync data.
type openVault struct {
	data    syncData
	userKey *crypto.SymmetricKey
	orgKeys map[string]*crypto.SymmetricKey
	private *rsa.PrivateKey
}

// openSyncData parses the stored sync data and unwraps the organization keys.
func openSyncData(raw json.RawMessage, userKey *crypto.SymmetricKey, encPrivateKey string) (*openVault, error) {
	v := &openVault{userKey: userKey, orgKeys: map[string]*crypto.SymmetricKey{}}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &v.data); err != nil {
			return nil, fmt.Errorf("corrupt vault cache, run `bw sync -f`: %w", err)
		}
	}
	if encPrivateKey == "" {
		encPrivateKey = v.data.Profile.PrivateKey
	}
	if encPrivateKey != "" {
		if der, err := crypto.DecryptBytes(userKey, encPrivateKey); err == nil {
			v.private, _ = crypto.ParsePrivateKey(der)
		}
	}
	for _, o := range v.data.Profile.Organizations {
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

// orgKey returns the key of an organization, or ErrNoOrgKey.
func (v *openVault) orgKey(orgID string) (*crypto.SymmetricKey, error) {
	k, ok := v.orgKeys[orgID]
	if !ok {
		return nil, ErrNoOrgKey
	}
	return k, nil
}

// cipherKey returns the key protecting the cipher's fields (per-item key if present).
func (v *openVault) cipherKey(c *vault.Cipher) (*crypto.SymmetricKey, error) {
	k := v.userKey
	if c.OrganizationID != nil && *c.OrganizationID != "" {
		var err error
		if k, err = v.orgKey(*c.OrganizationID); err != nil {
			return nil, err
		}
	}
	if c.Key != nil && *c.Key != "" {
		return crypto.DecryptKey(k, *c.Key)
	}
	return k, nil
}

// decryptString decrypts an EncString, returning vault.DecryptError on failure.
func decryptString(key *crypto.SymmetricKey, s string) string {
	if s == "" {
		return s
	}
	if key != nil {
		if d, err := crypto.DecryptString(key, s); err == nil {
			return d
		}
	}
	return vault.DecryptError
}

// decrypt returns a decrypted copy of the cipher.
func (v *openVault) decrypt(c *vault.Cipher) *vault.Cipher {
	out := c.Clone()
	key, _ := v.cipherKey(c)
	encryptedStrings(out, func(p *string) { *p = decryptString(key, *p) })
	return out
}

// encryptedStrings visits every encrypted string field of the cipher (except
// the cipher key and attachment keys, which wrap keys rather than text).
func encryptedStrings(c *vault.Cipher, f func(*string)) {
	opt := func(ps ...*string) {
		for _, p := range ps {
			if p != nil {
				f(p)
			}
		}
	}
	f(&c.Name)
	opt(c.Notes)
	if l := c.Login; l != nil {
		opt(l.Username, l.Password, l.Totp)
		for _, u := range l.URIs {
			opt(u.URI, u.URIChecksum)
		}
		for _, fc := range l.Fido2Credentials {
			opt(fc.CredentialID, fc.KeyType, fc.KeyAlgorithm, fc.KeyCurve, fc.KeyValue,
				fc.RpID, fc.UserHandle, fc.UserName, fc.Counter, fc.RpName, fc.UserDisplayName, fc.Discoverable)
		}
	}
	if cd := c.Card; cd != nil {
		opt(cd.CardholderName, cd.Brand, cd.Number, cd.ExpMonth, cd.ExpYear, cd.Code)
	}
	if id := c.Identity; id != nil {
		opt(id.Title, id.FirstName, id.MiddleName, id.LastName, id.Address1, id.Address2,
			id.Address3, id.City, id.State, id.PostalCode, id.Country, id.Company, id.Email,
			id.Phone, id.SSN, id.Username, id.PassportNumber, id.LicenseNumber)
	}
	if k := c.SSHKey; k != nil {
		opt(k.PrivateKey, k.PublicKey, k.KeyFingerprint)
	}
	for _, fd := range c.Fields {
		opt(fd.Name, fd.Value)
	}
	for i := range c.PasswordHistory {
		f(&c.PasswordHistory[i].Password)
	}
	for i := range c.Attachments {
		f(&c.Attachments[i].FileName)
	}
}

// ciphers returns all decrypted ciphers sorted like the official clients.
func (v *openVault) ciphers() []*vault.Cipher {
	out := make([]*vault.Cipher, 0, len(v.data.Ciphers))
	for i := range v.data.Ciphers {
		out = append(out, v.decrypt(&v.data.Ciphers[i]))
	}
	vault.SortCiphers(out)
	return out
}

// rawCipher returns the encrypted cipher with the given id.
func (v *openVault) rawCipher(id string) *vault.Cipher {
	for i := range v.data.Ciphers {
		if v.data.Ciphers[i].ID == id {
			return &v.data.Ciphers[i]
		}
	}
	return nil
}

// folders returns decrypted folders sorted by name.
func (v *openVault) folders() []vault.Folder {
	out := make([]vault.Folder, 0, len(v.data.Folders))
	for _, f := range v.data.Folders {
		f.Name = decryptString(v.userKey, f.Name)
		out = append(out, f)
	}
	vault.SortBy(out, func(f vault.Folder) string { return f.Name })
	return out
}

// collections returns decrypted collections sorted by name, skipping those
// of organizations without a key.
func (v *openVault) collections() []vault.Collection {
	out := make([]vault.Collection, 0, len(v.data.Collections))
	for _, c := range v.data.Collections {
		k, err := v.orgKey(c.OrganizationID)
		if err != nil {
			continue
		}
		c.Name = decryptString(k, c.Name)
		out = append(out, c)
	}
	vault.SortBy(out, func(c vault.Collection) string { return c.Name })
	return out
}

// collectionName decrypts a collection name with its organization key.
func (v *openVault) collectionName(orgID, name string) string {
	k, _ := v.orgKey(orgID)
	return decryptString(k, name)
}

// organizations returns the user's organizations sorted by name.
func (v *openVault) organizations() []vault.ProfileOrganization {
	out := slices.Clone(v.data.Profile.Organizations)
	vault.SortBy(out, func(o vault.ProfileOrganization) string { return o.Name })
	return out
}

// findOrg returns the user's membership in an organization.
func (v *openVault) findOrg(orgID string) (*vault.ProfileOrganization, error) {
	for i, o := range v.data.Profile.Organizations {
		if o.ID == orgID {
			return &v.data.Profile.Organizations[i], nil
		}
	}
	return nil, ErrOrgNotFound
}

// equivalentDomains returns the domains equivalent to the target URL's domain
// (from the user's and the global equivalent domain rules).
func (v *openVault) equivalentDomains(target string) map[string]bool {
	set := map[string]bool{}
	d := vault.Domain(target)
	if d == "" || v.data.Domains == nil {
		return set
	}
	groups := slices.Clone(v.data.Domains.EquivalentDomains)
	for _, g := range v.data.Domains.GlobalEquivalentDomains {
		if !g.Excluded {
			groups = append(groups, g.Domains)
		}
	}
	for _, g := range groups {
		if slices.Contains(g, d) {
			for _, x := range g {
				set[x] = true
			}
		}
	}
	return set
}
