// Package vault holds the vault data model, decryption/encryption of vault
// objects and the CLI response shapes.
package vault

import (
	"encoding/json"
	"strconv"
)

// Cipher types.
const (
	TypeLogin      = 1
	TypeSecureNote = 2
	TypeCard       = 3
	TypeIdentity   = 4
	TypeSSHKey     = 5
)

// FlexString accepts a JSON string or number (attachment sizes vary by server).
type FlexString string

func (f *FlexString) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = FlexString(s)
		return nil
	}
	if string(b) == "null" {
		*f = ""
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = FlexString(n.String())
	return nil
}

// Cipher is the server representation of a vault item. The same struct holds
// decrypted values after Decrypt; encrypted string fields are walked by strings().
type Cipher struct {
	ID                  string            `json:"id,omitempty"`
	OrganizationID      *string           `json:"organizationId"`
	FolderID            *string           `json:"folderId"`
	Type                int               `json:"type"`
	Name                string            `json:"name"`
	Notes               *string           `json:"notes"`
	Key                 *string           `json:"key"`
	Login               *Login            `json:"login,omitempty"`
	Card                *Card             `json:"card,omitempty"`
	Identity            *Identity         `json:"identity,omitempty"`
	SecureNote          *SecureNote       `json:"secureNote,omitempty"`
	SSHKey              *SSHKey           `json:"sshKey,omitempty"`
	Fields              []Field           `json:"fields"`
	PasswordHistory     []PasswordHistory `json:"passwordHistory"`
	Attachments         []Attachment      `json:"attachments,omitempty"`
	CollectionIDs       []string          `json:"collectionIds,omitempty"`
	Favorite            bool              `json:"favorite"`
	Reprompt            int               `json:"reprompt"`
	Edit                *bool             `json:"edit,omitempty"`
	ViewPassword        *bool             `json:"viewPassword,omitempty"`
	OrganizationUseTotp bool              `json:"organizationUseTotp,omitempty"`
	RevisionDate        string            `json:"revisionDate,omitempty"`
	CreationDate        *string           `json:"creationDate,omitempty"`
	DeletedDate         *string           `json:"deletedDate,omitempty"`
	ArchivedDate        *string           `json:"archivedDate,omitempty"`
	// Unknown server fields of newer item types are kept so edits don't drop them.
	BankAccount    json.RawMessage `json:"bankAccount,omitempty"`
	DriversLicense json.RawMessage `json:"driversLicense,omitempty"`
	Passport       json.RawMessage `json:"passport,omitempty"`
}

type Login struct {
	URIs                 []LoginURI        `json:"uris"`
	Username             *string           `json:"username"`
	Password             *string           `json:"password"`
	PasswordRevisionDate *string           `json:"passwordRevisionDate"`
	Totp                 *string           `json:"totp"`
	AutofillOnPageLoad   *bool             `json:"autofillOnPageLoad,omitempty"`
	Fido2Credentials     []Fido2Credential `json:"fido2Credentials,omitempty"`
}

type LoginURI struct {
	URI         *string `json:"uri"`
	URIChecksum *string `json:"uriChecksum,omitempty"`
	Match       *int    `json:"match"`
}

type Fido2Credential struct {
	CredentialID    *string `json:"credentialId"`
	KeyType         *string `json:"keyType"`
	KeyAlgorithm    *string `json:"keyAlgorithm"`
	KeyCurve        *string `json:"keyCurve"`
	KeyValue        *string `json:"keyValue"`
	RpID            *string `json:"rpId"`
	UserHandle      *string `json:"userHandle"`
	UserName        *string `json:"userName"`
	Counter         *string `json:"counter"`
	RpName          *string `json:"rpName"`
	UserDisplayName *string `json:"userDisplayName"`
	Discoverable    *string `json:"discoverable"`
	CreationDate    *string `json:"creationDate"`
}

type Card struct {
	CardholderName *string `json:"cardholderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

type Identity struct {
	Title          *string `json:"title"`
	FirstName      *string `json:"firstName"`
	MiddleName     *string `json:"middleName"`
	LastName       *string `json:"lastName"`
	Address1       *string `json:"address1"`
	Address2       *string `json:"address2"`
	Address3       *string `json:"address3"`
	City           *string `json:"city"`
	State          *string `json:"state"`
	PostalCode     *string `json:"postalCode"`
	Country        *string `json:"country"`
	Company        *string `json:"company"`
	Email          *string `json:"email"`
	Phone          *string `json:"phone"`
	SSN            *string `json:"ssn"`
	Username       *string `json:"username"`
	PassportNumber *string `json:"passportNumber"`
	LicenseNumber  *string `json:"licenseNumber"`
}

type SecureNote struct {
	Type int `json:"type"`
}

type SSHKey struct {
	PrivateKey     *string `json:"privateKey"`
	PublicKey      *string `json:"publicKey"`
	KeyFingerprint *string `json:"keyFingerprint"`
}

type Field struct {
	Name     *string `json:"name"`
	Value    *string `json:"value"`
	Type     int     `json:"type"`
	LinkedID *int    `json:"linkedId"`
}

type PasswordHistory struct {
	Password     string `json:"password"`
	LastUsedDate string `json:"lastUsedDate"`
}

type Attachment struct {
	ID       string     `json:"id"`
	URL      *string    `json:"url,omitempty"`
	FileName string     `json:"fileName"`
	Key      *string    `json:"key"`
	Size     FlexString `json:"size"`
	SizeName string     `json:"sizeName"`
}

// strings visits every encrypted string field of the cipher (except the
// cipher key and attachment keys, which wrap keys rather than text).
func (c *Cipher) strings(f func(*string) error) error {
	visit := func(ps ...*string) error {
		for _, p := range ps {
			if p != nil {
				if err := f(p); err != nil {
					return err
				}
			}
		}
		return nil
	}
	opt := func(pps ...**string) error {
		for _, pp := range pps {
			if *pp != nil {
				if err := f(*pp); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(&c.Name); err != nil {
		return err
	}
	if err := opt(&c.Notes); err != nil {
		return err
	}
	if l := c.Login; l != nil {
		if err := opt(&l.Username, &l.Password, &l.Totp); err != nil {
			return err
		}
		for i := range l.URIs {
			if err := opt(&l.URIs[i].URI, &l.URIs[i].URIChecksum); err != nil {
				return err
			}
		}
		for i := range l.Fido2Credentials {
			fc := &l.Fido2Credentials[i]
			if err := opt(&fc.CredentialID, &fc.KeyType, &fc.KeyAlgorithm, &fc.KeyCurve, &fc.KeyValue,
				&fc.RpID, &fc.UserHandle, &fc.UserName, &fc.Counter, &fc.RpName, &fc.UserDisplayName, &fc.Discoverable); err != nil {
				return err
			}
		}
	}
	if cd := c.Card; cd != nil {
		if err := opt(&cd.CardholderName, &cd.Brand, &cd.Number, &cd.ExpMonth, &cd.ExpYear, &cd.Code); err != nil {
			return err
		}
	}
	if id := c.Identity; id != nil {
		if err := opt(&id.Title, &id.FirstName, &id.MiddleName, &id.LastName, &id.Address1, &id.Address2,
			&id.Address3, &id.City, &id.State, &id.PostalCode, &id.Country, &id.Company, &id.Email,
			&id.Phone, &id.SSN, &id.Username, &id.PassportNumber, &id.LicenseNumber); err != nil {
			return err
		}
	}
	if k := c.SSHKey; k != nil {
		if err := opt(&k.PrivateKey, &k.PublicKey, &k.KeyFingerprint); err != nil {
			return err
		}
	}
	for i := range c.Fields {
		if err := opt(&c.Fields[i].Name, &c.Fields[i].Value); err != nil {
			return err
		}
	}
	for i := range c.PasswordHistory {
		if err := visit(&c.PasswordHistory[i].Password); err != nil {
			return err
		}
	}
	for i := range c.Attachments {
		if err := visit(&c.Attachments[i].FileName); err != nil {
			return err
		}
	}
	return nil
}

// Clone returns a deep copy via JSON round-trip.
func (c *Cipher) Clone() *Cipher {
	b, _ := json.Marshal(c)
	var out Cipher
	_ = json.Unmarshal(b, &out)
	return &out
}

// Folder is a vault folder.
type Folder struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RevisionDate string `json:"revisionDate,omitempty"`
}

// Collection is an organization collection.
type Collection struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organizationId"`
	Name           string  `json:"name"`
	ExternalID     *string `json:"externalId"`
	ReadOnly       bool    `json:"readOnly"`
	HidePasswords  bool    `json:"hidePasswords"`
	Manage         bool    `json:"manage"`
}

// ProfileOrganization is an organization membership from the sync profile.
type ProfileOrganization struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Key     string `json:"key"`
	Status  int    `json:"status"`
	Type    int    `json:"type"`
	Enabled bool   `json:"enabled"`
	UseTotp bool   `json:"useTotp"`
}

// Itoa is a small helper used by response builders.
func Itoa(i int) string { return strconv.Itoa(i) }
