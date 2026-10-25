// Package vault holds the vault data model returned by bw.Client (items,
// folders, collections, organizations) and the official clients' search,
// sorting and URI matching rules.
package vault

import (
	"encoding/json"
)

// DecryptError is the placeholder the official clients show for undecryptable values.
const DecryptError = "[error: cannot decrypt]"

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

// UnmarshalJSON implements json.Unmarshaler.
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

// Cipher is a vault item. bw.Client returns it with all text fields
// decrypted; the server sends the same shape with EncStrings.
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
}

// Login is the login part of a TypeLogin item.
type Login struct {
	URIs                 []LoginURI        `json:"uris"`
	Username             *string           `json:"username"`
	Password             *string           `json:"password"`
	PasswordRevisionDate *string           `json:"passwordRevisionDate"`
	Totp                 *string           `json:"totp"`
	AutofillOnPageLoad   *bool             `json:"autofillOnPageLoad,omitempty"`
	Fido2Credentials     []Fido2Credential `json:"fido2Credentials,omitempty"`
}

// LoginURI is a login URI with its optional match strategy (Match* constants).
type LoginURI struct {
	URI         *string `json:"uri"`
	URIChecksum *string `json:"uriChecksum,omitempty"`
	Match       *int    `json:"match"`
}

// Fido2Credential is a passkey stored with a login.
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

// Card is the card part of a TypeCard item.
type Card struct {
	CardholderName *string `json:"cardholderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

// Identity is the identity part of a TypeIdentity item.
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

// SecureNote is the secure note part of a TypeSecureNote item.
type SecureNote struct {
	Type int `json:"type"`
}

// SSHKey is the key part of a TypeSSHKey item.
type SSHKey struct {
	PrivateKey     *string `json:"privateKey"`
	PublicKey      *string `json:"publicKey"`
	KeyFingerprint *string `json:"keyFingerprint"`
}

// Field is a custom field (Type 0 text, 1 hidden, 2 boolean, 3 linked).
type Field struct {
	Name     *string `json:"name"`
	Value    *string `json:"value"`
	Type     int     `json:"type"`
	LinkedID *int    `json:"linkedId"`
}

// PasswordHistory is a previous password of a login.
type PasswordHistory struct {
	Password     string `json:"password"`
	LastUsedDate string `json:"lastUsedDate"`
}

// Attachment describes a file attached to an item; download it with
// bw.Client.Attachment.
type Attachment struct {
	ID       string     `json:"id"`
	URL      *string    `json:"url,omitempty"`
	FileName string     `json:"fileName"`
	Key      *string    `json:"key"`
	Size     FlexString `json:"size"`
	SizeName string     `json:"sizeName"`
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

// SelectionReadOnly is a group/user access entry of an org collection.
type SelectionReadOnly struct {
	ID            string `json:"id"`
	ReadOnly      bool   `json:"readOnly"`
	HidePasswords bool   `json:"hidePasswords"`
	Manage        bool   `json:"manage"`
}
