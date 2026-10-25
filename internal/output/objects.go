package output

import (
	"time"

	"github.com/oneryx/bw/vault"
)

// JSDate converts a server timestamp to JavaScript Date.toJSON() format
// (millisecond precision, UTC). Unparseable input is returned unchanged.
func JSDate(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return JSTime(t)
}

// JSTime formats a time like JavaScript's Date.toJSON().
func JSTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// JSDatePtr is JSDate for optional values.
func JSDatePtr(s *string) *string {
	if s == nil {
		return nil
	}
	d := JSDate(*s)
	return &d
}

// The object shapes below reproduce the official CLI JSON key order and its
// omission of undefined values.

type ItemResponse struct {
	Type            int                        `json:"type"`
	Name            string                     `json:"name"`
	Favorite        bool                       `json:"favorite"`
	Reprompt        int                        `json:"reprompt"`
	ID              string                     `json:"id"`
	CollectionIDs   []string                   `json:"collectionIds"`
	Object          string                     `json:"object"`
	OrganizationID  *string                    `json:"organizationId,omitempty"`
	FolderID        *string                    `json:"folderId,omitempty"`
	Notes           *string                    `json:"notes,omitempty"`
	Fields          []FieldResponse            `json:"fields"`
	Login           *LoginResponse             `json:"login,omitempty"`
	SecureNote      *vault.SecureNote          `json:"secureNote,omitempty"`
	Card            *CardResponse              `json:"card,omitempty"`
	Identity        *IdentityResponse          `json:"identity,omitempty"`
	SSHKey          *SSHKeyResponse            `json:"sshKey,omitempty"`
	PasswordHistory *[]PasswordHistoryResponse `json:"passwordHistory,omitempty"`
	CreationDate    *string                    `json:"creationDate,omitempty"`
	RevisionDate    string                     `json:"revisionDate"`
	DeletedDate     *string                    `json:"deletedDate,omitempty"`
	ArchivedDate    *string                    `json:"archivedDate,omitempty"`
	Attachments     []AttachmentResponse       `json:"attachments"`
}

type FieldResponse struct {
	Type     int     `json:"type"`
	Name     *string `json:"name,omitempty"`
	Value    *string `json:"value,omitempty"`
	LinkedID *int    `json:"linkedId,omitempty"`
}

type URIResponse struct {
	URI   *string `json:"uri,omitempty"`
	Match *int    `json:"match,omitempty"`
}

type LoginResponse struct {
	URIs                 []URIResponse   `json:"uris"`
	Fido2Credentials     []Fido2Response `json:"fido2Credentials"`
	Username             *string         `json:"username,omitempty"`
	Password             *string         `json:"password,omitempty"`
	Totp                 *string         `json:"totp,omitempty"`
	PasswordRevisionDate *string         `json:"passwordRevisionDate"`
}

type Fido2Response struct {
	CredentialID    string  `json:"credentialId"`
	KeyType         string  `json:"keyType"`
	KeyAlgorithm    string  `json:"keyAlgorithm"`
	KeyCurve        string  `json:"keyCurve"`
	KeyValue        string  `json:"keyValue"`
	RpID            string  `json:"rpId"`
	Counter         string  `json:"counter"`
	Discoverable    string  `json:"discoverable"`
	CreationDate    *string `json:"creationDate"`
	UserHandle      *string `json:"userHandle,omitempty"`
	UserName        *string `json:"userName,omitempty"`
	RpName          *string `json:"rpName,omitempty"`
	UserDisplayName *string `json:"userDisplayName,omitempty"`
}

type CardResponse struct {
	CardholderName *string `json:"cardholderName,omitempty"`
	Brand          *string `json:"brand,omitempty"`
	Number         *string `json:"number,omitempty"`
	ExpMonth       *string `json:"expMonth,omitempty"`
	ExpYear        *string `json:"expYear,omitempty"`
	Code           *string `json:"code,omitempty"`
}

type IdentityResponse struct {
	Title          *string `json:"title,omitempty"`
	FirstName      *string `json:"firstName,omitempty"`
	MiddleName     *string `json:"middleName,omitempty"`
	LastName       *string `json:"lastName,omitempty"`
	Address1       *string `json:"address1,omitempty"`
	Address2       *string `json:"address2,omitempty"`
	Address3       *string `json:"address3,omitempty"`
	City           *string `json:"city,omitempty"`
	State          *string `json:"state,omitempty"`
	PostalCode     *string `json:"postalCode,omitempty"`
	Country        *string `json:"country,omitempty"`
	Company        *string `json:"company,omitempty"`
	Email          *string `json:"email,omitempty"`
	Phone          *string `json:"phone,omitempty"`
	SSN            *string `json:"ssn,omitempty"`
	Username       *string `json:"username,omitempty"`
	PassportNumber *string `json:"passportNumber,omitempty"`
	LicenseNumber  *string `json:"licenseNumber,omitempty"`
}

type SSHKeyResponse struct {
	PrivateKey     string `json:"privateKey"`
	PublicKey      string `json:"publicKey"`
	KeyFingerprint string `json:"keyFingerprint"`
}

type PasswordHistoryResponse struct {
	LastUsedDate string `json:"lastUsedDate"`
	Password     string `json:"password"`
}

type AttachmentResponse struct {
	ID       string  `json:"id"`
	FileName string  `json:"fileName"`
	Size     string  `json:"size"`
	SizeName string  `json:"sizeName"`
	URL      *string `json:"url,omitempty"`
}

// Deref returns *s, or "" for nil.
func Deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

const fieldHidden = 1

// ItemOutput converts a decrypted cipher into the official CLI item shape.
func ItemOutput(c *vault.Cipher) ItemResponse {
	viewPassword := c.ViewPassword == nil || *c.ViewPassword
	r := ItemResponse{
		Type:           c.Type,
		Name:           c.Name,
		Favorite:       c.Favorite,
		Reprompt:       c.Reprompt,
		ID:             c.ID,
		CollectionIDs:  c.CollectionIDs,
		Object:         "item",
		OrganizationID: c.OrganizationID,
		FolderID:       c.FolderID,
		Notes:          c.Notes,
		Fields:         []FieldResponse{},
		CreationDate:   JSDatePtr(c.CreationDate),
		RevisionDate:   JSDate(c.RevisionDate),
		DeletedDate:    JSDatePtr(c.DeletedDate),
		ArchivedDate:   JSDatePtr(c.ArchivedDate),
		Attachments:    []AttachmentResponse{},
	}
	if r.CollectionIDs == nil {
		r.CollectionIDs = []string{}
	}
	for _, f := range c.Fields {
		fr := FieldResponse{Type: f.Type, Name: f.Name, Value: f.Value, LinkedID: f.LinkedID}
		if !viewPassword && f.Type == fieldHidden {
			fr.Value = nil
		}
		r.Fields = append(r.Fields, fr)
	}
	switch c.Type {
	case vault.TypeLogin:
		if l := c.Login; l != nil {
			lr := &LoginResponse{
				URIs:                 []URIResponse{},
				Fido2Credentials:     []Fido2Response{},
				Username:             l.Username,
				Password:             l.Password,
				Totp:                 l.Totp,
				PasswordRevisionDate: JSDatePtr(l.PasswordRevisionDate),
			}
			for _, u := range l.URIs {
				lr.URIs = append(lr.URIs, URIResponse{URI: u.URI, Match: u.Match})
			}
			for _, f := range l.Fido2Credentials {
				lr.Fido2Credentials = append(lr.Fido2Credentials, Fido2Response{
					CredentialID: Deref(f.CredentialID), KeyType: Deref(f.KeyType),
					KeyAlgorithm: Deref(f.KeyAlgorithm), KeyCurve: Deref(f.KeyCurve),
					KeyValue: Deref(f.KeyValue), RpID: Deref(f.RpID), Counter: Deref(f.Counter),
					Discoverable: Deref(f.Discoverable), CreationDate: JSDatePtr(f.CreationDate),
					UserHandle: f.UserHandle, UserName: f.UserName, RpName: f.RpName,
					UserDisplayName: f.UserDisplayName,
				})
			}
			if !viewPassword {
				lr.Password, lr.Totp = nil, nil
			}
			r.Login = lr
		}
	case vault.TypeSecureNote:
		sn := vault.SecureNote{}
		if c.SecureNote != nil {
			sn = *c.SecureNote
		}
		r.SecureNote = &sn
	case vault.TypeCard:
		if cd := c.Card; cd != nil {
			cr := CardResponse(*cd)
			r.Card = &cr
		}
	case vault.TypeIdentity:
		if id := c.Identity; id != nil {
			ir := IdentityResponse(*id)
			r.Identity = &ir
		}
	case vault.TypeSSHKey:
		if k := c.SSHKey; k != nil {
			r.SSHKey = &SSHKeyResponse{Deref(k.PrivateKey), Deref(k.PublicKey), Deref(k.KeyFingerprint)}
		}
	}
	if viewPassword {
		ph := []PasswordHistoryResponse{}
		for _, h := range c.PasswordHistory {
			ph = append(ph, PasswordHistoryResponse{LastUsedDate: JSDate(h.LastUsedDate), Password: h.Password})
		}
		r.PasswordHistory = &ph
	}
	for _, a := range c.Attachments {
		r.Attachments = append(r.Attachments, AttachmentResponse{
			ID: a.ID, FileName: a.FileName, Size: string(a.Size), SizeName: a.SizeName, URL: a.URL,
		})
	}
	return r
}

// FolderResponse is the CLI folder shape.
type FolderResponse struct {
	Name   string `json:"name"`
	Object string `json:"object"`
	ID     string `json:"id"`
}

func FolderOutput(f vault.Folder) FolderResponse {
	return FolderResponse{Name: f.Name, Object: "folder", ID: f.ID}
}

// CollectionResponse is the CLI collection shape. ExternalID is an interface
// so a nil value is omitted (synced collections) while a typed nil pointer
// prints null (collections fetched from the organization API).
type CollectionResponse struct {
	Object         string `json:"object"`
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	ExternalID     any    `json:"externalId,omitempty"`
}

// CollectionOutput formats a synced collection (null externalId omitted).
func CollectionOutput(c vault.Collection) CollectionResponse {
	r := CollectionResponse{Object: "collection", ID: c.ID, OrganizationID: c.OrganizationID, Name: c.Name}
	if c.ExternalID != nil {
		r.ExternalID = *c.ExternalID
	}
	return r
}

// APICollectionOutput formats a collection fetched from the organization API.
func APICollectionOutput(c vault.Collection) CollectionResponse {
	return CollectionResponse{Object: "collection", ID: c.ID, OrganizationID: c.OrganizationID, Name: c.Name, ExternalID: c.ExternalID}
}

// OrgCollectionResponse is the CLI org-collection shape.
type OrgCollectionResponse struct {
	Object         string                    `json:"object"`
	ID             string                    `json:"id"`
	OrganizationID string                    `json:"organizationId"`
	Name           string                    `json:"name"`
	ExternalID     *string                   `json:"externalId"`
	Groups         []vault.SelectionReadOnly `json:"groups"`
	Users          []vault.SelectionReadOnly `json:"users"`
}

// OrganizationResponse is the CLI organization shape.
type OrganizationResponse struct {
	Object  string `json:"object"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  int    `json:"status"`
	Type    int    `json:"type"`
	Enabled bool   `json:"enabled"`
}

func OrganizationOutput(o vault.ProfileOrganization) OrganizationResponse {
	return OrganizationResponse{Object: "organization", ID: o.ID, Name: o.Name, Status: o.Status, Type: o.Type, Enabled: o.Enabled}
}

// OrgMemberResponse is the CLI org-member shape.
type OrgMemberResponse struct {
	Object           string  `json:"object"`
	ID               string  `json:"id"`
	Email            string  `json:"email"`
	Name             *string `json:"name,omitempty"`
	Status           int     `json:"status"`
	Type             int     `json:"type"`
	TwoFactorEnabled bool    `json:"twoFactorEnabled"`
}
