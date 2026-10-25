package vault

import (
	"slices"
	"time"
)

// CipherInput is the JSON accepted by `bw create item` / `bw edit item`
// (the official CipherExport shape). Pointers distinguish absent from set.
type CipherInput struct {
	Type            int               `json:"type"`
	FolderID        *string           `json:"folderId"`
	OrganizationID  *string           `json:"organizationId"`
	CollectionIDs   []string          `json:"collectionIds"`
	Name            *string           `json:"name"`
	Notes           *string           `json:"notes"`
	Favorite        bool              `json:"favorite"`
	Reprompt        *int              `json:"reprompt"`
	Fields          []Field           `json:"fields"`
	Login           *LoginInput       `json:"login"`
	SecureNote      *SecureNote       `json:"secureNote"`
	Card            *Card             `json:"card"`
	Identity        *Identity         `json:"identity"`
	SSHKey          *SSHKey           `json:"sshKey"`
	PasswordHistory []PasswordHistory `json:"passwordHistory"`
	CreationDate    *string           `json:"creationDate"`
	RevisionDate    *string           `json:"revisionDate"`
	DeletedDate     *string           `json:"deletedDate"`
	ArchivedDate    *string           `json:"archivedDate"`
}

// LoginInput is the login part of CipherInput.
type LoginInput struct {
	URIs             []LoginURI        `json:"uris"`
	Username         *string           `json:"username"`
	Password         *string           `json:"password"`
	Totp             *string           `json:"totp"`
	Fido2Credentials []Fido2Credential `json:"fido2Credentials"`
}

// ApplyInput merges the input into base (nil for a new item), mirroring
// CipherExport.toView.
func ApplyInput(in *CipherInput, base *Cipher) *Cipher {
	c := &Cipher{}
	if base != nil {
		c = base.Clone()
	}
	c.Type = in.Type
	c.FolderID = in.FolderID
	if c.OrganizationID == nil {
		c.OrganizationID = in.OrganizationID
	}
	if c.CollectionIDs != nil || in.CollectionIDs != nil {
		ids := append([]string(nil), c.CollectionIDs...)
		for _, id := range in.CollectionIDs {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		c.CollectionIDs = ids
	}
	c.Name = ""
	if in.Name != nil {
		c.Name = *in.Name
	}
	c.Notes = in.Notes
	c.Favorite = in.Favorite
	c.Reprompt = 0
	if in.Reprompt != nil {
		c.Reprompt = *in.Reprompt
	}
	if in.Fields != nil {
		c.Fields = in.Fields
	}
	switch in.Type {
	case TypeLogin:
		if in.Login != nil {
			c.Login = &Login{
				URIs:             in.Login.URIs,
				Username:         in.Login.Username,
				Password:         in.Login.Password,
				Totp:             in.Login.Totp,
				Fido2Credentials: in.Login.Fido2Credentials,
			}
			for i := range c.Login.URIs {
				c.Login.URIs[i].URIChecksum = nil
			}
		}
	case TypeSecureNote:
		if in.SecureNote != nil {
			c.SecureNote = in.SecureNote
		}
	case TypeCard:
		if in.Card != nil {
			c.Card = in.Card
		}
	case TypeIdentity:
		if in.Identity != nil {
			c.Identity = in.Identity
		}
	case TypeSSHKey:
		if in.SSHKey != nil {
			c.SSHKey = in.SSHKey
		}
	}
	if in.PasswordHistory != nil {
		c.PasswordHistory = in.PasswordHistory
	}
	if in.CreationDate != nil {
		c.CreationDate = in.CreationDate
	}
	if in.RevisionDate != nil {
		c.RevisionDate = *in.RevisionDate
	}
	if in.DeletedDate != nil {
		c.DeletedDate = in.DeletedDate
	}
	if in.ArchivedDate != nil {
		c.ArchivedDate = in.ArchivedDate
	}
	// Only the sub-object of the item's type is kept.
	if c.Type != TypeLogin {
		c.Login = nil
	}
	if c.Type != TypeSecureNote {
		c.SecureNote = nil
	} else if c.SecureNote == nil {
		c.SecureNote = &SecureNote{}
	}
	if c.Type != TypeCard {
		c.Card = nil
	}
	if c.Type != TypeIdentity {
		c.Identity = nil
	}
	if c.Type != TypeSSHKey {
		c.SSHKey = nil
	}
	return c
}

const maxPasswordHistory = 5

func nowJS() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000Z") }

// UpdatePasswordHistory mirrors the SDK's CipherView::update_password_history.
func UpdatePasswordHistory(c, original *Cipher) {
	var changes []PasswordHistory
	if c.Login != nil && original.Login != nil {
		orig, cur := deref(original.Login.Password), deref(c.Login.Password)
		switch {
		case orig == "":
			if cur != "" {
				now := nowJS()
				c.Login.PasswordRevisionDate = &now
			}
		case orig == cur:
			c.Login.PasswordRevisionDate = original.Login.PasswordRevisionDate
		default:
			now := nowJS()
			c.Login.PasswordRevisionDate = &now
			changes = append(changes, PasswordHistory{Password: orig, LastUsedDate: now})
		}
	}
	hidden := func(fs []Field) map[string]string {
		m := map[string]string{}
		for _, f := range fs {
			if f.Type == 1 && deref(f.Name) != "" && deref(f.Value) != "" {
				m[*f.Name] = *f.Value
			}
		}
		return m
	}
	cur := hidden(c.Fields)
	for _, f := range original.Fields {
		if f.Type != 1 || deref(f.Name) == "" || deref(f.Value) == "" {
			continue
		}
		if v, ok := cur[*f.Name]; !ok || v != *f.Value {
			changes = append(changes, PasswordHistory{Password: *f.Name + ": " + *f.Value, LastUsedDate: nowJS()})
		}
	}
	slices.Reverse(changes)
	hist := append(changes, original.PasswordHistory...)
	if len(hist) > maxPasswordHistory {
		hist = hist[:maxPasswordHistory]
	}
	c.PasswordHistory = hist
}

// AttachmentRequest is an entry of the attachments2 map in cipher requests.
type AttachmentRequest struct {
	FileName string  `json:"fileName"`
	Key      *string `json:"key"`
}

// CipherRequest is the body for creating/updating a cipher on the server.
type CipherRequest struct {
	Type                  int                          `json:"type"`
	FolderID              *string                      `json:"folderId"`
	OrganizationID        *string                      `json:"organizationId"`
	Name                  string                       `json:"name"`
	Notes                 *string                      `json:"notes"`
	Favorite              bool                         `json:"favorite"`
	Reprompt              int                          `json:"reprompt"`
	Key                   *string                      `json:"key"`
	Login                 *Login                       `json:"login,omitempty"`
	Card                  *Card                        `json:"card,omitempty"`
	Identity              *Identity                    `json:"identity,omitempty"`
	SecureNote            *SecureNote                  `json:"secureNote,omitempty"`
	SSHKey                *SSHKey                      `json:"sshKey,omitempty"`
	Fields                []Field                      `json:"fields"`
	PasswordHistory       []PasswordHistory            `json:"passwordHistory"`
	Attachments2          map[string]AttachmentRequest `json:"attachments2,omitempty"`
	LastKnownRevisionDate *string                      `json:"lastKnownRevisionDate,omitempty"`
	ArchivedDate          *string                      `json:"archivedDate,omitempty"`
	// EncryptedFor is the id of the user whose keys encrypted the cipher.
	EncryptedFor string `json:"encryptedFor"`
}

// NewCipherRequest builds a request from an encrypted cipher.
func NewCipherRequest(enc *Cipher, userID string) *CipherRequest {
	r := &CipherRequest{
		EncryptedFor: userID,
		Type:         enc.Type, FolderID: enc.FolderID, OrganizationID: enc.OrganizationID,
		Name: enc.Name, Notes: enc.Notes, Favorite: enc.Favorite, Reprompt: enc.Reprompt,
		Key: enc.Key, Login: enc.Login, Card: enc.Card, Identity: enc.Identity,
		SecureNote: enc.SecureNote, SSHKey: enc.SSHKey, Fields: enc.Fields,
		PasswordHistory: enc.PasswordHistory, ArchivedDate: enc.ArchivedDate,
	}
	if enc.RevisionDate != "" {
		rd := enc.RevisionDate
		r.LastKnownRevisionDate = &rd
	}
	if len(enc.Attachments) > 0 {
		r.Attachments2 = map[string]AttachmentRequest{}
		for _, a := range enc.Attachments {
			r.Attachments2[a.ID] = AttachmentRequest{FileName: a.FileName, Key: a.Key}
		}
	}
	return r
}
