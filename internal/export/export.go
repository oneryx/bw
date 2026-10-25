// Package export holds the file shapes of vault exports (JSON, encrypted
// JSON, CSV), mirroring the official clients' ExportService.
package export

import (
	"slices"
	"strconv"
	"strings"

	"github.com/oneryx/bw/internal/output"
	"github.com/oneryx/bw/vault"
)

// Item is the decrypted item shape of JSON exports (CipherWithIdExport).
type Item struct {
	Type            int                      `json:"type"`
	Name            string                   `json:"name"`
	Favorite        bool                     `json:"favorite"`
	Reprompt        int                      `json:"reprompt"`
	ID              string                   `json:"id"`
	CollectionIDs   []string                 `json:"collectionIds"`
	OrganizationID  *string                  `json:"organizationId,omitempty"`
	FolderID        *string                  `json:"folderId,omitempty"`
	Notes           *string                  `json:"notes,omitempty"`
	Fields          []output.FieldResponse   `json:"fields"`
	Login           *Login                   `json:"login,omitempty"`
	SecureNote      *vault.SecureNote        `json:"secureNote,omitempty"`
	Card            *output.CardResponse     `json:"card,omitempty"`
	Identity        *output.IdentityResponse `json:"identity,omitempty"`
	SSHKey          *output.SSHKeyResponse   `json:"sshKey,omitempty"`
	PasswordHistory []PasswordEntry          `json:"passwordHistory"`
	CreationDate    *string                  `json:"creationDate,omitempty"`
	RevisionDate    string                   `json:"revisionDate"`
	DeletedDate     *string                  `json:"deletedDate,omitempty"`
	ArchivedDate    *string                  `json:"archivedDate,omitempty"`
}

// Login is the login part of Item.
type Login struct {
	URIs             []output.URIResponse   `json:"uris"`
	Fido2Credentials []output.Fido2Response `json:"fido2Credentials"`
	Username         *string                `json:"username,omitempty"`
	Password         *string                `json:"password,omitempty"`
	Totp             *string                `json:"totp,omitempty"`
}

// PasswordEntry is a password history entry of exported items.
type PasswordEntry struct {
	Password     string `json:"password"`
	LastUsedDate string `json:"lastUsedDate"`
}

// NewItem converts a decrypted cipher into the JSON export shape.
func NewItem(c *vault.Cipher, withCollections bool) Item {
	r := output.ItemOutput(c)
	e := Item{
		Type: r.Type, Name: r.Name, Favorite: r.Favorite, Reprompt: r.Reprompt, ID: r.ID,
		OrganizationID: r.OrganizationID, FolderID: r.FolderID, Notes: r.Notes, Fields: r.Fields,
		SecureNote: r.SecureNote, Card: r.Card, Identity: r.Identity, SSHKey: r.SSHKey,
		CreationDate: r.CreationDate, RevisionDate: r.RevisionDate, DeletedDate: r.DeletedDate,
		ArchivedDate: r.ArchivedDate, PasswordHistory: []PasswordEntry{},
	}
	if withCollections {
		e.CollectionIDs = r.CollectionIDs
	}
	if l := r.Login; l != nil {
		e.Login = &Login{URIs: l.URIs, Fido2Credentials: l.Fido2Credentials, Username: l.Username, Password: l.Password, Totp: l.Totp}
	}
	for _, h := range c.PasswordHistory {
		e.PasswordHistory = append(e.PasswordHistory, PasswordEntry{Password: h.Password, LastUsedDate: output.JSDate(h.LastUsedDate)})
	}
	return e
}

// EncryptedItem is the encrypted item shape (built from the stored cipher).
type EncryptedItem struct {
	Type            int                      `json:"type"`
	Name            string                   `json:"name"`
	Favorite        bool                     `json:"favorite"`
	Reprompt        int                      `json:"reprompt"`
	ID              string                   `json:"id"`
	CollectionIDs   []string                 `json:"collectionIds"`
	OrganizationID  *string                  `json:"organizationId"`
	FolderID        *string                  `json:"folderId"`
	Notes           *string                  `json:"notes,omitempty"`
	Key             *string                  `json:"key,omitempty"`
	Fields          []output.FieldResponse   `json:"fields"`
	Login           *EncryptedLogin          `json:"login,omitempty"`
	SecureNote      *vault.SecureNote        `json:"secureNote,omitempty"`
	Card            *output.CardResponse     `json:"card,omitempty"`
	Identity        *output.IdentityResponse `json:"identity,omitempty"`
	SSHKey          *vault.SSHKey            `json:"sshKey,omitempty"`
	PasswordHistory []PasswordEntry          `json:"passwordHistory"`
	CreationDate    *string                  `json:"creationDate,omitempty"`
	RevisionDate    string                   `json:"revisionDate"`
	DeletedDate     *string                  `json:"deletedDate,omitempty"`
	ArchivedDate    *string                  `json:"archivedDate,omitempty"`
}

// EncryptedLogin is the login part of EncryptedItem.
type EncryptedLogin struct {
	// URIs is a pointer so a null server value is omitted while [] is kept.
	URIs             *[]EncryptedURI         `json:"uris,omitempty"`
	Fido2Credentials []vault.Fido2Credential `json:"fido2Credentials,omitempty"`
	Username         *string                 `json:"username,omitempty"`
	Password         *string                 `json:"password,omitempty"`
	Totp             *string                 `json:"totp,omitempty"`
}

// EncryptedURI is a login URI of EncryptedLogin.
type EncryptedURI struct {
	URI         *string `json:"uri,omitempty"`
	URIChecksum *string `json:"uriChecksum,omitempty"`
	Match       *int    `json:"match,omitempty"`
}

// NewEncryptedItem converts a stored (encrypted) cipher.
func NewEncryptedItem(c *vault.Cipher, withCollections bool) EncryptedItem {
	e := EncryptedItem{
		Type: c.Type, Name: c.Name, Favorite: c.Favorite, Reprompt: c.Reprompt, ID: c.ID,
		OrganizationID: c.OrganizationID, FolderID: c.FolderID, Notes: c.Notes, Key: c.Key,
		Fields: []output.FieldResponse{}, SSHKey: c.SSHKey,
		CreationDate: output.JSDatePtr(c.CreationDate), RevisionDate: output.JSDate(c.RevisionDate),
		DeletedDate: output.JSDatePtr(c.DeletedDate), ArchivedDate: output.JSDatePtr(c.ArchivedDate),
		PasswordHistory: []PasswordEntry{},
	}
	if withCollections {
		e.CollectionIDs = c.CollectionIDs
		if e.CollectionIDs == nil {
			e.CollectionIDs = []string{}
		}
	}
	for _, f := range c.Fields {
		e.Fields = append(e.Fields, output.FieldResponse{Type: f.Type, Name: f.Name, Value: f.Value, LinkedID: f.LinkedID})
	}
	switch c.Type {
	case vault.TypeLogin:
		if l := c.Login; l != nil {
			el := &EncryptedLogin{Fido2Credentials: l.Fido2Credentials,
				Username: l.Username, Password: l.Password, Totp: l.Totp}
			if l.URIs != nil {
				uris := []EncryptedURI{}
				for _, u := range l.URIs {
					uris = append(uris, EncryptedURI(u))
				}
				el.URIs = &uris
			}
			e.Login = el
		}
	case vault.TypeSecureNote:
		sn := vault.SecureNote{}
		if c.SecureNote != nil {
			sn = *c.SecureNote
		}
		e.SecureNote = &sn
	case vault.TypeCard:
		if cd := c.Card; cd != nil {
			cr := output.CardResponse(*cd)
			e.Card = &cr
		}
	case vault.TypeIdentity:
		if id := c.Identity; id != nil {
			ir := output.IdentityResponse(*id)
			e.Identity = &ir
		}
	}
	if c.Type != vault.TypeSSHKey {
		e.SSHKey = nil
	}
	for _, h := range c.PasswordHistory {
		e.PasswordHistory = append(e.PasswordHistory, PasswordEntry{Password: h.Password, LastUsedDate: output.JSDate(h.LastUsedDate)})
	}
	return e
}

// Folder is the folder shape of JSON exports.
type Folder struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// Collection is the collection shape of org JSON exports.
type Collection struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organizationId"`
	Name           string  `json:"name"`
	ExternalID     *string `json:"externalId"`
}

// SortByID orders ciphers by id, the storage order used by encrypted exports.
func SortByID(cs []*vault.Cipher) {
	slices.SortFunc(cs, func(a, b *vault.Cipher) int { return strings.Compare(a.ID, b.ID) })
}

// CSVRow is an ordered set of CSV columns.
type CSVRow struct {
	Keys   []string
	Values map[string]any
}

// CommonCSV mirrors buildCommonCipher for login and secure note items.
func CommonCSV(row *CSVRow, c *vault.Cipher) {
	set := func(k string, v any) {
		if _, ok := row.Values[k]; !ok {
			row.Keys = append(row.Keys, k)
		}
		row.Values[k] = v
	}
	set("type", nil)
	set("name", c.Name)
	set("notes", c.Notes)
	set("fields", nil)
	set("reprompt", c.Reprompt)
	set("archivedDate", output.JSDatePtr(c.ArchivedDate))
	set("login_uri", nil)
	set("login_username", nil)
	set("login_password", nil)
	set("login_totp", nil)
	if len(c.Fields) > 0 {
		var parts []string
		for _, f := range c.Fields {
			v := "null"
			if f.Value != nil {
				v = *f.Value
			}
			parts = append(parts, output.Deref(f.Name)+": "+v)
		}
		set("fields", strings.Join(parts, "\n"))
	}
	switch c.Type {
	case vault.TypeLogin:
		set("type", "login")
		if c.Login != nil {
			set("login_username", c.Login.Username)
			set("login_password", c.Login.Password)
			set("login_totp", c.Login.Totp)
			if c.Login.URIs != nil {
				var uris []string
				for _, u := range c.Login.URIs {
					uris = append(uris, output.Deref(u.URI))
				}
				set("login_uri", uris)
			}
		}
	case vault.TypeSecureNote:
		set("type", "note")
	}
}

// UnparseCSV mirrors papaparse's unparse defaults (CRLF rows, minimal quoting).
func UnparseCSV(rows []*CSVRow) string {
	if len(rows) == 0 {
		return ""
	}
	cell := func(v any) string {
		var s string
		switch x := v.(type) {
		case nil:
			return ""
		case string:
			s = x
		case *string:
			if x == nil {
				return ""
			}
			s = *x
		case []string:
			s = strings.Join(x, ",")
		case int:
			s = strconv.Itoa(x)
		default:
			s = output.JSON(x, "")
		}
		if strings.ContainsAny(s, ",\"\r\n\uFEFF") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
			s = `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
		}
		return s
	}
	keys := rows[0].Keys
	lines := []string{}
	header := make([]string, len(keys))
	for i, k := range keys {
		header[i] = cell(k)
	}
	lines = append(lines, strings.Join(header, ","))
	for _, r := range rows {
		vals := make([]string, len(keys))
		for i, k := range keys {
			vals[i] = cell(r.Values[k])
		}
		lines = append(lines, strings.Join(vals, ","))
	}
	return strings.Join(lines, "\r\n")
}
