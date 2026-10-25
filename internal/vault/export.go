package vault

import (
	"slices"
	"strings"

	"github.com/yangxiang/bw/internal/output"
)

// ExportItem is the decrypted item shape of JSON exports (CipherWithIdExport).
type ExportItem struct {
	Type            int                   `json:"type"`
	Name            string                `json:"name"`
	Favorite        bool                  `json:"favorite"`
	Reprompt        int                   `json:"reprompt"`
	ID              string                `json:"id"`
	CollectionIDs   []string              `json:"collectionIds"`
	OrganizationID  *string               `json:"organizationId,omitempty"`
	FolderID        *string               `json:"folderId,omitempty"`
	Notes           *string               `json:"notes,omitempty"`
	Fields          []FieldResponse       `json:"fields"`
	Login           *ExportLogin          `json:"login,omitempty"`
	SecureNote      *SecureNote           `json:"secureNote,omitempty"`
	Card            *CardResponse         `json:"card,omitempty"`
	Identity        *IdentityResponse     `json:"identity,omitempty"`
	SSHKey          *SSHKeyResponse       `json:"sshKey,omitempty"`
	PasswordHistory []ExportPasswordEntry `json:"passwordHistory"`
	CreationDate    *string               `json:"creationDate,omitempty"`
	RevisionDate    string                `json:"revisionDate"`
	DeletedDate     *string               `json:"deletedDate,omitempty"`
	ArchivedDate    *string               `json:"archivedDate,omitempty"`
}

type ExportLogin struct {
	URIs             []URIResponse   `json:"uris"`
	Fido2Credentials []Fido2Response `json:"fido2Credentials"`
	Username         *string         `json:"username,omitempty"`
	Password         *string         `json:"password,omitempty"`
	Totp             *string         `json:"totp,omitempty"`
}

type ExportPasswordEntry struct {
	Password     string `json:"password"`
	LastUsedDate string `json:"lastUsedDate"`
}

// ExportItemOutput converts a decrypted cipher into the JSON export shape.
func ExportItemOutput(c *Cipher, withCollections bool) ExportItem {
	r := ItemOutput(c)
	e := ExportItem{
		Type: r.Type, Name: r.Name, Favorite: r.Favorite, Reprompt: r.Reprompt, ID: r.ID,
		OrganizationID: r.OrganizationID, FolderID: r.FolderID, Notes: r.Notes, Fields: r.Fields,
		SecureNote: r.SecureNote, Card: r.Card, Identity: r.Identity, SSHKey: r.SSHKey,
		CreationDate: r.CreationDate, RevisionDate: r.RevisionDate, DeletedDate: r.DeletedDate,
		ArchivedDate: r.ArchivedDate, PasswordHistory: []ExportPasswordEntry{},
	}
	if withCollections {
		e.CollectionIDs = r.CollectionIDs
	}
	if l := r.Login; l != nil {
		e.Login = &ExportLogin{URIs: l.URIs, Fido2Credentials: l.Fido2Credentials, Username: l.Username, Password: l.Password, Totp: l.Totp}
	}
	for _, h := range c.PasswordHistory {
		e.PasswordHistory = append(e.PasswordHistory, ExportPasswordEntry{Password: h.Password, LastUsedDate: JSDate(h.LastUsedDate)})
	}
	return e
}

// EncryptedExportItem is the encrypted item shape (built from the stored cipher).
type EncryptedExportItem struct {
	Type            int                   `json:"type"`
	Name            string                `json:"name"`
	Favorite        bool                  `json:"favorite"`
	Reprompt        int                   `json:"reprompt"`
	ID              string                `json:"id"`
	CollectionIDs   []string              `json:"collectionIds"`
	OrganizationID  *string               `json:"organizationId"`
	FolderID        *string               `json:"folderId"`
	Notes           *string               `json:"notes,omitempty"`
	Key             *string               `json:"key,omitempty"`
	Fields          []FieldResponse       `json:"fields"`
	Login           *EncryptedExportLogin `json:"login,omitempty"`
	SecureNote      *SecureNote           `json:"secureNote,omitempty"`
	Card            *CardResponse         `json:"card,omitempty"`
	Identity        *IdentityResponse     `json:"identity,omitempty"`
	SSHKey          *SSHKey               `json:"sshKey,omitempty"`
	PasswordHistory []ExportPasswordEntry `json:"passwordHistory"`
	CreationDate    *string               `json:"creationDate,omitempty"`
	RevisionDate    string                `json:"revisionDate"`
	DeletedDate     *string               `json:"deletedDate,omitempty"`
	ArchivedDate    *string               `json:"archivedDate,omitempty"`
}

type EncryptedExportLogin struct {
	// URIs is a pointer so a null server value is omitted while [] is kept.
	URIs             *[]EncryptedExportURI `json:"uris,omitempty"`
	Fido2Credentials []Fido2Credential     `json:"fido2Credentials,omitempty"`
	Username         *string               `json:"username,omitempty"`
	Password         *string               `json:"password,omitempty"`
	Totp             *string               `json:"totp,omitempty"`
}

type EncryptedExportURI struct {
	URI         *string `json:"uri,omitempty"`
	URIChecksum *string `json:"uriChecksum,omitempty"`
	Match       *int    `json:"match,omitempty"`
}

// EncryptedExportItemOutput converts a stored (encrypted) cipher.
func EncryptedExportItemOutput(c *Cipher, withCollections bool) EncryptedExportItem {
	e := EncryptedExportItem{
		Type: c.Type, Name: c.Name, Favorite: c.Favorite, Reprompt: c.Reprompt, ID: c.ID,
		OrganizationID: c.OrganizationID, FolderID: c.FolderID, Notes: c.Notes, Key: c.Key,
		Fields: []FieldResponse{}, SSHKey: c.SSHKey,
		CreationDate: jsDatePtr(c.CreationDate), RevisionDate: JSDate(c.RevisionDate),
		DeletedDate: jsDatePtr(c.DeletedDate), ArchivedDate: jsDatePtr(c.ArchivedDate),
		PasswordHistory: []ExportPasswordEntry{},
	}
	if withCollections {
		e.CollectionIDs = c.CollectionIDs
		if e.CollectionIDs == nil {
			e.CollectionIDs = []string{}
		}
	}
	for _, f := range c.Fields {
		e.Fields = append(e.Fields, FieldResponse{Type: f.Type, Name: f.Name, Value: f.Value, LinkedID: f.LinkedID})
	}
	switch c.Type {
	case TypeLogin:
		if l := c.Login; l != nil {
			el := &EncryptedExportLogin{Fido2Credentials: l.Fido2Credentials,
				Username: l.Username, Password: l.Password, Totp: l.Totp}
			if l.URIs != nil {
				uris := []EncryptedExportURI{}
				for _, u := range l.URIs {
					uris = append(uris, EncryptedExportURI{URI: u.URI, URIChecksum: u.URIChecksum, Match: u.Match})
				}
				el.URIs = &uris
			}
			e.Login = el
		}
	case TypeSecureNote:
		sn := SecureNote{}
		if c.SecureNote != nil {
			sn = *c.SecureNote
		}
		e.SecureNote = &sn
	case TypeCard:
		if cd := c.Card; cd != nil {
			e.Card = &CardResponse{cd.CardholderName, cd.Brand, cd.Number, cd.ExpMonth, cd.ExpYear, cd.Code}
		}
	case TypeIdentity:
		if id := c.Identity; id != nil {
			ir := IdentityResponse(*id)
			e.Identity = &ir
		}
	}
	if c.Type != TypeSSHKey {
		e.SSHKey = nil
	}
	for _, h := range c.PasswordHistory {
		e.PasswordHistory = append(e.PasswordHistory, ExportPasswordEntry{Password: h.Password, LastUsedDate: JSDate(h.LastUsedDate)})
	}
	return e
}

// ExportFolder is the folder shape of JSON exports.
type ExportFolder struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// ExportCollection is the collection shape of org JSON exports.
type ExportCollection struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organizationId"`
	Name           string  `json:"name"`
	ExternalID     *string `json:"externalId"`
}

// SortByID orders ciphers by id, the storage order used by encrypted exports.
func SortByID(cs []*Cipher) {
	slices.SortFunc(cs, func(a, b *Cipher) int { return strings.Compare(a.ID, b.ID) })
}

// CSVRow is an ordered set of CSV columns.
type CSVRow struct {
	Keys   []string
	Values map[string]any
}

// CommonCSV mirrors buildCommonCipher; returns false for unsupported types.
func CommonCSV(row *CSVRow, c *Cipher) bool {
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
	set("archivedDate", jsDatePtr(c.ArchivedDate))
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
			parts = append(parts, deref(f.Name)+": "+v)
		}
		set("fields", strings.Join(parts, "\n"))
	}
	switch c.Type {
	case TypeLogin:
		set("type", "login")
		if c.Login != nil {
			set("login_username", c.Login.Username)
			set("login_password", c.Login.Password)
			set("login_totp", c.Login.Totp)
			if c.Login.URIs != nil {
				var uris []string
				for _, u := range c.Login.URIs {
					uris = append(uris, deref(u.URI))
				}
				set("login_uri", uris)
			}
		}
	case TypeSecureNote:
		set("type", "note")
	default:
		return false
	}
	return true
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
			s = Itoa(x)
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
