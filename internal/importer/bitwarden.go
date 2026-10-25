package importer

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/vault"
)

// --- bitwardencsv ---

type bitwardenCSV struct{ base }

func (b *bitwardenCSV) Parse(data string) (*Result, error) {
	r := &Result{}
	rows, _ := parseCSV(data, true)
	if rows == nil {
		return r, nil
	}
	for _, v := range rows {
		if cols, ok := v.get("collections"); b.organization() && !ws(cols) && ok {
			for _, col := range strings.Split(cols, ",") {
				processFolder(r, ptr(col), true)
			}
		} else if !b.organization() {
			processFolder(r, v.val("folder"), true)
		}
		c := &vault.Cipher{Type: vault.TypeLogin}
		if fav := v.val("favorite"); !b.organization() && fav != nil && *fav != "0" {
			c.Favorite = true
		}
		c.Notes = v.val("notes")
		c.Name = "--"
		if n := v.val("name"); n != nil {
			c.Name = *n
		}
		if rp := v.val("reprompt"); rp != nil {
			c.Reprompt, _ = strconv.Atoi(strings.TrimSpace(*rp))
		}
		if ad := v.val("archivedDate"); ad != nil {
			c.ArchivedDate = ad
		}
		if fs := v.val("fields"); fs != nil {
			for _, line := range splitNewLine(*fs) {
				if ws(line) {
					continue
				}
				pos := strings.LastIndex(line, ": ")
				if pos == -1 {
					continue
				}
				f := vault.Field{Type: 0, Name: ptr(line[:pos])}
				if len(line) > pos+2 {
					f.Value = ptr(line[pos+2:])
				}
				c.Fields = append(c.Fields, f)
			}
		}
		typ, _ := v.get("type")
		switch strings.ToLower(typ) {
		case "note":
			c.Type = vault.TypeSecureNote
			c.SecureNote = &vault.SecureNote{}
		default:
			// JS `a || b`: the first non-empty raw value wins.
			first := func(keys ...string) *string {
				for _, k := range keys {
					if s, ok := v.get(k); ok && s != "" {
						return &s
					}
				}
				return nil
			}
			orDefault := func(p *string) *string {
				if p == nil {
					return nil
				}
				return valueOrDefault(*p, true, nil)
			}
			c.Login = &vault.Login{
				Totp:     orDefault(first("login_totp", "totp")),
				Username: orDefault(first("login_username", "username")),
				Password: orDefault(first("login_password", "password")),
			}
			uri := first("login_uri", "uri")
			c.Login.URIs = makeURIs(parseSingleRowCSV(uri)...)
		}
		r.Ciphers = append(r.Ciphers, c)
	}
	if b.organization() {
		moveFoldersToCollections(r)
	}
	r.Success = true
	return r, nil
}

// --- bitwardenjson (plain, account-encrypted and password-protected) ---

type bitwardenJSON struct{ base }

type bwExport struct {
	Encrypted         bool              `json:"encrypted"`
	PasswordProtected bool              `json:"passwordProtected"`
	Salt              string            `json:"salt"`
	KdfType           *int              `json:"kdfType"`
	KdfIterations     *int              `json:"kdfIterations"`
	KdfMemory         *int              `json:"kdfMemory"`
	KdfParallelism    *int              `json:"kdfParallelism"`
	Validation        string            `json:"encKeyValidation_DO_NOT_EDIT"`
	Data              string            `json:"data"`
	Folders           []json.RawMessage `json:"folders"`
	Collections       []json.RawMessage `json:"collections"`
	Items             []json.RawMessage `json:"items"`
}

func (b *bitwardenJSON) Parse(data string) (*Result, error) {
	var doc bwExport
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		return nil, ErrFormat
	}
	if doc.Encrypted && doc.PasswordProtected {
		return b.parsePasswordProtected(&doc)
	}
	if doc.Items == nil {
		return &Result{}, nil
	}
	if doc.Encrypted {
		return b.parseEncrypted(&doc)
	}
	return b.parseDecrypted(&doc)
}

func (b *bitwardenJSON) parsePasswordProtected(doc *bwExport) (*Result, error) {
	if doc.Salt == "" || doc.Validation == "" || doc.Data == "" {
		return &Result{}, nil
	}
	kdf, ok := importKDF(doc)
	if !ok {
		return &Result{ErrorMessage: "The import file contains unsupported KDF settings."}, nil
	}
	if b.opts.Password == nil {
		return nil, errors.New("Import file password is required. Provide --passwordfile or --passwordenv, or run interactively.")
	}
	password, err := b.opts.Password()
	if err != nil {
		return nil, err
	}
	invalid := &Result{ErrorMessage: "Invalid file password, please use the password you entered when you created the export file."}
	if ws(password) {
		return invalid, nil
	}
	km, err := crypto.DeriveKDF([]byte(password), []byte(doc.Salt), kdf)
	if err != nil {
		return invalid, nil
	}
	key := crypto.StretchKey(km)
	if _, err := crypto.DecryptString(key, doc.Validation); err != nil {
		return invalid, nil
	}
	clear, err := crypto.DecryptString(key, doc.Data)
	if err != nil {
		return invalid, nil
	}
	return b.Parse(clear)
}

// importKDF mirrors kdfConfigFromPasswordProtectedExport bounds checks.
func importKDF(doc *bwExport) (crypto.KDFParams, bool) {
	if doc.KdfType == nil || doc.KdfIterations == nil {
		return crypto.KDFParams{}, false
	}
	switch *doc.KdfType {
	case crypto.KDFPBKDF2:
		if *doc.KdfIterations >= 5000 && *doc.KdfIterations <= 2_000_000 {
			return crypto.KDFParams{Type: crypto.KDFPBKDF2, Iterations: *doc.KdfIterations}, true
		}
	case crypto.KDFArgon2id:
		if doc.KdfMemory != nil && doc.KdfParallelism != nil &&
			*doc.KdfIterations >= 2 && *doc.KdfIterations <= 10 &&
			*doc.KdfMemory >= 16 && *doc.KdfMemory <= 1024 &&
			*doc.KdfParallelism >= 1 && *doc.KdfParallelism <= 16 {
			return crypto.KDFParams{Type: crypto.KDFArgon2id, Iterations: *doc.KdfIterations,
				Memory: *doc.KdfMemory, Parallelism: *doc.KdfParallelism}, true
		}
	}
	return crypto.KDFParams{}, false
}

type groupRef struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	OrganizationID string  `json:"organizationId"`
	ExternalID     *string `json:"externalId"`
}

type itemRefs struct {
	FolderID      *string  `json:"folderId"`
	CollectionIDs []string `json:"collectionIds"`
}

// addRelationships links the current cipher to its folder or collections.
func (b *bitwardenJSON) addRelationships(r *Result, raw json.RawMessage, groups map[string]int) {
	var refs itemRefs
	_ = json.Unmarshal(raw, &refs)
	idx := len(r.Ciphers)
	if !b.organization() && refs.FolderID != nil {
		if g, ok := groups[*refs.FolderID]; ok {
			r.FolderRelationships = append(r.FolderRelationships, [2]int{idx, g})
		}
	} else if b.organization() {
		for _, cid := range refs.CollectionIDs {
			if g, ok := groups[cid]; ok {
				r.CollectionRelationships = append(r.CollectionRelationships, [2]int{idx, g})
			}
		}
	}
}

// finish resets ids and trims history like the official importer.
func finish(c *vault.Cipher) {
	c.ID = ""
	c.OrganizationID = nil
	c.CollectionIDs = nil
	c.Key = nil
	c.RevisionDate = ""
	c.CreationDate = nil
	c.DeletedDate = nil
	c.Attachments = nil
	c.Edit, c.ViewPassword = nil, nil
	if len(c.PasswordHistory) > 5 {
		c.PasswordHistory = c.PasswordHistory[:5]
	}
	cleanup(c)
}

func (b *bitwardenJSON) parseDecrypted(doc *bwExport) (*Result, error) {
	r := &Result{}
	groups := map[string]int{}
	if doc.Collections != nil {
		for _, raw := range doc.Collections {
			var g groupRef
			if json.Unmarshal(raw, &g) == nil {
				groups[g.ID] = len(r.Collections)
				r.Collections = append(r.Collections, Collection{ID: ptr(g.ID), Name: g.Name, ExternalID: g.ExternalID})
			}
		}
	} else {
		for _, raw := range doc.Folders {
			var g groupRef
			if json.Unmarshal(raw, &g) == nil {
				groups[g.ID] = len(r.Folders)
				r.Folders = append(r.Folders, Folder{ID: ptr(g.ID), Name: g.Name})
			}
		}
	}
	for _, raw := range doc.Items {
		var in vault.CipherInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, ErrFormat
		}
		c := vault.ApplyInput(&in, nil)
		b.addRelationships(r, raw, groups)
		finish(c)
		r.Ciphers = append(r.Ciphers, c)
	}
	r.Success = true
	return r, nil
}

func (b *bitwardenJSON) parseEncrypted(doc *bwExport) (*Result, error) {
	v := b.opts.Vault
	encKeyErr := &Result{ErrorMessage: "Error decrypting the exported file. Your encryption key does not match the encryption key used export the data."}
	if ws(doc.Validation) || v == nil {
		return encKeyErr, nil
	}
	key := v.UserKey
	if b.organization() {
		if k, err := v.OrgKey(b.opts.OrganizationID); err == nil {
			key = k
		}
	}
	if _, err := crypto.DecryptString(key, doc.Validation); err != nil {
		return encKeyErr, nil
	}
	r := &Result{}
	groups := map[string]int{}
	if doc.Collections != nil {
		for _, raw := range doc.Collections {
			var g groupRef
			if json.Unmarshal(raw, &g) != nil {
				continue
			}
			groups[g.ID] = len(r.Collections)
			r.Collections = append(r.Collections, Collection{ID: ptr(g.ID), Name: v.DecryptCollectionName(g.OrganizationID, g.Name), ExternalID: g.ExternalID})
		}
	} else {
		for _, raw := range doc.Folders {
			var g groupRef
			if json.Unmarshal(raw, &g) != nil {
				continue
			}
			name, err := crypto.DecryptString(v.UserKey, g.Name)
			if err != nil {
				name = vault.DecryptError
			}
			groups[g.ID] = len(r.Folders)
			r.Folders = append(r.Folders, Folder{ID: ptr(g.ID), Name: name})
		}
	}
	for _, raw := range doc.Items {
		var enc vault.Cipher
		if err := json.Unmarshal(raw, &enc); err != nil {
			return nil, ErrFormat
		}
		enc.OrganizationID = nil
		if b.organization() {
			enc.OrganizationID = ptr(b.opts.OrganizationID)
		}
		c := v.Decrypt(&enc)
		b.addRelationships(r, raw, groups)
		finish(c)
		r.Ciphers = append(r.Ciphers, c)
	}
	r.Success = true
	return r, nil
}
