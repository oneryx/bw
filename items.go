package bw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/oneryx/bw/internal/api"
	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/vault"
)

var guidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// IsGUID reports whether s is a Bitwarden object id.
func IsGUID(s string) bool { return guidRe.MatchString(s) }

func isDeleted(c *vault.Cipher) bool  { return c.DeletedDate != nil }
func isArchived(c *vault.Cipher) bool { return c.ArchivedDate != nil }

// ItemFilter selects items for Items. FolderID, CollectionID and
// OrganizationID also accept "null" (not set) and "notnull" (set). Combining
// filters is a logical OR; Search is ANDed with them. Trash and Archived
// select deleted and archived items instead of active ones.
type ItemFilter struct {
	Search         string
	URL            string
	FolderID       string
	CollectionID   string
	OrganizationID string
	Trash          bool
	Archived       bool
}

// Items returns the decrypted items matching f, sorted like the official
// clients.
func (c *Client) Items(f ItemFilter) ([]*vault.Cipher, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	ciphers := v.Ciphers()
	if strings.TrimSpace(f.URL) != "" {
		eq := v.EquivalentDomains(f.URL)
		ciphers = slices.DeleteFunc(ciphers, func(ci *vault.Cipher) bool {
			return isDeleted(ci) || isArchived(ci) || !ci.MatchesURL(f.URL, eq, vault.MatchDomain)
		})
	}
	stateOK := func(ci *vault.Cipher) bool { return f.Trash == isDeleted(ci) && f.Archived == isArchived(ci) }
	if f.FolderID != "" || f.CollectionID != "" || f.OrganizationID != "" {
		ciphers = slices.DeleteFunc(ciphers, func(ci *vault.Cipher) bool {
			return !stateOK(ci) || !matchesFilter(ci, f)
		})
	} else if strings.TrimSpace(f.Search) == "" {
		ciphers = slices.DeleteFunc(ciphers, func(ci *vault.Cipher) bool { return !stateOK(ci) })
	}
	if strings.TrimSpace(f.Search) != "" {
		ciphers = slices.DeleteFunc(ciphers, func(ci *vault.Cipher) bool { return !stateOK(ci) })
		ciphers = vault.SearchCiphers(ciphers, f.Search)
	}
	return ciphers, nil
}

func matchesFilter(ci *vault.Cipher, f ItemFilter) bool {
	if f.FolderID != "" {
		if f.FolderID == "notnull" && ci.FolderID != nil {
			return true
		}
		if (f.FolderID == "null" && ci.FolderID == nil) || (ci.FolderID != nil && *ci.FolderID == f.FolderID) {
			return true
		}
	}
	if f.OrganizationID != "" {
		if f.OrganizationID == "notnull" && ci.OrganizationID != nil {
			return true
		}
		if (f.OrganizationID == "null" && ci.OrganizationID == nil) || (ci.OrganizationID != nil && *ci.OrganizationID == f.OrganizationID) {
			return true
		}
	}
	if f.CollectionID != "" {
		if f.CollectionID == "notnull" && len(ci.CollectionIDs) > 0 {
			return true
		}
		if f.CollectionID == "null" && len(ci.CollectionIDs) == 0 {
			return true
		}
		if f.CollectionID != "null" && slices.Contains(ci.CollectionIDs, f.CollectionID) {
			return true
		}
	}
	return false
}

// Item returns the decrypted item with the given id.
func (c *Client) Item(id string) (*vault.Cipher, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	raw := v.RawCipher(strings.ToLower(id))
	if raw == nil {
		return nil, ErrNotFound
	}
	return v.Decrypt(raw), nil
}

// FindItem looks up an item by id, or else searches active items. When the
// search matches several items, the optional filter narrows them down; a
// remaining ambiguity returns a *MultipleResultsError.
func (c *Client) FindItem(query string, filter func(*vault.Cipher) bool) (*vault.Cipher, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	id := strings.ToLower(query)
	var found *vault.Cipher
	if IsGUID(id) {
		if raw := v.RawCipher(id); raw != nil {
			found = v.Decrypt(raw)
		}
	} else if strings.TrimSpace(id) != "" {
		cs := slices.DeleteFunc(v.Ciphers(), func(ci *vault.Cipher) bool { return isDeleted(ci) || isArchived(ci) })
		cs = vault.SearchCiphers(cs, id)
		if len(cs) > 1 {
			if filter != nil {
				cs = slices.DeleteFunc(cs, func(ci *vault.Cipher) bool { return !filter(ci) })
			}
			if len(cs) == 0 {
				return nil, ErrNotFound
			}
			if len(cs) > 1 {
				return nil, multipleResults(cs, func(ci *vault.Cipher) string { return ci.ID })
			}
			return cs[0], nil
		}
		if len(cs) == 1 {
			found = cs[0]
		}
	}
	if found == nil || (filter != nil && !filter(found)) {
		return nil, ErrNotFound
	}
	return found, nil
}

// cacheCipher stores the server's cipher response and returns it decrypted.
func (c *Client) cacheCipher(raw json.RawMessage) (*vault.Cipher, error) {
	var enc vault.Cipher
	if err := json.Unmarshal(raw, &enc); err != nil {
		return nil, err
	}
	if err := c.st.Account.UpsertVaultObject("ciphers", raw); err != nil {
		return nil, err
	}
	if err := c.save(); err != nil {
		return nil, err
	}
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	return v.Decrypt(&enc), nil
}

// refreshCipher re-fetches a cipher into the cache.
func (c *Client) refreshCipher(ctx context.Context, id string) (*vault.Cipher, error) {
	var raw json.RawMessage
	if err := c.api().Get(ctx, "/ciphers/"+id, &raw); err != nil {
		return nil, err
	}
	return c.cacheCipher(raw)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// CreateItem encrypts and creates a new item. Set OrganizationID and
// CollectionIDs to create it in an organization.
func (c *Client) CreateItem(ctx context.Context, item *vault.Cipher) (*vault.Cipher, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	enc, err := v.EncryptCipher(item)
	if err != nil {
		return nil, err
	}
	req := vault.NewCipherRequest(enc, c.userID())
	var raw json.RawMessage
	if enc.OrganizationID != nil && *enc.OrganizationID != "" {
		body := map[string]any{"cipher": req, "collectionIds": nonNil(item.CollectionIDs)}
		err = c.api().Do(ctx, http.MethodPost, "/ciphers/create", body, &raw)
	} else {
		err = c.api().Do(ctx, http.MethodPost, "/ciphers", req, &raw)
	}
	if err != nil {
		return nil, err
	}
	return c.cacheCipher(raw)
}

// UpdateItem saves changes to an existing item (matched by item.ID). The
// password history is updated, and hidden values the user may not view are
// preserved.
func (c *Client) UpdateItem(ctx context.Context, item *vault.Cipher) (*vault.Cipher, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	raw := v.RawCipher(strings.ToLower(item.ID))
	if raw == nil {
		return nil, ErrNotFound
	}
	if raw.Edit != nil && !*raw.Edit {
		return nil, errors.New("You do not have permission to edit this item")
	}
	orig := v.Decrypt(raw)
	if orig.DeletedDate != nil {
		return nil, errors.New("You may not edit a deleted item. Use the restore command first.")
	}
	view := item.Clone()
	if orig.ViewPassword != nil && !*orig.ViewPassword {
		restoreRedacted(view, orig)
	}
	vault.UpdatePasswordHistory(view, orig)
	enc, err := v.EncryptCipher(view)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	if err := c.api().Do(ctx, http.MethodPut, "/ciphers/"+raw.ID, vault.NewCipherRequest(enc, c.userID()), &out); err != nil {
		return nil, err
	}
	return c.cacheCipher(out)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// restoreRedacted keeps hidden values the user could not see (PM-16160).
func restoreRedacted(view, orig *vault.Cipher) {
	if view.Login != nil && orig.Login != nil {
		if view.Login.Password == nil {
			view.Login.Password = orig.Login.Password
		}
		if view.Login.Totp == nil {
			view.Login.Totp = orig.Login.Totp
		}
	}
	values := map[string][]*string{}
	for _, f := range orig.Fields {
		if f.Type == 1 {
			values[deref(f.Name)] = append(values[deref(f.Name)], f.Value)
		}
	}
	for i := range view.Fields {
		f := &view.Fields[i]
		if f.Type != 1 || f.Value != nil {
			continue
		}
		if vs := values[deref(f.Name)]; len(vs) > 0 {
			f.Value, values[deref(f.Name)] = vs[0], vs[1:]
		}
	}
}

// SetItemCollections replaces the collections of an organization item.
func (c *Client) SetItemCollections(ctx context.Context, id string, collectionIDs []string) (*vault.Cipher, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	raw := v.RawCipher(strings.ToLower(id))
	if raw == nil {
		return nil, ErrNotFound
	}
	if raw.OrganizationID == nil {
		return nil, errors.New("Item does not belong to an organization. Consider moving it first.")
	}
	if raw.ViewPassword != nil && !*raw.ViewPassword {
		return nil, errors.New("You do not have permission to edit this item")
	}
	body := map[string]any{"collectionIds": nonNil(collectionIDs)}
	if err := c.api().Do(ctx, http.MethodPost, "/ciphers/"+raw.ID+"/collections", body, nil); err != nil {
		return nil, err
	}
	return c.refreshCipher(ctx, raw.ID)
}

// DeleteItem moves an item to the trash, or deletes it permanently.
func (c *Client) DeleteItem(ctx context.Context, id string, permanent bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return err
	}
	raw := v.RawCipher(strings.ToLower(id))
	if raw == nil {
		return ErrNotFound
	}
	if raw.OrganizationID != nil && raw.Edit != nil && !*raw.Edit {
		return errors.New("You do not have permission to delete this item.")
	}
	if permanent {
		if err := c.api().Do(ctx, http.MethodDelete, "/ciphers/"+raw.ID, nil, nil); err != nil {
			return err
		}
		if err := c.st.Account.DeleteVaultObject("ciphers", raw.ID); err != nil {
			return err
		}
		return c.save()
	}
	if err := c.api().Do(ctx, http.MethodPut, "/ciphers/"+raw.ID+"/delete", nil, nil); err != nil {
		return err
	}
	_, err = c.refreshCipher(ctx, raw.ID)
	return err
}

// RestoreItem restores an item from the trash or the archive.
func (c *Client) RestoreItem(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return err
	}
	raw := v.RawCipher(strings.ToLower(id))
	if raw == nil {
		return ErrNotFound
	}
	action := "/restore"
	if raw.ArchivedDate != nil && raw.DeletedDate == nil {
		action = "/unarchive"
	} else if raw.DeletedDate == nil {
		return errors.New("Cipher is not in trash.")
	}
	if err := c.api().Do(ctx, http.MethodPut, "/ciphers/"+raw.ID+action, nil, nil); err != nil {
		return err
	}
	_, err = c.refreshCipher(ctx, raw.ID)
	return err
}

// ArchiveItem archives an item.
func (c *Client) ArchiveItem(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return err
	}
	raw := v.RawCipher(strings.ToLower(id))
	if raw == nil {
		return ErrNotFound
	}
	if raw.ArchivedDate != nil {
		return errors.New("Item is already archived.")
	}
	if raw.DeletedDate != nil {
		return errors.New("Item is in the trash, the item must be restored before archiving.")
	}
	if err := c.api().Do(ctx, http.MethodPut, "/ciphers/"+raw.ID+"/archive", nil, nil); err != nil {
		return err
	}
	_, err = c.refreshCipher(ctx, raw.ID)
	return err
}

// MoveItem moves a personal item into an organization, assigning it to the
// given collections (at least one).
func (c *Client) MoveItem(ctx context.Context, id, orgID string, collectionIDs []string) (*vault.Cipher, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(collectionIDs) == 0 {
		return nil, errors.New("You must provide at least one collection id for this item.")
	}
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	id, orgID = strings.ToLower(id), strings.ToLower(orgID)
	raw := v.RawCipher(id)
	if raw == nil {
		return nil, ErrNotFound
	}
	if raw.OrganizationID != nil {
		return nil, errors.New("This item already belongs to an organization.")
	}
	if !slices.ContainsFunc(v.Data.Profile.Organizations, func(o vault.ProfileOrganization) bool { return o.ID == orgID }) {
		return nil, ErrOrgNotFound
	}
	for _, cid := range collectionIDs {
		if !slices.ContainsFunc(v.Data.Collections, func(col vault.Collection) bool {
			return col.ID == cid && col.OrganizationID == orgID && !col.ReadOnly
		}) {
			return nil, errors.New("You do not have permission to add items to this collection.")
		}
	}
	view := v.Decrypt(raw)
	userCipherKey, err := v.CipherKey(raw)
	if err != nil {
		return nil, err
	}
	orgKey, err := v.OrgKey(orgID)
	if err != nil {
		return nil, ErrNoOrgKey
	}
	// Re-wrap per-item and attachment keys with the organization key.
	if view.Key != nil {
		k, err := crypto.Encrypt(orgKey, userCipherKey.Bytes())
		if err != nil {
			return nil, err
		}
		s := k.String()
		view.Key = &s
	}
	for i := range view.Attachments {
		at := &view.Attachments[i]
		if at.Key == nil || *at.Key == "" || view.Key != nil {
			continue
		}
		ak, err := crypto.DecryptKey(userCipherKey, *at.Key)
		if err != nil {
			return nil, err
		}
		wrapped, err := crypto.Encrypt(orgKey, ak.Bytes())
		if err != nil {
			return nil, err
		}
		s := wrapped.String()
		at.Key = &s
	}
	view.OrganizationID = &orgID
	view.CollectionIDs = collectionIDs
	enc, err := v.EncryptCipher(view)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	body := map[string]any{"cipher": vault.NewCipherRequest(enc, c.userID()), "collectionIds": collectionIDs}
	if err := c.api().Do(ctx, http.MethodPut, "/ciphers/"+raw.ID+"/share", body, &out); err != nil {
		return nil, err
	}
	return c.cacheCipher(out)
}

// --- attachments ---

// AddAttachment encrypts and uploads a file to an item.
func (c *Client) AddAttachment(ctx context.Context, itemID, fileName string, data []byte) (*vault.Cipher, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	raw := v.RawCipher(strings.ToLower(itemID))
	if raw == nil {
		return nil, ErrNotFound
	}
	cipherKey, err := v.CipherKey(raw)
	if err != nil {
		return nil, err
	}
	attKey := crypto.GenerateSymmetricKey()
	encKey, err := crypto.Encrypt(cipherKey, attKey.Bytes())
	if err != nil {
		return nil, err
	}
	encName, err := crypto.EncryptString(cipherKey, fileName)
	if err != nil {
		return nil, err
	}
	encData, err := crypto.EncryptBuffer(attKey, data)
	if err != nil {
		return nil, err
	}
	cl := c.api()
	var up struct {
		AttachmentID   string `json:"attachmentId"`
		FileUploadType int    `json:"fileUploadType"`
	}
	body := map[string]any{"key": encKey.String(), "fileName": encName, "fileSize": len(encData), "adminRequest": false}
	if err := cl.Do(ctx, http.MethodPost, "/ciphers/"+raw.ID+"/attachment/v2", body, &up); err != nil {
		return nil, err
	}
	if up.FileUploadType != 0 {
		return nil, fmt.Errorf("Unsupported attachment upload type %d.", up.FileUploadType)
	}
	mp, err := api.Multipart(nil, "data", encName, encData)
	if err != nil {
		return nil, err
	}
	uploadURL := cl.Env.APIURL() + "/ciphers/" + raw.ID + "/attachment/" + up.AttachmentID
	if err := cl.SendRaw(ctx, http.MethodPost, uploadURL, mp, nil); err != nil {
		_ = cl.Do(ctx, http.MethodDelete, "/ciphers/"+raw.ID+"/attachment/"+up.AttachmentID, nil, nil)
		return nil, err
	}
	return c.refreshCipher(ctx, raw.ID)
}

// DeleteAttachment removes an attachment from an item.
func (c *Client) DeleteAttachment(ctx context.Context, itemID, attachmentID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return err
	}
	raw := v.RawCipher(strings.ToLower(itemID))
	if raw == nil {
		return ErrNotFound
	}
	if len(raw.Attachments) == 0 {
		return errors.New("No attachments available for this item.")
	}
	var attID string
	for _, at := range raw.Attachments {
		if strings.EqualFold(at.ID, attachmentID) {
			attID = at.ID
		}
	}
	if attID == "" {
		return fmt.Errorf("Attachment `%s` was not found.", attachmentID)
	}
	if err := c.api().Do(ctx, http.MethodDelete, "/ciphers/"+raw.ID+"/attachment/"+attID, nil, nil); err != nil {
		return err
	}
	_, err = c.refreshCipher(ctx, raw.ID)
	return err
}

// Attachment downloads and decrypts an attachment of an item.
func (c *Client) Attachment(ctx context.Context, itemID, attachmentID string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	return c.downloadAttachment(ctx, v, strings.ToLower(itemID), attachmentID)
}

func (c *Client) downloadAttachment(ctx context.Context, v *vault.Vault, cipherID, attachmentID string) ([]byte, error) {
	raw := v.RawCipher(cipherID)
	if raw == nil {
		return nil, ErrNotFound
	}
	var att *vault.Attachment
	for i := range raw.Attachments {
		if raw.Attachments[i].ID == attachmentID {
			att = &raw.Attachments[i]
		}
	}
	if att == nil {
		return nil, fmt.Errorf("Attachment `%s` was not found.", attachmentID)
	}
	cl := c.api()
	var meta struct {
		URL string `json:"url"`
	}
	if err := cl.Get(ctx, "/ciphers/"+cipherID+"/attachment/"+att.ID, &meta); err != nil {
		return nil, err
	}
	enc, err := cl.Download(ctx, meta.URL)
	if err != nil {
		var ae *api.Error
		if errors.As(err, &ae) {
			return nil, fmt.Errorf("A %d error occurred while downloading the attachment.", ae.Status)
		}
		return nil, err
	}
	key, err := v.CipherKey(raw)
	if err != nil {
		return nil, err
	}
	if att.Key != nil && *att.Key != "" {
		if key, err = crypto.DecryptKey(key, *att.Key); err != nil {
			return nil, err
		}
	}
	plain, err := crypto.DecryptBuffer(key, enc)
	if err != nil {
		return nil, errors.New("An error occurred while saving the attachment.")
	}
	return plain, nil
}
