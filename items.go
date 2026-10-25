package bw

import (
	"context"
	"errors"
	"fmt"
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
