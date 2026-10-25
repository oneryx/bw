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
	var equivalent map[string]bool
	if strings.TrimSpace(f.URL) != "" {
		equivalent = v.equivalentDomains(f.URL)
	}
	idFilter := f.FolderID != "" || f.CollectionID != "" || f.OrganizationID != ""
	ciphers := slices.DeleteFunc(v.ciphers(), func(ci *vault.Cipher) bool {
		return f.Trash != isDeleted(ci) || f.Archived != isArchived(ci) ||
			(equivalent != nil && (isDeleted(ci) || isArchived(ci) || !ci.MatchesURL(f.URL, equivalent, vault.MatchDomain))) ||
			(idFilter && !matchesFilter(ci, f))
	})
	if strings.TrimSpace(f.Search) != "" {
		ciphers = vault.SearchCiphers(ciphers, f.Search)
	}
	return ciphers, nil
}

// matchesFilter reports whether the item matches any of the id filters.
func matchesFilter(ci *vault.Cipher, f ItemFilter) bool {
	matchID := func(filter string, id *string) bool {
		switch filter {
		case "":
			return false
		case "null":
			return id == nil
		case "notnull":
			return id != nil
		}
		return id != nil && *id == filter
	}
	if matchID(f.FolderID, ci.FolderID) || matchID(f.OrganizationID, ci.OrganizationID) {
		return true
	}
	switch f.CollectionID {
	case "":
		return false
	case "null":
		return len(ci.CollectionIDs) == 0
	case "notnull":
		return len(ci.CollectionIDs) > 0
	}
	return slices.Contains(ci.CollectionIDs, f.CollectionID)
}

// Item returns the decrypted item with the given id.
func (c *Client) Item(id string) (*vault.Cipher, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	raw := v.rawCipher(strings.ToLower(id))
	if raw == nil {
		return nil, ErrNotFound
	}
	return v.decrypt(raw), nil
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
	var found []*vault.Cipher
	if IsGUID(id) {
		if raw := v.rawCipher(id); raw != nil {
			found = append(found, v.decrypt(raw))
		}
	} else if strings.TrimSpace(id) != "" {
		found = slices.DeleteFunc(v.ciphers(), func(ci *vault.Cipher) bool { return isDeleted(ci) || isArchived(ci) })
		found = vault.SearchCiphers(found, id)
	}
	if len(found) > 1 && filter != nil {
		found = slices.DeleteFunc(found, func(ci *vault.Cipher) bool { return !filter(ci) })
	}
	switch len(found) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return found[0], nil
	}
	return nil, multipleResults(found, func(ci *vault.Cipher) string { return ci.ID })
}

// FindAttachment looks up an item like FindItem and one of its attachments
// by id, or else by a file name search (an exact name match wins over
// partial matches).
func (c *Client) FindAttachment(itemQuery, query string) (*vault.Cipher, *vault.Attachment, error) {
	it, err := c.FindItem(itemQuery, nil)
	if err != nil {
		return nil, nil, err
	}
	if len(it.Attachments) == 0 {
		return nil, nil, errors.New("No attachments available for this item.")
	}
	query = strings.ToLower(query)
	var matches, exact []vault.Attachment
	for _, at := range it.Attachments {
		name := strings.ToLower(at.FileName)
		if strings.ToLower(at.ID) == query || strings.Contains(name, query) {
			matches = append(matches, at)
		}
		if name == query {
			exact = append(exact, at)
		}
	}
	if len(exact) == 1 {
		matches = exact
	}
	switch len(matches) {
	case 0:
		return nil, nil, fmt.Errorf("Attachment `%s` was not found.", query)
	case 1:
		return it, &matches[0], nil
	}
	return nil, nil, multipleResults(matches, func(at vault.Attachment) string { return at.ID })
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

func (c *Client) downloadAttachment(ctx context.Context, v *openVault, cipherID, attachmentID string) ([]byte, error) {
	raw := v.rawCipher(cipherID)
	if raw == nil {
		return nil, ErrNotFound
	}
	i := slices.IndexFunc(raw.Attachments, func(a vault.Attachment) bool { return a.ID == attachmentID })
	if i < 0 {
		return nil, fmt.Errorf("Attachment `%s` was not found.", attachmentID)
	}
	att := &raw.Attachments[i]
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
	key, err := v.cipherKey(raw)
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
