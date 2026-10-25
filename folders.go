package bw

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/vault"
)

// Folders returns the decrypted folders sorted by name.
func (c *Client) Folders() ([]vault.Folder, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	return v.Folders(), nil
}

// cacheFolder stores the server's folder response and returns it decrypted.
func (c *Client) cacheFolder(v *vault.Vault, raw json.RawMessage) (vault.Folder, error) {
	var f vault.Folder
	if err := json.Unmarshal(raw, &f); err != nil {
		return f, err
	}
	if err := c.st.Account.UpsertVaultObject("folders", raw); err != nil {
		return f, err
	}
	if err := c.save(); err != nil {
		return f, err
	}
	name, err := crypto.DecryptString(v.UserKey, f.Name)
	if err != nil {
		name = vault.DecryptError
	}
	f.Name = name
	return f, nil
}

// CreateFolder creates a folder.
func (c *Client) CreateFolder(ctx context.Context, name string) (vault.Folder, error) {
	return c.saveFolder(ctx, "", name)
}

// RenameFolder renames a folder.
func (c *Client) RenameFolder(ctx context.Context, id, name string) (vault.Folder, error) {
	return c.saveFolder(ctx, strings.ToLower(id), name)
}

func (c *Client) saveFolder(ctx context.Context, id, name string) (vault.Folder, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return vault.Folder{}, err
	}
	if id != "" && !hasFolder(v, id) {
		return vault.Folder{}, ErrNotFound
	}
	encName, err := crypto.EncryptString(v.UserKey, name)
	if err != nil {
		return vault.Folder{}, err
	}
	var raw json.RawMessage
	body := map[string]string{"name": encName}
	if id == "" {
		err = c.api().Do(ctx, http.MethodPost, "/folders", body, &raw)
	} else {
		err = c.api().Do(ctx, http.MethodPut, "/folders/"+id, body, &raw)
	}
	if err != nil {
		return vault.Folder{}, err
	}
	return c.cacheFolder(v, raw)
}

func hasFolder(v *vault.Vault, id string) bool {
	return slices.ContainsFunc(v.Data.Folders, func(f vault.Folder) bool { return f.ID == id })
}

// DeleteFolder deletes a folder; its items move to "No Folder".
func (c *Client) DeleteFolder(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return err
	}
	id = strings.ToLower(id)
	if !hasFolder(v, id) {
		return ErrNotFound
	}
	if err := c.api().Do(ctx, http.MethodDelete, "/folders/"+id, nil, nil); err != nil {
		return err
	}
	// Items in the folder move to "No Folder"; resync to reflect that.
	return c.sync(ctx, true)
}
