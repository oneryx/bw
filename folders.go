package bw

import (
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
