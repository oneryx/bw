package bw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/internal/importer"
	"github.com/oneryx/bw/vault"
)

// ImportFormats lists the formats accepted by Import.
func ImportFormats() []string { return importer.Formats() }

// ImportOptions configure Import.
type ImportOptions struct {
	// Format is one of ImportFormats.
	Format string
	// OrganizationID imports into an organization vault.
	OrganizationID string
	// Password is called for password protected Bitwarden exports.
	Password func() (string, error)
}

type kvp struct {
	Key   int `json:"key"`
	Value int `json:"value"`
}

// Import parses an export file and adds its content to the vault, then
// syncs.
func (c *Client) Import(ctx context.Context, data []byte, opts ImportOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return err
	}
	orgID := opts.OrganizationID
	if orgID != "" {
		if err := c.checkImportOrg(orgID); err != nil {
			return err
		}
	}
	password := opts.Password
	if password == nil {
		password = func() (string, error) { return "", errors.New("Import file password is required.") }
	}
	imp := importer.Get(opts.Format, importer.Options{OrganizationID: orgID, Vault: v, Password: password})
	if imp == nil {
		return fmt.Errorf("Import format `%s` is not supported. Supported formats: %s.", opts.Format, strings.Join(importer.Formats(), ", "))
	}
	if len(data) == 0 {
		return errors.New("Import file was empty.")
	}
	result, err := imp.Parse(string(data))
	if err != nil {
		return err
	}
	if err := c.importResult(ctx, v, result, orgID); err != nil {
		return err
	}
	return c.sync(ctx, true)
}

// checkImportOrg verifies the user may import into the organization.
func (c *Client) checkImportOrg(orgID string) error {
	var org *struct {
		Type        int `json:"type"`
		Permissions *struct {
			AccessImportExport bool `json:"accessImportExport"`
		} `json:"permissions"`
	}
	var raw struct {
		Profile struct {
			Organizations []json.RawMessage `json:"organizations"`
		} `json:"profile"`
	}
	_ = json.Unmarshal(c.st.Account.Vault, &raw)
	for _, o := range raw.Profile.Organizations {
		var id struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(o, &id)
		if id.ID == orgID {
			_ = json.Unmarshal(o, &org)
		}
	}
	if org == nil {
		return fmt.Errorf("You do not belong to an organization with the ID of %s. Check the organization ID and sync your vault.", orgID)
	}
	if org.Type > OrgUserAdmin && (org.Permissions == nil || !org.Permissions.AccessImportExport) {
		return errors.New("You are not authorized to import into the provided organization.")
	}
	return nil
}

func badData(c *vault.Cipher) bool {
	return (c.Name == "" || c.Name == "--") && c.Type == vault.TypeLogin && c.Login != nil &&
		(c.Login.Password == nil || strings.TrimSpace(*c.Login.Password) == "")
}

// importResult mirrors ImportService.importImportResult and posts the data.
func (c *Client) importResult(ctx context.Context, v *vault.Vault, r *importer.Result, orgID string) error {
	if !r.Success {
		if strings.TrimSpace(r.ErrorMessage) != "" {
			return errors.New(r.ErrorMessage)
		}
		return importer.ErrFormat
	}
	if len(r.Folders) == 0 && len(r.Ciphers) == 0 {
		return errors.New("Nothing was imported.")
	}
	if n := len(r.Ciphers); n > 0 && badData(r.Ciphers[0]) && badData(r.Ciphers[n/2]) && badData(r.Ciphers[n-1]) {
		return importer.ErrFormat
	}
	if orgID != "" && len(r.CollectionRelationships) < len(r.Ciphers) {
		return errors.New("File contains unassigned items.")
	}
	uid := c.userID()
	ciphers := []*vault.CipherRequest{}
	for _, ci := range r.Ciphers {
		if orgID != "" {
			ci.OrganizationID = &orgID
		}
		if ci.Fields == nil {
			ci.Fields = []vault.Field{}
		}
		enc, err := v.EncryptCipher(ci)
		if err != nil {
			return err
		}
		ciphers = append(ciphers, vault.NewCipherRequest(enc, uid))
	}
	type folderReq struct {
		ID   *string `json:"id,omitempty"`
		Name string  `json:"name"`
	}
	folders := []folderReq{}
	for _, f := range r.Folders {
		name, err := crypto.EncryptString(v.UserKey, f.Name)
		if err != nil {
			return err
		}
		folders = append(folders, folderReq{ID: f.ID, Name: name})
	}
	rels := func(in [][2]int) []kvp {
		out := []kvp{}
		for _, x := range in {
			out = append(out, kvp{x[0], x[1]})
		}
		return out
	}
	if orgID == "" {
		body := map[string]any{"ciphers": ciphers, "folders": folders, "folderRelationships": rels(r.FolderRelationships)}
		return c.api().Do(ctx, http.MethodPost, "/ciphers/import", body, nil)
	}
	orgKey, err := v.OrgKey(orgID)
	if err != nil {
		return err
	}
	type collectionReq struct {
		ID         *string `json:"id,omitempty"`
		Name       string  `json:"name"`
		ExternalID *string `json:"externalId,omitempty"`
	}
	cols := []collectionReq{}
	for _, col := range r.Collections {
		name, err := crypto.EncryptString(orgKey, col.Name)
		if err != nil {
			return err
		}
		cols = append(cols, collectionReq{ID: col.ID, Name: name, ExternalID: col.ExternalID})
	}
	body := map[string]any{
		"ciphers": ciphers, "folders": folders, "folderRelationships": rels(r.FolderRelationships),
		"collections": cols, "collectionRelationships": rels(r.CollectionRelationships),
	}
	return c.api().Do(ctx, http.MethodPost, "/ciphers/import-organization?organizationId="+orgID, body, nil)
}
