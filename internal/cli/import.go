package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yangxiang/bw/internal/crypto"
	"github.com/yangxiang/bw/internal/importer"
	"github.com/yangxiang/bw/internal/output"
	"github.com/yangxiang/bw/internal/vault"
)

type kvp struct {
	Key   int `json:"key"`
	Value int `json:"value"`
}

func (a *App) runImport(cmd *cobra.Command, args []string) output.Response {
	format, path := "", ""
	if len(args) > 0 {
		format = args[0]
	}
	if len(args) > 1 {
		path = args[1]
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	orgID := str(cmd, "organizationid")
	if orgID != "" {
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
		st, _ := a.state()
		_ = json.Unmarshal(st.Account.Vault, &raw)
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
			return output.Error("You do not belong to an organization with the ID of %s. Check the organization ID and sync your vault.", orgID)
		}
		if org.Type > 1 && (org.Permissions == nil || !org.Permissions.AccessImportExport) {
			return output.Error("You are not authorized to import into the provided organization.")
		}
	}
	if boolean(cmd, "formats") {
		list := strings.Join(importer.Formats(), "\n")
		return output.Message("Supported input formats:", list, list)
	}
	if format == "" {
		return output.Error("`format` was not provided.")
	}
	if path == "" {
		return output.Error("`filepath` was not provided.")
	}
	imp := importer.Get(format, importer.Options{
		OrganizationID: orgID,
		Vault:          v,
		Password: func() (string, error) {
			pw, r := a.getPassword("", str(cmd, "passwordfile"), str(cmd, "passwordenv"), "Import file password:")
			if r != nil {
				return "", errors.New("Import file password is required. Provide --passwordfile or --passwordenv, or run interactively.")
			}
			return pw, nil
		},
	})
	if imp == nil {
		if slices.Contains(importer.OfficialFormats, format) {
			return output.Error("Import format `%s` is not supported by this CLI yet. Supported formats: %s.", format, strings.Join(importer.Formats(), ", "))
		}
		return output.Error("Proper importer type required.")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return output.Error("%v", err)
	}
	if len(contents) == 0 {
		return output.Error("Import file was empty.")
	}
	result, err := imp.Parse(string(contents))
	if err != nil {
		return output.Error("%v", err)
	}
	if err := a.importResult(v, result, orgID); err != nil {
		return output.Error("%v", err)
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	st, _ := a.state()
	if err := a.fullSync(c, st, true); err != nil {
		return output.Error("%v", err)
	}
	return output.Message("Imported "+path, "", "")
}

func badData(c *vault.Cipher) bool {
	return (c.Name == "" || c.Name == "--") && c.Type == vault.TypeLogin && c.Login != nil &&
		(c.Login.Password == nil || strings.TrimSpace(*c.Login.Password) == "")
}

// importResult mirrors ImportService.importImportResult and posts the data.
func (a *App) importResult(v *vault.Vault, r *importer.Result, orgID string) error {
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
	uid := a.userID()
	ciphers := []*vault.CipherRequest{}
	for _, c := range r.Ciphers {
		if orgID != "" {
			c.OrganizationID = &orgID
		}
		if c.Fields == nil {
			c.Fields = []vault.Field{}
		}
		enc, err := v.EncryptCipher(c)
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
	c, err := a.client()
	if err != nil {
		return err
	}
	if orgID == "" {
		body := map[string]any{"ciphers": ciphers, "folders": folders, "folderRelationships": rels(r.FolderRelationships)}
		return c.Do(http.MethodPost, "/ciphers/import", body, nil)
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
	return c.Do(http.MethodPost, "/ciphers/import-organization?organizationId="+orgID, body, nil)
}
