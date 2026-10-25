package bw

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/internal/output"
	"github.com/oneryx/bw/vault"
)

// ExportFormats lists the formats accepted by Export.
var ExportFormats = []string{"csv", "json", "encrypted_json", "zip"}

// ExportOptions configure Export.
type ExportOptions struct {
	// Format is one of ExportFormats; defaults to "csv".
	Format string
	// Password, when set, produces a password protected encrypted_json
	// export instead of one tied to the account key.
	Password string
	// OrganizationID exports an organization vault instead of the
	// individual vault.
	OrganizationID string
}

// Export exports the vault and returns the file content and its suggested
// file name.
func (c *Client) Export(ctx context.Context, opts ExportOptions) ([]byte, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, "", err
	}
	format := opts.Format
	if format == "" {
		format = "csv"
	}
	if !slices.Contains(ExportFormats, format) {
		return nil, "", fmt.Errorf("'%s' is not a supported export format. Supported formats: %s.", format, strings.Join(ExportFormats, ", "))
	}
	if opts.Password != "" {
		if format == "csv" {
			return nil, "", fmt.Errorf("CSV does not support password protected export")
		}
		format = "encrypted_json"
	}
	if opts.OrganizationID != "" {
		return c.orgExport(ctx, v, opts.OrganizationID, format, opts.Password)
	}
	return c.individualExport(ctx, v, format, opts.Password)
}

// exportFileName mirrors ExportHelper.getFileName (local time).
func exportFileName(prefix, format string) string {
	if format == "encrypted_json" {
		if prefix == "" {
			prefix = "encrypted"
		} else {
			prefix = "encrypted_" + prefix
		}
		format = "json"
	}
	if prefix != "" {
		prefix = "_" + prefix
	}
	return "bitwarden" + prefix + "_export_" + time.Now().Format("20060102150405") + "." + format
}

func prettyJSON(v any) string { return output.JSON(v, "  ") }

func (c *Client) individualExport(ctx context.Context, v *vault.Vault, format, password string) ([]byte, string, error) {
	ciphers := v.Ciphers()
	active := ciphers[:0:0]
	for _, ci := range ciphers {
		if ci.DeletedDate == nil {
			active = append(active, ci)
		}
	}
	switch format {
	case "csv":
		folderName := map[string]string{}
		for _, f := range v.Folders() {
			folderName[f.ID] = f.Name
		}
		var rows []*vault.CSVRow
		for _, ci := range active {
			if (ci.Type != vault.TypeLogin && ci.Type != vault.TypeSecureNote) || ci.OrganizationID != nil {
				continue
			}
			row := &vault.CSVRow{Keys: []string{"folder", "favorite"}, Values: map[string]any{}}
			if ci.FolderID != nil {
				if n, ok := folderName[*ci.FolderID]; ok {
					row.Values["folder"] = n
				}
			}
			if ci.Favorite {
				row.Values["favorite"] = 1
			}
			vault.CommonCSV(row, ci)
			rows = append(rows, row)
		}
		return []byte(vault.UnparseCSV(rows)), exportFileName("", "csv"), nil
	case "json", "zip":
		doc := decryptedJSONExport(v, active)
		if format == "json" {
			return []byte(doc), exportFileName("", "json"), nil
		}
		data, err := c.zipExport(ctx, v, doc, active)
		return data, exportFileName("", "zip"), err
	case "encrypted_json":
		if password != "" {
			doc := decryptedJSONExport(v, active)
			out, err := c.passwordProtect(doc, password)
			return []byte(out), exportFileName("", "encrypted_json"), err
		}
		validation, err := crypto.EncryptString(v.UserKey, uuid.NewString())
		if err != nil {
			return nil, "", err
		}
		doc := struct {
			Encrypted  bool                        `json:"encrypted"`
			Validation string                      `json:"encKeyValidation_DO_NOT_EDIT"`
			Folders    []vault.ExportFolder        `json:"folders"`
			Items      []vault.EncryptedExportItem `json:"items"`
		}{Encrypted: true, Validation: validation, Folders: []vault.ExportFolder{}, Items: []vault.EncryptedExportItem{}}
		for _, f := range v.Data.Folders {
			doc.Folders = append(doc.Folders, vault.ExportFolder{Name: f.Name, ID: f.ID})
		}
		raw := make([]*vault.Cipher, 0, len(v.Data.Ciphers))
		for i := range v.Data.Ciphers {
			ci := &v.Data.Ciphers[i]
			if ci.DeletedDate == nil && ci.OrganizationID == nil {
				raw = append(raw, ci)
			}
		}
		vault.SortByID(raw)
		for _, ci := range raw {
			doc.Items = append(doc.Items, vault.EncryptedExportItemOutput(ci, false))
		}
		return []byte(prettyJSON(doc)), exportFileName("", "encrypted_json"), nil
	}
	return nil, "", fmt.Errorf("unsupported format %s", format)
}

func decryptedJSONExport(v *vault.Vault, active []*vault.Cipher) string {
	doc := struct {
		Encrypted bool                 `json:"encrypted"`
		Folders   []vault.ExportFolder `json:"folders"`
		Items     []vault.ExportItem   `json:"items"`
	}{Folders: []vault.ExportFolder{}, Items: []vault.ExportItem{}}
	for _, f := range v.Folders() {
		doc.Folders = append(doc.Folders, vault.ExportFolder{Name: f.Name, ID: f.ID})
	}
	for _, ci := range active {
		if ci.OrganizationID == nil {
			doc.Items = append(doc.Items, vault.ExportItemOutput(ci, false))
		}
	}
	return prettyJSON(doc)
}

// passwordProtect mirrors buildPasswordExport using the account KDF settings.
func (c *Client) passwordProtect(clear, password string) (string, error) {
	kdf := kdfParams(c.st.Account.KDF)
	salt := base64.StdEncoding.EncodeToString(crypto.RandomBytes(16))
	km, err := crypto.DeriveKDF([]byte(password), []byte(salt), kdf)
	if err != nil {
		return "", err
	}
	key := crypto.StretchKey(km)
	validation, err := crypto.EncryptString(key, uuid.NewString())
	if err != nil {
		return "", err
	}
	data, err := crypto.EncryptString(key, clear)
	if err != nil {
		return "", err
	}
	doc := struct {
		Encrypted         bool   `json:"encrypted"`
		PasswordProtected bool   `json:"passwordProtected"`
		Salt              string `json:"salt"`
		KdfType           int    `json:"kdfType"`
		KdfIterations     int    `json:"kdfIterations"`
		Validation        string `json:"encKeyValidation_DO_NOT_EDIT"`
		Data              string `json:"data"`
		KdfMemory         *int   `json:"kdfMemory,omitempty"`
		KdfParallelism    *int   `json:"kdfParallelism,omitempty"`
	}{true, true, salt, kdf.Type, kdf.Iterations, validation, data, nil, nil}
	if kdf.Type == crypto.KDFArgon2id {
		doc.KdfMemory, doc.KdfParallelism = &kdf.Memory, &kdf.Parallelism
	}
	return prettyJSON(doc), nil
}

var (
	unsafeName    = regexp.MustCompile(`[/\\><:"|?*]`)
	unsafeAttName = regexp.MustCompile(`[/\\><:"|?*.]`)
	multiUnder    = regexp.MustCompile(`__+`)
)

// zipExport mirrors getDecryptedExportZip: data.json plus decrypted attachments.
func (c *Client) zipExport(ctx context.Context, v *vault.Vault, doc string, active []*vault.Cipher) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	now := time.Now()
	create := func(name string) (io.Writer, error) {
		return zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: now})
	}
	w, err := create("data.json")
	if err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte(doc)); err != nil {
		return nil, err
	}
	if _, err := create("attachments/"); err != nil {
		return nil, err
	}
	names := map[string]int{}
	for _, ci := range active {
		if len(ci.Attachments) == 0 || ci.OrganizationID != nil {
			continue
		}
		folder := multiUnder.ReplaceAllString(unsafeName.ReplaceAllString(ci.Name, "_"), "_")
		if n, ok := names[ci.Name]; ok {
			names[ci.Name] = n + 1
			folder += fmt.Sprintf("_%d", n)
		} else {
			names[ci.Name] = 1
		}
		attNames := map[string]int{}
		for _, at := range ci.Attachments {
			data, err := c.downloadAttachment(ctx, v, ci.ID, at.ID)
			if err != nil {
				continue
			}
			base, suffix := at.FileName, ""
			if parts := strings.Split(at.FileName, "."); len(parts) > 1 {
				base = strings.Join(parts[:len(parts)-1], "")
				suffix = "." + parts[len(parts)-1]
			}
			base = multiUnder.ReplaceAllString(unsafeAttName.ReplaceAllString(base, "_"), "_")
			full := base + suffix
			if n, ok := attNames[full]; ok {
				attNames[full] = n + 1
				full = fmt.Sprintf("%s_%d%s", base, n, suffix)
			} else {
				attNames[full] = 1
			}
			f, err := create("attachments/" + folder + "/" + full)
			if err != nil {
				return nil, err
			}
			if _, err := f.Write(data); err != nil {
				return nil, err
			}
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// orgExport mirrors getOrganizationExport (full export via the org API).
func (c *Client) orgExport(ctx context.Context, v *vault.Vault, orgID, format, password string) ([]byte, string, error) {
	if format == "zip" {
		return nil, "", fmt.Errorf("Zip export not supported for organization")
	}
	orgKey, err := v.OrgKey(orgID)
	if err != nil {
		return nil, "", fmt.Errorf("No encryption key found for organization")
	}
	var res struct {
		Collections []vault.Collection `json:"collections"`
		Ciphers     []vault.Cipher     `json:"ciphers"`
	}
	if err := c.api().Get(ctx, "/organizations/"+orgID+"/export", &res); err != nil {
		return nil, "", err
	}
	var live []vault.Cipher
	for _, ci := range res.Ciphers {
		if ci.DeletedDate == nil {
			live = append(live, ci)
		}
	}
	if format == "encrypted_json" && password == "" {
		validation, err := crypto.EncryptString(orgKey, uuid.NewString())
		if err != nil {
			return nil, "", err
		}
		doc := struct {
			Encrypted   bool                        `json:"encrypted"`
			Validation  string                      `json:"encKeyValidation_DO_NOT_EDIT"`
			Collections []vault.ExportCollection    `json:"collections"`
			Items       []vault.EncryptedExportItem `json:"items"`
		}{Encrypted: true, Validation: validation, Collections: []vault.ExportCollection{}, Items: []vault.EncryptedExportItem{}}
		for _, col := range res.Collections {
			doc.Collections = append(doc.Collections, vault.ExportCollection{ID: col.ID, OrganizationID: col.OrganizationID, Name: col.Name, ExternalID: col.ExternalID})
		}
		for i := range live {
			doc.Items = append(doc.Items, vault.EncryptedExportItemOutput(&live[i], true))
		}
		return []byte(prettyJSON(doc)), exportFileName("org", "encrypted_json"), nil
	}
	cols := map[string]string{}
	var decCols []vault.ExportCollection
	for _, col := range res.Collections {
		name := v.DecryptCollectionName(orgID, col.Name)
		cols[col.ID] = name
		decCols = append(decCols, vault.ExportCollection{ID: col.ID, OrganizationID: col.OrganizationID, Name: name, ExternalID: col.ExternalID})
	}
	var dec []*vault.Cipher
	for i := range live {
		dec = append(dec, v.Decrypt(&live[i]))
	}
	switch format {
	case "csv":
		var rows []*vault.CSVRow
		for _, ci := range dec {
			if ci.Type != vault.TypeLogin && ci.Type != vault.TypeSecureNote {
				continue
			}
			names := []string{}
			for _, id := range ci.CollectionIDs {
				if n, ok := cols[id]; ok {
					names = append(names, n)
				}
			}
			row := &vault.CSVRow{Keys: []string{"collections"}, Values: map[string]any{"collections": names}}
			vault.CommonCSV(row, ci)
			rows = append(rows, row)
		}
		return []byte(vault.UnparseCSV(rows)), exportFileName("org", "csv"), nil
	default:
		doc := struct {
			Encrypted   bool                     `json:"encrypted"`
			Collections []vault.ExportCollection `json:"collections"`
			Items       []vault.ExportItem       `json:"items"`
		}{Collections: []vault.ExportCollection{}, Items: []vault.ExportItem{}}
		doc.Collections = append(doc.Collections, decCols...)
		for _, ci := range dec {
			doc.Items = append(doc.Items, vault.ExportItemOutput(ci, true))
		}
		out := prettyJSON(doc)
		if format == "encrypted_json" {
			out, err = c.passwordProtect(out, password)
			return []byte(out), exportFileName("org", "encrypted_json"), err
		}
		return []byte(out), exportFileName("org", "json"), nil
	}
}
