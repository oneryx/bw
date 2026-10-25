package cli

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/yangxiang/bw/internal/crypto"
	"github.com/yangxiang/bw/internal/output"
	"github.com/yangxiang/bw/internal/vault"
)

var exportFormats = []string{"csv", "json", "encrypted_json", "zip"}

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

func (a *App) runExport(cmd *cobra.Command, args []string) output.Response {
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	orgID := str(cmd, "organizationid")
	hasPassword := changed(cmd, "password")
	password := strings.TrimSpace(str(cmd, "password"))
	format := str(cmd, "format")
	if hasPassword && password != "" && format == "json" {
		format = "encrypted_json"
	}
	if format == "" {
		format = "csv"
	}
	valid := false
	for _, f := range exportFormats {
		valid = valid || f == format
	}
	if !valid {
		return output.Error("'%s' is not a supported export format. Supported formats: %s.", format, strings.Join(exportFormats, ", "))
	}
	if changed(cmd, "organizationid") && !isGUID(orgID) {
		return output.Error("`%s` is not a GUID.", orgID)
	}
	if format == "encrypted_json" && hasPassword && password == "" {
		password = promptSecret("Export file password:")
	}
	if password != "" && format == "csv" {
		return jsError("CSV does not support password protected export")
	}
	var data []byte
	var fileName string
	var err error
	if password != "" {
		format = "encrypted_json"
	}
	if orgID != "" {
		data, fileName, err = a.orgExport(v, orgID, format, password)
	} else {
		data, fileName, err = a.individualExport(v, format, password)
	}
	if err != nil {
		return jsError(err.Error())
	}
	return a.saveResultToFile(data, str(cmd, "output"), fileName)
}

func (a *App) individualExport(v *vault.Vault, format, password string) ([]byte, string, error) {
	ciphers := v.Ciphers()
	active := ciphers[:0:0]
	for _, c := range ciphers {
		if c.DeletedDate == nil {
			active = append(active, c)
		}
	}
	switch format {
	case "csv":
		folderName := map[string]string{}
		for _, f := range v.Folders() {
			folderName[f.ID] = f.Name
		}
		var rows []*vault.CSVRow
		for _, c := range active {
			if (c.Type != vault.TypeLogin && c.Type != vault.TypeSecureNote) || c.OrganizationID != nil {
				continue
			}
			row := &vault.CSVRow{Keys: []string{"folder", "favorite"}, Values: map[string]any{}}
			if c.FolderID != nil {
				if n, ok := folderName[*c.FolderID]; ok {
					row.Values["folder"] = n
				}
			}
			if c.Favorite {
				row.Values["favorite"] = 1
			}
			vault.CommonCSV(row, c)
			rows = append(rows, row)
		}
		return []byte(vault.UnparseCSV(rows)), exportFileName("", "csv"), nil
	case "json", "zip":
		doc := a.decryptedJSONExport(v, active)
		if format == "json" {
			return []byte(doc), exportFileName("", "json"), nil
		}
		data, err := a.zipExport(v, doc, active)
		return data, exportFileName("", "zip"), err
	case "encrypted_json":
		if password != "" {
			doc := a.decryptedJSONExport(v, active)
			out, err := passwordProtect(a, doc, password)
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
			c := &v.Data.Ciphers[i]
			if c.DeletedDate == nil && c.OrganizationID == nil {
				raw = append(raw, c)
			}
		}
		vault.SortByID(raw)
		for _, c := range raw {
			doc.Items = append(doc.Items, vault.EncryptedExportItemOutput(c, false))
		}
		return []byte(prettyJSON(doc)), exportFileName("", "encrypted_json"), nil
	}
	return nil, "", fmt.Errorf("unsupported format %s", format)
}

func (a *App) decryptedJSONExport(v *vault.Vault, active []*vault.Cipher) string {
	doc := struct {
		Encrypted bool                 `json:"encrypted"`
		Folders   []vault.ExportFolder `json:"folders"`
		Items     []vault.ExportItem   `json:"items"`
	}{Folders: []vault.ExportFolder{}, Items: []vault.ExportItem{}}
	for _, f := range v.Folders() {
		doc.Folders = append(doc.Folders, vault.ExportFolder{Name: f.Name, ID: f.ID})
	}
	for _, c := range active {
		if c.OrganizationID == nil {
			doc.Items = append(doc.Items, vault.ExportItemOutput(c, false))
		}
	}
	return prettyJSON(doc)
}

// passwordProtect mirrors buildPasswordExport using the account KDF settings.
func passwordProtect(a *App, clear, password string) (string, error) {
	st, _ := a.state()
	kdf := kdfParams(st.Account.KDF)
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
func (a *App) zipExport(v *vault.Vault, doc string, active []*vault.Cipher) ([]byte, error) {
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
	client, err := a.client()
	if err != nil {
		return nil, err
	}
	names := map[string]int{}
	for _, c := range active {
		if len(c.Attachments) == 0 || c.OrganizationID != nil {
			continue
		}
		folder := multiUnder.ReplaceAllString(unsafeName.ReplaceAllString(c.Name, "_"), "_")
		if n, ok := names[c.Name]; ok {
			names[c.Name] = n + 1
			folder += fmt.Sprintf("_%d", n)
		} else {
			names[c.Name] = 1
		}
		attNames := map[string]int{}
		for _, at := range c.Attachments {
			data, err := a.downloadAttachment(client, v, c.ID, at)
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
func (a *App) orgExport(v *vault.Vault, orgID, format, password string) ([]byte, string, error) {
	if format == "zip" {
		return nil, "", fmt.Errorf("Zip export not supported for organization")
	}
	orgKey, err := v.OrgKey(orgID)
	if err != nil {
		return nil, "", fmt.Errorf("No encryption key found for organization")
	}
	c, err := a.client()
	if err != nil {
		return nil, "", err
	}
	var res struct {
		Collections []vault.Collection `json:"collections"`
		Ciphers     []vault.Cipher     `json:"ciphers"`
	}
	if err := c.Get("/organizations/"+orgID+"/export", &res); err != nil {
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
			out, err = passwordProtect(a, out, password)
			return []byte(out), exportFileName("org", "encrypted_json"), err
		}
		return []byte(out), exportFileName("org", "json"), nil
	}
}
