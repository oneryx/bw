package cli

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/yangxiang/bw/internal/api"
	"github.com/yangxiang/bw/internal/crypto"
	"github.com/yangxiang/bw/internal/output"
	"github.com/yangxiang/bw/internal/vault"
)

// serveMode is set while `bw serve` runs (BW_SERVE in the official CLI);
// commands must never read stdin or prompt then.
var serveMode bool

// readStdin mirrors CliUtils.readStdin: empty when stdin is a terminal.
func readStdin() string {
	if serveMode || term.IsTerminal(int(os.Stdin.Fd())) {
		return ""
	}
	b, _ := io.ReadAll(stdinReader)
	return string(b)
}

// decodeLenientBase64 behaves like Node's Buffer.from(s, "base64").
func decodeLenientBase64(s string) []byte {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/':
			sb.WriteRune(r)
		case r == '-':
			sb.WriteRune('+')
		case r == '_':
			sb.WriteRune('/')
		case r == '=':
			goto done
		}
	}
done:
	clean := sb.String()
	if len(clean)%4 == 1 { // a lone trailing sextet carries no full byte
		clean = clean[:len(clean)-1]
	}
	b, _ := base64.RawStdEncoding.DecodeString(clean)
	return b
}

// decodeRequest reads encodedJson (argument or stdin) into v.
func decodeRequest(arg string, v any) *output.Response {
	if arg == "" {
		arg = readStdin()
	}
	if arg == "" {
		r := output.Error("`requestJson` was not provided.")
		return &r
	}
	if err := json.Unmarshal(decodeLenientBase64(arg), v); err != nil {
		r := output.Error("Error parsing the encoded request data.")
		return &r
	}
	return nil
}

func errResp(err error) output.Response {
	if r, ok := err.(*output.Response); ok {
		return *r
	}
	return output.Error("%v", err)
}

// jsError formats errors thrown as JS Error objects ("Error: msg").
func jsError(msg string) output.Response { return output.Error("Error: %s", msg) }

// saveCipher caches the server's cipher response and returns the decrypted item.
func (a *App) saveCipher(v *vault.Vault, raw json.RawMessage) output.Response {
	var enc vault.Cipher
	if err := json.Unmarshal(raw, &enc); err != nil {
		return output.Error("%v", err)
	}
	st, _ := a.state()
	if err := st.Account.UpsertVaultObject("ciphers", raw); err != nil {
		return output.Error("%v", err)
	}
	if err := st.Save(); err != nil {
		return output.Error("%v", err)
	}
	return output.Success(vault.ItemOutput(v.Decrypt(&enc)))
}

// --- create ---

func (a *App) runCreate(cmd *cobra.Command, args []string) output.Response {
	obj := args[0]
	if r := validateObject(obj, createObjects); r != nil {
		return *r
	}
	encoded := ""
	if len(args) > 1 {
		encoded = args[1]
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	switch strings.ToLower(obj) {
	case "item":
		var in vault.CipherInput
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		view := vault.ApplyInput(&in, nil)
		enc, err := v.EncryptCipher(view)
		if err != nil {
			return output.Error("%v", err)
		}
		req := vault.NewCipherRequest(enc, a.userID())
		var raw json.RawMessage
		if enc.OrganizationID != nil && *enc.OrganizationID != "" {
			body := map[string]any{"cipher": req, "collectionIds": nonNil(view.CollectionIDs)}
			err = c.Do(http.MethodPost, "/ciphers/create", body, &raw)
		} else {
			err = c.Do(http.MethodPost, "/ciphers", req, &raw)
		}
		if err != nil {
			return errResp(err)
		}
		return a.saveCipher(v, raw)
	case "folder":
		var in struct {
			Name *string `json:"name"`
		}
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		name, err := crypto.EncryptString(v.UserKey, deref(in.Name))
		if err != nil {
			return output.Error("%v", err)
		}
		var raw json.RawMessage
		if err := c.Do(http.MethodPost, "/folders", map[string]string{"name": name}, &raw); err != nil {
			return errResp(err)
		}
		return a.saveFolder(v, raw)
	case "attachment":
		return a.createAttachment(v, c, str(cmd, "itemid"), str(cmd, "file"))
	case "org-collection":
		var in orgCollectionInput
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		return a.saveOrgCollection(v, c, "", &in, str(cmd, "organizationid"))
	}
	return output.Error("Unknown object.")
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (a *App) saveFolder(v *vault.Vault, raw json.RawMessage) output.Response {
	var f vault.Folder
	if err := json.Unmarshal(raw, &f); err != nil {
		return output.Error("%v", err)
	}
	st, _ := a.state()
	if err := st.Account.UpsertVaultObject("folders", raw); err != nil {
		return output.Error("%v", err)
	}
	if err := st.Save(); err != nil {
		return output.Error("%v", err)
	}
	name, err := crypto.DecryptString(v.UserKey, f.Name)
	if err != nil {
		name = vault.DecryptError
	}
	f.Name = name
	return output.Success(vault.FolderOutput(f))
}

type orgCollectionInput struct {
	OrganizationID string                    `json:"organizationId"`
	Name           *string                   `json:"name"`
	ExternalID     *string                   `json:"externalId"`
	Groups         []vault.SelectionReadOnly `json:"groups"`
	Users          []vault.SelectionReadOnly `json:"users"`
}

// saveOrgCollection creates (id == "") or updates an organization collection.
func (a *App) saveOrgCollection(v *vault.Vault, c *api.Client, id string, in *orgCollectionInput, optOrgID string) output.Response {
	orgID := optOrgID
	if strings.TrimSpace(orgID) == "" {
		orgID = in.OrganizationID
	}
	if strings.TrimSpace(orgID) == "" {
		return output.Error("An organization id is required, either via the `--organizationid` option " +
			"(or `organizationId` query parameter when using `bw serve`), or the request's `organizationId` property.")
	}
	if !isGUID(orgID) {
		return output.Error("`%s` is not a GUID.", orgID)
	}
	if strings.TrimSpace(optOrgID) != "" && strings.TrimSpace(in.OrganizationID) != "" && optOrgID != in.OrganizationID {
		return output.Error("The `--organizationid` option (or `organizationId` query parameter) does not match " +
			"the request's `organizationId` property.")
	}
	if in.Name == nil || strings.TrimSpace(*in.Name) == "" {
		return output.Error("Collection name is required.")
	}
	key, err := v.OrgKey(orgID)
	if err != nil {
		return jsError(err.Error())
	}
	name, err := crypto.EncryptString(key, *in.Name)
	if err != nil {
		return output.Error("%v", err)
	}
	users := in.Users
	if users == nil && id == "" {
		// Grant the creating member manage access, like the official CLI.
		var orgs struct {
			Data []struct {
				ID                 string `json:"id"`
				OrganizationUserID string `json:"organizationUserId"`
			} `json:"data"`
		}
		if err := c.Get("/organizations", &orgs); err == nil {
			for _, o := range orgs.Data {
				if o.ID == orgID && o.OrganizationUserID != "" {
					users = []vault.SelectionReadOnly{{ID: o.OrganizationUserID, Manage: true}}
				}
			}
		}
	}
	body := map[string]any{"name": name, "externalId": in.ExternalID, "groups": in.Groups, "users": users}
	var res struct {
		ID     string                    `json:"id"`
		Groups []vault.SelectionReadOnly `json:"groups"`
		Users  []vault.SelectionReadOnly `json:"users"`
	}
	path := "/organizations/" + orgID + "/collections"
	method := http.MethodPost
	if id != "" {
		path += "/" + id
		method = http.MethodPut
	}
	if err := c.Do(method, path, body, &res); err != nil {
		return errResp(err)
	}
	if res.Groups == nil {
		res.Groups = []vault.SelectionReadOnly{}
	}
	if res.Users == nil {
		res.Users = []vault.SelectionReadOnly{}
	}
	return output.Success(vault.OrgCollectionResponse{
		Object: "org-collection", ID: res.ID, OrganizationID: orgID, Name: *in.Name,
		ExternalID: in.ExternalID, Groups: res.Groups, Users: res.Users,
	})
}

// createAttachment encrypts and uploads a file to an item.
func (a *App) createAttachment(v *vault.Vault, c *api.Client, itemID, file string) output.Response {
	if itemID == "" {
		return output.Error("`itemid` option is required.")
	}
	if file == "" {
		return output.Error("`file` option is required.")
	}
	abs, _ := filepath.Abs(file)
	data, err := os.ReadFile(file)
	if err != nil {
		return output.Error("Cannot find file at %s", abs)
	}
	fileName := filepath.Base(abs)
	raw := v.RawCipher(strings.ToLower(itemID))
	if raw == nil {
		return notFound()
	}
	cipherKey, err := v.CipherKey(raw)
	if err != nil {
		return output.Error("%v", err)
	}
	attKey := crypto.GenerateSymmetricKey()
	encKey, err := crypto.Encrypt(cipherKey, attKey.Bytes())
	if err != nil {
		return output.Error("%v", err)
	}
	encName, err := crypto.EncryptString(cipherKey, fileName)
	if err != nil {
		return output.Error("%v", err)
	}
	encData, err := crypto.EncryptBuffer(attKey, data)
	if err != nil {
		return output.Error("%v", err)
	}
	var up struct {
		AttachmentID   string          `json:"attachmentId"`
		URL            string          `json:"url"`
		FileUploadType int             `json:"fileUploadType"`
		CipherResponse json.RawMessage `json:"cipherResponse"`
	}
	body := map[string]any{"key": encKey.String(), "fileName": encName, "fileSize": len(encData), "adminRequest": false}
	if err := c.Do(http.MethodPost, "/ciphers/"+raw.ID+"/attachment/v2", body, &up); err != nil {
		return errResp(err)
	}
	if up.FileUploadType != 0 {
		return output.Error("Unsupported attachment upload type %d.", up.FileUploadType)
	}
	mp, err := api.Multipart(nil, "data", encName, encData)
	if err != nil {
		return output.Error("%v", err)
	}
	// Direct uploads go to the API itself, like apiService.postAttachmentFile.
	uploadURL := c.Env.APIURL() + "/ciphers/" + raw.ID + "/attachment/" + up.AttachmentID
	if err := c.SendRaw(http.MethodPost, uploadURL, mp, nil); err != nil {
		_ = c.Do(http.MethodDelete, "/ciphers/"+raw.ID+"/attachment/"+up.AttachmentID, nil, nil)
		return errResp(err)
	}
	var updated json.RawMessage
	if err := c.Get("/ciphers/"+raw.ID, &updated); err != nil {
		return errResp(err)
	}
	return a.saveCipher(v, updated)
}

// --- edit ---

func (a *App) runEdit(cmd *cobra.Command, args []string) output.Response {
	obj, id := args[0], strings.ToLower(args[1])
	if r := validateObject(obj, editObjects); r != nil {
		return *r
	}
	encoded := ""
	if len(args) > 2 {
		encoded = args[2]
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	switch strings.ToLower(obj) {
	case "item":
		var in vault.CipherInput
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		raw := v.RawCipher(id)
		if raw == nil {
			return notFound()
		}
		if raw.Edit != nil && !*raw.Edit {
			return output.Error("You do not have permission to edit this item")
		}
		orig := v.Decrypt(raw)
		if orig.DeletedDate != nil {
			return output.Error("You may not edit a deleted item. Use the restore command first.")
		}
		view := vault.ApplyInput(&in, orig)
		if orig.ViewPassword != nil && !*orig.ViewPassword {
			restoreRedacted(view, orig)
		}
		vault.UpdatePasswordHistory(view, orig)
		enc, err := v.EncryptCipher(view)
		if err != nil {
			return output.Error("%v", err)
		}
		var out json.RawMessage
		if err := c.Do(http.MethodPut, "/ciphers/"+raw.ID, vault.NewCipherRequest(enc, a.userID()), &out); err != nil {
			return errResp(err)
		}
		return a.saveCipher(v, out)
	case "item-collections":
		var ids []string
		if r := decodeRequest(encoded, &ids); r != nil {
			return *r
		}
		raw := v.RawCipher(id)
		if raw == nil {
			return notFound()
		}
		if raw.OrganizationID == nil {
			return output.Error("Item does not belong to an organization. Consider moving it first.")
		}
		if raw.ViewPassword != nil && !*raw.ViewPassword {
			return output.Error("You do not have permission to edit this item")
		}
		if err := c.Do(http.MethodPost, "/ciphers/"+raw.ID+"/collections", map[string]any{"collectionIds": nonNil(ids)}, nil); err != nil {
			return errResp(err)
		}
		var out json.RawMessage
		if err := c.Get("/ciphers/"+raw.ID, &out); err != nil {
			return errResp(err)
		}
		return a.saveCipher(v, out)
	case "folder":
		var in struct {
			Name *string `json:"name"`
		}
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		found := false
		for _, f := range v.Data.Folders {
			found = found || f.ID == id
		}
		if !found {
			return notFound()
		}
		name, err := crypto.EncryptString(v.UserKey, deref(in.Name))
		if err != nil {
			return output.Error("%v", err)
		}
		var raw json.RawMessage
		if err := c.Do(http.MethodPut, "/folders/"+id, map[string]string{"name": name}, &raw); err != nil {
			return errResp(err)
		}
		return a.saveFolder(v, raw)
	case "org-collection":
		var in orgCollectionInput
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		if !isGUID(id) {
			return output.Error("`%s` is not a GUID.", id)
		}
		return a.saveOrgCollection(v, c, id, &in, str(cmd, "organizationid"))
	}
	return output.Error("Unknown object.")
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

// --- delete / restore / archive ---

func (a *App) runDelete(cmd *cobra.Command, args []string) output.Response {
	obj, id := args[0], strings.ToLower(args[1])
	if r := validateObject(obj, deleteObjects); r != nil {
		return *r
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	st, _ := a.state()
	switch strings.ToLower(obj) {
	case "item":
		raw := v.RawCipher(id)
		if raw == nil {
			return notFound()
		}
		if raw.OrganizationID != nil && raw.Edit != nil && !*raw.Edit {
			return output.Error("You do not have permission to delete this item.")
		}
		if boolean(cmd, "permanent") {
			if err := c.Do(http.MethodDelete, "/ciphers/"+raw.ID, nil, nil); err != nil {
				return errResp(err)
			}
			if err := st.Account.DeleteVaultObject("ciphers", raw.ID); err != nil {
				return output.Error("%v", err)
			}
			if err := st.Save(); err != nil {
				return output.Error("%v", err)
			}
			return output.Success(nil)
		}
		if err := c.Do(http.MethodPut, "/ciphers/"+raw.ID+"/delete", nil, nil); err != nil {
			return errResp(err)
		}
		return a.refreshCipher(c, raw.ID)
	case "attachment":
		itemID := strings.ToLower(str(cmd, "itemid"))
		if itemID == "" {
			return output.Error("`itemid` option is required.")
		}
		raw := v.RawCipher(itemID)
		if raw == nil {
			return notFound()
		}
		if len(raw.Attachments) == 0 {
			return output.Error("No attachments available for this item.")
		}
		var attID string
		for _, at := range raw.Attachments {
			if strings.ToLower(at.ID) == id {
				attID = at.ID
			}
		}
		if attID == "" {
			return output.Error("Attachment `%s` was not found.", id)
		}
		if err := c.Do(http.MethodDelete, "/ciphers/"+raw.ID+"/attachment/"+attID, nil, nil); err != nil {
			return errResp(err)
		}
		return a.refreshCipher(c, raw.ID)
	case "folder":
		found := false
		for _, f := range v.Data.Folders {
			found = found || f.ID == id
		}
		if !found {
			return notFound()
		}
		if err := c.Do(http.MethodDelete, "/folders/"+id, nil, nil); err != nil {
			return errResp(err)
		}
		// Items in the folder move to "No Folder"; resync to reflect that.
		if err := a.fullSync(c, st, true); err != nil {
			return output.Error("%v", err)
		}
		return output.Success(nil)
	case "org-collection":
		orgID := str(cmd, "organizationid")
		if orgID == "" {
			return output.Error("`organizationid` options is required.")
		}
		if !isGUID(id) {
			return output.Error("`%s` is not a GUID.", id)
		}
		if !isGUID(orgID) {
			return output.Error("`%s` is not a GUID.", orgID)
		}
		if err := c.Do(http.MethodDelete, "/organizations/"+orgID+"/collections/"+id, nil, nil); err != nil {
			return errResp(err)
		}
		_ = st.Account.DeleteVaultObject("collections", id)
		_ = st.Save()
		return output.Success(nil)
	}
	return output.Error("Unknown object.")
}

// refreshCipher re-fetches a cipher into the cache and returns an empty success.
func (a *App) refreshCipher(c *api.Client, id string) output.Response {
	st, _ := a.state()
	var raw json.RawMessage
	if err := c.Get("/ciphers/"+id, &raw); err != nil {
		return errResp(err)
	}
	if err := st.Account.UpsertVaultObject("ciphers", raw); err != nil {
		return output.Error("%v", err)
	}
	if err := st.Save(); err != nil {
		return output.Error("%v", err)
	}
	return output.Success(nil)
}

func (a *App) runRestore(cmd *cobra.Command, args []string) output.Response {
	obj, id := args[0], strings.ToLower(args[1])
	if r := validateObject(obj, restoreObjects); r != nil {
		return *r
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	raw := v.RawCipher(id)
	if raw == nil {
		return notFound()
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	if raw.ArchivedDate != nil && raw.DeletedDate == nil {
		if err := c.Do(http.MethodPut, "/ciphers/"+raw.ID+"/unarchive", nil, nil); err != nil {
			return errResp(err)
		}
		return a.refreshCipher(c, raw.ID)
	}
	if raw.DeletedDate == nil {
		return output.Error("Cipher is not in trash.")
	}
	if err := c.Do(http.MethodPut, "/ciphers/"+raw.ID+"/restore", nil, nil); err != nil {
		return errResp(err)
	}
	return a.refreshCipher(c, raw.ID)
}

func (a *App) runArchive(cmd *cobra.Command, args []string) output.Response {
	obj, id := args[0], strings.ToLower(args[1])
	if r := validateObject(obj, archiveObjects); r != nil {
		return *r
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	raw := v.RawCipher(id)
	if raw == nil {
		return notFound()
	}
	if raw.ArchivedDate != nil {
		return output.Error("Item is already archived.")
	}
	if raw.DeletedDate != nil {
		return output.Error("Item is in the trash, the item must be restored before archiving.")
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	if err := c.Do(http.MethodPut, "/ciphers/"+raw.ID+"/archive", nil, nil); err != nil {
		if api.IsNotFound(err) {
			return output.Error("Archiving is not supported by this server.")
		}
		return errResp(err)
	}
	return a.refreshCipher(c, raw.ID)
}

// --- move / share ---

func (a *App) runMove(cmd *cobra.Command, args []string) output.Response {
	id, orgID := strings.ToLower(args[0]), strings.ToLower(args[1])
	encoded := ""
	if len(args) > 2 {
		encoded = args[2]
	}
	var ids []string
	if encoded == "" {
		encoded = readStdin()
	}
	if encoded == "" {
		return output.Error("`requestJson` was not provided.")
	}
	if err := json.Unmarshal(decodeLenientBase64(encoded), &ids); err != nil {
		return output.Error("Error parsing the encoded request data.")
	}
	if len(ids) == 0 {
		return output.Error("You must provide at least one collection id for this item.")
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	raw := v.RawCipher(id)
	if raw == nil {
		return notFound()
	}
	if raw.OrganizationID != nil {
		return output.Error("This item already belongs to an organization.")
	}
	var org *vault.ProfileOrganization
	for _, o := range v.Data.Profile.Organizations {
		if o.ID == orgID {
			org = &o
		}
	}
	if org == nil {
		return output.Error("Organization not found.")
	}
	for _, cid := range ids {
		ok := false
		for _, col := range v.Data.Collections {
			if col.ID == cid && col.OrganizationID == orgID && !col.ReadOnly {
				ok = true
			}
		}
		if !ok {
			return output.Error("You do not have permission to add items to this collection.")
		}
	}
	view := v.Decrypt(raw)
	userCipherKey, err := v.CipherKey(raw)
	if err != nil {
		return output.Error("%v", err)
	}
	orgKey, err := v.OrgKey(orgID)
	if err != nil {
		return jsError(err.Error())
	}
	// Re-wrap per-item and attachment keys with the organization key.
	if view.Key != nil {
		k, err := crypto.Encrypt(orgKey, userCipherKey.Bytes())
		if err != nil {
			return output.Error("%v", err)
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
			return output.Error("%v", err)
		}
		wrapped, err := crypto.Encrypt(orgKey, ak.Bytes())
		if err != nil {
			return output.Error("%v", err)
		}
		s := wrapped.String()
		at.Key = &s
	}
	view.OrganizationID = &orgID
	view.CollectionIDs = ids
	enc, err := v.EncryptCipher(view)
	if err != nil {
		return output.Error("%v", err)
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	var out json.RawMessage
	body := map[string]any{"cipher": vault.NewCipherRequest(enc, a.userID()), "collectionIds": ids}
	if err := c.Do(http.MethodPut, "/ciphers/"+raw.ID+"/share", body, &out); err != nil {
		return errResp(err)
	}
	// Re-open so the new organization ownership is decrypted with the org key.
	return a.saveCipher(v, out)
}

// --- confirm ---

func (a *App) runConfirm(cmd *cobra.Command, args []string) output.Response {
	obj, id := args[0], strings.ToLower(args[1])
	if r := validateObject(obj, confirmObjects); r != nil {
		return *r
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	orgID := str(cmd, "organizationid")
	if orgID == "" {
		return output.Error("--organizationid <organizationid> required.")
	}
	if !isGUID(id) {
		return output.Error("`%s` is not a GUID.", id)
	}
	if !isGUID(orgID) {
		return output.Error("`%s` is not a GUID.", orgID)
	}
	orgKey, err := v.OrgKey(orgID)
	if err != nil {
		return jsError(err.Error())
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	var member struct {
		UserID string `json:"userId"`
		Status int    `json:"status"`
	}
	if err := c.Get("/organizations/"+orgID+"/users/"+id, &member); err != nil {
		if api.IsNotFound(err) {
			return jsError("Member id does not exist for this organization.")
		}
		return errResp(err)
	}
	switch member.Status {
	case 0:
		return jsError("User must accept the invitation before they can be confirmed.")
	case 2:
		return jsError("User is already confirmed.")
	case -1:
		return jsError("User is revoked and cannot be confirmed.")
	case 1:
	default:
		return jsError("User is not in a valid state to be confirmed.")
	}
	var pk struct {
		PublicKey string `json:"publicKey"`
	}
	if err := c.Get("/users/"+member.UserID+"/public-key", &pk); err != nil {
		return errResp(err)
	}
	pub, err := base64.StdEncoding.DecodeString(pk.PublicKey)
	if err != nil {
		return output.Error("%v", err)
	}
	wrapped, err := crypto.EncryptRSA(pub, orgKey.Bytes())
	if err != nil {
		return output.Error("%v", err)
	}
	collName, err := crypto.EncryptString(orgKey, "My items")
	if err != nil {
		return output.Error("%v", err)
	}
	body := map[string]string{"key": wrapped, "defaultUserCollectionName": collName}
	if err := c.Do(http.MethodPost, "/organizations/"+orgID+"/users/"+id+"/confirm", body, nil); err != nil {
		return errResp(err)
	}
	return output.Success(nil)
}

func (a *App) userID() string {
	st, _ := a.state()
	if st == nil || st.Account == nil {
		return ""
	}
	return st.Account.UserID
}
