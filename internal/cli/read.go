package cli

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yangxiang/bw/internal/api"
	"github.com/yangxiang/bw/internal/crypto"
	"github.com/yangxiang/bw/internal/output"
	"github.com/yangxiang/bw/internal/totp"
	"github.com/yangxiang/bw/internal/vault"
)

var guidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func isGUID(s string) bool { return guidRe.MatchString(s) }

// validateObject mirrors the official "Unknown object" check. `bw serve`
// skips the program-level validation and reports the command's own message.
func validateObject(obj string, valid []string) *output.Response {
	if slices.Contains(valid, obj) {
		return nil
	}
	if serveMode {
		r := output.Error("Unknown object.")
		return &r
	}
	r := output.Error(`Unknown object "%s". Allowed objects are: %s.`, obj, strings.Join(valid, ", "))
	return &r
}

func multipleResults(ids []string) output.Response {
	msg := "More than one result was found. Try getting a specific object by `id` instead. The following objects were found:"
	for _, id := range ids {
		msg += "\n" + id
	}
	r := output.Error("%s", msg)
	r.Data = ids
	return r
}

func notFound() output.Response { return output.Error("Not found.") }

func isNullOrWhitespace(s *string) bool { return s == nil || strings.TrimSpace(*s) == "" }

// --- list ---

func (a *App) runList(cmd *cobra.Command, args []string) output.Response {
	obj := args[0]
	if r := validateObject(obj, listObjects); r != nil {
		return *r
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	search := str(cmd, "search")
	orgID := str(cmd, "organizationid")
	switch strings.ToLower(obj) {
	case "items":
		return a.listItems(cmd, v)
	case "folders":
		folders := v.Folders()
		folders = append(folders, vault.Folder{Name: "No Folder"})
		if strings.TrimSpace(search) != "" {
			folders = vault.SearchByName(folders, search, func(f vault.Folder) string { return f.Name })
		}
		out := []vault.FolderResponse{}
		for _, f := range folders {
			out = append(out, vault.FolderOutput(f))
		}
		return output.List(out)
	case "collections":
		cols := v.Collections()
		if orgID != "" {
			cols = slices.DeleteFunc(cols, func(c vault.Collection) bool { return c.OrganizationID != orgID })
		}
		if strings.TrimSpace(search) != "" {
			cols = vault.SearchByName(cols, search, func(c vault.Collection) string { return c.Name })
		}
		out := []vault.CollectionResponse{}
		for _, c := range cols {
			out = append(out, vault.CollectionOutput(c))
		}
		return output.List(out)
	case "organizations":
		orgs := v.Organizations()
		if strings.TrimSpace(search) != "" {
			orgs = vault.SearchByName(orgs, search, func(o vault.ProfileOrganization) string { return o.Name })
		}
		out := []vault.OrganizationResponse{}
		for _, o := range orgs {
			out = append(out, vault.OrganizationOutput(o))
		}
		return output.List(out)
	case "org-collections":
		org, r := a.requireOrg(v, orgID)
		if r != nil {
			return *r
		}
		c, err := a.client()
		if err != nil {
			return output.Error("%v", err)
		}
		var res struct {
			Data []vault.Collection `json:"data"`
		}
		path := "/collections"
		if org.Type <= 1 { // owner/admin can view all collections
			path = "/organizations/" + orgID + "/collections"
		}
		if err := c.Get(path, &res); err != nil {
			return output.Error("%v", err)
		}
		cols := []vault.Collection{}
		for _, col := range res.Data {
			if col.OrganizationID == orgID {
				col.Name = v.DecryptCollectionName(orgID, col.Name)
				cols = append(cols, col)
			}
		}
		if strings.TrimSpace(search) != "" {
			cols = vault.SearchByName(cols, search, func(c vault.Collection) string { return c.Name })
		}
		out := []vault.CollectionResponse{}
		for _, col := range cols {
			out = append(out, vault.APICollectionOutput(col))
		}
		return output.List(out)
	case "org-members":
		if _, r := a.requireOrg(v, orgID); r != nil {
			return *r
		}
		c, err := a.client()
		if err != nil {
			return output.Error("%v", err)
		}
		var res struct {
			Data []struct {
				ID               string  `json:"id"`
				Email            string  `json:"email"`
				Name             *string `json:"name"`
				Status           int     `json:"status"`
				Type             int     `json:"type"`
				TwoFactorEnabled bool    `json:"twoFactorEnabled"`
			} `json:"data"`
		}
		if err := c.Get("/organizations/"+orgID+"/users", &res); err != nil {
			return output.Error("%v", err)
		}
		out := []vault.OrgMemberResponse{}
		for _, u := range res.Data {
			out = append(out, vault.OrgMemberResponse{Object: "org-member", ID: u.ID, Email: u.Email,
				Name: u.Name, Status: u.Status, Type: u.Type, TwoFactorEnabled: u.TwoFactorEnabled})
		}
		return output.List(out)
	}
	return output.Error("Unknown object.")
}

// requireOrg validates --organizationid for org-scoped commands.
func (a *App) requireOrg(v *vault.Vault, orgID string) (*vault.ProfileOrganization, *output.Response) {
	fail := func(format string, args ...any) (*vault.ProfileOrganization, *output.Response) {
		r := output.Error(format, args...)
		return nil, &r
	}
	if orgID == "" {
		return fail("`organizationid` option is required.")
	}
	if !isGUID(orgID) {
		return fail("`%s` is not a GUID.", orgID)
	}
	for _, o := range v.Data.Profile.Organizations {
		if o.ID == orgID {
			return &o, nil
		}
	}
	return fail("Organization not found.")
}

func isDeleted(c *vault.Cipher) bool  { return c.DeletedDate != nil }
func isArchived(c *vault.Cipher) bool { return c.ArchivedDate != nil }

func (a *App) listItems(cmd *cobra.Command, v *vault.Vault) output.Response {
	trash, archived := boolean(cmd, "trash"), boolean(cmd, "archived")
	folderID, collectionID, orgID := str(cmd, "folderid"), str(cmd, "collectionid"), str(cmd, "organizationid")
	search, rawURL := str(cmd, "search"), str(cmd, "url")

	ciphers := v.Ciphers()
	if strings.TrimSpace(rawURL) != "" {
		eq := v.EquivalentDomains(rawURL)
		ciphers = slices.DeleteFunc(ciphers, func(c *vault.Cipher) bool {
			return isDeleted(c) || isArchived(c) || !c.MatchesURL(rawURL, eq, vault.MatchDomain)
		})
	}
	stateOK := func(c *vault.Cipher) bool { return trash == isDeleted(c) && archived == isArchived(c) }

	if folderID != "" || collectionID != "" || orgID != "" {
		ciphers = slices.DeleteFunc(ciphers, func(c *vault.Cipher) bool {
			if !stateOK(c) {
				return true
			}
			if folderID != "" {
				if folderID == "notnull" && c.FolderID != nil {
					return false
				}
				if (folderID == "null" && c.FolderID == nil) || (c.FolderID != nil && *c.FolderID == folderID) {
					return false
				}
			}
			if orgID != "" {
				if orgID == "notnull" && c.OrganizationID != nil {
					return false
				}
				if (orgID == "null" && c.OrganizationID == nil) || (c.OrganizationID != nil && *c.OrganizationID == orgID) {
					return false
				}
			}
			if collectionID != "" {
				if collectionID == "notnull" && len(c.CollectionIDs) > 0 {
					return false
				}
				if collectionID == "null" && len(c.CollectionIDs) == 0 {
					return false
				}
				if collectionID != "null" && slices.Contains(c.CollectionIDs, collectionID) {
					return false
				}
			}
			return true
		})
	} else if strings.TrimSpace(search) == "" {
		ciphers = slices.DeleteFunc(ciphers, func(c *vault.Cipher) bool { return !stateOK(c) })
	}
	if strings.TrimSpace(search) != "" {
		ciphers = slices.DeleteFunc(ciphers, func(c *vault.Cipher) bool { return !stateOK(c) })
		ciphers = vault.SearchCiphers(ciphers, search)
	}
	out := []vault.ItemResponse{}
	for _, c := range ciphers {
		out = append(out, vault.ItemOutput(c))
	}
	return output.List(out)
}

// --- get ---

func (a *App) runGet(cmd *cobra.Command, args []string) output.Response {
	obj, id := args[0], strings.ToLower(args[1])
	if r := validateObject(obj, getObjects); r != nil {
		return *r
	}
	if strings.ToLower(obj) == "template" {
		t, ok := vault.Templates[strings.ToLower(id)]
		if !ok {
			if id == "send.file" || id == "send.text" {
				return output.Error("Invalid template object. Use `bw send template %s` instead.", id)
			}
			return output.Error("Unknown template object.")
		}
		return output.Template(t)
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	switch strings.ToLower(obj) {
	case "item":
		c, r := a.findCipher(v, id, nil)
		if r != nil {
			return *r
		}
		return output.Success(vault.ItemOutput(c))
	case "username":
		return a.getLoginField(v, id, "username", "No username available for this login.", func(c *vault.Cipher) *string { return c.Login.Username })
	case "password":
		return a.getLoginField(v, id, "password", "No password available for this login.", func(c *vault.Cipher) *string { return c.Login.Password })
	case "uri":
		c, r := a.findCipher(v, id, func(c *vault.Cipher) bool {
			return c.Type == vault.TypeLogin && c.Login != nil && len(c.Login.URIs) > 0 && deref(c.Login.URIs[0].URI) != ""
		})
		if r != nil {
			return *r
		}
		if c.Type != vault.TypeLogin {
			return output.Error("Not a login.")
		}
		if c.Login == nil || len(c.Login.URIs) == 0 || deref(c.Login.URIs[0].URI) == "" {
			return output.Error("No uri available for this login.")
		}
		return output.String(*c.Login.URIs[0].URI)
	case "totp":
		r := a.getLoginField(v, id, "totp", "No TOTP available for this login.", func(c *vault.Cipher) *string { return c.Login.Totp })
		if !r.Success {
			return r
		}
		code, err := totp.Generate(*r.Data.(output.StringResponse).Data)
		if err != nil {
			return output.Error("Couldn't generate TOTP code.")
		}
		return output.String(code)
	case "notes":
		c, r := a.findCipher(v, id, func(c *vault.Cipher) bool { return !isNullOrWhitespace(c.Notes) })
		if r != nil {
			return *r
		}
		if isNullOrWhitespace(c.Notes) {
			return output.Error("No notes available for this item.")
		}
		return output.String(*c.Notes)
	case "exposed":
		r := a.getLoginField(v, id, "password", "No password available for this login.", func(c *vault.Cipher) *string { return c.Login.Password })
		if !r.Success {
			return r
		}
		n, err := pwnedCount(*r.Data.(output.StringResponse).Data)
		if err != nil {
			return output.Error("%v", err)
		}
		return output.String(fmt.Sprint(n))
	case "attachment":
		return a.getAttachment(v, id, str(cmd, "itemid"), str(cmd, "output"))
	case "folder":
		var found *vault.Folder
		folders := v.Folders()
		if isGUID(id) {
			for i := range folders {
				if folders[i].ID == id {
					found = &folders[i]
				}
			}
		} else if strings.TrimSpace(id) != "" {
			m := vault.SearchByName(folders, id, func(f vault.Folder) string { return f.Name })
			if len(m) > 1 {
				return multipleResults(mapIDs(m, func(f vault.Folder) string { return f.ID }))
			}
			if len(m) == 1 {
				found = &m[0]
			}
		}
		if found == nil {
			return notFound()
		}
		return output.Success(vault.FolderOutput(*found))
	case "collection":
		var found *vault.Collection
		cols := v.Collections()
		if isGUID(id) {
			for i := range cols {
				if cols[i].ID == id {
					found = &cols[i]
				}
			}
		} else if strings.TrimSpace(id) != "" {
			m := vault.SearchByName(cols, id, func(c vault.Collection) string { return c.Name })
			if len(m) > 1 {
				return multipleResults(mapIDs(m, func(c vault.Collection) string { return c.ID }))
			}
			if len(m) == 1 {
				found = &m[0]
			}
		}
		if found == nil {
			return notFound()
		}
		if isGUID(id) {
			// Lookup by id decrypts the stored collection directly, keeping a null externalId.
			return output.Success(vault.APICollectionOutput(*found))
		}
		return output.Success(vault.CollectionOutput(*found))
	case "org-collection":
		return a.getOrgCollection(v, id, str(cmd, "organizationid"))
	case "organization":
		var found *vault.ProfileOrganization
		orgs := v.Organizations()
		if isGUID(id) {
			for i := range orgs {
				if orgs[i].ID == id {
					found = &orgs[i]
				}
			}
		} else if strings.TrimSpace(id) != "" {
			m := vault.SearchByName(orgs, id, func(o vault.ProfileOrganization) string { return o.Name })
			if len(m) > 1 {
				return multipleResults(mapIDs(m, func(o vault.ProfileOrganization) string { return o.ID }))
			}
			if len(m) == 1 {
				found = &m[0]
			}
		}
		if found == nil {
			return notFound()
		}
		return output.Success(vault.OrganizationOutput(*found))
	case "fingerprint":
		return a.getFingerprint(v, id)
	case "send":
		return a.sendGet(v, args[1], "", false)
	}
	return output.Error("Unknown object.")
}

func mapIDs[T any](items []T, id func(T) string) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = id(it)
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// findCipher mirrors GetCommand.getCipher: id lookup or basic search, with an
// optional filter applied to multiple/single results.
func (a *App) findCipher(v *vault.Vault, id string, filter func(*vault.Cipher) bool) (*vault.Cipher, *output.Response) {
	fail := func(r output.Response) (*vault.Cipher, *output.Response) { return nil, &r }
	var found *vault.Cipher
	if isGUID(id) {
		if raw := v.RawCipher(id); raw != nil {
			found = v.Decrypt(raw)
		}
	} else if strings.TrimSpace(id) != "" {
		cs := slices.DeleteFunc(v.Ciphers(), func(c *vault.Cipher) bool { return isDeleted(c) || isArchived(c) })
		cs = vault.SearchCiphers(cs, id)
		if len(cs) > 1 {
			if filter != nil {
				cs = slices.DeleteFunc(cs, func(c *vault.Cipher) bool { return !filter(c) })
			}
			if len(cs) == 0 {
				return fail(notFound())
			}
			if len(cs) > 1 {
				return fail(multipleResults(mapIDs(cs, func(c *vault.Cipher) string { return c.ID })))
			}
			return cs[0], nil
		}
		if len(cs) == 1 {
			found = cs[0]
		}
	}
	if found == nil || (filter != nil && !filter(found)) {
		return fail(notFound())
	}
	return found, nil
}

func (a *App) getLoginField(v *vault.Vault, id, field, missing string, get func(*vault.Cipher) *string) output.Response {
	c, r := a.findCipher(v, id, func(c *vault.Cipher) bool {
		return c.Type == vault.TypeLogin && c.Login != nil && !isNullOrWhitespace(get(c))
	})
	if r != nil {
		return *r
	}
	if c.Type != vault.TypeLogin || c.Login == nil {
		return output.Error("Not a login.")
	}
	val := get(c)
	if isNullOrWhitespace(val) {
		return output.Error("%s", missing)
	}
	return output.String(*val)
}

// pwnedCount queries the HIBP range API (k-anonymity).
func pwnedCount(password string) (int, error) {
	sum := sha1.Sum([]byte(password))
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	resp, err := http.Get("https://api.pwnedpasswords.com/range/" + h[:5])
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		suffix, count, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && suffix == h[5:] {
			var n int
			fmt.Sscan(count, &n)
			return n, nil
		}
	}
	return 0, nil
}

func (a *App) getFingerprint(v *vault.Vault, id string) output.Response {
	st, _ := a.state()
	var phrase string
	var err error
	if id == "me" {
		pub, perr := v.PublicKey()
		if perr != nil {
			return output.Error("No public key available for the active user.")
		}
		phrase, err = crypto.Fingerprint(st.Account.UserID, pub)
	} else if isGUID(id) {
		c, cerr := a.client()
		if cerr != nil {
			return output.Error("%v", cerr)
		}
		var res struct {
			PublicKey string `json:"publicKey"`
		}
		if c.Get("/users/"+id+"/public-key", &res) != nil {
			return notFound()
		}
		pub, derr := base64.StdEncoding.DecodeString(res.PublicKey)
		if derr != nil {
			return notFound()
		}
		phrase, err = crypto.Fingerprint(id, pub)
	} else {
		return notFound()
	}
	if err != nil {
		return notFound()
	}
	return output.String(phrase)
}

func (a *App) getOrgCollection(v *vault.Vault, id, orgID string) output.Response {
	if orgID == "" {
		return output.Error("`organizationid` option is required.")
	}
	if !isGUID(id) {
		return output.Error("`%s` is not a GUID.", id)
	}
	if !isGUID(orgID) {
		return output.Error("`%s` is not a GUID.", orgID)
	}
	if _, err := v.OrgKey(orgID); err != nil {
		return output.Error("%v", err)
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	var res struct {
		vault.Collection
		Groups []vault.SelectionReadOnly `json:"groups"`
		Users  []vault.SelectionReadOnly `json:"users"`
	}
	if err := c.Get("/organizations/"+orgID+"/collections/"+id+"/details", &res); err != nil {
		return output.Error("%v", err)
	}
	return output.Success(vault.OrgCollectionResponse{
		Object: "org-collection", ID: res.ID, OrganizationID: res.OrganizationID,
		Name: v.DecryptCollectionName(orgID, res.Name), ExternalID: res.ExternalID,
		Groups: res.Groups, Users: res.Users,
	})
}

// getAttachment downloads and decrypts an attachment.
func (a *App) getAttachment(v *vault.Vault, id, itemID, outPath string) output.Response {
	if itemID == "" {
		return output.Error("--itemid <itemid> required.")
	}
	c, r := a.findCipher(v, strings.ToLower(itemID), nil)
	if r != nil {
		return *r
	}
	if len(c.Attachments) == 0 {
		return output.Error("No attachments available for this item.")
	}
	var matches []vault.Attachment
	for _, at := range c.Attachments {
		if strings.ToLower(at.ID) == id || strings.Contains(strings.ToLower(at.FileName), id) {
			matches = append(matches, at)
		}
	}
	if len(matches) == 0 {
		return output.Error("Attachment `%s` was not found.", id)
	}
	var exact []vault.Attachment
	for _, at := range matches {
		if strings.ToLower(at.FileName) == id {
			exact = append(exact, at)
		}
	}
	if len(exact) == 1 {
		matches = exact
	}
	if len(matches) > 1 {
		return multipleResults(mapIDs(matches, func(at vault.Attachment) string { return at.ID }))
	}
	att := matches[0]
	client, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	data, err := a.downloadAttachment(client, v, c.ID, att)
	if err != nil {
		return output.Error("%v", err)
	}
	return a.saveResultToFile(data, outPath, filepath.Base(att.FileName))
}

func (a *App) downloadAttachment(client *api.Client, v *vault.Vault, cipherID string, att vault.Attachment) ([]byte, error) {
	url := deref(att.URL)
	var meta struct {
		URL string `json:"url"`
	}
	if err := client.Get("/ciphers/"+cipherID+"/attachment/"+att.ID, &meta); err == nil && meta.URL != "" {
		url = meta.URL
	} else if err != nil && !api.IsNotFound(err) {
		return nil, err
	}
	enc, err := client.Download(url)
	if err != nil {
		if ae, ok := err.(*api.Error); ok {
			return nil, fmt.Errorf("A %d error occurred while downloading the attachment.", ae.Status)
		}
		return nil, err
	}
	raw := v.RawCipher(cipherID)
	key, err := v.CipherKey(raw)
	if err != nil {
		return nil, err
	}
	// Attachment keys are wrapped with the cipher (or user/org) key. Look up the
	// encrypted key from the raw cipher since att holds decrypted values.
	for _, ra := range raw.Attachments {
		if ra.ID == att.ID && ra.Key != nil && *ra.Key != "" {
			if key, err = crypto.DecryptKey(key, *ra.Key); err != nil {
				return nil, err
			}
		}
	}
	plain, err := crypto.DecryptBuffer(key, enc)
	if err != nil {
		return nil, fmt.Errorf("An error occurred while saving the attachment.")
	}
	return plain, nil
}

// saveResultToFile mirrors CliUtils.saveResultToFile.
func (a *App) saveResultToFile(data []byte, outPath, defaultName string) output.Response {
	if a.serve {
		return output.Success(output.FileResponse{Data: data, FileName: defaultName})
	}
	if outPath == "" && a.opts.Raw {
		os.Stdout.Write(data)
		return output.Success(nil)
	}
	p, err := saveFile(data, outPath, defaultName)
	if err != nil {
		return output.Error("%v", err)
	}
	return output.Message("Saved "+p, "", p)
}

func saveFile(data []byte, outPath, defaultName string) (string, error) {
	var p string
	mkdir := false
	switch {
	case outPath == "":
		p = defaultName
	case !strings.ContainsRune(filepath.Clean(outPath), filepath.Separator) && !strings.HasSuffix(outPath, string(filepath.Separator)):
		p = outPath
	default:
		mkdir = true
		if strings.HasSuffix(outPath, string(filepath.Separator)) {
			p = filepath.Join(outPath, defaultName)
		} else {
			p = outPath
		}
	}
	p, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if mkdir {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return "", fmt.Errorf("Cannot save file to %s", p)
	}
	return p, nil
}
