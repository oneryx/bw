package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/internal/output"
	"github.com/oneryx/bw/totp"
	"github.com/oneryx/bw/vault"
)

func isGUID(s string) bool { return bw.IsGUID(s) }

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
	return errResp(&bw.MultipleResultsError{IDs: ids})
}

func notFound() output.Response { return output.Error("Not found.") }

func isNullOrWhitespace(s *string) bool { return s == nil || strings.TrimSpace(*s) == "" }

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

// --- list ---

func (a *App) runList(cmd *cobra.Command, args []string) output.Response {
	obj := args[0]
	if r := validateObject(obj, listObjects); r != nil {
		return *r
	}
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	ctx := context.Background()
	search := str(cmd, "search")
	orgID := str(cmd, "organizationid")
	switch strings.ToLower(obj) {
	case "items":
		items, err := c.Items(bw.ItemFilter{
			Search: search, URL: str(cmd, "url"), FolderID: str(cmd, "folderid"),
			CollectionID: str(cmd, "collectionid"), OrganizationID: orgID,
			Trash: boolean(cmd, "trash"), Archived: boolean(cmd, "archived"),
		})
		if err != nil {
			return errResp(err)
		}
		out := []vault.ItemResponse{}
		for _, it := range items {
			out = append(out, vault.ItemOutput(it))
		}
		return output.List(out)
	case "folders":
		folders, err := c.Folders()
		if err != nil {
			return errResp(err)
		}
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
		cols, err := c.Collections()
		if err != nil {
			return errResp(err)
		}
		if orgID != "" {
			cols = slices.DeleteFunc(cols, func(c vault.Collection) bool { return c.OrganizationID != orgID })
		}
		if strings.TrimSpace(search) != "" {
			cols = vault.SearchByName(cols, search, func(c vault.Collection) string { return c.Name })
		}
		out := []vault.CollectionResponse{}
		for _, col := range cols {
			out = append(out, vault.CollectionOutput(col))
		}
		return output.List(out)
	case "organizations":
		orgs, err := c.Organizations()
		if err != nil {
			return errResp(err)
		}
		if strings.TrimSpace(search) != "" {
			orgs = vault.SearchByName(orgs, search, func(o vault.ProfileOrganization) string { return o.Name })
		}
		out := []vault.OrganizationResponse{}
		for _, o := range orgs {
			out = append(out, vault.OrganizationOutput(o))
		}
		return output.List(out)
	case "org-collections":
		if r := checkOrgID(orgID); r != nil {
			return *r
		}
		cols, err := c.OrgCollections(ctx, orgID)
		if err != nil {
			return errResp(err)
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
		if r := checkOrgID(orgID); r != nil {
			return *r
		}
		members, err := c.OrgMembers(ctx, orgID)
		if err != nil {
			return errResp(err)
		}
		out := []vault.OrgMemberResponse{}
		for _, u := range members {
			out = append(out, vault.OrgMemberResponse{Object: "org-member", ID: u.ID, Email: u.Email,
				Name: u.Name, Status: u.Status, Type: u.Type, TwoFactorEnabled: u.TwoFactorEnabled})
		}
		return output.List(out)
	}
	return output.Error("Unknown object.")
}

// checkOrgID validates --organizationid for org-scoped commands.
func checkOrgID(orgID string) *output.Response {
	if orgID == "" {
		r := output.Error("`organizationid` option is required.")
		return &r
	}
	if !isGUID(orgID) {
		r := output.Error("`%s` is not a GUID.", orgID)
		return &r
	}
	return nil
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
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	ctx := context.Background()
	switch strings.ToLower(obj) {
	case "item":
		it, err := c.FindItem(id, nil)
		if err != nil {
			return errResp(err)
		}
		return output.Success(vault.ItemOutput(it))
	case "username":
		return getLoginField(c, id, "No username available for this login.", func(c *vault.Cipher) *string { return c.Login.Username })
	case "password":
		return getLoginField(c, id, "No password available for this login.", func(c *vault.Cipher) *string { return c.Login.Password })
	case "uri":
		it, err := c.FindItem(id, func(c *vault.Cipher) bool {
			return c.Type == vault.TypeLogin && c.Login != nil && len(c.Login.URIs) > 0 && deref(c.Login.URIs[0].URI) != ""
		})
		if err != nil {
			return errResp(err)
		}
		if it.Type != vault.TypeLogin {
			return output.Error("Not a login.")
		}
		if it.Login == nil || len(it.Login.URIs) == 0 || deref(it.Login.URIs[0].URI) == "" {
			return output.Error("No uri available for this login.")
		}
		return output.String(*it.Login.URIs[0].URI)
	case "totp":
		r := getLoginField(c, id, "No TOTP available for this login.", func(c *vault.Cipher) *string { return c.Login.Totp })
		if !r.Success {
			return r
		}
		code, err := totp.Generate(*r.Data.(output.StringResponse).Data)
		if err != nil {
			return output.Error("Couldn't generate TOTP code.")
		}
		return output.String(code)
	case "notes":
		it, err := c.FindItem(id, func(c *vault.Cipher) bool { return !isNullOrWhitespace(c.Notes) })
		if err != nil {
			return errResp(err)
		}
		if isNullOrWhitespace(it.Notes) {
			return output.Error("No notes available for this item.")
		}
		return output.String(*it.Notes)
	case "exposed":
		r := getLoginField(c, id, "No password available for this login.", func(c *vault.Cipher) *string { return c.Login.Password })
		if !r.Success {
			return r
		}
		n, err := c.PasswordExposures(ctx, *r.Data.(output.StringResponse).Data)
		if err != nil {
			return output.Error("%v", err)
		}
		return output.String(fmt.Sprint(n))
	case "attachment":
		return a.getAttachment(c, id, str(cmd, "itemid"), str(cmd, "output"))
	case "folder":
		folders, err := c.Folders()
		if err != nil {
			return errResp(err)
		}
		f, r := findByIDOrName(folders, id, func(f vault.Folder) string { return f.ID }, func(f vault.Folder) string { return f.Name })
		if r != nil {
			return *r
		}
		return output.Success(vault.FolderOutput(*f))
	case "collection":
		cols, err := c.Collections()
		if err != nil {
			return errResp(err)
		}
		col, r := findByIDOrName(cols, id, func(c vault.Collection) string { return c.ID }, func(c vault.Collection) string { return c.Name })
		if r != nil {
			return *r
		}
		if isGUID(id) {
			// Lookup by id decrypts the stored collection directly, keeping a null externalId.
			return output.Success(vault.APICollectionOutput(*col))
		}
		return output.Success(vault.CollectionOutput(*col))
	case "org-collection":
		return getOrgCollection(c, id, str(cmd, "organizationid"))
	case "organization":
		orgs, err := c.Organizations()
		if err != nil {
			return errResp(err)
		}
		o, r := findByIDOrName(orgs, id, func(o vault.ProfileOrganization) string { return o.ID }, func(o vault.ProfileOrganization) string { return o.Name })
		if r != nil {
			return *r
		}
		return output.Success(vault.OrganizationOutput(*o))
	case "fingerprint":
		phrase, err := c.Fingerprint(ctx, id)
		if err != nil {
			return errResp(err)
		}
		return output.String(phrase)
	case "send":
		return a.sendGet(c, args[1], "", false)
	}
	return output.Error("Unknown object.")
}

// findByIDOrName looks up an object by id, or else by a unique name search.
func findByIDOrName[T any](items []T, id string, idOf, nameOf func(T) string) (*T, *output.Response) {
	fail := func(r output.Response) (*T, *output.Response) { return nil, &r }
	if isGUID(id) {
		for i := range items {
			if idOf(items[i]) == id {
				return &items[i], nil
			}
		}
	} else if strings.TrimSpace(id) != "" {
		m := vault.SearchByName(items, id, nameOf)
		if len(m) > 1 {
			return fail(multipleResults(mapIDs(m, idOf)))
		}
		if len(m) == 1 {
			return &m[0], nil
		}
	}
	return fail(notFound())
}

func getLoginField(c *bw.Client, id, missing string, get func(*vault.Cipher) *string) output.Response {
	it, err := c.FindItem(id, func(c *vault.Cipher) bool {
		return c.Type == vault.TypeLogin && c.Login != nil && !isNullOrWhitespace(get(c))
	})
	if err != nil {
		return errResp(err)
	}
	if it.Type != vault.TypeLogin || it.Login == nil {
		return output.Error("Not a login.")
	}
	val := get(it)
	if isNullOrWhitespace(val) {
		return output.Error("%s", missing)
	}
	return output.String(*val)
}

func getOrgCollection(c *bw.Client, id, orgID string) output.Response {
	if orgID == "" {
		return output.Error("`organizationid` option is required.")
	}
	if !isGUID(id) {
		return output.Error("`%s` is not a GUID.", id)
	}
	if !isGUID(orgID) {
		return output.Error("`%s` is not a GUID.", orgID)
	}
	col, err := c.OrgCollection(context.Background(), orgID, id)
	if err != nil {
		return errResp(err)
	}
	return output.Success(orgCollectionOutput(col))
}

func orgCollectionOutput(col *bw.OrgCollection) vault.OrgCollectionResponse {
	return vault.OrgCollectionResponse{
		Object: "org-collection", ID: col.ID, OrganizationID: col.OrganizationID, Name: col.Name,
		ExternalID: col.ExternalID, Groups: col.Groups, Users: col.Users,
	}
}

// getAttachment downloads and decrypts an attachment.
func (a *App) getAttachment(c *bw.Client, id, itemID, outPath string) output.Response {
	if itemID == "" {
		return output.Error("--itemid <itemid> required.")
	}
	it, err := c.FindItem(itemID, nil)
	if err != nil {
		return errResp(err)
	}
	if len(it.Attachments) == 0 {
		return output.Error("No attachments available for this item.")
	}
	var matches []vault.Attachment
	for _, at := range it.Attachments {
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
	data, err := c.Attachment(context.Background(), it.ID, att.ID)
	if err != nil {
		return errResp(err)
	}
	return a.saveResultToFile(data, outPath, filepath.Base(att.FileName))
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
