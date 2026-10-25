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

// validateObject mirrors the official "Unknown object" check.
func validateObject(obj string, valid []string) error {
	if slices.Contains(valid, obj) {
		return nil
	}
	r := output.Error(`Unknown object "%s". Allowed objects are: %s.`, obj, strings.Join(valid, ", "))
	return &r
}

// checkGUID validates an id argument or option.
func checkGUID(id string) error {
	if !bw.IsGUID(id) {
		r := output.Error("`%s` is not a GUID.", id)
		return &r
	}
	return nil
}

// checkOrgID validates --organizationid for org-scoped commands.
func checkOrgID(orgID string) error {
	if orgID == "" {
		r := output.Error("`organizationid` option is required.")
		return &r
	}
	return checkGUID(orgID)
}

func isNullOrWhitespace(s *string) bool { return s == nil || strings.TrimSpace(*s) == "" }

// listOf converts objects into their CLI shape for a list response.
func listOf[T, R any](items []T, conv func(T) R) output.Response {
	out := make([]R, 0, len(items))
	for _, it := range items {
		out = append(out, conv(it))
	}
	return output.List(out)
}

// searchByName applies --search to folders, collections and organizations.
func searchByName[T any](items []T, search string, name func(T) string) []T {
	if strings.TrimSpace(search) == "" {
		return items
	}
	return vault.SearchByName(items, search, name)
}

func folderName(f vault.Folder) string                    { return f.Name }
func collectionName(c vault.Collection) string            { return c.Name }
func organizationName(o vault.ProfileOrganization) string { return o.Name }

// --- list ---

func (a *App) runList(cmd *cobra.Command, args []string) output.Response {
	obj := args[0]
	if err := validateObject(obj, listObjects); err != nil {
		return errResp(err)
	}
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	r, err := listObject(c, obj, cmd)
	if err != nil {
		return errResp(err)
	}
	return r
}

func listObject(c *bw.Client, obj string, cmd *cobra.Command) (output.Response, error) {
	ctx := context.Background()
	search := str(cmd, "search")
	orgID := str(cmd, "organizationid")
	switch obj {
	case "items":
		items, err := c.Items(bw.ItemFilter{
			Search: search, URL: str(cmd, "url"), FolderID: str(cmd, "folderid"),
			CollectionID: str(cmd, "collectionid"), OrganizationID: orgID,
			Trash: boolean(cmd, "trash"), Archived: boolean(cmd, "archived"),
		})
		return listOf(items, output.ItemOutput), err
	case "folders":
		folders, err := c.Folders()
		folders = append(folders, vault.Folder{Name: "No Folder"})
		return listOf(searchByName(folders, search, folderName), output.FolderOutput), err
	case "collections":
		cols, err := c.Collections()
		if orgID != "" {
			cols = slices.DeleteFunc(cols, func(c vault.Collection) bool { return c.OrganizationID != orgID })
		}
		return listOf(searchByName(cols, search, collectionName), output.CollectionOutput), err
	case "organizations":
		orgs, err := c.Organizations()
		return listOf(searchByName(orgs, search, organizationName), output.OrganizationOutput), err
	case "org-collections":
		if err := checkOrgID(orgID); err != nil {
			return output.Response{}, err
		}
		cols, err := c.OrgCollections(ctx, orgID)
		return listOf(searchByName(cols, search, collectionName), output.APICollectionOutput), err
	case "org-members":
		if err := checkOrgID(orgID); err != nil {
			return output.Response{}, err
		}
		members, err := c.OrgMembers(ctx, orgID)
		return listOf(members, func(u bw.OrgMember) output.OrgMemberResponse {
			return output.OrgMemberResponse{Object: "org-member", ID: u.ID, Email: u.Email,
				Name: u.Name, Status: u.Status, Type: u.Type, TwoFactorEnabled: u.TwoFactorEnabled}
		}), err
	}
	return output.Error("Unknown object."), nil
}

// --- get ---

func (a *App) runGet(cmd *cobra.Command, args []string) output.Response {
	obj, id := args[0], strings.ToLower(args[1])
	if err := validateObject(obj, getObjects); err != nil {
		return errResp(err)
	}
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	r, err := a.getObject(c, obj, id, cmd)
	if err != nil {
		return errResp(err)
	}
	return r
}

func (a *App) getObject(c *bw.Client, obj, id string, cmd *cobra.Command) (output.Response, error) {
	ctx := context.Background()
	switch obj {
	case "item":
		it, err := c.FindItem(id, nil)
		if err != nil {
			return output.Response{}, err
		}
		return output.Success(output.ItemOutput(it)), nil
	case "username":
		return loginField(c, id, "No username available for this login.", func(l *vault.Login) *string { return l.Username })
	case "password":
		return loginField(c, id, "No password available for this login.", func(l *vault.Login) *string { return l.Password })
	case "uri":
		hasURI := func(c *vault.Cipher) bool {
			return c.Login != nil && len(c.Login.URIs) > 0 && output.Deref(c.Login.URIs[0].URI) != ""
		}
		it, err := c.FindItem(id, func(c *vault.Cipher) bool { return c.Type == vault.TypeLogin && hasURI(c) })
		if err != nil {
			return output.Response{}, err
		}
		if it.Type != vault.TypeLogin {
			return output.Error("Not a login."), nil
		}
		if !hasURI(it) {
			return output.Error("No uri available for this login."), nil
		}
		return output.String(*it.Login.URIs[0].URI), nil
	case "totp":
		r, err := loginField(c, id, "No TOTP available for this login.", func(l *vault.Login) *string { return l.Totp })
		if err != nil || !r.Success {
			return r, err
		}
		code, err := totp.Generate(stringData(r))
		if err != nil {
			return output.Error("Couldn't generate TOTP code."), nil
		}
		return output.String(code), nil
	case "notes":
		it, err := c.FindItem(id, func(c *vault.Cipher) bool { return !isNullOrWhitespace(c.Notes) })
		if err != nil {
			return output.Response{}, err
		}
		if isNullOrWhitespace(it.Notes) {
			return output.Error("No notes available for this item."), nil
		}
		return output.String(*it.Notes), nil
	case "attachment":
		itemID := str(cmd, "itemid")
		if itemID == "" {
			return output.Error("--itemid <itemid> required."), nil
		}
		it, att, err := c.FindAttachment(itemID, id)
		if err != nil {
			return output.Response{}, err
		}
		data, err := c.Attachment(ctx, it.ID, att.ID)
		if err != nil {
			return output.Response{}, err
		}
		return a.saveResultToFile(data, str(cmd, "output"), filepath.Base(att.FileName)), nil
	case "folder":
		folders, err := c.Folders()
		if err != nil {
			return output.Response{}, err
		}
		f, err := findByIDOrName(folders, id, func(f vault.Folder) string { return f.ID }, folderName)
		if err != nil {
			return output.Response{}, err
		}
		return output.Success(output.FolderOutput(*f)), nil
	case "collection":
		cols, err := c.Collections()
		if err != nil {
			return output.Response{}, err
		}
		col, err := findByIDOrName(cols, id, func(c vault.Collection) string { return c.ID }, collectionName)
		if err != nil {
			return output.Response{}, err
		}
		if bw.IsGUID(id) {
			// Lookup by id decrypts the stored collection directly, keeping a null externalId.
			return output.Success(output.APICollectionOutput(*col)), nil
		}
		return output.Success(output.CollectionOutput(*col)), nil
	case "org-collection":
		orgID := str(cmd, "organizationid")
		if orgID == "" {
			return output.Error("`organizationid` option is required."), nil
		}
		if err := checkGUID(id); err != nil {
			return output.Response{}, err
		}
		if err := checkGUID(orgID); err != nil {
			return output.Response{}, err
		}
		col, err := c.OrgCollection(ctx, orgID, id)
		if err != nil {
			return output.Response{}, err
		}
		return output.Success(output.OrgCollectionResponse{
			Object: "org-collection", ID: col.ID, OrganizationID: col.OrganizationID, Name: col.Name,
			ExternalID: col.ExternalID, Groups: col.Groups, Users: col.Users,
		}), nil
	case "organization":
		orgs, err := c.Organizations()
		if err != nil {
			return output.Response{}, err
		}
		o, err := findByIDOrName(orgs, id, func(o vault.ProfileOrganization) string { return o.ID }, organizationName)
		if err != nil {
			return output.Response{}, err
		}
		return output.Success(output.OrganizationOutput(*o)), nil
	}
	return output.Error("Unknown object."), nil
}

// stringData returns the value of a successful output.String response.
func stringData(r output.Response) string { return *r.Data.(output.StringResponse).Data }

// findByIDOrName looks up an object by id, or else by a unique name search.
func findByIDOrName[T any](items []T, id string, idOf, nameOf func(T) string) (*T, error) {
	var found []T
	if bw.IsGUID(id) {
		if i := slices.IndexFunc(items, func(it T) bool { return idOf(it) == id }); i >= 0 {
			found = items[i : i+1]
		}
	} else if strings.TrimSpace(id) != "" {
		found = vault.SearchByName(items, id, nameOf)
	}
	switch len(found) {
	case 0:
		return nil, bw.ErrNotFound
	case 1:
		return &found[0], nil
	}
	ids := make([]string, len(found))
	for i, it := range found {
		ids[i] = idOf(it)
	}
	return nil, &bw.MultipleResultsError{IDs: ids}
}

// loginField mirrors the official getUsername/getPassword/getUri/getTotp.
func loginField(c *bw.Client, id, missing string, get func(*vault.Login) *string) (output.Response, error) {
	it, err := c.FindItem(id, func(c *vault.Cipher) bool {
		return c.Type == vault.TypeLogin && c.Login != nil && !isNullOrWhitespace(get(c.Login))
	})
	if err != nil {
		return output.Response{}, err
	}
	if it.Type != vault.TypeLogin || it.Login == nil {
		return output.Error("Not a login."), nil
	}
	val := get(it.Login)
	if isNullOrWhitespace(val) {
		return output.Error("%s", missing), nil
	}
	return output.String(*val), nil
}

// saveResultToFile mirrors CliUtils.saveResultToFile.
func (a *App) saveResultToFile(data []byte, outPath, defaultName string) output.Response {
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
	p, mkdir := outPath, true
	switch {
	case outPath == "":
		p, mkdir = defaultName, false
	case strings.HasSuffix(outPath, string(filepath.Separator)):
		p = filepath.Join(outPath, defaultName)
	case !strings.ContainsRune(filepath.Clean(outPath), filepath.Separator):
		mkdir = false
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
