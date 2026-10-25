package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/internal/output"
	"github.com/oneryx/bw/vault"
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

// orgKeyError reports a missing organization key like the official CLI,
// which throws it as an Error.
func orgKeyError(err error) output.Response {
	if errors.Is(err, bw.ErrNoOrgKey) {
		return jsError(err.Error())
	}
	return errResp(err)
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
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	ctx := context.Background()
	switch strings.ToLower(obj) {
	case "item":
		var in vault.CipherInput
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		it, err := c.CreateItem(ctx, vault.ApplyInput(&in, nil))
		if err != nil {
			return errResp(err)
		}
		return output.Success(vault.ItemOutput(it))
	case "folder":
		var in struct {
			Name *string `json:"name"`
		}
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		f, err := c.CreateFolder(ctx, deref(in.Name))
		if err != nil {
			return errResp(err)
		}
		return output.Success(vault.FolderOutput(f))
	case "attachment":
		return createAttachment(c, str(cmd, "itemid"), str(cmd, "file"))
	case "org-collection":
		var in orgCollectionInput
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		return saveOrgCollection(c, "", &in, str(cmd, "organizationid"))
	}
	return output.Error("Unknown object.")
}

type orgCollectionInput struct {
	OrganizationID string                    `json:"organizationId"`
	Name           *string                   `json:"name"`
	ExternalID     *string                   `json:"externalId"`
	Groups         []vault.SelectionReadOnly `json:"groups"`
	Users          []vault.SelectionReadOnly `json:"users"`
}

// saveOrgCollection creates (id == "") or updates an organization collection.
func saveOrgCollection(c *bw.Client, id string, in *orgCollectionInput, optOrgID string) output.Response {
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
	col, err := c.SaveOrgCollection(context.Background(), bw.OrgCollection{
		ID: id, OrganizationID: orgID, Name: *in.Name, ExternalID: in.ExternalID, Groups: in.Groups, Users: in.Users,
	})
	if err != nil {
		return orgKeyError(err)
	}
	return output.Success(orgCollectionOutput(col))
}

// createAttachment encrypts and uploads a file to an item.
func createAttachment(c *bw.Client, itemID, file string) output.Response {
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
	it, err := c.AddAttachment(context.Background(), itemID, filepath.Base(abs), data)
	if err != nil {
		return errResp(err)
	}
	return output.Success(vault.ItemOutput(it))
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
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	ctx := context.Background()
	switch strings.ToLower(obj) {
	case "item":
		var in vault.CipherInput
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		orig, err := c.Item(id)
		if err != nil {
			return errResp(err)
		}
		it, err := c.UpdateItem(ctx, vault.ApplyInput(&in, orig))
		if err != nil {
			return errResp(err)
		}
		return output.Success(vault.ItemOutput(it))
	case "item-collections":
		var ids []string
		if r := decodeRequest(encoded, &ids); r != nil {
			return *r
		}
		it, err := c.SetItemCollections(ctx, id, ids)
		if err != nil {
			return errResp(err)
		}
		return output.Success(vault.ItemOutput(it))
	case "folder":
		var in struct {
			Name *string `json:"name"`
		}
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		f, err := c.RenameFolder(ctx, id, deref(in.Name))
		if err != nil {
			return errResp(err)
		}
		return output.Success(vault.FolderOutput(f))
	case "org-collection":
		var in orgCollectionInput
		if r := decodeRequest(encoded, &in); r != nil {
			return *r
		}
		if !isGUID(id) {
			return output.Error("`%s` is not a GUID.", id)
		}
		return saveOrgCollection(c, id, &in, str(cmd, "organizationid"))
	}
	return output.Error("Unknown object.")
}

// --- delete / restore / archive ---

func (a *App) runDelete(cmd *cobra.Command, args []string) output.Response {
	obj, id := args[0], strings.ToLower(args[1])
	if r := validateObject(obj, deleteObjects); r != nil {
		return *r
	}
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	ctx := context.Background()
	switch strings.ToLower(obj) {
	case "item":
		err = c.DeleteItem(ctx, id, boolean(cmd, "permanent"))
	case "attachment":
		itemID := str(cmd, "itemid")
		if itemID == "" {
			return output.Error("`itemid` option is required.")
		}
		err = c.DeleteAttachment(ctx, itemID, id)
	case "folder":
		err = c.DeleteFolder(ctx, id)
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
		err = c.DeleteOrgCollection(ctx, orgID, id)
	default:
		return output.Error("Unknown object.")
	}
	if err != nil {
		return errResp(err)
	}
	return output.Success(nil)
}

func (a *App) runRestore(cmd *cobra.Command, args []string) output.Response {
	if r := validateObject(args[0], restoreObjects); r != nil {
		return *r
	}
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	if err := c.RestoreItem(context.Background(), args[1]); err != nil {
		return errResp(err)
	}
	return output.Success(nil)
}

func (a *App) runArchive(cmd *cobra.Command, args []string) output.Response {
	if r := validateObject(args[0], archiveObjects); r != nil {
		return *r
	}
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	if err := c.ArchiveItem(context.Background(), args[1]); err != nil {
		return errResp(err)
	}
	return output.Success(nil)
}

// --- move / share ---

func (a *App) runMove(cmd *cobra.Command, args []string) output.Response {
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
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	it, err := c.MoveItem(context.Background(), args[0], args[1], ids)
	if err != nil {
		return orgKeyError(err)
	}
	return output.Success(vault.ItemOutput(it))
}

// --- confirm ---

func (a *App) runConfirm(cmd *cobra.Command, args []string) output.Response {
	obj, id := args[0], strings.ToLower(args[1])
	if r := validateObject(obj, confirmObjects); r != nil {
		return *r
	}
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
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
	if err := c.ConfirmOrgMember(context.Background(), orgID, id); err != nil {
		// Validation failures are thrown as Errors by the official CLI.
		var ae *bw.APIError
		if errors.As(err, &ae) {
			return errResp(err)
		}
		return jsError(err.Error())
	}
	return output.Success(nil)
}
