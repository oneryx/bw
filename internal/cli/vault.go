package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

var (
	listObjects = []string{"items", "folders", "collections", "org-collections", "org-members", "organizations"}
	getObjects  = []string{"item", "username", "password", "uri", "totp", "notes", "attachment", "folder", "collection", "org-collection", "organization"}
)

func validObjects(objs []string) string { return "Valid objects are: " + strings.Join(objs, ", ") }

func (a *App) listCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <object>",
		Short: "List an array of objects from the vault.",
		Long: "List an array of objects from the vault.\n\n  <object>  " + validObjects(listObjects) + `

Notes:
  Combining search with a filter performs a logical AND operation.
  Combining multiple filters performs a logical OR operation.`,
		Example: `  bw list items
  bw list items --folderid 60556c31-e649-4b5d-8daf-fc1c391a1bf2
  bw list items --search google --folderid 60556c31-e649-4b5d-8daf-fc1c391a1bf2
  bw list items --url https://google.com
  bw list items --folderid null
  bw list items --organizationid notnull
  bw list items --trash
  bw list folders --search email
  bw list org-members --organizationid 60556c31-e649-4b5d-8daf-fc1c391a1bf2`,
		Args: cobra.ExactArgs(1),
		Run:  a.action(a.runList),
	}
	f := cmd.Flags()
	f.String("search", "", "Perform a search on the listed objects.")
	f.String("url", "", "Filter items of type login with a url-match search.")
	f.String("folderid", "", "Filter items by folder id.")
	f.String("collectionid", "", "Filter items by collection id.")
	f.String("organizationid", "", "Filter items or collections by organization id.")
	f.Bool("trash", false, "Filter items that are deleted and in the trash.")
	f.Bool("archived", false, "Filter items that are archived.")
	return cmd
}

func (a *App) getCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <object> <id>",
		Short: "Get an object from the vault.",
		Long: "Get an object from the vault.\n\n  <object>  " + validObjects(getObjects) + "\n  <id>      Search term or object's globally unique `id`." + `

  If raw output is specified and no output filename or directory is given for
  an attachment query, the attachment content is written to stdout.`,
		Example: `  bw get item 99ee88d2-6046-4ea7-92c2-acac464b1412
  bw get password https://google.com
  bw get totp google.com
  bw get notes google.com
  bw get attachment b857igwl1dzrs2 --itemid 99ee88d2-6046-4ea7-92c2-acac464b1412 --output ./photo.jpg
  bw get attachment photo.jpg --itemid 99ee88d2-6046-4ea7-92c2-acac464b1412 --raw
  bw get folder email`,
		Args: cobra.ExactArgs(2),
		Run:  a.action(a.runGet),
	}
	f := cmd.Flags()
	f.String("itemid", "", "Attachment's item id.")
	f.String("output", "", "Output directory or filename for attachment.")
	f.String("organizationid", "", "Organization id for an organization object.")
	return cmd
}

func (a *App) exportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export vault data to a CSV, JSON or ZIP file.",
		Long: `Export vault data to a CSV, JSON or ZIP file.

Notes:
  Valid formats are ` + "`csv`, `json`, `encrypted_json`, `zip`" + `. Default format is ` + "`csv`" + `.

  If --raw option is specified and no output filename or directory is given, the
  result is written to stdout.`,
		Example: `  bw export
  bw --raw export
  bw export myPassword321
  bw export myPassword321 --format json
  bw export --output ./exp/bw.csv
  bw export myPassword321 --output bw.json --format json
  bw export --organizationid 7063feab-4b10-472e-b64c-785e2b870b92`,
		Args: cobra.NoArgs,
		Run:  a.action(a.runExport),
	}
	f := cmd.Flags()
	f.String("output", "", "Output directory or filename.")
	f.String("format", "", "Export file format.")
	f.String("password", "", "Use password to encrypt instead of your Bitwarden account encryption key. Only applies to the encrypted_json format.")
	f.Lookup("password").NoOptDefVal = " "
	f.String("organizationid", "", "Organization id for an organization.")
	return cmd
}
