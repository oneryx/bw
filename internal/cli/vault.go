package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

var (
	listObjects    = []string{"items", "folders", "collections", "org-collections", "org-members", "organizations"}
	getObjects     = []string{"item", "username", "password", "uri", "totp", "notes", "exposed", "attachment", "folder", "collection", "org-collection", "organization", "template", "fingerprint", "send"}
	createObjects  = []string{"item", "attachment", "folder", "org-collection"}
	editObjects    = []string{"item", "item-collections", "folder", "org-collection"}
	deleteObjects  = []string{"item", "attachment", "folder", "org-collection"}
	archiveObjects = []string{"item"}
	restoreObjects = []string{"item"}
	confirmObjects = []string{"org-member"}
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
  bw get exposed yahoo.com
  bw get attachment b857igwl1dzrs2 --itemid 99ee88d2-6046-4ea7-92c2-acac464b1412 --output ./photo.jpg
  bw get attachment photo.jpg --itemid 99ee88d2-6046-4ea7-92c2-acac464b1412 --raw
  bw get folder email
  bw get template folder`,
		Args: cobra.ExactArgs(2),
		Run:  a.action(a.runGet),
	}
	f := cmd.Flags()
	f.String("itemid", "", "Attachment's item id.")
	f.String("output", "", "Output directory or filename for attachment.")
	f.String("organizationid", "", "Organization id for an organization object.")
	return cmd
}

func (a *App) createCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <object> [encodedJson]",
		Short: "Create an object in the vault.",
		Long:  "Create an object in the vault.\n\n  <object>       " + validObjects(createObjects) + "\n  [encodedJson]  Encoded json of the object to create. Can also be piped into stdin.",
		Example: `  bw create folder eyJuYW1lIjoiTXkgRm9sZGVyIn0K
  echo 'eyJuYW1lIjoiTXkgRm9sZGVyIn0K' | bw create folder
  bw create attachment --file ./myfile.csv --itemid 16b15b89-65b3-4639-ad2a-95052a6d8f66`,
		Args: cobra.RangeArgs(1, 2),
		Run:  a.action(a.runCreate),
	}
	f := cmd.Flags()
	f.String("file", "", "Path to file for attachment.")
	f.String("itemid", "", "Attachment's item id.")
	f.String("organizationid", "", "Organization id for an organization object.")
	return cmd
}

func (a *App) editCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <object> <id> [encodedJson]",
		Short: "Edit an object from the vault.",
		Long:  "Edit an object from the vault.\n\n  <object>       " + validObjects(editObjects) + "\n  <id>           Object's globally unique `id`.\n  [encodedJson]  Encoded json of the object to create. Can also be piped into stdin.",
		Example: `  bw edit folder 5cdfbd80-d99f-409b-915b-f4c5d0241b02 eyJuYW1lIjoiTXkgRm9sZGVyMiJ9Cg==
  echo 'eyJuYW1lIjoiTXkgRm9sZGVyMiJ9Cg==' | bw edit folder 5cdfbd80-d99f-409b-915b-f4c5d0241b02
  bw edit item-collections 78307355-fd25-416b-88b8-b33fd0e88c82 WyI5NzQwNTNkMC0zYjMzLTRiOTgtODg2ZS1mZWNmNWM4ZGJhOTYiXQ==`,
		Args: cobra.RangeArgs(2, 3),
		Run:  a.action(a.runEdit),
	}
	cmd.Flags().String("organizationid", "", "Organization id for an organization object.")
	return cmd
}

func (a *App) deleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <object> <id>",
		Short: "Delete an object from the vault.",
		Long:  "Delete an object from the vault.\n\n  <object>  " + validObjects(deleteObjects) + "\n  <id>      Object's globally unique `id`.",
		Example: `  bw delete item 7063feab-4b10-472e-b64c-785e2b870b92
  bw delete item 89c21cd2-fab0-4f69-8c6e-ab8a0168f69a --permanent
  bw delete folder 5cdfbd80-d99f-409b-915b-f4c5d0241b02
  bw delete attachment b857igwl1dzrs2 --itemid 310d5ffd-e9a2-4451-af87-ea054dce0f78`,
		Args: cobra.ExactArgs(2),
		Run:  a.action(a.runDelete),
	}
	f := cmd.Flags()
	f.String("itemid", "", "Attachment's item id.")
	f.String("organizationid", "", "Organization id for an organization object.")
	f.BoolP("permanent", "p", false, "Permanently deletes the item instead of soft-deleting it (item only).")
	return cmd
}

func (a *App) archiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "archive <object> <id>",
		Short:   "Archive an object from the vault.",
		Long:    "Archive an object from the vault.\n\n  <object>  " + validObjects(archiveObjects) + "\n  <id>      Object's globally unique `id`.",
		Example: "  bw archive item 7063feab-4b10-472e-b64c-785e2b870b92",
		Args:    cobra.ExactArgs(2),
		Run:     a.action(a.runArchive),
	}
}

func (a *App) restoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "restore <object> <id>",
		Short:   "Restores an object from the trash or archive.",
		Long:    "Restores an object from the trash or archive.\n\n  <object>  " + validObjects(restoreObjects) + "\n  <id>      Object's globally unique `id`.",
		Example: "  bw restore item 7063feab-4b10-472e-b64c-785e2b870b92",
		Args:    cobra.ExactArgs(2),
		Run:     a.action(a.runRestore),
	}
}

func (a *App) moveCmd(deprecated bool) *cobra.Command {
	name, desc := "move", "Move an item to an organization."
	if deprecated {
		name, desc = "share", "--DEPRECATED-- Move an item to an organization."
	}
	return &cobra.Command{
		Use:   name + " <id> <organizationId> [encodedJson]",
		Short: desc,
		Long:  desc + "\n\n  <id>              Object's globally unique `id`.\n  <organizationId>  Organization's globally unique `id`.\n  [encodedJson]     Encoded json of an array of collection ids. Can also be piped into stdin.",
		Example: `  bw ` + name + ` 4af958ce-96a7-45d9-beed-1e70fabaa27a 6d82949b-b44d-468a-adae-3f3bacb0ea32 WyI5NzQwNTNkMC0zYjMzLTRiOTgtODg2ZS1mZWNmNWM4ZGJhOTYiXQ==
  echo '["974053d0-3b33-4b98-886e-fecf5c8dba96"]' | bw encode | bw ` + name + ` 4af958ce-96a7-45d9-beed-1e70fabaa27a 6d82949b-b44d-468a-adae-3f3bacb0ea32`,
		Hidden: deprecated,
		Args:   cobra.RangeArgs(2, 3),
		Run:    a.action(a.runMove),
	}
}

func (a *App) confirmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "confirm <object> <id>",
		Short:   "Confirm an object to the organization.",
		Long:    "Confirm an object to the organization.\n\n  <object>  " + validObjects(confirmObjects) + "\n  <id>      Object's globally unique `id`.",
		Example: "  bw confirm org-member 7063feab-4b10-472e-b64c-785e2b870b92 --organizationid 310d5ffd-e9a2-4451-af87-ea054dce0f78",
		Args:    cobra.ExactArgs(2),
		Run:     a.action(a.runConfirm),
	}
	cmd.Flags().String("organizationid", "", "Organization id for an organization object.")
	return cmd
}

func (a *App) importCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import [format] [input]",
		Short: "Import vault data from a file.",
		Example: `  bw import --formats
  bw import bitwardencsv ./from/source.csv
  bw import keepass2xml keepass_backup.xml
  bw import --organizationid cf14adc3-aca5-4573-890a-f6fa231436d9 keepass2xml keepass_backup.xml`,
		Args: cobra.MaximumNArgs(2),
		Run:  a.action(a.runImport),
	}
	f := cmd.Flags()
	f.Bool("formats", false, "List formats")
	f.String("organizationid", "", "ID of the organization to import to.")
	f.String("keyfile", "", "Path to a key file used to unlock a KeePass (kdbx) database.")
	f.String("passwordenv", "", "Environment variable storing the password for an encrypted import file.")
	f.String("passwordfile", "", "Path to a file containing the password for an encrypted import file as its first line.")
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
