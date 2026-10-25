package cli

import (
	"github.com/spf13/cobra"
)

func (a *App) sendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send [data]",
		Short: "Work with Bitwarden sends. A Send can be quickly created using this command or subcommands can be used to fine-tune the Send",
		Long: `Work with Bitwarden sends. A Send can be quickly created using this command or subcommands can be used to fine-tune the Send

  <data>  The data to Send. Specify as a filepath with the --file option`,
		Example: `  bw send -f ./file.ext
  bw send "text to send"
  echo "text to send" | bw send
  bw send -n "My Send" -d 3 --hidden "secret text"`,
		Args: cobra.MaximumNArgs(1),
		Run:  a.action(a.runQuickSend),
	}
	f := cmd.Flags()
	f.BoolP("file", "f", false, "Specifies that <data> is a filepath")
	f.StringP("deleteInDays", "d", "7", "The number of days in the future to set deletion date, defaults to 7")
	f.String("password", "", "optional password to access this Send. Can also be specified in JSON.")
	f.String("emails", "", "optional emails to access this Send. Can also be specified in JSON.")
	f.StringP("maxAccessCount", "a", "", "The amount of max possible accesses.")
	f.Bool("hidden", false, "Hide <data> in web by default. Valid only if --file is not set.")
	f.StringP("name", "n", "", "The name of the Send. Defaults to a guid for text Sends and the filename for files.")
	f.String("notes", "", "Notes to add to the Send.")
	f.Bool("fullObject", false, "Specifies that the full Send object should be returned rather than just the access url.")

	cmd.AddCommand(a.sendListCmd(), a.sendTemplateCmd(), a.sendGetCmd(), a.sendReceiveCmd("receive"),
		a.sendCreateCmd(), a.sendEditCmd(), a.sendRemovePasswordCmd(), a.sendDeleteCmd())
	return cmd
}

func (a *App) receiveCmd() *cobra.Command { return a.sendReceiveCmd("receive") }

func (a *App) sendReceiveCmd(name string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   name + " <url>",
		Short: "Access a Bitwarden Send from a url",
		Example: `  bw receive https://vault.bitwarden.com/#/send/rg3iuoS_Akm2gqy6ADRHmg/Ht7dYjsqjmgqUM3rjzZDSQ
  bw receive https://vault.bitwarden.com/#/send/rg3iuoS_Akm2gqy6ADRHmg/Ht7dYjsqjmgqUM3rjzZDSQ --password myPassword123`,
		Args: cobra.ExactArgs(1),
		Run:  a.action(a.runReceive),
	}
	f := cmd.Flags()
	f.String("password", "", "Password needed to access the Send.")
	f.String("passwordenv", "", "Environment variable storing the Send's password")
	f.String("passwordfile", "", "Path to a file containing the Sends password as its first line")
	f.Bool("obj", false, "Return the Send's json object rather than the Send's content")
	f.String("output", "", "Specify a file path to save a File-type Send to")
	return cmd
}

func (a *App) sendListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all the Sends owned by you",
		Example: "  bw send list",
		Args:    cobra.NoArgs,
		Run:     a.action(a.runSendList),
	}
}

func (a *App) sendTemplateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "template <object>",
		Short: "Get json templates for send objects",
		Long:  "Get json templates for send objects\n\n  <object>  Valid objects are: send.text, text, send.file, file",
		Args:  cobra.ExactArgs(1),
		Run:   a.action(a.runSendTemplate),
	}
}

func (a *App) sendGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Get Sends owned by you.",
		Long:  "Get Sends owned by you.\n\n  <id>  Search term or Send's globally unique `id`.\n\n  If raw output is specified and no output filename or directory is given for\n  an attachment query, the attachment content is written to stdout.",
		Example: `  bw send get searchText
  bw send get id
  bw send get searchText --text
  bw send get searchText --file
  bw send get searchText --file --output ../Photos/photo.jpg
  bw send get searchText --file --raw`,
		Args: cobra.ExactArgs(1),
		Run:  a.action(a.runSendGet),
	}
	cmd.Flags().String("output", "", "Output directory or filename for attachment.")
	cmd.Flags().Bool("text", false, "Specifies to return the text content of a Send")
	return cmd
}

func (a *App) sendCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [encodedJson]",
		Short: "create a Send",
		Long:  "create a Send\n\n  [encodedJson]  JSON object to upload. Can also be piped in through stdin.",
		Args:  cobra.MaximumNArgs(1),
		Run:   a.action(a.runSendCreate),
	}
	f := cmd.Flags()
	f.String("file", "", "file to Send. Can also be specified in parent's JSON.")
	f.String("text", "", "text to Send. Can also be specified in parent's JSON.")
	f.Bool("hidden", false, "text hidden flag. Valid only with the --text option.")
	f.String("password", "", "optional password to access this Send. Can also be specified in JSON.")
	f.String("emails", "", "optional emails to access this Send. Can also be specified in JSON.")
	f.Bool("fullObject", false, "Specifies that the full Send object should be returned rather than just the access url.")
	return cmd
}

func (a *App) sendEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit [encodedJson]",
		Short: "edit a Send",
		Long:  "edit a Send\n\n  [encodedJson]  Updated JSON object to save. If not provided, encodedJson is read from stdin.\n\nNote:\n  You cannot update a File-type Send's file. Just delete and remake it",
		Args:  cobra.MaximumNArgs(1),
		Run:   a.action(a.runSendEdit),
	}
	f := cmd.Flags()
	f.String("itemid", "", "Overrides the itemId provided in [encodedJson]")
	f.String("password", "", "optional password to access this Send. Can also be specified in JSON.")
	f.String("emails", "", "optional emails to access this Send. Can also be specified in JSON.")
	return cmd
}

func (a *App) sendRemovePasswordCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove-password <id>",
		Short: "removes the saved password from a Send.",
		Args:  cobra.ExactArgs(1),
		Run:   a.action(a.runSendRemovePassword),
	}
}

func (a *App) sendDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "delete a Send",
		Args:  cobra.ExactArgs(1),
		Run:   a.action(a.runSendDelete),
	}
}
