// Package cli defines the bw command tree.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/internal/output"
)

// App carries per-invocation state shared by all commands.
type App struct {
	opts          output.Options
	session       string
	noInteraction bool
	exitCode      int

	bw *bw.Client
}

func envTrue(name string) bool { return os.Getenv(name) == "true" }

// Execute runs the CLI and returns the process exit code.
func Execute(args []string) int {
	app := &App{}
	root := app.newRootCmd()
	args = joinOptionalValues(args)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "unknown command") {
			fmt.Fprintln(os.Stderr, "Invalid command: "+strings.Join(args, " "))
			fmt.Fprint(os.Stderr, "See --help for a list of available commands.")
		} else {
			fmt.Fprintln(os.Stderr, "error: "+msg)
		}
		return 1
	}
	return app.exitCode
}

func (a *App) newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:               "bw",
		Short:             "Bitwarden CLI (Go implementation for Vaultwarden)",
		SilenceErrors:     true,
		SilenceUsage:      true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		Example: `  bw login
  bw lock
  bw unlock myPassword321
  bw list --help
  bw list items --search google
  bw get item 99ee88d2-6046-4ea7-92c2-acac464b1412
  bw get password google.com
  bw export --format json --output ./vault.json
  bw config server https://bitwarden.example.com`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			a.loadGlobals(cmd)
			return nil
		},
	}

	pf := root.PersistentFlags()
	pf.Bool("pretty", false, "Format output. JSON is tabbed with two spaces.")
	pf.Bool("raw", false, "Return raw output instead of a descriptive message.")
	pf.Bool("response", false, "Return a JSON formatted version of response output.")
	pf.Bool("cleanexit", false, "Exit with a success exit code (0) unless an error is thrown.")
	pf.Bool("quiet", false, "Don't return anything to stdout.")
	pf.Bool("nointeraction", false, "Do not prompt for interactive user input.")
	pf.String("session", "", "Pass session key instead of reading from env.")

	root.AddCommand(
		a.loginCmd(), a.logoutCmd(), a.lockCmd(), a.unlockCmd(), a.syncCmd(),
		a.configCmd(), a.statusCmd(),
		a.listCmd(), a.getCmd(),
		a.exportCmd(),
	)
	return root
}

// loadGlobals merges global flags with their BW_* environment equivalents.
func (a *App) loadGlobals(cmd *cobra.Command) {
	f := cmd.Flags()
	flag := func(name, env string) bool {
		v, _ := f.GetBool(name)
		return v || envTrue(env)
	}
	a.opts = output.Options{
		Pretty:    flag("pretty", "BW_PRETTY"),
		Raw:       flag("raw", "BW_RAW"),
		Response:  flag("response", "BW_RESPONSE"),
		Quiet:     flag("quiet", "BW_QUIET"),
		CleanExit: flag("cleanexit", "BW_CLEANEXIT"),
	}
	a.noInteraction = flag("nointeraction", "BW_NOINTERACTION")
	a.session, _ = f.GetString("session")
	if a.session == "" {
		a.session = os.Getenv("BW_SESSION")
	}
}

// print writes a response and records the exit code.
func (a *App) print(r output.Response) {
	a.exitCode = output.NewPrinter(a.opts).Print(r)
}

// action adapts a command implementation returning a Response to cobra.
func (a *App) action(fn func(cmd *cobra.Command, args []string) output.Response) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		a.print(fn(cmd, args))
	}
}

// Flag helpers keep command definitions short.
func str(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func boolean(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
}

func changed(cmd *cobra.Command, name string) bool { return cmd.Flags().Changed(name) }

// optionalValueFlags are commander options declared as "--flag [value]": the
// value is taken from the next argument unless it looks like an option.
var optionalValueFlags = map[string]string{"export": "--password"}

// joinOptionalValues rewrites "--flag value" into "--flag=value" for those
// options, because pflag only accepts "--flag=value" for optional values.
func joinOptionalValues(args []string) []string {
	out := make([]string, 0, len(args))
	cmd := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if cmd == "" && a == "--session" && i+1 < len(args) {
			out = append(out, a, args[i+1])
			i++
			continue
		}
		if cmd == "" && !strings.HasPrefix(a, "-") {
			cmd = a
		}
		if flag, ok := optionalValueFlags[cmd]; ok && a == flag && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			out = append(out, a+"="+args[i+1])
			i++
			continue
		}
		out = append(out, a)
	}
	return out
}
