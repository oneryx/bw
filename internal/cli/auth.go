package cli

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/internal/output"
)

func (a *App) loginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login [email] [password]",
		Short: "Log into a user account.",
		Long:  "Log into a user account.\n\nNotes:\n  See docs for valid `method` enum values.\n\n  Pass `--raw` option to only return the session key.",
		Example: `  bw login
  bw login john@example.com myPassword321 --raw
  bw login john@example.com myPassword321 --method 1 --code 249213`,
		Args: cobra.MaximumNArgs(2),
		Run:  a.action(a.runLogin),
	}
	f := cmd.Flags()
	f.String("method", "", "Two-step login method.")
	f.String("code", "", "Two-step login code.")
	f.Bool("apikey", false, "Log in with an Api Key.")
	f.String("passwordenv", "", "Environment variable storing your password")
	f.String("passwordfile", "", "Path to a file containing your password as its first line")
	f.Bool("check", false, "Check login status.")
	return cmd
}

func (a *App) runLogin(cmd *cobra.Command, args []string) output.Response {
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	if boolean(cmd, "check") {
		if c.LoggedIn() {
			return output.Message("You are logged in!", "", "")
		}
		return output.Error("You are not logged in.")
	}
	if email := c.Email(); email != "" {
		return output.Error("You are already logged in as %s.", email)
	}

	var opts bw.LoginOptions
	if len(args) > 0 {
		opts.Email = args[0]
	}
	if len(args) > 1 {
		opts.Password = args[1]
	}
	apiKey := boolean(cmd, "apikey")
	if apiKey {
		opts.Email, opts.Password = "", ""
		opts.ClientID, opts.ClientSecret = os.Getenv("BW_CLIENTID"), os.Getenv("BW_CLIENTSECRET")
		if _, ok := os.LookupEnv("BW_CLIENTID"); !ok && !a.noInteraction {
			opts.ClientID = prompt("client_id:")
		}
		if _, ok := os.LookupEnv("BW_CLIENTSECRET"); !ok && !a.noInteraction {
			opts.ClientSecret = prompt("client_secret:")
		}
		if strings.TrimSpace(opts.ClientID) == "" {
			return output.Error("client_id is required.")
		}
	} else {
		// The library validates these too; checking here fails before the
		// password prompt, like the official CLI.
		if opts.Email == "" && !a.noInteraction {
			opts.Email = prompt("Email address:")
		}
		if strings.TrimSpace(opts.Email) == "" {
			return output.Error("Email address is required.")
		}
		if !strings.Contains(opts.Email, "@") {
			return output.Error("Email address is invalid.")
		}
		if opts.Password == "" {
			if f := str(cmd, "passwordfile"); f != "" {
				if opts.Password, err = readFirstLine(f); err != nil {
					return output.Error("%v", err)
				}
			} else if e := str(cmd, "passwordenv"); e != "" && os.Getenv(e) != "" {
				opts.Password = os.Getenv(e)
			} else if !a.noInteraction {
				opts.Password = promptSecret("Master password:")
			}
		}
	}

	code, method := str(cmd, "code"), -1
	if m := str(cmd, "method"); m != "" {
		v, err := strconv.Atoi(m)
		if err != nil || v < 0 || v > 8 {
			return output.Error("Invalid two-step login method.")
		}
		method = v
	}
	if code != "" && method >= 0 {
		opts.TwoFactor = &bw.TwoFactor{Provider: bw.TwoFactorProvider(method), Code: code}
	}

	ctx := context.Background()
	err = c.Login(ctx, opts)
	var tf *bw.TwoFactorRequiredError
	if errors.As(err, &tf) {
		err = a.twoFactorLogin(ctx, tf, method, code, apiKey)
	}
	if err != nil {
		return errResp(err)
	}
	if apiKey {
		return output.Message("You are logged in!", "\nTo unlock your vault, use the `unlock` command. ex:\n$ bw unlock", "")
	}
	session, err := c.NewSession()
	if err != nil {
		return output.Error("%v", err)
	}
	return sessionMessage("You are logged in!", session)
}

func sessionMessage(title, session string) output.Response {
	return output.Message(title, "\n"+
		"To unlock your vault, set your session key to the `BW_SESSION` environment variable. ex:\n"+
		`$ export BW_SESSION="`+session+`"`+"\n"+
		`> $env:BW_SESSION="`+session+`"`+"\n\n"+
		"You can also pass the session key to any command with the `--session` option. ex:\n"+
		"$ bw list items --session "+session, session)
}

// twoFactorLogin selects a provider, collects the code and completes the login.
func (a *App) twoFactorLogin(ctx context.Context, tf *bw.TwoFactorRequiredError, method int, code string, apiKey bool) error {
	available := tf.Providers
	if len(available) == 0 {
		return errors.New("No providers available for this client.")
	}
	selected := bw.TwoFactorProvider(-1)
	if method >= 0 && slices.Contains(available, bw.TwoFactorProvider(method)) {
		selected = bw.TwoFactorProvider(method)
	}
	if selected < 0 {
		switch {
		case len(available) == 1:
			selected = available[0]
		case !a.noInteraction:
			for i, p := range available {
				os.Stderr.WriteString("  " + strconv.Itoa(i+1) + ") " + p.String() + "\n")
			}
			os.Stderr.WriteString("  " + strconv.Itoa(len(available)+1) + ") Cancel\n")
			i, err := strconv.Atoi(strings.TrimSpace(prompt("Two-step login method:")))
			if err != nil || i < 1 || i > len(available) {
				return bw.ErrTwoFactorFailed
			}
			selected = available[i-1]
		default:
			return errors.New("Login failed. No provider selected.")
		}
	}
	if code == "" && selected == bw.TwoFactorEmail && !apiKey {
		if err := tf.SendEmail(ctx); err != nil {
			return err
		}
	}
	if code == "" {
		if !a.noInteraction {
			code = prompt("Two-step login code:")
		}
		if code == "" {
			return errors.New("Code is required.")
		}
	}
	return tf.Submit(ctx, selected, code)
}

func (a *App) logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "logout",
		Short:   "Log out of the current user account.",
		Example: "  bw logout",
		Args:    cobra.NoArgs,
		Run: a.action(func(cmd *cobra.Command, args []string) output.Response {
			c, err := a.requireAuthed()
			if err != nil {
				return errResp(err)
			}
			if err := c.Logout(); err != nil {
				return output.Error("%v", err)
			}
			return output.Message("You have logged out.", "", "")
		}),
	}
}

func (a *App) lockCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "lock",
		Short:   "Lock the vault and destroy active session keys.",
		Example: "  bw lock",
		Args:    cobra.NoArgs,
		Run: a.action(func(cmd *cobra.Command, args []string) output.Response {
			c, err := a.requireAuthed()
			if err != nil {
				return errResp(err)
			}
			if err := c.Lock(); err != nil {
				return output.Error("%v", err)
			}
			return output.Message("Your vault is locked.", "", "")
		}),
	}
}

func (a *App) unlockCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unlock [password]",
		Short: "Unlock the vault and return a new session key.",
		Long:  "Unlock the vault and return a new session key.\n\nNotes:\n  After unlocking, any previous session keys will no longer be valid.\n\n  Pass `--raw` option to only return the session key.",
		Example: `  bw unlock
  bw unlock myPassword321
  bw unlock myPassword321 --raw`,
		Args: cobra.MaximumNArgs(1),
		Run: a.action(func(cmd *cobra.Command, args []string) output.Response {
			c, err := a.requireAuthed()
			if err != nil {
				return errResp(err)
			}
			if boolean(cmd, "check") {
				if a.isUnlocked() {
					return output.Message("Vault is unlocked!", "", "")
				}
				return output.Error("Vault is locked.")
			}
			pw := ""
			if len(args) > 0 {
				pw = args[0]
			}
			password, err := a.getPassword(pw, str(cmd, "passwordfile"), str(cmd, "passwordenv"), "Master password:")
			if err != nil {
				return errResp(err)
			}
			if err := c.Unlock(password); err != nil {
				return errResp(err)
			}
			session, err := c.NewSession()
			if err != nil {
				return output.Error("%v", err)
			}
			return sessionMessage("Your vault is now unlocked!", session)
		}),
	}
	f := cmd.Flags()
	f.Bool("check", false, "Check lock status.")
	f.String("passwordenv", "", "Environment variable storing your password")
	f.String("passwordfile", "", "Path to a file containing your password as its first line")
	return cmd
}

func (a *App) syncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Pull the latest vault data from server.",
		Example: `  bw sync
  bw sync -f
  bw sync --last`,
		Args: cobra.NoArgs,
		Run: a.action(func(cmd *cobra.Command, args []string) output.Response {
			c, err := a.requireAuthed()
			if err != nil {
				return errResp(err)
			}
			if boolean(cmd, "last") {
				last := c.LastSync()
				if last == nil {
					return output.Success(output.StringResponse{Object: "string"})
				}
				return output.String(output.JSTime(*last))
			}
			if err := c.Sync(context.Background(), boolean(cmd, "force")); err != nil {
				return output.Error("Syncing failed: %v", err)
			}
			return output.Message("Syncing complete.", "", "")
		}),
	}
	cmd.Flags().BoolP("force", "f", false, "Force a full sync.")
	cmd.Flags().Bool("last", false, "Get the last sync date.")
	return cmd
}
