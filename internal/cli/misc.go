package cli

import (
	"encoding/base64"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/generator"
	"github.com/oneryx/bw/internal/output"
)

// jsTime formats a time like JavaScript's Date.toJSON().
func jsTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// parseIntOption behaves like parseInt with a fallback default.
func parseIntOption(s string, def int) int {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || end == 0 && (s[0] == '-' || s[0] == '+')) {
		end++
	}
	if v, err := strconv.Atoi(s[:end]); err == nil {
		return v
	}
	return def
}

func (a *App) generateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a password/passphrase.",
		Args:  cobra.NoArgs,
		Example: `  bw generate
  bw generate -u -l --length 18
  bw generate -ulns --length 25
  bw generate -ul
  bw generate -p --separator _
  bw generate -p --words 5 --separator space
  bw generate -p --words 5 --separator empty`,
		Long: `Generate a password/passphrase.

Notes:
  Default options are ` + "`-uln --length 14`" + `.
  Minimum ` + "`length`" + ` is 5.
  Minimum ` + "`words`" + ` is 3.`,
		Run: a.action(func(cmd *cobra.Command, args []string) output.Response {
			if boolean(cmd, "passphrase") {
				sep := "-"
				if changed(cmd, "separator") {
					sep = str(cmd, "separator")
				}
				switch {
				case sep == "space":
					sep = " "
				case sep == "empty":
					sep = ""
				case len([]rune(sep)) > 1:
					sep = string([]rune(sep)[:1])
				}
				return output.String(generator.Passphrase(generator.PassphraseOptions{
					NumWords:      max(parseIntOption(str(cmd, "words"), 6), 3),
					Separator:     sep,
					Capitalize:    boolean(cmd, "capitalize"),
					IncludeNumber: boolean(cmd, "includeNumber"),
				}))
			}
			o := generator.PasswordOptions{
				Uppercase:  boolean(cmd, "uppercase"),
				Lowercase:  boolean(cmd, "lowercase"),
				Number:     boolean(cmd, "number"),
				Special:    boolean(cmd, "special"),
				Length:     max(parseIntOption(str(cmd, "length"), 14), 5),
				MinNumber:  parseIntOption(str(cmd, "minNumber"), 1),
				MinSpecial: parseIntOption(str(cmd, "minSpecial"), 0),
				Ambiguous:  !boolean(cmd, "ambiguous"),
			}
			if !o.Uppercase && !o.Lowercase && !o.Number && !o.Special {
				o.Uppercase, o.Lowercase, o.Number = true, true, true
			}
			return output.String(generator.Password(o))
		}),
	}
	f := cmd.Flags()
	f.BoolP("uppercase", "u", false, "Include uppercase characters.")
	f.BoolP("lowercase", "l", false, "Include lowercase characters.")
	f.BoolP("number", "n", false, "Include numeric characters.")
	f.BoolP("special", "s", false, "Include special characters.")
	f.BoolP("passphrase", "p", false, "Generate a passphrase.")
	f.String("length", "", "Length of the password.")
	f.String("words", "", "Number of words.")
	f.String("minNumber", "", "Minimum number of numeric characters.")
	f.String("minSpecial", "", "Minimum number of special characters.")
	f.String("separator", "", "Word separator.")
	f.BoolP("capitalize", "c", false, "Title case passphrase.")
	f.Bool("includeNumber", false, "Passphrase includes number.")
	f.Bool("ambiguous", false, "Avoid ambiguous characters.")
	return cmd
}

func (a *App) encodeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "encode",
		Short:   "Base 64 encode stdin.",
		Long:    "Base 64 encode stdin.\n\nNotes:\n  Use to create `encodedJson` for `create` and `edit` commands.",
		Example: `  echo '{"name":"My Folder"}' | bw encode`,
		Args:    cobra.NoArgs,
		Run: a.action(func(cmd *cobra.Command, args []string) output.Response {
			if term.IsTerminal(int(os.Stdin.Fd())) {
				return output.Error("No stdin was piped in.")
			}
			in, err := io.ReadAll(os.Stdin)
			if err != nil {
				return output.Error("%v", err)
			}
			return output.String(base64.StdEncoding.EncodeToString(in))
		}),
	}
}

func (a *App) configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config <setting> [value]",
		Short: "Configure CLI settings.",
		Long:  "Configure CLI settings.\n\nSettings:\n  server - On-premises hosted installation URL.",
		Example: `  bw config server
  bw config server https://bw.company.com
  bw config server bitwarden.com
  bw config server --api http://localhost:4000 --identity http://localhost:33656`,
		Args: cobra.RangeArgs(1, 2),
		Run: a.action(func(cmd *cobra.Command, args []string) output.Response {
			if strings.ToLower(args[0]) != "server" {
				return output.Error("Unknown setting.")
			}
			c, err := a.client()
			if err != nil {
				return output.Error("%v", err)
			}
			url := ""
			if len(args) > 1 {
				url = strings.TrimSpace(args[1])
			}
			cfg := bw.ServerConfig{
				WebVault:      str(cmd, "web-vault"),
				API:           str(cmd, "api"),
				Identity:      str(cmd, "identity"),
				Icons:         str(cmd, "icons"),
				Notifications: str(cmd, "notifications"),
				Events:        str(cmd, "events"),
				KeyConnector:  str(cmd, "key-connector"),
			}
			if url == "" && cfg.WebVault == "" && cfg.API == "" && cfg.Identity == "" &&
				cfg.Icons == "" && cfg.Notifications == "" && cfg.Events == "" {
				if base := c.ServerConfig().Base; base != "" {
					return output.String(base)
				}
				return output.String("https://bitwarden.com")
			}
			if url != "null" && url != "bitwarden.com" && url != "https://bitwarden.com" {
				cfg.Base = url
			}
			if err := c.SetServerConfig(cfg); err != nil {
				return output.Error("%v", err)
			}
			return output.Message("Saved setting `config`.", "", "")
		}),
	}
	f := cmd.Flags()
	f.String("web-vault", "", "Provides a custom web vault URL that differs from the base URL.")
	f.String("api", "", "Provides a custom API URL that differs from the base URL.")
	f.String("identity", "", "Provides a custom identity URL that differs from the base URL.")
	f.String("icons", "", "Provides a custom icons service URL that differs from the base URL.")
	f.String("notifications", "", "Provides a custom notifications URL that differs from the base URL.")
	f.String("events", "", "Provides a custom events URL that differs from the base URL.")
	f.String("key-connector", "", "Provides the URL for your Key Connector server.")
	return cmd
}

// statusTemplate keeps the official key order; unset values are omitted
// except lastSync, which is null like the official output.
type statusTemplate struct {
	ServerURL string  `json:"serverUrl,omitempty"`
	LastSync  *string `json:"lastSync"`
	UserEmail string  `json:"userEmail,omitempty"`
	UserID    string  `json:"userId,omitempty"`
	Status    string  `json:"status"`
}

func (a *App) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show server, last sync, user information, and vault status.",
		Example: `  bw status

  Example return value:
    {
      "serverUrl": "https://bitwarden.example.com",
      "lastSync": "2020-06-16T06:33:51.419Z",
      "userEmail": "user@example.com",
      "userId": "00000000-0000-0000-0000-000000000000",
      "status": "locked"
    }`,
		Args: cobra.NoArgs,
		Run: a.action(func(cmd *cobra.Command, args []string) output.Response {
			c, err := a.client()
			if err != nil {
				return output.Error("%v", err)
			}
			a.isUnlocked() // applies the session key
			s := c.Status()
			t := statusTemplate{ServerURL: s.ServerURL, UserEmail: s.UserEmail, UserID: s.UserID, Status: s.Status}
			if s.LastSync != nil {
				last := jsTime(*s.LastSync)
				t.LastSync = &last
			}
			return output.Template(t)
		}),
	}
}
