package cli

import (
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/internal/output"
)

// jsTime formats a time like JavaScript's Date.toJSON().
func jsTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

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
