package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yangxiang/bw/internal/api"
	"github.com/yangxiang/bw/internal/crypto"
	"github.com/yangxiang/bw/internal/output"
	"github.com/yangxiang/bw/internal/state"
)

func (a *App) loginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login [email] [password]",
		Short: "Log into a user account.",
		Long:  "Log into a user account.\n\nNotes:\n  See docs for valid `method` enum values.\n\n  Pass `--raw` option to only return the session key.",
		Example: `  bw login
  bw login john@example.com myPassword321 --raw
  bw login john@example.com myPassword321 --method 1 --code 249213
  bw login --sso`,
		Args: cobra.MaximumNArgs(2),
		Run:  a.action(a.runLogin),
	}
	f := cmd.Flags()
	f.String("method", "", "Two-step login method.")
	f.String("code", "", "Two-step login code.")
	f.String("sso", "", "Log in with Single-Sign On with optional organization identifier.")
	f.Lookup("sso").NoOptDefVal = " "
	f.Bool("apikey", false, "Log in with an Api Key.")
	f.String("passwordenv", "", "Environment variable storing your password")
	f.String("passwordfile", "", "Path to a file containing your password as its first line")
	f.Bool("check", false, "Check login status.")
	return cmd
}

// Two-step login providers supported by this CLI, in the official order.
var twoFactorProviders = []struct {
	Type int
	Name string
}{
	{0, "Authenticator App"},
	{3, "YubiKey OTP Security Key"},
	{1, "Email"},
}

// jwtClaims extracts the user id and email from an access token.
func jwtClaims(token string) (sub, email string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", ""
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", ""
	}
	var c struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	_ = json.Unmarshal(b, &c)
	return c.Sub, c.Email
}

func (a *App) runLogin(cmd *cobra.Command, args []string) output.Response {
	st, err := a.state()
	if err != nil {
		return output.Error("%v", err)
	}
	if boolean(cmd, "check") {
		if st.Account != nil && st.Account.Tokens.AccessToken != "" {
			return output.Message("You are logged in!", "", "")
		}
		return output.Error("You are not logged in.")
	}
	if st.Account != nil {
		return output.Error("You are already logged in as %s.", st.Account.Email)
	}
	sso := changed(cmd, "sso") && !a.noInteraction

	var email, password string
	if len(args) > 0 {
		email = args[0]
	}
	if len(args) > 1 {
		password = args[1]
	}
	apiKey := boolean(cmd, "apikey")
	var clientID, clientSecret string
	var ssoCode, ssoVerifier, ssoRedirect string
	if apiKey {
		clientID, clientSecret = os.Getenv("BW_CLIENTID"), os.Getenv("BW_CLIENTSECRET")
		if _, ok := os.LookupEnv("BW_CLIENTID"); !ok && !a.noInteraction {
			clientID = prompt("client_id:")
		}
		if _, ok := os.LookupEnv("BW_CLIENTSECRET"); !ok && !a.noInteraction {
			clientSecret = prompt("client_secret:")
		}
		if strings.TrimSpace(clientID) == "" {
			return output.Error("client_id is required.")
		}
		if clientSecret == "" {
			return output.Error("client_secret is required.")
		}
		if !strings.HasPrefix(clientID, "user") {
			return output.Error("Invalid API Key; Organization API Key currently not supported")
		}
	} else if sso {
		ssoCode, ssoVerifier, ssoRedirect, err = ssoAuthorize(st.Environment.WebVaultURL(), strings.TrimSpace(str(cmd, "sso")))
		if err != nil {
			return output.Error("%v", err)
		}
	} else {
		if email == "" && !a.noInteraction {
			email = prompt("Email address:")
		}
		if strings.TrimSpace(email) == "" {
			return output.Error("Email address is required.")
		}
		if !strings.Contains(email, "@") {
			return output.Error("Email address is invalid.")
		}
		if password == "" {
			if f := str(cmd, "passwordfile"); f != "" {
				if password, err = readFirstLine(f); err != nil {
					return output.Error("%v", err)
				}
			} else if e := str(cmd, "passwordenv"); e != "" && os.Getenv(e) != "" {
				password = os.Getenv(e)
			} else if !a.noInteraction {
				password = promptSecret("Master password:")
			}
		}
		if password == "" {
			return output.Error("Master password is required.")
		}
	}

	twoFactorCode := str(cmd, "code")
	twoFactorMethod := -1
	if m := str(cmd, "method"); m != "" {
		v, err := strconv.Atoi(m)
		if err != nil || v < 0 || v > 8 {
			return output.Error("Invalid two-step login method.")
		}
		twoFactorMethod = v
	}

	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}

	form := url.Values{}
	var masterKey []byte
	var pwHash string
	var kdf state.KDF
	if apiKey {
		form.Set("grant_type", "client_credentials")
		form.Set("scope", "api")
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	} else if sso {
		form.Set("grant_type", "authorization_code")
		form.Set("scope", "api offline_access")
		form.Set("client_id", "cli")
		form.Set("code", ssoCode)
		form.Set("code_verifier", ssoVerifier)
		form.Set("redirect_uri", ssoRedirect)
	} else {
		pre, err := c.Prelogin(email)
		if err != nil {
			return output.Error("%v", err)
		}
		kdf = state.KDF{Type: pre.Kdf, Iterations: pre.KdfIterations, Memory: pre.KdfMemory, Parallelism: pre.KdfParallelism}
		if masterKey, err = crypto.MasterKey(password, email, kdfParams(kdf)); err != nil {
			return output.Error("%v", err)
		}
		pwHash = crypto.MasterPasswordHash(masterKey, password)
		form.Set("grant_type", "password")
		form.Set("scope", "api offline_access")
		form.Set("client_id", "cli")
		form.Set("username", email)
		form.Set("password", pwHash)
	}
	if twoFactorCode != "" && twoFactorMethod >= 0 {
		form.Set("twoFactorToken", twoFactorCode)
		form.Set("twoFactorProvider", strconv.Itoa(twoFactorMethod))
		form.Set("twoFactorRemember", "0")
	}

	tr, err := c.Token(form)
	if tf, ok := err.(*api.TwoFactorRequired); ok {
		tr, err = a.twoFactorLogin(c, form, tf, twoFactorMethod, twoFactorCode, email, pwHash)
	}
	if err != nil {
		if r, ok := err.(*output.Response); ok {
			return *r
		}
		if ae, ok := err.(*api.Error); ok {
			if apiKey && ae.ErrorCode == "invalid_client" {
				return output.Error("client_id or client_secret is incorrect. Try again.")
			}
			if strings.HasPrefix(ae.Message, "Username or password is incorrect") {
				u, _ := url.Parse(st.Environment.WebVaultURL())
				return output.Error("Invalid master password. Confirm your email is correct and your account was created on %s.", u.Host)
			}
		}
		return output.Error("%v", err)
	}

	if sso && (tr.UserDecryptionOptions == nil || !tr.UserDecryptionOptions.HasMasterPassword) {
		return output.Error("In order to log in with SSO from the CLI, you must first log in" +
			" through the web vault, the desktop, or the extension to set your master password.")
	}
	userID, jwtEmail := jwtClaims(tr.AccessToken)
	if apiKey || sso {
		email = jwtEmail
		kdf = state.KDF{Type: tr.Kdf, Iterations: tr.KdfIterations, Memory: tr.KdfMemory, Parallelism: tr.KdfParallelism}
	}
	acc := &state.Account{
		UserID:        userID,
		Email:         strings.ToLower(strings.TrimSpace(email)),
		KDF:           kdf,
		EncUserKey:    tr.Key,
		EncPrivateKey: tr.PrivateKey,
	}
	api.SetTokens(&acc.Tokens, tr)
	if apiKey {
		acc.Tokens.ClientID, acc.Tokens.ClientSecret = clientID, clientSecret
	}
	st.Account = acc
	c.Tokens = &acc.Tokens

	var session string
	if !apiKey && !sso {
		uk, err := crypto.DecryptUserKey(masterKey, tr.Key)
		if err != nil {
			st.Account = nil
			return output.Error("Legacy encryption is no longer supported. Please contact support to recover your account.")
		}
		if session, err = newSession(acc, uk); err != nil {
			return output.Error("%v", err)
		}
	}
	if err := st.Save(); err != nil {
		return output.Error("%v", err)
	}
	if err := a.fullSync(c, st, true); err != nil {
		return output.Error("Syncing failed: %v", err)
	}
	if apiKey || sso {
		return output.Message("You are logged in!", "\nTo unlock your vault, use the `unlock` command. ex:\n$ bw unlock", "")
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

// twoFactorLogin selects a provider, collects the code and retries the token request.
func (a *App) twoFactorLogin(c *api.Client, form url.Values, tf *api.TwoFactorRequired, method int, code, email, pwHash string) (*api.TokenResponse, error) {
	var available []int
	var names []string
	for _, p := range twoFactorProviders {
		if _, ok := tf.Providers[strconv.Itoa(p.Type)]; ok {
			available = append(available, p.Type)
			names = append(names, p.Name)
		}
	}
	fail := func(msg string) (*api.TokenResponse, error) {
		r := output.Error("%s", msg)
		return nil, &r
	}
	if len(available) == 0 {
		return fail("No providers available for this client.")
	}
	selected := -1
	if method >= 0 && slices.Contains(available, method) {
		selected = method
	}
	if selected < 0 {
		switch {
		case len(available) == 1:
			selected = available[0]
		case !a.noInteraction:
			for i, n := range names {
				os.Stderr.WriteString("  " + strconv.Itoa(i+1) + ") " + n + "\n")
			}
			os.Stderr.WriteString("  " + strconv.Itoa(len(names)+1) + ") Cancel\n")
			i, err := strconv.Atoi(strings.TrimSpace(prompt("Two-step login method:")))
			if err != nil || i < 1 || i > len(names) {
				return fail("Login failed.")
			}
			selected = available[i-1]
		default:
			return fail("Login failed. No provider selected.")
		}
	}
	if code == "" && selected == 1 && email != "" {
		body := map[string]string{"email": email, "masterPasswordHash": pwHash, "deviceIdentifier": c.DeviceID}
		if err := c.SendAnonymous(http.MethodPost, "/two-factor/send-email-login", body, nil); err != nil {
			return nil, err
		}
	}
	if code == "" {
		if !a.noInteraction {
			code = prompt("Two-step login code:")
		}
		if code == "" {
			return fail("Code is required.")
		}
	}
	form.Set("twoFactorToken", code)
	form.Set("twoFactorProvider", strconv.Itoa(selected))
	form.Set("twoFactorRemember", "0")
	tr, err := c.Token(form)
	if _, ok := err.(*api.TwoFactorRequired); ok {
		return fail("Login failed.")
	}
	return tr, err
}

func (a *App) logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "logout",
		Short:   "Log out of the current user account.",
		Example: "  bw logout",
		Args:    cobra.NoArgs,
		Run: a.action(func(cmd *cobra.Command, args []string) output.Response {
			st, resp := a.requireAuthed()
			if resp != nil {
				return *resp
			}
			st.Account = nil
			if err := st.Save(); err != nil {
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
			st, resp := a.requireAuthed()
			if resp != nil {
				return *resp
			}
			st.Account.SessionUserKey = ""
			if err := st.Save(); err != nil {
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
			st, resp := a.requireAuthed()
			if resp != nil {
				return *resp
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
			password, resp := a.getPassword(pw, str(cmd, "passwordfile"), str(cmd, "passwordenv"), "Master password:")
			if resp != nil {
				return *resp
			}
			uk, err := unlockWithPassword(st.Account, password)
			if err != nil {
				return output.Error("%v", err)
			}
			session, err := newSession(st.Account, uk)
			if err != nil {
				return output.Error("%v", err)
			}
			if err := st.Save(); err != nil {
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
			st, resp := a.requireAuthed()
			if resp != nil {
				return *resp
			}
			if boolean(cmd, "last") {
				if st.Account.LastSync == nil {
					return output.Success(output.StringResponse{Object: "string"})
				}
				return output.String(jsTime(*st.Account.LastSync))
			}
			c, err := a.client()
			if err != nil {
				return output.Error("%v", err)
			}
			if err := a.fullSync(c, st, boolean(cmd, "force")); err != nil {
				return output.Error("Syncing failed: %v", err)
			}
			return output.Message("Syncing complete.", "", "")
		}),
	}
	cmd.Flags().BoolP("force", "f", false, "Force a full sync.")
	cmd.Flags().Bool("last", false, "Get the last sync date.")
	return cmd
}

// fullSync downloads the vault unless the server revision is unchanged.
func (a *App) fullSync(c *api.Client, st *state.State, force bool) error {
	acc := st.Account
	if !force && acc.LastSync != nil && len(acc.Vault) > 0 {
		var ms int64
		if err := c.Get("/accounts/revision-date", &ms); err == nil && ms > 0 {
			if !time.UnixMilli(ms).After(*acc.LastSync) {
				now := time.Now()
				acc.LastSync = &now
				return st.Save()
			}
		}
	}
	var raw json.RawMessage
	if err := c.Get("/sync?excludeDomains=true", &raw); err != nil {
		return err
	}
	var profile struct {
		Profile struct {
			Key        string `json:"key"`
			PrivateKey string `json:"privateKey"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		return err
	}
	if profile.Profile.Key != "" {
		acc.EncUserKey = profile.Profile.Key
	}
	if profile.Profile.PrivateKey != "" {
		acc.EncPrivateKey = profile.Profile.PrivateKey
	}
	acc.Vault = raw
	now := time.Now()
	acc.LastSync = &now
	return st.Save()
}
