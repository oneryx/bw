# bw — a Go Bitwarden CLI and client library for Vaultwarden

A single static binary (~11 MB, vs ~137 MB for the official Node build) that
re-implements the [official Bitwarden CLI](https://bitwarden.com/help/cli/)
for self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
servers. Commands, arguments, flags, environment variables, JSON output and
exit codes follow the official CLI (verified side-by-side against `bw`
2026.10.0 and Vaultwarden 1.37), so existing scripts keep working.

The same functionality is available as a Go library (`github.com/oneryx/bw`)
for other applications, e.g. GUI clients. See [Library](#library).

Only current Vaultwarden releases are supported (tested with 1.37); fallbacks
for older server APIs have been removed.

## Build

```sh
make build VERSION=0.1.0    # CGO_ENABLED=0, stripped -> bin/bw
make test                   # unit tests
make integration            # end-to-end tests in a throwaway Vaultwarden container (podman/docker)
```

Dependencies: `spf13/cobra`, `golang.org/x/{crypto,term,net}`, `google/uuid`.

## Quick start

```sh
bw config server https://vault.example.com
bw login you@example.com                 # prompts for password / 2FA code
export BW_SESSION="$(bw unlock --raw)"
bw list items --search github --pretty
bw get password github.com
bw get totp github.com
```

Self-signed server certificate? Point Go at it with `SSL_CERT_FILE=/path/ca.pem`
(the equivalent of the official `NODE_EXTRA_CA_CERTS`). Like the official CLI,
plain `http://` servers are refused unless `BWCLI_ENV=development` is set.

State lives in `$XDG_CONFIG_HOME/Bitwarden CLI-go/data.json` (or
`BITWARDENCLI_APPDATA_DIR`). It is separate from the official CLI's data, so
both can be used side by side. Vault data stays encrypted at rest; the user key
is only stored wrapped by the session key (`BW_SESSION`).

## Supported commands

`login` (password, `--apikey`, 2FA: authenticator, email),
`logout`, `lock`, `unlock`, `sync`, `status`, `config server`, `list`, `get`
(incl. `totp`, `exposed`, `attachment`, `fingerprint`, `template`), `create`,
`edit`, `delete`, `restore`, `archive`, `move`/`share`, `confirm org-member`,
`import`, `export` (`csv`, `json`, `encrypted_json`, `zip`, password-protected,
organization exports), `generate`, `encode`, `send` (+ `list`, `template`, `get`,
`create`, `edit`, `remove-password`, `delete`), `receive`, `serve` (REST API).

Import formats: `bitwardencsv`, `bitwardenjson` (plain, account-encrypted and
password-protected), `keepass2xml`, `keepassxcsv`.

## Differences from the official CLI

Not implemented (not available on Vaultwarden, or not ported yet):

- `device-approval` (Bitwarden-only), Key Connector, `report password-health`.
- SSO login (`--sso`), `completion`, `update`, `sdk-version`.
- Data in old encryption formats (AES-CBC without HMAC, RSA with HMAC);
  login to such accounts fails with "Legacy encryption is no longer supported".
- Two-step login other than authenticator app and email (no YubiKey OTP, Duo
  or WebAuthn).
- Email-verified Sends (`--emails`) return a clear error.
- Import formats other than those listed above (e.g. Chrome, Firefox,
  LastPass, 1Password, `keepasskdbx`); `bw import --formats` lists only what
  is supported.
- `bw serve` on `fd+...` hostnames; `update` does not self-update.

Intentional behavior differences:

- When the vault is locked and interaction is allowed, a command prompts for the
  master password and unlocks **only for that command**, without invalidating
  existing session keys.
- `bw get send <id>` works (the official CLI answers "Unknown object.").
- Help text layout comes from cobra and differs from commander's.
- Official bugs are not reproduced: `send get --text` with several matches
  (stack overflow), missing keys in `serve`'s send list, and `receive`
  accepting a wrong Send password after a cached successful access.

## Library

```go
import (
	"github.com/oneryx/bw"
	"github.com/oneryx/bw/vault"
)

c, err := bw.New(bw.Options{Store: bw.FileStore("/path/to/data.json")})
if err != nil { ... }
if !c.LoggedIn() {
	_ = c.SetServerConfig(bw.ServerConfig{Base: "https://vault.example.com"})
	err = c.Login(ctx, bw.LoginOptions{Email: email, Password: password})
	var tf *bw.TwoFactorRequiredError
	if errors.As(err, &tf) {
		// tf.Providers lists the available methods; tf.SendEmail sends an email code.
		err = tf.Submit(ctx, bw.TwoFactorAuthenticator, code)
	}
} else {
	err = c.Unlock(password) // the user key is kept in memory only
}
items, err := c.Items(bw.ItemFilter{Search: "github"})
item, err := c.CreateItem(ctx, &vault.Cipher{Type: vault.TypeLogin, Name: "Example", Login: &vault.Login{...}})
```

- `bw.Client` covers everything the CLI does: login/unlock/lock/sync, items
  (incl. attachments, trash, archive, move to organization), folders,
  collections, organizations and members, Sends (create, edit, receive),
  import and export. All methods are safe for concurrent use; network calls
  take a `context.Context`.
- Errors are values: `bw.ErrLocked`, `bw.ErrNotFound`,
  `*bw.MultipleResultsError`, `*bw.TwoFactorRequiredError`, `*bw.APIError`, …
  Messages match the official CLI and can be shown to users.
- State goes through a `bw.Store` (`FileStore`, `MemoryStore`, or your own,
  e.g. the OS keychain). The vault stays encrypted in the store.
- `NewSession`/`UnlockWithSession` provide the CLI's `BW_SESSION` mechanism if
  several processes need to share an unlocked vault.
- `github.com/oneryx/bw/vault` holds the data model (`vault.Cipher`,
  `vault.Folder`, `vault.DecryptedSend`, …), search and URI matching;
  `github.com/oneryx/bw/generator` and `github.com/oneryx/bw/totp` generate
  passwords/passphrases and TOTP codes.

The CLI (`internal/cli`) is a thin layer over this API that adds prompts,
flags and output formatting.

## Debugging

`BWGO_DEBUG=1` traces HTTP requests and responses to stderr (this prints
secrets; don't use it in shared logs).
