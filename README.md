# bw — a read-only Go Bitwarden CLI and client library for Vaultwarden

A single static binary (~10 MB, vs ~137 MB for the official Node build) that
implements the read-only part of the
[official Bitwarden CLI](https://bitwarden.com/help/cli/) for self-hosted
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) servers: log in,
sync, list/get vault objects, and export. It never changes vault data.
Commands, arguments, flags, environment variables, JSON output and exit codes
follow the official CLI (verified side-by-side against `bw` 2026.10.0 and
Vaultwarden 1.37), so existing read-only scripts keep working.

The same functionality is available as a Go library (`github.com/oneryx/bw`)
for other Go programs, e.g. small command-line tools. See [Library](#library).

Only current Vaultwarden releases are supported (tested with 1.37); fallbacks
for older server APIs have been removed.

## Build

```sh
make build VERSION=0.1.0    # CGO_ENABLED=0, stripped -> bin/bw
make test                   # go vet + unit tests
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

State (server config, login tokens and the encrypted vault cache) lives in
`data.json` next to the `bw` binary (symlinks are resolved), so that directory
must be writable; set `BITWARDENCLI_APPDATA_DIR` to use another directory. It
is separate from the official CLI's data, so both can be used side by side.
Vault data stays encrypted at rest; the user key is only stored wrapped by the
session key (`BW_SESSION`). The file contains login tokens: never commit or
share it.

## Commands

The tool is read-only: no command changes vault data. Run `bw <command> --help`
for all options. Commands that read
the vault need it unlocked (`BW_SESSION` or `--session`); interactively they prompt for the master
password instead.

### Account and setup

| Command | Description | Examples |
|---|---|---|
| `config server` | Show or set the server URL (log out first to change it). `--api`, `--identity`, `--web-vault` … override single services. | `bw config server https://vault.example.com`<br>`bw config server` |
| `login` | Log in with email and master password, or a personal API key (`BW_CLIENTID`/`BW_CLIENTSECRET`). Supports authenticator and email two-step login. Prints a session key. | `bw login you@example.com`<br>`bw login you@example.com --passwordfile pw.txt --raw`<br>`bw login you@example.com --method 0 --code 123456`<br>`bw login --apikey` |
| `unlock` | Unlock the vault with the master password and print a new session key. | `export BW_SESSION="$(bw unlock --raw)"`<br>`bw unlock --passwordenv BW_PASSWORD --raw`<br>`bw unlock --check` |
| `lock` | Lock the vault and invalidate session keys. | `bw lock` |
| `logout` | Log out and remove the cached vault. | `bw logout` |
| `sync` | Download the latest vault data (skipped if unchanged unless `--force`). | `bw sync`<br>`bw sync -f`<br>`bw sync --last` |
| `status` | Server URL, last sync, user and lock state as JSON. | `bw status --pretty` |

### Reading the vault

| Command | Description | Examples |
|---|---|---|
| `list items` | List items; filter with `--search`, `--url`, `--folderid`, `--collectionid`, `--organizationid` (ids, `null` or `notnull`), `--trash`, `--archived`. | `bw list items --search github`<br>`bw list items --url https://github.com/login`<br>`bw list items --folderid null --pretty` |
| `list folders` / `collections` / `organizations` | List folders, collections or organizations (`--search`). | `bw list folders`<br>`bw list collections --organizationid <org-id>` |
| `list org-collections` / `org-members` | All collections or members of an organization. | `bw list org-members --organizationid <org-id>` |
| `get item` | Get one item by id or search term (fails if the search is ambiguous). | `bw get item <id>`<br>`bw get item github --pretty` |
| `get username` / `password` / `uri` / `notes` | Get one field of an item. | `bw get password github.com`<br>`bw get username <id>` |
| `get totp` | Current TOTP code of a login. | `bw get totp github.com` |
| `get attachment` | Download and decrypt an attachment (by id or file name). | `bw get attachment photo.jpg --itemid <id> --output ./photo.jpg`<br>`bw get attachment <att-id> --itemid <id> --raw > file` |
| `get folder` / `collection` / `organization` / `org-collection` | Get one object by id or name. | `bw get folder Work`<br>`bw get org-collection <id> --organizationid <org-id>` |

### Export

| Command | Description | Examples |
|---|---|---|
| `export` | Export the vault as `csv`, `json`, `encrypted_json` (account key, or `--password` for a password-protected file) or `zip` (JSON plus attachments). `--organizationid` exports an organization. | `bw export --format json --output ./vault.json`<br>`bw export --format encrypted_json --password`<br>`bw export --organizationid <org-id> --format json` |

### Global options

`--raw` (plain value only), `--pretty` (indented JSON), `--response` (JSON envelope with
`success`), `--quiet`, `--cleanexit`, `--nointeraction`, `--session <key>`. Each has a
`BW_*` environment variable equivalent (`BW_RAW`, `BW_PRETTY`, `BW_SESSION`, …).

## Differences from the official CLI

Not supported, by design (the tool is read-only and targets Vaultwarden):

- Anything that changes the vault: `create`, `edit`, `delete`, `move`/`share`,
  `restore`, `archive`, `confirm`, `import`, `encode`, `get template`.
- `device-approval` and Key Connector (not available on Vaultwarden),
  `report password-health`, `get exposed` (Have I Been Pwned lookup; the tool
  only talks to your server), `get fingerprint` (only useful when confirming
  members, which needs vault changes).
- `send`, `receive`, `generate`, `serve` (REST API), SSO login (`--sso`),
  `completion`, `update`, `sdk-version`.
- Data in old encryption formats (AES-CBC without HMAC, RSA with HMAC);
  login to such accounts fails with "Legacy encryption is no longer supported".
- Two-step login other than authenticator app and email (no YubiKey OTP, Duo
  or WebAuthn).

Intentional behavior differences:

- When the vault is locked and interaction is allowed, a command prompts for the
  master password and unlocks **only for that command**, without invalidating
  existing session keys.
- Help text layout comes from cobra and differs from commander's.

## Library

```go
import "github.com/oneryx/bw"

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
data, fileName, err := c.Export(ctx, bw.ExportOptions{Format: "json"})
```

- `bw.Client` covers everything the CLI does: login/unlock/lock/sync, reading
  items (`Items`, `FindItem`, `FindAttachment`, `Attachment`), folders,
  collections, organizations and members, and export. It never changes vault
  data. All methods are safe for concurrent use; network calls take a
  `context.Context`. A compiled example is in `example_test.go`.
- Errors are values: `bw.ErrLocked`, `bw.ErrNotFound`,
  `*bw.MultipleResultsError`, `*bw.TwoFactorRequiredError`, `*bw.APIError`, …
  Messages match the official CLI and can be shown to users.
- State goes through a `bw.Store` (`FileStore`, `MemoryStore`, or your own,
  e.g. the OS keychain). The vault stays encrypted in the store.
- `NewSession`/`UnlockWithSession` provide the CLI's `BW_SESSION` mechanism if
  several processes need to share an unlocked vault.
- `github.com/oneryx/bw/vault` holds the data model (`vault.Cipher`,
  `vault.Folder`, `vault.Collection`, …) and the official search, sorting and
  URI matching rules; `github.com/oneryx/bw/totp` generates TOTP codes.

The CLI (`internal/cli`) is a thin layer over this API that adds prompts,
flags and output formatting.

## Debugging

`BWGO_DEBUG=1` traces HTTP requests and responses to stderr (this prints
secrets; don't use it in shared logs).
