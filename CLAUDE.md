# bw — notes for working on this repo

Go client library (`github.com/oneryx/bw`) and a Bitwarden-CLI-compatible
command line tool for Vaultwarden. The owner pushes to GitHub; don't push.

## Layout

| Path | Role |
|---|---|
| `*.go` (root, package `bw`) | **The library.** `Client` with typed methods; all business logic lives here. |
| `vault/` (public) | Data model (`Cipher`, `Folder`, `DecryptedSend`, …), decrypt/encrypt of vault objects (`Vault`), search, URI matching, CSV/JSON export shapes, CLI JSON response shapes and templates. |
| `generator/`, `totp/` (public) | Password/passphrase generator, TOTP codes. |
| `internal/cli` | cobra command tree. Thin layer: flags, prompts, stdin, output formatting, mapping library errors to official messages. `serve.go` implements `bw serve` by re-running CLI commands in capture mode. |
| `internal/api` | HTTP client (identity/API, token refresh, multipart). Takes `context.Context`. |
| `internal/crypto` | KDFs, EncString (type 2 only), RSA (types 3/4), file buffers, fingerprint. |
| `internal/state` | Persisted state (env URLs, device id, tokens, account, encrypted `/sync` cache) behind a `Store`. |
| `internal/importer` | `bitwardencsv`, `bitwardenjson` (plain/encrypted/password-protected), `keepass2xml`, `keepassxcsv`. |
| `internal/output` | Official CLI response envelope and printing rules (`--raw/--pretty/--response/--quiet/--cleanexit`). |
| `internal/testutil` | Account registration, org creation, 2FA enabling against a live server (tests and `cmd/vw*` helpers). |
| `integration/` | End-to-end tests (`-tags integration`) against a throwaway Vaultwarden container. |

## Rules

- **Library first.** New features go into package `bw` as `Client` methods
  returning typed values and errors; the CLI only adapts them. The library
  must not read env vars, stdin/stdout or prompt; options go in `bw.Options`.
  Every public `Client` method takes `c.mu` (internal helpers like `open`,
  `sync`, `save`, `cacheCipher` assume it is held). Network methods take `ctx`.
- **Errors carry the official CLI message text** (e.g. `"Vault is locked."`,
  `"Not found."`) so the CLI can print `err.Error()` unchanged. Sentinels and
  types are in `errors.go`. CLI-specific wording (mentions of flags,
  `--nointeraction` hints, the `"Error: "` prefix for JS-thrown errors via
  `jsError`/`orgKeyError`) stays in `internal/cli`.
- **CLI output compatibility matters**: commands, flags, env vars (`BW_*`,
  `BITWARDENCLI_APPDATA_DIR`), JSON field names/order and exit codes follow the
  official CLI. Compare against the official binary at `/usr/local/bin/bw`
  (2026.3.0) using separate data dirs (`BITWARDENCLI_APPDATA_DIR=...`).
- `c.save()` must be used after changing state: it persists and drops the
  cached decrypted vault. Server responses for changed objects are written
  into the cached sync data (`UpsertVaultObject`/`DeleteVaultObject`) instead
  of a full resync, except where the server changes other objects too (folder
  delete, import).
- Edits must preserve fields this client doesn't understand (cipher keys,
  fido2 credentials, newer item types kept as `json.RawMessage`).

## Deliberately unsupported (owner's decision — don't re-add)

Older Vaultwarden/Bitwarden server APIs (no fallbacks; target current
Vaultwarden, tested with 1.37), old account encryption formats (type 0
EncStrings, headerless EncStrings, 32-byte MAC-less keys, RSA types 5/6), SSO
login, YubiKey/Duo/WebAuthn 2FA (authenticator and email only), shell
`completion`, `update`, `sdk-version`, importers for Chrome/Edge/Brave/Opera/
Vivaldi, Firefox, LastPass and 1Password. Not available on Vaultwarden:
`device-approval`, Key Connector, email-verified Sends.

## Build and test

```sh
make build VERSION=x.y.z   # static stripped binary -> bin/bw (~11 MB)
make test                  # go vet + unit tests
make integration           # podman/docker, pulls docker.io/vaultwarden/server
go vet -tags integration ./integration   # integration code isn't vetted by `make test`
```

Integration test notes:
- The container serves HTTPS with a generated cert; tests set `SSL_CERT_FILE`.
  Plain-HTTP servers need `BWCLI_ENV=development` (CLI) or
  `Options.AllowInsecureHTTP` (library).
- The container raises `LOGIN_RATELIMIT_*`; Vaultwarden's default (10 logins
  per minute) is easily hit by the suite.
- Enabling TOTP consumes the current code and Vaultwarden rejects reused codes:
  log in with the next time step's code (`nextCode`) and use one account per
  TOTP login.
- `library_test.go` exercises `bw.Client` directly; CLI tests run the built
  binary with `BW_NOINTERACTION=true`.

Manual testing against a local server: `go run ./internal/testutil/cmd/vwregister <server> <email> <pw>`,
`vworg` (create org / invite), `vw2fa` (enable TOTP, prints secret).
`BWGO_DEBUG=1` traces HTTP traffic (contains secrets).
