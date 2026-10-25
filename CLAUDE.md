# bw — notes for working on this repo

Go client library (`github.com/oneryx/bw`) and a Bitwarden-CLI-compatible
command line tool for Vaultwarden. The owner pushes to GitHub; don't push.

## Layout

| Path | Role |
|---|---|
| `*.go` (root, package `bw`) | **The library.** `Client` with typed methods; all business logic lives here. |
| `vault.go` (root) | Unexported decryption of the cached `/sync` data (`openVault`); `Client.open` caches it until `c.save()`. |
| `vault/` (public) | Data model only (`Cipher`, `Folder`, `Collection`, …) plus the official search, sorting and URI matching rules. Keep internal types (`internal/crypto` keys, CLI shapes) out of it. |
| `totp/` (public) | TOTP codes. |
| `internal/cli` | cobra command tree. Thin layer: flags, prompts, stdin, output formatting, mapping library errors to official messages. |
| `internal/api` | HTTP client (identity/API, token refresh, multipart). Takes `context.Context`. |
| `internal/crypto` | KDFs, EncString (type 2 only), RSA (types 3/4), file buffers. |
| `internal/state` | Persisted state (env URLs, device id, tokens, account, encrypted `/sync` cache) behind a `Store`. The CLI keeps it in `data.json` beside the binary (owner's choice) unless `BITWARDENCLI_APPDATA_DIR` is set. |
| `internal/output` | Official CLI response envelope and printing rules (`--raw/--pretty/--response/--quiet/--cleanexit`), CLI JSON object shapes (`ItemOutput`, …), JS date formatting. |
| `internal/export` | Export file shapes (JSON, encrypted JSON items, CSV rows); the export logic itself is in `export.go`. |
| `internal/testutil` | Account registration, org creation, 2FA enabling, seeding items/attachments against a live server (tests and `cmd/vw*` helpers). Writes that the read-only `internal/api` can't do use its own small HTTP helpers (`http.go`). |
| `integration/` | End-to-end tests (`-tags integration`) against a throwaway Vaultwarden container. |

## Rules

- **Library first.** New features go into package `bw` as `Client` methods
  returning typed values and errors; the CLI only adapts them. The library
  must not read env vars, stdin/stdout or prompt; options go in `bw.Options`.
  Every public `Client` method takes `c.mu` (internal helpers like `open`,
  `sync`, `save` assume it is held). Network methods take `ctx`.
- **Errors carry the official CLI message text** (e.g. `"Vault is locked."`,
  `"Not found."`) so the CLI can print `err.Error()` unchanged. Sentinels and
  types are in `errors.go`. CLI-specific wording (mentions of flags,
  `--nointeraction` hints, the `"Error: "` prefix for JS-thrown errors via
  `jsError`) stays in `internal/cli`.
- **CLI output compatibility matters**: commands, flags, env vars (`BW_*`,
  `BITWARDENCLI_APPDATA_DIR`), JSON field names/order and exit codes follow the
  official CLI. Compare against the official binary (verified against
  2026.10.0; install it e.g. at `/usr/local/bin/bw`) using separate data dirs
  (`BITWARDENCLI_APPDATA_DIR=...`).
- **Read-only by design (owner's decision):** nothing in the CLI or library
  changes vault data; only local state (config, tokens, sync cache, session)
  is written. Don't add create/edit/delete/import paths.
- `c.save()` must be used after changing state: it persists and drops the
  cached decrypted vault.
- The library is used by this CLI and possibly other command-line tools, not
  by GUI clients: keep the public API small; don't add GUI-oriented machinery
  (caches, change notifications).

## Deliberately unsupported (owner's decision — don't re-add)

- Any change to vault data, in the CLI and the library: `create`, `edit`,
  `delete`, `move`/`share`, `restore`, `archive`, `confirm`, `import`,
  `encode`, `get template`, attachment upload/delete, folder and
  org-collection management.
- Sends (`send`/`receive`), password generation (`generate`), `serve` (REST
  API), shell `completion`, `update`, `sdk-version`, `get exposed` (the tool
  only talks to the configured server), `get fingerprint`.
- SSO login; two-step login other than authenticator app and email (no
  YubiKey/Duo/WebAuthn).
- Older Vaultwarden/Bitwarden server APIs (no fallbacks; target current
  Vaultwarden, tested with 1.37).
- Old account encryption formats (type 0 and headerless EncStrings, 32-byte
  MAC-less keys, RSA types 5/6).
- Not available on Vaultwarden anyway: `device-approval`, Key Connector.

## Build and test

```sh
make build                 # static stripped binary -> bin/bw (~8 MB)
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
- Offline unit tests of `bw.Client` (`client_test.go`) build an encrypted
  vault in memory; prefer them for filter/search/export logic.
- Test data is created with `testutil.Session.Seed` and
  `testutil.Session.AddAttachment` (direct API calls), since the client itself
  can't write. Vaultwarden answers 422 to cipher creation without
  `encryptedFor`/`organizationId`/`key`.

Manual testing against a local server: `go run ./internal/testutil/cmd/vwregister <server> <email> <pw>`,
`vworg` (create org / invite), `vw2fa` (enable TOTP, prints secret).
`BWGO_DEBUG=1` traces HTTP traffic (contains secrets).
