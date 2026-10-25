# Plan: `bw` — a Go reimplementation of the Bitwarden CLI for Vaultwarden

## Context

The official Bitwarden CLI (`apps/cli` in bitwarden/clients) is TypeScript/Node and is distributed as a large binary (~100 MB). The goal is a small, dependency-light, single static Go binary named `bw` that:

- talks to a **self-hosted Vaultwarden** server (configurable URL via `bw config server <url>`),
- accepts the **same commands, arguments, flags and env vars** as the official CLI and produces **output that matches it** (JSON shape, `--raw`/`--pretty`/`--response`/`--quiet` behavior, exit codes), so existing scripts keep working,
- skips features that Vaultwarden doesn't implement (or that need Bitwarden's non-OSS/cloud services).

The working dir `/home/yx/src/go/bw` is empty (greenfield). Go 1.27.3 is installed. After approval I'll also copy this plan to `/home/yx/src/go/bw/PLAN.md`.

---

## 1. Third-party libraries (please review)

★ = my preference. Go 1.24+ stdlib already covers PBKDF2 (`crypto/pbkdf2`), HKDF (`crypto/hkdf`), AES-CBC, HMAC, RSA-OAEP, SHA, HTTP client/server (with method+path routing), CSV, XML, ZIP and `embed`, so the list stays short.

| Library | Purpose | Pick |
|---|---|---|
| `github.com/spf13/cobra` (+ `spf13/pflag`) | Command tree, help text, flag parsing, built-in `completion` generation. Supports camelCase long flags (`--minNumber`) and optional flag values (`--sso [identifier]`, `export --password [password]`). | ★ |
| ↳ alt: `github.com/urfave/cli/v3` or `github.com/alecthomas/kong` | Same role; less ecosystem/completion support. | |
| `golang.org/x/crypto` | Only for `argon2` (Argon2id KDF). | ★ |
| `golang.org/x/term` | Hidden master-password prompt, TTY detection. | ★ |
| `golang.org/x/net/publicsuffix` | Base-domain URI matching (`--url`, `get password <search>` by URI, default match type "domain"). | ★ |
| `github.com/google/uuid` | Device identifier, client-generated IDs. (Could hand-roll a v4 in ~10 lines instead.) | ★ (optional) |
| `github.com/gofrs/flock` | File lock on the data file so `bw serve` and concurrent CLI calls don't corrupt state. | optional |
| `github.com/pquerna/otp` | TOTP. Not preferred — own implementation is ~50 lines and must also handle `steam://` codes like the official CLI. | ✗ |
| `github.com/charmbracelet/huh` / `survey` | Fancy interactive prompts (2FA method picker). Not preferred — plain stdin prompts are enough. | ✗ |
| `github.com/stretchr/testify` | Test assertions. Not preferred — stdlib `testing` is fine. | ✗ |

Embedded data (not a library): EFF long wordlist (passphrase generation + account fingerprint phrase), via `go:embed`.

---

## 2. Command coverage

Global options (all commands): `--pretty`, `--raw`, `--response`, `--cleanexit`, `--quiet`, `--nointeraction`, `--session <key>`, `-v/--version`, `-h/--help`. Env vars: `BW_SESSION`, `BW_CLIENTID`, `BW_CLIENTSECRET`, `BW_NOINTERACTION`, `BW_RAW`, `BW_PRETTY`, `BW_RESPONSE`, `BW_QUIET`, `BW_CLEANEXIT`, `BITWARDENCLI_APPDATA_DIR`. Custom CAs work via Go's native `SSL_CERT_FILE`/`SSL_CERT_DIR` (replaces `NODE_EXTRA_CA_CERTS`).

| Command | Args / flags (same as official) | Status |
|---|---|---|
| `login [email] [password]` | `--method`, `--code`, `--apikey`, `--passwordenv`, `--passwordfile`, `--check`, `--sso [id]` | Password + API key ✅. 2FA: Authenticator(0), Email(1), YubiKey OTP(3) ✅; Duo/WebAuthn ❌ (need browser). `--sso` ⏳ later phase (Vaultwarden ≥1.35 has OIDC SSO; needs local browser callback) |
| `logout`, `lock` | — | ✅ |
| `unlock [password]` | `--check`, `--passwordenv`, `--passwordfile` | ✅ (prints `export BW_SESSION=...` like official) |
| `sync` | `-f/--force`, `--last` | ✅ |
| `status` | — | ✅ (`serverUrl`, `lastSync`, `userEmail`, `userId`, `status`) |
| `config server [url]` | `--web-vault`, `--api`, `--identity`, `--icons`, `--notifications`, `--events`, `--key-connector` | ✅ (`--key-connector` accepted/stored, unused) |
| `list <object>` | `items|folders|collections|org-collections|org-members|organizations`; `--search`, `--url`, `--folderid`, `--collectionid`, `--organizationid` (each accepts `null`/`notnull`), `--trash`, `--archived` | ✅ (`--archived` only if server supports archive, else empty/error) |
| `get <object> <id>` | `item|username|password|uri|totp|notes|exposed|attachment|folder|collection|org-collection|organization|template|fingerprint|send`; `--itemid`, `--output`, `--organizationid` | ✅ (id or search term, "more than one result" error like official) |
| `create <object> [encodedJson]` | `item|attachment|folder|org-collection`; `--file`, `--itemid`, `--organizationid` | ✅ |
| `edit <object> <id> [encodedJson]` | `item|item-collections|folder|org-collection`; `--organizationid` | ✅ |
| `delete <object> <id>` | `item|attachment|folder|org-collection`; `-p/--permanent`, `--itemid`, `--organizationid` | ✅ |
| `restore item <id>` | — | ✅ |
| `archive item <id>` | — | ⚠️ implement, return clear error if Vaultwarden lacks the endpoint |
| `move <id> <orgId> [encodedJson]`, `share` (deprecated alias) | — | ✅ |
| `confirm org-member <id>` | `--organizationid` | ✅ |
| `import [format] [input]` | `--formats`, `--organizationid`, `--keyfile`, `--passwordenv`, `--passwordfile` | ✅ subset of formats (see §6) |
| `export` | `--output`, `--format csv|json|encrypted_json|zip`, `--password [pw]`, `--organizationid` | ✅ |
| `generate` | `-u -l -n -s -p`, `--length`, `--words`, `--minNumber`, `--minSpecial`, `--separator`, `-c/--capitalize`, `--includeNumber`, `--ambiguous` | ✅ (offline) |
| `encode` | — | ✅ (offline) |
| `send <data>` + `list|template|get|receive|create|edit|remove-password|delete` | `-f/--file`, `-d/--deleteInDays`, `--password`, `-a/--maxAccessCount`, `--hidden`, `-n/--name`, `--notes`, `--fullObject`, `--emails`; sub-flags `--text`, `--output`, `--obj`, `--itemid`, `--passwordenv`, `--passwordfile` | ✅ (`--emails` ⚠️ only if Vaultwarden supports email-restricted Sends) |
| `receive <url>` | same as `send receive` | ✅ |
| `serve` | `--hostname`, `--port`, `--disable-origin-protection` (Vault Management REST API) | ✅ later phase |
| `completion --shell <shell>` | zsh (official) + bash/fish via cobra | ✅ |
| `update` | — | prints current version / "not supported" (no auto-update) |
| `sdk-version` | — | prints Go module version |
| `device-approval …` | — | ❌ skipped (Bitwarden non-OSS, not in Vaultwarden) |
| `report password-health` | — | ❌ skipped initially (not in core program; can add later) |

---

## 3. Architecture

```
cmd/bw/main.go                 entry point; version via -ldflags
internal/cli/                  one file per command (login.go, unlock.go, list.go, get.go, create.go,
                               edit.go, delete.go, restore.go, archive.go, move.go, confirm.go, import.go,
                               export.go, generate.go, encode.go, config.go, status.go, sync.go,
                               send.go, receive.go, serve.go, completion.go) + root.go (global flags, env)
internal/output/               Response types matching official: MessageResponse{object:"message",title,message,raw},
                               ListResponse{object:"list",data}, StringResponse{object:"string",data},
                               {success,data|message} wrapper for --response; --raw/--pretty/--quiet/--cleanexit,
                               exit codes (0/1)
internal/api/                  HTTP client: identity (prelogin, token: password/client_credentials/refresh_token,
                               2FA email send), sync, ciphers, folders, collections, orgs, attachments (v2 upload
                               + legacy), sends, HIBP. Auto token refresh. Headers: Device-Type 25 (Linux CLI),
                               Bitwarden-Client-Name: cli, Bitwarden-Client-Version.
internal/crypto/               KDF (PBKDF2-SHA256, Argon2id with SHA256(email) salt), master key → HKDF stretch,
                               master password hash, EncString parse/encrypt/decrypt (types 0, 2, 3, 4, 6),
                               EncArrayBuffer (attachments/send files), SymmetricKey(enc+mac), RSA-OAEP,
                               per-cipher keys, Send key derivation (HKDF "bitwarden-send"/"send"),
                               fingerprint phrase
internal/state/                Data dir (BITWARDENCLI_APPDATA_DIR or $XDG_CONFIG_HOME/Bitwarden CLI-go/),
                               data.json (0600): server URLs, device id, tokens, account (email, id, kdf params,
                               protected user key, encrypted private key, org keys), encrypted vault cache from
                               last sync, last sync date. Session: on unlock generate random 64-byte session key,
                               store user key encrypted under it; BW_SESSION decrypts it; lock deletes it.
internal/vault/                Server models ⇄ decrypted "view" models; JSON output structs with official field
                               names/order (item, login, uris, card, identity, secureNote, sshKey, fields,
                               passwordHistory, attachments, fido2Credentials…); templates; search
                               (port of searchCiphersBasic); URI matching (domain/host/startsWith/exact/regex/never);
                               filtering (null/notnull)
internal/generator/            password & passphrase generator (crypto/rand), embedded EFF wordlist
internal/totp/                 RFC 6238 + otpauth:// parsing + steam://
internal/importer/             format registry; bitwarden csv/json/encrypted json + selected others
internal/exporter/             csv, json, encrypted_json (account key or password-protected), zip w/ attachments
internal/serve/                net/http REST server mirroring official `bw serve` routes
```

Key compatibility points:
- **Data stays encrypted at rest**: vault cache is stored as the server returned it (EncStrings); only decrypted in memory per command.
- **Session semantics identical**: `bw unlock` → session key; commands without valid `BW_SESSION`/`--session` return "Vault is locked." exactly like official.
- **Input**: `encodedJson` is base64 JSON, read from stdin when omitted (with `bw encode`). Same validation error messages where feasible.
- **Editing preserves unknown/encrypted fields** (cipher `key`, fido2 credentials) so round-trips through this CLI never lose data written by official clients.
- New items are created without per-cipher keys initially (official behavior depends on server feature flag); existing cipher keys are honored.
- Not compatible with the official CLI's `data.json` (internal format differs) — uses its own directory so both can coexist.

---

## 4. Implementation phases

1. **Skeleton** – go module, cobra root with all commands/flags registered (stubs return "Not implemented"), output package, state package, `config server`, `status`, `generate`, `encode`, `completion`. Makefile/`go build -ldflags "-s -w"`.
2. **Crypto core** – KDFs, EncString, keys, RSA, test vectors (from official repo's `*.spec.ts` known values).
3. **Auth** – prelogin, `login` (password, API key, 2FA), token refresh, `unlock`, `lock`, `logout`, `sync`.
4. **Read path** – decrypt vault; `list`, `get` (all objects incl. totp, exposed, fingerprint, template, attachment download).
5. **Write path** – `create`, `edit`, `delete`, `restore`, `archive`, `move`/`share`, attachments upload/delete, org collections, `confirm org-member`.
6. **Send** – all `send` subcommands and `receive`.
7. **Import/Export**.
8. **`serve`** and **`--sso`**.

---

## 5. Verification

- **Unit tests** (`go test ./...`): crypto against known vectors, EncString round-trips, generator constraints, TOTP RFC vectors, search/URI matching, CSV/JSON import-export round-trip, output formatting golden files (compare JSON shapes with official examples).
- **Integration tests** (`go test -tags integration ./...`): spin up `docker.io/vaultwarden/server` with podman on a random port, register a test account via the API (client-side crypto implemented in a test helper), then exercise each command end-to-end: login/unlock/sync, CRUD on items/folders/attachments, org collection + member confirm, send create/receive, export→import round-trip, `serve` endpoints with curl.
- **Manual check** against your real instance: `bw config server https://your.vaultwarden`, `bw login`, `export BW_SESSION=$(bw unlock --raw)`, `bw list items --search github --pretty`, `bw get password github`.
- **Binary size**: report `ls -lh` of stripped build (expect ~8–12 MB).

---

## 6. Decisions I'll take unless you say otherwise

- Binary name `bw`; module path `github.com/<you>/bw` (tell me the real one).
- Import formats in first pass: `bitwardencsv`, `bitwardenjson`, `bitwardenpasswordprotected`, `chromecsv` (also Edge/Brave), `firefoxcsv`, `keepass2xml`, `lastpasscsv`, `1passwordcsv`/`1password1pux`, `keepassxccsv`. Others listed by `--formats` would error "format not supported yet" (official supports ~60).
- `update` does not self-update.
- No Duo/WebAuthn 2FA in CLI (official CLI doesn't support WebAuthn either).

---

## 7. Implementation status (2026-10-25)

All 8 phases implemented. Verified side-by-side against the official `bw` 2026.10.0 binary on Vaultwarden 1.37.4 (outputs diffed byte-for-byte where deterministic):

- Read commands: 60 reference cases identical (only `status.lastSync` and `--help` layout differ).
- Create/edit/delete/restore/archive/attachments, org commands, Sends, `serve`: identical output (IDs/dates masked); each CLI reads/decrypts data written by the other.
- Exports: CSV/JSON (personal + org) byte-identical; encrypted JSON structurally identical; imports of all supported formats produce identical vault contents.
- Tests: `make test` (crypto vectors from bitwarden/sdk-internal, RFC 6238, output, search, importers) and `make integration` (end-to-end in a disposable Vaultwarden container).

Deviations from this plan:
- Import formats: 1Password (`1password1pux`/csv) not ported yet; added the Chrome-family aliases (`bravecsv`, `edgecsv`, `operacsv`, `vivaldicsv`).
- `gofrs/flock` not used (atomic file writes + a request mutex in `serve` instead).
- Search diacritic folding uses a generated table instead of `golang.org/x/text` (avoids an unreviewed dependency).
