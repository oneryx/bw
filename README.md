# bw — a Go Bitwarden CLI for Vaultwarden

A single static binary (~11 MB, vs ~137 MB for the official Node build) that
re-implements the [official Bitwarden CLI](https://bitwarden.com/help/cli/)
for self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
servers. Commands, arguments, flags, environment variables, JSON output and
exit codes follow the official CLI (verified side-by-side against `bw`
2026.10.0 and Vaultwarden 1.37), so existing scripts keep working.

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

`login` (password, `--apikey`, `--sso`, 2FA: authenticator, email, YubiKey OTP),
`logout`, `lock`, `unlock`, `sync`, `status`, `config server`, `list`, `get`
(incl. `totp`, `exposed`, `attachment`, `fingerprint`, `template`), `create`,
`edit`, `delete`, `restore`, `archive`, `move`/`share`, `confirm org-member`,
`import`, `export` (`csv`, `json`, `encrypted_json`, `zip`, password-protected,
organization exports), `generate`, `encode`, `send` (+ `list`, `template`, `get`,
`create`, `edit`, `remove-password`, `delete`), `receive`, `serve` (REST API),
`completion` (zsh, bash, fish, powershell), `update`, `sdk-version`.

Import formats: `bitwardencsv`, `bitwardenjson` (plain, account-encrypted and
password-protected), `chromecsv`, `bravecsv`, `edgecsv`, `operacsv`,
`vivaldicsv`, `firefoxcsv`, `keepass2xml`, `keepassxcsv`, `lastpasscsv`.

## Differences from the official CLI

Not implemented (not available on Vaultwarden, or not ported yet):

- `device-approval` (Bitwarden-only), Key Connector, `report password-health`.
- Duo and WebAuthn two-step login (need a browser; the official CLI lacks WebAuthn too).
- Email-verified Sends (`--emails`) return a clear error.
- Import formats other than those listed above (e.g. 1Password, Dashlane,
  `keepasskdbx`); `bw import --formats` lists only what is supported.
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
- `bw login --sso` is implemented (PKCE, local callback on ports 8065-8070) but
  has only been exercised up to the token exchange, not against a real IdP.

## Debugging

`BWGO_DEBUG=1` traces HTTP requests and responses to stderr (this prints
secrets; don't use it in shared logs).
