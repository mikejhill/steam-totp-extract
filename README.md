# Steam TOTP Extract

[![CI](https://github.com/mikejhill/steam-totp-extract/actions/workflows/ci.yml/badge.svg)](https://github.com/mikejhill/steam-totp-extract/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/mikejhill/steam-totp-extract)](LICENSE)

Extract your Steam Guard TOTP secret so you can import it into
[Bitwarden](https://bitwarden.com/) (or any TOTP app) and remove the
Steam mobile authenticator from your phone.

This tool replicates the
[Steam Desktop Authenticator](https://github.com/Jessecar96/SteamDesktopAuthenticator)
linking flow in a minimal Python script — no .NET required. It logs into
your Steam account, removes the existing authenticator, registers a new
one, and outputs the `shared_secret` in a format Bitwarden can import
directly.

## Prerequisites

- **Python 3.12+**
- **[uv](https://docs.astral.sh/uv/getting-started/installation/)** —
  Python package manager
- **Your Steam account credentials** (username and password)
- **Your current Steam Guard revocation code** (starts with `R`,
  e.g. `R12345`) — this is shown when you first set up Steam Guard

## Usage

### 1. Clone and run

```bash
git clone https://github.com/mikejhill/steam-totp-extract.git
cd steam-totp-extract
uv run steam-totp-extract
```

The tool will prompt you for your Steam username, password, and
revocation code. It will then walk you through the extraction process.

### 2. Follow the interactive prompts

```text
Steam Guard TOTP Extractor
─────────────────────────

Steam username: your_username
Steam password:
Current revocation code (e.g. R12345): RXXXXX
```

You will be asked to confirm the login on your Steam mobile app (or
enter an email/device code), then enter an SMS verification code sent to
your phone.

### 3. Collect the output

On success, the tool displays your TOTP secret and a ready-to-paste
Bitwarden URI:

```text
═══════════════════════════════════════════════
  STEAM GUARD TOTP EXTRACTION COMPLETE
═══════════════════════════════════════════════
  Account:          your_username
  SteamID:          XXXXXXXXXXXXXXXXX
  Revocation Code:  RXXXXX  ← SAVE THIS!

  shared_secret (base64): XXXXXXXXXXXXXXXXXXXXXXXXXXX=
  shared_secret (base32): XXXXXXXXXXXXXXXXXXXXXXXXXXXXX

  ┌─ FOR BITWARDEN ────────────────────────────
  │ Paste this into the 'Authenticator Key
  │ (TOTP)' field of your Steam login entry:
  │
  │   steam://XXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  └────────────────────────────────────────────

  Current code:  XXXXX  (verify in Bitwarden)

  Backup saved:  /path/to/steam_guard_XXXXXXXXXXXXXXXXX.json
═══════════════════════════════════════════════
```

### 4. Import into Bitwarden

1. Open Bitwarden and find (or create) your Steam login entry
2. Click **Edit**
3. In the **Authenticator Key (TOTP)** field, paste the `steam://...`
   URI shown in the output
4. Save the entry
5. Verify that Bitwarden generates the same code shown in the output

### 5. Clean up

After confirming Bitwarden generates correct codes:

1. **Save your revocation code** somewhere safe — you will need it if
   you ever need to remove the authenticator
2. **Delete the backup `.json` file** — it contains your unencrypted
   authenticator secrets
3. **Clear your terminal scrollback** — the secrets were printed to
   your screen

## Options

```text
usage: steam-totp-extract [--output-dir DIR] [--log-level LEVEL]

options:
  --output-dir DIR     Directory for authenticator backup (default: current directory)
  --log-level LEVEL    Logging verbosity: DEBUG, INFO, WARNING, ERROR (default: INFO)
```

## How It Works

This tool performs the same authenticator linking flow as
[Steam Desktop Authenticator](https://github.com/Jessecar96/SteamDesktopAuthenticator),
ported from the
[SteamAuth](https://github.com/geel9/SteamAuth) C# library:

1. **Login** — Authenticates via Steam's `IAuthenticationService` API
   using RSA-encrypted credentials
2. **Remove** — Removes the existing authenticator using your
   revocation code (`ITwoFactorService/RemoveAuthenticator`)
3. **Add** — Registers a new authenticator
   (`ITwoFactorService/AddAuthenticator`)
4. **Finalize** — Confirms via SMS code
   (`ITwoFactorService/FinalizeAddAuthenticator`)
5. **Output** — Converts the `shared_secret` to base32 and formats it
   as a `steam://` URI for Bitwarden

All network requests go exclusively to `https://api.steampowered.com`.
No data is sent anywhere else.

## Security

- **No data exfiltration** — credentials are only sent to Steam's
  official API over HTTPS
- **No system modifications** — no registry changes, no settings
  changes, no modification of existing files
- **Minimal dependencies** — only `requests` and `rsa` at runtime
  (both well-established PyPI packages)
- **Password handling** — entered via `getpass` (not echoed),
  RSA-encrypted before transmission
- **Single file write** — only the authenticator backup is written to disk

> **⚠️ Important:** The backup file contains your unencrypted
> authenticator secrets. Delete it after importing into Bitwarden.

## Development

```bash
uv sync --group dev
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```

## Acknowledgments

This tool is a Python port of the authenticator linking flow from:

- [SteamAuth](https://github.com/geel9/SteamAuth) by Joshua Coffey —
  the C# library implementing Steam's TOTP algorithm and two-factor
  service API
- [Steam Desktop Authenticator](https://github.com/Jessecar96/SteamDesktopAuthenticator)
  by Jesse Cardone — the desktop application that inspired this tool
- [KeeTrayTOTP guide][keetraytotp] — reference guide for extracting
  the TOTP secret from SDA

[keetraytotp]: https://github.com/KeeTrayTOTP/KeeTrayTOTP/blob/master/docs/secret_sda/steam_desktop_authenticator_sda.md

## License

[MIT](LICENSE)
