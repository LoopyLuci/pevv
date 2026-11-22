<p align="center">
  <img src="src/pevv/brand/pevv-logo.svg" alt="PEVV padlock logo" width="128" />
</p>

<h1 align="center">PEVV</h1>
<p align="center"><b>Password &amp; Environment Variable Vault</b><br/>An open-source, zero-knowledge vault for logins, API keys, secrets and <code>.env</code> variables.<br/>Web app, browser extension and desktop app. One encrypted file format.</p>

<p align="center">
  <a href="https://github.com/LoopyLuci/pevv/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/LoopyLuci/pevv/actions/workflows/ci.yml/badge.svg" /></a>
  <img alt="License: GPL-3.0" src="https://img.shields.io/badge/license-GPL--3.0-blue" />
</p>

> PEVV was originally developed as part of Luciverse and now lives here as an independent project.
> **Status: pre-1.0.** It has had no independent security audit. Read [SECURITY.md](SECURITY.md) and the [threat model](docs/DESIGN.md#3-threat-model)
> before trusting it with anything you cannot afford to lose.

## What it is

- **Everything is encrypted on your device.** The master password is stretched with Argon2id and wraps a random 256-bit vault key.
  Every item is sealed separately with AES-256-GCM. Nothing readable ever touches a server or the disk.
- **No account, no server needed.** It runs fully offline. Optional sync (to a Supabase project *you* host) copies only the ciphertext.
- **Many ways to unlock:** master password, passkey or security key (WebAuthn PRF), recovery codes, recovery kit, USB key file.
  Add an authenticator (TOTP), a passkey or a USB key file as a second factor.
- **Built for developers too:** named environments (`dev`, `prod`, ...) of variables, `.env` import and export, per-program grants and a
  `pevv run -- command` command-line tool on the desktop.

## Clients

| | Web app | Browser extension | Desktop app | Android |
|---|:--:|:--:|:--:|:--:|
| Vault, items, generator, health, import/export | yes | yes (vault screen) | yes | yes (native app) |
| Fill and save logins on websites | no | **yes** (exact-origin only) | via the extension link | autofill service (exact host; apps by asset links or your choice) |
| Passkey / security-key unlock | yes | no (use the desktop link) | yes (native) | PRF passkey unlock where the passkey provider supports it |
| Auto-type into other programs | no | no | **yes** (global shortcut) | |
| `pevv run` command line | no | no | **yes** | |
| Passkey provider for other apps and sites | no | no | experimental Windows 11 provider, off by default | Credential Manager provider (Android 14+) |
| Auto-lock, clipboard clear | yes | yes | yes, plus OS lock/suspend | yes, plus biometric unlock (Keystore) |
| Where the vault file lives | `localStorage` | `chrome.storage.local` | file in the app-data folder | private app storage, no system backup |

Docs: [web](docs/CLIENT_WEB.md), [extension](docs/CLIENT_EXTENSION.md), [desktop](docs/CLIENT_DESKTOP.md), [Android](docs/CLIENT_ANDROID.md) ([design](docs/ANDROID.md); the release APK is unsigned and not yet tested on real devices).

## Security model in one page

- **Zero knowledge.** The key is derived from what only you know and lives in memory only while unlocked (a non-extractable
  `CryptoKey` where possible). It is never written to disk, `localStorage`, `chrome.storage` or a server.
- **Authenticated encryption everywhere.** AES-256-GCM with a fresh 96-bit IV and AAD binding each value to its vault, id and version, so
  entries cannot be swapped or rolled back inside a file. A sealed index detects added or removed entries.
- **Memory-hard KDF with a downgrade floor.** Argon2id (default 64 MiB, t=3) via WebAssembly, PBKDF2-SHA256 (600k+) as fallback; weaker
  parameters are refused on unlock.
- **Exact-origin fills.** The extension fills a login only into the page whose scheme, host and port equal the saved one, never into
  frames, and only after an explicit action by you.
- **No plaintext at rest.** Titles, sites, usernames and notes are encrypted too. Decrypted values never go to storage. The clipboard is
  cleared after a delay.
- **Strict CSP** on every surface (no remote scripts, no inline scripts).
- **No password reset.** If you lose the master password and every recovery method, the data is gone. That is the design.
- It does **not** protect against malware or a malicious extension on a device while the vault is unlocked.

Details: [SECURITY.md](SECURITY.md), [docs/CRYPTO.md](docs/CRYPTO.md), [docs/DESIGN.md](docs/DESIGN.md).

## Quick start

Requirements: Node.js 20 or newer (`.nvmrc` says 22). For the desktop app also Rust (stable) and the
[Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/).

```bash
git clone https://github.com/LoopyLuci/pevv.git
cd pevv
npm ci

npm run dev                 # web app on http://localhost:5173
npm test                    # unit tests
npm run build               # web app -> dist/ (host it anywhere static)
npm run build:extension     # extension -> dist-extension/ (Chromium) and dist-extension-firefox/
npm run desktop:build       # desktop installers -> desktop/src-tauri/target/release/bundle/
```

Load the extension: `chrome://extensions` > Developer mode > *Load unpacked* > `dist-extension/`.
Firefox: `about:debugging` > *This Firefox* > *Load Temporary Add-on* > `dist-extension-firefox/manifest.json`.

Release builds are **unsigned** (Windows SmartScreen and Gatekeeper-style warnings are expected). See [docs/RELEASING.md](docs/RELEASING.md).

### Optional: sync and vault QR

Off by default. To enable it, run your own Supabase project and build with `VITE_PEVV_SYNC_URL` and `VITE_PEVV_SYNC_ANON_KEY`
([docs/SYNC_SELF_HOSTING.md](docs/SYNC_SELF_HOSTING.md)). Without it, vaults move by encrypted export file or offline QR codes.

## Repo map

```
src/pevv/            the engine (crypto, vault, store, ...) and the web / extension / desktop glue
  host/              the only seam to an optional backend and the language store
  ui/  extension/  desktop/  brand/
extension/           manifest.json and popup / vault pages
desktop/src-tauri/   Rust: desktop app, `pevv` CLI, native-messaging host
scripts/             extension build and packaging, desktop build
supabase/            SQL for the optional sync backend
tests/               unit (Vitest), e2e (Playwright), e2e-extension
docs/                architecture, vault format, crypto, clients, sync, releasing
```

## Contributing, security, license

- [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [AGENTS.md](AGENTS.md) for AI coding agents.
- Report vulnerabilities **privately** via [GitHub Security Advisories](https://github.com/LoopyLuci/pevv/security/advisories/new). See [SECURITY.md](SECURITY.md).
- Licensed under the [GNU General Public License v3.0](LICENSE) (`GPL-3.0-only`).
