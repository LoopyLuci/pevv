# Architecture

PEVV is one TypeScript vault engine with several thin shells around it. Every client reads and writes the **same encrypted file
format** ([VAULT_FORMAT.md](VAULT_FORMAT.md)), so a vault made in one client opens in all the others.

```
                        +-----------------------------+
                        |        src/pevv/ (TS)       |
                        |  crypto, vault, model,      |
                        |  store, webauthn, totp ...  |
                        +--+---------+--------+-------+
                           |         |        |
          web app (index.html)   extension    desktop (Tauri shell)
          src/pevv/boot.tsx    src/pevv/      src/pevv/desktop/ + desktop/src-tauri (Rust)
                               extension/
                                  |                 |
                                  +-- native messaging <-> pevv-native-host (Rust) -- pipe --+

          optional, all clients:  src/pevv/host/  ->  your Supabase project (ciphertext only)
```

## Layers inside `src/pevv/`

| Path | Role |
|---|---|
| `bytes.ts`, `crypto.ts` | Base64 helpers, Argon2id / PBKDF2, HKDF, AES-256-GCM seal/open. No UI, no I/O. |
| `vault.ts`, `model.ts`, `recovery.ts`, `usbkey.ts`, `totp.ts`, `webauthn.ts`, `devices.ts` | The vault file format, key slots, second factors, recovery kit, USB key file, passkeys, device roster. Pure logic over the model. |
| `store.ts` | The Zustand store: unlock state, entries in memory, persistence to `localStorage`, import/export, auto-lock, QR hand-off. The only place plaintext lives, and only while unlocked. |
| `sync.ts`, `roster.ts` | Opt-in sync of the ciphertext file, and live device exchange. Both go through `host/`. |
| `host/` | **The seam to the outside world** (below). The only code that talks to Supabase or reads build-time configuration. |
| `ui/` | React views (items, tools, auth, QR). Language strings are in `i18n.ts` (EN and ES). |
| `extension/` | Browser extension: service worker, content script, popup, vault-screen bridge, desktop link. |
| `desktop/` | Desktop webview glue: IPC bridge, browser link, auto-type, CLI access, passkey provider. |
| `brand/` | The padlock logo. |

## `src/pevv/host/`: the only outward dependencies

PEVV started inside a larger app (Luciverse) and was extracted. Everything it used to import from there is replaced by four small modules:

| Module | Provides | Why |
|---|---|---|
| `config.ts` | `SYNC_URL`, `SYNC_ANON_KEY`, `PUBLIC_URL`, `syncConfigured()` | Build-time configuration (`VITE_PEVV_*`). With nothing set, sync is off and nothing touches the network. |
| `cloud.ts` | A tiny named-file store (`useCloudFiles`), the account (`currentAccount`, `sendMagicLink`, `signOut`), `pullCloud()` | Optional sync of the encrypted vault file to one row in `pevv_blobs`. |
| `relay.ts` | Vault-QR transfer lane and live device roster over Supabase Realtime broadcast | Optional. Anonymous session, ciphertext only. |
| `locale.ts` | `useLocaleStore`, `initLocale()` | The language setting (`en` / `es`), saved locally. |

To run PEVV against a different backend, replace `cloud.ts` and `relay.ts`, keeping their exported names.

## Data flow

1. **Unlock**: KDF(master password) -> KEK -> unwrap the vault key from a slot -> open the sealed meta -> open each entry. The key
   exists only in memory (a non-extractable `CryptoKey` where the platform allows it).
2. **Write**: every change re-seals the entry (new version, AAD binds id + version), bumps `rev`, re-seals meta, then persists:
   `localStorage` in the web app, `chrome.storage.local` via the bridge in the extension, a file via the Rust shell on desktop.
3. **Sync (optional)**: the whole *ciphertext* `VaultFile` is mirrored to `pevv_blobs` when the user turns it on; a higher `rev` wins.

## Rust shell (`desktop/src-tauri/`)

Tauri 2. Does what a webview cannot: an atomic vault file with backups, clipboard with timed clear, OS lock/suspend events, native
passkey and security-key access, USB key files, the `pevv` command-line tool, the native-messaging host for the extension link,
auto-type into other programs and (optional feature) a Windows passkey provider. Details: [CLIENT_DESKTOP.md](CLIENT_DESKTOP.md).

## Repo map

```
src/pevv/            TypeScript engine, UI and the shells' glue
src/styles/          Tailwind entry and palette tokens
extension/           manifest.json and the popup / vault HTML pages
desktop/src-tauri/   Rust: app, pevv CLI, pevv-native-host
scripts/             build-extension.mjs, extension-package.mjs, desktop-build.mjs
supabase/            optional sync backend SQL
tests/unit/          Vitest (jsdom), pevv.*.test.ts
tests/e2e/           Playwright against the built web app
tests/e2e-extension/ Playwright with the unpacked extension (and a Firefox WebDriver BiDi script)
public/_headers      Security headers for hosting the web app
docs/                this documentation
.github/             CI, release, CodeQL, secret scanning, templates
```
