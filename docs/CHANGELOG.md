# Changelog

PEVV history. PEVV was developed as part of Luciverse until it moved to this repository; the entries below are the
PEVV entries from that project's log, lightly cleaned. Earlier entries mention the Luciverse site, the Android app and
the original sync; those no longer apply to this repository (see [docs/CLIENT_ANDROID.md](CLIENT_ANDROID.md)).

## Unreleased

- Standalone repository: GPL-3.0, no dependency on the Luciverse game, optional self-hosted Supabase sync (`VITE_PEVV_SYNC_URL`), passkey rpId from `PEVV_RP_ID`, CI, release workflow, security policy, open-source documentation.
- Removed from this repository (they stay in Luciverse): the in-game HUD launcher, the in-game autofill buttons and save offers, and the game terminal commands (`vault ...`, `$VAR` expansion).
- Vault QR links are built from `VITE_PEVV_PUBLIC_URL`; without it the QR carries the bare code.
- New authenticator entries use the issuer `PEVV` (was `Luciverse PEVV`).

## 2026-11-21 - PEVV desktop: Windows 11 passkey provider (feature `win-passkey-provider`, untested on Windows 11)

- PEVV can be a third-party passkey provider (plugin authenticator) for Windows 11: sites create passkeys in the Windows dialog under "PEVV", and sign in with them in any browser or app. The vault keeps them as a new optional item kind `passkey` (rpId, credential id, user handle, user name, P-256 private key inside the sealed item, sign count). No vault format change; older clients keep the item through their edits and never offer it as a login, and this client hides it from the item list and every login, auto-type and terminal path.
- ES256 credential creation, assertion signing (DER), authenticatorData, COSE key and attestation `none` in TypeScript with WebCrypto (`src/pevv/passkeyProvider.ts`), tested against known vectors including RFC 6979.
- Rust, behind the cargo feature `win-passkey-provider` (off by default): the CTAP2 CBOR request and response codec with `ciborium`, a broker that wakes the window if the vault is locked and checks what the vault window answers, hand-declared FFI and the `IPluginAuthenticator` COM class (the `windows` crate has no bindings for them), registration with Windows ("PEVV", fixed AAGUID, logo). New commands `passkey_provider_*` exist in every build and say why the provider is off.
- MSIX packaging path (`desktop/src-tauri/windows/msix/AppxManifest.xml`, `build-msix.ps1` using `makeappx`; signing needs a certificate you supply, none is created). Settings section (hidden on Linux and Windows older than build 26100) with the requirements, add/remove with Windows, and the list of PEVV-held passkeys with delete.
- Written without a Windows 11 machine: the API surface comes from the SDK headers; request format details, the exact minimum build, the DLL name, request-signature verification and the Windows Hello plugin flow are listed as unconfirmed in `docs/CLIENT_DESKTOP.md`. Tests: `tests/unit/pevv.passkeyProvider.test.ts`, `cargo test` and `cargo test --features win-passkey-provider`.

## 2026-11-21 - PEVV desktop: auto-type into other programs, and `pevv run`

- Auto-type: a global shortcut (default Ctrl+Alt+A, changeable in Settings, live only while the vault is unlocked) reads the foreground window (Windows `GetForegroundWindow`; Linux X11 `_NET_ACTIVE_WINDOW`; Wayland cannot, and says so) and the unlocked vault matches logins by their own optional Auto-type field (title globs, optional program, a sequence such as `{USERNAME}{TAB}{PASSWORD}{ENTER}` with `{TOTP}` and `{DELAY n}`). A web address alone never matches. A small always-on-top chooser that never takes focus names the window and the entry and always asks; the target's window handle and process are re-checked before every step and typing is abandoned if they change. Typing is `SendInput` (Unicode, marked as ours) on Windows and XTEST on X11; elevated windows and UAC prompts are detected and reported; on Wayland the password is copied instead (30 s clear). The new optional `autoType` field of an entry is ignored and kept by older clients. The real typing paths are untested.
- `pevv`, a third binary next to the app: `pevv run [--project NAME | --env ID]... -- cmd` (variables added to the child's environment, the vault wins with a warning by name, exit code passed through, secrets never printed), `pevv env --format dotenv|json|sh|ps`, `pevv status`, `pevv lock`. It talks to the running, unlocked app over the same owner-only local channel as the browser link. The app identifies the caller from the OS (process id, executable path and file hash) and asks the first time each program connects; every request for secrets is confirmed in a popup showing the command and the variable names, and `run` can be allowed for 8 hours for that exact command. Approvals live in `cli-access.json` and are revoked in Settings. The installer adds the install folder to the user's PATH. Docs: `docs/CLIENT_DESKTOP.md`. Tests: `tests/unit/pevv.autotype.test.ts`, `tests/unit/pevv.cli.test.ts`, `cargo test`.

## 2026-11-21 - PEVV extension linked to the desktop app

- New `pevv-native-host` (Chrome native messaging relay, second binary of the desktop package) and a private local channel to the app: Windows named pipe with a current-user-only DACL, Linux Unix socket in `$XDG_RUNTIME_DIR` (0600, peer uid checked).
- Pairing with an approval card and matching fingerprint in the app and the popup; afterwards every message is HMAC-SHA256 signed with a counter, replays refused. Protocol v1: `status`, `unlock-request`, `match`, `fill`, `save-offer`, `lock`. The app unlocks natively (passkeys, USB key) and enforces the exact origin; the extension caches nothing the app returns.
- Extension 0.2.0: optional `nativeMessaging` permission (no install warning), setting "Use the PEVV desktop app", popup shows the app's lock state and fills through it; standalone mode unchanged. Pinned extension id via `key` (`dolmkecfaekonkkgpjpamipjleindand`, listed in `desktop/src-tauri/extension-ids.json`). Firefox stays standalone.
- Host registration for Chrome, Edge, Brave (HKCU / `~/.config`, plus Chromium on Linux) from the app on start and from Settings, and from the NSIS installer hook. Docs: `docs/CLIENT_EXTENSION.md`, `docs/CLIENT_DESKTOP.md`. Tests: `tests/unit/pevv.link.test.ts`, `cargo test`.

## 2026-11-20 — PEVV desktop: native passkeys, USB key file, presence lock

- Desktop app: passkeys and security keys enrolled on the Luciverse site now unlock the vault natively, with no vault change and no re-enrolment. Windows uses `webauthn.dll` (needs WebAuthn API 6, Windows 11 22H2+; PRF on platform passkeys depends on the authenticator), Linux talks CTAP2 `hmac-secret` to USB keys (PIN asked in the app; needs a udev rule). The rpId is a constant in the app. Hardware paths are untested on real authenticators.
- New key slot type `usb-key`: a 32-byte secret in a `.pevvkey` file on a USB drive, as an alternative unlock or as a second factor after the master password. Any client can use one, the desktop app creates it. No format bump: older clients ignore the slot. Weaker than a FIDO2 key, and the UI says so.
- Desktop presence lock: designate a connected USB device (mouse, keyboard...) and the vault locks when it is unplugged; optional soft "do not unlock while absent". It is never an unlock factor. Stored in the app's local settings, not the vault.
- Fixed the desktop welcome text that offered passkeys it could not use. Docs: `docs/DESIGN.md`, `docs/CLIENT_DESKTOP.md`. Tests: `pevv.usbkey.test.ts`, `pevv.native.test.ts`, `cargo test`.

## 2026-11-20 — PEVV desktop app (Windows, Linux)

- New Tauri 2 desktop app that runs the standalone PEVV screen, so existing vaults open unchanged. The vault ciphertext is kept in `%APPDATA%PEVVault.json` / `~/.local/share/pevv/vault.json` (atomic write, revision check, 5 backups, 0600 on Linux); the shell never sees keys or plaintext.
- Locks on workstation lock, remote disconnect and suspend (Windows) or logind / screensaver signals (Linux), plus the existing idle timer. Copied secrets clear after 30 s only if the clipboard is unchanged, and stay out of Windows clipboard history. Single instance, tray (Show / Lock now / Quit), strict CSP.
- Unlock is master password + authenticator code; passkeys are hidden with an explanation (`inDesktopApp()`, EN + ES) because they are bound to the site.
- `npm run build:desktop-web`, `desktop:dev`, `desktop:build`. Docs: `docs/CLIENT_DESKTOP.md`. Tests: `tests/unit/pevv.desktop.test.ts` and `cargo test` in `desktop/src-tauri`.

## 2026-11-15 — PEVV extension 0.1.1: no account needed, Firefox

- PEVV works with no Luciverse account. A fresh browser that has never signed in creates a vault or brings one in by vault QR, encrypted export or import, then unlocks, fills, saves and generates. Account sync stays optional: the vault screen offers "From my Luciverse account" only when this browser already has a Luciverse session (the standalone app and the extension have no sign-in screen).
- A vault QR shown in the extension now links the public site. It used to encode a `chrome-extension://` link that a phone camera cannot open.
- Firefox 128+: the same build with a Firefox manifest (event page, add-on id `pevv@luciverse.pages.dev`). Tested in Firefox 147 over WebDriver BiDi (`npm run test:extension:firefox`).
- `npm run package:extension` writes the Chromium and Firefox zips. The 0.1.0 zip had backslash (`\`) path separators and unpacked into flat file names outside Windows.
- New Chromium e2e `pevv-extension-no-account.spec.ts`: two fresh profiles, no account, the vault moves by a photo of its QR and fills. See [CLIENT_EXTENSION.md](CLIENT_EXTENSION.md).

## 2026-11-14 — PEVV browser extension

- PEVV now has a browser extension for Chrome, Edge and Brave. The popup fills a saved login into the page you are on, generates a password into the focused field, and offers to save a new or changed password. It uses the same encrypted vault as the site and the app; its vault screen is the standalone PEVV app, so a vault comes in by QR, export file or import. The key stays in memory only and is forgotten when the screen locks, the browser closes or the timer runs out. Passkeys do not work in the extension yet. Build with `npm run build:extension`. See [CLIENT_EXTENSION.md](CLIENT_EXTENSION.md).

## 2026-11-12 — PEVV M3: cards, SSH keys, identities, folders, activity log, CSV import, project environments
- **New item types**: payment cards (Luhn checksum, brand, CVV length, MM/YY expiry with expired/expiring badges), SSH keys (OpenSSH `SHA256:` fingerprint, key type/bits, detects unencrypted private keys without decrypting — openssh-key-v1, PEM, PKCS#8, PuTTY), identities.
- **Folders** (sealed in vault meta; rename moves items, delete keeps them), shown in the sidebar with counts; editor folder picker.
- **History restore**: put any of the last 20 values back (current value moves into history; needs recent re-auth).
- **Security health** now a local Watchtower with a 0–100 score: adds insecure `http://` sites, duplicate site+username, logins without TOTP, expired/expiring/invalid cards, SSH keys without a passphrase. Nothing leaves the device.
- **Activity log**: encrypted with the vault key, device-only (never synced, no `rev` bump), 500 events, never stores secret values; search, CSV export, clear. Copies and reveals are attributed to the item.
- **CSV import** from Bitwarden, 1Password, LastPass, Chrome/Edge, Firefox, Safari (folders, favorites, tags, archived carry over).
- **Per-project environments**: link `project:<id>` to an environment (Settings → Project environments or `vault env link ENV`); hybrid program env requests use it. `vault list cards|ssh|ids`.
- **Passkeys**: rename, last-used date; clear error on IP-literal origins. Fixed the two passkey e2e tests (WebAuthn rejects `127.0.0.1` as an RP ID — they now run on `localhost`).
- **Strict CSP as Report-Only** in `_headers` (enforced policy unchanged); workers get `'unsafe-eval'` for the hybrid sandbox only.
- Help EN/ES, docs/PEVV.md (1Password/Bitwarden gap table, CSP section), unit `pevv.extra.test.ts` (12), e2e M3 flow.

## 2026-11-12 - PEVV vault

- **PEVV — Password & Environment Variable Vault:** on-device vault for logins (site, username, password, TOTP secret, notes), API keys, secure notes and environment variables in named environments with `.env` import/export. Argon2id master password (PBKDF2-SHA256 ≥ 600k fallback) → HKDF → wraps a random 256-bit vault key; every item AES-256-GCM with AAD bound to id + version; sealed index detects rollback / tampering. Nothing plaintext is stored.
- **Everywhere:** 🔑 HUD button next to the Computer launcher, **Y** key, controller **LT + View/Select**; **Vault (PEVV)** app on the LQCS desktop; Terminal `vault status|unlock|lock|list|get|set|env use` and `$VAR` / `${VAR}` expansion; hybrid programs `env.get('NAME')` after per-program permission; opt-in autofill buttons (Cloud sync, Passport), same-origin only.
- **Headers:** CSP `object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`, WebAuthn Permissions-Policy, COOP. Threat model and CSP review in `docs/DESIGN.md`. Help EN+ES (Vault, Computer).
