# PEVV: design and behaviour

PEVV is an on-device vault for logins, API keys, secure notes and
environment variables (it was originally developed as part of Luciverse). It has
**no server of its own**: everything is encrypted in the
browser and stored in `localStorage` (`lv-pevv-vault-v1`). Optional sync copies
the *ciphertext* into a Supabase project you run
([SYNC_SELF_HOSTING.md](SYNC_SELF_HOSTING.md)). A device with no vault of its own
adopts that copy and then asks for the same master password. An encrypted
export file can also start a vault on a device that is not signed in.

**Import with QR code** checks the master password on the device that already
has the vault and, only if it is correct, shows a code. The locked vault is
sealed again with a random AES-256-GCM key that stays in that code and is never
uploaded. Scanning the code starts the transfer immediately. The other device
does not sign in and does not need the same account. Keep the code on screen
until the vault has arrived (10 minutes). Without a network, the same button
shows one or more offline codes of the already-encrypted vault file (gzipped,
checksummed, at most 12). The password is never in the code. The authenticator secret, recovery-code slots and passkey
registrations travel with the vault file, so the same authenticator app and the
same saved recovery codes work on the new device. A YubiKey (or a passkey the
new device already has for this site) keeps working because the registration
and the PRF slot move with the file. A passkey that exists only inside the
other computer, such as Windows Hello, does not — the private key never leaves
that authenticator. The text of recovery codes is never stored, so an export
does not reprint them.

**Devices** (PEVV → Devices) lists every browser that has unlocked the vault.
The list is sealed inside vault meta. While two devices that already have the
vault are open, they exchange the encrypted file directly (no account, the key
stays on the device) and union the device list, so the phone that was paired
last shows up on the computer without pairing again. A higher revision still
wins for the items when the devices are live, or when cloud sync is on. Removing
a device adds its id to a sealed revoked list; that copy wipes itself the next
time it unlocks. Sync will not install it again on that browser.
A device that never comes back online still holds its local copy until the
vault is deleted there.

An encrypted export (format v2) is the whole vault file sealed under a separate
export password. Opening it on a new device does not ask for a new master
password. Legacy v1 exports are items only.

**Browser extension** (Chrome, Edge, Brave) is a third client of the same
vault: fill, save and generate logins on any site, with the same vault screen as
the web app. See [CLIENT_EXTENSION.md](CLIENT_EXTENSION.md).

**Desktop app** (Windows, Linux; Tauri) is a fourth client: the same screen in a
window, with the ciphertext in a file in the OS app-data folder, locking on
screen lock and suspend, and a clipboard that clears itself. See
[CLIENT_DESKTOP.md](CLIENT_DESKTOP.md).

Code: `src/pevv/` (crypto, vault format, store, WebAuthn, TOTP, recovery),
`src/pevv/host/` (the small seams to the optional backend and the language store), `src/pevv/ui/` (React UI) and `src/pevv/extension/` (browser
extension) and `src/pevv/desktop/` plus `desktop/src-tauri/` (desktop app). Tests: `tests/unit/pevv.*.test.ts`, `tests/e2e/pevv.spec.ts`,
`tests/e2e-extension/`.

## 1. Crypto design

See [CRYPTO.md](CRYPTO.md) (key hierarchy, KDFs, slots, AAD bindings, WebAuthn PRF, TOTP, recovery).

## 2. App behaviour
- Auto-lock after N idle minutes (default 5) and on `visibilitychange` /
  `pagehide` (default on). Locking drops the vault key and all plaintext from
  memory (best effort in JS).
- Re-auth (password or passkey) before reveal / print / export; grace window
  120 s by default.
- Clipboard copies are cleared after 20 s (only if the clipboard still holds
  the copied value).
- Programs: variables are handed to a program only when it was granted the
  name (`Allow once` / `Always` / `Deny`, stored in sealed meta, revocable in
  Settings). The desktop app's `pevv` command line asks the unlocked vault the same way.
- Autofill in the browser extension: an explicit click per fill, logins match
  the **exact origin** (scheme, host and port) only, never inside frames. The
  legacy `luciverse:<formId>` site syntax (in-app form ids of the original game
  integration) is still read from old vaults and never matches a web page.

## 2b. Item types, organisation and audit (M3)

Compared against 1Password and Bitwarden; gaps filled:

| Area | PEVV |
|---|---|
| Item types | login, env var, API key, secure note, **payment card** (Luhn, brand, CVV length, expiry state), **SSH key** (OpenSSH SHA256 fingerprint, detects unencrypted private keys without decrypting: openssh-key-v1 cipher, PEM Proc-Type, PKCS#8, PuTTY), **identity** |
| Organisation | favorites, tags, **folders** (sealed in meta; delete keeps items), per-environment env vars |
| History | last 20 values per secret field, **restore** (current value moves into history; needs recent re-auth) |
| Health | local-only Watchtower: weak / common / reused / >1 year old, **insecure http://**, **duplicate site+username**, **no TOTP**, **expired / expiring / invalid cards**, **unprotected SSH keys**, 0–100 score. No breach API calls (nothing leaves the device). |
| Audit | encrypted **activity log** in `lv-pevv-audit-<vaultId>` (AES-GCM with the vault key, AAD `luciverse/pevv/v1/audit/<id>`), max 500 events, device-only (never synced, does not bump `rev`), records ids/events/short details — never secret values. CSV export, clear. |
| Import | encrypted PEVV export, `.env`, Proton Pass unencrypted JSON or CSV, Brave/Chrome/Edge CSV, Bitwarden, 1Password, KeePass, Dashlane, NordPass, LastPass, Firefox, Safari |
| Env per program | `meta.projectEnv[programId]` links a program id (`project:<id>`) to an environment; `requestProgramEnv`, the `pevv` CLI and the grant dialog read that environment. Settings → Project environments |
| Passkeys | rename, last-used date, remove; clear error on IP-literal origins (WebAuthn needs a domain, e.g. `localhost`) |

## 3. Threat model

**Protects against**
- Theft of the stored file (disk, backup, synced copy, the sync server's row): attacker
  needs the master password (memory-hard KDF), a PRF passkey, a recovery code
  or the kit + passphrase.
- Tampering with ciphertext, swapping or rolling back individual entries,
  stripping 2FA flags (AEAD + sealed index/flags).
- Shoulder-surfing and accidental disclosure (masked fields, re-auth, clipboard
  clear, auto-lock).
- Programs and pages reading variables they were not granted.

**Does not protect against (by design or platform limits)**
- **Same-origin XSS or a malicious extension** while the vault is unlocked —
  code running in the page can read memory and the DOM. Mitigations: no
  no `eval` of user content, the hardened headers below,
  auto-lock. A strict `script-src` CSP is deferred (see §4).
- **TOTP and passkey-2FA gates are client-side.** Someone with the file *and*
  the password can bypass them by editing code. They raise the bar for casual
  access on a shared device; the cryptographic boundary is the password / PRF /
  recovery secret. The UI says this plainly.
- **Whole-file rollback** to an older valid copy (e.g. restoring an old backup)
  cannot be detected without a server; sync refuses to adopt a lower `rev`.
- Malware / keyloggers on the device, a compromised browser, forced disclosure.
- **No password reset.** Losing every factor means the data is gone.
- The limiter is stored in `localStorage` and can be cleared by a local attacker;
  offline guessing is bounded by Argon2id cost instead.
- JS cannot guarantee zeroing memory; we wipe buffers we own and drop references.

## 4. CSP / headers

The web app ships `public/_headers` (Cloudflare Pages / Netlify format). It is an **enforced** policy:

- `Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; style-src-attr 'unsafe-inline'; …; connect-src 'self' https://*.supabase.co wss://*.supabase.co; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`.
  No remote scripts, no inline scripts, no frames, no forms posting anywhere. `wasm-unsafe-eval` is for the Argon2id WebAssembly only.
- `X-Frame-Options: DENY` and `frame-ancestors 'none'`: no clickjacking of the vault.
- `Permissions-Policy`: camera only for the vault-QR scanner, WebAuthn only in our own top-level origin.
- `Cross-Origin-Opener-Policy: same-origin`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`.

The desktop app's CSP is in `desktop/src-tauri/tauri.conf.json` (and is widened to your sync origin by `scripts/desktop-build.mjs`); the
extension's is in `extension/manifest.json`. Self-hosters on another domain must change the `connect-src` origin.

## 5. Hand-test checklist
1. Create a vault, lock, unlock with the password; wrong password shows an error and backs off after 5 tries.
2. Add a **YubiKey / platform passkey** (Chrome or Edge on desktop, Safari 18+, Android). If it reports PRF, lock and unlock with the key alone; otherwise confirm it is asked after the password.
3. Enroll **Google Authenticator / Authy** from the QR; lock; unlock with password + code; a reused or wrong code is rejected.
4. Generate recovery codes, lock, unlock with one, set a new password; the same code no longer works.
5. Download the recovery kit, unlock with kit + passphrase.
6. Add env vars, export/import `.env`, switch environment.
7. Hide the tab: the vault locks. Copy a secret: the clipboard clears.
8. With sync configured: turn sync on in Settings on device A, sign in on device B with the same account, "I already have a vault" > check, unlock with the same master password.
