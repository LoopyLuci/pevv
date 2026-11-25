# Security Policy

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a security problem.**

Report it privately with a **GitHub Security Advisory**:
<https://github.com/LoopyLuci/pevv/security/advisories/new> (Security tab > *Report a vulnerability*).

Include what you found, the affected client and version, steps to reproduce and the impact. Do not include a real vault or real
credentials. We aim to acknowledge a report within 5 working days and to agree on a fix and disclosure timeline with you. Please give
us reasonable time before publishing. There is no bug bounty.

Supported versions: only the latest release and `main`. PEVV is pre-1.0 and has not had an independent security audit.

## Scope

In scope:

- Vault cryptography and file format: `src/pevv/crypto.ts`, `vault.ts`, `recovery.ts`, `usbkey.ts`, `totp.ts`, `qr.ts`.
- Key handling and storage: anything that could leak the vault key, a master password or decrypted data to disk, a page, another origin or a server.
- Unlock, second-factor and recovery logic, including bypass and downgrade (KDF floors, flag stripping, entry rollback).
- The browser extension: filling into the wrong origin or frame, content-script/worker messaging, native-messaging link to the desktop app.
- The desktop app: IPC commands, the named pipe / socket, file handling, clipboard, auto-type, the `pevv` CLI, CSP.
- The optional sync backend schema and policies (`supabase/`) and the relay.
- CI and release workflows (supply-chain issues, leaked tokens).

Out of scope:

- Anything that needs malware, a keylogger or full control of the unlocked device or browser profile (see the threat model).
- A weak master password the user chose, or loss of every unlock method (there is no reset by design).
- Social engineering, physical attacks, denial of service against your own Supabase project.
- Remembering that the authenticator was passed on a device ("Authenticator frequency", docs/CRYPTO.md) being usable by whoever
  already controls that unlocked device or its key store. The record is bound to the vault key and to a device-only key, so it
  cannot be forged from the master password or by editing stored data.
- The in-page TOTP / passkey second-factor *gates* being client-side: they are documented as a convenience barrier; the cryptographic
  boundary is the master password / PRF / recovery secret.
- Findings in third-party services (Supabase, GitHub, browser vendors); report those upstream.
- Unsigned release binaries (they are not Authenticode-signed on purpose until a signing certificate exists; see Verifying downloads).

## Verifying downloads

The release binaries are **not Authenticode-signed** (no code-signing certificate exists yet), so Windows SmartScreen warns on first run
("Windows protected your PC": More info > Run anyway) and Linux packages carry no distro signature. Check what you downloaded against the
`SHA256SUMS` file attached to the same release:

- Linux: `sha256sum -c --ignore-missing SHA256SUMS` in the folder with the downloads.
- Windows (PowerShell): `(Get-FileHash .\PEVV_<version>_x64-setup.exe -Algorithm SHA256).Hash` and compare it, ignoring case, with the line for that file in `SHA256SUMS`.

A checksum from the same page only proves the download was not corrupted; compare against a copy you trust (for example the release page
opened over a different network). The desktop app's own updates are separate: it installs an update only if it carries a valid signature
from PEVV's update key (the public half is in `desktop/src-tauri/tauri.conf.json`), and only after you click "Update now".

## Threat model summary

PEVV is zero-knowledge: encryption and decryption happen on the device and the optional server stores only ciphertext.

**Protects against**

- Theft of the stored file, a backup, a synced copy or the server's database: the attacker needs the master password (Argon2id), a PRF
  passkey, a recovery code or kit.
- Tampering with ciphertext, swapping or rolling back single entries, stripping the 2FA requirement flags (AEAD with bound associated
  data, sealed index and flags).
- A page or program reading secrets it was not granted; fills across origins or into frames; shoulder-surfing; clipboard residue
  (masking, re-authentication, timed clear, auto-lock).

**Does not protect against**

- Malware, a keylogger, a malicious extension or same-origin XSS while the vault is unlocked (memory and DOM are readable). Mitigations:
  strict CSP, no inline or remote scripts, auto-lock.
- Whole-file rollback to an older valid copy without a server to compare against; sync refuses to adopt a lower revision.
- A local attacker clearing the unlock rate limiter (offline guessing is bounded by the Argon2id cost instead).
- JavaScript cannot guarantee zeroing memory; buffers we own are wiped and references dropped.
- Forced disclosure. **No password reset exists**: losing every factor loses the data.

Full text: [docs/DESIGN.md](docs/DESIGN.md#3-threat-model), [docs/CRYPTO.md](docs/CRYPTO.md).

## For self-hosters

The sync backend stores ciphertext only, but your Supabase project is yours to secure: keep row-level security on, never put the
service-role key in a build or in this repository, rate-limit anonymous sign-ins and keep the project's access keys private.
See [docs/SYNC_SELF_HOSTING.md](docs/SYNC_SELF_HOSTING.md).
