# Cryptography

How PEVV protects the vault. The file layout is in [VAULT_FORMAT.md](VAULT_FORMAT.md); behaviour and the threat model are in
[DESIGN.md](DESIGN.md). The code is `src/pevv/crypto.ts`, `vault.ts`, `recovery.ts`, `usbkey.ts`, `totp.ts` and `webauthn.ts`.

## Design

| Piece | Choice |
|---|---|
| Password KDF | **Argon2id** via `hash-wasm` (lazy-loaded WebAssembly). Default m = 64 MiB, t = 3, p = 1; "strong" 128 MiB / t = 4; floor m = 19 MiB, t = 2 (OWASP 2024). Password is NFC-normalized. |
| Fallback KDF | **PBKDF2-SHA256, ≥ 600 000 iterations** (WebCrypto) when WebAssembly is unavailable. Params below the floors are rejected on unlock (downgrade protection). |
| Domain separation | Every KDF / PRF / recovery output goes through **HKDF-SHA256** with a distinct `info` (`luciverse/pevv/v1/password-kek`, `…/prf-kek`, `…/recovery-code-kek`, `…/recovery-key-kek`, …). |
| Vault key | Random **256-bit** AES key, generated once. Never stored in the clear and only kept in memory while unlocked. |
| Key slots | The vault key is wrapped (AES-256-GCM) by each KEK: `password`, `prf` (one per PRF passkey), `recovery-code` (one per code), `recovery-key` (kit), `usb-key` (one per USB key file, see below). Any one slot unlocks. Clients skip slot types they do not know. |
| Entries | Each entry is sealed separately with **AES-256-GCM**, a fresh 96-bit random IV, and AAD = `luciverse/pevv/v1/entry/<id>/<version>`, so ciphertexts cannot be swapped between entries or replayed at an older version. |
| Meta | A sealed meta record holds environments, program env grants, prefs that matter for security, the authoritative **2FA requirement flags**, and the **entry index (id → version)**. AAD binds it to the vault id and **rev**. Unlock fails if an entry is missing, added, or at a different version than the index, or if the plaintext `require` hint disagrees with the sealed flags (flag stripping). |
| TOTP secret | Sealed under the vault key (AAD `…/totp`). A plaintext `require.totp` hint lets the locked screen ask for the code; the sealed copy is authoritative. |
| Export | Whole vault re-sealed under a separate export password (Argon2id) with AAD `…/export`. v2 carries the vault file (items, authenticator, recovery slots, passkeys, device list). v1 is items and environments only. |

**Never stored:** the master password, the vault key, any decrypted entry, PRF
outputs, recovery codes (only salted SHA-256 hashes, used to show which codes
are spent), TOTP codes.

## WebAuthn / passkeys / security keys
- No server, so **rpId = the current host** and the challenge is generated
  locally. PEVV verifies each assertion itself: `type`, challenge, origin,
  `crossOrigin=false`, rpIdHash, UP (and UV when required), signature over
  `authData ‖ SHA-256(clientDataJSON)` with the stored public key (ES256, RS256,
  Ed25519), and signature-counter regression.
- **PRF mode** (`prf` / CTAP2 `hmac-secret`): each passkey gets a random
  32-byte salt; the PRF output → HKDF → KEK wraps the vault key. The passkey
  alone unlocks (it already is "something you have + PIN/biometric").
- **2FA mode** (no PRF, e.g. older keys/browsers): the key is a *gate* after the
  password. This is an application check, not cryptography (see §3).
- Multiple keys per device are supported; each is named and removable.

## USB key file (`usb-key` slot, key-file second factor)
A 32-byte random secret in a small JSON file named `.pevvkey` (`{"format":"luciverse.pevvkey","v":1,"vault":"<id>","secret":"<base64>"}`)
on a drive the user keeps. Any client can *use* one (pick the file; the desktop app also reads it from a removable drive); the desktop
app *creates* it (see `PEVV_DESKTOP.md`).
- **Alternative unlock (`unlock`)**: slot `{ id, type: 'usb-key', name, salt, wrapped }`. KEK = HKDF-SHA256(secret, salt, info `luciverse/pevv/v1/usb-kek`),
  the vault key is wrapped with AES-256-GCM (AAD = vault id + slot id) exactly like the other slots. The file alone opens the vault, like a PRF passkey.
  Several slots are allowed (main drive plus a backup drive).
- **Second factor (`second-factor`)**: no slot. The sealed meta keeps `usbKeys: [{ id, name, check, added }]` where `check` = SHA-256(`luciverse/pevv/v1/usb-gate` ‖ secret),
  and `require.usbKey` (also a plaintext hint like the others). After the password the vault asks for the file; a file that matches a gate, or opens a `usb-key`
  slot of this vault, passes. It is a gate enforced by the app (see §3), and the file alone opens nothing.
- Bound to the file's **content only**, not to the drive's serial number: serials can be read and spoofed and add nothing.
- Honest limits: a file can be copied without you noticing, so this is weaker than a FIDO2 key. Keep it on one drive and keep a backup.
- Compatibility: no format bump. A client that predates `usb-key` ignores the slot (every unlock path looks only at its own slot types, a password
  change keeps the slot), and ignores `meta.usbKeys` / `require.usbKey`. Covered by `tests/unit/pevv.usbkey.test.ts`.

## TOTP (RFC 6238)
SHA-1 / 6 digits / 30 s by default (Google Authenticator compatible); SHA-256/512
and 8 digits are supported for imported secrets. Verification accepts ±1 step,
rejects reuse of the last accepted step, and is **rate-limited**: 5 free tries,
then 30 s lockout doubling up to 1 h (also applied to password guesses). The
limiter state is in `localStorage`, so it slows casual guessing only.

### Authenticator frequency (`secondFactorRecheck`)

By default the code is asked at every login. The sealed meta can relax that to once a day, week or month, or to "only on a
new device" (`secondFactorRecheck`, per vault and synced, see VAULT_FORMAT.md). Only the authenticator code is relaxed: the master
password or passkey is always required, and a passkey or key file that is a second factor is still asked every time.

- **The record is per device and local** (`localStorage` `lv-pevv-2fa-trust:<vaultId>` on web and desktop, app preferences on
  Android): `{ t, mac }` where `t` is when the code was last accepted here.
- **It cannot be forged by editing `t`, and the master password alone does not forge it.**
  `tag = HMAC-SHA256(vault key, "luciverse/pevv/v1/2fa-trust" | vault id | device id | key epoch | trust epoch | t)` and
  `mac = HMAC-SHA256(device key, tag)`. The device key never leaves the device: a non-extractable WebCrypto key in IndexedDB on
  web and desktop, an Android Keystore HMAC key on Android. Someone who phished the password (so holds the vault key) still has no
  device key, so on their own device they are a new device and are asked for the code. If no device key is available nothing is
  trusted and the code is asked every time.
- **New device** means a device with no valid record: it has never passed the code for this vault (or its record was reset).
- **Clock rollback:** a `t` in the future counts as expired for every setting, including "new device".
- **Resets:** a password change, a revoked device, replacing or removing the authenticator (all bump `trustEpoch`) and a key
  rotation (new vault key and key epoch) invalidate every device's record. They are asked for the code at their next unlock.
- **Changing the setting needs a valid current code** (and the authenticator must be on). The device that passes the code there is
  remembered like a normal login.
- The browser extension does not use this: it always asks (it keeps no raw vault key and no device key).
- Limits, honestly: someone who controls the unlocked device or its storage and key store can use the device key there, and a
  clock set back by less than the window only extends it by that much.

## Recovery
- **10 one-time recovery codes**, 100 bits each (`XXXXX-XXXXX-XXXXX-XXXXX`
  base32). Each code is its own slot (HKDF → KEK). A used code's slot is deleted
  and the user must set a new master password.
- **Recovery kit**: a 256-bit recovery key, delivered as a JSON file encrypted
  under a kit passphrase the user chooses (Argon2id). Kit + passphrase unlock.
- Regenerating codes or the kit invalidates the previous ones.
