# Vault file format (version 1; version 2 only after a key rotation)

The vault is one JSON document, `VaultFile` (`src/pevv/model.ts`), validated by `validateFile` (`src/pevv/vault.ts`). It is what is
stored in `localStorage` / `chrome.storage.local` / the desktop `vault.json`, mirrored by sync, moved by the vault QR, and the
payload of portable export v2. **It must stay readable by every released client.** See the compatibility rules at the end.

```jsonc
{
  "format": "luciverse.pevv",        // fixed identifier, kept from the original project for compatibility
  "v": 1,
  "id": "<24 hex>",                  // vault id, random, never changes
  "created": 1700000000000, "updated": 1700000000000,
  "rev": 7,                          // monotonic revision, +1 on every write; last writer wins on sync
  "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": "<b64>" },   // or { "alg": "pbkdf2-sha256", "iter": 600000, "salt": "<b64>" }
  "slots": [                         // any ONE slot unlocks; clients skip slot types they do not know
    { "id": "...", "type": "password",      "wrapped": "<Sealed>" },
    { "id": "...", "type": "prf",           "credId": "...", "salt": "<b64>", "wrapped": "<Sealed>" },
    { "id": "...", "type": "recovery-code", "hash": "<b64>", "salt": "<b64>", "wrapped": "<Sealed>" },
    { "id": "...", "type": "recovery-key",  "salt": "<b64>", "wrapped": "<Sealed>" },
    { "id": "...", "type": "usb-key", "name": "...", "salt": "<b64>", "wrapped": "<Sealed>" }
  ],
  "passkeys": [ /* PasskeyRecord: credential id, public key, alg, PRF salt, mode, rpId, signCount ... */ ],
  "require": { "totp": false, "passkey": false, "usbKey": false },  // plaintext HINT only; the sealed meta is authoritative
  "totp": null,                      // or the authenticator secret, sealed under the vault key
  "meta": "<Sealed>",                // environments, grants, index id -> version, sealed 2FA flags, folders, devices, ...
  "entries": [ { "id": "...", "ver": 3, "sealed": "<Sealed>" } ]   // one sealed JSON object per item
}
```

`Sealed` is `{ "iv": "<b64, 12 bytes>", "ct": "<b64, ciphertext + 16-byte GCM tag>" }`.

## Fields added for sync and key rotation

- `v`: 1, or 2 after a key rotation. `keyEpoch` (integer >= 1, only with `v: 2`) counts rotations; a copy with a lower epoch is refused by sync.
- Inside the sealed meta: `lastWriter` (device id of the last writer, used to refuse writes from revoked devices).
- Inside a sealed item: `conflicts[]` of `{at, ver, data}`, the versions that lost a merge (at most 5). Older clients keep them untouched.

See [SYNC.md](SYNC.md).

## What is plaintext, and what is not

Plaintext in the file: `format`, `v`, `id`, timestamps, `rev`, KDF parameters and salts, slot ids and types, credential ids and public
keys of passkeys, the `require` hint, entry ids and versions, and the sizes of everything. **Everything else** (titles, sites,
usernames, secrets, notes, tags, folders, device names, environments, the authenticator secret) is inside `Sealed` values.

## Associated data (AAD) bindings

Each sealed value is bound to its place so it cannot be moved or replayed. The strings are part of the format and keep the original
project prefix:

| Value | AAD |
|---|---|
| slot | `luciverse/pevv/v1/slot/<vaultId>/<slotId>` |
| entry | `luciverse/pevv/v1/entry/<vaultId>/<entryId>/<ver>` |
| meta | `luciverse/pevv/v1/meta/<vaultId>/<rev>` |
| totp | `luciverse/pevv/v1/totp/<vaultId>` |
| export (v2) | `luciverse/pevv/v1/export/<id>` |
| recovery kit | `luciverse/pevv/v1/kit/<vaultId>` |
| audit log (device only) | `luciverse/pevv/v1/audit/<vaultId>` |

HKDF `info` labels: `luciverse/pevv/v1/password-kek`, `.../prf-kek`, `.../recovery-code-kek`, `.../recovery-key-kek`, `.../usb-kek`,
`.../usb-gate`. Details in [CRYPTO.md](CRYPTO.md).

## Related file formats

| File | `format` | Purpose |
|---|---|---|
| Portable export | `luciverse.pevv.export` (v1 items only, v2 whole vault) | Whole vault sealed under a separate export password (Argon2id). |
| Recovery kit | `luciverse.pevv.recovery-kit` | The recovery key sealed under a kit passphrase. |
| USB key file | `luciverse.pevvkey` | `.pevvkey`: a 32-byte random secret for a `usb-key` slot or as a second factor. |
| Offline QR frames | `PEVV1\|...` | The vault file gzipped, checksummed and split into up to 12 codes. |

## Compatibility rules (invariants)

1. **Never change** the `format` strings, AAD strings or HKDF labels. Doing so makes existing vaults unreadable.
2. Add things only as optional fields. Unknown fields inside sealed entries are preserved as they are; unknown slot types are skipped.
3. A new `v` of the file needs a migration that older clients refuse cleanly (`validateFile` rejects unknown `v`).
4. KDF floors are enforced on unlock (downgrade protection): Argon2id m >= 19456 KiB and t >= 2; PBKDF2 >= 600000 iterations.
5. The round-trip tests (`tests/unit/pevv.crypto.test.ts`, `pevv.store.test.ts`, `pevv.devices.test.ts`) must keep passing without
   changing what they expect of the file shape.
