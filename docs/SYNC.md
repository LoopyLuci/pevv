# Sync: protocol, conflict rules, key rotation, hardened schema

Sync copies the **encrypted** vault file between your devices. The server only ever holds ciphertext
([SYNC_SELF_HOSTING.md](SYNC_SELF_HOSTING.md) says what it can see). This page is the contract that the TypeScript
clients (web, extension, desktop webview) and the Kotlin client (Android) both implement. The code is
`src/pevv/merge.ts`, `rotate.ts`, `store.ts`, `host/cloud.ts` and `android/.../core/Merge.kt`, `Rotate.kt`,
`store/VaultController.kt`, `sync/SyncManager.kt`; the SQL is `supabase/migrations/0002_pevv_hardening.sql` and `0003_pevv_no_size_cap.sql`.

## Lanes

| Lane | What | Server object |
|---|---|---|
| Cloud copy | The vault file, one row per account and path `/vault/pevv.vault.json` | table `pevv_blobs` (RPC `pevv_put`) |
| Live devices | Paired devices open at the same time swap the file | Realtime topic `pevv:d:<vaultId>` |
| Vault QR | One-time transfer | Realtime topic `pevv:<token>` |
| Direct link (desktop, optional, off by default) | Paired desktops swap the sealed file over Transferd; a peer's copy goes through the same `reconcileRemote` merge as the cloud copy ([TRANSPORT.md](TRANSPORT.md)) | none (no relay unless you add one) |

## Cloud copy: compare-and-swap writes

Every row has a server revision `rev` (monotonic, bumped by the server). A client remembers the `rev` it last saw and writes with

    pevv_put(p_path, p_body, p_expected_rev)  ->  {ok: true, rev}  |  {ok: false, error, ...}

The write is accepted only while the row is still at `p_expected_rev` (0 means "no row yet"). Errors: `conflict` (answer
carries the newer `body` and `rev`), `rate-limited`, `too-large` (only from a server that has not applied 0003 yet), `rev-regressed` (the vault's own `rev` went down),
`not-allowed`, `bad-body`, `not-signed-in`. On `conflict` the client stores the server copy, **merges** it with its own
(below) and writes again, at most twice per attempt. A write the server refuses never discards local data: the vault stays
on the device and the status screen says why.

The vault file's own `rev` (inside the JSON) is a second, independent monotonic counter: the server refuses a body whose
vault `rev` is lower than the stored one. Deleting is a soft delete (`pevv_delete`); `pevv_undelete` brings it back.

## Merge: nothing is dropped

`mergeVaults(session, base, local, remote)` folds two copies of the same vault. `base` is the copy last known to equal the
server's (kept next to the vault, ciphertext only); without it the merge is two-way. Both languages produce the same bytes
(checked by `tests/sync-scenarios`, see below).

1. Different `id`: rejected (`other-vault`).
2. Key epoch (see rotation): a copy with a **lower** epoch is rejected (`stale-key`); a **higher** one means the key was
   rotated elsewhere and is taken whole (`key-rotated`, below).
3. A copy whose sealed meta does not open with our key: rejected (`key-mismatch`).
4. A copy whose `lastWriter` device is in the revoked list (ours or the base's): rejected (`revoked-writer`).
5. Equal content: nothing to do. Local equals base: take the remote. Remote equals base: keep local.
6. Otherwise, item by item (three-way against `base` when known):
   - changed on one side only: that change wins;
   - **edited on both sides**: the newest edit wins (`updated`, then item `ver`, then a fixed byte order, so both clients
     pick the same winner); the **loser is kept inside the winner** in `conflicts[]` (`{at, ver, data}`, at most 5,
     oldest dropped). The user can read it in the sync status screen;
   - **deleted on one side, edited on the other**: the edit wins, the item stays (reported as a resolved conflict);
   - deleted on one side, untouched on the other: deleted.
   - Meta (folders, environments, grants, device list...) is merged field by field; the device list is a union and a
     revoked device stays revoked. Unknown fields (top level, meta, items, slots) and unknown slot or item kinds are
     carried through untouched, so an old client that opens a newer vault does not lose what it does not understand.
7. The merged file gets `rev = max(local, remote) + 1`, is sealed with fresh IVs, and stamps `meta.lastWriter` with this device.
8. Restore from a backup revision (`restoreRevision`): the items of an older copy come back as new versions on top of the
   current file; the current versions that are replaced are kept in `conflicts[]`. History is never rewritten.

Revision ordering: `rev` is a per-file counter, `ver` is per item. Three-way merges are order independent (merging A then B
gives the same result as B then A); `three-way-order-1` and `-2` pin that.

### A locked device never replaces its copy

A locked device cannot tell a genuine newer copy from a forged one (it has no key to decrypt or authenticate it). So:

- While locked, `reconcileRemote` **never installs** a remote file, even with a higher `rev`. The copy on disk stays as it is.
- A newer remote copy is **staged** in memory only and the status shows "pending".
- At the next unlock, with the key in hand, the staged copy goes through the normal merge: it is decrypted, authenticated
  (`key-mismatch` if it is not ours), checked for a revoked writer and a stale key, and only then merged. A forged file
  with a huge `rev` is therefore refused and the device keeps its data (`pevv.sync-store.test.ts`, "a locked device does
  not trust a newer copy it cannot check").
- The Android client does the same (`VaultController.reconcileRemote` stages, `finishUnlock` replays).
- The one exception to "keep the old copy" is a **rotated** copy (`key-rotated`): it is structurally valid, passes the KDF floors and has a higher
  `keyEpoch` than ours (an unverified copy with a lower or equal epoch never takes this path); the previous copy is kept as `lv-pevv-vault-prev` (Android: `vault-prev.json`) as a
  backup. The device then locks and asks for the master password again.

## Key rotation (device revocation)

Revoking a device only stops it from syncing; it still knows the old vault key and may hold old copies. Rotation makes
those worthless (`rotateVaultKey`, UI: "Also change the vault key" when removing a device, on by default).

1. The caller proves the master password.
2. A new random 256-bit vault key is generated.
3. Every item, the sealed meta and the authenticator secret are re-sealed under it (fresh IVs; the AAD is unchanged).
4. Every slot is re-wrapped under the key encryption key of its factor, or removed:
   password (new KDF salt), recovery codes and recovery key (new codes and key are issued and shown once), passkey PRF and
   USB key file (re-wrapped only when the caller supplies the secret; otherwise removed and listed as "dropped" so the
   user can add them again). Unknown slot types cannot be re-wrapped and are dropped (`dropUnknown`).
5. The file becomes `v: 2` with `keyEpoch` = previous epoch + 1 (the first rotation gives 1). `rev` goes up by one.
6. The biometric wrap of the old key is erased on the device.

Format versioning: `v: 2` is written **only** by a rotation. Old clients that validate the file refuse `v: 2` cleanly
instead of mixing keys (`validateFile` rejects unknown `v`); they must be updated. Files that never rotated stay `v: 1` and
every client keeps writing them. `keyEpoch` is the sync-level guard: a copy with a lower epoch is `stale-key`.

Golden vectors for rotation (`tests/sync-scenarios/vectors/rotation.json`) are checked by both clients, using a
deterministic IV hook (synthetic IV = HMAC-SHA256(vaultKey, aad || 0x00 || plaintext), first 12 bytes; production always
uses random IVs).

## Cross-client tests

`tests/sync-scenarios/*.json` are shared scenarios: a list of operations on named devices (create, copy, edit, add, delete,
meta, revoke, snapshot, restore, rotate, sync) and assertions. `tests/sync-scenarios/golden/*.json` hold the merged vault
files. The TypeScript test (`tests/unit/pevv.sync-scenarios.test.ts`) and the Kotlin test
(`android/app/src/test/java/dev/pevv/app/SyncScenarioTest.kt`) each run every scenario with the deterministic IV hook and
must produce **byte-identical** files equal to the goldens. Regenerate goldens only on purpose, from the TypeScript side:
`PEVV_WRITE_GOLDEN=1 npx vitest run tests/unit/pevv.sync-scenarios.test.ts`, and review the diff.

Scenarios: two devices editing different items offline; the same item on both (rule above); delete vs edit; three-way merges
in both orders; a revoked device's write rejected; a write from before a rotation rejected; an old-format client opening a
newer vault; restore from a backup revision; merge without a base.

Divergences found between the two implementations while building the suite were fixed; see the changelog.

## What the status screen tells the user

Last synced, whether changes are pending, conflicts resolved (and, per item, the kept losing versions with secret values
masked until shown), and errors in plain language (offline, too many changes, a server that still has the old size limit, copy from a removed device
ignored, copy under an old key ignored, a copy that cannot be opened, refused by the server, signed out). English and
Spanish. Web/extension/desktop: `src/pevv/ui/SyncStatus.tsx` fed by `src/pevv/syncStatus.ts`; Android: Settings > Sync.

## Self-hosting the hardened schema

Apply `supabase/migrations/0001_pevv_sync.sql`, then `0002_pevv_hardening.sql`, then `0003_pevv_no_size_cap.sql` (SQL editor or
`supabase db push`). The second and third files are idempotent and do not change the earlier ones. Do not run 0002 again after
0003 (it would put the old size limit back). 0002 adds:

- **Revision CAS**: `pevv_put` (security invoker, so RLS stays in force), server `rev`, `doc_rev` (the vault's own `rev`,
  must not go down), `vault_id`.
- **History**: the last `history_keep` (default 20) revisions per blob in `pevv_blob_history` (read through
  `pevv_history` and `pevv_history_get`; clients cannot write it). Restore is done client side from a revision (above).
- **Soft delete**: `pevv_delete` marks the row; `pevv_undelete` restores it. Plain `delete` is turned into a soft delete.
- **Rate limit** (`pevv_config`): `rate_per_minute` (60 writes per user). Settings are not readable or writable by clients.
  0002 also capped a blob at 262144 bytes (`max_body`); **0003 removes that cap**, see below.
- **`strict_cas`** (default false): set to `true` to refuse plain upserts, so only `pevv_put` writes. Turn it on once every
  device runs a client that knows `pevv_put` (older clients use plain upserts, which still work with `strict_cas` off).
- **Realtime publication**: `pevv_blobs` is added to `supabase_realtime`, so devices hear about changes (RLS applies: a user
  only receives their own rows).
- **RLS review**: owner only (`user_id = auth.uid()`), RLS forced, the anon role has no grants on any table or function.
  `pevv_put`, `pevv_delete` and friends are granted to `authenticated` only.
- **Realtime topic access** (`realtime.messages` policies `"pevv rt read"` / `"pevv rt write"`). Before 0002 any session,
  anonymous ones included, could read and write every `pevv:%` topic. Now a topic must have one of two shapes:
  `pevv:<token>` (QR transfer; the random token in the QR code is the capability, the payload is ciphertext whose key stays in
  the QR) or `pevv:d:<vaultId>` (live device list), which only a session that **owns a synced copy of that vault** may use.
  Anything else is denied, and so is any session without a user. **Behaviour note:** because of that rule, live device
  exchange between devices that are not signed in to the same account no longer works. To keep the old behaviour set
  `update public.pevv_config set value = 'true' where key = 'open_roster';`. The web client's roster lane uses the account
  session when signed in and falls back to the anonymous relay session (which then needs `open_roster`).

### No size limit (0003)

A person syncs their own vault between their own devices, so nothing limits how big the sealed vault may be: not the
clients (web, desktop, extension, Android), not the QR and live device lanes, not the Transferd PSP/1 protocol, and, with
`0003_pevv_no_size_cap.sql`, not the database. 0003 drops the `char_length(body)` check from 0001 and the
`pevv_blobs_body_bytes` check from 0002, deletes the `max_body` setting and recreates the guard trigger without the size
test. What still protects the account is not a size cap: owner-only RLS, compare-and-swap, the monotonic revision guard,
history, soft delete and the per-user write rate limit.

Large bodies are sent in pieces where a transport has a hard message size: the Realtime lanes cut a body into 48,000
character parts (a part counter, not a size, is bounded), and PSP/1 reads a blob body in 64 KiB chunks so a header that
lies about its size cannot reserve memory. What can still stop a very large vault is outside PEVV: the request size limit
of your API gateway or proxy, the hosting plan's database size, and (for the offline QR codes) how many codes a person is
willing to scan.

### Testing the SQL

`npm run test:sql` starts a throwaway PostgreSQL cluster, loads a stub of the Supabase pieces (`auth.uid()`, roles,
`realtime.messages`, the publication), applies 0001, some legacy rows, 0002 and 0003 twice each (idempotence) and runs
`tests/sql/hardening.test.sql` (CAS, conflicts, history, soft delete and restore, no size cap, rate limit, RLS between two
users, anon denied, Realtime topic policy). It needs PostgreSQL binaries: set `PEVV_PG_BIN` to the folder with `initdb`,
`pg_ctl` and `psql`; optional `PEVV_SQL_TMP` (scratch folder) and `PEVV_PG_PORT`.

**Not tested against a live Supabase project.** The stub stands in for GoTrue, PostgREST and Realtime. Before relying on it,
on a staging project: apply both migrations, sign in with two accounts, check (1) a second account cannot read the first's
row or history, (2) an anonymous session cannot subscribe to `pevv:d:<id>` of a vault it does not own, (3) a QR transfer
still works, (4) two devices editing offline converge after reconnecting, (5) the Realtime publication delivers a change to
the other device. The `realtime.messages` policy relies on `realtime.topic()` as shipped by Supabase; check that your
project's Realtime version enforces RLS on private channels.
