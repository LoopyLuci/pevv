# Transferd as PEVV's secure transport: design and threat model

Status: **draft for owner review** (2026-11-22). Phases 0 and 1 have a first implementation in `transport/pevv-transport` and the desktop wiring of phase 3 is in place behind a run-time switch (see the results under section 11); the rest is a plan. Sizes and timings in the phase 0 results are measured; others stay estimates.

This document proposes making [Transferd](https://github.com/LoopyLuci/Transferd) (the protocol) and its reference implementation
[TransferDaemon](https://github.com/LoopyLuci/TransferDaemon) the way PEVV devices find each other, pair and move the encrypted vault,
with the optional Supabase backend demoted to an encrypted backup and offline mailbox. It also records, honestly, where TransferDaemon
is not yet ready for that job (section 12 and Appendix A). Where this document says "verified" it means someone read the code;
nothing was built or run. Sizes and timings marked *estimate* are not measurements.

Contents: 1 Goals and non-goals, 2 What PEVV does today, 3 Architecture, 4 Identity mapping, 5 Pairing, 6 Sync over Transferd,
7 Per-client integration, 8 Relays, 9 Threat model, 10 Licensing, 11 Phased plan, 12 Open questions, Appendix A readiness review of
TransferDaemon, Appendix B changes to ask of TransferDaemon.

---

## Summary of recommendations

| Topic | Recommendation |
|---|---|
| Role of Transferd | Authenticated, encrypted device-to-device transport (discovery, pairing, sessions). PEVV's vault encryption is unchanged and stays the only thing protecting content. |
| Role of Supabase | Optional encrypted backup and offline mailbox, exactly the `pevv_blobs` row it is today. Never required, never removed. |
| Desktop | Link the Transferd crates **in-process** into the Tauri shell through one PEVV-owned Rust crate (`pevv-transport`). Do not run TransferDaemon as a sidecar. |
| Android | Build the same `pevv-transport` crate for Android and call it through **UniFFI** bindings. Do not reuse TransferDaemon's Android app; do not port to Kotlin. |
| Web and extension | Extension: through the desktop app's native-messaging link (ciphertext only). Hosted web app: stays on Supabase/QR in v1; a browser cannot be a first-class Transferd node. |
| Pairing | A Transferd invite (QR) plus a short-authentication-string check on the approving device. Existing paired devices migrate with no re-scan, by publishing their node identity in the sealed vault meta. |
| Sync | A small PEVV sync protocol (PSP/1) carried over Transferd streams; compare-and-swap on `rev` keeps today's rules. |
| Relays | Self-hosted `relayd` (UDP) and `relayd-ws` (WebSocket). PEVV ships **no** default relay. Prefer a `wss://` relay on mobile. |
| Rollout | Behind build-time and run-time flags, dark first, with the existing Supabase and QR paths kept and used as the automatic fallback. |
| Readiness | TransferDaemon's overlay is a serious, well-tested piece of code, but several README claims are not backed by the code, the protocol repo's spec is a placeholder, there is no external audit and there is no second implementation. Plan a hardening phase and a short list of upstream changes before this becomes the default. |

---

## 1. Goals and non-goals

### Goals

1. **PEVV keeps its own end-to-end vault encryption.** The vault file ([VAULT_FORMAT.md](VAULT_FORMAT.md), [CRYPTO.md](CRYPTO.md)) is
   byte-for-byte what it is today. Every client still opens every vault. The master password, the vault key, recovery material and
   plaintext never enter the transport.
2. **Transferd provides device discovery, pairing and transport, as defence in depth.** Even if the vault cipher or the master password
   were weak, ciphertext is then released only to authenticated, user-approved devices over a hybrid post-quantum channel, not to a
   cloud operator or to anyone who learns a vault id.
3. **Supabase becomes optional and secondary.** Sync with no cloud account and no PEVV-operated server. When configured, Supabase is an
   encrypted backup and an offline mailbox for devices that are never online together.
4. **No loss of any current feature.** Cloud sync, the vault QR (online and offline codes), the live roster over Realtime, file export
   and import all keep working. Transferd is an additional transport, selectable and falling back to the old ones.
5. **Real device identity.** A roster entry today is a random UUID with a name. Make it cryptographically bound to a key, so removing a
   device is enforced by the transport as well as by a flag in the vault.
6. **Self-hostable end to end.** Anyone can run the relays, no vendor infrastructure.

### Non-goals

- Replacing or weakening the vault format, the KDF, key slots, passkey/PRF, recovery codes or the USB key.
- Making the transport carry secrets: no key exchange of vault keys, no password transfer, no "remote unlock".
- Messaging, calls, file transfer or any other TransferDaemon application feature. PEVV uses the overlay only.
- Hiding that a user runs PEVV from a network observer (traffic analysis resistance, Tor). See section 9.7.
- Fixing the "last writer wins" loss of concurrent edits. The transport makes forks visible; entry-level merge is a separate decision
  (section 6.6, question 6).
- Cryptographic revocation. Removing a device stops it using the transport and tells it to wipe; it does **not** change the vault key.
  Re-keying on revoke is a separate feature and is called out wherever it matters (sections 4.5 and 9.4).
- A browser-native Transferd node (section 7.3).

---

## 2. What PEVV does today (the baseline this replaces)

- **Whole-file sync.** `src/pevv/sync.ts` mirrors the sealed `VaultFile` JSON (no size cap since migration `0003`) to one Supabase row
  (`pevv_blobs`, row-level security per user). A higher `rev` wins (`reconcileRemote` in `src/pevv/store.ts`).
- **Live exchange.** `src/pevv/roster.ts` and `src/pevv/host/relay.ts` join a Supabase Realtime *broadcast* channel
  `pevv:d:<vaultId>`, announce `rhave {rev}` every 3 seconds, ask with `rwant`, and push the file as up to 8 parts of 48,000
  characters.
- **Vault QR.** `src/pevv/qr.ts` seals the vault with a random AES-256-GCM key shown only in the QR, parks the ciphertext on a
  Realtime channel `pevv:<token>` or in `pevv_blobs`, and expires in 3 minutes. Offline QR frames (`PEVV1|...`, up to 12 codes)
  need no network.
- **Device roster.** `src/pevv/devices.ts`: entries `{id, name, kind, added, seen, agent}` inside the sealed meta. `id` is a random
  UUID kept in `localStorage`; there is no key behind it. Revocation is `meta.revokedDevices`, a list of ids; the revoked copy
  "wipes itself" when it next unlocks or syncs. Rosters merge as a union and revoked wins.
- **Desktop link.** `desktop/src-tauri/src/link*.rs` is a separate, local-only trust relationship between the desktop app and the
  browser extension (native messaging, HMAC-SHA256 with a counter, pairing approved by a person, 1 MB frames). It is not used for
  device sync and stays as it is.
- **Android.** `android/.../sync/{SyncManager,Relay,Realtime,Supabase}.kt` is a Kotlin port speaking the same Supabase topics and
  events, kept compatible with golden vectors.

### Weaknesses this design addresses (read from the code, not tested)

1. **The live channel is protected only by knowing the vault id.** The Realtime policies in `supabase/migrations` allow any
   authenticated (including anonymous) session to read and write every topic matching `pevv:%`. The vault id is plaintext in every
   copy of the vault file.
2. **A locked device adopts a higher `rev` without checking that it decrypts.** In `reconcileRemote`, when the vault is locked and the
   source is `peer`, a file with the same id and a higher `rev` that passes `validateFile` replaces the stored ciphertext
   (`adoptRemoteInner` writes it before anything is opened). Together with (1), someone who knows a vault id can overwrite the locked
   copy on a device that has the app open. The desktop keeps 5 backups, which limits the damage; other clients should be checked.
3. **The cloud operator holds the ciphertext.** A Supabase breach or insider gets a file to attack offline with the master password.
4. **Roster identity is a label.** Anything that can write a valid vault (any holder of the vault key) can add or remove any
   device id. Nothing ties a roster entry to a particular piece of hardware.
5. **Revocation is advisory.** A revoked device keeps the vault key and ciphertext it already had.

Transferd fixes 1 to 3 and the transport half of 4 and 5. It cannot fix the key-holding half of 4 and 5 (section 9.4).

---

## 3. Architecture

```
          +--------------------------- one PEVV device -----------------------------+
          |  vault engine (TS on web/desktop/extension, Kotlin on Android)           |
          |     store.ts: reconcileRemote(), roster merge, rev rules (UNCHANGED)     |
          |            ^                                                             |
          |            | SyncTransport interface (new)  src/pevv/host/transport.ts   |
          |   +--------+---------+----------------------+                            |
          |   | supabase (today) |  transferd (new)     |  <- chosen per vault pref  |
          |   +------------------+----------+-----------+                            |
          |                                 | PSP/1 messages (section 6)             |
          |                      pevv-transport (Rust crate, in process)             |
          |                      identity + sealing, pairing, allow-list             |
          |                      transferd-overlay (OverlayNode, sessions, streams)  |
          +-----------------------------------|--------------------------------------+
                                              | outbound only
                      direct (LAN / tailnet) -+- relay (relayd UDP, relayd-ws WSS) - blind
```

Layers, from the outside in:

| Layer | Owner | Provides |
|---|---|---|
| L4 Supabase | optional, PEVV schema | per-user ciphertext row, offline mailbox, backup. Authenticated by the Supabase account. |
| L3 Relay | self-hosted `relayd` / `relayd-ws` | rendezvous and forwarding of opaque datagrams. Anti-abuse proof of work. |
| L2 Transferd session | `transferd-overlay` | mutual authentication of node identities (Ed25519 + ML-DSA-87), hybrid key exchange (X25519 + ML-KEM-768), AES-256-GCM tunnel with counters and replay window, multiplexed flow-controlled streams, multi-route failover. |
| L1 Pairing and allow-list | PEVV (`pevv-transport` + store) | which node ids may open the PSP service, tied to the sealed roster. |
| L0 Vault | PEVV (unchanged) | Argon2id, AES-256-GCM per entry, AAD bindings, key slots. Content confidentiality and integrity. |

The seam already exists. [ARCHITECTURE.md](ARCHITECTURE.md) says `src/pevv/host/` is "the only outward dependency", and that to run
against another backend one replaces `cloud.ts` and `relay.ts` keeping their exported names. This design keeps both modules working
unchanged and puts a `SyncTransport` selector in front of them (section 11, phase 3).

### How PSP rides on Transferd

TransferDaemon's overlay does not offer a message API. Its unit is a **service**: a named TCP-like byte stream that a paired peer may
open (`OPEN {stream, service}`), carried in DATA/ACK/WINDOW/CLOSE frames inside the encrypted tunnel (docs/PROTOCOL.md section 4 and 5
of the TransferDaemon repository). `OverlayNode::ensure_session(node_id)` returns a `SessionHandle` with `open(service)`,
`send(stream, bytes, fin)`, `recv(stream)` and `close(stream)`, which is what PEVV needs and does not require any loopback socket.
The inbound side is the gap: today an exposed service is only a forward to a local TCP address, and the handler never learns which
peer is on the other end. Section 7 and Appendix B (item U1) ask for an in-process service handler that receives the authenticated
peer id. Until that exists, the interim is one exposed service and one loopback listener per peer; this is **not acceptable on
Android** (any app can connect to loopback), so U1 is on the critical path for Android.

Service name: `pevv-sync-1` (service names may not contain dots or spaces).

---

## 4. Identity mapping

### 4.1 What a Transferd identity is

- A 64-byte seed derives a hybrid signing key: Ed25519 plus ML-DSA-87. The **node id** is the lowercase hex of the 32-byte Ed25519
  public key (64 characters). The full hybrid public key is 2,624 bytes.
- A **key fingerprint** is BLAKE3 over the hybrid public key under the context `TransferDaemon-overlay-key-fingerprint-v1`
  (32 bytes, 64 hex characters). Invites carry the fingerprint, not the key; first contact is refused unless the dialled node presents
  a key that hashes to it. This is what binds the post-quantum half of the identity. A node id that later presents a different key is
  refused (trust on first use).
- The relay token is a public function of the node id (`BLAKE3-derive_key("transferd-overlay-relay-token-v1", node_id)`).

### 4.2 Mapping from PEVV roster entries

Today: `VaultDevice = {id, name, kind, added, seen, agent}` where `id` is a random UUID in `localStorage`.

Proposed: keep `id` exactly as is (it is the stable, human-visible handle, and old clients rely on it) and add one **optional** field,
inside the sealed meta where all device fields already live (compatibility rule 2 of VAULT_FORMAT.md: add only optional fields):

```jsonc
{
  "id": "<uuid, unchanged>", "name": "...", "kind": "phone", "added": 0, "seen": 0, "agent": "...",
  "node": {                                  // absent = legacy device (no Transferd identity yet)
    "id":  "<64 hex, Ed25519 public key>",
    "fp":  "<64 hex, key fingerprint>",
    "at":  1700000000000,                    // when the binding was approved
    "via": "invite" | "roster",              // how it was established (section 5)
    "relays": ["host:port", "wss://host"]    // optional reach hints, no secrets
  }
}
```

Design decisions:

- **Per-device random identity, never derived from the vault or the master password.** One compromised device must not reveal
  another device's transport key, and a transport key must not help unlock a vault.
- **No signatures in the roster.** An ML-DSA-87 signature is 4,627 bytes (plus 64 for Ed25519). Forty devices would add more than
  200 KB to every vault file, which every sync would then carry. The roster is sealed under the vault key, so only a vault-key holder could have written it;
  that is the same trust as today and enough, because every holder of the vault key is already fully trusted at the vault level.
- **Fingerprint, not full key, in the roster** (about 200 bytes per device). The full key arrives in the handshake and must hash to
  the fingerprint, so the roster entry fully authenticates the peer.
- **Web and extension have no node.** They stay legacy roster entries and are reached through the desktop link (section 7.3). The
  extension is a client of the desktop app, as in `link_core.rs`, and is not a Transferd peer.
- **The transport allow-list is derived, not stored in the vault:** `allow = { entry.node.id : entry in roster, entry.id not in revokedDevices }`,
  recomputed on every vault write and cached in a device-local file (node ids are not secret; the cache lets a locked device keep
  enforcing it).
- **Display.** Settings, Devices shows the PEVV name plus a short fingerprint of 8 words (BIP-39 wordlist, from `fp`) so a user can compare
  two screens.

### 4.3 Where the keys live

Hardware cannot hold the key itself. Android Keystore and the TPM (CNG) cannot do ML-DSA at all and are not a safe home for Ed25519 either (hardware
Ed25519 support is patchy); the Secure Enclave only holds P-256 keys. So the model is: **a hardware-backed key wraps the 64-byte seed
at rest; the seed (and so the signing key) exists in process memory while the transport runs.** Hardware protects the stored seed against
offline extraction, not against code running as the user while the app is open. TransferDaemon's own `KeyStore` trait is a RAM store
only (Appendix A), so PEVV does this wrapping itself in `pevv-transport` (`seal.rs`, one implementation per platform behind a trait).

| Platform | Wrapping key (at rest) | Notes |
|---|---|---|
| Windows (desktop) | **DPAPI**, user scope (`CryptProtectData`, already linkable through the `windows` crate PEVV depends on). Optional upgrade: a non-exportable RSA key in the TPM via the CNG "Microsoft Platform Crypto Provider", used to RSA-OAEP-wrap the seed. | Seed file in the app data folder next to `vault.json`, current-user ACL. A TPM-wrapped seed does not survive a motherboard or TPM reset; the failure path is "generate a new identity and re-pair", never "lock the user out". |
| Linux (desktop) | **Secret Service** (GNOME Keyring, KWallet) through the `keyring` crate. Fallback: a `0600` file in a `0700` folder, as `vault_store.rs` already does. Optional: TPM2 sealing via `systemd-creds`. | A headless or minimal desktop with no Secret Service uses the file and the UI says so. |
| Android | **Android Keystore** AES-256-GCM key (StrongBox when present, otherwise TEE), `setUnlockedDeviceRequired(true)`, **no** per-use biometric (background sync must work). The wrapped seed lives in no-backup storage (excluded from Auto Backup and device-to-device transfer). | PEVV already has `security/Security.kt` (`DeviceSeal`) for sync tokens; reuse it. If unwrapping fails after a restore, generate a new identity and re-pair. |
| macOS / iOS (no client today) | Secure Enclave P-256 key doing ECIES over the seed; or the Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. | Listed so the trait covers it; not planned. |
| Extension / web | None. No Transferd identity (section 7.3). | |

Not recommended: sealing the seed under the vault key. It would be the strongest choice (the identity exists only while unlocked) but
background and locked-state sync could not work, and a locked device could not even accept an incoming `rev`.

Identity lifecycle: created on first enabling the transport; never exported; rotating it means a new node id, i.e. re-pairing and
revoking the old entry.

### 4.4 Identity files and zeroisation

`pevv-transport` holds the seed in a zeroizing buffer, derives the `NodeIdentity`, and drops the seed copy. The Tauri shell never
passes the seed to the webview. Only node id, fingerprint and status cross into TypeScript.

### 4.5 Revocation: what it does and what it cannot do

**Propagation** (when device A, unlocked, revokes device C):

1. A writes C's `id` into `revokedDevices` and removes C from `devices` (today's `revokeDevice`), bumping `rev`.
2. A's transport recomputes the allow-list and, **immediately**, closes C's session and refuses new streams from C's node id.
3. A sends `ROSTER_HINT {rev, revoked: [nodeId]}` to every other connected peer so they drop C at once (a hint can only restrict).
4. The new file reaches every online peer by the normal announce, and offline peers by the next announce or from the Supabase mailbox.
   Each peer recomputes its own allow-list from the file it adopts.
5. C, when it next connects to anyone, is refused at the stream level, learns nothing, and (if it ever syncs a file listing it as
   revoked) wipes itself as today.

**What it cannot do.** C already holds the vault key (or a biometric-wrapped copy of it) and the ciphertext. Revocation here stops C
from *receiving future ciphertext and from tampering with the others*, and it makes the loss visible; it does not make past or
cached data unreadable to C. A revoked device that still holds a valid vault key can also seal a valid higher-`rev` file and push it
to a shared Supabase row. True revocation needs **re-keying** (new vault key, re-seal every entry, re-wrap every slot, rotate the
`id`'s trust), which PEVV does not have. This design should add a "revoke and re-key" action as its own project (question 7) and
until then the UI must say "removing a device stops sync; if the device was stolen, also change your master password and rotate your
secrets".

**Upstream dependency:** TransferDaemon's overlay has no unpair or revoke call (Appendix B, U2). Without it a revoked node can still
complete a handshake and learn presence and addresses until its session is dropped. Adding U2 is required before phase 4 exits.

---

## 5. Pairing

### 5.1 UX (new device B joins a vault held by unlocked device A)

1. **A:** Settings, Devices, "Add a device", choose "Direct (Transferd)". A shows a QR and a copyable link containing a Transferd
   invite. A shows a countdown (default 3 minutes, as `HANDOFF_TTL_MS` today; Transferd accepts 30 s to 24 h).
2. **B:** scans it (camera, or paste), "I already have a vault". B dials A (relay, or direct addresses carried in the invite), and
   both screens show **the same 6 words** (a short authentication string derived from both key fingerprints and the invite nonce).
3. **A:** "Pixel 9 wants to join. Do the words match B's screen?" A person confirms or declines. Nothing is sent before this.
4. **A to B:** the sealed vault file. B asks for the master password (or passkey, recovery code, USB key) exactly as today; the
   password is checked on B against the file, and is never sent anywhere.
5. B adds its own roster entry (name, kind, `node`) through the normal write; A's roster binding is already in the file; the
   allow-lists update on both sides; the invite is dead.

The QR carries an invite, not a key to the vault: the vault never travels under a key that is on screen, which is a strict
improvement on the current handoff QR (a photograph of today's QR plus the cloud row is enough to take the ciphertext within 3
minutes; a photograph of a Transferd invite is not, because step 3 needs a person).

### 5.2 One-time nonce and what the invite protects

- The invite is `tdov2:` plus base64url JSON `{node_id, name, key_fingerprint, relays, direct, expires_at, nonce, signature}`, a few
  hundred bytes, QR-sized, signed by the inviting node. The `nonce` is 16 random bytes, generated per invite.
- In TransferDaemon the inviter stores `nonce -> expiry` and **removes the nonce on first use** (`invites.remove(&nonce)` in
  `node.rs`); a second dial with the same nonce is not treated as the pairing. The inviter learns the accepter presented it from the
  `pairing` field of the first HELLO.
- **The nonce only proves "someone read the QR".** It does not authenticate the person. A shoulder-surfer who scans first wins the
  nonce. The invite's Ed25519 signature is classical; only the key fingerprint binds the post-quantum key. Therefore PEVV adds:
  - the **SAS check on A** (step 3). The legitimate B, which then fails to pair, shows "this invite was already used";
  - at most one outstanding invite per vault, cancelled when the dialog closes, and a limit of 3 unconfirmed attempts per invite;
  - **explicit per-node ACL only.** PEVV never uses the `*paired` shorthand (which TransferDaemon applies to anyone who presented a
    valid nonce); the allow-list is the roster-derived set of node ids and changes only after the person approves.
- A "Require Transferd for new devices" vault setting disables the legacy handoff QR for enrolment, for users who want that.

### 5.3 Migration: existing paired devices

"Paired" today means "has the same vault". There is nothing to re-scan; the sealed roster already is an authenticated channel
between devices (only a vault-key holder can write it).

1. A build with the transport enabled creates a node identity on first run (offline, no network).
2. It writes `node: {id, fp, via: "roster", relays}` into **its own** roster entry (normal vault write, `rev` +1). That write travels
   over the **existing** lanes (Supabase or Realtime), so the binding is published through the old transport.
3. Every other device, on adopting that file, sees a new `node` binding on a roster entry and pairs with it by node id and
   fingerprint, no invite needed. This needs a small upstream function, `pair_trusted(node_id, key_fingerprint, reach)` (Appendix
   B, U3). The first handshake must present a key hashing to `fp`.
4. When both ends have each other's binding, they connect directly and prefer Transferd. Devices without a binding stay on the legacy
   lanes. The settings screen shows "Direct link: 2 of 3 devices; Pixel has not updated."
5. Nothing is removed. The legacy QR, Realtime lane and Supabase sync continue in parallel until the owner turns them off.

Trust note: step 3 trusts whoever could write the vault, which is already the trust boundary. It adds no new trust in Supabase. A
malicious Supabase cannot forge a binding (it cannot seal under the vault key) but could replay an older roster; that only delays
adoption.

---

## 6. Sync over Transferd

### 6.1 PSP/1: the PEVV sync protocol

A deliberately small protocol over Transferd streams, so it can be implemented in TypeScript, Kotlin and Rust and checked with shared
golden vectors (section 11, phase 2).

Frame on a stream: `type u8 | flags u8 | len u32 BE | body`. Control bodies are UTF-8 JSON, at most 16 KiB. Blobs follow their
header as raw bytes. Unknown `type` values are skipped using `len`; unknown JSON fields are ignored (same additive rule as Transferd).

| Type | Name | Body | Purpose |
|---|---|---|---|
| 0x01 | HELLO | `{psp: 1, vault, dev, rev, hash, caps}` | first frame each way on every stream; `vault` = vault id; `dev` = PEVV device id; `hash` = SHA-256 of the canonical vault JSON; `caps` = optional feature names |
| 0x02 | ANNOUNCE | `{rev, hash, size}` | "I have this revision." Level-triggered and idempotent. |
| 0x03 | FETCH | `{have, want}` | `have` = my rev (or -1); `want` = rev number or `"latest"`. |
| 0x04 | BLOB | `{rev, hash, size}` then exactly `size` raw bytes | the vault file; reply to FETCH or part of PUSH. |
| 0x05 | PUSH | `{base, rev, hash, size}` then `size` raw bytes | "replace your rev `base` with this." |
| 0x06 | PUSH_ACK | `{result, rev}` | `ok`, `stale` (you are behind, fetch), `fork` (same rev, different hash), `invalid`, `denied`. |
| 0x07 | ROSTER_HINT | `{rev, revoked: [nodeId]}` | early revocation notice (can only restrict). |
| 0x7e | ERR | `{code, reason}` | protocol or policy error, then close. |
| 0x7f | BYE | `{}` | clean close. |

Reserved for later: 0x10 `ENTRIES_HAVE`, 0x11 `ENTRIES_FETCH`, 0x12 `ENTRIES_PUSH` (entry-level merge, section 6.6).

### 6.2 Mapping to Transferd streams and frames

| PSP traffic | Transferd | Why |
|---|---|---|
| ANNOUNCE, ROSTER_HINT, FETCH, PUSH_ACK, BYE | Each side opens **one long-lived control stream** to the other (service `pevv-sync-1`) and only writes on its own. | No open-glare: Transferd lets either side allocate ids, and with one stream per direction nobody has to arbitrate. Small messages ride DATA frames, in order, with the stream's flow control. |
| BLOB, PUSH body (any size, read in 64 KiB chunks) | A **new short-lived stream per transfer**, opened by the sender of the bytes, closed with `fin`. | Head-of-line blocking is per stream; an ANNOUNCE is never stuck behind 200 KB. A failed transfer is a closed stream, not a damaged control channel. |
| Liveness | Transferd's own 1 Hz route pings and 300 ms control-frame retransmission. PSP sends no pings. | Do not duplicate it. |

Transferd's frame cap is about 16 KiB per DATA frame and a stream window starts at 256 KiB, so a 200 KB vault is a dozen frames and at
most one window grant. The 48,000-character chunking, `want` polling and 3-second `rhave` beacon of the Realtime lane disappear.

### 6.3 Ordering

- Within a stream: in order and reliable (Transferd delivers in order, buffers up to 256 out-of-order frames, acknowledges
  cumulatively with SACK).
- Across streams: no ordering. PSP does not depend on any.
- Semantics are by `rev`, not by arrival: ANNOUNCE is level-triggered (the latest rev wins, an older one is ignored), BLOB and PUSH
  carry their own `rev` and `hash`, and the receiver verifies size and hash **before** parsing, then runs `validateFile`, then (if
  unlocked) `readMeta` exactly as `reconcileRemote` does today.
- Re-announce on connect, on every local write (debounced 400 ms as today), and every 30 s as a safety net.

### 6.4 Retries and failure

- Every message is idempotent. FETCH can be repeated; a repeated PUSH with the same `(base, rev, hash)` where the receiver already
  has that hash returns `ok`.
- Session loss: reconnect with exponential backoff and jitter (1 s to 60 s). On reconnect, send HELLO and ANNOUNCE and let the
  comparison decide; no queue of unsent messages is kept because the vault itself is the queue.
- Blob streams time out after 20 s without progress; a failed blob is simply re-requested (the file is at most a few hundred KB, so
  no resume protocol).
- No peer reachable for more than N seconds (default 30) and a Supabase mailbox is configured: write the file there too (section 6.5).
- Transferd resends lost data on another route and ends a session after 60 s with no control receipt. Its guarantees stop at the
  stream; PSP does not assume delivery without an `PUSH_ACK`.

### 6.5 Supabase as backup and mailbox

- The row is the same `pevv_blobs` ciphertext as today, written by the same `mirror()` logic, so older clients that only know Supabase
  keep working during rollout.
- On a device that is `transport = auto`: prefer a Transferd peer when one is reachable; otherwise pull from Supabase on foreground,
  focus and the existing 2-minute poll. A file arriving from both is adopted once, keyed by `(rev, hash)`.
- Optional hardening (needs a migration `0002`): make the write a **compare-and-swap** on the server (`update ... where rev = base`),
  so two offline devices cannot silently overwrite each other in the mailbox. Not required for correctness of the Transferd path.
- A strict mode `transferd-only` never contacts Supabase for that vault. Then no third party ever holds the ciphertext.

### 6.6 Composition with the CAS and conflict rules

There is no `docs/SYNC.md` yet. The rules below are the ones implemented by `sync.ts`, `store.ts`, `devices.ts` and
`vault_store.rs` today, stated abstractly; PSP keeps all of them and adds checks in front.

| # | Existing rule | With PSP |
|---|---|---|
| R1 | The unit of sync is the whole sealed file; no field merge. | Unchanged. |
| R2 | `rev` is monotonic; a higher `rev` of the same vault id replaces local entries when the source is allowed to (`peer` always; `cloud` only if `prefs.sync`). | A Transferd peer is source `peer`. |
| R3 | Rosters merge as a union; `revokedDevices` is a union; revoked wins. | Unchanged; the allow-list is recomputed from the merged result. |
| R4 | A file for a different vault id is ignored. | Also enforced at HELLO: `vault` must equal the local vault id or the stream is refused. |
| R5 | A vault revoked locally is never re-adopted. | Same, and the node denies that peer. |
| R6 | `vault_write(json, expectedRev)` on desktop refuses a lower revision (`rev-conflict`). | This is the on-disk CAS; PSP adds a network CAS in PUSH (`base`). |
| T1 | (new) Adopt only from an authenticated, un-revoked peer, never from "whoever is on the channel". | Fixes weaknesses 1 and 2 of section 2. |
| T2 | (new) A PUSH applies only if the receiver's current rev equals `base`; if the receiver is ahead the answer is `stale` and the sender fetches and reconciles; if the receiver has the same rev but another hash, `fork`. | Network-level compare-and-swap. |
| T3 | (new) Equal `rev`, different `hash` is a **fork**: surfaced to the user, both copies are kept (the loser goes to the device's local backup), the higher hash is taken only as a deterministic tiebreak so devices converge, and the next write supersedes it. | Today this case is silent: neither side adopts the other and they diverge until the next write on one of them. |
| T4 | (new) Keep a device-local high-water mark of the highest `rev` seen per vault from authenticated peers; if a backup (Supabase) is behind by more than a threshold while peers are ahead, warn ("backup is stale"); never adopt a lower `rev`. | Detects a mailbox serving an old file to hide a revocation. |

Honesty note: R2 loses concurrent edits (two devices editing offline, higher `rev` wins). T3 makes that visible, not fixed. The
reserved `ENTRIES_*` messages and entry `ver` fields leave room for a real merge (union by entry id, higher `ver` wins, keep both on a
tie) as a separate piece of work.

---

## 7. Per-client integration

### 7.1 Desktop (Tauri 2, Rust shell)

| | A. Link the crates in-process | B. Run TransferDaemon as a sidecar |
|---|---|---|
| What | New crate `pevv-transport` depending on `transferd-overlay` and `transferd-crypto`; started on its own Tokio runtime thread by the Tauri shell. | Bundle the `transferd` daemon (and its control hub) as a Tauri `externalBin`, or rely on an installed one, and talk to it over gRPC or the local HTTP control hub. |
| Attack surface | Only what PEVV calls. No new listening socket (outbound only). | The daemon exposes a gRPC server and a control hub with 47+ operations including GUI/TUI control, MCP, relay start/stop and updates, guarded by a token. TransferDaemon's installers also register an autostart service. Far more than PEVV needs. |
| Key custody | The seed is wrapped by PEVV (section 4.3) and never leaves the process. | The daemon's identity comes from its own account (a BIP-39 phrase); its overlay seed is a file protected by DPAPI or an owner-only file. PEVV would have to trust another program with its device identity, or run a second daemon. |
| Identity and peer id | Direct `SessionHandle` use; the peer id is known. | The overlay exposes services as loopback TCP forwards; any local process can use a `connect` endpoint, and the service handler does not learn the peer id. |
| Install and update | One binary, one updater. | Two programs to version, install, start, restart and keep compatible; PEVV must handle "daemon missing, wrong version, crashed, user closed it". |
| Isolation | A panic in the transport takes the app down (TransferDaemon builds with `panic = abort`); mitigate with a dedicated thread and `catch_unwind` at the boundary, and by keeping the Rust side ciphertext-only. | A crash is contained. |
| Build cost | Pulls `transferd-core` (and `ring-channel`, `relayd`, `transferd-dns`, `tokio-tungstenite`) into the build. Needs a pinned git dependency or vendoring (the crates are `0.1.0` and not published). Longer builds. | None. |
| Reuse | PEVV only. | Shared if the user already runs TransferDaemon. |

**Recommendation: A, in-process.** The security argument decides it: PEVV's own rule is that the Rust shell "never sees a password, vault
key or plaintext" and has a short, audited command list (`capabilities/default.json`). A daemon with a 47-operation control plane is a
much larger thing to trust next to a password manager. The cost of A is build plumbing, which is a one-time cost. Keep `pevv-transport`
a library with a thin `main.rs` so a sidecar build (`pevv-transportd`) is a one-day change if the owner prefers process isolation.

New Tauri pieces (Tauri-free policy kept in `_core` files, like `link_core.rs`):

- `desktop/src-tauri/src/transport.rs` (commands and events), `transport_core.rs` (allow-list, pairing state, policy, unit-tested without
  Tauri), `transport_seal.rs` (DPAPI / keyring / file).
- Commands (added to `capabilities/default.json`): `transport_status`, `transport_enable`, `transport_invite_create`,
  `transport_invite_accept`, `transport_pair_confirm(sas_ok)`, `transport_send(peer, bytes)`, `transport_set_allow(list)`,
  `transport_set_relays(list)`. Events: `transport-peer`, `transport-msg`, `transport-pair-request`.
- The webview speaks PSP through these commands, so `reconcileRemote` and the roster merge stay in TypeScript, in one place.
- The extension link (`link_core.rs`) gains sync operations (7.3).

### 7.2 Android

| | A. Rust core via UniFFI (recommended) | B. Reuse TransferDaemon's Android code | C. Port to Kotlin |
|---|---|---|---|
| What | Build `pevv-transport` for `aarch64-linux-android` (and `armv7`, `x86_64` for emulators) with `cargo-ndk`; generate Kotlin bindings with UniFFI; load `libpevv_transport.so`. Same Rust crate as desktop. | Install or embed TransferDaemon's Android app and talk to it. | Re-implement the overlay (hybrid handshake, tunnel, mux, congestion control, relay client, optional punching) in Kotlin with BouncyCastle for ML-KEM/ML-DSA. |
| Fit | Good. | Poor. TransferDaemon's Android build is a whole **NativeActivity egui app** (`transferd-mobile` cdylib, daemon thread, gRPC bridge, package `com.transferdaemon.app`), not an embeddable library. Its shipped `.so` is 13.8 to 20.5 MB per ABI. Two apps, user must install both, loopback gRPC reachable by other apps, Android background limits on a second app. | Plausible but large. The overlay crate alone is about 12,000 lines of Rust plus its crypto and relay dependencies; interoperability would have to be proven byte-for-byte against a reference whose spec repo is a placeholder (Appendix A). |
| APK size | *Estimate, not measured:* low single-digit MB per ABI stripped with LTO for an overlay-only build (AES-GCM, X25519, ML-KEM, ML-DSA, Tokio, tungstenite, BLAKE3), plus UniFFI's JNA runtime (about 1 to 2 MB per ABI) unless the hand-written `jni` crate is used instead. TransferDaemon's 18 MB arm64 library includes egui, WebRTC, gRPC and everything else and is **not** the right figure. Phase 0 must measure; set a budget of 6 MB per shipped ABI (arm64-v8a only on the Play AAB split). | +18 MB. | Smaller native size, but BouncyCastle adds several MB before R8 shrinking; *estimate*. |
| Maintenance | NDK and `cargo-ndk` in CI; UniFFI version pinned; Android 15+ requires **16 KB page-aligned** native libraries (PEVV targets SDK 36); one Rust codebase for desktop and mobile, so a fix lands once. | Tracking someone else's app. | Highest: permanent second implementation, security fixes twice, risk of silent divergence. |
| Verdict | **Recommended.** | Reject. | Reject for now; reconsider only if a small, spec-conforming relay-only subset is ever wanted. |

Android specifics:

- Kotlin `TransferdTransport.kt` implements the same `SyncTransport` shape as `Relay.kt`/`Supabase.kt`, behind `SyncManager`. PSP encode and
  decode live in Kotlin (`PspCodec.kt`) checked against the shared golden vectors, as the vault format already is.
- `minSdk 26`: gate StrongBox and `setUnlockedDeviceRequired` on API level.
- Foreground only to start: the transport runs while the app is in the foreground or the autofill service is active, as sync does
  today. A persistent background service is a battery and Play-policy question (question 9).
- Prefer a `wss://` relay on mobile networks (section 8 and Appendix A: UDP relay datagrams here can be up to 16 KiB and there is no
  path-MTU handling).
- Manifest: `allowBackup="false"` for the seed file (or exclude it), no new permissions beyond `INTERNET` (already needed).

### 7.3 Web app and browser extension

What a browser cannot do: open raw UDP or TCP sockets (no relay UDP, no hole punching, no direct dialling, no listening); use
mDNS or LAN discovery; keep a socket alive when the tab is frozen or the Manifest V3 service worker is asleep; hold
hardware-backed Ed25519 or any ML-DSA/ML-KEM key (WebCrypto has no stable post-quantum support; a JavaScript or WASM implementation
would be needed); connect to arbitrary hosts without a `connect-src` entry in PEVV's strict CSP; call `http://` from an `https://`
page without mixed-content and Private Network Access problems.

| Option | Verdict |
|---|---|
| **Extension via the desktop app's native messaging** | **Recommended.** Reuses the existing, reviewed link (`link_core.rs`: extension id allow-list, person-approved pairing, per-message HMAC, replay counter, 1 MB frames). Add sync operations that carry **ciphertext only**: `sync-state {rev, hash}`, `sync-get`, `sync-put {base, body}`. The desktop app is the Transferd node. Works while the app runs; without the desktop app the extension keeps today's Supabase/QR paths. A 200 KB vault is about 270 KB as base64, under the 1 MB frame cap. The ops must be allowed while locked (they never need the key) but only for a paired, un-revoked extension. |
| Browser as a Transferd node over a WebSocket relay | Not for v1. It requires a full JavaScript or WASM port of the hybrid handshake, the tunnel and the session/mux code, which is the Kotlin-port problem again in a worse environment (TransferDaemon's overlay uses UDP sockets and Tokio and does not target WASM). |
| WebSocket bridge: a small service next to the user's relay terminates the browser's WebSocket and acts as a Transferd peer on its behalf | Possible later as an explicitly weaker mode. The bridge sees only ciphertext (the vault is already end to end encrypted), but device authentication would terminate at the bridge, so the Transferd identity guarantee is lost for that client. Needs its own threat model; not planned. |
| Hosted web app | Stays on Supabase and the QR codes. It can still receive a vault by offline QR frames. |

Extension background: MV3 service workers sleep after about 30 seconds of idleness; the native port keeps the worker alive while it
is open, and a 1-minute `alarms` poll covers the rest. State this in `CLIENT_EXTENSION.md` when it ships.

---

## 8. Relays

### 8.1 What exists (verified in the TransferDaemon repository)

| Piece | What it is |
|---|---|
| `relayd` | Blind UDP relay (`relayd` crate). Registers 32-byte tokens with proof of work (BLAKE3, default difficulty 20), forwards `Forward {token, ciphertext}`, per-source token bucket, TTL pruning (90 s), `Locate` for hole punching. Env: `RELAYD_PORT` (5901), `RELAYD_DIFFICULTY`, `RELAYD_TTL`, `RELAYD_RATE_PER_30S` (default 300), `RELAYD_BIND`, `RELAYD_MAX_BLOB_BYTES`, `RELAYD_MAX_MB_PER_DAY/WEEK/MONTH`, ghost-key variables. |
| `relayd-ws` | The same relay over WebSocket (`RELAYD_WS_PORT`, 5902). Speaks the same frames, so one client logic. |
| Cloudflare Worker | Durable Object relay in `deploy/cloudflare-worker`. **No proof of work** (the edge's rate limits are the only abuse barrier). |
| Docker and nginx | `deploy/docker-compose.yml` (relayd, relayd-ws, dhtd), `deploy/nginx/*` for TLS in front. |
| `harbor/` | **Not a relay.** It is a capability-gated MCP server for computer control. Ignore it for this design. |
| `dhtd` and the DHT | Contact discovery for the messaging app. PEVV does not use it: nodes learn each other's relays from the invite or the sealed roster. |

### 8.2 Defaults and configuration for PEVV

- **PEVV ships no default relay.** TransferDaemon's own roadmap lists "public relay node deployment" as unfinished, and a default
  would put every user's pseudonymous traffic graph on one operator. The first-run flow asks for relay addresses, or the user pairs
  on a LAN or tailnet (direct routes need no relay).
- Settings, Devices, "Relays": a list of `host:port` (UDP) and `wss://host[:port]` entries, at most 4. They are stored per device
  and published in the roster entry's `node.relays` (sealed) and in invites, so a new device learns them automatically. Build-time
  default: `VITE_PEVV_RELAYS` (comma separated, empty by default), mirrored as `pevv.relays` for Gradle and `PEVV_RELAYS` for cargo.
- Recommended deployment: a small VPS with `relayd` on UDP 5901 **and** `relayd-ws` behind nginx or Caddy on 443 as `wss://`; register
  on both. WebSocket-over-TLS crosses networks that drop UDP or fragments, and it makes the traffic look like ordinary HTTPS.
  Raise `RELAYD_RATE_PER_30S` (TransferDaemon's own overlay documentation says the default is sized for messaging, not for streams).
- A relay needs no account, no database and no PEVV secret. It must not be given any.
- PEVV adds a **Diagnostics** screen: which route each peer uses (direct, relay, punched), round-trip time, bytes, last announce. No
  telemetry leaves the device.

### 8.3 What a relay sees (from the code, not from the README)

| Visible to the relay | Detail |
|---|---|
| Source IP and port of every device | Always. Hidden only if the device reaches the relay through a VPN or Tor. |
| Registration token per device | A stable pseudonym that is a **public function of the device's node id**: anyone who knows a node id can compute its token. |
| Destination token **and sender token** of every datagram | The overlay's relay payload is `[prefix][sender_token][sealed frame]` padded to a power of two. Only the inner tunnel frame is sealed. So the relay sees who (by token) talks to whom, contrary to the README's "never knows who is communicating". |
| Handshake flights in the clear | The 8.5 KB hybrid handshake flights carry both parties' 2,624-byte public identity keys unencrypted. The relay (and any on-path observer) can read the full public keys, and so the node ids and fingerprints, of both ends. |
| Sizes | To within a factor of two (power-of-two padding), and timing, rates and session lifetimes. No constant-rate padding was found in the overlay. |
| Not visible | Plaintext, vault id, rev, hashes, device names (all inside the encrypted tunnel or the vault). |

For PEVV all devices belong to one user, so this is "an operator learns that these N pseudonyms and these IP addresses form a group,
and when it is active". That is a real, accepted leak for a self-hosted relay and a larger one for someone else's relay. It is also
why PEVV node ids must stay private (they are exchanged only by QR and in the sealed vault).

---

## 9. Threat model

Notation: S spoofing, T tampering, R repudiation, I information disclosure, D denial of service, E elevation of privilege.
"Vault" means the L0 layer (unchanged). "Backup" means Supabase.

### 9.1 What each layer guarantees (and does not)

| Layer | Guarantees | Does not guarantee |
|---|---|---|
| L0 Vault (PEVV) | Confidentiality of entries and meta; integrity and place-binding of every sealed value; KDF floors; entry version rollback detection inside a file. | Freshness of the whole file (a stale but valid file looks fine); protection from a holder of the vault key; hiding sizes, `rev`, vault id, slot types. |
| L1 Pairing / allow-list | Only user-approved, roster-listed node ids can open the PSP service; allow-list follows the sealed roster; explicit per-node ACL. | Anything about a device that was approved then stolen or compromised; that the approving person compared the SAS. |
| L2 Transferd session | Mutual authentication of the two node identities; hybrid post-quantum key agreement (an attacker needs to break X25519 **and** ML-KEM-768); forward secrecy per handshake; per-frame AEAD with authenticated length and counter; 4096-wide replay window; reordering and duplicate tolerance; route failover. | Hiding identities from on-path observers (public keys are sent in clear); metadata; availability; a security audit has not been done. |
| L3 Relay | Forwards opaque datagrams without being able to read or forge them; rate and proof-of-work limits. | Anonymity of who talks to whom; availability; ordering or delivery. |
| L4 Backup | Persistence and offline delivery of ciphertext. | Freshness, availability, privacy of timing and size, or protection from the account owner's compromised credentials deleting or rolling back the row. |

### 9.2 Compromised relay

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Relay (or anyone) registers a victim's token first or with a higher sequence number and receives traffic meant for it. Tokens are derived from public node ids and registration is not signed (proof of work plus a sequence number only). | Payload is end-to-end authenticated, so the squatter cannot read it or answer as the victim. A second relay in the list. Direct routes preferred. | Denial of service on that relay; the squatter sees ciphertext. |
| T | Modify, drop, duplicate, reorder, inject datagrams. | AEAD per frame, counters, replay window; retransmission over other routes; PSP verifies hash and `validateFile`. | Loss and delay; never silent corruption. |
| R | Relay denies or claims it forwarded something. | Not a goal. | None needed. |
| I | Reads tokens, IPs, sizes, timing, both full public keys from the handshake, and who talks to whom (by token). | Self-host; relay-only is not required (direct and LAN routes bypass it); node ids private; optional VPN. | Pseudonymous social graph and activity times. See 8.3. |
| D | Blocks, throttles, restarts; floods. | Multiple relays; WSS fallback; direct routes; offline mailbox. | Sync waits. |
| E | Registration or forwarding bug becomes remote code execution on the relay host. | Run `relayd` unprivileged in a container; it holds no key material. | A compromise of the host reveals only what the relay already saw. |

### 9.3 Compromised Supabase (or its operator, or a breach)

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Serves a different or forged file as "the vault". | Vault AEAD: a forged file cannot be opened; PSP-adopted files only come from authenticated peers; the cloud path keeps `reconcileRemote` plus `readMeta` check when unlocked. | When the device is locked the cloud path still adopts by `rev` (weakness 2). Fix: require the file to open before replacing, or defer adoption until unlock. |
| T | Modify ciphertext, roll back to an old file, delete the row. | AEAD detects modification; `rev` monotonic and the high-water mark (T4) detect rollback when any peer is ahead; the devices hold the real copy. | A rollback while no peer is online goes unnoticed until one is; deletion needs the user's other devices (or a backup). |
| R | Operator denies access or alters logs. | n/a. | |
| I | Holds a copy of the ciphertext, plaintext vault id, `rev`, size, account email, write times. A breach hands attackers a file to brute-force offline. | `transferd-only` mode never uploads. Argon2id floors protect the file. | In `auto` mode the cloud copy still exists; this design reduces what is *needed*, not what is stored. |
| D | Outage, quota, account lock. | Transferd path independent of it. | None for connected devices. |
| E | Using the anonymous Realtime policy to inject into live channels. | Transferd path removes the Realtime channel entirely when `transferd-only`; legacy path should be tightened separately. | Legacy lane stays exposed while enabled. |

### 9.4 Malicious or compromised paired device

A paired device already holds the vault key or can obtain it from a person, so L0 cannot defend against it. The transport can limit
blast radius and make abuse visible.

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Pretends to be another roster device. | Node identity is a key; the handshake proves it; the roster binds `node.id` and `fp`. | A stolen key is the device. |
| T | Pushes a hostile file: lower, higher, forked or malformed. | CAS on `base`; hash and size checks; `validateFile`; `readMeta` when unlocked; fork surfaced; never lower `rev`; desktop keeps 5 backups. | A valid higher-`rev` file sealed by a holder of the vault key (it can rewrite everything, including revoking the others). Undetectable cryptographically. |
| R | Denies having pushed. | The audit log records device id and node id of the source of each adopted `rev`. | Not signed per write (size). |
| I | Reads everything it syncs. | That is the definition of a paired device. | Re-key on revoke (question 7). |
| D | Floods announces or blobs; opens many streams. | Per-service rate limit (overlay), PSP caps (control message size 16 KiB, 1 transfer in flight per peer; the blob has no size cap and is read in 64 KiB chunks, hash-checked before it is parsed), session limit per node. | Self-DoS only; the user removes the device. |
| E | Revokes others, adds devices, changes policy through the sealed roster. | Adding a device needs a person to approve on an unlocked device (SAS); all roster edits are audited. | Same trust as today. |

### 9.5 Stolen phone

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Attacker uses the phone's transport identity to join sessions. | The seed is wrapped by a Keystore key with `setUnlockedDeviceRequired`; the app has the vault and the app lock/biometric as today; owner revokes from another device and the others drop the node at once (section 4.5). | While the phone is unlocked and the app is open, the identity is usable. Between theft and revoke, an online stolen phone can sync; revoke fast. |
| I | Offline extraction of the seed or the vault. | Keystore (StrongBox when available); vault key only under biometric/password/passkey as today; Argon2id on the master password; the transport seed is not the vault key. | A device with a broken Keystore (rooted, no TEE) offers little; the vault remains protected by the master password. |
| D | Thief wipes or locks. | The vault is on other devices and in the backup. | |
| E | Using the phone as a stepping stone to other nodes. | It can reach only the PSP service (sync), not a shell or files; allow-list enforced per stream. | It can ask the other devices for the latest ciphertext until revoked. |

### 9.6 Downgrade attacks

| Target | Attack | Defence |
|---|---|---|
| Handshake suite | Force a weaker KEM or signature. | One suite exists (`0x0002`, X25519 + ML-KEM-768 with Ed25519 + ML-DSA-87); PEVV pins `supported = [0x0002]` and refuses anything else (needs Appendix B, U4). Version, suite and both identities are inside the signed handshake transcript. |
| Frame protocol version | Force version 1 or 2 so features like punching are off. | The negotiation happens inside the encrypted tunnel, so an on-path attacker cannot alter it; a malicious peer could, but gains nothing. PEVV sets a minimum. |
| Invite version | Present a `tdov1:` invite. | Refused by name by TransferDaemon. |
| PSP | Pretend not to speak it. | `psp` is in HELLO and a per-vault minimum is enforced (`prefs.minPsp`). |
| **Transport** (the important one) | Block Transferd (drop UDP, drop the relay) to push devices onto the legacy Supabase path. | The fallback is deliberate, so this is a policy question, not a bug. Default `auto` shows "synced through cloud backup, direct link unavailable"; `transferd-only` never falls back; the roster `seen` times plus T4 warn when peers are active but unreachable directly for days. The vault stays encrypted either way; what is lost is defence in depth. |
| Pairing | Use the legacy QR to enrol a device when the user wants Transferd only. | The "Require Transferd for new devices" setting. |
| Vault | Weaken the KDF. | Existing KDF floors enforced on unlock. |
| Suite lifetime | Suites carry a hard-coded sunset date compared with the device clock. | A wrong clock can make a suite "sunset" and break sync; an attacker with clock control gets denial of service only. |

### 9.7 Replay

| Where | Replay of | Defence |
|---|---|---|
| Tunnel | A captured frame. | Per-direction counter in the nonce and AAD, replay window 4096, keys fresh per handshake (counter reuse cannot happen across sessions). |
| Handshake | A captured initiator flight. | The responder answers a repeated identical flight with the same cached answer, never derives a second key; a replay yields nothing but the cached reply. The relay path binds the sender token. |
| Relay registration | An old register or keepalive. | Strictly increasing sequence number per token, plus proof of work. |
| Invite | A used or old invite or its QR. | Single-use nonce, expiry (3 minutes by PEVV policy), signed, and the SAS approval. |
| PSP | An old ANNOUNCE, BLOB or PUSH. | `rev` monotonic and CAS on `base`; `(rev, hash)` verified; high-water mark. Old blobs are ignored, never adopted. |
| Native-messaging link | A captured extension request. | Existing counter and HMAC (`link_proto.rs`); new sync operations reuse it. |
| Backup | An old row. | T4. |

### 9.8 Metadata leakage (summary by observer)

| Observer | Learns | Does not learn |
|---|---|---|
| Network on the path | That the device talks UDP or WSS to a relay (or directly to a peer, with its IP); handshake flights with public keys; sizes to a factor of two; timing. | Content, vault id, rev, names. |
| Relay operator | Everything in 8.3. | Content, what is synced. |
| Paired devices | IP addresses (direct candidates and punch candidates are exchanged), names, kinds, last seen, online/offline. | Each other's keys at rest. |
| Supabase operator | Email, vault id, `rev`, size, sync times, ciphertext. | Plaintext. |
| A local app on the same device | On Android and desktop, nothing about the transport if the node is in-process (no loopback listener). | n/a |

Mitigations available in the design: relay-only mode (disable direct addresses and punching: `OverlayConfig.punch = false`, empty
`direct`), VPN/Tor around the whole app, `transferd-only` (no Supabase metadata), private node ids. Not mitigated: pseudonymous
traffic graph visible to the relay; no constant-rate padding; identity keys sent in clear in the handshake.

---

## 10. Licensing compatibility

| Item | License | Consequence |
|---|---|---|
| PEVV | GPL-3.0-only (`package.json`, `LICENSE`) | The combined work is GPL-3.0-only. |
| TransferDaemon | The `LICENSE` file is **MIT** only (copyright "TransferDaemon Contributors"). The README and badge say "MIT OR Apache-2.0" and ask contributors to license under both, but no `LICENSE-APACHE` file exists. | MIT is compatible with GPL-3.0 (permissive code may be included in a GPL-3.0 work). Even if Apache-2.0 applied, it is compatible with GPL-3.0 (not with GPL-2.0-only). **Treat TransferDaemon as MIT**, and ask upstream to add the Apache text or correct the README. |
| Transferd (spec) | MIT | Documentation and specification; no combination issue. |
| Dependencies of `transferd-overlay` | Need an inventory (`cargo deny check licenses`, `cargo about`). Direct crates seen: `ml-kem`, `ml-dsa` (a release candidate), `ed25519-dalek` (BSD-3-Clause), `x25519-dalek`, `aes-gcm`, `blake3`, `tokio`, `tokio-tungstenite`, `bincode`, `rsa`, `socket2`. | Expected to be MIT, Apache-2.0 or BSD. Verify, do not assume; add `deny.toml` to CI. `arti-client` (optional Tor feature) must stay off. |

Obligations:

- Keep the MIT copyright and permission notice for TransferDaemon and for each dependency in a `THIRD_PARTY_NOTICES` file shipped inside
  the desktop installers and in the Android "About" screen.
- If a TransferDaemon crate is copied (vendored) rather than depended on, keep its file headers and license text. If modified, the
  modifications are distributed under GPL-3.0 inside PEVV; upstream remains MIT, and changes proposed upstream stay MIT. Check that both
  repositories are owned by the same copyright holder before any relicensing statement; the contributors file does not say.
- GPL-3.0 and app stores: Google Play and F-Droid are fine with GPL source offered (PEVV already ships an Android app). Apple's App Store
  terms conflict with GPL-3.0; irrelevant today (no iOS client) but it would be a blocker for a future one.
- Strong cryptography in distributed software has export-classification paperwork in some jurisdictions; PEVV already ships AES and
  Argon2id, and the post-quantum primitives do not change the category, but confirm for store listings.
- `SECURITY.md` and the README should say the transport is third-party reference code with its own history and no external audit.

---

## 11. Phased implementation plan

Sizes: S under a week, M one to three weeks, L more, for one engineer; they are guesses.

### Phase 0: de-risk and upstream (S to M)

- Build `transferd-overlay` and `transferd-crypto` for Windows, Linux and `aarch64-linux-android` in a scratch crate; record the
  stripped `.so` size and the compile time. Decide the size budget.
- Run `cargo deny`, `cargo audit`, `cargo tree -d` on the dependency set; review the 5 `unsafe` sites in the crates PEVV uses.
- Open the upstream issues in Appendix B (U1 in-process service handler, U2 unpair, U3 pair by fingerprint, U4 pin suite and version,
  U5 path MTU, U6 licence file, U7 spec repo).
- Decide the dependency form (pinned git revision, or vendored subset with notices).
- Owner decisions: questions 1 to 5 below.
- **Exit:** a written go or no-go with the measured size, and the upstream issue list accepted or a fork plan.

#### Phase 0 results (2026-11-22, measured)

Built from the new crate `transport/pevv-transport` (feature `ffi`, which pulls `transferd-overlay`, `transferd-core`, `transferd-crypto`,
`relayd`, `transferd-dns` and UniFFI), pinned to TransferDaemon `main` at
`270f79b67c8e30b7a3d53eaf71e3421e936462bf`. Release profile: `opt-level = "z"`, fat LTO, one codegen unit, `panic = "abort"`, stripped.

| Target | Artefact | Size | Notes |
|---|---|---|---|
| `aarch64-linux-android` (cargo-ndk 4.1.2, NDK 27.2.12479018, API 21 minimum) | `libpevv_transport.so` (cdylib) | **2,153,096 bytes (2.05 MiB)** stripped; 955,148 bytes with `gzip -9` (an upper bound for the APK delta) | Native Android ABI figure, measured. LOAD segments aligned to 16 KB (`-Wl,-z,max-page-size=16384` is needed with NDK r27). Release build took about 60 s from a warm registry cache. |
| `x86_64-pc-windows-msvc` (host) | `pevv_transport.dll` | 2,064,896 bytes (1.97 MiB) | Same code, for comparison only. |

Against the section 7.2 budget of 6 MB per ABI this leaves a wide margin. UniFFI's JNA runtime (Kotlin side, about 1 to 2 MB, estimate) is not
in these numbers. Only arm64-v8a was built; the other ABIs were not measured. Other phase 0 items **not done**: `cargo deny`, `cargo audit`, the
review of the `unsafe` sites, the upstream issue list (U1 to U10 are still to be opened), and the owner decisions.

Findings from reading the pinned revision while wrapping it (new, and not in Appendix A):

- The overlay's `OverlayConfig::relays` accepts UDP `ip:port` only. A `wss://` relay cannot be configured at this revision (the doc comment
  says a WebSocket relay is also registered, the code does not do it). `pevv-transport` rejects `wss://` entries with a clear error. Section 7.2's advice to
  prefer `wss://` on mobile therefore depends on an upstream change (**U11**).
- An inviter has no way to read the joiner's key (not in the public API and not in the state file for an inbound pairing), so the pairing words bind the
  inviter's key fingerprint, the joiner's node id and the nonce, **not** the joiner's post-quantum key (**U12**).
- Exposed services are restored from the state file with their old loopback ports; `pevv-transport` removes every `pevv-sync-1*` service at start-up.

### Phase 1: `pevv-transport` crate and local multi-node harness (M)

Files:

- `crates/pevv-transport/Cargo.toml`, `src/lib.rs` (public API: `Transport::start(config)`, `invite_create`, `invite_accept`,
  `pair_trusted`, `set_allow`, `open_control`, events), `src/identity.rs`, `src/seal.rs` (trait plus `dpapi.rs`, `secretservice.rs`,
  `file.rs`; Android Keystore bridge is a callback trait implemented in Kotlin), `src/node.rs` (wraps `OverlayNode`), `src/policy.rs`
  (allow-list, rate limits, pure and unit-tested), `src/psp.rs` (codec), `src/error.rs`.
- `crates/pevv-testnet/` (dev-only): spawns `relayd` in-process (the `relayd` library), N `OverlayNode`s on loopback with temp
  directories, a shaper for loss and latency and a NAT emulator (copy `tests/common/{nat,shaper}.rs` from the TransferDaemon overlay
  crate with the MIT notice), and a scripted scenario runner. A `docker-compose.yml` runs the **real** `relayd`/`relayd-ws` images for a
  nightly job.
- **Tests:** unit tests for policy, seal and codec; testnet scenarios: two nodes pair by invite; SAS mismatch refuses; a used invite
  is refused; relay only; direct only; relay then punch; 20% loss; relay restart; node restart; key change refused (TOFU); fingerprint
  mismatch refused; 5 nodes full mesh; revoke closes a session; clock skew.
- **Exit:** the scenarios pass in CI on Linux and Windows without Tauri or Android.

#### Phase 1 status (2026-11-22)

Built in `transport/pevv-transport` (stand-alone Cargo workspace, nothing else in the repository depends on it): PSP/1 codec and engine
(`psp.rs`, `policy.rs`, `engine.rs`, `store.rs`), `seal.rs` (DPAPI on Windows, owner-only file elsewhere, Keystore callback for Android),
`sas.rs`, `config.rs` and, behind the cargo feature `overlay` (off by default), `transport.rs` and `bridge.rs`. The run-time switch
`TransportConfig.enabled` is `false` by default and `relays` is empty by default (no default relay). The UniFFI interface is
`src/pevv_transport.udl` (feature `ffi`; Kotlin generation verified, not wired into the app). Tests: unit tests, six engine tests over an in-memory pipe, and
an in-process two-node loopback test over the real overlay (pairing with matching six words, approval gate, blob sync, CAS conflict answered `stale`,
fork converging with both copies kept, revocation).

Deviations from the design, and what is not done:

- PSP runs one short-lived bidirectional stream per exchange (HELLO, ANNOUNCE, FETCH/BLOB or PUSH/PUSH_ACK, BYE), not the long-lived control stream
  per direction of section 6.2. Wire frames and rules are as specified; the stream layout can change without touching the codec.
- Inbound streams reach the engine through one loopback listener and one overlay service per allowed peer (`pevv-sync-1-<16 hex of the dialler>`, ACL = that
  node id). This is the interim of section 3 and is **not acceptable on Android** until U1 exists. In-process outbound streams need no socket.
- Not built: `pevv-testnet` (NAT emulator, shaper, loss scenarios, relay restart, 5-node mesh, clock skew), Secret Service sealing, TPM wrapping, the
  `golden.rs` vectors (phase 2), fuzzing, a `wss://` relay.
- Upstream gaps handled by wrapping, still to ask for: **U1** (in-process handler with peer id: loopback bridge above), **U2** (unpair: the node is only
  removed from the PEVV allow-list and its service and session are dropped; it stays in the overlay's paired set), **U3** (`pair_trusted` from the roster:
  not wrapped, roster migration is phase 4), **U4** (suite and version pinning: not wrapped), **U5** (UDP relay MTU: untouched), **U11** (`wss://` relays),
  **U12** (accessor for a peer's key, so the pairing words can bind the joiner's post-quantum key), **U13** (cancel an invite nonce).

### Phase 2: PSP/1 and golden vectors (M)

Files:

- `src/pevv/syncproto.ts` (pure: encode, decode, CAS decision `decide(local, announce)`, fork detection), `src/pevv/host/transport.ts`
  (the `SyncTransport` interface and selector), `src/pevv/host/transport-supabase.ts` (wraps the existing `cloud.ts` and `relay.ts`
  with **no behaviour change**), `src/pevv/host/transport-transferd.ts`.
- `tests/golden/psp/*.json` (frames in hex, expected decisions, malformed cases), `scripts/psp-vectors.mjs` (writes them from the
  TypeScript code, in the style of `scripts/android-vectors.mjs`), `crates/pevv-transport/tests/golden.rs`, and later
  `android/app/src/test/.../PspCodecTest.kt`.
- **Tests:** `tests/unit/pevv.syncproto.test.ts` (codec round-trips, unknown types skipped, oversize rejected, hash mismatch, CAS
  table: ahead, behind, equal and same, equal and different, other vault id, revoked vault); property tests on random message
  sequences against the decision function; the existing Vitest suite unchanged and green.
- **Cross-client golden tests:** the same vector file is consumed by Vitest (TypeScript), `cargo test` (Rust) and JUnit (Kotlin); a CI
  job fails if any consumer disagrees or if the vector file changed without regeneration.
- **Exit:** vectors pass in TypeScript and Rust; the Supabase wrapper passes the existing `pevv.host.test.ts`.

### Phase 3: Desktop integration behind a flag (M)

Files: `desktop/src-tauri/src/transport.rs`, `transport_core.rs`, `transport_seal.rs`, `capabilities/default.json` (new commands),
`src/pevv/desktop/transport.ts` (webview glue), Settings UI in `src/pevv/ui/` (Devices, Relays, Diagnostics), `docs/CLIENT_DESKTOP.md`,
`docs/SYNC_SELF_HOSTING.md` (relay section), Cargo feature `transport` (off by default).

- **Tests:** `transport_core` unit tests with a fake `Ui` (the pattern of `link_core.rs`); Vitest for the selector and fallback;
  two desktop processes against the testnet relay in a Playwright/WebDriver script (pair, edit on A, appears on B, revoke B, B refused);
  an extension-free end-to-end run; a build with and without the feature, both passing the whole existing suite.
- **Exit:** Windows and Linux desktop to desktop sync works with no Supabase configured; with Supabase configured and the relay
  killed the app falls back within 10 s.

#### Desktop integration status (2026-11-23)

The `pevv-transport` crate is wired into the desktop app. Checked with unit tests, a clean release build and the crate's own loopback test only; no GUI was started and no two-process run was made.

- **Build.** `desktop/src-tauri` depends on `../../transport/pevv-transport` by path with its `overlay` feature behind the cargo feature `transferd`. It is **on by default**, because the release build (`cargo build --release`, LTO, `panic = "abort"`) is clean with it, clippy `-D warnings` passes and the whole test suite passes with and without it (`cargo test --no-default-features` leaves it out; CI runs both). The release `pevv-desktop.exe` grew from about 4.3 MB to about 5.6 MB. Building needs the pinned TransferDaemon git revision in the cargo cache (or network once).
- **Run time.** Off by default (`transferd.json` in `<app data>/transferd/`, `enabled: false`; nothing is created or opened until the person switches it on). No relay unless the person adds one (UDP `host:port`, at most 4; `wss://` is refused, see U11). No inbound port. The seed is sealed by the crate (DPAPI on Windows, an owner-only file elsewhere) in `<app data>/transferd/`; the folder follows `PEVV_DATA_DIR`, and `%APPDATA%\PEVV` is never used by tests or by this code when the override is set.
- **Commands** (`transport_status`, `_enable`, `_set_addresses`, `_invite_create`, `_invite_cancel`, `_join`, `_pair_confirm`, `_peer_approve`, `_peer_revoke`, `_sync_now`, `_take_staged`), each with its own `allow-*` permission, granted to the `main` window only in `capabilities/transport.json`. They return public node ids, names, the pairing words and status; never the seed, a key or plaintext. Without the feature they exist and answer `available: false` / `not-in-this-build`.
- **Sync.** A Transferd peer is one more lane next to Supabase. The shell's store reads the vault file for `head` and `current`, and **never writes it**: a file from a peer (PUSH or FETCH reply, or the loser side of a fork) is held in memory and announced to the window with a payload-less `transport-event`; the window takes it with `transport_take_staged` and runs `reconcileRemote(file, 'peer')`, i.e. the existing three-way merge, the revoked-writer and key-epoch checks, and the "a locked device stages and verifies at unlock" rule (docs/SYNC.md). No merge logic was copied to Rust. The network compare-and-swap on `rev` (PUSH `base`) and the size/format/vault-id checks run in Rust before a file is even held. The window pushes after local writes (debounced 400 ms) and every 30 s. Supabase is not touched: when no peer is reachable the cloud copy carries on by itself, and the panel says which lane is carrying the vault (`chooseLane`).
- **Revoke** removes the peer from the allow-list, closes its session and service, sends ROSTER_HINT to the others, and then the window runs the existing `rotateKey` (new vault key, password required, new recovery codes shown once); the rotation is skipped if the revoke itself failed.
- **UI.** Settings, "Direct device link (Transferd)", English and Spanish (`tfd*` keys, parity tested): on/off, this device's id and eight check words, how the seed is protected, relays and direct addresses, "Add a device" (QR plus text invite, one outstanding, cancel), "Join a device", the six pairing words with approve or decline, the linked devices with reachability and "Remove".
- **Not done / gaps.** (1) A device with **no vault yet** cannot receive one this way: PSP refuses a different vault id at HELLO, so first-copy transfer to an empty device (design section 5.1 steps 4 and 5) is phase 4; for now the new device must already hold the vault (file, QR or cloud). (2) The peer list is device-local: peers are not yet bound to roster entries (`node` field, migration by roster, phase 4), so a revoke by node id does not also remove a roster device entry, and a peer's decision is not shared through the vault. (3) The extension is unchanged (it still goes through the native host; no ops for sync, phase 6). (4) No two-process end-to-end run, no relay run and no Linux build were done; the crate's loopback test is the only real overlay run. (5) A panic in the overlay aborts the app (`panic = "abort"`); no `catch_unwind` boundary yet. (6) The shell parses only `format`, `id` and `rev` of the vault file envelope. (7) The upstream gaps U1, U2, U3, U4, U5, U11, U12 and U13 stay as listed under phase 1.

### Phase 4: pairing UX, roster binding, migration, revocation (L)

Files: `src/pevv/model.ts` (optional `VaultDevice.node`), `src/pevv/devices.ts` (`mergeDevices` keeps `node`; allow-list derivation),
`src/pevv/pairing.ts` (invite parse, SAS words, state machine), `src/pevv/qr.ts` (`parseScan` accepts `T.<invite>`, ignored by older
clients), `src/pevv/store.ts` (`revokeDevice` also calls the transport), UI dialogs, `docs/VAULT_FORMAT.md` (document `node`),
`docs/CRYPTO.md` and `docs/DESIGN.md` (threat model section).

- **Tests:** `tests/unit/pevv.devices.test.ts` extended (merge keeps `node`; legacy entries; allow-list excludes revoked);
  `tests/unit/pevv.pairing.test.ts` (SAS equality, wrong SAS, expired and reused invite, third device racing the nonce);
  testnet scenarios for migration (A and B legacy, A upgrades, B upgrades, bindings exchanged over a fake Supabase, no QR) and for
  revoke propagation while one peer is offline; a golden vector for the roster with `node`; a regression test that an old client
  (fixture file) opens a vault whose meta contains `node`.
- **Exit:** the owner's own devices run migrated for two weeks (stage 1 below) without a manual re-pair.

### Phase 5: Android (L)

Files: `crates/pevv-transport-ffi/` (UniFFI definitions, `uniffi.toml`), `android/app/build.gradle.kts` (cargo-ndk task, ABI
filters, `pevv.transport` property), `android/app/src/main/java/dev/pevv/app/sync/TransferdTransport.kt`, `PspCodec.kt`,
`security/SeedSeal.kt` (Keystore, reusing `DeviceSeal`), `sync/SyncManager.kt` (select transport), `AndroidManifest.xml`, Settings
screens; `docs/CLIENT_ANDROID.md`, `docs/ANDROID.md`.

- **Tests:** JVM unit tests for `PspCodec` against the golden vectors; instrumented test on an emulator pairing with a desktop
  testnet node through the relay; a 16 KB page-size alignment check in CI (`zipalign -P 16`); APK size gate (fails above the budget
  from phase 0); a hand-test checklist on at least one real phone (the Android client has not run on a real device yet, per
  `CLIENT_ANDROID.md`, so this phase cannot finish before that does).
- **Exit:** phone and desktop sync over relay, over LAN, and after airplane-mode toggles.

### Phase 6: extension through the desktop link (S to M)

Files: `desktop/src-tauri/src/link_core.rs` and `link_proto.rs` (new ops `sync-state`, `sync-get`, `sync-put`, allowed while locked, rate
limited, ciphertext only), `src/pevv/extension/bridge.ts`, `src/pevv/extension/` worker, `docs/CLIENT_EXTENSION.md`.

- **Tests:** extend `tests/unit/pevv.link.test.ts` and `pevv.extension.test.ts`; Rust unit tests in `link_core` for lock state, frame size and
  counter replay; Playwright extension suite with the desktop stub.

### Phase 7: hardening, review, default flip (M)

- Fuzz the PSP codec (`cargo-fuzz`, TypeScript property tests); fuzz the invite parser; run TransferDaemon's `fuzz/` targets for the
  handshake and relay protocol against the pinned revision; a threat-model review against this document; an **external review** of the
  integration and of the parts of TransferDaemon PEVV depends on (question 4); relay operations guide in
  `docs/SYNC_SELF_HOSTING.md`; soak test on three real devices for a week.
- **Exit:** the review's high findings closed; stage 3 below allowed.

### Phase 8: optional follow-ups

Entry-level merge (`ENTRIES_*`), re-key on revoke, Supabase CAS migration `0002`, a WebSocket bridge for the hosted web app, Diagnostics
export.

### Rollout and feature flags

| Stage | Flags | Behaviour | Gate to the next stage |
|---|---|---|---|
| 0 Dark | cargo feature `transport` off, `VITE_PEVV_TRANSPORT=legacy` | Code present, not compiled in or not reachable. CI runs both configurations. | Phases 1 and 2 green. |
| 1 Dogfood | `VITE_PEVV_TRANSPORT=auto`, `prefs.transport = 'off'` by default, hidden "Developer" toggle | Only the owner's devices; Transferd and legacy lanes both run, results compared and logged locally. | Two weeks with zero manual re-pairs and no divergence. |
| 2 Opt-in beta | `prefs.transport` visible as "Direct device sync (beta)" | Opt-in per vault; Supabase still carries everything as the safety net. | No data-loss or lock-out reports; the review of phase 7 done. |
| 3 Default for new pairings | `prefs.transport = 'auto'` for new vaults | New devices use Transferd first; legacy QR still selectable ("Pair with QR (legacy)"). Existing users keep their setting. | A release cycle with no high-severity bugs. |
| 4 Backup-only mailbox | optional `transferd-only` | Users who want no cloud copy. Supabase stays available as backup/mailbox. | n/a |

Nothing in this plan removes a feature. The legacy QR, the Realtime roster and the Supabase sync stay selectable at every stage and
remain the **automatic fallback**: if the transport fails to start (missing library, unsupported ABI, seed unwrap error), cannot reach
any peer within 10 seconds, or a peer speaks no PSP, the existing path is used and the UI says which transport carried the last sync.
`transferd-only` is the only mode that does not fall back, and it is explicit.

---

## 12. Open questions for the owner

1. **Go or no-go on depending on TransferDaemon at all,** given Appendix A? Alternative: a much smaller PEVV-specific transport (Noise
   over WebSocket relay) with the post-quantum layer added later. It would cost less to audit and port, but it is new crypto-plumbing
   to own. Which risk do you prefer?
2. **Dependency form:** pinned git revision of TransferDaemon, a vendored subset, or a PEVV-owned fork? Can the PEVV and TransferDaemon
   repositories accept shared upstream changes (U1 to U7), and who reviews them?
3. **Licensing statement:** is MIT the intended licence (the README says MIT or Apache-2.0, the file says MIT)? Is the copyright holder
   the same person for both repositories?
4. **External review:** may we budget an independent review of the integration and of the overlay, handshake and relay code before the
   default flips? Without one, the honest security claim is "a self-reviewed reference implementation".
5. **Relays:** who hosts them? Ship no default relay (recommended), or run one PEVV-branded relay? Is a single operator acceptable
   given section 8.3?
6. **Conflicts:** accept T3 (surface forks, keep both) now, or invest in entry-level merge before this ships? Entry merge is the only
   way to stop losing offline edits.
7. **Revoke and re-key:** do you want a real cryptographic revoke (new vault key, re-seal everything)? Without it, a stolen device
   keeps whatever it has.
8. **Strict mode:** is `transferd-only` (no cloud copy at all) a feature you want to offer, and should it be the default for new
   vaults once stable?
9. **Android background sync:** foreground-only (simple, matches today) or a foreground service with a persistent notification
   (battery, Play policy)?
10. **Direct addresses:** are you comfortable with paired devices learning each other's LAN and public IPs (needed for direct routes
    and punching), or should the default be relay-only?
11. **Identity recovery:** if a device's transport seed is lost, we re-pair. Is that acceptable, or should the seed be recoverable
    from the vault (it would then no longer be per-device)?
12. **iOS and macOS:** any plan that should shape the key-sealing trait now?
13. **Hosted web app:** is "Supabase and QR only" acceptable permanently, or is a WebSocket bridge (a weaker mode) worth building?
14. **Naming and repo layout:** a `crates/` workspace at the PEVV root (as proposed), or inside `desktop/src-tauri/`? The Android build
    needs the crate outside the Tauri folder.

---

## Appendix A. TransferDaemon readiness review

Method: documentation, `Cargo.toml` files, and source of `transferd-overlay`, `transferd-crypto`, `relayd`, `transferd-core` (relay
client), `transferd-mobile`, deploy files and the Android folder were read. Nothing was built or run, so test counts and benchmark
numbers below are quoted claims, not verified results.

### A.1 What looks solid

- The overlay (`transferd-overlay`, about 12,000 lines) is substantial, coherent and documented in detail: handshake, tunnel framing
  with counters and replay window, multiplexed streams with flow control, per-route congestion control, SACK, hole punching, invites
  with single-use nonces and key-fingerprint binding, an audit log and a state file with versioning and migration.
- Tests exist at the right level for PEVV's needs: loopback relay, lossy relay (20% drop), NAT emulation, congestion shaping, a
  current peer against an older one, and `cargo-fuzz` targets for the handshake and relay protocol.
- Design choices PEVV benefits from: outbound-only connections, explicit ACLs per service, "paired only through an invite", refusal
  of a changed key for a known node id, zeroizing key material, workspace lints that deny `unwrap` and `panic`.
- The relay is small, has no key material, and enforces per-source rate limits, proof of work, TTL and per-token bandwidth budgets.

### A.2 Claims the code does not back up

| Claim (README or project docs) | What the code shows |
|---|---|
| "Private keys are sealed inside hardware security modules (TPM / Secure Enclave) where available"; "hardware-bound keys". | `transferd-crypto/src/keystore.rs`: `create_key_store()` returns a **RAM-only** store; `TpmKeyStore` and `SecureEnclaveKeyStore` are named in a doc comment and feature flags (`tpm-backend`, `secure-enclave-backend`) that gate nothing. The project's own `TODO.md` lists hardware-bound keys as planned for v1.1.0, and `CONTEXT.md` section 7 says "(future)". The overlay seed is a file protected by DPAPI on Windows and an owner-only file elsewhere. |
| "Relays never know who is communicating", "zero metadata leakage". | Each relayed datagram carries the destination token (relay field) and the sender token inside the unencrypted prefix; handshake flights carry full public identity keys in clear. Tokens are public functions of node ids. The relay can see the pairing graph by pseudonym. |
| "Metadata protection ... optional constant-rate padding"; "timing is jittered at the relay". | Only power-of-two padding was found (`pad()` in the overlay relay). No constant-rate padding or relay jitter was found in the overlay or relay path read. |
| "AES-256-GCM with rotating keys", "keys rotated every epoch". | The overlay tunnel derives two directional keys per link and uses a 64-bit counter; no in-session rekey is specified in its wire protocol. There are `epochs.rs` and `ratchet.rs` in `transferd-crypto`, not used by the overlay path read. |
| "Optional pure Kyber-1024 mode", crypto-agility with several suites. | `CIPHERSUITES` has **one** entry (`0x0002`). Agility is a mechanism with a sunset date and has never been exercised with two suites. |
| "Wi-Fi Direct / Bluetooth LE local transfers"; "swarm" lane. | The project's own metrics call Wi-Fi "simulated", BLE and swarm "stub". |
| "Tor transport", "off-grid mesh over mDNS and Bluetooth". | `arti-client` is an optional feature; Tor is listed under planned work. Bluetooth is a stub. |
| "Pentest: 22 scenarios, 0 critical", "Battle-tested". | `transferd-pentest` is a local tool written by the project, not an independent assessment. It is useful regression testing, not an audit. |
| "More secure than an air-gapped system", "First ...". | Marketing; disregard. |
| Version and spec consistency. | README says v1.0.0 and protocol v3; `CHANGELOG.md` says 2.4.0; the handshake is "protocol version 2" and frames are versions 1 to 3. Easy to confuse in an audit. |

### A.3 Gaps and risks that matter to PEVV

1. **The protocol repository is a placeholder.** In the Transferd repository `docs/PROTOCOL.md` is a single line ("See the full
   specification at the end of this process..."), `docs/OVERLAY.md` ends with the same sentence, and `docs/IMPLEMENTATION.md` says the
   documents there are the source of truth. The real, complete wire spec is `docs/PROTOCOL.md` inside the TransferDaemon repository.
   There is **no second implementation**, so no interoperability evidence, and "the spec" and "the code" are the same artefact.
2. **No external audit.** Hybrid designs are sensible, but the authenticated handshake, the replay window and the relay protocol are
   bespoke. `ml-dsa` is a release candidate crate (`0.1.0-rc.11`) and all crates are `0.1.0`, unpublished, referenced by path.
3. **No message-style API; service forwards only.** The overlay forwards TCP services. The handler does not receive the peer id, and
   `connect` publishes a loopback listener usable by any local process. PEVV needs an in-process stream API with peer identity (U1).
4. **No unpair or revoke operation.** The overlay stores paired nodes in `state.json` and has no `unpair` (U2). The `*paired` ACL means
   "presented a valid invite nonce", which is not what PEVV wants.
5. **UDP relay path and MTU.** Relay payloads are padded to a power-of-two grid up to 16 KiB per datagram and the handshake flights
   are 8.5 KB, all in UDP datagrams with no path-MTU discovery or fragmentation handling that I could find. On the real Internet,
   and especially mobile networks and IPv6, fragmented UDP is often dropped. Tests are on loopback and emulators. Prefer the WebSocket relay;
   verify on cellular before trusting UDP.
6. **Proof of work on every datagram.** `send_forward` fetches a challenge and solves proof of work per forward (difficulty 20 by
   default). The published throughput (about 96 MB/s relayed) comes from an in-process relay, not a real relay with PoW, and nothing
   measures phone CPU or battery.
7. **Hole punching** works only through cone NATs, once, at session start; symmetric NATs and UDP-blocking networks stay on the relay
   (the documentation says so honestly).
8. **Clock dependence:** suite sunset dates and invite expiry use the device clock.
9. **Android is a whole app.** `transferd-mobile` is an egui NativeActivity application with its own UI, daemon thread and gRPC
   bridge. The checked-in `.so` files are 13.8 to 20.5 MB. Not a reusable library. Camera and microphone are listed as v1.1.0.
10. **Weight and coupling.** `transferd-overlay` depends on `transferd-core`, which pulls `ring-channel` (a hugepage DMI ring for
    100 Gbit/s Thunderbolt transfers), `relayd`, `transferd-dns` and `tokio-tungstenite`. PEVV needs none of that. A slimmer feature set
    is needed (U8).
11. **Process and housekeeping:** the working tree contains build logs, a compiled `TransferDaemon.exe`, a `.keystore` file and
    Android build outputs at the repository root. Confirm none of it is committed (secrets and a signing keystore in particular).
12. **Documentation conflicts:** `CONTEXT.md` documents the "authenticated handshake" and "trust on first use" in the messaging
    stack; the overlay re-implements pairing separately. Two identity-pinning code paths exist; PEVV would use only the overlay's.

### A.4 Verdict

TransferDaemon's overlay is good enough to **build on, behind a flag, with a hardening phase**, and not yet good enough to be the
sole transport of a password manager. The honest security statement today is: the post-quantum, mutually authenticated channel is a
real design implemented in a substantial and well-tested codebase, but unreviewed by anyone outside the project, with several README
claims (hardware-bound keys, relay blindness to who talks to whom, constant-rate padding, key rotation, multiple suites) that must not
be repeated in PEVV's documentation. PEVV's own vault encryption remains the primary protection, which is exactly why this design
treats Transferd as defence in depth and keeps the fallback.

## Appendix B. Changes to ask of TransferDaemon (upstream)

| # | Change | Why | Priority |
|---|---|---|---|
| U1 | An in-process service API: register a handler `fn(peer: &NodeId, stream)` for a service, with the authenticated peer id, instead of a loopback forward. | Peer identity at the application, no loopback socket (required on Android). `SessionHandle` already has `open/send/recv/close` for the client side. | Critical |
| U2 | `unpair(node_id)` and "drop session and refuse to re-establish". | Revocation (section 4.5). | Critical |
| U3 | `pair_trusted(node_id, key_fingerprint, reach)` without an invite. | Migration from the roster (section 5.3). | High |
| U4 | Config to pin accepted ciphersuites and a minimum frame version. | Downgrade defence (9.6). | High |
| U5 | Cap relay datagrams near 1,200 bytes (or add fragmentation) for the UDP relay; keep large datagrams only on WS. | Real-network reliability (A.3 item 5). | High |
| U6 | Add `LICENSE-APACHE` or correct the README; list third-party notices. | Section 10. | Medium |
| U7 | Put the real protocol spec in the Transferd repository, remove placeholders, add test vectors (handshake transcript, tunnel frame, invite). | Second implementations and audits. | High |
| U8 | Feature-gate `ring-channel`, DNS, Tor and messaging dependencies out of the overlay build; tag releases with semver. | Size and attack surface. | Medium |
| U9 | Reconsider per-datagram PoW (cache a solved challenge per token and interval) and measure on a phone. | Battery and throughput. | Medium |
| U10 | Remove or qualify the README claims in A.2. | PEVV must not echo them. | Medium |
| U11 | Accept `wss://` relays in `OverlayConfig::relays` (and resolve host names). | Mobile networks that drop UDP (section 7.2). | High |
| U12 | `OverlayNode::peer_key_fingerprint(node_id)`, available to an inviter after first contact. | Pairing words that bind the joiner's post-quantum key (section 5.1). | Medium |
| U13 | Cancel an issued invite nonce. | One outstanding invite, cancelled when the dialog closes (section 5.2). | Medium |
