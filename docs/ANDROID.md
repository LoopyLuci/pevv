# Android app: design

The Android app is a **native** Kotlin app (Jetpack Compose, Material 3) in [`android/`](../android). It is not a WebView. It reads
and writes the same `luciverse.pevv` vault file as the web app, the extension and the desktop app, byte for byte, and it syncs
through the same Supabase table and relay topics. How to build and run it: [CLIENT_ANDROID.md](CLIENT_ANDROID.md).

## Goals and limits

- One vault format everywhere ([VAULT_FORMAT.md](VAULT_FORMAT.md), [CRYPTO.md](CRYPTO.md)). Android is a client, not a fork.
- Keep every secret on the device. The cloud holds only the sealed vault (no size limit on a user's own vault; `supabase/migrations/0003_pevv_no_size_cap.sql`).
- Fail closed: if a check cannot be made (origin, asset links, key store), nothing is filled or signed.
- No Google Play Services, no analytics, no crash reporter. Network access is limited to the sync URL the build was given.
- minSdk 26 (Android 8.0). It is the first release with the autofill framework and `java.util.Base64`, which keeps the crypto
  code free of desugaring. targetSdk and compileSdk 36. Biometric unlock needs 9 (API 28); passkeys need 14 (API 34). Below that
  the matching screens say so instead of hiding.

## Layout

```
android/app/src/main/java/dev/pevv/app/
  core/      vault format and crypto (pure Kotlin, no Android classes, unit-testable on the JVM)
  store/     VaultController (state, atomic persistence, locking), AppPrefs
  security/  clipboard, Keystore seal for sync tokens, biometric key wrapping
  sync/      Supabase (auth, REST), Realtime socket, relay transfers and roster, SyncManager
  autofill/  AutofillService, auth and save activities, origin matching, Digital Asset Links
  passkey/   Credential Manager provider and its activity, WebAuthn PRF unlock
  ui/        Compose screens (onboarding, unlock, list, detail/edit, generator, settings, devices, recovery, import, QR)
```

### `core/` (the compatibility surface)

A line-by-line port of the TypeScript in `src/pevv/`, with these rules:

- **Everything is a JSON tree.** The vault file, entries and meta are `JsonObject`s. Edits change known fields and keep key order
  and unknown fields, so a newer client's data is never dropped by Android.
- **Crypto:** Argon2id from Bouncy Castle (`Argon2BytesGenerator`, version 0x13, 32-byte output; parameters read from the file and
  checked against the same floors as the TypeScript: m at least 19456 KiB, t at least 2, p 1 to 4; PBKDF2 at least 600000),
  AES-256-GCM from the platform provider, HKDF-SHA256 written out with HMAC. Passwords are NFC-normalised.
- **AADs and labels** are the `luciverse/pevv/v1/*` strings from the TypeScript, in one `Aad` object and one list of HKDF `info`
  labels. A wrong byte there makes a vault unreadable on the other clients, which is why the golden tests exist.
- **Slots:** password, recovery code, recovery key (kit), passkey (PRF), USB key file, plus the TOTP gate and the plaintext
  `require` hint. `commit` bumps `rev`, reseals meta and keeps the hint in step.
- **Reconcile** is last-writer-wins on `rev`, only for the same vault id, with the device roster merged as a union in which a
  revoked device stays revoked.
- **Transfer:** offline QR frames (`PEVV1|i|n|crc8|chunk`, gzip, base64url, 520-character chunks, at most 12 frames), the encrypted
  handoff (`H.<key>.<transfer>`) and the relay chunking (8 parts of 48000 characters).

### Golden tests (both directions)

- `scripts/android-vectors.mjs` loads the real TypeScript modules and writes 17 JSON files of vectors into
  `android/app/src/test/resources/vectors/` (KDF, HKDF, AES, base32, TOTP, vaults sealed with Argon2id and with PBKDF2, recovery,
  transfer frames, roster merge, reconcile, passkey, imports, dotenv, generator). The keys are random each run.
- Kotlin tests (`GoldenVectorTest`) decrypt and verify all of them. CI regenerates them on every run.
- `KotlinFixtureTest` writes `vectors/kotlin-made.json` (run with `PEVV_WRITE_FIXTURES=1`): a vault made by Kotlin, a recovery
  kit, a USB key, an export, QR frames, a handoff, a passkey signature and a TOTP code. `tests/unit/pevv.android.test.ts` opens
  that fixture with the TypeScript code. The fixture is committed, so `npm test` needs no Android toolchain.

## State and storage

`VaultController` is the single owner of the vault. States: none, locked, second factor, set new password (after a recovery
unlock), unlocked. The vault file is `filesDir/pevv/vault.json`, written to a temporary file and renamed. Decrypted items live
only in memory while unlocked and are dropped on lock. Locking happens on demand, after leaving the app (delay in Settings, 1 minute by default)
and after an idle time (5 minutes by default). Preferences hold no secrets; sync tokens are sealed with an AES key in the Android
Keystore (`DeviceSeal`).

Deviations from the web app, on purpose:

- There is no audit log on Android.
- Unlocking by recovery code or key forces a new master password before the vault opens.
- Turning sync off removes the cloud copy; erasing the local vault or revoking a device never deletes it.
- A user-confirmed app-to-login link for autofill is stored in the sealed meta as `androidAppLinks`. Other clients keep it
  because unknown meta fields survive their edits.

## Sync

- **Cloud copy:** table `pevv_blobs`, GoTrue email sign-in (code or magic link, deep link `dev.pevv.app://auth`), PostgREST upsert,
  and `reconcile` for conflicts as in `host/cloud.ts`. Realtime (`postgres_changes`) is used when the table is in the project's
  realtime publication; otherwise a 2-minute poll in the foreground. Configuration: `VITE_PEVV_SYNC_URL` and
  `VITE_PEVV_SYNC_ANON_KEY` as Gradle properties or environment variables, turned into `BuildConfig` fields. If either is unset,
  sync is off and the screens say so ([SYNC_SELF_HOSTING.md](SYNC_SELF_HOSTING.md)).
- **Realtime:** a Phoenix-protocol (vsn 1.0.0) client over OkHttp WebSocket, with heartbeats and re-joins.
- **Relay:** topics `pevv:<token>` (events `part`, `want`) for vault transfer and `pevv:d:<vaultId>` (events `rhave`, `rwant`,
  `rpart`) for the device roster and live exchange, including revocation. Anonymous relay sessions only.
- **QR transfer:** show and scan, offline frames or the live handoff, compatible with `qr.ts`. CameraX delivers frames and
  ZXing decodes them (ML Kit is not used, to avoid Play Services).

## Android security

| Area | Decision |
|---|---|
| Screen | `FLAG_SECURE` on every window that can show a secret (main, autofill, credential screens). |
| Clipboard | `EXTRA_IS_SENSITIVE` on the clip, auto-clear after the chosen time (default 30 s), cleared on lock. |
| Backup | `allowBackup=false`, `dataExtractionRules` exclude all domains from cloud backup and device transfer. |
| Network | `networkSecurityConfig` with cleartext off; HTTPS and WSS only. |
| Biometrics | Framework `BiometricPrompt` with a `CryptoObject`. Keystore AES-GCM key: user authentication required, strong biometrics only, invalidated by new enrolment, StrongBox when the device has it (falls back to the TEE). It wraps a copy of the vault key. The master password and recovery factors still open the vault if the key is gone. The second-factor gates still apply after a biometric unlock. |
| Locking | On leaving the app (after the chosen delay), on idle, and on demand. |
| Logs | No vault data, tokens or passwords are logged. |
| Release | R8 shrinking on; signing only from environment variables, no keystore in the repository. |

The framework `BiometricPrompt` is used instead of `androidx.biometric` to keep the dependency list short.

## Autofill

`PevvAutofillService` implements the framework `AutofillService`.

- **Locked:** one "Unlock PEVV" suggestion (menu and inline) and no vault data, not even whether anything matches.
- **Unlocked:** one suggestion per matching login showing title and user name only. Each dataset uses *dataset authentication*:
  the user name and password are not in the response. Tapping opens `AutofillAuthActivity`, which asks for the unlock if needed and
  only then returns the filled dataset. Inline presentations use `androidx.autofill` where the keyboard supports them.
- **Web pages (browsers that report `webDomain`):** the saved site must have **exactly** the reported host, the reported scheme
  (https when none) and the default port. Never a sub-domain, a parent, a sibling or a look-alike (`example.com.evil.test`).
  This is the same rule as the extension (AGENTS.md invariant 4) and has unit tests.
- **Native apps:** a login is offered only if the user linked it to the package (the picker, stored as `androidAppLinks`), or the
  site's `/.well-known/assetlinks.json` lists the package and its signing certificate for
  `delegate_permission/common.get_login_creds` (Digital Asset Links, cached 7 days when valid, 1 day when not). Only the host name of
  a site that is already in the vault is ever requested. With no match, a native app gets a "Choose a login" entry that links it.
- **Saving:** a `SaveInfo` makes the system offer to save a submitted login. The values go into an in-memory holder for at most five
  minutes, the user unlocks, confirms, and the login is added. On Android 8 the service cannot open a screen from the save callback,
  so the save is offered only when the vault is already unlocked.
- The app never fills itself.

## Passkeys (Android 14+)

`PevvCredentialProviderService` is a Credential Manager provider for passkeys and passwords.

- **Passkey items** are the same `type: "passkey"` items as the desktop provider: ES256 key pair, PKCS#8 private key and raw public
  key sealed inside the item, `credentialId`, `userHandle`, `rpId`, `signCount`. `authenticatorData` flags are UP, BE, BS (and AT on
  creation, UV when verified), AAGUID `661cf2bd-74e1-42fd-93d3-7e2ed09cf977`, attestation `none`, signatures in ASN.1 DER, COSE key
  as in the desktop code. The same golden tests cover signing and verification.
- **Flow:** the provider answers "begin" requests with names only (locked: one "Unlock PEVV" action). Choosing an entry opens
  `PevvCredentialActivity` (FLAG_SECURE), which unlocks the vault, asks for user verification (biometrics or screen lock) and only
  then signs or stores.
- **Who is asking:**
  - An ordinary app gets the origin `android:apk-key-hash:<certificate>` and must be allowed by the site through Digital Asset Links
    (`get_login_creds`), otherwise the request is refused.
  - A browser supplies the page origin and the client data hash. That is trusted **only if the browser is in an allow-list file**
    `assets/privileged_browsers.json` (the format Credential Manager documents). **No such file ships in this repository**, because
    the list is Google's and PEVV does not copy it offline, so browser passkey requests are refused with an explanation until the
    maintainer adds the list. This is an open decision (see below).
- **Passwords:** offered to an app only when that app is linked to a login. New passwords the app saves are added as logins, linked to it.
- **Unlock with a passkey (PRF):** `PasskeyAuth.assertPrf` asks Credential Manager for a `GetPublicKeyCredentialOption` with the
  `prf` extension and the stored `evalByCredential` salt, for the relying-party ID in the build (`PEVV_RP_ID`). It needs a credential provider that supports PRF (a recent Google Password Manager or a compatible
  third-party one) and the passkey must have been made for the same relying-party ID as the vault slot. If anything is missing, the
  unlock screen says so; password, recovery and key-file unlock keep working.

## Screens

Onboarding (create, import file or QR, sign in to find a cloud vault), unlock (password, biometrics, passkey, key file, recovery
code, recovery key, recovery kit), second factor, set a new password, item list with search, tags and favourites, item detail and
edit for every kind (login, note, card, identity, environment variable, API key, SSH key, passkey record), generator
(characters or passphrase, EFF short word list), settings, devices and revocation, recovery codes and kit, key files, authenticator
code gate, passkey records, sync, import (CSV, Proton, Bitwarden, PEVV export, `.env`), export, QR show and scan.

English and Spanish (`values/`, `values-es/`), chosen in Settings or by the system (per-app language on Android 13+).
Accessibility: content descriptions on icons and images, secrets masked with a show toggle, state never shown by colour
alone, system font scale and dark theme respected. (No TalkBack pass on a device has been done yet.)

The word list in `assets/eff_short_wordlist.txt` is the EFF short word list 1 (CC BY 3.0 US, Electronic Frontier Foundation).

## Build and release

Gradle (Kotlin DSL, version catalog, wrapper 8.11.1, AGP 8.7.3, Kotlin 2.0.21, Compose BOM-free pinned versions in
`gradle/libs.versions.toml`). `./gradlew test lint assembleDebug assembleRelease`. The release APK is unsigned unless
`PEVV_KEYSTORE_FILE`, `PEVV_KEYSTORE_PASSWORD`, `PEVV_KEY_ALIAS` and `PEVV_KEY_PASSWORD` are set. CI (`.github/workflows/ci.yml`,
job `android`) generates the vectors, runs unit tests and lint, and builds debug and unsigned release; the release workflow attaches
the unsigned APK. No setup-java action is used: the runner's JDK 17 and Android SDK are used directly, so there is no extra action to pin.

## Not tested on a real device

Unit tests run on the JVM. Autofill, the passkey provider, PRF unlock, biometrics with StrongBox, CameraX scanning and the Realtime
socket have been compiled and linted but **not exercised on hardware or against a live Supabase project** in this change.

## Open decisions

1. **Browser allow-list for passkeys** (above): add `privileged_browsers.json` or accept that web passkeys through Android are unavailable.
2. **Realtime publication:** `pevv_blobs` must be in the `supabase_realtime` publication for push updates; polling covers it otherwise.
3. **Asset links for apps:** a login for a native app is matched only through a link the user confirms or a site that publishes asset links.
4. **Relying-party ID:** passkey unlock needs the same `PEVV_RP_ID` as the web build that created the passkey slot.
