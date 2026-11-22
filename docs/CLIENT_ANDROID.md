# Android app

A native Kotlin app (Jetpack Compose, Material 3) in [`android/`](../android), package `dev.pevv.app`. It opens, edits and syncs the
same `luciverse.pevv` vaults as the web app, the extension and the desktop app. The design, the compatibility tests and the security
choices are in [ANDROID.md](ANDROID.md).

**Status:** builds, passes its unit tests and lint, and is checked against the TypeScript implementation with golden vectors in both
directions. It has **not been run on a real device yet**: autofill, the passkey provider, passkey (PRF) unlock, biometrics with
StrongBox and QR scanning need a hands-on pass. Releases are **unsigned**.

## What you need

- JDK 17 and the Android SDK with platform 36 and build tools (set `ANDROID_HOME`, or put `sdk.dir` in an untracked `local.properties`).
- Android 8.0 (API 26) or newer on the phone. Biometric unlock needs Android 9, the passkey provider needs Android 14.

## Build and test

```bash
node scripts/android-vectors.mjs        # from the repo root: golden vectors from the TypeScript code (needs `npm ci`)
cd android
./gradlew test lint assembleDebug       # unit tests, lint, debug APK  -> app/build/outputs/apk/debug/
./gradlew assembleRelease               # unsigned release APK         -> app/build/outputs/apk/release/
```

The first Gradle run downloads the Gradle distribution and the libraries from Maven. After that it works offline.

To refresh the Kotlin-made fixture the TypeScript test reads (only when the Kotlin format code changes):
`PEVV_WRITE_FIXTURES=1 ./gradlew :app:testDebugUnitTest`, then `npx vitest run tests/unit/pevv.android.test.ts`.

## Configuration (all optional)

Pass as Gradle properties (`-Ppevv.syncUrl=...`, in `~/.gradle/gradle.properties`) or environment variables. Nothing is committed.

| Setting | Property | Environment variable | If unset |
|---|---|---|---|
| Sync project URL | `pevv.syncUrl` | `VITE_PEVV_SYNC_URL` | sync is off |
| Sync anon key | `pevv.syncAnonKey` | `VITE_PEVV_SYNC_ANON_KEY` | sync is off |
| Public URL for vault QR links | `pevv.publicUrl` | `VITE_PEVV_PUBLIC_URL` | the QR carries the bare code |
| Passkey relying-party ID | `pevv.rpId` | `PEVV_RP_ID` | passkey (PRF) unlock is unavailable |

See [SYNC_SELF_HOSTING.md](SYNC_SELF_HOSTING.md) for the Supabase side.

## Signing and installing

The release APK is unsigned and cannot be installed as is. Either sign it yourself with `apksigner`, or let Gradle do it by setting
`PEVV_KEYSTORE_FILE`, `PEVV_KEYSTORE_PASSWORD`, `PEVV_KEY_ALIAS` and `PEVV_KEY_PASSWORD` before `assembleRelease`. No keystore or
password is in the repository and none should ever be added. The debug APK (`dev.pevv.app.debug`) is signed with the SDK's debug key
and installs next to a release build.

## Turning on autofill and passkeys

- **Autofill:** Android Settings, search "Autofill service", choose PEVV. Browsers must report the page address to the service; the app
  only fills a login whose saved site is exactly that address.
- **Passkeys and passwords (Android 14+):** Settings, Passwords and accounts, Preferred service or Additional providers, enable PEVV.
  Browsers can only use it once PEVV has the browser allow-list (see "Open decisions" in [ANDROID.md](ANDROID.md)); ordinary apps work
  through Digital Asset Links.

## Not included

- The audit log of the web app.
- Google Play Services features (no ML Kit, no Play integrity, no Play-based credential bridge).
- Automatic updates. Install new APKs yourself.
