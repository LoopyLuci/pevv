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

## Updates

Settings > Updates checks the GitHub releases of `LoopyLuci/pevv` (the latest-release API, no sign-in, HTTPS only) for
`pevv-android-v<version>.apk` and `SHA256SUMS`. Pre-releases are ignored unless "Include pre-releases" is on. A background check runs
about every 12 hours (network connected, battery not low); "Check for updates now" runs one at once. The screen also shows the
current version and when the last check ran.

Modes (the default is Manual):

- **Manual:** checks and notifies. You tap "Download and install".
- **Auto-download:** WorkManager downloads in the background (only on an unmetered network unless you turn that option off, and
  only while the battery is not low), then posts "Update ready - tap to install".
- **Auto-download and install:** the same download, then installation through a `PackageInstaller` session. An automatic install never
  runs while the vault is unlocked and on screen; it waits until the vault is locked or the app is in the background. A tap by you is
  never deferred.

What is checked before anything is installed (any mismatch deletes the file and shows why):

1. the APK's SHA-256 equals its line in `SHA256SUMS`;
2. the package is `dev.pevv.app` and its `versionCode` is higher than the installed one;
3. the APK's signing certificate equals the signing certificate of the running app (`PackageManager.getPackageArchiveInfo` with
   `GET_SIGNING_CERTIFICATES`, compared with our own).

The checks run again just before the install. Downloads live in the app's private cache and are deleted after use. A debug build
(`dev.pevv.app.debug`) rejects release APKs, because the package name differs.

**Silent install works only in one situation.** The update is applied without a prompt only on Android 12 (API 31) or later and when PEVV is
the installer of record of itself, which happens after the first update PEVV installed on that phone (an APK installed from a browser,
a file manager or `adb` leaves another app as the installer of record). Android may still ask. In every other case, including
Android 11 and older, there is one tap: PEVV posts a notification that opens the system install prompt.

Android also needs "Install unknown apps" enabled for PEVV; if it is off, Updates shows a button that opens that screen, and a
background install posts a notification that does the same. On Android 13+ PEVV asks for the notification permission when you choose an
automatic mode.

Not tested on a device: the PackageInstaller flow, the silent path, the notifications and the WorkManager schedule.
