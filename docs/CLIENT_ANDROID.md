# Android app (not in this repository yet)

PEVV also exists as an Android app (a thin Kotlin/Compose shell around a WebView that loads the standalone PEVV web build). **It is not
part of this repository yet**, on purpose:

- In its original project the Android module is built inside a multi-module Gradle project that also ships a game app, and shares a
  `:core` and `:updater` module, an in-app updater and a release signing configuration with it.
- Its web assets were committed as build output together with chunks of the game, not as a clean PEVV bundle.
- Signing keys and keystore properties live next to it in that project. They must never be copied into a public repository.

## Plan to bring it in

1. A new `android/` Gradle project with only the PEVV module (package `dev.pevv.app`), no `:updater`, no shared signing config.
2. The WebView loads `dist/` of this repo, copied into `assets/` by the build (not committed), with the same CSP as `public/_headers`.
3. Biometric quick unlock via the Android keystore, a separate key that never leaves the secure hardware.
4. CI builds an unsigned debug APK; releases are signed by the maintainer's own key outside the repository.

The vault format is the same on every client, so a vault made on Android opens in the web app, the extension and the desktop app and
the other way round. Until the app is here, use the web app, or move vaults with export and import files.
