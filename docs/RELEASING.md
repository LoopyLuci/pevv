# Releasing

Releases are cut from tags named `v<version>` (for example `v0.3.0`). The `release` workflow
(`.github/workflows/release.yml`) builds and attaches:

| Artifact | Built on | Notes |
|---|---|---|
| `pevv-extension-chromium-<version>.zip` | Ubuntu | Chrome, Edge, Brave (load unpacked or upload to a store). |
| `pevv-extension-firefox-<version>.zip` | Ubuntu | Needs Mozilla signing to install permanently. |
| `PEVV_<version>_x64-setup.exe` (NSIS), `PEVV_<version>_x64_en-US.msi` | Windows | **Unsigned.** SmartScreen warns on first run. |
| `PEVV_<version>_amd64.AppImage`, `pevv_<version>_amd64.deb` | Ubuntu | **Unsigned.** |
| `dist.zip` | Ubuntu | The static web app, built **without** sync configured. Self-hosters should build their own. |
| `SHA256SUMS` | Ubuntu | Checksums of everything above. |

Nothing in the workflow signs binaries, and no signing keys exist in this repository. If you add signing, put the certificate in
GitHub Actions secrets and keep the workflow's `permissions:` least-privilege.

## Checklist

1. All CI green on `main` (lint, typecheck, unit, extension build and e2e, Rust fmt/clippy/test, CodeQL, gitleaks).
2. Bump the version everywhere it appears (they are independent, keep them meaningful):
   - `package.json` `version` (the app and web build),
   - `extension/manifest.json` `version` (the extension; Chrome Web Store requires it to increase),
   - `desktop/src-tauri/tauri.conf.json` `version` and `desktop/src-tauri/Cargo.toml` `version` (the desktop app).
3. Update `docs/CHANGELOG.md`.
4. `git tag -s v<version> -m "PEVV <version>"` (or `git tag -a`), `git push origin v<version>`.
5. The workflow creates a **draft** GitHub release. Check the artifacts, paste the changelog entry, publish.
6. Extension stores (manual): upload the Chromium zip to the Chrome Web Store and the Firefox zip to AMO. Add the store extension id to
   `desktop/src-tauri/extension-ids.json` so the desktop link accepts it.

## Configuring a release build

The workflow builds with **no sync backend**, so the published installers make no network connections at all. A build with sync
(`VITE_PEVV_SYNC_URL`, `VITE_PEVV_SYNC_ANON_KEY`, `VITE_PEVV_PUBLIC_URL`, `PEVV_RP_ID`) is yours to make, from your own fork or machine:
[SYNC_SELF_HOSTING.md](SYNC_SELF_HOSTING.md). If you want the workflow to do it, store the values as repository *variables* (they are
public values, not secrets) and pass them in the `env:` of the build steps.

## Extension key

`extension/manifest.json` contains a `key` field: the **public** key that makes the unpacked extension get a fixed id
(`dolmkecfaekonkkgpjpamipjleindand`). It is not a secret and cannot sign anything. Forks that publish their own extension must remove
or replace it (and update `desktop/src-tauri/extension-ids.json` and `GECKO_ID` in `scripts/extension-package.mjs`); see
[CLIENT_EXTENSION.md](CLIENT_EXTENSION.md#extension-id).

## Reproducing a build locally

```bash
npm ci
npm run package:extension     # dist-extension-zips/
npm run desktop:build         # desktop/src-tauri/target/release/bundle/
```
