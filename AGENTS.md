# AGENTS.md: guide for AI coding agents

PEVV is a zero-knowledge password and environment-variable vault (web app, browser extension, Tauri desktop app). It protects people's
secrets. Treat every change as security-sensitive. Humans: see [CONTRIBUTING.md](CONTRIBUTING.md); this file has the same rules in a
form that is quick to scan.

## Commands

```bash
npm ci                         # install exactly from package-lock.json
npm run lint                   # ESLint (must be clean)
npm run typecheck              # tsc --noEmit (must be clean)
npm test                       # Vitest unit tests, tests/unit/**
npm run build                  # web app -> dist/
npm run build:extension        # extension -> dist-extension/ and dist-extension-firefox/
npm run build:desktop-web      # desktop web bundle -> dist-desktop/ (required before cargo compiles the desktop crate)
npm run desktop:build          # web bundle + Tauri installers (slow)
npm run test:e2e               # Playwright web e2e (needs `npm run build` and a Chromium)
npm run test:e2e:extension     # Playwright extension e2e (needs `npm run build:extension`)
cd desktop/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
node scripts/android-vectors.mjs   # regenerate the TypeScript -> Kotlin golden vectors (android/app/src/test/resources/vectors/)
cd android && ./gradlew test lint assembleDebug assembleRelease   # Android app (JDK 17, Android SDK; release APK is unsigned)
```

Run lint + typecheck + `npm test` before finishing any TypeScript change; run the cargo trio for any Rust change; run the Gradle line for any change under `android/`
(and `node scripts/android-vectors.mjs` first if you touched crypto, vault, qr, devices, passkey or import code, so the Kotlin port is checked against it).

## Architecture map

```
src/pevv/crypto.ts bytes.ts        primitives: Argon2id/PBKDF2, HKDF, AES-256-GCM, base64
src/pevv/vault.ts model.ts         vault file format, slots, meta, entries (the format spec is docs/VAULT_FORMAT.md)
src/pevv/recovery.ts usbkey.ts totp.ts webauthn.ts devices.ts qr.ts   factors, kits, passkeys, device roster, QR transfer
src/pevv/store.ts                  Zustand store: the ONLY holder of plaintext and the vault key, only while unlocked
src/pevv/sync.ts roster.ts         opt-in ciphertext sync / live device exchange (via host/)
src/pevv/host/                     the ONLY place that touches the network or build-time config
    config.ts  cloud.ts  relay.ts  locale.ts
src/pevv/ui/                       React views         src/pevv/i18n.ts  EN + ES strings
src/pevv/extension/                MV3 worker, content script, popup, vault bridge, desktop link, protocol
src/pevv/desktop/                  webview glue for the Tauri shell (IPC bridge, browser link, auto-type, CLI, passkey provider)
desktop/src-tauri/                 Rust: app, `pevv` CLI, `pevv-native-host`
android/                           native Kotlin/Compose app (docs/ANDROID.md): core/ is the Kotlin port of src/pevv, checked by golden vectors
extension/manifest.json            MV3 manifest        scripts/  build-extension.mjs, extension-package.mjs, desktop-build.mjs
supabase/migrations/               optional sync backend (ciphertext only)       public/_headers  web CSP/headers
```

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first for anything non-trivial.

## Invariants that must never break

1. **Vault format compatibility.** A vault written by any released client must open in the current one and the other way round.
   Never change `format` strings (`luciverse.pevv`, `luciverse.pevv.export`, `luciverse.pevv.recovery-kit`, `luciverse.pevvkey`), the AAD
   strings (`luciverse/pevv/v1/...`), HKDF labels, slot types, or the meaning of existing fields. Additions must be optional and ignored by
   older clients. The `luciverse` prefix is a historical identifier, not branding: do not "clean it up".
2. **The key never leaves memory.** The vault key, master password, PRF outputs, recovery codes and decrypted entries are never written to
   `localStorage`, `chrome.storage`, IndexedDB, files, logs, URLs, error messages, analytics or the network. Locking drops all of them.
   The extension must not persist the key to survive worker restarts (it locks instead: fail closed).
3. **No plaintext at rest.** Persisted data is the encrypted `VaultFile` only (and the device-local encrypted audit log). Titles, sites
   and usernames are encrypted too.
4. **Exact-origin fills.** A login fills a page only when scheme + host + port equal the saved site; never into frames, never without
   an explicit user action, never to a look-alike or sub-domain (`https://x.com.evil.test`). The origin comes from the browser
   (`sender.origin`), never from a message body. The legacy `luciverse:<form>` site syntax must never match a web page.
5. **AEAD with bound associated data.** Every sealed value uses AES-256-GCM, a fresh random 96-bit IV and the AAD from
   `crypto.ts` (`aad.*`). Keep the sealed meta index and the 2FA flags authoritative over their plaintext hints.
6. **KDF floors and downgrade protection.** Do not lower Argon2id (m 19456, t 2) or PBKDF2 (600 000) minimums. Reject weaker parameters on unlock.
7. **No network outside `src/pevv/host/`.** The core, UI and workers must work with no network and must never send anything but the
   ciphertext file / relay ciphertext. Sync stays opt-in and off unless `VITE_PEVV_SYNC_URL` and `VITE_PEVV_SYNC_ANON_KEY` are set at build time.
8. **No hard-coded endpoints, keys or hostnames.** Configuration is `VITE_PEVV_*` (web) or `PEVV_RP_ID` (desktop shell). Never commit a
   service-role key, a signing key, a real vault, a token or a machine path.
9. **Strict CSP stays strict.** No inline or remote scripts, no `eval`, no `unsafe-inline` for scripts, in `public/_headers`,
   `desktop/src-tauri/tauri.conf.json` or `extension/manifest.json`. `wasm-unsafe-eval` is only for Argon2id.
10. **IPC and native messaging are authenticated and minimal.** Desktop commands are an explicit allow-list (`build.rs`,
    `capabilities/`), the browser link needs user-approved pairing, HMAC with a counter and an extension-id allow-list
    (`extension-ids.json`), and the desktop side never sees decrypted vault data it was not asked for.
11. **Secrets are masked, copies are cleared, reveals need recent re-authentication.** Do not log secret values or put them in error text.
12. **Do not weaken or delete a test to get green.** Fix the code, or explain in the PR why the expectation was wrong.

## Where tests live

| Area | Tests |
|---|---|
| Crypto, vault, store flows | `tests/unit/pevv.crypto.test.ts`, `pevv.store.test.ts`, `pevv.extra.test.ts`, `pevv.devices.test.ts`, `pevv.usbkey.test.ts` |
| QR transfer and relay framing | `tests/unit/pevv.qr.test.ts` |
| Optional backend seams (`host/`), desktop CSP | `tests/unit/pevv.host.test.ts` |
| Site matching | `tests/unit/pevv.sitematch.test.ts` |
| Extension worker, core, packaging | `tests/unit/pevv.extension.core.test.ts`, `pevv.extension.test.ts` |
| Desktop webview glue, link, CLI, auto-type, passkeys | `tests/unit/pevv.desktop.test.ts`, `pevv.link.test.ts`, `pevv.cli.test.ts`, `pevv.autotype.test.ts`, `pevv.native.test.ts`, `pevv.passkeyProvider.test.ts` |
| Android (Kotlin core, golden vectors from TypeScript, autofill matching) | `android/app/src/test/java/dev/pevv/app/*Test.kt`; `tests/unit/pevv.android.test.ts` opens a Kotlin-made vault with the TypeScript code |
| Rust shell | `#[cfg(test)]` modules in `desktop/src-tauri/src/*.rs` (`cargo test`) |
| Web e2e (real browser, virtual authenticator) | `tests/e2e/pevv.spec.ts` |
| Extension e2e | `tests/e2e-extension/*.spec.ts`, `tests/e2e-extension/firefox/` |

## Working rules

- Match the surrounding code; no drive-by refactors; keep diffs small. New behaviour gets a test against real objects.
- Add user-visible strings in both languages in `src/pevv/i18n.ts`.
- Conventional Commits, signed off (`git commit -s`). Update `docs/CHANGELOG.md` and the relevant doc in the same change.
- Never commit build output (`dist*`, `target`), `node_modules`, `.env*`, vault files or screenshots of real data.
- Security-relevant findings go to the private advisory flow in [SECURITY.md](SECURITY.md), not into public issues or commit messages.
- Do not add dependencies lightly (every one is attack surface); explain why in the PR. Pin GitHub Actions by commit SHA.
