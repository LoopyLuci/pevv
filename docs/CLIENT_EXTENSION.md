# PEVV browser extension

A browser extension is a third client of the same vault, next to the web app and the desktop app. It does not need an account.

Status: 0.2.0, Chrome, Edge and Brave (one Manifest V3 package) and Firefox 128+ (the same files with a Firefox manifest). Not published to a store yet.

## No account needed

PEVV in the extension never needs an account. A fresh browser profile can:

- create a vault, or bring one in with the vault QR (camera or a photo of the code), an encrypted PEVV export, or a password-manager import;
- exchange live with another device that has the vault open (`roster.ts`);
- unlock, fill, save, generate and lock.

The vault QR goes through the optional relay (`src/pevv/host/relay.ts`, an anonymous Supabase Realtime socket that is not an account; it needs a sync backend, see [SYNC_SELF_HOSTING.md](SYNC_SELF_HOSTING.md)). A QR shown in the extension links your public web app when the build has `VITE_PEVV_PUBLIC_URL` (`<url>?pevvq=…`), because a phone camera cannot open a `chrome-extension://` link; without it the QR carries the bare code, which PEVV's own scanner accepts. Without a sync backend the QR move uses the offline codes (already-encrypted vault file, gzipped, up to 12 codes).

Account sync is optional and exists only in builds that configure a sync backend. In such a build the vault screen shows an email sign-in box (Settings and "I already have a vault"); without it there is no sign-in screen at all.

## What it does

- Fills logins on the page the user is looking at, from the unlocked vault.
- Offers to save a new or changed password.
- Generates a password into the focused field.
- Locks itself when the screen locks, when the last browser window closes, or when the auto-lock timer fires.

It does not browse the galaxy or hold a second copy of the master key outside the vault format.

## How it stays one vault

The extension stores only the ciphertext `VaultFile` (the same JSON the app and the site store), in `chrome.storage.local` under `pevv.vault`. Unlock uses the same Argon2id and AES-GCM code (`src/pevv/crypto.ts`, `vault.ts`), compiled into the extension.

The extension ships the standalone PEVV app as its **vault screen** (`extension/vault.html`, the same `PevvStandalone` as the web app's `index.html`). That screen is how a vault gets in and out:

- scan a vault QR from another device (camera or photo), the same relay lane the web app uses;
- open an encrypted PEVV export, or create a new vault;
- import Proton Pass, Brave, Chrome, Bitwarden and the other exports (`importManagerExport`);
- live device exchange (`roster.ts`) while another device with the vault is open, and (optional) account sync when this browser is already signed in, exactly as in the app.

The vault screen keeps its copy in its own `localStorage` and mirrors every write to `pevv.vault` (`src/pevv/extension/bridge.ts`). A login the worker saves is folded back into the open vault screen like a live paired device (`reconcileRemote(…, 'peer')`). A higher revision wins; the worker always writes on top of the newest stored copy.

The vault screen and the popup unlock separately. The vault screen has the full unlock (recovery code, recovery kit); the popup has master password plus authenticator code.

## Shape

- Manifest V3. One service worker (`worker.js`). One small popup (locked / search / generate). A content script that only talks to password fields the user focused.
- Permissions: `activeTab`, `storage`, `scripting` (fill the tab the user is on), `idle` (lock when the screen locks), `alarms` (auto-lock timer). None of them shows an install warning. No host access at install. `https://*/*` and `http://*/*` are optional: when the user turns autofill on for a site, Chrome asks for that one origin only.
- The content script never sees the vault key. It asks the worker for a single matching username and password, and the worker forgets the plaintext on lock.
- No `externally_connectable` and no web-accessible resources: a web page cannot message the extension.

### Where the key lives

Chrome stops an idle MV3 service worker after about 30 seconds. The extension does **not** keep the key alive by writing it anywhere — not `chrome.storage.session`, not an offscreen document:

- After unlock, the vault key exists only as a **non-extractable** WebCrypto `CryptoKey` in the worker's memory. The raw key bytes are wiped right after import.
- The worker keeps only a title / site / username index of logins. A password is decrypted for the one fill that asked for it and is not kept.
- While unlocked, the worker makes a cheap extension API call every 20 seconds, which Chrome counts as activity. This stops at the auto-lock deadline (1–60 minutes; there is no "never").
- If Chrome stops the worker anyway (update, crash, memory pressure), the key is gone and the vault is locked. It fails closed.
- Lock also happens on: the screen locking (`chrome.idle` "locked"), the last browser window closing, the manual lock button, and `runtime.onSuspend`. Every request checks the deadline too, in case an alarm fires late.

### Filling

- **From the popup** (works on any http/https site, `activeTab`): the popup lists the logins saved for the tab's exact origin (scheme, host and port — the same rule as the site). Choosing one creates a one-time ticket in the worker, bound to that tab and origin, valid 30 seconds. The worker injects the content script into the top frame; the content script redeems the ticket. The worker checks the origin Chrome reports for the content script, never one from a message. The password goes from the worker to the page and never through the popup.
- **Inline button** (only on sites the user approved): focusing a password or username field shows a small 🔐 button in a closed shadow root. Only a real (trusted) click fills. With several logins for the site it shows a short list (titles and usernames).
- The focused field decides what is filled: a password field (and its username), or a username field in a form with a password field. Never frames.
- Legacy in-app `luciverse:` form ids (from an older game integration) never match a web page.

### Saving

On approved sites the content script watches form submits. A new username, or a changed password for a saved username, becomes an offer in the worker's memory (5 minutes, cleared on lock). The toolbar badge shows it; the popup asks Save / Update / Not now / Never for this site. An update keeps the old password in the item's history, like an edit in the vault. A generated password filled from the popup becomes an offer too.

## Linking to the desktop app

Like "unlock with the desktop app" in other password managers: with the PEVV desktop app installed, the extension can leave the vault in the app. The app unlocks natively (master password, passkeys, security keys, USB key file, presence lock) and the extension only asks it for logins.

How to use it: open the popup, press **Use the PEVV desktop app**, accept Chrome's permission prompt, then approve the pairing in the app after checking that both show the same code (`XXXXX-XXXXX`). The setting **Use the PEVV desktop app** is on by default once the permission is granted and a pairing exists; "Use this browser's vault instead" in the popup switches back to the standalone mode, which is unchanged and keeps working with no app at all.

When linked, the popup shows the app's state (unlocked, locked, not running). Locked: **Unlock in the app** brings the app window forward (and starts it if it is not running); the popup follows. Fills go page, worker, host, app: the worker asks the app for exactly one login at the moment the page redeems the fill, for the page's own origin (`sender.origin`, from Chrome, never from a message), and hands it straight to the page. **Nothing the app returns is cached in the extension.** Save offers go to the app, which shows its own card; the extension keeps no copy. Passkeys in the extension: the vault screen and the popup still cannot use site passkeys inside the extension, but a vault that requires one unlocks fine in the linked app, and the popup's message now says so.

### Parts

```
page --content script--> service worker --connectNative--> pevv-native-host --pipe/socket--> PEVV desktop app
                          (HMAC-signed JSON)                (relay, no secrets)                (vault, prompts)
```

- `src/pevv/extension/link.ts`: the client (framing is the browser's; this does pairing, counters, HMAC, one request at a time, idle close of the port so the host exits).
- `desktop/src-tauri/src/bin/pevv-native-host.rs`: the host. Chrome native messaging (4-byte little-endian length + JSON on stdio, 1 MB cap). It only relays and adds the extension origin from argv[1]. App not running: reply `app-not-running`; only `unlock-request` and `launch` start the app (the `pevv-desktop` next to the host), `status`/`match`/`fill` never do.
- The app side: `link_core.rs` (policy), `link_ipc.rs` (named pipe / Unix socket), `link_register.rs` (host registration), `src/pevv/desktop/link.ts` (the unlocked-vault side: exact-origin matching, offers).

### Protocol (version 1)

Every message is a JSON object with `v: 1`. Unauthenticated: `pair`, `launch`, and errors `{type: "error", code}` (from the host or the app). Everything else is `{v, n, type, body, mac}` where `body` is a JSON string and `mac = HMAC-SHA256(secret, "pevv-nm1|<ext|app>|<n>|<len(type)>:<type>|<body>")` in hex. The reply reuses `n` and is signed with direction `app`, so a request cannot be turned into a reply. The app accepts a request only if its `n` is higher than the last one it accepted for that extension, and writes the new value to disk before acting.

| type | body | answer |
|---|---|---|
| `status` | `{}` | `{ok, locked}` |
| `unlock-request` | `{}` | `{ok, locked}`; the app comes to the front |
| `match` | `{origin}` | `{ok, logins: [{id, title, username}]}` for that exact origin; `locked` while locked |
| `fill` | `{origin, id}` | `{ok, username, password}` only if that login is saved for exactly `origin`; else `no-match` |
| `save-offer` | `{origin, username, password}` | `{ok, queued}`; the app shows Save / Not now (waits for unlock) |
| `lock` | `{}` | `{ok, locked: true}` |

Errors: `app-not-running`, `origin-denied`, `not-paired`, `bad-mac`, `replay`, `pair-denied`, `busy`, `disabled`, `locked`, `no-match`, `bad-origin`, `bad-request`, `unsupported-version`, `app-busy`, `app-connection-lost`. Pairing: the extension makes a random 256-bit secret and sends it in `pair`; the app shows a fingerprint of it (SHA-256, 10 hex characters) and asks the person; on approval it stores the secret and answers `pair-ok` signed with it. The extension stores `{secret, n}` in `chrome.storage.local` (key `pevv.link`) only after that reply checks out.

### Permission and install warning

`nativeMessaging` is declared as an **optional** permission, not a required one. A required `nativeMessaging` shows the install warning "Communicate with cooperating native applications" and, on an update of an existing install, disables the extension until the person accepts it again. As an optional permission nothing changes for people who never link the app; the popup asks for it from the "Use the PEVV desktop app" click and Chrome shows its own prompt then. The consequence: the link cannot be detected without the permission, so "on by default" means on as soon as the permission is granted and a pairing exists. Firefox has neither the permission nor the host; its package drops the field and stays standalone.

### Extension id

> **The `key` in `extension/manifest.json` is a PUBLIC key.** It is the public half of an RSA key pair, base64 (the same value a store dashboard shows as "public key"). Chrome hashes it to a fixed extension id, `dolmkecfaekonkkgpjpamipjleindand`. It cannot sign or decrypt anything and the matching private key does not exist anymore, so it is safe to publish. It is not used by Firefox (the Firefox build drops it). **Forks that publish their own extension must remove it** (Chrome then derives an id from the install folder) **or replace it** with the public key of their own store listing, and update `desktop/src-tauri/extension-ids.json` to the new id, otherwise the desktop app would accept your fork under this project's id and not your own.

The host manifest's `allowed_origins` is the only thing that lets a browser start the host, and the extension id has to be known when the app is installed. An unpacked extension gets an id from its folder path unless the manifest has a `key`, so `extension/manifest.json` now carries a `key` (the public half; the private half was discarded and is not needed for unpacked or store use). It gives the id `dolmkecfaekonkkgpjpamipjleindand`, listed in `desktop/src-tauri/extension-ids.json`; a unit test checks the two agree. **When a store listing exists**, copy the public key from the Chrome Web Store dashboard (Package, View public key) into `key` and add the store id to `extension-ids.json` (the app, host manifest and host all read that one file). The app also checks the origin itself: a browser that ignored `allowed_origins` still cannot pair another extension.

### Not covered

No real browser or real registry was driven by the automated tests (see docs/PEVV_DESKTOP.md, "Browser extension link"): the extension tests mock `connectNative` against an in-process copy of the app's protocol, the Rust tests use real pipes / files / a throwaway registry subtree, and the Playwright extension e2e does not exercise the link because it would need a real host registered in the browser's profile. Flatpak and snap browsers use their own native-messaging folders and are not registered.

## Passkeys

Passkeys made in the PEVV web app are bound to the web app's host. Inside an extension the WebAuthn origin is `chrome-extension://<id>`, so they cannot be used there, and new ones would only work in the extension.

- The popup unlocks with the master password, then the authenticator code if the vault requires it.
- A vault that requires a passkey or security key as its second factor cannot be unlocked in the extension. Both the plaintext hint and the sealed flag are checked, so stripping the hint does not help. The popup says so plainly.
- The vault screen hides "Add passkey" and explains why.
- Linked to the desktop app (above), the app does the unlocking natively and this limit does not apply to filling.

**Planned:** make passkeys work in the extension without weakening them. Options to evaluate: a PRF slot enrolled from the extension's own origin (its own key slot, like a second device), or a WebAuthn request relayed to a web-app tab so its rpId is used. Either one has to keep the rule that any one slot unlocks and no key is stored outside the vault format.

## Firefox

The Firefox package is the same build with a different manifest (`scripts/extension-package.mjs`): the worker runs as an event page (`background.scripts`) instead of a service worker, and it has an add-on id (`pevv@luciverse.pages.dev`, kept so existing installs keep one identity; forks must change `GECKO_ID` in `scripts/extension-package.mjs`), `strict_min_version` 128 and `data_collection_permissions: none`. Everything else is shared code.

- Firefox also stops an idle background page after about 30 seconds. The same 20-second keep-alive holds it while unlocked; the Firefox test checks the vault is still unlocked after 40 idle seconds.
- Firefox does not report a locked screen to extensions (`idle` gives only active/idle), so there the auto-lock timer, the lock button and closing the last window do the locking.
- Firefox match patterns ignore the port, so approving `http://host:8080` for the inline button approves that host on every port.
- Load it: `about:debugging#/runtime/this-firefox` → Load Temporary Add-on → `dist-extension-firefox/manifest.json` (or the Firefox zip). A permanent install needs the add-on signed by Mozilla (not done yet).

## Build, load and test

```
npm run build:extension          # → dist-extension/ (Chromium) and dist-extension-firefox/
npm run package:extension        # also → dist-extension-zips/pevv-extension-{chromium,firefox}-<version>.zip
```

Load it in Chromium: `chrome://extensions` (or `edge://extensions`, `brave://extensions`) → Developer mode → Load unpacked → `dist-extension/` (or the unzipped Chromium zip).

The zips are written by the build (forward-slash paths, fixed timestamps). The 0.1.0 zip was made with Windows' Compress-Archive, which wrote `\` separators: it unpacked into flat file names on Linux and macOS.

- Unit: `tests/unit/pevv.extension.core.test.ts` (unlock, second factor, tickets, auto-lock, offers, writes on top of the vault screen), `tests/unit/pevv.extension.test.ts` (manifest permissions, field helpers, bridge, Firefox manifest, zip writer), `tests/unit/pevv.qr.test.ts` (the extension's QR link).
- End to end, real Chromium with the unpacked build: `npm run build:extension && npx playwright test -c playwright.extension.config.ts`. Playwright cannot click the toolbar button that grants `activeTab`, so the test copy of the manifest grants the one test host instead.
  - `pevv-extension.spec.ts`: vault screen, popup unlock, fill, generate, inline fill, save offer, lock.
  - `pevv-extension-no-account.spec.ts`: two fresh profiles with no sync account; one makes a vault, the other gets it by a photo of the vault QR and fills from it (needs a sync backend and a build with `VITE_PEVV_SYNC_URL`/`VITE_PEVV_SYNC_ANON_KEY`; skipped unless `PEVV_E2E_SYNC=1`).
- End to end, the installed Firefox: `npm run build:extension && npm run test:extension:firefox`. It installs the build as a temporary add-on over WebDriver BiDi in a fresh profile and runs the same flow (create, popup unlock, fill, 40 s idle, inline fill, save offer, lock). `FIREFOX_BIN` overrides the Firefox path.

Code: `src/pevv/extension/` (worker, core, content script, popup, vault-screen bridge), `extension/` (manifest and the two HTML pages), `scripts/build-extension.mjs`.

## Not in the first build

- Passkeys inside the extension itself (see above); the linked desktop app covers them.
- Sharing a vault with a page that is not PEVV, and reading the browser's own password store. Brave and Chrome passwords come in through the CSV import the vault already has.
- Store listings (Chrome Web Store, Mozilla signing), icons.
- Spanish strings in the popup (the vault screen is already EN + ES).
- The worker does not read the revoked-devices list. Removing the extension in Devices takes effect the next time its vault screen unlocks or syncs: that copy wipes itself, and the worker's copy goes with it. Until then the popup still unlocks with the master password.
