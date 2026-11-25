# PEVV desktop (Windows and Linux)

A fourth client of the same vault, next to the web app and the browser extension. It is the standalone PEVV screen in a Tauri 2 window, with the ciphertext kept in a file in the OS app-data folder.

Status: 0.1.0, built and tested on Windows; the Linux code paths are type-checked and linted but not yet run on a Linux desktop.

## Architecture

```
desktop.html + src/pevv/desktop/boot.tsx   the PEVV standalone UI (vite.desktop.config.ts -> dist-desktop/)
src/pevv/desktop/bridge.ts                 localStorage copy <-> vault file, lock event, clipboard hand-off
desktop/src-tauri/                         Rust shell
  src/vault_store.rs                       the vault file: atomic write, revision check, 5 backups
  src/clipboard.rs                         copy a secret, clear it later only if unchanged
  src/lock_win.rs / src/lock_linux.rs      OS lock / suspend signals
  src/passkey.rs                           native passkey command: request checks, PRF salt, clientDataJSON (+ passkey_win.rs / passkey_linux.rs)
  src/usbkey.rs                            removable drives, .pevvkey write / read-back
  src/presence.rs                          designated USB device, settings.json, 2 s poller
  src/autotype*.rs                         auto-type into other programs (policy, Win32, X11, hotkey + chooser)
  src/cli_core.rs / cli_proto.rs / bin/pevv.rs   the `pevv` command-line tool and the app's side of it
  src/winpath.rs                           the install folder on the user's PATH (installer hook)
  src/provider.rs                          Windows passkey provider: support state, commands, webview bridge (always built)
  src/provider_core.rs / provider_win.rs   ... CTAP/CBOR codec and broker (feature `win-passkey-provider`); COM class and registration FFI (Windows)
  windows/msix/                            AppxManifest.xml and build-msix.ps1 (the MSIX the provider needs)
  src/lib.rs                               commands, file watcher, tray, single instance
src/pevv/native.ts, src/pevv/desktop/native.ts   the page-side view of those commands (null outside the app)
src/pevv/passkeyProvider.ts                ES256 credential creation / assertion for the passkey provider (WebCrypto)
src/pevv/desktop/provider.ts, PasskeyProvider.tsx   the webview side of the provider, its prompts and settings section
```

The UI keeps its working copy in `localStorage` (`lv-pevv-vault-v1`), as on every other client. The bridge mirrors each write to the shell (`vault_write`) and folds changes made elsewhere back in with `reconcileRemote(..., 'peer')`, the same way the extension bridge does. The shell watches the file and emits `vault-changed` when something other than this process rewrites it (a second install, Syncthing, a restored backup).

Tauri commands, and nothing else (`capabilities/default.json` lists exactly these plus event listen/unlisten):

| command | what it does |
|---|---|
| `vault_read` | the ciphertext JSON or `null` |
| `vault_write(json, expectedRev)` | atomic write; refuses a lower revision of the same vault with `rev-conflict` |
| `vault_clear` | a vault reset: keeps a backup, then removes the file |
| `clipboard_copy(text, clearAfterSecs)` | copy, then clear after N seconds only if the clipboard still holds the secret |
| `passkey_support` | whether native passkeys work here, the compiled-in rpId, why not |
| `passkey_prf({ credentials: [{ id, salt1?, salt2? }], challenge, requireUv, pin? })` | ask Windows / the USB key for the assertion and PRF secrets; returns `{ credentialId, prf1, prf2?, authenticatorData, clientDataJson, signature }` (base64url) |
| `usb_volumes` / `usb_keyfile_read(path)` / `usb_keyfile_write(path, content)` | removable drives; read or create `<drive>/.pevvkey` (refuses to overwrite; reads it back; 0600 on Unix) |
| `usb_devices` / `presence_get` / `presence_set(designation)` | USB devices; the designated presence-lock device and whether it is plugged in |
| `autotype_support` / `autotype_settings_get` / `autotype_settings_set(enabled, hotkey)` | what this system can do, the shortcut and its state |
| `autotype_offer` / `autotype_type` / `autotype_finish` / `autotype_mode` | the vault window answers a hotkey press (titles only), sends the keys to type, or reports the end |
| `autotype_pending` / `autotype_confirm` / `autotype_cancel` | the chooser window only (its own capability file, `capabilities/autotype.json`) |
| `cli_state` / `cli_prompts` / `cli_prompt_answer` / `cli_revoke_client` / `cli_revoke_command` | `pevv` approvals, what is allowed, revoking it |
| `passkey_provider_support` / `passkey_provider_register` / `passkey_provider_unregister` / `passkey_provider_respond(id, ok, value)` / `passkey_provider_sync(credentials)` | the Windows passkey provider (see below): what this PC and build can do, register or remove it with Windows, the vault window's answer to a Windows request, account names for Windows' lists. Present in every build; without the feature they only report why it is off. |

Events to the page: `lock`, `vault-changed`, `link-prompt`, `link-request`, `cli-prompt`, `cli-served`, `autotype-request`, `autotype-run` (and `autotype-view` to the chooser). The presence lock emits the same `lock` event.

## Why Tauri and not Python

The vault format, Argon2id and AES-GCM code, vault QR transfer, imports, device roster and sync are all TypeScript under `src/pevv/`. A Python or native rewrite would have to reproduce all of it byte for byte and keep doing so. Tauri reuses that code unchanged, so a vault made in the browser or in the extension opens here and the other way round. Rust only does what a webview cannot: files, OS signals, the clipboard, the tray. Compared with Electron the installer is a few MB and there is no bundled Node.

## Security model

- The Rust side never sees a password, vault key or plaintext. It parses three header fields of the vault file (`format`, `id`, `rev`) to reject a stale or foreign write. It does handle two secrets in passing, never stored or logged: the PRF output a security key returns (handed straight to the page) and the text of a key file it writes or reads for the page.
- The vault lives at `%APPDATA%\PEVV\vault.json` (Windows) or `~/.local/share/pevv/vault.json` (Linux). Writes go to a temp file in the same folder, are fsynced and renamed over the target. The last 5 backups are kept in `backups/` (a new one at most every 10 minutes, or when a different vault replaces the file, or on reset). On Linux the folders are 0700 and the files 0600; on Windows they inherit the per-user ACL of `%APPDATA%`.
- Auto-lock: the UI idle timer (default 5 minutes), and the shell emits `lock` on workstation lock, RDP/console disconnect and suspend (Windows: WTS session notifications and power broadcasts; Linux: logind `Lock` for this session and `PrepareForSleep`, plus the GNOME / freedesktop screensaver `ActiveChanged`, best effort). Closing the window on Windows hides it to the tray locked.
- Clipboard: the copy is made with arboard; on Windows it asks to be left out of clipboard history, the cloud clipboard and clipboard monitors. The default clear delay is 30 s (the Settings choice is honoured, 0 = never). A newer copy cancels the older timer, and a clipboard the user has since changed is left alone.
- CSP (`tauri.conf.json`): `default-src 'none'`; scripts and styles from the app only (plus `wasm-unsafe-eval` for Argon2id); `connect-src` is the app and Tauri IPC, plus, only when you build with `VITE_PEVV_SYNC_URL`, that one sync origin (`https` and `wss`; `scripts/desktop-build.mjs` adds it at build time, nothing is hard-coded). No remote scripts, frames, forms or objects. Release builds have devtools off and the webview context menu disabled.
- Capabilities grant the main window its commands (listed in `capabilities/default.json`) and event listening. The auto-type chooser is a second window with a capability file of its own (three commands, no vault, clipboard or file access). The global-shortcut plugin is registered in Rust only; the page is not granted its JavaScript commands. No fs, shell, http or opener plugin is present.
- One instance at a time (a second launch focuses the first). Window size and position are remembered.
- Same limits as any local vault: malware running as the user while the vault is unlocked can read the page. The file on disk is as safe as the master password and the Argon2id/AES-GCM design.

## Sign-in on desktop

Master password plus the authenticator (TOTP) code, like the extension. Recovery codes and the recovery kit work. Also:

- **Passkeys and security keys enrolled on the site** unlock here (PRF mode) or act as the second factor (2FA mode). See below.
- **USB key file** (`.pevvkey`), as an alternative unlock or as a second factor. See below.
- **New passkeys are not made in the app.** Creating one needs the site's rpId and a PRF-capable create call; `passkey_create` is not implemented, so enrolment stays in the PEVV web app (the Settings screen says so). The page code refuses `registerPasskey` in the app.

### Native passkeys (what the site actually does)

Read from `src/pevv/webauthn.ts`, `vault.ts`, `crypto.ts`:

- **rpId = `location.hostname` of the page that enrolled it.** There is no fixed rpId in the web app; each `PasskeyRecord` stores the `rpId` it was made under. The desktop app compiles in the rpId you give it with `PEVV_RP_ID=pevv.example.com` at build time (the host name of your web app) and only offers records whose `rpId` equals it. **With `PEVV_RP_ID` unset, native passkey unlock reports itself unavailable** (master password, recovery and USB key still work). A passkey made on `localhost`, a preview deploy or another domain cannot be used here. Change `RP_ID` in `src/passkey.rs` (or set `PEVV_RP_ID`) if the site is served from a custom domain.
- Credential ids come from the vault's `passkeys[]` / `prf` slots (`credId`, base64url). `allowCredentials` lists them.
- **PRF only, no other fallback for unlock**: `prf: { evalByCredential: { <credId>: { first: <32 random bytes> } } }`, salt stored in the slot (`salt`, base64) and the record (`prfSalt`). Only `first` is used. The 32-byte output goes through HKDF-SHA256 (salt = slot salt, info `luciverse/pevv/v1/prf-kek`) into the KEK that wraps the vault key. A passkey without PRF is `2fa` mode: a gate after the password, verified locally.
- `userVerification`: `required` for unlock and re-auth, `preferred` for the second-factor check. Enrolment used `preferred`, `attestation: none`, `residentKey: preferred`.
- Assertions are verified by the page itself (origin, challenge, rpIdHash, UP/UV, signature, counter). The desktop path builds the same clientDataJSON with origin `https://<rpId>` so that check is unchanged.
- **No server verifies a PEVV assertion.** The vault sync only carries ciphertext, including the passkey records.

**Windows**: `WebAuthNAuthenticatorGetAssertion` on the app window, with `pAllowCredentialList`, `pHmacSecretSaltValues` (per credential) and `WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG`, options struct version 6. The PRF input is hashed as browsers do before it reaches hmac-secret. **The API must be version 6** (the brief said 4: version 4 has no hmac-secret salts on get-assertion; the version number is read with `WebAuthNGetApiVersionNumber`). Older Windows (this development machine is Windows 10) gets a clear message and the master password path. Windows shows its own dialog (including the PIN). Whether a platform passkey (Windows Hello) returns hmac-secret depends on the authenticator; USB keys are the supported case.

**Linux**: `ctap-hid-fido2` over `/dev/hidraw*`, `hmac-secret` with salt = SHA-256(`"WebAuthn PRF" ‖ 0x00 ‖ input`), clientDataHash = SHA-256 of the clientDataJSON built in the app. If the key has a PIN the command answers `pin-required`, the page shows a PIN box and retries with `pin` (a wrong PIN answers `pin-invalid`, up to 3 tries). A key with a PIN is always used with user verification, because the key derives a different secret with and without it. Keys without a PIN are asked without UV. Limits: one request per credential per key; with several keys plugged in, each is tried in turn. udev rule so a normal user may open the key (or install your distro's `libfido2` / `fido2-udev` package):

```
# /etc/udev/rules.d/70-pevv-fido.rules, then: sudo udevadm control --reload && sudo udevadm trigger
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"   # Yubico; add the vendor id of other keys
```

Building on Linux also needs `libudev-dev` (hidapi).

**Untested on hardware**: both native paths compile and their request building, salt transform, client-data and error mapping are unit tested (`cargo test`, and the Linux module ran under WSL), but no security key or Windows Hello was touched.

### USB key file

Settings, USB key file. Pick a removable drive (Windows `GetDriveTypeW == DRIVE_REMOVABLE`; Linux mounts under `/run/media/$USER/` and `/media/` from `/proc/mounts`; a USB SSD that Windows reports as a fixed disk is not listed), name it, choose *Unlock the vault by itself* (a `usb-key` slot) or *Second factor after my master password* (a gate record), create. The page makes the secret; the shell writes the file (0600 where the file system has modes), reads it back and compares, and refuses to overwrite an existing `.pevvkey`. The vault only changes after the write succeeded. The shell only touches a drive it listed itself a moment before, never an arbitrary path. Every client can use a key file by choosing it; the desktop app also finds it on a plugged drive. Format, crypto and limits: `docs/PEVV.md`. The screen states that a key file can be copied without you noticing, is weaker than a FIDO2 key, and should live on one drive with a backup.

### Presence lock (USB device)

Settings, Presence lock. Pick a connected USB device (Windows SetupAPI, instance id `USB\VID_xxxx&PID_xxxx\...`; Linux `/sys/bus/usb/devices`, hubs and interfaces left out). The app polls every 2 s and locks when the device goes from present to absent; a failed enumeration never locks. Optionally *Do not start an unlock while it is unplugged*. This is **not** a factor: a mouse or keyboard holds no secret, its vendor id, product id and serial are readable by any program and a USB microcontroller can claim the same ones. It only triggers a lock, and the refuse-to-unlock option is a soft gate (recovery codes are never gated, so it cannot lock you out). A device with no serial is identified by vendor, product and port, so another port counts as another device. The designation is in `settings.json` in the app data folder, not in the vault.

## Browser extension link

The PEVV extension (Chrome, Edge, Brave; protocol and extension side in docs/PEVV_EXTENSION.md) can use this app as its vault. Pieces in this crate:

- `pevv-native-host` (`src/bin/pevv-native-host.rs`): second binary of the same package, built by `cargo build --release --bins` / `tauri build` and installed next to `pevv-desktop`. Started by the browser, relays stdio native messaging to the app. For `tauri dev` build it once with `cargo build --bins` so the registration finds it.
- Local channel (`link_ipc.rs`): Windows named pipe `\\.\pipe\pevv-link-<user SID>` with a DACL granting only the current user's SID, remote clients rejected, first instance flagged so a squatter makes the app fail loudly; Linux Unix socket `$XDG_RUNTIME_DIR/pevv-link/native.sock` (directory 0700, socket 0600) and every accepted connection's `SO_PEERCRED` uid must equal ours. Max 16 connections.
- Policy (`link_core.rs`): extension id from argv[1] must be in `extension-ids.json`; pairing needs the person's approval in the app window (fingerprint shown); afterwards every request is HMAC-SHA256 signed with a counter (replay refused, counter persisted first); `match`/`fill` refused while locked; origins must be a bare canonical `http(s)://host[:port]`. The Rust side never sees decrypted logins: it forwards to the webview, which holds the unlocked vault and applies the exact-origin rule (`src/pevv/desktop/link.ts`: scheme, host and port equal to the saved site; `luciverse:` sites and non-login items never match). The shell reports lock state both from the webview and directly on every lock event.
- Pairings and the on/off setting live in `native-link.json` in the app data folder (mode 0600 on Linux; on Windows the user's profile ACL). It holds the shared secrets in plain text, like any browser profile holds its own; deleting the file or "Remove" in Settings, Browser extension link, unpairs. This is not the vault key and cannot open the vault.
- Registration (`link_register.rs`): the host manifest `com.luciverse.pevv` with `allowed_origins` from `extension-ids.json`. Windows: `<app data>\native-messaging\com.luciverse.pevv.json`, and HKCU `Software\{Google\Chrome, Microsoft\Edge, BraveSoftware\Brave-Browser}\NativeMessagingHosts\com.luciverse.pevv` default value pointing at it. Linux: `~/.config/{google-chrome,microsoft-edge,BraveSoftware/Brave-Browser,chromium}/NativeMessagingHosts/com.luciverse.pevv.json`. The app (re)writes these on every start while the setting is on and removes them when it is switched off (Settings, Browser extension link). The NSIS installer runs `pevv-desktop.exe --register-link` after install (honours an earlier "off") and `--unregister-link` before uninstall (`windows/hooks.nsh`). The AppImage is not registered: its path changes on every start; use the .deb.
- UI: pairing and save-offer cards (`src/pevv/desktop/BrowserLink.tsx`) appear over the window and bring it to the front; the settings section is under Settings. These strings are English only.

Tested: framing and the 1 MB cap, HMAC (RFC 4231 vectors), the same MAC and fingerprint vectors as the TypeScript client, replay and tamper cases, pairing approval and refusal, origin handling, counter persistence, manifest generation for both platforms and the registry/file layout through a recording sink, a real pipe round trip (and a real file + throwaway `HKCU\Software\Luciverse-PevvTest-<pid>` registry round trip that is deleted afterwards), the host relay with a fake app. Not tested: a real browser launching the host, the installer hook, and the Linux socket code (it is written and checked only by code review here; the Linux-only tests run with `cargo test` on Linux).

## Direct device link (Transferd)

Optional sync straight between your own computers over the Transferd overlay, with no account and no server; design and threat model in [TRANSPORT.md](TRANSPORT.md). The shell runs the transport in process (`src/transport.rs`, policy in `transport_core.rs`, protocol in `transport/pevv-transport`); the vault window drives it (`src/pevv/desktop/transferd.ts`, panel in `TransferdPanel.tsx`, Settings, "Direct device link").

- **Off by default.** The cargo feature `transferd` is on by default (`cargo build --no-default-features` leaves it out; the commands then answer `not-in-this-build`), and the run-time switch in Settings is off until the person turns it on. No relay is built in; add your own (UDP `host:port`, up to 4) or pair on one network with a direct address. No inbound port is opened.
- **Ciphertext only.** Only the sealed vault file crosses. The shell never writes a peer's file to the vault file: it holds it and the window merges it with the same `reconcileRemote` as the cloud copy ([SYNC.md](SYNC.md)); a locked window stages it for the next unlock. Supabase keeps running beside it, so with no peer reachable the cloud copy carries on.
- **Files.** `<app data>/transferd/`: `transferd.json` (switch, device name, relays, the peers you approved or removed), the sealed node seed (DPAPI on Windows, an owner-only file elsewhere; the panel says which), `overlay-state.json` and `overlay-audit.jsonl`. It follows `PEVV_DATA_DIR`. Nothing is created until the switch is on.
- **Pairing.** "Add a device" shows a one-time invite as QR and text; the other device pastes it under "Join a device". Both screens show six words; the inviting device approves only if they match. Removing a device stops direct sync with it at once and runs the vault-key rotation (needs the master password).
- **Window access.** The commands have their own `allow-transport-*` permissions in `capabilities/transport.json` (main window only). The webview CSP is unchanged: the networking is in the shell, not in the page.
- **Not yet.** An empty device cannot receive its first copy this way (it must already hold the vault); peers are not yet tied to roster entries; the extension does not use it. Untested on two real machines and on Linux. See the status list in TRANSPORT.md.
- **Tests.** `cargo test` (with and without the feature), `tests/unit/pevv.transferd.test.ts`.

## Auto-type into other programs

Press a global shortcut (default **Ctrl+Alt+A**, changeable in Settings, Auto-type into other programs) while any program is in front, pick a login in a small window, and PEVV types it there. Browsers have the extension for this; auto-type is for programs that have none: an SSH or RDP client, a VPN login, a desktop app.

How a press goes, and where each rule lives:

1. **Only while unlocked.** The hotkey is registered with `tauri-plugin-global-shortcut` when the vault unlocks and unregistered on every lock (the webview reports the state; the shell also drops it on its own lock events), and the handler checks the lock state again. The shortcut needs at least one of Ctrl, Alt or Win, so it cannot swallow ordinary typing. Pressing it while PEVV's own window is in front does nothing.
2. **Context.** Rust reads the foreground window: Windows `GetForegroundWindow`, `GetWindowTextW`, `QueryFullProcessImageNameW` (and the process's integrity level); X11 `_NET_ACTIVE_WINDOW`, `_NET_WM_NAME`, `_NET_WM_PID` through x11rb. **Wayland**: there is no reliable way to learn which window has focus, so the app says so; the target is "unknown", every login that has an auto-type setting is offered, and picking one copies its password to the clipboard (the usual 30 s clear) instead of typing. (The global shortcut itself may not register under Wayland either; Settings shows the error.)
3. **Matching** happens in the webview, which holds the vault (`src/pevv/autotype.ts`). A login has an optional `autoType` field (`{ windows: string[], process?, sequence? }`): title patterns with `*` and `?`, case-insensitive, any one may match; an optional program name (`putty` = `putty.exe`); and a sequence, default `{USERNAME}{TAB}{PASSWORD}{ENTER}`, with `{TOTP}`, `{TAB}`, `{ENTER}`, `{DELAY n}` (10 s each, 30 s in all) and `{{}` / `{}}` for literal braces. A login with no `autoType`, or with no patterns and no program, never matches; **a URL or `site` alone never matches a window**. The field is optional data inside the sealed entry: older clients ignore it and keep it through their own edits (tested), so the vault format does not change.
4. **Always confirmed.** A small always-on-top window (`autotype`, no taskbar button, `focusable: false` so it never takes focus from the target) names the target window and program and lists the matching entries by title and user name; nothing is typed until you click one. It is a separate webview with no vault access: it only receives the titles the vault window sent it. It is mouse-only (it cannot take keystrokes without taking focus).
5. **Re-check, then type.** The target window handle, process id and executable path are remembered when the key is pressed. Before the first key and before every later step (so also after every `{DELAY}`) the foreground window must still be that handle and process and must not be elevated, or the rest of the sequence is dropped and the chooser says why. A title change alone (a browser tab) does not abort. If a click did hand focus to the chooser, PEVV puts focus back on the remembered window first; the same check still has the last word.
6. **Typing.** Windows: `SendInput` with `KEYEVENTF_UNICODE`, so the text does not depend on the keyboard layout (Tab and Enter as virtual keys); every injected event carries `dwExtraInfo = 0x50455656` ("PEVV") so it can be told from real input; it waits up to 3 s for Ctrl, Alt, Shift and Win to be released first (the shortcut itself uses some). X11: XTEST through x11rb; a character the layout lacks is typed by borrowing a spare keycode for a moment and handing it back (X11 has no extra-info field, so these events cannot be marked). No key, character or sequence is ever logged: `Action`'s `Debug` prints lengths, and error messages never contain typed text. Requests are bounded (256 steps, 8192 characters, only Tab and Enter as keys).
7. **Elevated and security windows.** Windows (UIPI) drops input aimed at a window of higher integrity than PEVV, and a UAC prompt lives on the secure desktop. PEVV compares the target's integrity level with its own, treats a process it cannot even query as elevated, and reports "that window runs as administrator ... nothing was typed" instead of pretending; with no foreground window at all (secure desktop, lock screen) it says there is no window.

The activity log gets a line per use (entry id and "typed into another program"), never a value. The settings (`enabled`, `hotkey`) are in `autotype.json` in the app data folder, not in the vault. If "Lock when the app goes to the background" is on, keep the PEVV window open behind your other programs (not minimised): a hidden window locks the vault and the shortcut with it.

Tested (`cargo test`, `tests/unit/pevv.autotype.test.ts`): sequence parsing and its limits, glob and program matching, URL-never-matches, field resolution with an RFC 6238 one-time-code vector, the model round trip through a real sealed vault and the older-client edit path, the webview wiring against a fake shell, the Rust request validation, the **target-changed abort with a mocked platform layer** (different handle, different process, a window that changes between steps or during a delay, elevated, no window, modifiers held, typing unsupported), the pending-request state machine (stale ids refused, one confirmation types once, expiry), hotkey validation. The Linux module type-checks and lints for `x86_64-unknown-linux-gnu`. **Not tested**: the real `SendInput` and XTEST typing (it would type into a real window), the integrity check against a real elevated window, clicking the non-focusable chooser on each desktop, the hotkey on a real Linux session, Wayland.

## Command line: `pevv`

`pevv` is a third binary in this package, installed next to `pevv-desktop`. The NSIS installer adds the install folder to the user's PATH (`pevv-desktop.exe --add-path`, undone by `--remove-path` on uninstall; it edits `HKCU\Environment\Path` as REG_EXPAND_SZ and leaves it alone if it cannot read it); on Linux the .deb installs it with the other binaries. It needs the app to be running and unlocked.

```
pevv run [--project NAME | --env ID]... -- <command> [args]        run with the vault's variables added; exit code passed through
pevv env [--project NAME | --env ID]... --format dotenv|json|sh|ps  print to stdout (the app asks every time)
pevv status      prints locked / unlocked (exit 0 unlocked, 4 locked)
pevv lock        locks the vault now
```

Variables come from the vault's existing concepts (`src/pevv/cli.ts`): an environment is one of `meta.environments` and its variables are the `env` items; `--project NAME` is the program id `project:NAME` and uses the environment linked to it (Settings, Project environments; `vault env link`), else the active one, exactly like `envForProgram`; `--env ID` names an environment directly; with no option the active environment is used. Several sources merge in order (projects, then environments) and the later one wins a clash. The child's environment is the parent's plus the vault's, **the vault wins**, and each replaced name is warned about on stderr (names only). `run` never prints a secret and passes the child's exit code through (128 + signal on Unix). `pevv`'s own exit codes: 2 usage, 3 app not running, 4 locked, 5 declined, 1 anything else.

Protocol: the same local channel as the browser link (`link_ipc.rs`, same framing), with `"client": "cli"` in the request (`cli_proto.rs`); the browser link is untouched.

- **Who is calling is decided by the OS, not the tool.** The app asks the channel for the client's process id (`GetNamedPipeClientProcessId`, `SO_PEERCRED`), reads that process's executable path and SHA-256, and ignores anything the tool says about itself. The first time each executable path connects, the app asks "Allow a program to use PEVV?" and shows the path; path and hash are kept in `cli-access.json` in the app data folder (paths, hashes and command lines only, never a value) and can be revoked in Settings, Command line (pevv). The same path with a different file (an update, a replaced binary) is asked again. An approval alone gives no secret.
- **`status` and `lock`** need only that approval. **`secrets`** (`run` and `env`) needs the vault unlocked and, every time, an answer in the app: a popup with the command line and working folder (`run`) or the output format (`env`), where the variables come from, the variable **names** (never values) and the requesting program. `run` can be allowed **for 8 hours** for exactly that program (path and hash), command line, working folder, sources and set of variable names; change any of them and it asks again; allowances are listed in Settings with Revoke. `env` prints secrets, so it has no allowance and always asks. One question at a time; no answer in 2 minutes is a "no".
- The values are picked by the unlocked vault window (a `cli-env` request, answered in `src/pevv/desktop/link.ts` and never available to the browser extension, whose request kinds are whitelisted in Rust) and travel on to the tool only after the yes, over the owner-only pipe or socket. The popup, the settings file and the activity log carry names and the program's file name only (the log line is "npm - 3 variable(s)", written for every hand-over, including ones under an 8 h allowance).

Tested (`cargo test`): argument parsing and limits, the wire messages, the four `env` formats and their quoting, merging (vault wins, only changed values reported, case-insensitive names on Windows), a real child process that sees the variable and whose exit code comes back, refusals printing a reason and no secret, the app-side policy with a fake UI (first-contact approval, changed-binary re-ask, refusal, locked, popup content without values, the 8 h allowance's binding and expiry with a fake clock, `env` always asking, revocation, one question at a time, persistence without secrets), the PATH editing, and a real pipe round trip where the app identifies this test program by its OS process id and hash. Webview side (`tests/unit/pevv.cli.test.ts`): which variables a project, an environment or nothing selects, merge order, errors. **Not tested**: the popup and Settings UI in a real window, the installer's PATH change, Ctrl+C while a child runs, a Linux socket.

Security decisions: no shared secret for the tool (anything a user's own process could read from disk is no secret from that user's other processes); identity is the OS-reported path plus content hash, and every sensitive request still needs an interactive yes; names, not values, are shown, stored and logged; `env` and the first call of each program always ask; revocation is immediate.

## Windows passkey provider (PEVV as a passkey manager)

PEVV can be one of the places Windows 11 keeps passkeys. A site asks for a passkey, the Windows dialog lists "PEVV", and the passkey is made and kept in the vault; later the same dialog signs in with it, in any browser or app. Everything here is behind the cargo feature **`win-passkey-provider`** (off by default), works only from an **MSIX install on Windows 11**, and **has never run**: it was written on Windows 10, from the SDK headers, with no Windows 11 machine. Treat it as a first draft that compiles, passes its unit tests and matches the headers, not as a working feature.

### Research: what the Windows API is, and what could not be confirmed

Sources: the Windows SDK 10.0.26100.0 headers (`webauthnplugin.h`, `pluginauthenticator.h/.idl`, `webauthn.h`), Microsoft's public header mirror `github.com/microsoft/webauthn` (headers, IDL, README), the Microsoft Learn reference pages for `webauthnplugin.h`, the Learn "Passkeys" overview, the `windows` crate sources (0.61.3) and, for how a shipping provider packages and registers itself, the open source Bitwarden desktop client (`apps/desktop/desktop_native/win_webauthn`, its AppX manifest and COM server).

Confirmed to exist (header text read, not guessed):

| thing | where |
|---|---|
| `WebAuthNPluginAddAuthenticator(options, &response)` and `WebAuthNPluginFreeAddAuthenticatorResponse`; `...AddAuthenticator2` with `pwszUserVerificationKeyName` | `webauthnplugin.h`. Options: name, CLSID, optional logos (base64 SVG 1.1, light and dark), CTAP `authenticatorGetInfo` CBOR, list of supported RP ids (empty = all). The response carries `pbOpSignPubKey`, the key Windows signs requests with. |
| `WebAuthNPluginRemoveAuthenticator(clsid)`, `WebAuthNPluginGetAuthenticatorState(clsid, &state)` (`Disabled = 0`, `Enabled = 1`), `WebAuthNPluginUpdateAuthenticatorDetails(2)` | same |
| `WebAuthNPluginAuthenticatorAddCredentials / RemoveCredentials / RemoveAllCredentials / GetAllCredentials`: account metadata (credential id, rp, user) Windows keeps for its account lists and browser autofill | same |
| `WebAuthNPluginPerformUserVerification(2)` (Windows Hello for the plugin), `...GetUserVerificationPublicKey`, `...GetOperationSigningPublicKey`, `WebAuthNPluginRegisterStatusChangeCallback` | same |
| `WebAuthNDecodeMakeCredentialRequest` / `...GetAssertionRequest` / `WebAuthNEncodeMakeCredentialResponse` / `...GetAssertionResponse` | same (Windows' own CTAP CBOR helpers; PEVV does not use them: the brief was `ciborium` in Rust) |
| COM interface **`IPluginAuthenticator`**, IID `d26bcf6f-b54c-43ff-9f06-d5bf148625f7`: `MakeCredential(request, response)`, `GetAssertion(request, response)`, `CancelOperation(cancelRequest)`, `GetLockStatus(&status)`. The request holds `hWnd`, `transactionId`, a request signature, `requestType` (1 = CTAP2 CBOR) and the encoded CTAP request; the response is a CoTaskMemAlloc'd byte string. | `pluginauthenticator.idl` |
| An earlier, experimental generation of all of this (`EXPERIMENTAL_*` in `webauthn.h`, interface `e6466e9a-...` with three methods, CLSID passed as a string) from Insider builds. | `webauthn.h`, `pluginauthenticator.idl` |
| Error to DOM mapping: `NTE_EXISTS` = InvalidStateError, `NTE_INVALID_PARAMETER` = NotSupportedError, `NTE_USER_CANCELLED` / `NTE_NOT_FOUND` / `ERROR_TIMEOUT` = NotAllowedError | `webauthn.h` (`WebAuthNGetErrorName`) |
| `makeappx.exe` and `signtool.exe` in this SDK (`Windows Kits\10\bin\10.0.26100.0\x64`) | file system |

The `windows` crate 0.61.3 has **no bindings** for any of this (searched its sources), and this SDK's `webauthn.lib` exports none of the final names. So `src/provider_win.rs` declares the structs and the one COM interface by hand, copied from the headers, and finds the functions with `GetProcAddress` at run time. Two unit tests pin the struct sizes and field offsets to the C layout, and the IIDs.

Version and packaging, as far as it is known:

- **Minimum build.** The Microsoft header mirror says `...AddAuthenticator2`, `...PerformUserVerification2` and `...UpdateAuthenticatorDetails2` arrived with builds 26200.8524 and 26100.8524 (KB5089573), i.e. Windows 11 24H2 / 25H2 with updates. Bitwarden's wrapper says the plugin API shipped in the Windows 11 "November 2025 update". The exact KB for the first (version 1) functions was **not found**. PEVV uses **build 26100 (24H2)** as the floor for showing the section and then asks the only reliable question: do `WebAuthNPluginAddAuthenticator` and `WebAuthNPluginGetAuthenticatorState` resolve. It calls the version 1 function, which every build with the API has.
- **Which DLL.** The Learn reference pages say `WebAuthnPlugin.dll` / `WebAuthnPlugin.Lib`; the shipping Bitwarden code loads the same names from `webauthn.dll`. PEVV tries `webauthn.dll`, then `WebAuthnPlugin.dll`, both from the system folder only.
- **Package identity.** The plugin model hands requests to a COM class the package declares, so a packaged (MSIX) app is how every shipping provider does it, and PEVV refuses to register unless it has package identity. Whether the OS itself refuses an unpackaged registration was **not confirmed**; Microsoft's own article on writing a plugin passkey manager could not be fetched (the search index returned only the reference pages).
- **Manifest.** The only extension Bitwarden's manifest declares for the passkey plugin is `windows.comServer` (`com:ExeServer` with a `com:Class`), plus `runFullTrust`. `windows/msix/AppxManifest.xml` does the same. **Any other manifest element Microsoft's documentation may require was not confirmed**; Windows learns of the authenticator from the registration call, not from the manifest.
- **How the person turns it on.** The Learn passkeys overview says passkeys are managed under Settings > Accounts > Passkeys and that plugin passkey managers are a supported model. The page "Advanced options" and the toggle wording are from the brief and were not confirmed on a real machine. PEVV cannot switch itself on; `WebAuthNPluginGetAuthenticatorState` tells it whether you did.

Not confirmed, and built defensively:

- Whether `pbEncodedRequest` starts with the CTAP command byte. `provider_core::decode_*` accepts both (a CBOR map starts `0xa0..0xbf`, a command byte is `0x01` or `0x02`).
- Whether a response needs a leading CTAP status byte. None is written: `{1: "none", 2: authData, 3: {}}` for make, `{1: {id, type}, 2: authData, 3: signature, 4: {id, name}}` for get, as bare CBOR maps. If Windows rejects them, the fix is one byte in `encode_*_response`.
- Whether the `authenticatorGetInfo` PEVV registers (`provider_core::authenticator_info`: FIDO_2_0 and FIDO_2_1, the AAGUID, `rk`/`up`/`uv` true, transport `internal`, ES256) is what Windows wants there.
- Request signatures. Windows signs each request with the key returned at registration; a careful plugin verifies it. **PEVV does not** (the key format is not documented and a wrong guess would refuse every request). Every request still needs the unlocked vault and a click in the PEVV window, so a stray COM call cannot sign anything silently. Decision for the owner below.
- The Windows Hello plugin user-verification flow (`WebAuthNPluginPerformUserVerification`) is declared in the header but **not used**: PEVV asks with its own confirmation card. The authenticator data says "user verified" only because the vault was unlocked (master password, passkey or USB key) and you clicked.
- Backup flags: new credentials are marked backup-eligible and backed-up (BE and BS), as they live in a vault file that can sync. If you never sync the vault this is slightly generous. Change `FLAG_BE`/`FLAG_BS` in `passkeyProvider.ts` if you disagree.
- Whether Windows needs the account metadata (`passkey_provider_sync`) to list PEVV passkeys or only for browser autofill. It is sent either way; a name and a user name are what Windows keeps, never a key.

### The data model

A passkey PEVV makes for another site is a vault item with **`type: 'passkey'`**, sealed like every other entry (`src/pevv/model.ts`, `src/pevv/passkeyProvider.ts`). Fields, all optional data inside the sealed JSON: `rpId`, `rpName`, `credentialId` and `userHandle` (base64url), `userName`, `userDisplayName`, `passkeyPrivateKey` (PKCS#8 P-256, base64url, **inside the encrypted item, like a password**), `passkeyPublicKey` (the 65-byte point), `signCount`, and the usual `created`. There is no vault format change.

- **Older clients.** The vault file validates and decrypts exactly as before; an older client keeps the item through its own edits (it spreads fields it does not know) and, because every list, matcher, auto-type and login path selects by `type`, it never offers the item as a login. A client from before this change still lists it in "All items" as an unfamiliar entry titled `<site> (passkey)` with a blank type icon; it shows no key and cannot use it. (Tested here for the current code and for a future unknown kind.)
- **This client.** The item list, search, "All items" count, terminal `vault ls` and `vault get` skip passkey items; they are managed under Settings, Passkeys for other sites (Windows). Deleting one deletes the key.
- **The crypto** is WebCrypto in the webview, which already holds the vault: ES256 key generation, ECDSA signing (raw `r||s` turned into ASN.1 DER), authenticatorData (rpIdHash, flags, 4-byte big-endian counter, attested credential data with the PEVV AAGUID and the COSE key `{1:2, 3:-7, -1:1, -2:x, -3:y}`) and attestation `none`. The counter is saved before the signature is returned.
- **Fixed ids.** AAGUID `661cf2bd-74e1-42fd-93d3-7e2ed09cf977` (in `passkeyProvider.ts` and `provider_core.rs`, compared by a test) and the COM class id `56b40049-0a16-42c3-bded-1de50937b256` (in `provider_core.rs` and `AppxManifest.xml`, compared by a test). Both were generated once and must never change for a shipped build.

### The request path (feature `win-passkey-provider`)

```
website -> browser -> Windows passkey dialog -> "PEVV" ->  IPluginAuthenticator (COM, MTA thread in pevv-desktop.exe)
   src/provider_win.rs   COM class, registration FFI, struct layouts            (Windows, feature)
   src/provider_core.rs  ciborium decode of the CTAP request, checks on the answer, ciborium encode of the response (any OS, feature)
   src/provider.rs       Tauri glue: emits `passkey-provider-request`, waits for `passkey_provider_respond`
 -> webview (src/pevv/desktop/provider.ts, PasskeyProvider.tsx): the unlocked vault, a confirmation card, passkeyProvider.ts crypto
```

- The class factory is registered at app start (`CoRegisterClassObject`, multi-use, own MTA thread) only when the process has package identity. If PEVV is not running, Windows starts it from the manifest's `ExeServer` entry; if it is running, Windows uses that copy.
- **Locked vault:** the broker brings the PEVV window forward and waits up to 2 minutes for you to unlock, then refuses (`ERROR_TIMEOUT`, a NotAllowedError). A malformed request never wakes the window.
- **Confirmation:** the webview shows "Save a passkey in PEVV?" (create) or "Sign in to `<site>` with PEVV?" (with a picker when several accounts exist). Declining returns `NTE_USER_CANCELLED`. Windows cancelling a request closes its card.
- **Checks in Rust on what the webview returns:** the authenticatorData must be for the requested rp (SHA-256 of the rp id), carry the right flags and the PEVV AAGUID, and name exactly the credential id it claims (create); for sign-in it must be 37 bytes, not registration data, with a plausible signature and a credential in the request's allow list. Anything else fails the request.
- **Duplicates:** a credential in the request's exclude list that PEVV already holds for that site returns `NTE_EXISTS` (InvalidStateError). Only ES256 is offered; a request without it returns `NTE_INVALID_PARAMETER`.
- **Windows side effects** (never at build, test or start): "Add PEVV to Windows" in Settings calls `WebAuthNPluginAddAuthenticator` (name "PEVV", the AAGUID in the GetInfo, the logo `windows/pevv-passkey-logo.svg`, all relying parties); "Remove PEVV from Windows" calls `WebAuthNPluginRemoveAuthenticator`; the vault window pushes account names (no keys) with `passkey_provider_sync` when the passkey list changes.

New commands (listed in `capabilities/default.json`; they exist, and answer honestly, in builds without the feature): `passkey_provider_support`, `passkey_provider_register`, `passkey_provider_unregister`, `passkey_provider_respond`, `passkey_provider_sync`.

### Packaging (MSIX)

`desktop/src-tauri/windows/msix/AppxManifest.xml` (identity, `runFullTrust`, `windows.comServer` for the class id above, MinVersion 10.0.26100.0) and `build-msix.ps1`:

```powershell
npm run build:desktop-web
npx tauri build --no-bundle --features win-passkey-provider        # release exe with the web UI embedded
pwsh desktop/src-tauri/windows/msix/build-msix.ps1 -Publisher "CN=Your Name, O=Your Org, C=XX"
# signing, with a certificate YOU supply (the script never creates or imports one):
pwsh desktop/src-tauri/windows/msix/build-msix.ps1 -Publisher "<the certificate's exact Subject>" -PfxPath path\to\cert.pfx -PfxPassword (Read-Host -AsSecureString)
```

The script finds `makeappx.exe` (and `signtool.exe` for `-PfxPath`) in the newest Windows SDK, stages `pevv-desktop.exe`, `pevv.exe`, `pevv-native-host.exe` and three icons under `desktop/src-tauri/target/msix/layout`, fills the manifest and writes `target/msix/PEVV_<version>_x64.msix`. **Signing:** an MSIX only installs when signed by a certificate the PC trusts, and the manifest's `Publisher` must equal the certificate's Subject exactly. For your own PC that means your own code-signing certificate (trusted in "Trusted People" or the Root store, or a real CA certificate); PEVV's repository holds none and the script makes none. The MSIX is a **separate** install from the NSIS/MSI one: its own identity and update path, and very likely its own redirected app data (not checked): do not expect the vault of the NSIS install to appear in it, move it with an encrypted export. The `pevv` command-line tool's PATH hook and the browser-extension registration are installer steps and are not part of the MSIX; the in-app "Browser extension link" registration still works from the package.

### Settings section

Settings, "Passkeys for other sites (Windows)": the four requirements (Windows 11 24H2+ with this PC's build, MSIX install, a build with the provider, switching it on in Windows Settings > Accounts > Passkeys > Advanced options), the registration state, **Add PEVV to Windows** / **Remove PEVV from Windows**, and the list of passkeys PEVV holds with **Delete**. It is not shown on Linux or on Windows older than build 26100 (`sectionVisible` in `provider.ts`); on Windows 11 it shows what is missing, including "this build was made without the passkey provider".

### Tested, and not

Tested: `tests/unit/pevv.passkeyProvider.test.ts` (rpIdHash, COSE key and DER signature against known vectors including the RFC 6979 P-256 signature, authenticatorData layout, create then verify, counters, the request handler with a fake vault: locked, declined, excluded, wrong site, allow list, chooser, malformed; the item riding through a real sealed vault and being invisible to lists, login matching, auto-type, reuse and the item list; the AAGUID equal in the Rust file; section visibility) and `cargo test` with and without the feature (`provider_core`: request decode for both commands, with and without a command byte, size and shape limits, response encoding, GetInfo, HRESULT mapping, the broker end to end with a fake window including locked, cancelled and lying answers, the manifest naming the class id; `provider_win`: struct layouts, IIDs, the logo; `provider`: build parsing, the reason line, JSON names). **Not tested, because they need Windows 11 and an MSIX install:** that the functions exist on a real build, registration, the COM class being created by Windows, the real request bytes (command byte, any status byte), the response being accepted, the Windows dialog, the toggle in Settings, activation by Windows when PEVV is not running, installing the MSIX, signing (`build-msix.ps1` was run once, unsigned, against a build without the feature: `makeappx pack` accepted the manifest and wrote `target/msix/PEVV_0.1.0.0_x64.msix`), and the Linux compile of the feature (the D-Bus system library was not available where it was written; the feature code is platform-neutral except `provider_win.rs`).

## Updates

The desktop app looks for a new release when it starts and once a day (Settings > Updates has a switch for the automatic check and a
"Check now" button). What happens when one is found is the **update mode** in Settings > Updates (English and Spanish):

| Mode | Behaviour |
|---|---|
| Manual (default) | Tells you with an "Update now" / "Later" card. Nothing is downloaded or installed until you press "Update now". |
| Auto-download | Downloads and verifies in the background, then shows "Restart to update" / "Later". It installs only when you press the button. |
| Auto-download and install | Downloads and installs in the background with no prompt, but only while the vault is **locked** (or none exists). With the vault unlocked, in the second-factor step or in setup it waits and installs when the vault locks (on Windows closing the window locks it), so a restart never interrupts an edit. Installing as PEVV quits is not implemented yet. |

The signature is checked in every mode: the shell verifies it when downloading and again before installing, and a package that fails is dropped.

How it stays safe:

- The Rust shell (`src/updater.rs`, `tauri-plugin-updater`) fetches `https://github.com/LoopyLuci/pevv/releases/latest/download/latest.json` and
  verifies the minisign signature of the installer against the `pubkey` in `tauri.conf.json` (`plugins.updater`). The check cannot be
  turned off and a bad signature is refused. The webview has no updater plugin permission: its restricted capability allows only the
  three commands `update_enabled`, `update_check` and `update_install` (`capabilities/default.json`).
- The updater is disabled at run time while the pubkey is the placeholder `REPLACE_WITH_UPDATER_PUBKEY`: no request is made.
- Only the Windows NSIS installer and the Linux AppImage are listed in `latest.json`. The MSI and deb are not auto-updated.

### Maintainer steps (once)

1. Generate the signing key pair: `npx tauri signer generate -w <path-outside-the-repo>/pevv-updater.key` (choose a password).
   Keep the private key and password out of the repository and back them up: losing them means installed apps can never update again.
2. Set two repository secrets: `TAURI_SIGNING_PRIVATE_KEY` (the key file's contents) and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.
3. Put the public key (the contents of `pevv-updater.key.pub`, one line) into `desktop/src-tauri/tauri.conf.json` as `plugins.updater.pubkey`.
4. Tag a release. The `release` workflow signs the NSIS and AppImage installers (`*.sig`), writes `latest.json` with `scripts/make-latest-json.mjs` and
   attaches both to the draft release. Publish the draft: the endpoint above serves the latest *published* release.

Without the two secrets (forks, local builds) the build skips the signatures and no `latest.json` is made. Changing the key later strands
apps that carry the old one: they must be reinstalled by hand once.

## Build and install

Needs Node 20+, Rust stable and the platform toolchain for Tauri 2 (Windows: MSVC build tools and WebView2, which Windows 11 has; Linux: `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `libssl-dev`, `build-essential`, `patchelf`; D-Bus access uses the pure-Rust zbus, no libdbus needed).

```bash
npm ci
npm run build:desktop-web   # vite build of the PEVV screen -> dist-desktop/
npm run desktop:dev         # vite on :1421 and a Tauri window
npm run desktop:build       # web build, then the installers (VITE_PEVV_SYNC_URL / PEVV_RP_ID are read from the environment)
cd desktop/src-tauri && cargo test && cargo clippy --all-targets -- -D warnings
cd desktop/src-tauri && cargo test --features win-passkey-provider   # the Windows passkey provider (off by default)
cd desktop/src-tauri && cargo test --no-default-features             # without the Transferd device link (on by default)
```

Bundles (`desktop/src-tauri/target/release/bundle/`): `nsis/PEVV_0.2.0_x64-setup.exe` and `msi/PEVV_0.2.0_x64_en-US.msi` on Windows; `appimage/` and `deb/` on Linux (build those on Linux). Icons live in `desktop/src-tauri/icons/` (regenerate from a 512 px PNG with `npx tauri icon <png> -o desktop/src-tauri/icons`). The installers are not code-signed yet, so Windows SmartScreen warns on first run.

## Limitations

- New passkeys for unlocking PEVV cannot be created in the app (enrolment is in the web app). Native passkeys and the USB / presence features are untested on real hardware. The Windows passkey provider (above) is a different thing, passkeys for other sites, and is untested on any real Windows 11 machine.
- Passkeys made under another rpId (localhost, preview deploys) do not unlock here.
- No browser autofill from the desktop app itself; use the extension, linked to the app (Browser extension link above). Auto-type is for other programs; it types nothing on Wayland (clipboard instead) and nothing into elevated windows.
- `pevv` is approved by path and file hash. If it sits in a folder other programs can write to, one of them could replace it; the app then asks again, because the hash changed.
- Linux lock signals depend on logind / the desktop's screensaver service and are best effort; the idle timer is the fallback. Linux tray icons need an AppIndicator-capable shell (GNOME needs an extension), so closing the window quits there.
- Unsigned installers; no auto-update.
- macOS is not built.

## Planned

- Verify the Windows passkey provider on Windows 11 (see its list of unconfirmed points), then decide on request-signature verification and the Windows Hello plugin user-verification flow.
- `passkey_create` on Windows so new passkeys with the web app's rpId and PRF can be made in the app.
- Code signing and an update channel.
- Biometric quick unlock with the OS keystore, as on Android.

## Separate data folder (`PEVV_DATA_DIR`)

Set `PEVV_DATA_DIR` to an absolute folder to run a separate copy, for testing or as a portable copy. Everything the app writes then goes there instead of `%APPDATA%\PEVV` / `~/.local/share/pevv`:

- the vault and its backups
- settings, the browser-link pairing, `pevv` approvals and presence
- the webview profile

Window state is not saved. Browser-link registration goes under `HKCU\Software\Luciverse-PevvPortable` (Windows) or `<dir>/config` (Linux), so the real browsers are untouched. The IPC pipe and single-instance names do not change, so do not run an override copy while the installed app is running.

WebView2 form autofill and password autosave are turned off, because they would store typed field values in the webview profile in plaintext.
