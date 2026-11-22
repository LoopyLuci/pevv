# PEVV documentation

| Document | What is in it |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Layers, the `host/` seam, data flow, repo map. Start here. |
| [VAULT_FORMAT.md](VAULT_FORMAT.md) | The vault file, associated-data bindings, compatibility rules. |
| [CRYPTO.md](CRYPTO.md) | KDFs, key slots, AES-GCM, WebAuthn PRF, TOTP, recovery, USB key file. |
| [DESIGN.md](DESIGN.md) | App behaviour, item types, the threat model, CSP and headers, hand-test checklist. |
| [CLIENT_WEB.md](CLIENT_WEB.md) | The web app: build, hosting, storage. |
| [CLIENT_EXTENSION.md](CLIENT_EXTENSION.md) | The browser extension (Chrome, Edge, Brave, Firefox) and its link to the desktop app. |
| [CLIENT_DESKTOP.md](CLIENT_DESKTOP.md) | The Tauri desktop app, native passkeys, auto-type, the `pevv` CLI, the Windows passkey provider. |
| [CLIENT_ANDROID.md](CLIENT_ANDROID.md) | Status of the Android app (future work). |
| [SYNC_SELF_HOSTING.md](SYNC_SELF_HOSTING.md) | Optional sync and vault-QR relay: Supabase setup, build-time configuration, passkey rpId. |
| [RELEASING.md](RELEASING.md) | Versions, tags, the release workflow, signing status. |
| [CHANGELOG.md](CHANGELOG.md) | History. |

Security policy and how to report a vulnerability: [../SECURITY.md](../SECURITY.md). Contributing: [../CONTRIBUTING.md](../CONTRIBUTING.md).
Rules for AI agents working in this repository: [../AGENTS.md](../AGENTS.md).
