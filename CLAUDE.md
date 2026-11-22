# CLAUDE.md

@AGENTS.md

The same rules apply to Claude Code as to every other agent. The short version, in case the import above is not followed:

- **What this is:** PEVV, a zero-knowledge vault. Web app (`index.html`), browser extension (`extension/`, `src/pevv/extension/`),
  Tauri desktop app (`desktop/src-tauri/`, `src/pevv/desktop/`). One engine in `src/pevv/`. The optional network layer is only `src/pevv/host/`.
- **Check your work:** `npm run lint && npm run typecheck && npm test`. Build checks: `npm run build`, `npm run build:extension`.
  Rust: `cd desktop/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` (run `npm run build:desktop-web` once first).
- **Never break:** vault format compatibility (do not touch `luciverse.pevv*` identifiers or `luciverse/pevv/v1/...` AAD / HKDF strings), the key
  never leaves memory, no plaintext at rest, exact-origin fills only, no network outside `src/pevv/host/`, strict CSP, no hard-coded
  keys or endpoints.
- **Do not:** commit, push or tag unless asked; read, print or write any real vault, `%APPDATA%\PEVV` data, tokens or `.env` files; weaken a test.
- **Where tests live:** `tests/unit/pevv.*.test.ts`, `tests/e2e/`, `tests/e2e-extension/`, and Rust unit tests inside `desktop/src-tauri/src`.
