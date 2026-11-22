# Contributing to PEVV

Thanks for helping. PEVV protects people's secrets, so changes are reviewed carefully, and a small, well-tested change is easier to merge
than a large one. By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

**Security problems: do not open an issue or a pull request.** Report them privately, see [SECURITY.md](SECURITY.md).

## Setup

Requirements: Node.js 20+ (`.nvmrc` pins 22) and npm. For the desktop app: stable Rust and the
[Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/). On Ubuntu:

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev libdbus-1-dev libudev-dev libxdo-dev patchelf build-essential
```

```bash
git clone https://github.com/<you>/pevv.git && cd pevv
npm ci
```

## Commands

| Command | What it does |
|---|---|
| `npm run dev` | Web app dev server |
| `npm run lint` | ESLint |
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | Unit tests (Vitest, jsdom) |
| `npm run build` | Type-check and bundle the web app |
| `npm run build:extension` | Build the extension (`dist-extension/`, `dist-extension-firefox/`) |
| `npm run test:e2e` | Web e2e (Playwright; run `npm run build` first; needs `npx playwright install chromium`) |
| `npm run test:e2e:extension` | Extension e2e in Chromium (run `npm run build:extension` first) |
| `npm run build:desktop-web` | Desktop web bundle (needed before `cargo` can compile the desktop crate) |
| `cd desktop/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` | Rust checks |
| `npm run desktop:build` | Desktop installers |

## Tests

- New behaviour needs a test, written against real objects (real WebCrypto, the real store), not mocks of the thing under test.
- Unit tests: `tests/unit/pevv.*.test.ts`. Rust tests live next to the code (`#[cfg(test)]`).
- Anything touching the vault file, crypto or the extension/desktop protocols must keep **all existing tests passing unchanged**, and
  should add a round-trip test. Do not weaken or delete a test to make a change pass.

## Code style

- TypeScript strict mode, no `any` without a comment, no unused locals. Keep modules small and pure where possible; side effects live
  in `store.ts`, `host/` and the shells.
- Match the surrounding code (naming, comment density). Comments say *why*, not *what*.
- `.editorconfig` sets LF line endings, 2 spaces, final newline. Rust is formatted with `cargo fmt` (see `desktop/src-tauri/rustfmt.toml`).
- Never log, store or transmit secrets; never add network calls outside `src/pevv/host/`; never add telemetry.
- User-visible strings go in `src/pevv/i18n.ts` in **both** English and Spanish.
- Read the invariants in [AGENTS.md](AGENTS.md) before touching crypto, storage or fill logic. They apply to humans too.

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`, imperative, no trailing period.
Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `security`. Scopes: `crypto`, `vault`, `store`, `ui`, `extension`,
`desktop`, `sync`, `docs`, `ci`. Example: `fix(extension): refuse fills into cross-origin frames`.

## Sign-off (DCO)

Every commit must carry a `Signed-off-by` line, certifying the [Developer Certificate of Origin](https://developercertificate.org/):
that you wrote the change or have the right to submit it under this project's license (GPL-3.0-only).

```bash
git commit -s -m "fix(vault): reject a slot with an empty wrapped key"
```

## Pull request checklist

- [ ] One focused change; the description says what and why.
- [ ] `npm run lint`, `npm run typecheck` and `npm test` pass; `npm run build` and `npm run build:extension` pass if you touched them.
- [ ] Rust changes: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` pass.
- [ ] New or changed behaviour has tests; docs and `docs/CHANGELOG.md` updated.
- [ ] No vault-format change, or the change is backward compatible and documented in `docs/VAULT_FORMAT.md`.
- [ ] No secrets, personal data, machine paths or real vaults in code, fixtures, logs or screenshots.
- [ ] Commits are Conventional and signed off.

## Reporting bugs and proposing features

Use the issue templates. For a bug, say which client (web, extension, desktop), the browser/OS version and the steps. **Never paste a real
vault file, password or recovery code.** Larger features: open an issue first so we can agree on the approach.
