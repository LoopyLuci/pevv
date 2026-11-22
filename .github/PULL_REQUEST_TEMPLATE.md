## What and why

<!-- One focused change. Link the issue it closes. -->

## Checklist

- [ ] `npm run lint`, `npm run typecheck`, `npm test` pass (and `npm run build` / `build:extension` if touched)
- [ ] Rust changes: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` pass
- [ ] New or changed behaviour has tests; docs and `docs/CHANGELOG.md` updated
- [ ] Vault format unchanged, or the change is backward compatible and documented (`docs/VAULT_FORMAT.md`)
- [ ] No secrets, real vaults, personal data, machine paths or hard-coded endpoints/keys
- [ ] Commits are Conventional Commits and signed off (`git commit -s`)

## Security impact

<!-- Does this touch crypto, key handling, storage, fill logic, IPC or the network? Say how it stays safe. "None" is fine. -->
