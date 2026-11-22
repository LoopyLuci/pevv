# Web app

The standalone web app: `index.html` -> `src/pevv/boot.tsx` -> `PevvStandalone` -> `VaultApp`. Static files, no server code.

```bash
npm run dev          # Vite dev server (http://localhost:5173)
npm run build        # type-check, then bundle to dist/
npm run preview      # serve dist/ locally
npm run test:e2e     # Playwright against `vite preview` on http://localhost:4183 (build first)
```

## What it does

- Create a vault, unlock with the master password, a PRF passkey or security key, a recovery code, a recovery kit or a USB key file.
- Second factors: authenticator (TOTP), passkey, USB key file.
- Items: logins, environment variables (per environment, `.env` import and export), API keys, notes, payment cards, SSH keys, identities.
- Generator, security health (local only, no breach lookups), activity log, device list.
- Move a vault: encrypted export file, offline QR codes, or the vault QR (needs the optional relay).
- Import from Bitwarden, 1Password, KeePass, LastPass, Dashlane, NordPass, Proton Pass, Firefox, Safari, Chrome, Edge and Brave CSV.
- English and Spanish.

## Storage

The ciphertext vault file is kept in `localStorage` under `lv-pevv-vault-v1` (key name kept for compatibility with existing vaults).
The key and all decrypted items exist only in memory while unlocked; the page locks on idle, on tab hide and on request.
Clearing site data deletes the vault from this browser: keep an export, a recovery kit or another synced device.

## Hosting

Serve `dist/` from any static host over HTTPS (WebAuthn and WebCrypto need a secure context). Send the headers in
[`public/_headers`](../public/_headers) (Cloudflare Pages and Netlify read that file as is). The policy forbids inline scripts, remote
scripts, frames and form posts, and limits network access to the page itself plus Supabase for the optional sync.

If you build with sync (`VITE_PEVV_SYNC_URL`), see [SYNC_SELF_HOSTING.md](SYNC_SELF_HOSTING.md). Passkeys are bound to the host name you
serve the app from; moving the app to another domain invalidates the passkeys made on the old one (other unlock methods still work).

## Deep links

`?pevvq=<code>` (and the same in the URL hash) starts a vault-QR transfer. The code is removed from the address bar right away.
