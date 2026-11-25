# Sync and relay: self-hosting the optional backend

PEVV works fully offline with no server. **Sync is off unless you build the app with a backend configured.**
The backend is a Supabase project that you own. It stores only ciphertext and never sees a key.

What it does, and what it does not do:

| Feature | Needs the backend | Notes |
|---|---|---|
| Vault on one device, export/import files, offline QR codes | no | Works with no network access at all. |
| **Sync** (the encrypted vault file copied between your devices, opt-in in Settings) | yes | Table `pevv_blobs`, one row per signed-in user and path. |
| **Vault QR** (short code, fast transfer) | yes | Supabase Realtime private broadcast channels `pevv:<token>`. Without a backend the QR shows offline codes instead. |
| **Live device exchange** (paired devices open at the same time swap the encrypted file) | yes | Realtime channel `pevv:d:<vaultId>`. |

## What the server can and cannot see

- It stores `VaultFile` JSON: AEAD ciphertext, KDF parameters, wrapped-key slots and a plaintext revision number
  ([VAULT_FORMAT.md](VAULT_FORMAT.md)). Titles, sites, usernames and secrets are all inside the ciphertext.
- It never receives the master password, the vault key, recovery codes, PRF outputs or a QR key (the key is in the QR code only).
- Someone who breaks into the database gets the same thing as someone who steals the vault file: they must still brute-force the
  master password through Argon2id.
- The server does learn: the account email (magic-link sign-in), when you sync, the vault size and revision.

## 1. Create the Supabase project

1. Create a project at <https://supabase.com> (or run Supabase yourself).
2. **Authentication > Providers**: keep Email on (magic links) and turn on **Allow anonymous sign-ins** (the vault-QR relay opens its
   sockets with an anonymous session that is separate from your sync account).
3. **Authentication > URL configuration**: set *Site URL* to the address you host the web app on, and add it to *Redirect URLs*
   (the magic link returns there).
4. **Realtime > Settings**: switch **Allow public access** OFF (the policies below use private channels).
5. Run [`supabase/migrations/0001_pevv_sync.sql`](../supabase/migrations/0001_pevv_sync.sql) in the SQL editor
   (or `supabase db push` from this repo with the CLI linked to your project).

The migration contains no secrets and no service-role key. It creates `public.pevv_blobs` with row-level security (each user can read
and write only their own rows; the path is checked by the database) and the two Realtime policies for `pevv:%` topics.

Never put the **service-role key** into PEVV, a `.env` file in this repo, or a build. The browser only ever uses the project URL and the
**anon key**, which is public by design: row-level security is what protects the data.

## 2. Configure the build

PEVV reads these at **build time** (Vite `import.meta.env`). They are baked into the static files, so build once per backend.

| Variable | Meaning |
|---|---|
| `VITE_PEVV_SYNC_URL` | `https://<project-ref>.supabase.co`. Empty = sync and relay are off. |
| `VITE_PEVV_SYNC_ANON_KEY` | The project's anon (public) key. Both variables must be set, otherwise sync stays off. |
| `VITE_PEVV_PUBLIC_URL` | Optional. The public https address of your hosted web app. Vault QR links from the extension and desktop app point here (a phone cannot open `chrome-extension://` or `tauri://`). Without it the QR carries the bare code, which PEVV's scanner accepts. |
| `VITE_PEVV_BASE` | Optional. Sub-path when the web app is not served from `/`. |
| `PEVV_RP_ID` | Desktop shell only, read by `cargo`/`tauri build`: the host name of your web app (for example `pevv.example.com`) so passkeys enrolled there unlock the desktop app. Unset = native passkey unlock is reported unavailable. |

Copy `.env.example` to `.env.local` (git-ignored) and fill it in, or set the variables in your CI. Then:

```bash
npm run build                 # web app  -> dist/
npm run build:extension       # extension -> dist-extension/
npm run desktop:build         # desktop installers (the webview CSP gets your sync origin automatically)
```

Host `dist/` on any static host. Use [`public/_headers`](../public/_headers) as the starting point for security headers and replace the
`connect-src` Supabase wildcard with your own origin if you do not use `*.supabase.co`.

## 3. Passkeys and the rpId

A passkey registered in the web app is bound to the **host name** of the page that made it (its WebAuthn *rpId*). In the web app that
is simply `location.hostname`; there is nothing to configure. Moving the web app to another domain makes old passkeys unusable on the
new one (the master password, recovery codes and key files still work).

The desktop app unlocks with those passkeys through the operating system, so it has to know the rpId: build it with
`PEVV_RP_ID=pevv.example.com` (the same host name). The browser extension cannot use web-app passkeys (its origin is
`chrome-extension://<id>`).

## 4. Check it works

1. Open the web app on device A, create a vault, Settings > turn on **Sync the encrypted vault**, sign in with your email.
2. Open the web app on device B, "I already have a vault", sign in with the same email, "Check again".
3. In the Supabase table editor, `pevv_blobs.body` must be unreadable JSON (`"sealed":{"iv":..., "ct":...}`), never plaintext.

## Hardened schema

Also apply `supabase/migrations/0002_pevv_hardening.sql` (revision compare-and-swap, history, soft delete, rate limit, Realtime topic policies) and then `supabase/migrations/0003_pevv_no_size_cap.sql` (removes the size limit on the sealed vault: you sync your own vault, so it may be as large as it needs to be). What they do and how to test them: [SYNC.md](SYNC.md). Note that 0002 limits the live device lane to accounts that own a synced copy of the vault. Without 0003 the server refuses a vault above 262144 bytes and the clients report it. Limits that remain are yours to set: the request size limit of your API gateway or proxy and your plan's database size.

## Privacy and abuse notes

- Row-level security is forced on `pevv_blobs`; the anon role has no grants on it.
- The Realtime topics are unguessable random tokens, and messages are not stored. With migration 0002 a session needs a valid topic shape, and the live device lane needs a synced copy of that vault; the content is ciphertext. Rate-limit anonymous sign-ins in your Supabase auth settings.
- Deleting an account deletes its rows (`on delete cascade`).
- To disable sync again: rebuild without the two variables. Existing local vaults keep working.
