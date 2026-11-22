# PEVV sync backend (optional)

`migrations/0001_pevv_sync.sql` is everything PEVV needs from a Supabase project: one table of encrypted
blobs with row-level security, and Realtime policies for the vault-QR relay. It stores ciphertext only.

Setup, configuration and the privacy properties are in [docs/SYNC_SELF_HOSTING.md](../docs/SYNC_SELF_HOSTING.md).
