-- PEVV optional sync backend. Run once in your own Supabase project (SQL editor or `supabase db push`).
-- Holds ONLY ciphertext: the encrypted vault file, which is useless without the master password
-- (or another unlock factor) that never leaves the devices. No secrets, no service-role keys.

-- 1. One opaque row per user and path ---------------------------------------------------------------
create table if not exists public.pevv_blobs (
  user_id    uuid        not null default auth.uid() references auth.users (id) on delete cascade,
  path       text        not null check (path in ('/vault/pevv.vault.json', '/vault/pevv-handoff.json')),
  body       text        not null check (char_length(body) <= 262144),
  updated_at timestamptz not null default now(),
  primary key (user_id, path)
);

alter table public.pevv_blobs enable row level security;
alter table public.pevv_blobs force row level security;

-- Own rows only. The anon (not signed in) role gets nothing.
create policy "pevv_blobs select own" on public.pevv_blobs for select to authenticated using ((select auth.uid()) = user_id);
create policy "pevv_blobs insert own" on public.pevv_blobs for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "pevv_blobs update own" on public.pevv_blobs for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "pevv_blobs delete own" on public.pevv_blobs for delete to authenticated using ((select auth.uid()) = user_id);

revoke all on public.pevv_blobs from anon, public;
grant select, insert, update, delete on public.pevv_blobs to authenticated;

create or replace function public.pevv_touch() returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create trigger pevv_blobs_touch before update on public.pevv_blobs
  for each row execute function public.pevv_touch();

-- 2. Realtime relay for the vault QR and the live device exchange -----------------------------------------
-- Private broadcast channels named `pevv:<token>` (vault QR) and `pevv:d:<vaultId>` (paired devices).
-- The clients sign in anonymously on a separate session just to open these sockets. The names are
-- random and unguessable and the payload is ciphertext; the decryption key stays in the QR code.
-- Needs Authentication > Providers > "Allow anonymous sign-ins", and Realtime "Allow public access" OFF.
do $$
begin
  if to_regclass('realtime.messages') is not null then
    execute $p$create policy "pevv rt read" on realtime.messages for select to authenticated using (
      (select realtime.topic()) like 'pevv:%')$p$;
    execute $p$create policy "pevv rt write" on realtime.messages for insert to authenticated with check (
      (select realtime.topic()) like 'pevv:%' and extension = 'broadcast')$p$;
  end if;
end $$;
