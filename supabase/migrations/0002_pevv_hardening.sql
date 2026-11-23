-- PEVV sync backend hardening. Run after 0001 (SQL editor or `supabase db push`). Safe to run twice.
-- Still ciphertext only. What this adds (docs/SYNC.md, "Self-hosting the hardened schema"):
--   * compare-and-swap writes through public.pevv_put (a stale device gets the newer copy back instead of overwriting it)
--   * a monotonic server revision per blob, and for the vault blob a vault `rev` that can never go backwards
--   * the last N revisions of every blob (public.pevv_blob_history) and soft delete with public.pevv_undelete
--   * size caps and a per-user write rate limit, configurable in public.pevv_config
--   * pevv_blobs in the supabase_realtime publication, and Realtime topic access limited to the vault's owner
-- Old clients keep working: plain upserts and deletes still work, they just go through the same guards
-- (a delete becomes a soft delete, an upsert gets a server revision). Turn `strict_cas` on to refuse plain writes.

-- 1. Settings (not readable or writable by clients) -------------------------------------------------------
create table if not exists public.pevv_config (key text primary key, value text not null);
alter table public.pevv_config enable row level security;
revoke all on public.pevv_config from anon, authenticated, public;
insert into public.pevv_config (key, value) values
  ('history_keep', '20'),        -- revisions kept per blob
  ('max_body', '262144'),        -- bytes per blob
  ('rate_per_minute', '60'),     -- writes per user per minute
  ('strict_cas', 'false'),       -- true: refuse plain upserts, only public.pevv_put writes
  ('open_roster', 'false')       -- true: any signed-in session may use the `pevv:d:` live device lane (pre-0002 behaviour)
on conflict (key) do nothing;

create or replace function public.pevv_cfg(k text, d text) returns text
language sql stable security definer set search_path = ''
as $$ select coalesce((select value from public.pevv_config where key = k), d) $$;
revoke all on function public.pevv_cfg(text, text) from public, anon, authenticated;

-- 2. Columns on the blob table ----------------------------------------------------------------------------
alter table public.pevv_blobs add column if not exists rev bigint not null default 1;
alter table public.pevv_blobs add column if not exists doc_rev bigint not null default 0;
alter table public.pevv_blobs add column if not exists deleted_at timestamptz;
alter table public.pevv_blobs add column if not exists vault_id text;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'pevv_blobs_body_bytes') then
    alter table public.pevv_blobs add constraint pevv_blobs_body_bytes check (octet_length(body) <= 262144);
  end if;
end $$;

-- Fill the new columns for vault rows written before this migration (a row that is not valid JSON is left alone).
do $$
declare r record;
begin
  for r in select user_id, path, body from public.pevv_blobs where path = '/vault/pevv.vault.json' and vault_id is null loop
    begin
      update public.pevv_blobs set vault_id = (r.body::jsonb)->>'id', doc_rev = coalesce(((r.body::jsonb)->>'rev')::bigint, 0)
       where user_id = r.user_id and path = r.path;
    exception when others then null;
    end;
  end loop;
end $$;

-- 3. History ---------------------------------------------------------------------------------------------
create table if not exists public.pevv_blob_history (
  user_id  uuid        not null references auth.users (id) on delete cascade,
  path     text        not null,
  rev      bigint      not null,
  doc_rev  bigint      not null,
  body     text        not null,
  saved_at timestamptz not null default now(),
  primary key (user_id, path, rev)
);
alter table public.pevv_blob_history enable row level security;
revoke all on public.pevv_blob_history from anon, public;
revoke all on public.pevv_blob_history from authenticated;
grant select on public.pevv_blob_history to authenticated;
drop policy if exists "pevv_blob_history select own" on public.pevv_blob_history;
create policy "pevv_blob_history select own" on public.pevv_blob_history for select to authenticated using ((select auth.uid()) = user_id);

-- Only the guard trigger writes history (security definer, explicit user id, pinned search_path).
create or replace function public.pevv_archive(p_user uuid, p_path text, p_rev bigint, p_doc_rev bigint, p_body text) returns void
language plpgsql security definer set search_path = ''
as $$
declare keep int := greatest(1, least(500, coalesce(nullif(public.pevv_cfg('history_keep', '20'), '')::int, 20)));
begin
  insert into public.pevv_blob_history (user_id, path, rev, doc_rev, body) values (p_user, p_path, p_rev, p_doc_rev, p_body)
    on conflict (user_id, path, rev) do nothing;
  delete from public.pevv_blob_history h
   where h.user_id = p_user and h.path = p_path
     and h.rev <= p_rev - keep;
end;
$$;
revoke all on function public.pevv_archive(uuid, text, bigint, bigint, text) from public, anon, authenticated;

-- 4. Rate limit ------------------------------------------------------------------------------------------
create table if not exists public.pevv_rate (user_id uuid primary key references auth.users (id) on delete cascade, window_start timestamptz not null, hits int not null);
alter table public.pevv_rate enable row level security;
revoke all on public.pevv_rate from anon, authenticated, public;

create or replace function public.pevv_rate_hit(p_user uuid) returns void
language plpgsql security definer set search_path = ''
as $$
declare lim int := coalesce(nullif(public.pevv_cfg('rate_per_minute', '60'), '')::int, 60); h int;
begin
  insert into public.pevv_rate as r (user_id, window_start, hits) values (p_user, now(), 1)
  on conflict (user_id) do update
    set window_start = case when r.window_start < now() - interval '1 minute' then now() else r.window_start end,
        hits = case when r.window_start < now() - interval '1 minute' then 1 else r.hits + 1 end
  returning hits into h;
  if h > lim then raise exception 'pevv:rate-limited'; end if;
end;
$$;
revoke all on function public.pevv_rate_hit(uuid) from public, anon, authenticated;

-- 5. The guard: every write to pevv_blobs, whoever sends it -------------------------------------------------
create or replace function public.pevv_guard() returns trigger
language plpgsql security definer set search_path = ''
as $$
declare
  vault boolean := new.path = '/vault/pevv.vault.json';
  cap int := coalesce(nullif(public.pevv_cfg('max_body', '262144'), '')::int, 262144);
  parsed jsonb;
  doc bigint := 0;
  content boolean;
begin
  perform public.pevv_rate_hit(new.user_id);
  if octet_length(new.body) > cap then raise exception 'pevv:too-large'; end if;

  content := tg_op = 'INSERT' or new.body is distinct from old.body;
  if content then
    if public.pevv_cfg('strict_cas', 'false') = 'true' and coalesce(current_setting('pevv.via_put', true), '') <> '1' then
      raise exception 'pevv:cas-required';
    end if;
    new.vault_id := null;
    if vault then
      begin
        parsed := new.body::jsonb;
        doc := (parsed->>'rev')::bigint;
        new.vault_id := parsed->>'id';
      exception when others then
        raise exception 'pevv:bad-body';
      end;
      if new.vault_id is null or doc is null then raise exception 'pevv:bad-body'; end if;
    end if;
    new.doc_rev := doc;
  end if;

  if tg_op = 'INSERT' then
    new.rev := 1;
    new.deleted_at := null;
    return new;
  end if;

  if new.user_id <> old.user_id or new.path <> old.path then raise exception 'pevv:not-allowed'; end if;
  if content then
    -- A vault revision never goes backwards, except into a blob that was soft deleted (a fresh life).
    if vault and old.deleted_at is null and new.doc_rev <= old.doc_rev then raise exception 'pevv:rev-regressed'; end if;
    perform public.pevv_archive(old.user_id, old.path, old.rev, old.doc_rev, old.body);
    new.deleted_at := null;
  else
    new.doc_rev := old.doc_rev;
    new.vault_id := old.vault_id;
  end if;
  new.rev := old.rev + 1;
  return new;
end;
$$;

drop trigger if exists pevv_blobs_guard on public.pevv_blobs;
create trigger pevv_blobs_guard before insert or update on public.pevv_blobs
  for each row execute function public.pevv_guard();

-- A plain DELETE by the owner becomes a soft delete. System deletes (a deleted account cascades) really delete.
create or replace function public.pevv_soft_delete() returns trigger
language plpgsql set search_path = ''
as $$
begin
  if (select auth.uid()) is not null and old.user_id = (select auth.uid()) then
    update public.pevv_blobs set deleted_at = now() where user_id = old.user_id and path = old.path and deleted_at is null;
    return null;
  end if;
  return old;
end;
$$;
drop trigger if exists pevv_blobs_soft_delete on public.pevv_blobs;
create trigger pevv_blobs_soft_delete before delete on public.pevv_blobs
  for each row execute function public.pevv_soft_delete();

-- 6. RLS review: owner only, anon nothing (restated so a half-applied 0001 cannot leave a gap) ------------------
alter table public.pevv_blobs enable row level security;
alter table public.pevv_blobs force row level security;
revoke all on public.pevv_blobs from anon, public;
revoke all on public.pevv_blobs from authenticated;
grant select, insert, update, delete on public.pevv_blobs to authenticated;
drop policy if exists "pevv_blobs select own" on public.pevv_blobs;
drop policy if exists "pevv_blobs insert own" on public.pevv_blobs;
drop policy if exists "pevv_blobs update own" on public.pevv_blobs;
drop policy if exists "pevv_blobs delete own" on public.pevv_blobs;
create policy "pevv_blobs select own" on public.pevv_blobs for select to authenticated using ((select auth.uid()) = user_id);
create policy "pevv_blobs insert own" on public.pevv_blobs for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "pevv_blobs update own" on public.pevv_blobs for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "pevv_blobs delete own" on public.pevv_blobs for delete to authenticated using ((select auth.uid()) = user_id);

-- 7. The functions the clients call. All SECURITY INVOKER: they run as the signed-in user, so RLS applies to every
--    statement and a function can never reach another user's row. -------------------------------------------------
create or replace function public.pevv_put_inner(p_path text, p_body text, p_expected_rev bigint) returns jsonb
language plpgsql security invoker set search_path = ''
as $$
declare
  uid uuid := (select auth.uid());
  cur public.pevv_blobs;
  msg text;
begin
  if uid is null then return jsonb_build_object('ok', false, 'error', 'not-signed-in'); end if;
  if p_path is null or p_path not in ('/vault/pevv.vault.json', '/vault/pevv-handoff.json') then
    return jsonb_build_object('ok', false, 'error', 'not-allowed');
  end if;
  if p_body is null then return jsonb_build_object('ok', false, 'error', 'bad-body'); end if;
  begin
    select * into cur from public.pevv_blobs where user_id = uid and path = p_path for update;
    if not found then
      if coalesce(p_expected_rev, 0) <> 0 then return jsonb_build_object('ok', false, 'error', 'conflict', 'rev', 0); end if;
      insert into public.pevv_blobs (user_id, path, body) values (uid, p_path, p_body) returning * into cur;
      return jsonb_build_object('ok', true, 'rev', cur.rev);
    end if;
    if cur.rev <> coalesce(p_expected_rev, 0) then
      return jsonb_build_object('ok', false, 'error', 'conflict', 'rev', cur.rev,
        'body', case when cur.deleted_at is null then cur.body end, 'deleted', cur.deleted_at is not null);
    end if;
    update public.pevv_blobs set body = p_body where user_id = uid and path = p_path returning * into cur;
    return jsonb_build_object('ok', true, 'rev', cur.rev);
  exception when raise_exception then
    get stacked diagnostics msg = message_text;
    if msg like 'pevv:%' then return jsonb_build_object('ok', false, 'error', substr(msg, 6)); end if;
    raise;
  end;
end;
$$;

-- The public entry point: marks the transaction as a pevv_put write (strict_cas) only while the write runs.
create or replace function public.pevv_put(p_path text, p_body text, p_expected_rev bigint default 0) returns jsonb
language plpgsql security invoker set search_path = ''
as $$
declare r jsonb;
begin
  perform set_config('pevv.via_put', '1', true);
  r := public.pevv_put_inner(p_path, p_body, p_expected_rev);
  perform set_config('pevv.via_put', '', true);
  return r;
end;
$$;

create or replace function public.pevv_delete(p_path text) returns boolean
language plpgsql security invoker set search_path = ''
as $$
declare n int;
begin
  update public.pevv_blobs set deleted_at = now() where user_id = (select auth.uid()) and path = p_path and deleted_at is null;
  get diagnostics n = row_count;
  return n > 0;
end;
$$;

create or replace function public.pevv_undelete(p_path text) returns jsonb
language plpgsql security invoker set search_path = ''
as $$
declare cur public.pevv_blobs;
begin
  update public.pevv_blobs set deleted_at = null where user_id = (select auth.uid()) and path = p_path and deleted_at is not null returning * into cur;
  if not found then return jsonb_build_object('ok', false, 'error', 'not-deleted'); end if;
  return jsonb_build_object('ok', true, 'rev', cur.rev, 'body', cur.body);
end;
$$;

create or replace function public.pevv_history(p_path text) returns table (rev bigint, doc_rev bigint, saved_at timestamptz, bytes int)
language sql stable security invoker set search_path = ''
as $$
  select h.rev, h.doc_rev, h.saved_at, octet_length(h.body)
    from public.pevv_blob_history h
   where h.user_id = (select auth.uid()) and h.path = p_path
   order by h.rev desc
$$;

create or replace function public.pevv_history_get(p_path text, p_rev bigint) returns text
language sql stable security invoker set search_path = ''
as $$
  select h.body from public.pevv_blob_history h where h.user_id = (select auth.uid()) and h.path = p_path and h.rev = p_rev
$$;

revoke all on function public.pevv_put_inner(text, text, bigint), public.pevv_put(text, text, bigint), public.pevv_delete(text), public.pevv_undelete(text),
  public.pevv_history(text), public.pevv_history_get(text, bigint) from public, anon;
grant execute on function public.pevv_put_inner(text, text, bigint), public.pevv_put(text, text, bigint), public.pevv_delete(text), public.pevv_undelete(text),
  public.pevv_history(text), public.pevv_history_get(text, bigint) to authenticated;

-- 8. Realtime -----------------------------------------------------------------------------------------------
-- Change notifications for the blob table (RLS applies: a user only hears about their own rows).
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'pevv_blobs') then
    alter publication supabase_realtime add table public.pevv_blobs;
  end if;
end $$;

-- Broadcast topics. Before this migration any signed-in session, anonymous ones included, could read and write every
-- `pevv:%` topic. Now a topic must have exactly one of the two shapes PEVV uses:
--   pevv:<token>          one-time vault QR transfer. The random token in the QR code is the capability; the payload is
--                         ciphertext that only opens with the key that stays in the QR.
--   pevv:d:<vaultId>      live device list of one vault. Only a session that owns a synced copy of that vault may use it
--                         (set open_roster = 'true' in pevv_config to allow any session, the old behaviour).
create or replace function public.pevv_topic_ok(t text) returns boolean
language sql stable security definer set search_path = ''
as $$
  select case
    when (select auth.uid()) is null then false
    when t ~ '^pevv:d:[0-9a-fA-F-]{8,64}$' then
      public.pevv_cfg('open_roster', 'false') = 'true'
      or exists (select 1 from public.pevv_blobs b
                  where b.user_id = (select auth.uid()) and b.deleted_at is null and b.path = '/vault/pevv.vault.json' and b.vault_id = substr(t, 8))
    when t ~ '^pevv:[A-Za-z0-9_-]{16,128}$' then true
    else false
  end
$$;
revoke all on function public.pevv_topic_ok(text) from public, anon;
grant execute on function public.pevv_topic_ok(text) to authenticated;

do $$
begin
  if to_regclass('realtime.messages') is not null then
    execute 'drop policy if exists "pevv rt read" on realtime.messages';
    execute 'drop policy if exists "pevv rt write" on realtime.messages';
    execute $p$create policy "pevv rt read" on realtime.messages for select to authenticated using (
      extension = 'broadcast' and public.pevv_topic_ok((select realtime.topic())))$p$;
    execute $p$create policy "pevv rt write" on realtime.messages for insert to authenticated with check (
      extension = 'broadcast' and public.pevv_topic_ok((select realtime.topic())))$p$;
  end if;
end $$;
