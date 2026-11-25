-- PEVV sync backend, no size cap on a user's own vault. Run after 0002 (SQL editor or `supabase db push`). Safe to run twice.
-- Still ciphertext only. A person syncs their own vault between their own devices, so the server no longer limits how big
-- the sealed vault may be. What stays: row level security (owner only), compare-and-swap writes, the monotonic revision
-- guard, history, soft delete and the per-user write rate limit (`rate_per_minute`).
-- Do not run 0002 again after this file: it would put the old cap back.
--
-- Not changed here, because they are outside this database: the request size limit of your API gateway or reverse proxy,
-- and the hosting plan's database size. A very large vault is still bound by those (docs/SYNC_SELF_HOSTING.md).

-- 1. Drop the size checks on the blob table (the unnamed check from 0001 and the named one from 0002). ----------
do $$
declare c record;
begin
  for c in
    select conname from pg_constraint
     where conrelid = 'public.pevv_blobs'::regclass and contype = 'c'
       and (conname = 'pevv_blobs_body_bytes' or pg_get_constraintdef(oid) ~* '(char_length|octet_length|length)\(\s*body\s*\)')
  loop
    execute format('alter table public.pevv_blobs drop constraint %I', c.conname);
  end loop;
end $$;

-- 2. The setting is gone. -------------------------------------------------------------------------------------
delete from public.pevv_config where key = 'max_body';

-- 3. The guard, as in 0002 minus the size check. -------------------------------------------------------------
create or replace function public.pevv_guard() returns trigger
language plpgsql security definer set search_path = ''
as $$
declare
  vault boolean := new.path = '/vault/pevv.vault.json';
  parsed jsonb;
  doc bigint := 0;
  content boolean;
begin
  perform public.pevv_rate_hit(new.user_id);

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
