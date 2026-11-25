-- Tests for supabase/migrations/0002_pevv_hardening.sql and 0003_pevv_no_size_cap.sql on plain PostgreSQL (scripts/test-sql.mjs runs them).
-- Each DO block raises on a failed expectation and prints "ok: <name>" when it passes.
\set ON_ERROR_STOP on
\set A '''00000000-0000-0000-0000-00000000000a'''
\set B '''00000000-0000-0000-0000-00000000000b'''

insert into auth.users (id) values (:A), (:B);
create schema t;
create function t.vault(rev bigint, id text default 'aabbccddeeff00112233aabb') returns text language sql immutable as
  $$ select '{"format":"luciverse.pevv","v":1,"id":"' || id || '","rev":' || rev || '}' $$;
grant usage on schema t to authenticated, anon;
grant execute on function t.vault(bigint, text) to authenticated, anon;

-- ---------------------------------------------------------------------------------------------- migration data
do $$
declare r public.pevv_blobs;
begin
  select * into r from public.pevv_blobs where user_id = '00000000-0000-0000-0000-00000000000c' and path = '/vault/pevv.vault.json';
  assert r.vault_id = 'legacy0000000000000000aa' and r.doc_rev = 9 and r.rev = 1 and r.deleted_at is null, 'legacy row was not backfilled';
  assert (select count(*) from public.pevv_blobs where user_id = '00000000-0000-0000-0000-00000000000c') = 2, 'a legacy row that is not JSON must survive';
  raise notice 'ok: migration backfills vault_id and doc_rev and keeps odd legacy rows';
end $$;

do $$
begin
  assert exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'pevv_blobs'), 'pevv_blobs is not in supabase_realtime';
  raise notice 'ok: pevv_blobs is in the supabase_realtime publication';
end $$;

-- ---------------------------------------------------------------------------------------------- anon
begin;
set local role anon;
do $$
declare ok boolean;
begin
  ok := false; begin perform 1 from public.pevv_blobs; exception when insufficient_privilege then ok := true; end; assert ok, 'anon can select pevv_blobs';
  ok := false; begin insert into public.pevv_blobs (user_id, path, body) values ('00000000-0000-0000-0000-00000000000a', '/vault/pevv-handoff.json', 'x'); exception when insufficient_privilege then ok := true; end; assert ok, 'anon can insert';
  ok := false; begin perform public.pevv_put('/vault/pevv-handoff.json', 'x', 0); exception when insufficient_privilege then ok := true; end; assert ok, 'anon can call pevv_put';
  ok := false; begin perform 1 from public.pevv_blob_history; exception when insufficient_privilege then ok := true; end; assert ok, 'anon can read history';
  ok := false; begin perform 1 from public.pevv_config; exception when insufficient_privilege then ok := true; end; assert ok, 'anon can read config';
  ok := false; begin perform public.pevv_topic_ok('pevv:d:aabbccddeeff00112233aabb'); exception when insufficient_privilege then ok := true; end; assert ok, 'anon can call pevv_topic_ok';
  raise notice 'ok: anon can do nothing (tables, history, config, functions)';
end $$;
rollback;

-- ---------------------------------------------------------------------------------------------- owner only
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare r jsonb; ok boolean; n int;
begin
  r := public.pevv_put('/vault/pevv-handoff.json', 'hello', 0);
  assert (r->>'ok')::boolean and (r->>'rev')::int = 1, 'first write: ' || r::text;
  -- clients cannot write another user's row, not even by naming the user id
  ok := false; begin insert into public.pevv_blobs (user_id, path, body) values ('00000000-0000-0000-0000-00000000000b', '/vault/pevv-handoff.json', 'x'); exception when others then ok := true; end;
  assert ok, 'user A wrote a row for user B';
  select count(*) into n from public.pevv_blobs where user_id <> '00000000-0000-0000-0000-00000000000a'; assert n = 0, 'user A can see others rows';
  raise notice 'ok: owner can write their own row and cannot see or write anyone elses';
end $$;
rollback;

begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare r jsonb;
begin
  perform public.pevv_put('/vault/pevv.vault.json', t.vault(1), 0);
  perform set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000b', true);
  assert (select count(*) from public.pevv_blobs) = 0, 'B sees As blob';
  assert (select count(*) from public.pevv_history('/vault/pevv.vault.json')) = 0, 'B sees As history';
  assert public.pevv_history_get('/vault/pevv.vault.json', 1) is null, 'B reads As history body';
  r := public.pevv_undelete('/vault/pevv.vault.json');
  assert r->>'error' = 'not-deleted', 'B undeleted As blob';
  assert not public.pevv_delete('/vault/pevv.vault.json'), 'B deleted As blob';
  raise notice 'ok: history, delete and restore functions never reach another user';
end $$;
rollback;

-- ---------------------------------------------------------------------------------------------- compare-and-swap
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare r jsonb;
begin
  r := public.pevv_put('/vault/pevv.vault.json', t.vault(1), 0);
  assert (r->>'ok')::boolean and (r->>'rev')::int = 1, r::text;
  r := public.pevv_put('/vault/pevv.vault.json', t.vault(2), 1);
  assert (r->>'ok')::boolean and (r->>'rev')::int = 2, r::text;
  -- a device that still thinks the server is at rev 1 loses and gets the newer copy back
  r := public.pevv_put('/vault/pevv.vault.json', t.vault(3), 1);
  assert not (r->>'ok')::boolean and r->>'error' = 'conflict' and (r->>'rev')::int = 2 and r->>'body' = t.vault(2), 'conflict answer: ' || r::text;
  assert (select body from public.pevv_blobs where path = '/vault/pevv.vault.json') = t.vault(2), 'a conflicting write changed the row';
  -- a create when the row exists is a conflict too
  r := public.pevv_put('/vault/pevv.vault.json', t.vault(3), 0);
  assert r->>'error' = 'conflict', r::text;
  -- an update when the row is gone is a conflict without a body
  r := public.pevv_put('/vault/pevv-handoff.json', 'x', 5);
  assert r->>'error' = 'conflict' and (r->>'rev')::int = 0 and r->'body' is null, r::text;
  raise notice 'ok: compare-and-swap accepts the expected revision and returns the newer copy on conflict';
end $$;
rollback;

begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare r jsonb; ok boolean;
begin
  perform public.pevv_put('/vault/pevv.vault.json', t.vault(5), 0);
  r := public.pevv_put('/vault/pevv.vault.json', t.vault(4), 1);
  assert r->>'error' = 'rev-regressed', 'lower vault rev accepted: ' || r::text;
  r := public.pevv_put('/vault/pevv.vault.json', t.vault(5, 'aabbccddeeff00112233aabb') || ' ', 1);
  assert r->>'error' = 'rev-regressed', 'same vault rev accepted: ' || r::text;
  r := public.pevv_put('/vault/pevv.vault.json', t.vault(6), 1);
  assert (r->>'ok')::boolean, r::text;
  -- the same rule holds for plain upserts from an older client
  ok := false;
  begin
    insert into public.pevv_blobs (user_id, path, body) values ('00000000-0000-0000-0000-00000000000a', '/vault/pevv.vault.json', t.vault(2))
      on conflict (user_id, path) do update set body = excluded.body;
  exception when others then ok := sqlerrm like '%rev-regressed%'; end;
  assert ok, 'a plain upsert moved the vault revision backwards';
  insert into public.pevv_blobs (user_id, path, body) values ('00000000-0000-0000-0000-00000000000a', '/vault/pevv.vault.json', t.vault(7))
    on conflict (user_id, path) do update set body = excluded.body;
  assert (select rev from public.pevv_blobs where path = '/vault/pevv.vault.json') = 3 and (select doc_rev from public.pevv_blobs where path = '/vault/pevv.vault.json') = 7, 'server revision or doc_rev wrong after plain upsert';
  raise notice 'ok: the vault revision is monotonic for put and for plain upserts; the server revision counts every write';
end $$;
rollback;

begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare r jsonb;
begin
  assert public.pevv_put('/vault/other.json', 'x', 0)->>'error' = 'not-allowed', 'path not allowed';
  assert public.pevv_put('/vault/pevv.vault.json', 'this is not json', 0)->>'error' = 'bad-body', 'non-JSON vault accepted';
  assert public.pevv_put('/vault/pevv.vault.json', '{"id":"x"}', 0)->>'error' = 'bad-body', 'vault without rev accepted';
  assert public.pevv_put('/vault/pevv-handoff.json', null, 0)->>'error' = 'bad-body', 'null accepted';
  raise notice 'ok: only the two paths and well-formed vault bodies are accepted';
end $$;
rollback;

-- ---------------------------------------------------------------------------------------------- no size cap (0003)
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare r jsonb; ok boolean; n int;
begin
  -- Far past the old 262144 byte cap, through put and through plain writes.
  r := public.pevv_put('/vault/pevv-handoff.json', repeat('a', 5000000), 0);
  assert (r->>'ok')::boolean, 'a large body was refused: ' || r::text;
  r := public.pevv_put('/vault/pevv-handoff.json', repeat('b', 262145), 1);
  assert (r->>'ok')::boolean, 'a body just over the old cap was refused: ' || r::text;
  ok := true; begin insert into public.pevv_blobs (user_id, path, body) values ('00000000-0000-0000-0000-00000000000a', '/vault/pevv.vault.json', '{"id":"big","rev":1,"pad":"' || repeat('a', 400000) || '"}'); exception when others then ok := false; end;
  assert ok, 'plain insert of a large vault was refused';
  select count(*) into n from pg_constraint where conrelid = 'public.pevv_blobs'::regclass and contype = 'c' and pg_get_constraintdef(oid) ~* 'length\(';
  assert n = 0, 'a length check is still on pevv_blobs';
  raise notice 'ok: no size cap on put or on plain writes';
end $$;
rollback;

-- ---------------------------------------------------------------------------------------------- history
update public.pevv_config set value = '3' where key = 'history_keep';
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare r jsonb; i int; n int; revs bigint[];
begin
  for i in 1..7 loop
    r := public.pevv_put('/vault/pevv.vault.json', t.vault(i), i - 1);
    assert (r->>'ok')::boolean, r::text;
  end loop;
  select array_agg(rev order by rev desc) into revs from public.pevv_history('/vault/pevv.vault.json');
  assert revs = array[6, 5, 4]::bigint[], 'history keeps the last 3 revisions, got ' || revs::text;
  assert public.pevv_history_get('/vault/pevv.vault.json', 5) = t.vault(5), 'old revision body wrong';
  assert public.pevv_history_get('/vault/pevv.vault.json', 2) is null, 'pruned revision still readable';
  assert (select count(*) from public.pevv_blobs) = 1, 'history leaked into the blob table';
  raise notice 'ok: the last N revisions are kept per blob, older ones are pruned';
end $$;
rollback;
update public.pevv_config set value = '20' where key = 'history_keep';

begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare ok boolean;
begin
  perform public.pevv_put('/vault/pevv.vault.json', t.vault(1), 0);
  perform public.pevv_put('/vault/pevv.vault.json', t.vault(2), 1);
  ok := false; begin insert into public.pevv_blob_history (user_id, path, rev, doc_rev, body) values ('00000000-0000-0000-0000-00000000000a', '/vault/pevv.vault.json', 99, 99, 'forged'); exception when insufficient_privilege then ok := true; end;
  assert ok, 'a client wrote history directly';
  ok := false; begin update public.pevv_blob_history set body = 'x'; exception when insufficient_privilege then ok := true; end;
  assert ok, 'a client edited history';
  ok := false; begin delete from public.pevv_blob_history; exception when insufficient_privilege then ok := true; end;
  assert ok, 'a client deleted history';
  raise notice 'ok: history is read-only for clients';
end $$;
rollback;

-- ---------------------------------------------------------------------------------------------- soft delete and restore
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare r jsonb;
begin
  perform public.pevv_put('/vault/pevv.vault.json', t.vault(5), 0);
  assert public.pevv_delete('/vault/pevv.vault.json'), 'delete reported nothing deleted';
  assert (select deleted_at is not null from public.pevv_blobs where path = '/vault/pevv.vault.json'), 'row not soft deleted';
  assert not public.pevv_delete('/vault/pevv.vault.json'), 'deleting twice reported success';
  r := public.pevv_undelete('/vault/pevv.vault.json');
  assert (r->>'ok')::boolean and r->>'body' = t.vault(5), 'undelete: ' || r::text;
  assert (select deleted_at is null from public.pevv_blobs where path = '/vault/pevv.vault.json'), 'row still deleted after undelete';
  -- a plain DELETE (what an older client sends) is a soft delete as well
  delete from public.pevv_blobs where path = '/vault/pevv.vault.json';
  assert (select count(*) from public.pevv_blobs) = 1 and (select deleted_at is not null from public.pevv_blobs), 'plain DELETE destroyed the row';
  raise notice 'ok: delete is soft (RPC and plain DELETE) and the restore RPC brings the blob back';
end $$;
rollback;

begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare r jsonb;
begin
  perform public.pevv_put('/vault/pevv.vault.json', t.vault(50), 0);
  perform public.pevv_delete('/vault/pevv.vault.json');
  -- sync was switched off and on again: a fresh vault life may start at a lower revision, once the writer knows the server revision
  r := public.pevv_put('/vault/pevv.vault.json', t.vault(1), 0);
  assert r->>'error' = 'conflict' and jsonb_typeof(r->'body') = 'null' and (r->>'deleted')::boolean, 'deleted row must answer with its revision, no body: ' || r::text;
  r := public.pevv_put('/vault/pevv.vault.json', t.vault(1), (r->>'rev')::bigint);
  assert (r->>'ok')::boolean, r::text;
  assert (select deleted_at is null and doc_rev = 1 from public.pevv_blobs where path = '/vault/pevv.vault.json'), 'a write after a soft delete must bring the row back';
  raise notice 'ok: writing after a soft delete starts a new life at the server revision';
end $$;
rollback;

-- ---------------------------------------------------------------------------------------------- rate limit
update public.pevv_config set value = '5' where key = 'rate_per_minute';
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare r jsonb; i int;
begin
  for i in 1..5 loop
    r := public.pevv_put('/vault/pevv-handoff.json', 'v' || i, i - 1);
    assert (r->>'ok')::boolean, 'write ' || i || ': ' || r::text;
  end loop;
  r := public.pevv_put('/vault/pevv-handoff.json', 'v6', 5);
  assert r->>'error' = 'rate-limited', 'sixth write in a minute was accepted: ' || r::text;
  raise notice 'ok: writes are rate limited per user';
end $$;
commit;
-- another user is not affected, and the window resets
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :B, true);
do $$ begin assert (public.pevv_put('/vault/pevv-handoff.json', 'b', 0)->>'ok')::boolean, 'rate limit of A hit B'; raise notice 'ok: one user''s rate limit does not affect another'; end $$;
rollback;
reset role;
update public.pevv_rate set window_start = now() - interval '2 minutes';
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$ begin assert (public.pevv_put('/vault/pevv-handoff.json', 'v6', 5)->>'ok')::boolean, 'window did not reset'; raise notice 'ok: the rate window resets after a minute'; end $$;
rollback;
reset role;
delete from public.pevv_blobs where user_id = '00000000-0000-0000-0000-00000000000a';
delete from public.pevv_blob_history where user_id = '00000000-0000-0000-0000-00000000000a';
delete from public.pevv_rate;
update public.pevv_config set value = '60' where key = 'rate_per_minute';

-- ---------------------------------------------------------------------------------------------- strict CAS
update public.pevv_config set value = 'true' where key = 'strict_cas';
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare ok boolean;
begin
  assert (public.pevv_put('/vault/pevv-handoff.json', 'x', 0)->>'ok')::boolean, 'put refused in strict mode';
  ok := false; begin insert into public.pevv_blobs (user_id, path, body) values ('00000000-0000-0000-0000-00000000000a', '/vault/pevv-handoff.json', 'y') on conflict (user_id, path) do update set body = excluded.body; exception when others then ok := sqlerrm like '%cas-required%'; end;
  assert ok, 'plain upsert accepted in strict mode';
  raise notice 'ok: strict_cas refuses plain writes and still accepts pevv_put';
end $$;
rollback;
update public.pevv_config set value = 'false' where key = 'strict_cas';

-- ---------------------------------------------------------------------------------------------- realtime topics
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
begin
  assert (public.pevv_put('/vault/pevv.vault.json', t.vault(1, 'aabbccddeeff00112233aabb'), 0)->>'ok')::boolean;
  assert public.pevv_topic_ok('pevv:d:aabbccddeeff00112233aabb'), 'owner refused on the device lane of their own vault';
  assert not public.pevv_topic_ok('pevv:d:ffffffffffffffffffffffff'), 'owner allowed on a vault they do not hold';
  assert public.pevv_topic_ok('pevv:Abcdefghijklmnop-_0123456789'), 'QR token lane refused';
  assert not public.pevv_topic_ok('pevv:short'), 'short token accepted';
  assert not public.pevv_topic_ok('pevv:d:aabbccddeeff00112233aabb:extra'), 'extra segment accepted';
  assert not public.pevv_topic_ok('pevv:x:y'), 'unknown lane accepted';
  assert not public.pevv_topic_ok('other:Abcdefghijklmnop-_0123456789'), 'foreign topic accepted';
  assert not public.pevv_topic_ok('pevv:%'), 'wildcard accepted';
  raise notice 'ok: topic shapes are exact; the device lane needs a synced copy of that vault';
end $$;
commit;

begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :B, true);
do $$
begin
  assert not public.pevv_topic_ok('pevv:d:aabbccddeeff00112233aabb'), 'another user may use the device lane of As vault';
  raise notice 'ok: another user cannot use the device lane of a vault they do not hold';
end $$;
rollback;

begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', '', true);
do $$ begin assert not public.pevv_topic_ok('pevv:Abcdefghijklmnop-_0123456789'), 'no session accepted'; raise notice 'ok: no session, no topic'; end $$;
rollback;

-- the policies themselves, on realtime.messages
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :A, true);
do $$
declare ok boolean;
begin
  perform set_config('realtime.topic', 'pevv:d:aabbccddeeff00112233aabb', true);
  insert into realtime.messages (topic, extension) values ('pevv:d:aabbccddeeff00112233aabb', 'broadcast');
  ok := false;
  begin
    perform set_config('realtime.topic', 'pevv:d:ffffffffffffffffffffffff', true);
    insert into realtime.messages (topic, extension) values ('pevv:d:ffffffffffffffffffffffff', 'broadcast');
  exception when others then ok := true; end;
  assert ok, 'wrote to the device lane of a vault not held';
  ok := false;
  begin
    perform set_config('realtime.topic', 'pevv:d:aabbccddeeff00112233aabb', true);
    insert into realtime.messages (topic, extension) values ('pevv:d:aabbccddeeff00112233aabb', 'presence');
  exception when others then ok := true; end;
  assert ok, 'wrote a non-broadcast message';
  raise notice 'ok: realtime.messages policies enforce the topic rule for writes';
end $$;
commit;
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :B, true);
do $$
begin
  perform set_config('realtime.topic', 'pevv:d:aabbccddeeff00112233aabb', true);
  assert (select count(*) from realtime.messages) = 0, 'another user can read the device lane of As vault';
  raise notice 'ok: realtime.messages policies enforce the topic rule for reads';
end $$;
rollback;

update public.pevv_config set value = 'true' where key = 'open_roster';
begin;
set local role authenticated;
select set_config('request.jwt.claim.sub', :B, true);
do $$ begin assert public.pevv_topic_ok('pevv:d:aabbccddeeff00112233aabb'), 'open_roster did not open the device lane'; raise notice 'ok: open_roster restores the pre-0002 device lane'; end $$;
rollback;
update public.pevv_config set value = 'false' where key = 'open_roster';

-- ---------------------------------------------------------------------------------------------- account deletion
delete from public.pevv_blobs where user_id = '00000000-0000-0000-0000-00000000000c';
reset role;
do $$
begin
  perform 1;
  delete from auth.users where id = '00000000-0000-0000-0000-00000000000a';
  assert (select count(*) from public.pevv_blobs where user_id = '00000000-0000-0000-0000-00000000000a') = 0, 'blobs survived account deletion';
  assert (select count(*) from public.pevv_blob_history where user_id = '00000000-0000-0000-0000-00000000000a') = 0, 'history survived account deletion';
  raise notice 'ok: deleting an account really deletes its blobs and history';
end $$;
