-- Rows written by a pre-0002 client (after 0001, before 0002): the migration must backfill vault_id and doc_rev.
insert into auth.users (id) values ('00000000-0000-0000-0000-00000000000c');
insert into public.pevv_blobs (user_id, path, body)
values ('00000000-0000-0000-0000-00000000000c', '/vault/pevv.vault.json', '{"format":"luciverse.pevv","v":1,"id":"legacy0000000000000000aa","rev":9}');
insert into public.pevv_blobs (user_id, path, body)
values ('00000000-0000-0000-0000-00000000000c', '/vault/pevv-handoff.json', 'not json at all');
