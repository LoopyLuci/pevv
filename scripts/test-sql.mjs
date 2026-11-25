#!/usr/bin/env node
/**
 * Runs the SQL tests for supabase/migrations on a throw-away PostgreSQL cluster (tests/sql). No Supabase stack and no
 * network: the parts of Supabase the migrations use (auth.uid(), the Realtime tables, the anon and authenticated roles)
 * are small stand-ins in tests/sql/stub.sql, so this checks the SQL, the RLS policies and the functions on real
 * PostgreSQL, but not Supabase's own services (PostgREST, Realtime). docs/SYNC.md lists the manual steps for those.
 *
 *   node scripts/test-sql.mjs            initdb, run, stop, delete the temp cluster
 *   PEVV_PG_BIN=/path/to/postgres/bin    where initdb, pg_ctl and psql are (default: PATH)
 *   PEVV_PG_PORT=54329                   port for the temp cluster
 *   PEVV_SQL_TMP=/some/dir               parent for the temp cluster (default: the OS temp dir)
 *   --require                            fail instead of skipping when PostgreSQL is not installed
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const exe = process.platform === 'win32' ? '.exe' : '';
const bin = (n) => (process.env.PEVV_PG_BIN ? join(process.env.PEVV_PG_BIN, n + exe) : n + exe);
const port = process.env.PEVV_PG_PORT ?? '54329';
const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', ...opts });

const probe = run(bin('initdb'), ['--version']);
if (probe.error || probe.status !== 0) {
  const msg = 'PostgreSQL (initdb, pg_ctl, psql) not found: set PEVV_PG_BIN. SQL tests skipped.';
  if (process.argv.includes('--require')) { console.error(msg); process.exit(1); }
  console.log(msg);
  process.exit(0);
}

const tmp = mkdtempSync(join(process.env.PEVV_SQL_TMP ?? tmpdir(), 'pevv-sql-'));
const data = join(tmp, 'data');
let started = false;
let failed = false;
try {
  let r = run(bin('initdb'), ['-D', data, '-U', 'postgres', '--auth=trust', '-E', 'UTF8', '--locale=C']);
  if (r.status !== 0) throw new Error(`initdb failed: ${r.stderr}`);
  r = run(bin('pg_ctl'), ['-D', data, '-o', `-p ${port} -c listen_addresses=127.0.0.1 -c fsync=off -c unix_socket_directories=`, '-l', join(tmp, 'pg.log'), '-w', 'start'], { stdio: 'ignore' });
  if (r.status !== 0) throw new Error(`pg_ctl start failed (see ${join(tmp, 'pg.log')})`);
  started = true;

  const psql = (file, label) => {
    const p = run(bin('psql'), ['-h', '127.0.0.1', '-p', port, '-U', 'postgres', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-d', 'postgres', '-f', file]);
    if (p.status !== 0) { failed = true; console.error(`FAILED ${label}\n${p.stderr}`); }
    return p;
  };
  const migrations = (n) => join(root, 'supabase', 'migrations', n);
  psql(join(root, 'tests', 'sql', 'stub.sql'), 'stub');
  if (!failed) psql(migrations('0001_pevv_sync.sql'), '0001');
  if (!failed) psql(join(root, 'tests', 'sql', 'legacy.sql'), 'legacy rows');
  if (!failed) psql(migrations('0002_pevv_hardening.sql'), '0002 (first run)');
  if (!failed) psql(migrations('0002_pevv_hardening.sql'), '0002 (second run: must be idempotent)');
  if (!failed) psql(migrations('0003_pevv_no_size_cap.sql'), '0003 (first run)');
  if (!failed) psql(migrations('0003_pevv_no_size_cap.sql'), '0003 (second run: must be idempotent)');
  let ok = 0;
  if (!failed) {
    const p = psql(join(root, 'tests', 'sql', 'hardening.test.sql'), 'hardening tests');
    const lines = `${p.stderr}\n${p.stdout}`.split('\n').filter((l) => /ok: /.test(l));
    ok = lines.length;
    for (const l of lines) console.log(l.replace(/^.*NOTICE:\s*/, ''));
  }
  console.log(`\nSQL tests: ${failed ? 'FAILED' : 'passed'} (${ok} checks ok, PostgreSQL ${probe.stdout.trim()})`);
} catch (e) {
  failed = true;
  console.error(String(e));
} finally {
  if (started) run(bin('pg_ctl'), ['-D', data, '-m', 'fast', '-w', 'stop'], { stdio: 'ignore' });
  if (existsSync(tmp)) rmSync(tmp, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
