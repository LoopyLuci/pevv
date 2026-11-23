/**
 * Cross-client sync scenarios. The scenario files in tests/sync-scenarios/*.json are the shared spec: the same files are
 * run by the Kotlin client (android/.../SyncScenarioTest.kt) and both must produce byte-identical files, which are
 * checked against tests/sync-scenarios/golden/*.json. Refresh the goldens (TypeScript is the source of truth) with
 *   PEVV_WRITE_GOLDEN=1 npx vitest run tests/unit/pevv.sync-scenarios.test.ts
 * Only throw-away test keys appear in these files.
 */
import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { b64, unb64, utf8 } from '@/pevv/bytes';
import { aad, aesKeyFromRaw, openJson, passwordKek, sealJson, wrapVaultKey } from '@/pevv/crypto';
import { codeHash, codeKek, recoveryKeyKek } from '@/pevv/recovery';
import { canon, mergeVaults, restoreRevision, type MergeOutcome } from '@/pevv/merge';
import { rotateVaultKey } from '@/pevv/rotate';
import { prfKek, readMeta, sessionFromRaw, unlockWithPassword, unlockWithPrf, unlockWithRecoveryCode, unlockWithRecoveryKey, unlockWithUsbKey, usbKek, validateFile, type Session } from '@/pevv/vault';
import type { EntryRecord, VaultFile } from '@/pevv/model';

const VAULT_ID = '00112233445566778899aabb';
const dir = join(process.cwd(), 'tests', 'sync-scenarios');
const KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const hexBytes = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16)) as ReturnType<typeof unb64>;

type J = Record<string, unknown>;
interface Step extends J { op: string; device?: string; expect?: J }
interface Scenario { name: string; steps: Step[]; asserts: J[]; vaultId: string }

interface Dev { key: Uint8Array; session: Session; file: VaultFile | null; base: VaultFile | null }

const DEFAULT_META: J = {
  environments: ['dev', 'prod'], activeEnv: 'dev', grants: {}, index: {}, require: { totp: false, passkey: false, usbKey: false },
  usbKeys: [], totpLastStep: null, folders: [], projectEnv: {}, devices: [], revokedDevices: [],
};

/** Synthetic IV: HMAC-SHA256(vault key, aad || 0x00 || plaintext)[0..12]. Same inputs, same bytes, in both clients. */
function ivFor(key: Uint8Array) {
  return async (a: string, plain: Uint8Array) => {
    const k = await crypto.subtle.importKey('raw', new Uint8Array(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const msg = new Uint8Array([...utf8(a), 0, ...plain]);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg)).slice(0, 12) as ReturnType<typeof unb64>;
  };
}

export async function runScenario(sc: Scenario) {
  const devs = new Map<string, Dev>();
  const snaps = new Map<string, VaultFile>();
  const outcomes: string[] = [];
  const dev = async (name: string): Promise<Dev> => {
    let d = devs.get(name);
    if (!d) {
      const key = hexBytes(KEY_HEX);
      d = { key, session: await sessionFromRaw(new Uint8Array(key) as ReturnType<typeof unb64>), file: null, base: null };
      devs.set(name, d);
    }
    return d;
  };
  const opts = (d: Dev, now?: number, writer?: string) => ({ iv: ivFor(d.key), ...(now !== undefined ? { now } : {}), ...(writer ? { writer } : {}) });
  const seal = async (d: Dev, value: unknown, a: string) => sealJson(d.session.key, value, a, await ivFor(d.key)(a, utf8(JSON.stringify(value))));

  /** Re-seal meta at the next revision (what commit() does) after `change` was applied to the plain meta. */
  const commit = async (d: Dev, name: string, now: number, change: (m: J) => void, patch: (f: VaultFile) => void = () => undefined) => {
    const f = d.file!;
    const m = { ...(await readMeta(f, d.session)) } as unknown as J;
    change(m);
    const rev = f.rev + 1;
    m.lastWriter = name;
    const next: VaultFile = { ...f, rev, updated: now };
    patch(next);
    m.index = Object.fromEntries(next.entries.map((e) => [e.id, e.ver]));
    next.require = { ...(m.require as VaultFile['require']) };
    next.meta = await seal(d, m, aad.meta(f.id, rev));
    d.file = next;
  };

  const view = async (name: string) => {
    const d = devs.get(name)!;
    const f = d.file!;
    const items: Record<string, unknown> = {};
    for (const r of f.entries) items[r.id] = { ver: r.ver, data: await openJson(d.session.key, r.sealed, aad.entry(f.id, r.id, r.ver)) };
    const meta = { ...(await readMeta(f, d.session)) } as unknown as J;
    return { items, meta, f };
  };

  for (const st of sc.steps) {
    const name = st.device as string;
    switch (st.op) {
      case 'create': {
        const d = await dev(name);
        const entries: EntryRecord[] = [];
        for (const it of st.items as Array<{ id: string; data: J }>) entries.push({ id: it.id, ver: 1, sealed: await seal(d, it.data, aad.entry(sc.vaultId, it.id, 1)) });
        const meta: J = { ...DEFAULT_META, ...(st.meta as J ?? {}), index: Object.fromEntries(entries.map((e) => [e.id, 1])), lastWriter: name };
        const kek = await aesKeyFromRaw(new Uint8Array(32).fill(0xaa) as ReturnType<typeof unb64>);
        const iv = await ivFor(d.key)(aad.slot(sc.vaultId, 's-pw'), d.key);
        const file: J = {
          format: 'luciverse.pevv', v: 1, id: sc.vaultId, created: st.at, updated: st.at, rev: 1,
          kdf: { alg: 'pbkdf2-sha256', iter: 600000, salt: b64(new Uint8Array(16).fill(7)) },
          slots: [{ id: 's-pw', type: 'password', wrapped: await wrapVaultKey(kek, d.key, sc.vaultId, 's-pw', iv) }, ...((st.slots as J[]) ?? [])],
          passkeys: [], require: { ...(meta.require as J) }, totp: null, meta: await seal(d, meta, aad.meta(sc.vaultId, 1)), entries,
          ...((st.top as J) ?? {}),
        };
        d.file = file as unknown as VaultFile;
        d.base = d.file;
        break;
      }
      case 'copy': {
        const from = await dev(st.from as string);
        const to = await dev(st.to as string);
        to.file = from.file;
        to.base = from.file;
        to.key = from.key; to.session = from.session;
        break;
      }
      case 'edit':
      case 'add': {
        const d = await dev(name);
        const f = d.file!;
        const id = st.id as string;
        const prev = f.entries.find((e) => e.id === id);
        let data: J;
        if (st.op === 'add') data = st.data as J;
        else {
          data = { ...(await openJson<J>(d.session.key, prev!.sealed, aad.entry(f.id, id, prev!.ver))) };
          for (const [k, v] of Object.entries(st.set as J)) { if (v === null) delete data[k]; else data[k] = v; }
          data.updated = st.at;
        }
        const ver = (prev?.ver ?? 0) + 1;
        const rec: EntryRecord = { id, ver, sealed: await seal(d, data, aad.entry(f.id, id, ver)) };
        await commit(d, name, st.at as number, () => undefined, (n) => { n.entries = prev ? f.entries.map((e) => (e.id === id ? rec : e)) : [...f.entries, rec]; });
        break;
      }
      case 'delete': {
        const d = await dev(name);
        const f = d.file!;
        await commit(d, name, st.at as number, () => undefined, (n) => { n.entries = f.entries.filter((e) => e.id !== st.id); });
        break;
      }
      case 'meta': {
        const d = await dev(name);
        await commit(d, name, st.at as number, (m) => { for (const [k, v] of Object.entries(st.patch as J)) m[k] = v; });
        break;
      }
      case 'revoke': {
        const d = await dev(name);
        await commit(d, name, st.at as number, (m) => {
          m.revokedDevices = [...((m.revokedDevices as string[]) ?? []), st.target];
          m.devices = ((m.devices as Array<{ id: string }>) ?? []).filter((x) => x.id !== st.target);
        });
        break;
      }
      case 'top': {
        const d = await dev(name);
        const nf: J = { ...(d.file as unknown as J), ...(st.patch as J) };
        for (const [k, v] of Object.entries(st.patch as J)) if (v === null) delete nf[k];
        d.file = nf as unknown as VaultFile;
        break;
      }
      case 'snapshot': snaps.set(st.name as string, (await dev(name)).file!); break;
      case 'restore': {
        const d = await dev(name);
        const r = await restoreRevision(d.session, d.file!, snaps.get(st.name as string)!, opts(d, st.at as number, name));
        d.file = r.file;
        outcomes.push(`restore:${r.restored}:${r.removed}`);
        break;
      }
      case 'rotate': {
        const d = await dev(name);
        const r = await rotateVaultKey(d.file!, d.session, {
          password: 'pw', kdf: { alg: 'pbkdf2-sha256', iter: 600000, salt: b64(new Uint8Array(16).fill(9)) }, dropUnknown: true,
        }, { iv: ivFor(hexBytes(st.newKeyHex as string)), rng: (n) => new Uint8Array(n).fill(0x33) as ReturnType<typeof unb64>, newKey: hexBytes(st.newKeyHex as string), newId: (() => { let i = 0; return () => `rot-${i++}`; })(), now: st.at as number });
        d.file = r.file; d.base = r.file; d.key = hexBytes(st.newKeyHex as string); d.session = r.session;
        break;
      }
      case 'sync': {
        const d = await dev(name);
        const other = devs.get(st.with as string)!;
        const out: MergeOutcome = await mergeVaults(d.session, st.base === false ? null : d.base, d.file!, other.file!, opts(d, st.now as number, name));
        outcomes.push(`${out.kind}${out.reason ? ':' + out.reason : ''}${out.conflicts.length ? ':' + out.conflicts.map((c) => `${c.id}/${c.kind}/${c.kept}`).sort().join(',') : ''}`);
        if (st.expect) {
          const e = st.expect as J;
          expect(out.kind, `${sc.name} ${st.op} ${name}`).toBe(e.kind);
          if (e.reason) expect(out.reason).toBe(e.reason);
          if (e.conflicts) expect(out.conflicts.map((c) => `${c.id}/${c.kind}`).sort()).toEqual([...(e.conflicts as string[])].sort());
        }
        if (out.kind === 'merged' || out.kind === 'took-remote' || out.kind === 'key-rotated') { d.file = out.file; d.base = out.file; }
        break;
      }
      default: throw new Error(`unknown op ${st.op}`);
    }
  }

  for (const a of sc.asserts) {
    const name = (a.device as string) ?? '';
    const t = a.t as string;
    if (t === 'same') {
      const vs = await Promise.all((a.devices as string[]).map(async (n) => { const v = await view(n); const m = { ...v.meta }; delete m.lastWriter; return canon({ items: v.items, meta: m }); }));
      for (const v of vs) expect(v, sc.name).toBe(vs[0]);
      continue;
    }
    const v = await view(name);
    if (t === 'field') expect(canon((v.items[a.id as string] as { data: J } | undefined)?.data[a.field as string]), `${sc.name} ${a.id}.${a.field}`).toBe(canon(a.equals));
    else if (t === 'absent') expect(v.items[a.id as string], sc.name).toBeUndefined();
    else if (t === 'count') expect(Object.keys(v.items).length, sc.name).toBe(a.n);
    else if (t === 'conflicts') expect(((v.items[a.id as string] as { data: { conflicts?: unknown[] } }).data.conflicts ?? []).length, sc.name).toBe(a.n);
    else if (t === 'meta') expect(canon(v.meta[a.key as string]), sc.name).toBe(canon(a.equals));
    else if (t === 'top') expect(canon((v.f as unknown as J)[a.key as string]), sc.name).toBe(canon(a.equals));
    else if (t === 'slotTypes') expect(v.f.slots.map((s) => s.type), sc.name).toEqual(a.equals);
    else if (t === 'rev') expect(v.f.rev, sc.name).toBe(a.equals);
    else throw new Error(`unknown assert ${t}`);
  }
  const files: Record<string, string> = {};
  for (const [n, d] of devs) if (d.file) files[n] = JSON.stringify(d.file);
  return { outcomes, files };
}

const scenarios = existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.json')).sort() : [];

describe('sync scenarios (shared with the Kotlin client)', () => {
  it('has scenarios', () => { expect(scenarios.length).toBeGreaterThanOrEqual(8); });
  for (const file of scenarios) {
    it(file.replace('.json', ''), async () => {
      const sc = JSON.parse(readFileSync(join(dir, file), 'utf8')) as Scenario;
      const got = await runScenario(sc);
      const gp = join(dir, 'golden', file);
      if (process.env.PEVV_WRITE_GOLDEN === '1') { writeFileSync(gp, JSON.stringify(got, null, 1) + '\n'); return; }
      expect(existsSync(gp), `golden ${file} (PEVV_WRITE_GOLDEN=1 writes it)`).toBe(true);
      expect(got).toEqual(JSON.parse(readFileSync(gp, 'utf8')));
    }, 60_000);
  }
});

/* ───────────── key rotation golden vector ───────────── */

const KDF = { alg: 'pbkdf2-sha256' as const, iter: 600000, salt: b64(new Uint8Array(16).fill(7)) };
const NEW_KDF = { alg: 'pbkdf2-sha256' as const, iter: 600000, salt: b64(new Uint8Array(16).fill(9)) };
const USB_TEXT = `${JSON.stringify({ format: 'luciverse.pevvkey', v: 1, vault: 'vault', secret: b64(new Uint8Array(32).fill(0x41)) }, null, 2)}\n`;
const PRF_OUT = new Uint8Array(32).fill(0x55) as ReturnType<typeof unb64>;
const OLD_CODE = 'AAAAA-BBBBB-CCCCC-DDDDD';
const NEW_CODES = ['22222-33333-44444-55555', 'ABCDE-FGHIJ-KLMNO-PQRST'];
const NEW_RKEY = 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-IIII-JJJJ-KKKK-LLLL-MMMM';

async function rotationInput(): Promise<{ file: VaultFile; raw: ReturnType<typeof unb64> }> {
  const raw = hexBytes(KEY_HEX);
  const session = await sessionFromRaw(new Uint8Array(raw) as ReturnType<typeof unb64>);
  const iv = ivFor(raw);
  const id = VAULT_ID;
  const wrap = async (kek: CryptoKey, slotId: string) => wrapVaultKey(kek, raw, id, slotId, await iv(aad.slot(id, slotId), raw));
  const s = async (v: unknown, a: string) => sealJson(session.key, v, a, await iv(a, utf8(JSON.stringify(v))));
  const secretUsb = new Uint8Array(32).fill(0x41);
  const rkSalt = b64(new Uint8Array(16).fill(5));
  const codeSalt = b64(new Uint8Array(16).fill(6));
  const slots = [
    { id: 'p1', type: 'password', wrapped: await wrap(await passwordKek('old password', KDF), 'p1') },
    { id: 'f1', type: 'prf', credId: 'cred-1', salt: b64(new Uint8Array(32).fill(1)), wrapped: await wrap(await prfKek(PRF_OUT, b64(new Uint8Array(32).fill(1))), 'f1') },
    { id: 'f2', type: 'prf', credId: 'cred-2', salt: b64(new Uint8Array(32).fill(2)), wrapped: await wrap(await prfKek(new Uint8Array(32).fill(0x66) as ReturnType<typeof unb64>, b64(new Uint8Array(32).fill(2))), 'f2') },
    { id: 'u1', type: 'usb-key', name: 'Blue stick', salt: b64(new Uint8Array(32).fill(3)), wrapped: await wrap(await usbKek(secretUsb, b64(new Uint8Array(32).fill(3))), 'u1') },
    { id: 'c1', type: 'recovery-code', salt: codeSalt, hash: await codeHash(OLD_CODE, codeSalt), wrapped: await wrap(await codeKek(OLD_CODE, codeSalt), 'c1') },
    { id: 'k1', type: 'recovery-key', salt: rkSalt, wrapped: await wrap(await recoveryKeyKek(NEW_RKEY, rkSalt), 'k1') },
    { id: 'h1', type: 'hw-token', wrapped: { iv: 'AAAAAAAAAAAAAAAA', ct: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } },
  ];
  const entries: EntryRecord[] = [];
  for (const [eid, title] of [['e1', 'Alpha'], ['e2', 'Beta']] as const) {
    entries.push({ id: eid, ver: 3, sealed: await s({ type: 'login', title, password: `secret-${title}`, tags: [], favorite: false, created: 1, updated: 2, history: [], future: { k: 1 } }, aad.entry(id, eid, 3)) });
  }
  const meta = { ...DEFAULT_META, index: { e1: 3, e2: 3 }, futureMeta: true };
  const file = {
    format: 'luciverse.pevv', v: 1, id, created: 1000, updated: 1000, rev: 7, kdf: KDF, slots, passkeys: [], require: { totp: true, passkey: false, usbKey: false },
    totp: await s({ secret: 'JBSWY3DPEHPK3PXP' }, aad.totp(id)), meta: await s(meta, aad.meta(id, 7)), entries, 'x-future': { a: 1 },
  } as unknown as VaultFile;
  return { file, raw };
}

describe('key rotation (golden vector shared with the Kotlin client)', () => {
  it('rotates the key, re-wraps what it can, drops the rest, and matches the vector', async () => {
    const { file, raw } = await rotationInput();
    const session = await sessionFromRaw(new Uint8Array(raw) as ReturnType<typeof unb64>);
    const newKey = new Uint8Array(32).fill(0xee) as ReturnType<typeof unb64>;
    let n = 0;
    const res = await rotateVaultKey(file, session, {
      password: 'new password', kdf: NEW_KDF, recoveryCodes: NEW_CODES, recoveryKey: NEW_RKEY, dropUnknown: true,
      prf: { 'cred-1': PRF_OUT }, usbKeyFiles: [USB_TEXT],
    }, { iv: ivFor(newKey), rng: (k) => new Uint8Array(k).fill(0x33) as ReturnType<typeof unb64>, newKey, newId: () => `n${n++}`, now: 5000 });
    const out = res.file;
    const vec = {
      vaultKeyHex: KEY_HEX, newKeyHex: Buffer.from(newKey).toString('hex'), now: 5000,
      plan: { password: 'new password', kdf: NEW_KDF, recoveryCodes: NEW_CODES, recoveryKey: NEW_RKEY, prfCredId: 'cred-1', prfOutputHex: Buffer.from(PRF_OUT).toString('hex'), usbKeyFile: USB_TEXT },
      secrets: { oldPassword: 'old password', oldCode: OLD_CODE },
      input: JSON.stringify(file), output: JSON.stringify(out), dropped: res.dropped.map((d) => `${d.type}:${d.id}`).sort(),
    };
    const vp = join(dir, 'vectors', 'rotation.json');
    if (process.env.PEVV_WRITE_GOLDEN === '1') writeFileSync(vp, JSON.stringify(vec, null, 1) + '\n');
    expect(vec).toEqual(JSON.parse(readFileSync(vp, 'utf8')));

    // What the rotation promises.
    expect(out.v).toBe(2);
    expect(out.keyEpoch).toBe(1);
    expect(out.rev).toBe(8);
    expect(res.dropped.map((d) => d.type).sort()).toEqual(['hw-token', 'prf']);
    expect(out.slots.map((x) => x.type)).toEqual(['password', 'prf', 'usb-key', 'recovery-code', 'recovery-code', 'recovery-key']);
    expect((out as unknown as J)['x-future']).toEqual({ a: 1 });
    validateFile(out);
    const same = (s: Session) => expect(Buffer.from(s.raw).toString('hex')).toBe(Buffer.from(newKey).toString('hex'));
    same(await unlockWithPassword(out, 'new password'));
    same(await unlockWithPrf(out, 'cred-1', PRF_OUT));
    same(await unlockWithUsbKey(out, USB_TEXT));
    same((await unlockWithRecoveryCode(out, NEW_CODES[1]!)).session);
    same(await unlockWithRecoveryKey(out, NEW_RKEY));
    await expect(unlockWithPassword(out, 'old password')).rejects.toThrow();
    await expect(unlockWithRecoveryCode(out, OLD_CODE)).rejects.toThrow();
    // The old key opens nothing any more; the new key opens everything with the same ids and versions.
    const oldKey = await aesKeyFromRaw(raw);
    for (const r of out.entries) {
      await expect(openJson(oldKey, r.sealed, aad.entry(out.id, r.id, r.ver))).rejects.toThrow();
      await expect(openJson(res.session.key, r.sealed, aad.entry(out.id, r.id, r.ver))).resolves.toBeTruthy();
    }
    expect(await readMeta(out, res.session)).toMatchObject({ futureMeta: true });
    // A client that only knows v1 refuses the file instead of mixing keys (the check validateFile made before v2 existed).
    const oldClientAccepts = (f: VaultFile) => f.format === 'luciverse.pevv' && f.v === 1;
    expect(oldClientAccepts(file)).toBe(true);
    expect(oldClientAccepts(out)).toBe(false);
    // v2 must carry its epoch.
    expect(() => validateFile({ ...out, keyEpoch: undefined })).toThrow();
  }, 60_000);

  it('refuses to drop slot kinds it does not know unless told to', async () => {
    const { file, raw } = await rotationInput();
    const session = await sessionFromRaw(new Uint8Array(raw) as ReturnType<typeof unb64>);
    await expect(rotateVaultKey(file, session, { password: 'x', kdf: NEW_KDF })).rejects.toThrow('unknown-slot');
  }, 30_000);
});
