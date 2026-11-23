/**
 * Sync merge: folds two copies of the same vault into one without losing an edit. Pure functions over ciphertext
 * files and the unwrapped key; no storage, no network. The Kotlin twin is android/.../core/Merge.kt and both are
 * held byte-for-byte equal by tests/sync-scenarios (docs/SYNC.md has the rules in prose).
 *
 *  - Items are merged one by one (three-way when the last-synced copy `base` is known, two-way otherwise).
 *  - Same item edited on both sides: the newest edit wins (`updated`, then `ver`, then a fixed byte order) and the
 *    loser is kept inside the winner as `conflicts[]`. Nothing is dropped.
 *  - Deleted on one side, edited on the other: the edit wins and the item stays.
 *  - A copy written under an older key, or by a device the roster has revoked, is rejected.
 *  - Fields this client does not know (top level, meta, items, slots) are carried through untouched.
 */
import { type Bytes, utf8 } from './bytes';
import { aad, openJson, sealJson } from './crypto';
import type { ConflictCopy, EntryRecord, VaultFile, VaultMeta } from './model';
import { mergeRoster } from './devices';
import { type Session, readMeta, validateFile } from './vault';

export const CONFLICT_KEEP = 5;

export type Rejection = 'other-vault' | 'stale-key' | 'key-mismatch' | 'revoked-writer';
export interface ConflictNote { id: string; title: string; kind: 'edited-both' | 'deleted-vs-edited'; kept: 'local' | 'remote' }
export type MergeKind = 'same' | 'kept-local' | 'took-remote' | 'merged' | 'key-rotated' | 'rejected';
export interface MergeOutcome { kind: MergeKind; file: VaultFile | null; conflicts: ConflictNote[]; reason?: Rejection }

export interface MergeOptions {
  /** Deterministic IV source for golden tests. Production leaves it unset (random 96-bit IV per seal). */
  iv?: (aad: string, plain: Uint8Array) => Bytes | Promise<Bytes>;
  now?: number;
  /** Device id to stamp into the merged meta as `lastWriter`. */
  writer?: string;
}

type Obj = Record<string, unknown>;

/** JSON with sorted keys: the same text in every client, used for equality and tie-breaks. */
export function canon(v: unknown): string {
  if (v === undefined) return 'undefined';
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  const o = v as Obj;
  return `{${Object.keys(o).sort().filter((k) => o[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canon(o[k])}`).join(',')}}`;
}

export const keyEpoch = (f: { keyEpoch?: number | undefined }): number => (typeof f.keyEpoch === 'number' ? f.keyEpoch : 0);

const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const num = (v: unknown): number => (typeof v === 'number' ? v : 0);
const recEq = (x: EntryRecord, y: EntryRecord): boolean => x.ver === y.ver && x.sealed.iv === y.sealed.iv && x.sealed.ct === y.sealed.ct;

async function sealWith(s: Session, value: unknown, aadText: string, o: MergeOptions) {
  const iv = o.iv ? await o.iv(aadText, utf8(JSON.stringify(value))) : undefined;
  return sealJson(s.key, value, aadText, iv);
}

/** Three-way pick of one value. `undefined` means absent. Without a base, a present value beats an absent one. */
function pick(hasBase: boolean, base: unknown, a: unknown, b: unknown): unknown {
  const ca = canon(a);
  const cb = canon(b);
  if (ca === cb) return a;
  if (hasBase) {
    const c0 = canon(base);
    if (c0 === ca) return b;
    if (c0 === cb) return a;
  }
  return a !== undefined ? a : b;
}

const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/** Ordered union of two lists; with a base, an item one side removed stays removed. */
function mergeList(hasBase: boolean, base: unknown, a: unknown, b: unknown): unknown[] {
  const la = arr(a);
  const lb = arr(b);
  const out = [...la];
  const have = new Set(la.map(canon));
  for (const x of lb) if (!have.has(canon(x))) out.push(x);
  if (!hasBase) return out;
  const inBase = new Set(arr(base).map(canon));
  const inB = new Set(lb.map(canon));
  return out.filter((x) => {
    const c = canon(x);
    return !(inBase.has(c) && (!have.has(c) || !inB.has(c)));
  });
}

function mergeMap(hasBase: boolean, base: unknown, a: unknown, b: unknown, each: (hb: boolean, x: unknown, y: unknown, z: unknown) => unknown): Obj {
  const oa = isObj(a) ? a : {};
  const ob = isObj(b) ? b : {};
  const o0 = isObj(base) ? base : {};
  const out: Obj = {};
  for (const k of [...Object.keys(oa), ...Object.keys(ob).filter((x) => !(x in oa))]) {
    const v = each(hasBase, o0[k], oa[k], ob[k]);
    if (v !== undefined) out[k] = v;
  }
  return out;
}

function mergeById(hasBase: boolean, base: unknown, a: unknown, b: unknown): unknown {
  const items = [arr(a), arr(b), arr(base)];
  if (!items.every((l) => l.every((x) => isObj(x) && typeof x.id === 'string'))) return pick(hasBase, base, a, b);
  const idx = (l: unknown[]) => new Map(l.map((x) => [(x as Obj).id as string, x]));
  const [ma, mb, m0] = [idx(items[0]!), idx(items[1]!), idx(items[2]!)];
  const out: unknown[] = [];
  for (const id of [...ma.keys(), ...[...mb.keys()].filter((k) => !ma.has(k))]) {
    const v = pick(hasBase, m0.get(id), ma.get(id), mb.get(id));
    if (v !== undefined) out.push(v);
  }
  return out;
}

function mergeMeta(hasBase: boolean, base: VaultMeta | null, a: VaultMeta, b: VaultMeta): VaultMeta {
  const A = a as unknown as Obj;
  const B = b as unknown as Obj;
  const B0 = (base ?? {}) as unknown as Obj;
  const roster = mergeRoster(
    { devices: a.devices, revokedDevices: a.revokedDevices ?? [] },
    { devices: b.devices, revokedDevices: b.revokedDevices ?? [] },
  );
  const out: Obj = {};
  for (const k of [...Object.keys(A), ...Object.keys(B).filter((x) => !(k_in(A, x)))]) {
    let v: unknown;
    switch (k) {
      case 'environments':
      case 'folders': v = mergeList(hasBase, B0[k], A[k], B[k]); break;
      case 'grants': v = mergeMap(hasBase, B0[k], A[k], B[k], (hb, x, y, z) => { const l = mergeList(hb, x, y, z); return l.length ? l : undefined; }); break;
      case 'projectEnv':
      case 'require': v = mergeMap(hasBase, B0[k], A[k], B[k], pick); break;
      case 'usbKeys': v = mergeById(hasBase, B0[k], A[k], B[k]); break;
      case 'devices': v = roster.devices; break;
      case 'revokedDevices': v = roster.revokedDevices; break;
      case 'totpLastStep': v = typeof A[k] === 'number' && typeof B[k] === 'number' ? Math.max(A[k] as number, B[k] as number) : pick(hasBase, B0[k], A[k], B[k]); break;
      default: v = pick(hasBase, B0[k], A[k], B[k]);
    }
    if (v !== undefined) out[k] = v;
  }
  return out as unknown as VaultMeta;
}
const k_in = (o: Obj, k: string) => Object.prototype.hasOwnProperty.call(o, k);

const KNOWN_TOP = new Set(['format', 'v', 'id', 'created', 'updated', 'rev', 'keyEpoch', 'kdf', 'slots', 'passkeys', 'require', 'totp', 'meta', 'entries']);
const CRED = ['kdf', 'slots', 'passkeys', 'totp'] as const;
const credBlock = (f: VaultFile): Obj => ({ kdf: f.kdf, slots: f.slots, passkeys: f.passkeys, totp: f.totp });
const extras = (f: VaultFile): Obj => Object.fromEntries(Object.entries(f as unknown as Obj).filter(([k]) => !KNOWN_TOP.has(k)));

/** Everything that is content (not revision bookkeeping): used to tell "nothing changed" from "something merged". */
function contentKey(f: VaultFile, meta: VaultMeta): string {
  const m = { ...(meta as unknown as Obj) };
  delete m.lastWriter;
  const recs = [...f.entries].sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  return canon({ entries: recs, meta: m, cred: credBlock(f), extras: extras(f) });
}

async function openEntry(s: Session, f: VaultFile, r: EntryRecord): Promise<Obj | null> {
  try { return await openJson<Obj>(s.key, r.sealed, aad.entry(f.id, r.id, r.ver)); } catch { return null; }
}

const withoutConflicts = (d: Obj): Obj => {
  const o = { ...d };
  delete o.conflicts;
  return o;
};

function cmpText(x: string, y: string): number { return x < y ? -1 : x > y ? 1 : 0; }

function snapshot(data: Obj, ver: number): ConflictCopy {
  return { at: num(data.updated), ver, data: withoutConflicts(data) };
}

function keepConflicts(winner: Obj, loser: Obj, loserSnap: ConflictCopy): ConflictCopy[] {
  const all = [loserSnap, ...arr(winner.conflicts), ...arr(loser.conflicts)] as ConflictCopy[];
  const seen = new Set<string>();
  const uniq = all.filter((c) => { const k = canon(c); if (seen.has(k)) return false; seen.add(k); return true; });
  uniq.sort((x, y) => (num(y.at) - num(x.at)) || cmpText(canon(x), canon(y)));
  return uniq.slice(0, CONFLICT_KEEP);
}

/** Fold `remote` into `local`. `base` is the copy last known to be in sync with the server (null when unknown). */
export async function mergeVaults(session: Session, base: VaultFile | null, local: VaultFile, remote: VaultFile, opts: MergeOptions = {}): Promise<MergeOutcome> {
  const none = (kind: MergeKind, file: VaultFile | null, conflicts: ConflictNote[] = [], reason?: Rejection): MergeOutcome => ({ kind, file, conflicts, ...(reason ? { reason } : {}) });
  validateFile(local);
  validateFile(remote);
  if (local.id !== remote.id) return none('rejected', null, [], 'other-vault');
  const le = keyEpoch(local);
  const re = keyEpoch(remote);
  if (re < le) return none('rejected', null, [], 'stale-key');
  if (re > le) return none('key-rotated', remote);
  if (canon(local) === canon(remote)) return none('same', local);
  if (base && (base.id !== local.id || keyEpoch(base) !== le || remote.rev <= base.rev)) base = null;

  let rmeta: VaultMeta;
  try { rmeta = await readMeta(remote, session); } catch { return none('rejected', null, [], 'key-mismatch'); }
  const lmeta = await readMeta(local, session);
  let bmeta: VaultMeta | null = null;
  if (base) { try { bmeta = await readMeta(base, session); } catch { base = null; } }
  const revoked = new Set([...(lmeta.revokedDevices ?? []), ...(bmeta?.revokedDevices ?? [])]);
  if (typeof rmeta.lastWriter === 'string' && revoked.has(rmeta.lastWriter)) return none('rejected', null, [], 'revoked-writer');

  const same = (x: VaultFile, y: VaultFile) => canon(x) === canon(y);
  if (base && same(local, base)) return none('took-remote', remote);
  if (base && same(remote, base)) return none('kept-local', local);

  // Orient the pair by a total order so that the result does not depend on which side is "mine".
  const order = (num(local.rev) - num(remote.rev)) || (num(local.updated) - num(remote.updated)) || cmpText(canon(local), canon(remote));
  const localPrimary = order >= 0;
  const P = localPrimary ? local : remote;
  const S = localPrimary ? remote : local;
  const pmeta = localPrimary ? lmeta : rmeta;
  const smeta = localPrimary ? rmeta : lmeta;
  const side = (primary: boolean): 'local' | 'remote' => (primary === localPrimary ? 'local' : 'remote');
  const hasBase = !!base;

  /* ---- items ---- */
  const baseRecs = new Map((base?.entries ?? []).map((e) => [e.id, e]));
  const pRecs = new Map(P.entries.map((e) => [e.id, e]));
  const sRecs = new Map(S.entries.map((e) => [e.id, e]));
  const ids = [...pRecs.keys(), ...[...sRecs.keys()].filter((k) => !pRecs.has(k))];
  const conflicts: ConflictNote[] = [];
  const merged: EntryRecord[] = [];
  const titleOf = async (f: VaultFile, r: EntryRecord) => String((await openEntry(session, f, r))?.title ?? '');

  for (const id of ids) {
    const rp = pRecs.get(id);
    const rs = sRecs.get(id);
    const r0 = baseRecs.get(id);
    if (rp && rs) {
      if (recEq(rp, rs)) { merged.push(rp); continue; }
      if (hasBase && r0 && recEq(rp, r0)) { merged.push(rs); continue; }
      if (hasBase && r0 && recEq(rs, r0)) { merged.push(rp); continue; }
      const dp = await openEntry(session, P, rp);
      const ds = await openEntry(session, S, rs);
      if (!dp || !ds) { merged.push(dp ? rp : ds ? rs : rp); continue; }
      if (canon(withoutConflicts(dp)) === canon(withoutConflicts(ds))) {
        // Same content (one side already holds the other's resolution): keep the newer record, nothing to report.
        merged.push(rp.ver > rs.ver || (rp.ver === rs.ver && arr(dp.conflicts).length >= arr(ds.conflicts).length) ? rp : rs);
        continue;
      }
      // One side is the other's resolution already: its `conflicts` hold this very version. Take the resolved record.
      const held = (d: Obj, other: Obj) => arr(d.conflicts).some((c) => canon((c as ConflictCopy).data) === canon(withoutConflicts(other)));
      if (held(ds, dp)) { merged.push(rs); continue; }
      if (held(dp, ds)) { merged.push(rp); continue; }
      if (!hasBase) {
        const hi = rp.ver > rs.ver ? rp : rs.ver > rp.ver ? rs : null;
        if (hi) {
          const dh = hi === rp ? dp : ds;
          const dl = hi === rp ? ds : dp;
          if (num(dh.updated) >= num(dl.updated)) { merged.push(hi); continue; }
        }
      }
      const c = (num(dp.updated) - num(ds.updated)) || (rp.ver - rs.ver) || cmpText(canon(withoutConflicts(dp)), canon(withoutConflicts(ds)));
      const win = c >= 0 ? { d: dp, l: ds, lv: rs.ver, p: true } : { d: ds, l: dp, lv: rp.ver, p: false };
      const ver = Math.max(rp.ver, rs.ver) + 1;
      const data: Obj = { ...win.d, conflicts: keepConflicts(win.d, win.l, snapshot(win.l, win.lv)) };
      merged.push({ id, ver, sealed: await sealWith(session, data, aad.entry(local.id, id, ver), opts) });
      conflicts.push({ id, title: String(win.d.title ?? ''), kind: 'edited-both', kept: side(win.p) });
      continue;
    }
    const mine = (rp ?? rs)!;
    const mineIsP = !!rp;
    if (hasBase && r0) {
      // It existed at the last sync and the other side no longer has it.
      if (recEq(mine, r0)) continue;
      merged.push(mine);
      conflicts.push({ id, title: await titleOf(mineIsP ? P : S, mine), kind: 'deleted-vs-edited', kept: side(mineIsP) });
      continue;
    }
    merged.push(mine);
  }

  /* ---- meta, credentials, unknown fields ---- */
  const bm = hasBase ? bmeta : null;
  const meta = mergeMeta(hasBase, bm, pmeta, smeta) as unknown as Obj;
  meta.index = Object.fromEntries(merged.map((r) => [r.id, r.ver]));
  if (opts.writer) meta.lastWriter = opts.writer;
  const credP = credBlock(P);
  const cred = pick(hasBase, base ? credBlock(base) : undefined, credP, credBlock(S)) as Obj;

  const out: Obj = { ...(P as unknown as Obj) };
  for (const [k, v] of Object.entries(S as unknown as Obj)) if (!k_in(out, k)) out[k] = v;
  const rev = Math.max(local.rev, remote.rev) + 1;
  out.created = Math.min(num(local.created), num(remote.created));
  out.updated = opts.now ?? Date.now();
  out.rev = rev;
  for (const k of CRED) out[k] = cred[k];
  out.require = { ...(meta.require as Obj) };
  out.entries = merged;

  const probe = out as unknown as VaultFile;
  const key = contentKey({ ...probe, entries: merged }, meta as unknown as VaultMeta);
  // Adopting a copy is only a no-op when it is also the newer revision; otherwise a merged revision goes on top.
  if (key === contentKey(local, lmeta) && local.rev > remote.rev) return none('kept-local', local, conflicts);
  if (key === contentKey(remote, rmeta) && remote.rev > local.rev) return none('took-remote', remote, conflicts);
  out.meta = await sealWith(session, meta, aad.meta(local.id, rev), opts);
  return none('merged', out as unknown as VaultFile, conflicts);
}

/**
 * Restore the items of an older copy of this vault (a server-side backup revision) as a new revision on top of the
 * current one. The device roster, revoked list, second-factor settings and key slots stay as they are now, so a
 * restore can never bring back a removed device or an old password. Items that differ get a fresh `ver`.
 */
export async function restoreRevision(session: Session, current: VaultFile, old: VaultFile, opts: MergeOptions = {}): Promise<{ file: VaultFile; restored: number; removed: number }> {
  validateFile(current);
  validateFile(old);
  if (old.id !== current.id) throw new Error('other-vault');
  if (keyEpoch(old) !== keyEpoch(current)) throw new Error('stale-key');
  const cur = new Map(current.entries.map((e) => [e.id, e]));
  const oldIds = new Set(old.entries.map((e) => e.id));
  const rev = current.rev + 1;
  const entries: EntryRecord[] = [];
  let restored = 0;
  for (const r of old.entries) {
    const c = cur.get(r.id);
    if (c && recEq(c, r)) { entries.push(c); continue; }
    const data = await openEntry(session, old, r);
    if (!data) throw new Error('key-mismatch');
    const ver = Math.max(c?.ver ?? 0, r.ver) + 1;
    entries.push({ id: r.id, ver, sealed: await sealWith(session, data, aad.entry(current.id, r.id, ver), opts) });
    restored++;
  }
  const removed = current.entries.filter((e) => !oldIds.has(e.id)).length;
  const meta = { ...((await readMeta(current, session)) as unknown as Obj) };
  meta.index = Object.fromEntries(entries.map((r) => [r.id, r.ver]));
  if (opts.writer) meta.lastWriter = opts.writer;
  const out: VaultFile = { ...current, rev, updated: opts.now ?? Date.now(), entries, meta: await sealWith(session, meta, aad.meta(current.id, rev), opts) };
  return { file: out, restored, removed };
}
