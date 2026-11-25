/**
 * PEVV vault engine: pure async functions over the on-disk VaultFile and an
 * in-memory Session (the unwrapped vault key). No React, no storage.
 */
import { type Bytes, b64, ctEqual, randomBytes, unb64, wipe } from './bytes';
import {
  type KdfParams,
  DecryptError,
  aad,
  aesKeyFromRaw,
  hkdfAesKey,
  newKdf,
  newVaultKey,
  openJson,
  passwordKek,
  sealJson,
  unwrapVaultKey,
  wrapVaultKey,
} from './crypto';
import { type Entry, type EntryData, type EntryRecord, type Slot, type UsbKeyGate, type VaultFile, type VaultMeta, VAULT_FORMAT, newId } from './model';
import { RECOVERY_CODE_COUNT, codeHash, codeKek, newRecoveryCode, newRecoveryKey, normalizeCode, recoveryKeyKek } from './recovery';
import type { TotpConfig } from './totp';
import { USB_KEK_INFO, gateCheck, gateMatches, newKeyFile, parseKeyFile } from './usbkey';

export interface Session { raw: Bytes; key: CryptoKey }

export async function sessionFromRaw(raw: Bytes): Promise<Session> {
  return { raw, key: await aesKeyFromRaw(raw) };
}

export function endSession(s: Session | null): void {
  if (s) wipe(s.raw);
}

const DEFAULT_META: VaultMeta = {
  environments: ['dev', 'prod'],
  activeEnv: 'dev',
  grants: {},
  index: {},
  require: { totp: false, passkey: false, usbKey: false },
  usbKeys: [],
  totpLastStep: null,
  folders: [],
  projectEnv: {},
  devices: [],
  revokedDevices: [],
};

export async function createVault(password: string, kdf?: KdfParams): Promise<{ file: VaultFile; session: Session }> {
  const id = newId();
  const params = kdf ?? (await newKdf('standard'));
  const raw = newVaultKey();
  const session = await sessionFromRaw(raw);
  const slotId = newId();
  const kek = await passwordKek(password, params);
  const now = Date.now();
  const file: VaultFile = {
    format: VAULT_FORMAT,
    v: 1,
    id,
    created: now,
    updated: now,
    rev: 1,
    kdf: params,
    slots: [{ id: slotId, type: 'password', wrapped: await wrapVaultKey(kek, raw, id, slotId) }],
    passkeys: [],
    require: { totp: false, passkey: false },
    totp: null,
    meta: await sealJson(session.key, DEFAULT_META, aad.meta(id, 1)),
    entries: [],
  };
  return { file, session };
}

export function validateFile(f: unknown): asserts f is VaultFile {
  const v = f as VaultFile;
  if (!v || v.format !== VAULT_FORMAT || (v.v !== 1 && v.v !== 2) || typeof v.id !== 'string' || !Array.isArray(v.slots) || !Array.isArray(v.entries)) {
    throw new Error('not a PEVV vault file');
  }
  // v2 is a vault whose key was rotated: it must say so, so a stale copy can be told apart from it.
  if (v.v === 2 && !(Number.isInteger(v.keyEpoch) && (v.keyEpoch as number) >= 1)) throw new Error('not a PEVV vault file');
  // Slot types this client does not know are kept and ignored (older clients do the same with usb-key);
  // the ones it does know about must be well formed.
  for (const s of v.slots as unknown[]) {
    const slot = s as Partial<Slot> | null;
    if (!slot || typeof slot !== 'object' || typeof slot.id !== 'string' || typeof slot.type !== 'string') throw new Error('not a PEVV vault file');
    if (slot.type === 'usb-key') {
      const u = slot as Partial<Extract<Slot, { type: 'usb-key' }>>;
      if (typeof u.salt !== 'string' || typeof u.name !== 'string' || typeof u.wrapped?.iv !== 'string' || typeof u.wrapped?.ct !== 'string') throw new Error('not a PEVV vault file');
    }
  }
}

export async function unlockWithPassword(file: VaultFile, password: string): Promise<Session> {
  const kek = await passwordKek(password, file.kdf);
  for (const s of file.slots) {
    if (s.type !== 'password') continue;
    try {
      return await sessionFromRaw(await unwrapVaultKey(kek, s.wrapped, file.id, s.id));
    } catch { /* try next */ }
  }
  throw new DecryptError('wrong master password');
}

export async function prfKek(prfOutput: Uint8Array, salt: string): Promise<CryptoKey> {
  return hkdfAesKey(prfOutput, unb64(salt), 'luciverse/pevv/v1/prf-kek');
}

export async function unlockWithPrf(file: VaultFile, credId: string, prfOutput: Uint8Array): Promise<Session> {
  const slot = file.slots.find((s) => s.type === 'prf' && s.credId === credId) as Extract<Slot, { type: 'prf' }> | undefined;
  if (!slot) throw new DecryptError('this passkey is not enrolled for unlock');
  return sessionFromRaw(await unwrapVaultKey(await prfKek(prfOutput, slot.salt), slot.wrapped, file.id, slot.id));
}

export async function usbKek(secret: Uint8Array, salt: string): Promise<CryptoKey> {
  return hkdfAesKey(secret, unb64(salt), USB_KEK_INFO);
}

/** Unlock with the text of a `.pevvkey` file: any `usb-key` slot it opens will do. */
export async function unlockWithUsbKey(file: VaultFile, keyFileText: string): Promise<Session> {
  const { secret } = parseKeyFile(keyFileText);
  for (const s of file.slots) {
    if (s.type !== 'usb-key') continue;
    try {
      return await sessionFromRaw(await unwrapVaultKey(await usbKek(secret, s.salt), s.wrapped, file.id, s.id));
    } catch { /* next slot */ }
  }
  throw new DecryptError('this key file does not open the vault');
}

export function usbKeySlots(file: VaultFile): Array<Extract<Slot, { type: 'usb-key' }>> {
  return file.slots.filter((s): s is Extract<Slot, { type: 'usb-key' }> => s.type === 'usb-key');
}

/**
 * A new key file. `unlock` adds a slot (the file alone opens the vault); `second-factor` adds a gate record
 * (the file is only asked for after the master password). Returns the file text for the caller to write
 * to the drive; the caller should commit the returned vault only after that succeeded.
 */
export async function addUsbKey(
  file: VaultFile, session: Session, meta: VaultMeta, name: string, mode: 'unlock' | 'second-factor',
): Promise<{ file: VaultFile; meta: VaultMeta; text: string }> {
  const kf = newKeyFile(file.id);
  const id = newId();
  const label = name.trim().slice(0, 60) || 'USB key';
  if (mode === 'unlock') {
    const salt = b64(randomBytes(32));
    const wrapped = await wrapVaultKey(await usbKek(kf.secret, salt), session.raw, file.id, id);
    const slots: Slot[] = [...file.slots, { id, type: 'usb-key', name: label, salt, wrapped }];
    return { file: await commit(file, session, meta, { slots }), meta, text: kf.text };
  }
  const gate: UsbKeyGate = { id, name: label, check: await gateCheck(kf.secret), added: Date.now() };
  const nextMeta: VaultMeta = { ...meta, usbKeys: [...(meta.usbKeys ?? []), gate] };
  return { file: await commit(file, session, nextMeta), meta: nextMeta, text: kf.text };
}

export async function removeUsbKey(file: VaultFile, session: Session, meta: VaultMeta, id: string): Promise<{ file: VaultFile; meta: VaultMeta }> {
  const usbKeys = (meta.usbKeys ?? []).filter((g) => g.id !== id);
  const nextMeta: VaultMeta = { ...meta, usbKeys, require: { ...meta.require, usbKey: usbKeys.length ? !!meta.require.usbKey : false } };
  return { file: await commit(file, session, nextMeta, { slots: file.slots.filter((s) => s.id !== id) }), meta: nextMeta };
}

export async function setRequireUsbKey(file: VaultFile, session: Session, meta: VaultMeta, on: boolean): Promise<{ file: VaultFile; meta: VaultMeta }> {
  const nextMeta: VaultMeta = { ...meta, require: { ...meta.require, usbKey: on } };
  return { file: await commit(file, session, nextMeta), meta: nextMeta };
}

/** Does this key file satisfy the second factor for the open session? A gate record or a slot of this vault. */
export async function checkUsbKeyFactor(file: VaultFile, session: Session, meta: VaultMeta, keyFileText: string): Promise<boolean> {
  const { secret } = parseKeyFile(keyFileText);
  for (const g of meta.usbKeys ?? []) if (await gateMatches(secret, g.check)) return true;
  for (const s of usbKeySlots(file)) {
    try {
      const raw = await unwrapVaultKey(await usbKek(secret, s.salt), s.wrapped, file.id, s.id);
      const same = ctEqual(raw, session.raw);
      wipe(raw);
      if (same) return true;
    } catch { /* not this slot */ }
  }
  return false;
}

export async function unlockWithRecoveryCode(file: VaultFile, code: string): Promise<{ session: Session; slotId: string }> {
  if (normalizeCode(code).length !== 20) throw new DecryptError('recovery codes have 20 characters');
  for (const s of file.slots) {
    if (s.type !== 'recovery-code') continue;
    if ((await codeHash(code, s.salt)) !== s.hash) continue;
    const raw = await unwrapVaultKey(await codeKek(code, s.salt), s.wrapped, file.id, s.id);
    return { session: await sessionFromRaw(raw), slotId: s.id };
  }
  throw new DecryptError('unknown or already used recovery code');
}

export async function unlockWithRecoveryKey(file: VaultFile, key: string): Promise<Session> {
  for (const s of file.slots) {
    if (s.type !== 'recovery-key') continue;
    try {
      return await sessionFromRaw(await unwrapVaultKey(await recoveryKeyKek(key, s.salt), s.wrapped, file.id, s.id));
    } catch { /* next */ }
  }
  throw new DecryptError('recovery key does not match this vault');
}

let writerId: string | undefined;
/** The device id stamped into the sealed meta of every write, so other devices can reject a write from a revoked one. */
export function setWriterId(id: string | undefined): void { writerId = id; }

/** Bump revision and re-seal meta (meta AAD is bound to the revision). */
async function commit(file: VaultFile, session: Session, meta: VaultMeta, patch: Partial<VaultFile> = {}): Promise<VaultFile> {
  const rev = file.rev + 1;
  if (writerId) meta = { ...meta, lastWriter: writerId };
  const next: VaultFile = { ...file, ...patch, rev, updated: Date.now() };
  next.require = { ...meta.require };
  next.meta = await sealJson(session.key, meta, aad.meta(file.id, rev));
  return next;
}

export interface Decrypted {
  entries: Entry[];
  meta: VaultMeta;
  totp: TotpConfig | null;
  warnings: string[];
}

export async function decryptAll(file: VaultFile, session: Session): Promise<Decrypted> {
  const meta = { ...DEFAULT_META, ...(await openJson<VaultMeta>(session.key, file.meta, aad.meta(file.id, file.rev))) };
  const warnings: string[] = [];
  const entries: Entry[] = [];
  for (const r of file.entries) {
    try {
      const data = await openJson<EntryData>(session.key, r.sealed, aad.entry(file.id, r.id, r.ver));
      entries.push({ ...data, id: r.id, ver: r.ver });
    } catch {
      warnings.push(`entry ${r.id.slice(0, 6)} could not be decrypted`);
    }
    if (meta.index[r.id] !== r.ver) warnings.push(`entry ${r.id.slice(0, 6)} does not match the vault index (modified outside PEVV?)`);
  }
  for (const id of Object.keys(meta.index)) if (!file.entries.some((e) => e.id === id)) warnings.push(`entry ${id.slice(0, 6)} is missing from the file`);
  if (meta.require.totp !== file.require.totp || meta.require.passkey !== file.require.passkey || !!meta.require.usbKey !== !!file.require.usbKey) warnings.push('second-factor settings in the file were altered; using the encrypted copy');
  let totp: TotpConfig | null = null;
  if (file.totp) totp = await openJson<TotpConfig>(session.key, file.totp, aad.totp(file.id));
  if (meta.require.totp && !totp) warnings.push('TOTP is required but its secret is missing');
  return { entries, meta, totp, warnings };
}

export async function readMeta(file: VaultFile, session: Session): Promise<VaultMeta> {
  return { ...DEFAULT_META, ...(await openJson<VaultMeta>(session.key, file.meta, aad.meta(file.id, file.rev))) };
}

export async function putEntry(file: VaultFile, session: Session, meta: VaultMeta, id: string | null, data: EntryData): Promise<{ file: VaultFile; meta: VaultMeta; entry: Entry }> {
  const eid = id ?? newId();
  const prev = file.entries.find((e) => e.id === eid);
  const ver = (prev?.ver ?? 0) + 1;
  const rec: EntryRecord = { id: eid, ver, sealed: await sealJson(session.key, data, aad.entry(file.id, eid, ver)) };
  const entries = prev ? file.entries.map((e) => (e.id === eid ? rec : e)) : [...file.entries, rec];
  const nextMeta = { ...meta, index: { ...meta.index, [eid]: ver } };
  return { file: await commit(file, session, nextMeta, { entries }), meta: nextMeta, entry: { ...data, id: eid, ver } };
}

export async function removeEntry(file: VaultFile, session: Session, meta: VaultMeta, id: string): Promise<{ file: VaultFile; meta: VaultMeta }> {
  const index = { ...meta.index };
  delete index[id];
  const nextMeta = { ...meta, index };
  return { file: await commit(file, session, nextMeta, { entries: file.entries.filter((e) => e.id !== id) }), meta: nextMeta };
}

export async function saveMeta(file: VaultFile, session: Session, meta: VaultMeta): Promise<VaultFile> {
  return commit(file, session, meta);
}

export async function changePassword(file: VaultFile, session: Session, meta: VaultMeta, password: string, kdf?: KdfParams): Promise<VaultFile> {
  const params = kdf ?? (await newKdf(file.kdf.alg === 'argon2id' && file.kdf.m > 65_536 ? 'strong' : 'standard'));
  const slotId = newId();
  const kek = await passwordKek(password, params);
  const slots: Slot[] = [
    { id: slotId, type: 'password', wrapped: await wrapVaultKey(kek, session.raw, file.id, slotId) },
    ...file.slots.filter((s) => s.type !== 'password'),
  ];
  return commit(file, session, meta, { kdf: params, slots });
}

export async function addPrfSlot(file: VaultFile, session: Session, meta: VaultMeta, credId: string, prfOutput: Uint8Array): Promise<VaultFile> {
  const salt = b64(randomBytes(32));
  const id = newId();
  const wrapped = await wrapVaultKey(await prfKek(prfOutput, salt), session.raw, file.id, id);
  const slots: Slot[] = [...file.slots.filter((s) => !(s.type === 'prf' && s.credId === credId)), { id, type: 'prf', credId, salt, wrapped }];
  return commit(file, session, meta, { slots });
}

export function removeSlotsFor(file: VaultFile, credId: string): Slot[] {
  return file.slots.filter((s) => !(s.type === 'prf' && s.credId === credId));
}

export async function replaceRecoveryCodes(file: VaultFile, session: Session, meta: VaultMeta, count = RECOVERY_CODE_COUNT): Promise<{ file: VaultFile; codes: string[] }> {
  const codes: string[] = [];
  const slots: Slot[] = file.slots.filter((s) => s.type !== 'recovery-code');
  for (let i = 0; i < count; i++) {
    const code = newRecoveryCode();
    const salt = b64(randomBytes(16));
    const id = newId();
    slots.push({ id, type: 'recovery-code', salt, hash: await codeHash(code, salt), wrapped: await wrapVaultKey(await codeKek(code, salt), session.raw, file.id, id) });
    codes.push(code);
  }
  return { file: await commit(file, session, meta, { slots }), codes };
}

export async function consumeSlot(file: VaultFile, session: Session, meta: VaultMeta, slotId: string): Promise<VaultFile> {
  return commit(file, session, meta, { slots: file.slots.filter((s) => s.id !== slotId) });
}

export async function replaceRecoveryKey(file: VaultFile, session: Session, meta: VaultMeta): Promise<{ file: VaultFile; key: string }> {
  const key = newRecoveryKey();
  const salt = b64(randomBytes(16));
  const id = newId();
  const slots: Slot[] = [
    ...file.slots.filter((s) => s.type !== 'recovery-key'),
    { id, type: 'recovery-key', salt, wrapped: await wrapVaultKey(await recoveryKeyKek(key, salt), session.raw, file.id, id) },
  ];
  return { file: await commit(file, session, meta, { slots }), key };
}

export async function setTotp(file: VaultFile, session: Session, meta: VaultMeta, cfg: TotpConfig | null): Promise<{ file: VaultFile; meta: VaultMeta }> {
  // A new (or removed) authenticator starts a new trust epoch: nothing remembered about the old one counts.
  const nextMeta: VaultMeta = { ...meta, require: { ...meta.require, totp: !!cfg }, totpLastStep: null, trustEpoch: (typeof meta.trustEpoch === 'number' ? meta.trustEpoch : 0) + 1 };
  const totp = cfg ? await sealJson(session.key, cfg, aad.totp(file.id)) : null;
  return { file: await commit(file, session, nextMeta, { totp }), meta: nextMeta };
}

export function recoveryStatus(file: VaultFile): { codes: number; key: boolean; prf: number; usb: number } {
  return {
    codes: file.slots.filter((s) => s.type === 'recovery-code').length,
    key: file.slots.some((s) => s.type === 'recovery-key'),
    prf: file.slots.filter((s) => s.type === 'prf').length,
    usb: file.slots.filter((s) => s.type === 'usb-key').length,
  };
}

/* ───────────── encrypted export / import ───────────── */

export interface ExportFile {
  format: 'luciverse.pevv.export';
  /** 1 = items and environments only (legacy). 2 = the whole vault file, still sealed. */
  v: 1 | 2;
  id: string;
  created: string;
  kdf: KdfParams;
  sealed: { iv: string; ct: string };
}

export type OpenedExport =
  | { kind: 'items'; entries: EntryData[]; environments: string[] }
  | { kind: 'vault'; file: VaultFile };

/** Version is outside the seal so the UI can ask for a new master password only on legacy files. */
export function peekExport(text: string): 1 | 2 | 0 {
  try {
    const j = JSON.parse(text) as Partial<ExportFile>;
    if (j?.format !== 'luciverse.pevv.export') return 0;
    if (j.v === 2) return 2;
    if (j.v === 1) return 1;
    return 0;
  } catch { return 0; }
}

export async function exportEncrypted(entries: Entry[], meta: Pick<VaultMeta, 'environments'>, password: string, kdf?: KdfParams): Promise<ExportFile> {
  const params = kdf ?? (await newKdf('standard'));
  const id = newId();
  const kek = await passwordKek(password, params);
  const payload = { entries: entries.map(({ id: _i, ver: _v, ...d }) => d), environments: meta.environments };
  return { format: 'luciverse.pevv.export', v: 1, id, created: new Date().toISOString(), kdf: params, sealed: await sealJson(kek, payload, aad.export(id)) };
}

/**
 * Whole-vault export. The sealed payload is the vault file itself: items,
 * authenticator secret, recovery-code slots, recovery-key slot and passkey
 * registrations. The master password and the text of recovery codes are not
 * in the file (those slots still unlock with the same codes). A second layer
 * (the export password) hides even the ciphertext.
 */
export async function exportPortable(file: VaultFile, password: string, kdf?: KdfParams): Promise<ExportFile> {
  validateFile(file);
  const params = kdf ?? (await newKdf('standard'));
  const kek = await passwordKek(password, params);
  const payload = { kind: 'vault' as const, file };
  return { format: 'luciverse.pevv.export', v: 2, id: file.id, created: new Date().toISOString(), kdf: params, sealed: await sealJson(kek, payload, aad.export(file.id)) };
}

export async function openExport(file: ExportFile, password: string): Promise<OpenedExport> {
  if (file?.format !== 'luciverse.pevv.export' || (file.v !== 1 && file.v !== 2)) throw new Error('not a PEVV export file');
  const kek = await passwordKek(password, file.kdf);
  if (file.v === 1) {
    const p = await openJson<{ entries: EntryData[]; environments?: string[] }>(kek, file.sealed, aad.export(file.id));
    if (!Array.isArray(p.entries)) throw new Error('export is empty');
    return { kind: 'items', entries: p.entries, environments: p.environments ?? [] };
  }
  const p = await openJson<{ kind?: string; file: VaultFile }>(kek, file.sealed, aad.export(file.id));
  validateFile(p.file);
  if (p.file.id !== file.id) throw new Error('export is damaged');
  return { kind: 'vault', file: p.file };
}

export async function importEncrypted(file: ExportFile, password: string): Promise<{ entries: EntryData[]; environments: string[] }> {
  const opened = await openExport(file, password);
  if (opened.kind !== 'items') throw new Error('this export is a full vault');
  return { entries: opened.entries, environments: opened.environments };
}
