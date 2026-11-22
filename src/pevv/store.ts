/**
 * PEVV runtime store. Persists ONLY the ciphertext VaultFile and non-secret
 * prefs. Decrypted entries and the vault key live in memory while unlocked and
 * are dropped on lock (auto-lock, hide, manual, or tab close).
 */
import { create } from 'zustand';
import { type Entry, type EntryData, type VaultFile, type VaultMeta, ENV_NAME, applyEdit, emptyEntry, parseDotenv, serializeDotenv, siteMatches } from './model';
import { type KdfParams, newKdf } from './crypto';
import { type TotpConfig, limiterBlocked, limiterRecord, loadLimiter, newTotpSecret, saveLimiter, verifyTotp } from './totp';
import { type PasskeyRecord, assertPasskey, currentRpId, registerPasskey } from './webauthn';
import { unlockGate } from './native';
import { type RecoveryKit, buildKit, openKit } from './recovery';
import * as V from './vault';
import { ctEqual } from './bytes';
import { type AuditEvent, type AuditRecord, appendAudit, importManagerExport } from './extra';
import { openJson, sealJson } from './crypto';
import { HANDOFF_PATH, openHandoff, readHashToken, sealHandoff, shareUrl, stripHashToken, unpackFrames, type HandoffEnvelope } from './qr';
import { asDevices, clearVaultRevoked, describeDevice, deviceNeedsWrite, localDeviceId, markVaultRevoked, mergeDevices, mergeRoster, sameRoster, setLocalDeviceName, vaultRevokedLocally } from './devices';
import { armVaultBio, clearVaultBio } from './deviceBio';
import { pullCloud, syncEnabled, useCloudFiles } from './host/cloud';
import { dropTransfer, newTransferToken, pullTransfer, putTransfer } from './host/relay';

export const VAULT_KEY = 'lv-pevv-vault-v1';
export const PREFS_KEY = 'lv-pevv-prefs';

export interface Prefs {
  autoLockMin: number; // 0 = only when hidden/closed
  lockOnHide: boolean;
  clipboardSec: number;
  autofill: boolean;
  sync: boolean;
  revealReauthSec: number;
}

export const DEFAULT_PREFS: Prefs = { autoLockMin: 5, lockOnHide: true, clipboardSec: 20, autofill: false, sync: false, revealReauthSec: 120 };

export type Status = 'none' | 'locked' | 'second-factor' | 'set-password' | 'unlocked';
export type View = 'items' | 'generator' | 'audit' | 'settings' | 'activity' | 'devices' | 'qr';
export type QrWaitStep = 'cloud' | 'installing' | 'done' | 'signed-out' | 'nosync' | 'expired';

export interface QrWait {
  step: QrWaitStep;
  checks: number;
  started: number;
  got: number;
  total: number;
}

export interface EnvRequest { programId: string; names: string[]; resolve: (v: Record<string, string> | null) => void }

interface State {
  file: VaultFile | null;
  status: Status;
  entries: Entry[];
  meta: VaultMeta | null;
  totp: TotpConfig | null;
  warnings: string[];
  pending: { totp: boolean; passkey: boolean; usbKey?: boolean };
  prefs: Prefs;
  overlayOpen: boolean;
  view: View;
  selected: string | null;
  busy: boolean;
  error: string | null;
  reauthUntil: number;
  envRequest: EnvRequest | null;
  /** A recovery unlock must set a new password before the vault opens. */
  recoverySlot: string | null;
  /** A new-item draft requested from outside (e.g. `vault set NAME` in the Terminal). */
  draft: { type: 'env'; name: string; env?: string } | null;
  /** Local, encrypted activity log (this device only; loaded while unlocked). */
  audit: AuditRecord[];
  /** Live status of a scanned vault QR that still needs the other device's upload. */
  qrWait: QrWait | null;
}

function loadFile(): VaultFile | null {
  try {
    const raw = localStorage.getItem(VAULT_KEY);
    if (!raw) return null;
    const f = JSON.parse(raw) as unknown;
    V.validateFile(f);
    return f;
  } catch {
    return null;
  }
}

function loadPrefs(): Prefs {
  try {
    return { ...DEFAULT_PREFS, ...(JSON.parse(localStorage.getItem(PREFS_KEY) ?? '{}') as Partial<Prefs>) };
  } catch {
    return { ...DEFAULT_PREFS };
  }
}

const initialFile = typeof localStorage !== 'undefined' ? loadFile() : null;

export const usePevv = create<State>()(() => ({
  file: initialFile,
  status: initialFile ? 'locked' : 'none',
  entries: [],
  meta: null,
  totp: null,
  warnings: [],
  pending: { totp: false, passkey: false },
  prefs: typeof localStorage !== 'undefined' ? loadPrefs() : { ...DEFAULT_PREFS },
  overlayOpen: false,
  view: 'items',
  selected: null,
  busy: false,
  error: null,
  reauthUntil: 0,
  envRequest: null,
  recoverySlot: null,
  draft: null,
  audit: [],
  qrWait: null,
}));

/* ───────────── session (memory only) ───────────── */

let session: V.Session | null = null;
let kdfFactory: (s: 'standard' | 'strong') => Promise<KdfParams> = (s) => newKdf(s);
/** Test hook: cheaper (still validated) KDF params. */
export function __setKdfFactory(f: (s: 'standard' | 'strong') => Promise<KdfParams>): void { kdfFactory = f; }
let lockTimer: ReturnType<typeof setTimeout> | null = null;
let clipTimer: ReturnType<typeof setTimeout> | null = null;
let queue: Promise<unknown> = Promise.resolve();
const listeners = new Set<(f: VaultFile | null) => void>();

/** Subscribe to ciphertext writes (sync uses this). */
export function onVaultWrite(fn: (f: VaultFile | null) => void): () => void {
  listeners.add(fn);
  return () => { listeners.delete(fn); };
}

function persist(file: VaultFile | null): void {
  try {
    if (file) localStorage.setItem(VAULT_KEY, JSON.stringify(file));
    else localStorage.removeItem(VAULT_KEY);
  } catch (e) {
    usePevv.setState({ error: `Could not save the vault: ${(e as Error).message}` });
  }
  for (const fn of listeners) fn(file);
}

function serial<T>(fn: () => Promise<T>): Promise<T> {
  const run = queue.then(fn, fn);
  queue = run.catch(() => undefined);
  return run;
}

function set(p: Partial<State>) { usePevv.setState(p); }
const get = () => usePevv.getState();

export function setPrefs(p: Partial<Prefs>): void {
  const prefs = { ...get().prefs, ...p };
  set({ prefs });
  try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); } catch { /* ignore */ }
  touch();
}

export function isUnlocked(): boolean {
  return get().status === 'unlocked' && !!session;
}

/** Reset the inactivity timer (called on user activity inside PEVV and on reads). */
export function touch(): void {
  if (lockTimer) clearTimeout(lockTimer);
  lockTimer = null;
  const min = get().prefs.autoLockMin;
  if (get().status === 'unlocked' && min > 0) lockTimer = setTimeout(() => lock('timeout'), min * 60_000);
}

export function lock(_reason: 'manual' | 'timeout' | 'hidden' | 'reset' = 'manual'): void {
  if (session && get().status === 'unlocked') audit('lock', undefined, _reason);
  V.endSession(session);
  session = null;
  if (lockTimer) clearTimeout(lockTimer);
  lockTimer = null;
  const req = get().envRequest;
  set({
    status: get().file ? 'locked' : 'none',
    entries: [],
    meta: null,
    totp: null,
    warnings: [],
    pending: { totp: false, passkey: false },
    selected: null,
    reauthUntil: 0,
    recoverySlot: null,
    busy: false,
    audit: [],
  });
  // A program waiting on env vars keeps waiting for the next unlock unless it was a reset.
  if (req && _reason === 'reset') { req.resolve(null); set({ envRequest: null }); }
}

async function openSession(s: V.Session, opts: { skip2fa?: boolean; passkeyDone?: boolean; usbDone?: boolean } = {}): Promise<void> {
  const file = get().file!;
  const d = await V.decryptAll(file, s);
  if ((d.meta.revokedDevices ?? []).includes(localDeviceId())) {
    V.endSession(s);
    markVaultRevoked(file.id);
    destroyVault();
    set({ error: 'device-revoked' });
    return;
  }
  clearVaultRevoked(file.id);
  V.endSession(session);
  session = s;
  const need = {
    totp: d.meta.require.totp && !opts.skip2fa,
    passkey: d.meta.require.passkey && !opts.skip2fa && !opts.passkeyDone,
    usbKey: !!d.meta.require.usbKey && !opts.skip2fa && !opts.usbDone,
  };
  set({ meta: d.meta, totp: d.totp, warnings: d.warnings, error: null });
  if (need.totp || need.passkey || need.usbKey) {
    set({ status: 'second-factor', pending: need, entries: [] });
    pendingEntries = d.entries;
    return;
  }
  finishUnlock(d.entries);
}

let pendingEntries: Entry[] = [];

function finishUnlock(entries: Entry[]): void {
  pendingEntries = [];
  set({ status: 'unlocked', entries, pending: { totp: false, passkey: false, usbKey: false }, reauthUntil: Date.now() + get().prefs.revealReauthSec * 1000, busy: false });
  touch();
  const kind = unlockKind;
  unlockKind = 'unlock';
  void loadAudit().then(() => audit(kind));
  void rememberThisDevice();
}

let unlockKind: AuditEvent = 'unlock';

function limiterKey(kind: string) { return `${kind}:${get().file?.id ?? 'none'}`; }

function guardLimiter(kind: string): void {
  const ms = limiterBlocked(loadLimiter(limiterKey(kind)));
  if (ms > 0) throw new Error(`Too many attempts. Try again in ${Math.ceil(ms / 1000)} s.`);
}

function recordLimiter(kind: string, ok: boolean): void {
  const k = limiterKey(kind);
  saveLimiter(k, limiterRecord(loadLimiter(k), ok));
}

async function withBusy<T>(fn: () => Promise<T>): Promise<T> {
  set({ busy: true, error: null });
  try {
    return await fn();
  } catch (e) {
    set({ error: (e as Error).message });
    throw e;
  } finally {
    set({ busy: false });
  }
}

/* ───────────── lifecycle ───────────── */

export async function createVault(password: string, strength: 'standard' | 'strong' = 'standard'): Promise<void> {
  if (get().file) throw new Error('a vault already exists on this device');
  await withBusy(async () => {
    const kdf = await kdfFactory(strength);
    const { file, session: s } = await V.createVault(password, kdf);
    set({ file });
    persist(file);
    await openSession(s);
    armVaultBio(password);
  });
}

export async function unlockPassword(password: string): Promise<void> {
  await withBusy(async () => {
    const file = get().file;
    if (!file) throw new Error('no vault');
    const gated = await unlockGate();
    if (gated) throw new Error(gated);
    guardLimiter('pw');
    try {
      const s = await V.unlockWithPassword(file, password);
      recordLimiter('pw', true);
      await openSession(s);
      armVaultBio(password);
    } catch (e) {
      if ((e as Error).name === 'DecryptError') recordLimiter('pw', false);
      throw e;
    }
  });
}

export function prfPasskeys(): PasskeyRecord[] {
  const f = get().file;
  if (!f) return [];
  // Passkeys are bound to the site that created them: only offer this host's.
  const rp = currentRpId();
  return f.passkeys.filter((p) => p.mode === 'prf' && (!p.rpId || p.rpId === rp) && f.slots.some((s) => s.type === 'prf' && s.credId === p.id));
}

export async function unlockPasskey(): Promise<void> {
  await withBusy(async () => {
    const file = get().file;
    if (!file) throw new Error('no vault');
    const gated = await unlockGate();
    if (gated) throw new Error(gated);
    const recs = prfPasskeys();
    if (!recs.length) throw new Error('No passkey on this vault can unlock it on its own. Use your master password.');
    const a = await assertPasskey(recs, { requireUv: true });
    if (!a.prfOutput) throw new Error('This authenticator did not return a PRF secret here. Use your master password (the passkey can still be your second factor).');
    const s = await V.unlockWithPrf(file, a.credId, a.prfOutput);
    await bumpPasskeyUse(file, a.credId, a.signCount, s);
    unlockKind = 'unlock-passkey';
    await openSession(s, { passkeyDone: true });
  });
}

async function bumpPasskeyUse(file: VaultFile, credId: string, signCount: number, _s: V.Session): Promise<void> {
  // Sign counter + last-used are plaintext metadata (no re-seal needed).
  const next: VaultFile = { ...file, passkeys: file.passkeys.map((p) => (p.id === credId ? { ...p, signCount, lastUsed: Date.now() } : p)) };
  set({ file: next });
  persist(next);
}

export async function verifySecondTotp(code: string): Promise<void> {
  await withBusy(async () => {
    const st = get();
    if (st.status !== 'second-factor' || !session || !st.totp || !st.meta) throw new Error('not waiting for a code');
    guardLimiter('totp');
    const step = await verifyTotp(st.totp, code, Date.now(), 1, st.meta.totpLastStep);
    recordLimiter('totp', step !== null);
    if (step === null) throw new Error('That code is not valid. Check your authenticator app and the device clock.');
    const meta = { ...st.meta, totpLastStep: step };
    const file = await V.saveMeta(st.file!, session, meta);
    set({ file, meta, pending: { ...st.pending, totp: false } });
    persist(file);
    if (!get().pending.passkey && !get().pending.usbKey) finishUnlock(pendingEntries);
  });
}

export async function verifySecondPasskey(): Promise<void> {
  await withBusy(async () => {
    const st = get();
    if (st.status !== 'second-factor' || !st.file) throw new Error('not waiting for a passkey');
    const a = await assertPasskey(st.file.passkeys);
    if (!a.verified && st.file.passkeys.find((p) => p.id === a.credId)?.publicKey) throw new Error('passkey check failed');
    await bumpPasskeyUse(st.file, a.credId, a.signCount, session!);
    set({ pending: { ...get().pending, passkey: false } });
    if (!get().pending.totp && !get().pending.usbKey) finishUnlock(pendingEntries);
  });
}

/** Unlock with the text of a `.pevvkey` file (a `usb-key` slot). The file alone is enough, like a PRF passkey. */
export async function unlockUsbKey(keyFileText: string): Promise<void> {
  await withBusy(async () => {
    const file = get().file;
    if (!file) throw new Error('no vault');
    const gated = await unlockGate();
    if (gated) throw new Error(gated);
    if (!V.usbKeySlots(file).length) throw new Error('No USB key file is set up for this vault. Use your master password.');
    guardLimiter('usb');
    try {
      const s = await V.unlockWithUsbKey(file, keyFileText);
      recordLimiter('usb', true);
      unlockKind = 'unlock-usb-key';
      await openSession(s, { usbDone: true });
    } catch (e) {
      if ((e as Error).name === 'DecryptError') recordLimiter('usb', false);
      throw e;
    }
  });
}

/** Second factor after the password: a key file that matches a gate record or a slot of this vault. */
export async function verifySecondUsbKey(keyFileText: string): Promise<void> {
  await withBusy(async () => {
    const st = get();
    if (st.status !== 'second-factor' || !session || !st.file || !st.meta) throw new Error('not waiting for a key file');
    guardLimiter('usb');
    const ok = await V.checkUsbKeyFactor(st.file, session, st.meta, keyFileText);
    recordLimiter('usb', ok);
    if (!ok) throw new Error('That key file does not belong to this vault.');
    set({ pending: { ...get().pending, usbKey: false } });
    const p = get().pending;
    if (!p.totp && !p.passkey) finishUnlock(pendingEntries);
  });
}

export async function unlockRecoveryCode(code: string): Promise<void> {
  await withBusy(async () => {
    const file = get().file;
    if (!file) throw new Error('no vault');
    guardLimiter('rc');
    try {
      const { session: s, slotId } = await V.unlockWithRecoveryCode(file, code);
      recordLimiter('rc', true);
      const d = await V.decryptAll(file, s);
      V.endSession(session);
      session = s;
      pendingEntries = d.entries;
      set({ status: 'set-password', recoverySlot: slotId, meta: d.meta, totp: d.totp, warnings: d.warnings });
    } catch (e) {
      recordLimiter('rc', false);
      throw e;
    }
  });
}

export async function unlockRecoveryKit(kit: RecoveryKit, kitPassphrase: string): Promise<void> {
  await withBusy(async () => {
    const file = get().file;
    if (!file) throw new Error('no vault');
    if (kit.vaultId !== file.id) throw new Error('This recovery kit belongs to a different vault.');
    guardLimiter('kit');
    try {
      const key = await openKit(kit, kitPassphrase);
      const s = await V.unlockWithRecoveryKey(file, key);
      recordLimiter('kit', true);
      const d = await V.decryptAll(file, s);
      V.endSession(session);
      session = s;
      pendingEntries = d.entries;
      set({ status: 'set-password', recoverySlot: null, meta: d.meta, totp: d.totp, warnings: d.warnings });
    } catch (e) {
      recordLimiter('kit', false);
      throw e;
    }
  });
}

/** After a recovery unlock: set a new master password, burn the used code, open the vault. */
export async function finishRecovery(newPassword: string): Promise<void> {
  await withBusy(() => serial(async () => {
    const st = get();
    if (st.status !== 'set-password' || !session || !st.file || !st.meta) throw new Error('not in recovery');
    let file = await V.changePassword(st.file, session, st.meta, newPassword, await kdfFactory('standard'));
    if (st.recoverySlot) file = await V.consumeSlot(file, session, st.meta, st.recoverySlot);
    set({ file, recoverySlot: null });
    persist(file);
    unlockKind = 'unlock-recovery';
    finishUnlock(pendingEntries);
  }));
}

/* ───────────── re-auth for reveal / export ───────────── */

export function needsReauth(): boolean {
  return Date.now() > get().reauthUntil;
}

export async function reauthPassword(password: string): Promise<void> {
  await withBusy(async () => {
    const file = get().file;
    if (!file || !session) throw new Error('vault is locked');
    guardLimiter('pw');
    let s: V.Session;
    try {
      s = await V.unlockWithPassword(file, password);
    } catch (e) {
      recordLimiter('pw', false);
      throw e;
    }
    recordLimiter('pw', true);
    const same = ctEqual(s.raw, session.raw);
    V.endSession(s);
    if (!same) throw new Error('password does not match the open vault');
    set({ reauthUntil: Date.now() + get().prefs.revealReauthSec * 1000 });
    touch();
  });
}

export async function reauthPasskey(): Promise<void> {
  await withBusy(async () => {
    const file = get().file;
    if (!file?.passkeys.length) throw new Error('no passkeys registered');
    const a = await assertPasskey(file.passkeys, { requireUv: true });
    await bumpPasskeyUse(file, a.credId, a.signCount, session!);
    set({ reauthUntil: Date.now() + get().prefs.revealReauthSec * 1000 });
    touch();
  });
}

/* ───────────── entries ───────────── */

function need(): { file: VaultFile; meta: VaultMeta; s: V.Session } {
  const st = get();
  if (st.status !== 'unlocked' || !session || !st.file || !st.meta) throw new Error('vault is locked');
  return { file: st.file, meta: st.meta, s: session };
}

export async function saveEntry(id: string | null, patch: Partial<EntryData> & { type?: EntryData['type'] }): Promise<Entry> {
  if (!id) id = null;
  return serial(async () => {
    const { file, meta, s } = need();
    const prev = id ? get().entries.find((e) => e.id === id) : undefined;
    if (patch.type === 'env' || prev?.type === 'env') {
      const name = patch.name ?? prev?.name ?? '';
      if (!ENV_NAME.test(name)) throw new Error('Variable names use letters, digits and _ and cannot start with a digit.');
    }
    const base: EntryData = prev ? stripIds(prev) : emptyEntry(patch.type ?? 'login');
    const data = applyEdit(base, patch);
    if (!data.title.trim()) data.title = data.name || data.site || data.service || 'Untitled';
    const r = await V.putEntry(file, s, meta, id, data);
    const entries = prev ? get().entries.map((e) => (e.id === r.entry.id ? r.entry : e)) : [...get().entries, r.entry];
    set({ file: r.file, meta: r.meta, entries });
    persist(r.file);
    touch();
    audit(prev ? 'edit' : 'create', r.entry.id);
    return r.entry;
  });
}

function stripIds(e: Entry): EntryData {
  const { id: _i, ver: _v, ...d } = e;
  return d;
}

export async function deleteEntry(id: string): Promise<void> {
  return serial(async () => {
    const { file, meta, s } = need();
    const r = await V.removeEntry(file, s, meta, id);
    const title = get().entries.find((e) => e.id === id)?.title;
    set({ file: r.file, meta: r.meta, entries: get().entries.filter((e) => e.id !== id), selected: get().selected === id ? null : get().selected });
    persist(r.file);
    touch();
    audit('delete', undefined, title);
  });
}

async function writeMeta(patch: Partial<VaultMeta>): Promise<void> {
  const { file, meta, s } = need();
  const next = { ...meta, ...patch };
  const f = await V.saveMeta(file, s, next);
  set({ file: f, meta: next });
  persist(f);
  touch();
}

export async function updateMeta(patch: Partial<VaultMeta>): Promise<void> {
  return serial(() => writeMeta(patch));
}

export async function addEnvironment(name: string): Promise<void> {
  const n = name.trim().slice(0, 24);
  if (!/^[\w.-]+$/.test(n)) throw new Error('Environment names use letters, digits, . _ -');
  const meta = need().meta;
  if (meta.environments.includes(n)) return;
  await updateMeta({ environments: [...meta.environments, n] });
}

export async function setActiveEnv(name: string): Promise<void> {
  const meta = need().meta;
  if (!meta.environments.includes(name)) throw new Error(`no environment named ${name}`);
  await updateMeta({ activeEnv: name });
}

export function envVars(env?: string): Record<string, string> {
  if (!isUnlocked()) return {};
  const target = env ?? get().meta?.activeEnv ?? 'dev';
  const out: Record<string, string> = {};
  for (const e of get().entries) if (e.type === 'env' && (e.env ?? 'dev') === target && e.name) out[e.name] = e.value ?? '';
  return out;
}

export async function importDotenvText(env: string, text: string): Promise<number> {
  const vars = parseDotenv(text);
  const existing = new Map(get().entries.filter((e) => e.type === 'env' && (e.env ?? 'dev') === env).map((e) => [e.name, e]));
  if (!need().meta.environments.includes(env)) await addEnvironment(env);
  for (const v of vars) {
    const prev = existing.get(v.name);
    await saveEntry(prev?.id ?? null, { type: 'env', name: v.name, value: v.value, env, title: v.name });
  }
  audit('import-env', undefined, `${env}: ${vars.length}`);
  return vars.length;
}

export function exportDotenvText(env: string): string {
  audit('export-env', undefined, env);
  return serializeDotenv(get().entries.filter((e) => e.type === 'env' && (e.env ?? 'dev') === env).map((e) => ({ name: e.name ?? '', value: e.value ?? '' })));
}

/* ───────────── security settings ───────────── */

export async function changeMasterPassword(newPassword: string, strength: 'standard' | 'strong' = 'standard'): Promise<void> {
  if (needsReauth()) throw new Error('Confirm your current password first.');
  await withBusy(() => serial(async () => {
    const { file, meta, s } = need();
    const kdf: KdfParams = await kdfFactory(strength);
    const f = await V.changePassword(file, s, meta, newPassword, kdf);
    set({ file: f });
    persist(f);
    audit('password-change', undefined, kdf.alg);
  }));
}

export async function addPasskey(name: string, opts: { wantPrf: boolean; authenticator?: 'platform' | 'cross-platform' }): Promise<PasskeyRecord> {
  return withBusy(() => serial(async () => {
    const { file } = need();
    const reg = await registerPasskey({ vaultId: file.id, name, exclude: file.passkeys.map((p) => p.id), wantPrf: opts.wantPrf, ...(opts.authenticator ? { authenticator: opts.authenticator } : {}) });
    let rec = reg.record;
    let prfOut = reg.prfOutput;
    if (rec.mode === 'prf' && !prfOut) {
      // Most authenticators only evaluate PRF on get(): one more touch.
      try {
        const a = await assertPasskey([rec]);
        prfOut = a.prfOutput;
        rec = { ...rec, signCount: a.signCount, lastUsed: Date.now() };
      } catch { prfOut = null; }
    }
    if (rec.mode === 'prf' && !prfOut) rec = { ...rec, mode: '2fa', prfSalt: null };
    const cur = need();
    let f: VaultFile = { ...cur.file, passkeys: [...cur.file.passkeys, rec] };
    if (rec.mode === 'prf' && prfOut) f = await V.addPrfSlot(f, cur.s, cur.meta, rec.id, prfOut);
    else f = await V.saveMeta(f, cur.s, cur.meta);
    set({ file: f });
    persist(f);
    audit('passkey-add', undefined, `${rec.name} (${rec.mode})`);
    return rec;
  }));
}

export async function removePasskey(credId: string): Promise<void> {
  await serial(async () => {
    const { file, meta, s } = need();
    const passkeys = file.passkeys.filter((p) => p.id !== credId);
    let m = meta;
    if (!passkeys.length && meta.require.passkey) m = { ...meta, require: { ...meta.require, passkey: false } };
    const gone = file.passkeys.find((p) => p.id === credId)?.name;
    const f = await V.saveMeta({ ...file, passkeys, slots: V.removeSlotsFor(file, credId) }, s, m);
    set({ file: f, meta: m });
    persist(f);
    audit('passkey-remove', undefined, gone);
  });
}

/**
 * Make a key file. `write` puts the text on the drive (and reads it back); the vault only changes after it succeeded,
 * so a failed write never leaves a slot that no file opens.
 */
export async function addUsbKey(name: string, mode: 'unlock' | 'second-factor', write: (text: string) => Promise<void>): Promise<void> {
  if (needsReauth()) throw new Error('Confirm your current password first.');
  await withBusy(() => serial(async () => {
    const { file, meta, s } = need();
    const made = await V.addUsbKey(file, s, meta, name, mode);
    await write(made.text);
    set({ file: made.file, meta: made.meta });
    persist(made.file);
    audit('usb-key-add', undefined, `${name.slice(0, 60)} (${mode})`);
  }));
}

export async function removeUsbKey(id: string): Promise<void> {
  await serial(async () => {
    const { file, meta, s } = need();
    const r = await V.removeUsbKey(file, s, meta, id);
    set({ file: r.file, meta: r.meta });
    persist(r.file);
    audit('usb-key-remove');
  });
}

export async function setRequireUsbKey(on: boolean): Promise<void> {
  const { file, meta, s } = need();
  if (on && !(meta.usbKeys ?? []).length) throw new Error('Add a second-factor key file first.');
  await serial(async () => {
    const r = await V.setRequireUsbKey(file, s, meta, on);
    set({ file: r.file, meta: r.meta });
    persist(r.file);
  });
}

export async function setRequirePasskey(on: boolean): Promise<void> {
  const { file, meta } = need();
  if (on && !file.passkeys.length) throw new Error('Add a passkey or security key first.');
  await updateMeta({ require: { ...meta.require, passkey: on } });
}

export function startTotpEnrollment(): TotpConfig {
  return { secret: newTotpSecret(), digits: 6, period: 30, algorithm: 'SHA-1' };
}

export async function confirmTotpEnrollment(cfg: TotpConfig, code: string): Promise<void> {
  await withBusy(() => serial(async () => {
    const step = await verifyTotp(cfg, code);
    if (step === null) throw new Error('That code does not match. Make sure your phone clock is set automatically.');
    const { file, meta, s } = need();
    const r = await V.setTotp(file, s, meta, cfg);
    const m = { ...r.meta, totpLastStep: step };
    const f = await V.saveMeta(r.file, s, m);
    set({ file: f, meta: m, totp: cfg });
    persist(f);
    audit('totp-on');
  }));
}

export async function disableTotp(): Promise<void> {
  if (needsReauth()) throw new Error('Confirm your password first.');
  await serial(async () => {
    const { file, meta, s } = need();
    const r = await V.setTotp(file, s, meta, null);
    set({ file: r.file, meta: r.meta, totp: null });
    persist(r.file);
    audit('totp-off');
  });
}

export async function newRecoveryCodes(): Promise<string[]> {
  if (needsReauth()) throw new Error('Confirm your password first.');
  return serial(async () => {
    const { file, meta, s } = need();
    const r = await V.replaceRecoveryCodes(file, s, meta);
    set({ file: r.file });
    persist(r.file);
    audit('recovery-new', undefined, 'codes');
    return r.codes;
  });
}

export async function newRecoveryKit(kitPassphrase: string): Promise<{ kit: RecoveryKit; key: string }> {
  if (needsReauth()) throw new Error('Confirm your password first.');
  return withBusy(() => serial(async () => {
    const { file, meta, s } = need();
    const r = await V.replaceRecoveryKey(file, s, meta);
    const kit = await buildKit(file.id, r.key, kitPassphrase);
    set({ file: r.file });
    persist(r.file);
    audit('recovery-new', undefined, 'kit');
    return { kit, key: r.key };
  }));
}

export async function exportVault(password: string): Promise<string> {
  if (needsReauth()) throw new Error('Confirm your password first.');
  return withBusy(async () => {
    const { file } = need();
    audit('export', undefined, `${get().entries.length} items`);
    return JSON.stringify(await V.exportPortable(file, password), null, 2);
  });
}

export async function importVault(text: string, password: string): Promise<number> {
  return withBusy(async () => {
    const parsed = JSON.parse(text) as V.ExportFile;
    const opened = await V.openExport(parsed, password);
    if (opened.kind === 'vault') {
      const cur = get().file;
      if (cur && cur.id !== opened.file.id) throw new Error('qr-different');
      if (cur && opened.file.rev <= cur.rev) throw new Error('export-older');
      const ok = await adoptRemote(opened.file);
      if (!ok) throw new Error('qr-damaged');
      audit('import', undefined, 'full vault');
      return opened.file.entries.length;
    }
    const meta = need().meta;
    const envs = [...new Set([...meta.environments, ...opened.environments.filter((e) => /^[\w.-]{1,24}$/.test(e))])];
    if (envs.length !== meta.environments.length) await updateMeta({ environments: envs });
    for (const e of opened.entries) await saveEntry(null, { ...e, history: Array.isArray(e.history) ? e.history : [], tags: Array.isArray(e.tags) ? e.tags : [] });
    audit('import', undefined, `PEVV export: ${opened.entries.length}`);
    return opened.entries.length;
  });
}

/**
 * New device, no vault yet. A current export (v2) installs the same vault:
 * same master password, authenticator, recovery codes and passkeys. A legacy
 * export (v1) only has items, so it still needs a new master password.
 */
export async function installFromExport(text: string, exportPassword: string, masterPassword?: string, strength: 'standard' | 'strong' = 'standard'): Promise<number> {
  return withBusy(async () => {
    if (get().file) throw new Error('a vault already exists on this device');
    const parsed = JSON.parse(text) as V.ExportFile;
    const imported = await V.openExport(parsed, exportPassword);
    if (imported.kind === 'vault') {
      if (vaultRevokedLocally(imported.file.id)) clearVaultRevoked(imported.file.id);
      set({ file: imported.file, status: 'locked', entries: [], meta: null, totp: null, error: null });
      persist(imported.file);
      setPrefs({ sync: true });
      return imported.file.entries.length;
    }
    if (!masterPassword || masterPassword.length < 10) throw new Error('export-needs-master');
    const kdf = await kdfFactory(strength);
    const created = await V.createVault(masterPassword, kdf);
    set({ file: created.file });
    persist(created.file);
    await openSession(created.session);
    for (const e of imported.entries) {
      await saveEntry(null, { ...e, history: Array.isArray(e.history) ? e.history : [], tags: Array.isArray(e.tags) ? e.tags : [] });
    }
    setPrefs({ sync: true });
    return imported.entries.length;
  });
}

/** New device: take the ciphertext copy that cloud sync already downloaded. */
export async function claimSyncedVault(opts: { retryRevoked?: boolean } = {}): Promise<boolean> {
  await useCloudFiles.getState().initFiles();
  const f = useCloudFiles.getState().readFile('/vault/pevv.vault.json');
  if (!f) return false;
  const remote = JSON.parse(f.body) as VaultFile;
  V.validateFile(remote);
  if (opts.retryRevoked) clearVaultRevoked(remote.id);
  if (vaultRevokedLocally(remote.id)) {
    set({ error: 'device-revoked' });
    return false;
  }
  const ok = await adoptRemote(remote);
  if (ok) setPrefs({ sync: true });
  return ok;
}

const QR_PENDING = 'lv-pevv-qr-pending';

export function rememberQrToken(token: string): void {
  try { sessionStorage.setItem(QR_PENDING, token); } catch { /* private mode */ }
}
export function pendingQrToken(): string | null {
  try { return sessionStorage.getItem(QR_PENDING); } catch { return null; }
}
export function clearQrToken(): void {
  try { sessionStorage.removeItem(QR_PENDING); } catch { /* ignore */ }
}

/** Prove the master password, then forget the unwrapped key. Does not unlock the UI. */
export async function confirmPasswordForQr(password: string): Promise<void> {
  await withBusy(async () => {
    const file = get().file;
    if (!file) throw new Error('no vault');
    guardLimiter('pw');
    try {
      const s = await V.unlockWithPassword(file, password);
      V.endSession(s);
      recordLimiter('pw', true);
      audit('export', undefined, 'qr');
    } catch (e) {
      if ((e as Error).name === 'DecryptError') recordLimiter('pw', false);
      throw e;
    }
  });
}

/** Install a locked vault file on this device (same id updates; a different vault is refused). */
export async function installVaultCopy(remote: VaultFile): Promise<void> {
  V.validateFile(remote);
  const cur = get().file;
  if (cur && cur.id !== remote.id) throw new Error('qr-different');
  if (!cur || remote.rev > cur.rev) {
    await adoptRemote(remote);
    if (!get().file) throw new Error('qr-damaged');
  }
  setPrefs({ sync: true });
}

let activeXfer = '';

/** Seal the vault under a random key and upload the ciphertext before the QR is shown. The key stays in the code. */
export async function publishHandoff(): Promise<string> {
  const file = get().file;
  if (!file) throw new Error('no vault');
  const sealed = await sealHandoff(JSON.stringify(file), Date.now(), 10 * 60 * 1000);
  const token = newTransferToken();
  const body = JSON.stringify(sealed.envelope);
  touchWait('cloud', { got: 0, total: 0, checks: 0 });
  await putTransfer(token, body, (got, total) => touchWait('cloud', { got, total }));
  activeXfer = token;
  if (!pendingQrToken()) set({ qrWait: null });
  return shareUrl(`H.${sealed.key}.${token}`);
}

export function clearHandoff(): void {
  const token = activeXfer;
  activeXfer = '';
  if (token) void dropTransfer(token);
  try {
    if (useCloudFiles.getState().filesLoaded) useCloudFiles.getState().removeFile(HANDOFF_PATH);
  } catch { /* store not ready */ }
}

let lastQrPull = 0;
let qrBusy = false;

function touchWait(step: QrWaitStep, extra?: Partial<Pick<QrWait, 'checks' | 'got' | 'total'>>): void {
  const cur = usePevv.getState().qrWait;
  set({
    qrWait: {
      step,
      checks: extra?.checks ?? cur?.checks ?? 0,
      got: extra?.got ?? cur?.got ?? 0,
      total: extra?.total ?? cur?.total ?? 0,
      started: cur?.started ?? Date.now(),
    },
  });
}

export function dismissQrWait(): void {
  const token = pendingQrToken();
  clearQrToken();
  set({ qrWait: null });
  if (token?.startsWith('H.')) {
    const rest = token.slice(2);
    const dot = rest.indexOf('.');
    const xfer = dot < 0 ? '' : rest.slice(dot + 1);
    if (xfer) void dropTransfer(xfer);
  }
}

/** Keep asking for a scanned code until the vault arrives or the wait is dismissed. */
export function startQrPull(): () => void {
  const pullQr = window.setInterval(() => { void consumePendingQr(); }, 1000);
  void consumePendingQr();
  return () => window.clearInterval(pullQr);
}
export async function consumePendingQr(): Promise<'idle' | 'waiting' | 'done'> {
  if (typeof location !== 'undefined' && location.href.includes('pevvq=')) {
    const fromUrl = readHashToken(location.href);
    if (fromUrl) {
      rememberQrToken(fromUrl);
      openVault();
      if (!usePevv.getState().qrWait) {
        set({ error: null, qrWait: { step: 'cloud', checks: 0, got: 0, total: 0, started: Date.now() } });
      }
    }
    stripHashToken();
  }
  const token = pendingQrToken();
  if (!token || qrBusy) return token ? 'waiting' : 'idle';
  qrBusy = true;
  try {
    if (token.startsWith('H.')) {
      const started = usePevv.getState().qrWait?.started ?? Date.now();
      if (!syncEnabled()) { touchWait('nosync'); return 'waiting'; }
      if (Date.now() - started > 10 * 60 * 1000) { clearQrToken(); touchWait('expired'); return 'waiting'; }
      const rest = token.slice(2);
      const dot = rest.indexOf('.');
      const key = dot < 0 ? rest : rest.slice(0, dot);
      const xfer = dot < 0 ? '' : rest.slice(dot + 1);
      const checks = (usePevv.getState().qrWait?.checks ?? 0) + 1;
      if (xfer) {
        const pulled = await pullTransfer(xfer, (got, total) => touchWait('cloud', { checks, got, total }));
        if (pendingQrToken() !== token) return 'waiting';
        touchWait('cloud', { checks, got: pulled.got, total: pulled.total });
        if (!pulled.body) return 'waiting';
        touchWait('installing', { got: pulled.total, total: pulled.total });
        const remote = JSON.parse(await openHandoff(JSON.parse(pulled.body) as HandoffEnvelope, key)) as VaultFile;
        await installVaultCopy(remote);
        void dropTransfer(xfer);
      } else {
        touchWait('cloud', { checks });
        if (Date.now() - lastQrPull > 4000) {
          lastQrPull = Date.now();
          try { await pullCloud(); } catch { /* the next check says the cloud was asked again */ }
        }
        const ok = await claimHandoff(key);
        if (!ok) return 'waiting';
      }
    } else if (token.startsWith('PEVV1|')) {
      await installVaultCopy(await unpackFrames([token]));
    } else {
      clearQrToken();
      return 'idle';
    }
    clearQrToken();
    touchWait('done');
    openVault();
    set({ qrWait: null });
    return 'done';
  } catch (e) {
    const msg = (e as Error).message || 'qr-damaged';
    set({ error: msg });
    if (msg === 'qr-different' || msg === 'qr-damaged' || msg === 'qr-expired' || msg === 'qr-incomplete') {
      clearQrToken();
      touchWait(msg === 'qr-expired' ? 'expired' : 'cloud');
      return 'waiting';
    }
    touchWait('cloud');
    return 'waiting';
  } finally {
    qrBusy = false;
  }
}

async function claimHandoff(key: string): Promise<boolean> {
  await useCloudFiles.getState().initFiles();
  const f = useCloudFiles.getState().readFile(HANDOFF_PATH);
  if (!f) return false;
  touchWait('installing');
  const envelope = JSON.parse(f.body) as HandoffEnvelope;
  const remote = JSON.parse(await openHandoff(envelope, key)) as VaultFile;
  await installVaultCopy(remote);
  useCloudFiles.getState().removeFile(HANDOFF_PATH);
  return true;
}

/** Erase the vault from this device (requires recent re-auth when unlocked). */
export function destroyVault(): void {
  lock('reset');
  clearVaultBio();
  set({ file: null, status: 'none', warnings: [] });
  persist(null);
}

/* ───────────── sync hook ───────────── */

/** Adopt a newer ciphertext copy from another device (same vault id, higher rev). */
async function adoptRemoteInner(remote: VaultFile): Promise<boolean> {
  const c = get().file;
  if (vaultRevokedLocally(remote.id)) return false;
  if (c && (remote.id !== c.id || remote.rev <= c.rev)) return false;
  try { localStorage.setItem(VAULT_KEY, JSON.stringify(remote)); } catch { return false; }
  set({ file: remote, status: get().status === 'none' ? 'locked' : get().status });
  if (get().status === 'unlocked' && session) {
    try {
      const d = await V.decryptAll(remote, session);
      if ((d.meta.revokedDevices ?? []).includes(localDeviceId())) {
        markVaultRevoked(remote.id);
        destroyVault();
        set({ error: 'device-revoked' });
        return true;
      }
      set({ entries: d.entries, meta: d.meta, totp: d.totp, warnings: d.warnings });
    } catch {
      lock('manual');
    }
  }
  return true;
}

export async function adoptRemote(remote: VaultFile): Promise<boolean> {
  const cur = get().file;
  if (vaultRevokedLocally(remote.id)) return false;
  if (cur && (remote.id !== cur.id || remote.rev <= cur.rev)) return false;
  return serial(() => adoptRemoteInner(remote));
}

/**
 * Fold another copy of this vault into the open one.
 * A higher revision replaces items when `entries` is allowed (cloud sync on, or a live paired device).
 * The device list is always a union, so the phone that enrolled last still shows up on the computer.
 */
export async function reconcileRemote(remote: VaultFile, source: 'cloud' | 'peer'): Promise<boolean> {
  return serial(async () => {
    try { V.validateFile(remote); } catch { return false; }
    if (vaultRevokedLocally(remote.id)) return false;
    const local = get().file;
    if (local && local.id !== remote.id) return false;
    const unlocked = get().status === 'unlocked' && !!session;
    const takeEntries = source === 'peer' || !local || get().prefs.sync;
    if (!local) {
      if (source !== 'cloud') return false;
      return adoptRemoteInner(remote);
    }
    if (!unlocked) {
      if (takeEntries && remote.rev > local.rev) return adoptRemoteInner(remote);
      return false;
    }
    const live = session;
    if (!live) return false;
    let remoteMeta: VaultMeta;
    try { remoteMeta = await V.readMeta(remote, live); }
    catch { return false; }
    const before = {
      devices: asDevices(get().meta?.devices),
      revokedDevices: [...(get().meta?.revokedDevices ?? [])],
    };
    let folded = false;
    if (takeEntries && remote.rev > get().file!.rev) {
      const ok = await adoptRemoteInner(remote);
      if (!ok) return false;
      folded = true;
      if (get().status !== 'unlocked' || !get().meta) return true;
    }
    const left = {
      devices: asDevices(get().meta?.devices),
      revokedDevices: [...(get().meta?.revokedDevices ?? [])],
    };
    // After a full replace, put back any device that only this copy knew about.
    // Otherwise take the other copy's roster (it may be older, but it has the phone).
    const right = folded
      ? before
      : { devices: asDevices(remoteMeta.devices), revokedDevices: [...(remoteMeta.revokedDevices ?? [])] };
    const merged = mergeRoster(left, right);
    if (!sameRoster(left, merged)) await writeMeta({ devices: merged.devices, revokedDevices: merged.revokedDevices });
    if ((get().meta?.revokedDevices ?? []).includes(localDeviceId())) {
      markVaultRevoked(get().file!.id);
      destroyVault();
      set({ error: 'device-revoked' });
    }
    return true;
  });
}

let remembering = false;

/** Register this browser on the vault and refresh last-opened, at most once an hour. */
export async function rememberThisDevice(): Promise<void> {
  if (remembering || get().status !== 'unlocked' || !session) return;
  remembering = true;
  try {
    const id = localDeviceId();
    let meta = need().meta;
    if ((meta.revokedDevices ?? []).includes(id)) {
      markVaultRevoked(get().file!.id);
      destroyVault();
      set({ error: 'device-revoked' });
      return;
    }
    try {
      await useCloudFiles.getState().initFiles();
      const raw = useCloudFiles.getState().readFile('/vault/pevv.vault.json');
      if (raw) {
        const remote = JSON.parse(raw.body) as VaultFile;
        V.validateFile(remote);
        const local = get().file;
        if (local && remote.id === local.id) {
          await reconcileRemote(remote, 'cloud');
          if (get().status !== 'unlocked') return;
          meta = need().meta;
        }
      }
    } catch { /* keep the local roster */ }
    const prev = asDevices(meta.devices).find((d) => d.id === id);
    const mine = describeDevice(prev);
    if (!deviceNeedsWrite(prev, mine)) return;
    const revoked = meta.revokedDevices ?? [];
    const devices = mergeDevices(asDevices(meta.devices), [mine]).filter((d) => !revoked.includes(d.id));
    await updateMeta({ devices, revokedDevices: revoked });
  } catch { /* a device-list failure must not lock the user out */ }
  finally { remembering = false; }
}

export async function renameThisDevice(name: string): Promise<void> {
  // eslint-disable-next-line no-control-regex -- strip control characters from a device name
  const n = name.replace(/[\u0000-\u001f]/g, '').trim().slice(0, 40);
  if (n.length < 1) throw new Error('device-name');
  setLocalDeviceName(n);
  const { meta } = need();
  const id = localDeviceId();
  const prev = asDevices(meta.devices).find((d) => d.id === id);
  const mine = { ...describeDevice(prev), name: n, seen: Date.now() };
  const devices = mergeDevices(asDevices(meta.devices), [mine]);
  await updateMeta({ devices });
  audit('device-rename', undefined, n);
}

/** Forget another device. It wipes its copy the next time that copy unlocks or syncs. */
export async function revokeDevice(id: string): Promise<void> {
  if (id === localDeviceId()) throw new Error('device-self');
  const { meta } = need();
  const revoked = [...new Set([...(meta.revokedDevices ?? []), id])].slice(0, 100);
  const devices = asDevices(meta.devices).filter((d) => d.id !== id);
  await updateMeta({ devices, revokedDevices: revoked });
  audit('device-revoke', undefined, id.slice(0, 8));
}

/* ───────────── clipboard ───────────── */

/**
 * A host that owns the clipboard (the desktop app) takes over copying and clearing:
 * it clears after `sec` seconds only if the clipboard is unchanged. Resolves false on failure.
 */
export type NativeClipboard = (value: string, sec: number) => Promise<boolean>;
let nativeClipboard: NativeClipboard | null = null;
export function setNativeClipboard(fn: NativeClipboard | null): void { nativeClipboard = fn; }

export async function copySecret(value: string, itemId?: string): Promise<boolean> {
  if (itemId) audit('copy', itemId);
  if (nativeClipboard) {
    let ok = false;
    try { ok = await nativeClipboard(value, get().prefs.clipboardSec); } catch { ok = false; }
    if (clipTimer) { clearTimeout(clipTimer); clipTimer = null; }
    if (ok) touch();
    return ok;
  }
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    return false;
  }
  if (clipTimer) clearTimeout(clipTimer);
  const sec = get().prefs.clipboardSec;
  if (sec > 0) {
    clipTimer = setTimeout(() => {
      // Only clear if the clipboard still holds our value (when the browser lets us read it).
      void (async () => {
        try {
          const cur = await navigator.clipboard.readText();
          if (cur !== value) return;
        } catch { /* cannot read: clear anyway */ }
        try { await navigator.clipboard.writeText(''); } catch { /* ignore */ }
      })();
    }, sec * 1000);
  }
  touch();
  return true;
}

/* ───────────── overlay + program env requests ───────────── */

export function openVault(view?: View): void {
  set({ overlayOpen: true, ...(view ? { view } : {}) });
}
export function closeVault(): void {
  const req = get().envRequest;
  if (req) { req.resolve(null); set({ envRequest: null }); }
  set({ overlayOpen: false });
}
export function toggleVault(): void {
  if (get().overlayOpen) closeVault();
  else openVault();
}

/**
 * Hybrid programs call this before running when they use env.get().
 * Returns only the granted names; asks the user (unlocking first if needed).
 */
export function requestProgramEnv(programId: string, names: string[]): Promise<Record<string, string> | null> {
  const st = get();
  const granted = st.status === 'unlocked' ? st.meta?.grants[programId] ?? [] : [];
  if (st.status === 'unlocked' && names.every((n) => granted.includes(n))) {
    touch();
    return Promise.resolve(pick(envVars(envForProgram(programId)), names));
  }
  if (st.envRequest) st.envRequest.resolve(null);
  return new Promise((resolve) => {
    set({ envRequest: { programId, names, resolve }, overlayOpen: true });
  });
}

function pick(vars: Record<string, string>, names: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const n of names) if (Object.prototype.hasOwnProperty.call(vars, n)) out[n] = vars[n]!;
  return out;
}

export async function answerEnvRequest(choice: 'once' | 'always' | 'deny'): Promise<void> {
  const req = get().envRequest;
  if (!req) return;
  set({ envRequest: null, overlayOpen: false });
  if (choice === 'deny' || !isUnlocked()) { req.resolve(null); return; }
  if (choice === 'always') {
    const meta = need().meta;
    const prev = meta.grants[req.programId] ?? [];
    await updateMeta({ grants: { ...meta.grants, [req.programId]: [...new Set([...prev, ...req.names])].sort() } });
  }
  audit('grant', undefined, `${req.programId}: ${req.names.join(', ')}${choice === 'always' ? ' (always)' : ''}`);
  req.resolve(pick(envVars(envForProgram(req.programId)), req.names));
}

export async function revokeGrant(programId: string): Promise<void> {
  const meta = need().meta;
  const grants = { ...meta.grants };
  delete grants[programId];
  await updateMeta({ grants });
  audit('revoke', undefined, programId);
}

/* ───────────── autofill (explicit, same-origin) ───────────── */

export function autofillCandidates(formId: string): Entry[] {
  const st = get();
  if (!st.prefs.autofill || st.status !== 'unlocked') return [];
  if (typeof window !== 'undefined' && window.top !== window.self) return []; // never inside frames
  const origin = typeof location !== 'undefined' ? location.origin : '';
  return st.entries.filter((e) => e.type === 'login' && siteMatches(e.site, formId, origin));
}

export function markUsed(): void { touch(); }

/* ───────────── audit log (local, encrypted, this device only) ───────────── */

const auditKey = (vaultId: string) => `lv-pevv-audit-${vaultId}`;
const auditAad = (vaultId: string) => `luciverse/pevv/v1/audit/${vaultId}`;
let auditWrite: Promise<unknown> = Promise.resolve();

async function loadAudit(): Promise<void> {
  const st = get();
  if (!session || !st.file) return;
  try {
    const raw = localStorage.getItem(auditKey(st.file.id));
    const log = raw ? await openJson<AuditRecord[]>(session.key, JSON.parse(raw) as never, auditAad(st.file.id)) : [];
    if (Array.isArray(log)) set({ audit: [...get().audit, ...log].slice(0, 500) });
  } catch {
    set({ audit: [{ at: Date.now(), ev: 'unlock', detail: 'previous activity log could not be read (reset)' }] });
  }
}

/** Record an activity event. Never stores secret values — only the item id, event and a short detail. */
export function audit(ev: AuditEvent, item?: string, detail?: string): void {
  const st = get();
  if (!session || !st.file) return;
  const log = appendAudit(st.audit, { at: Date.now(), ev, ...(item ? { item } : {}), ...(detail ? { detail: detail.slice(0, 120) } : {}) });
  set({ audit: log });
  const key = session.key;
  const id = st.file.id;
  auditWrite = auditWrite.then(async () => {
    try { localStorage.setItem(auditKey(id), JSON.stringify(await sealJson(key, log, auditAad(id)))); } catch { /* quota: keep in memory */ }
  });
}

export function clearAudit(): void {
  const st = get();
  if (!st.file) return;
  try { localStorage.removeItem(auditKey(st.file.id)); } catch { /* ignore */ }
  set({ audit: [] });
  audit('folder', undefined, 'activity log cleared');
}

/* ───────────── folders ───────────── */

// 1–40 chars, no "/" and no control characters.
const FOLDER_RE = { test: (n: string) => n.length >= 1 && n.length <= 40 && !n.includes('/') && ![...n].some((c) => c.charCodeAt(0) < 32) };

export async function addFolder(name: string): Promise<string> {
  const n = name.trim();
  if (!FOLDER_RE.test(n)) throw new Error('Folder names are 1–40 characters and cannot contain "/".');
  const meta = need().meta;
  if (!meta.folders.includes(n)) { await updateMeta({ folders: [...meta.folders, n].sort((a, b) => a.localeCompare(b)) }); audit('folder', undefined, `+ ${n}`); }
  return n;
}

export async function renameFolder(from: string, to: string): Promise<void> {
  const n = to.trim();
  if (!FOLDER_RE.test(n)) throw new Error('Folder names are 1–40 characters and cannot contain "/".');
  const meta = need().meta;
  await updateMeta({ folders: [...new Set(meta.folders.map((f) => (f === from ? n : f)))].sort((a, b) => a.localeCompare(b)) });
  for (const e of get().entries.filter((x) => x.folder === from)) await saveEntry(e.id, { folder: n });
  audit('folder', undefined, `${from} → ${n}`);
}

/** Delete a folder; its items move to "No folder" (never deleted). */
export async function deleteFolder(name: string): Promise<void> {
  const meta = need().meta;
  for (const e of get().entries.filter((x) => x.folder === name)) await saveEntry(e.id, { folder: '' });
  await updateMeta({ folders: meta.folders.filter((f) => f !== name) });
  audit('folder', undefined, `− ${name}`);
}

/* ───────────── per-project environments ───────────── */

/** The environment a program runs with: its linked one, else the active one. */
export function envForProgram(programId: string): string {
  const m = get().meta;
  const linked = m?.projectEnv?.[programId];
  return linked && m?.environments.includes(linked) ? linked : m?.activeEnv ?? 'dev';
}

export async function linkProgramEnv(programId: string, env: string | null): Promise<void> {
  const meta = need().meta;
  if (env && !meta.environments.includes(env)) throw new Error(`no environment named ${env}`);
  const projectEnv = { ...meta.projectEnv };
  if (env) projectEnv[programId] = env; else delete projectEnv[programId];
  await updateMeta({ projectEnv });
  audit('env-link', undefined, `${programId} → ${env ?? '(active)'}`);
}

/* ───────────── CSV import, passkey rename, history restore ───────────── */

export async function importCsvText(text: string): Promise<{ added: number; skipped: number; source: string }> {
  return withBusy(async () => {
    const r = importManagerExport(text);
    const meta = need().meta;
    const folders = [...new Set(r.entries.map((e) => e.folder).filter((f): f is string => !!f && FOLDER_RE.test(f)))].filter((f) => !meta.folders.includes(f));
    if (folders.length) await updateMeta({ folders: [...meta.folders, ...folders].sort((a, b) => a.localeCompare(b)) });
    for (const e of r.entries) await saveEntry(null, e);
    audit('import', undefined, `${r.source} CSV: ${r.entries.length}`);
    return { added: r.entries.length, skipped: r.skipped, source: r.source };
  });
}

export async function renamePasskey(credId: string, name: string): Promise<void> {
  const n = name.trim().slice(0, 40);
  if (!n) throw new Error('Name the key.');
  await serial(async () => {
    const { file, meta, s } = need();
    const f = await V.saveMeta({ ...file, passkeys: file.passkeys.map((p) => (p.id === credId ? { ...p, name: n } : p)) }, s, meta);
    set({ file: f });
    persist(f);
  });
  audit('passkey-rename', undefined, n);
}

/** Restore a previous value from an item's history (the current value moves into history). */
export async function restoreHistory(entryId: string, index: number): Promise<void> {
  if (needsReauth()) throw new Error('Confirm your password first.');
  const e = get().entries.find((x) => x.id === entryId);
  const h = e?.history[index];
  if (!e || !h) throw new Error('That version no longer exists.');
  await saveEntry(entryId, { [h.field]: h.value } as Partial<EntryData>);
  audit('restore', entryId, h.field);
}

/* test hook */
export function __resetForTests(): void {
  V.endSession(session);
  session = null;
  queue = Promise.resolve();
  pendingEntries = [];
  usePevv.setState({
    file: null, status: 'none', entries: [], meta: null, totp: null, warnings: [], pending: { totp: false, passkey: false },
    prefs: { ...DEFAULT_PREFS }, overlayOpen: false, view: 'items', selected: null, busy: false, error: null, reauthUntil: 0, envRequest: null, recoverySlot: null, draft: null, audit: [],
  });
}
