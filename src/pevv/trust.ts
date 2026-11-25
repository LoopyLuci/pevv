/**
 * How often the authenticator (TOTP) is asked for, and the per-device record that makes "not this time" safe.
 *
 * The setting lives in the sealed vault meta (`secondFactorRecheck`, per vault, synced): it is a security policy of the
 * vault, so every device follows the same one and a device cannot quietly weaken it. The "last verified" record is
 * per device and local, because a code typed on one device says nothing about another.
 *
 * The record is `{ t, mac }`. `mac` needs BOTH secrets, so neither editing the stored field nor knowing the master password
 * is enough to forge it:
 *   tag = HMAC-SHA256(vault key, context | vault id | device id | key epoch | trust epoch | t)
 *   mac = HMAC-SHA256(device key, tag)      (device key: WebCrypto, non-extractable, kept in IndexedDB)
 * A new vault key (rotation) or a new trust epoch (password change, device revoked, authenticator replaced) invalidates it.
 * A timestamp in the future (clock set back) counts as expired. The Android client does the same with a Keystore key.
 */
import { b64, ctEqual, toBytes, unb64, utf8, type Bytes } from './bytes';
import { localDeviceId } from './devices';

export type Recheck = 'login' | 'daily' | 'weekly' | 'monthly' | 'new-device';
export const RECHECK_OPTIONS: readonly Recheck[] = ['login', 'daily', 'weekly', 'monthly', 'new-device'];

const HOUR = 3_600_000;
export const RECHECK_WINDOW_MS: Record<Exclude<Recheck, 'login' | 'new-device'>, number> = {
  daily: 24 * HOUR,
  weekly: 7 * 24 * HOUR,
  monthly: 30 * 24 * HOUR,
};

const CONTEXT = 'luciverse/pevv/v1/2fa-trust';
const KEY_PREFIX = 'lv-pevv-2fa-trust:';

/** Unknown or missing values mean "every login" (the strictest). */
export function asRecheck(v: unknown): Recheck {
  return typeof v === 'string' && (RECHECK_OPTIONS as readonly string[]).includes(v) ? (v as Recheck) : 'login';
}

export function asTrustEpoch(v: unknown): number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : 0;
}

/**
 * Is a verification made at `verifiedAt` still good at `now`? A timestamp after `now` (the clock was set back, or the
 * record is bogus) is expired, whatever the setting.
 */
export function trustFresh(freq: Recheck, verifiedAt: number, now: number): boolean {
  if (freq === 'login') return false;
  if (!Number.isFinite(verifiedAt) || !Number.isFinite(now) || verifiedAt <= 0 || verifiedAt > now) return false;
  if (freq === 'new-device') return true;
  return now - verifiedAt < RECHECK_WINDOW_MS[freq];
}

/** A MAC under a secret that never leaves this device. `null` = no such secret is available (then nothing is trusted). */
export type DeviceMac = (data: Bytes) => Promise<Bytes | null>;

let deviceMac: DeviceMac = idbDeviceMac;
/** Test hook. */
export function __setDeviceMac(f: DeviceMac | null): void { deviceMac = f ?? idbDeviceMac; }

const DB = 'pevv-device';
const STORE = 'keys';
const KEY_ID = 'trust-hmac';

function idb<T>(run: (db: IDBDatabase) => Promise<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => { req.result.createObjectStore(STORE); };
    req.onerror = () => reject(req.error ?? new Error('indexedDB'));
    req.onsuccess = () => { const db = req.result; run(db).then(resolve, reject).finally(() => db.close()); };
  });
}

const wrap = <T>(r: IDBRequest<T>): Promise<T> => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error ?? new Error('indexedDB')); });

async function idbKey(): Promise<CryptoKey> {
  return idb(async (db) => {
    const got = await wrap(db.transaction(STORE, 'readonly').objectStore(STORE).get(KEY_ID)) as CryptoKey | undefined;
    if (got) return got;
    const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    await wrap(db.transaction(STORE, 'readwrite').objectStore(STORE).put(key, KEY_ID));
    return key;
  });
}

async function idbDeviceMac(data: Bytes): Promise<Bytes | null> {
  try {
    if (typeof indexedDB === 'undefined') return null;
    return toBytes(await crypto.subtle.sign('HMAC', await idbKey(), data));
  } catch {
    return null;
  }
}

async function hmac(raw: Uint8Array, data: Uint8Array): Promise<Bytes> {
  const k = await crypto.subtle.importKey('raw', toBytes(raw), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toBytes(await crypto.subtle.sign('HMAC', k, toBytes(data)));
}

export interface TrustBinding { vaultId: string; vaultKey: Uint8Array; keyEpoch: number; trustEpoch: number }

async function macFor(b: TrustBinding, t: number): Promise<Bytes | null> {
  if (!b.vaultKey.length) return null;
  const input = utf8(`${CONTEXT}\n${b.vaultId}\n${localDeviceId()}\n${b.keyEpoch}\n${b.trustEpoch}\n${t}`);
  return deviceMac(await hmac(b.vaultKey, input));
}

interface TrustRecord { t: number; mac: string }

/** Remember that the authenticator was just passed on this device. */
export async function recordTrust(b: TrustBinding, now = Date.now()): Promise<void> {
  try {
    const mac = await macFor(b, now);
    if (!mac) { forgetTrust(b.vaultId); return; }
    localStorage.setItem(KEY_PREFIX + b.vaultId, JSON.stringify({ t: now, mac: b64(mac) } satisfies TrustRecord));
  } catch { /* storage unavailable: the next login simply asks again */ }
}

export function forgetTrust(vaultId: string): void {
  try { localStorage.removeItem(KEY_PREFIX + vaultId); } catch { /* ignore */ }
}

/** May the authenticator be skipped now? Fails closed on any doubt. */
export async function trustHolds(freq: Recheck, b: TrustBinding, now = Date.now()): Promise<boolean> {
  if (freq === 'login') return false;
  try {
    const raw = localStorage.getItem(KEY_PREFIX + b.vaultId);
    if (!raw) return false;
    const rec = JSON.parse(raw) as Partial<TrustRecord>;
    if (typeof rec.t !== 'number' || typeof rec.mac !== 'string') return false;
    if (!trustFresh(freq, rec.t, now)) return false;
    const want = await macFor(b, rec.t);
    if (!want) return false;
    return ctEqual(want, unb64(rec.mac));
  } catch {
    return false;
  }
}
