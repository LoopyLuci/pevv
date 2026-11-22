/**
 * RFC 4226 HOTP / RFC 6238 TOTP (SHA-1 default — what Google Authenticator,
 * Authy, 1Password and YubiKey OATH expect), plus otpauth:// URIs and an
 * attempt limiter. Pure WebCrypto.
 *
 * Honesty note: a client-side TOTP check is a *gate* — it is enforced by this
 * app's code, not by cryptography. The vault key never depends on it.
 */
import { base32Decode, base32Encode, randomBytes, toBytes, utf8 } from './bytes';

export type TotpAlg = 'SHA-1' | 'SHA-256' | 'SHA-512';

export interface TotpConfig {
  secret: string; // base32
  digits?: number; // 6
  period?: number; // 30 s
  algorithm?: TotpAlg;
}

export function newTotpSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

export async function hotp(secret: Uint8Array, counter: number, digits = 6, algorithm: TotpAlg = 'SHA-1'): Promise<string> {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error('bad counter');
  const msg = new Uint8Array(new ArrayBuffer(8));
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const key = await crypto.subtle.importKey('raw', toBytes(secret), { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[off]! & 0x7f) << 24) | (mac[off + 1]! << 16) | (mac[off + 2]! << 8) | mac[off + 3]!;
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export async function totpAt(cfg: TotpConfig, unixMs: number): Promise<string> {
  const period = cfg.period ?? 30;
  return hotp(base32Decode(cfg.secret), Math.floor(unixMs / 1000 / period), cfg.digits ?? 6, cfg.algorithm ?? 'SHA-1');
}

/** Verify with ±window steps of clock skew; returns the matched step or null. Rejects reuse via `lastStep`. */
export async function verifyTotp(
  cfg: TotpConfig,
  code: string,
  unixMs = Date.now(),
  window = 1,
  lastStep: number | null = null,
): Promise<number | null> {
  const clean = code.replace(/\s/g, '');
  const digits = cfg.digits ?? 6;
  if (!new RegExp(`^\\d{${digits}}$`).test(clean)) return null;
  const period = cfg.period ?? 30;
  const step = Math.floor(unixMs / 1000 / period);
  const key = base32Decode(cfg.secret);
  let match: number | null = null;
  for (let w = -window; w <= window; w++) {
    const s = step + w;
    if (s < 0) continue;
    const want = await hotp(key, s, digits, cfg.algorithm ?? 'SHA-1');
    // Compare every candidate so timing does not reveal which window matched.
    let d = 0;
    for (let i = 0; i < digits; i++) d |= want.charCodeAt(i) ^ clean.charCodeAt(i);
    if (d === 0 && match === null) match = s;
  }
  if (match !== null && lastStep !== null && match <= lastStep) return null; // replay
  return match;
}

export function otpauthUri(cfg: TotpConfig, account: string, issuer = 'PEVV'): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const q = new URLSearchParams({ secret: cfg.secret, issuer });
  if (cfg.algorithm && cfg.algorithm !== 'SHA-1') q.set('algorithm', cfg.algorithm.replace('-', ''));
  if (cfg.digits && cfg.digits !== 6) q.set('digits', String(cfg.digits));
  if (cfg.period && cfg.period !== 30) q.set('period', String(cfg.period));
  return `otpauth://totp/${label}?${q.toString()}`;
}

/** Parse an otpauth://totp URI or a bare base32 secret (for login entries' 2FA field). */
export function parseOtpauth(input: string): TotpConfig {
  const s = input.trim();
  if (!s.toLowerCase().startsWith('otpauth://')) {
    base32Decode(s); // throws on bad input
    return { secret: s.replace(/[\s=-]/g, '').toUpperCase() };
  }
  const u = new URL(s);
  if (u.host.toLowerCase() !== 'totp') throw new Error('only TOTP is supported');
  const secret = (u.searchParams.get('secret') ?? '').replace(/[\s=]/g, '').toUpperCase();
  base32Decode(secret);
  if (!secret) throw new Error('missing secret');
  const algRaw = (u.searchParams.get('algorithm') ?? 'SHA1').toUpperCase();
  const algorithm: TotpAlg = algRaw === 'SHA256' ? 'SHA-256' : algRaw === 'SHA512' ? 'SHA-512' : 'SHA-1';
  const digits = Number(u.searchParams.get('digits') ?? 6);
  const period = Number(u.searchParams.get('period') ?? 30);
  if (![6, 7, 8].includes(digits)) throw new Error('digits must be 6–8');
  if (!(period >= 5 && period <= 300)) throw new Error('bad period');
  return { secret, algorithm, digits, period };
}

/**
 * Attempt limiter: 5 free tries, then exponential lock-out (30 s doubling to 1 h).
 * Persisted per key so reloads do not reset it (still client-side — see docs/PEVV.md).
 */
export interface LimiterState { fails: number; until: number }

export function limiterDelay(fails: number): number {
  if (fails < 5) return 0;
  return Math.min(3_600_000, 30_000 * 2 ** (fails - 5));
}

export function limiterRecord(st: LimiterState, ok: boolean, now = Date.now()): LimiterState {
  if (ok) return { fails: 0, until: 0 };
  const fails = st.fails + 1;
  return { fails, until: now + limiterDelay(fails) };
}

export function limiterBlocked(st: LimiterState, now = Date.now()): number {
  return Math.max(0, st.until - now);
}

export function loadLimiter(key: string): LimiterState {
  try {
    const v = JSON.parse(localStorage.getItem(`lv-pevv-limit:${key}`) ?? 'null') as LimiterState | null;
    if (v && typeof v.fails === 'number' && typeof v.until === 'number') return v;
  } catch { /* ignore */ }
  return { fails: 0, until: 0 };
}

export function saveLimiter(key: string, st: LimiterState): void {
  try { localStorage.setItem(`lv-pevv-limit:${key}`, JSON.stringify(st)); } catch { /* ignore */ }
}

export { utf8 };
