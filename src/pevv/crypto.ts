/**
 * PEVV cryptography — WebCrypto + Argon2id (hash-wasm). Nothing here touches
 * the network or storage; callers persist only the ciphertext records.
 *
 *   master password ─Argon2id (64 MiB, t=3, p=1, 16-byte salt)─▶ KEK (AES-256-GCM)
 *     (fallback when WebAssembly is blocked: PBKDF2-SHA256, ≥ 600 000 iterations)
 *   PRF passkey ─WebAuthn PRF / hmac-secret (32 B)─HKDF-SHA256─▶ KEK
 *   recovery code / recovery key ─HKDF-SHA256 (high-entropy input)─▶ KEK
 *
 *   KEK ─AES-256-GCM (random IV, AAD = vault id + slot id)─▶ wrapped 256-bit vault key   ("key slots")
 *   vault key ─AES-256-GCM (random IV, AAD = vault id + entry id + version)─▶ each entry
 *
 * The vault key is random (CSPRNG), so changing the password only re-wraps it.
 * The password is never stored; GCM's tag makes a wrong password indistinguishable
 * from a tampered slot — both fail closed.
 */
import { type Bytes, b64, concat, randomBytes, toBytes, unb64, utf8, fromUtf8, wipe } from './bytes';

export const PBKDF2_MIN_ITER = 600_000;
export const PBKDF2_MAX_ITER = 10_000_000;
/** OWASP 2024 floor is m=19 MiB/t=2; we default well above it. */
export const ARGON2_MIN = { m: 19_456, t: 2, p: 1 } as const;
export const ARGON2_DEFAULT = { m: 65_536, t: 3, p: 1 } as const;
export const ARGON2_STRONG = { m: 131_072, t: 4, p: 1 } as const;

export type KdfParams =
  | { alg: 'argon2id'; m: number; t: number; p: number; salt: string }
  | { alg: 'pbkdf2-sha256'; iter: number; salt: string };

export interface Sealed {
  /** base64 12-byte IV */
  iv: string;
  /** base64 ciphertext ‖ 16-byte tag */
  ct: string;
}

export class DecryptError extends Error {
  constructor(msg = 'wrong secret or damaged data') {
    super(msg);
    this.name = 'DecryptError';
  }
}

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('WebCrypto is unavailable (PEVV needs a secure https context)');
  return s;
}

export function validateKdf(k: KdfParams): void {
  if (unb64(k.salt).length < 16) throw new Error('KDF salt must be at least 16 bytes');
  if (k.alg === 'argon2id') {
    if (!(k.m >= ARGON2_MIN.m && k.m <= 1_048_576)) throw new Error('Argon2id memory out of range');
    if (!(k.t >= ARGON2_MIN.t && k.t <= 20)) throw new Error('Argon2id iterations out of range');
    if (!(k.p >= 1 && k.p <= 4)) throw new Error('Argon2id parallelism out of range');
  } else if (k.alg === 'pbkdf2-sha256') {
    if (!(k.iter >= PBKDF2_MIN_ITER && k.iter <= PBKDF2_MAX_ITER)) throw new Error(`PBKDF2 iterations must be ≥ ${PBKDF2_MIN_ITER}`);
  } else {
    throw new Error('unknown KDF');
  }
}

let argonOk: boolean | null = null;
/** True when the Argon2id WebAssembly module loads (CSP or old browsers may block it). */
export async function argon2Available(): Promise<boolean> {
  if (argonOk !== null) return argonOk;
  try {
    const { argon2id } = await import('hash-wasm');
    await argon2id({ password: 'x', salt: new Uint8Array(16), parallelism: 1, iterations: 1, memorySize: 64, hashLength: 16, outputType: 'binary' });
    argonOk = true;
  } catch {
    argonOk = false;
  }
  return argonOk;
}

export async function newKdf(strength: 'standard' | 'strong' = 'standard', forcePbkdf2 = false): Promise<KdfParams> {
  const salt = b64(randomBytes(16));
  if (!forcePbkdf2 && (await argon2Available())) {
    const p = strength === 'strong' ? ARGON2_STRONG : ARGON2_DEFAULT;
    return { alg: 'argon2id', ...p, salt };
  }
  return { alg: 'pbkdf2-sha256', iter: strength === 'strong' ? 1_200_000 : PBKDF2_MIN_ITER, salt };
}

/** Passwords are NFC-normalised so the same passphrase unlocks on every device / keyboard. */
export function normalizePassword(pw: string): string {
  return pw.normalize('NFC');
}

/** Stretch a password into 32 raw bytes (caller wipes). */
export async function stretch(password: string, k: KdfParams): Promise<Bytes> {
  validateKdf(k);
  const pw = normalizePassword(password);
  if (!pw) throw new Error('empty password');
  const salt = unb64(k.salt);
  if (k.alg === 'argon2id') {
    const { argon2id } = await import('hash-wasm');
    const out = await argon2id({ password: pw, salt, parallelism: k.p, iterations: k.t, memorySize: k.m, hashLength: 32, outputType: 'binary' });
    return toBytes(out);
  }
  const base = await subtle().importKey('raw', utf8(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle().deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: k.iter }, base, 256);
  return toBytes(bits);
}

/** HKDF-SHA256 → non-extractable AES-256-GCM key. */
export async function hkdfAesKey(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<CryptoKey> {
  const base = await subtle().importKey('raw', toBytes(ikm), 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: toBytes(salt), info: utf8(info) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function passwordKek(password: string, k: KdfParams): Promise<CryptoKey> {
  const raw = await stretch(password, k);
  try {
    // Domain-separate the stretched secret before use as a KEK.
    return await hkdfAesKey(raw, unb64(k.salt), 'luciverse/pevv/v1/password-kek');
  } finally {
    wipe(raw);
  }
}

export async function aesKeyFromRaw(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error('vault key must be 256 bits');
  return subtle().importKey('raw', toBytes(raw), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * `iv` is for tests that need byte-identical output (golden vectors). Production callers never pass it:
 * a fresh random 96-bit IV per seal is invariant 5 in AGENTS.md.
 */
export async function seal(key: CryptoKey, plain: Uint8Array, aad: string, iv: Bytes = randomBytes(12)): Promise<Sealed> {
  if (iv.length !== 12) throw new Error('IV must be 96 bits');
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: utf8(aad), tagLength: 128 }, key, toBytes(plain));
  return { iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}

export async function open(key: CryptoKey, s: Sealed, aad: string): Promise<Bytes> {
  let iv: Bytes, ct: Bytes;
  try {
    iv = unb64(s.iv);
    ct = unb64(s.ct);
  } catch {
    throw new DecryptError('damaged record');
  }
  if (iv.length !== 12 || ct.length < 16) throw new DecryptError('damaged record');
  try {
    const pt = await subtle().decrypt({ name: 'AES-GCM', iv, additionalData: utf8(aad), tagLength: 128 }, key, ct);
    return toBytes(pt);
  } catch {
    throw new DecryptError();
  }
}

export async function sealJson(key: CryptoKey, value: unknown, aad: string, iv?: Bytes): Promise<Sealed> {
  return seal(key, utf8(JSON.stringify(value)), aad, iv);
}

export async function openJson<T>(key: CryptoKey, s: Sealed, aad: string): Promise<T> {
  const pt = await open(key, s, aad);
  try {
    return JSON.parse(fromUtf8(pt)) as T;
  } finally {
    wipe(pt);
  }
}

export const aad = {
  slot: (vaultId: string, slotId: string) => `luciverse/pevv/v1/slot/${vaultId}/${slotId}`,
  entry: (vaultId: string, entryId: string, ver: number) => `luciverse/pevv/v1/entry/${vaultId}/${entryId}/${ver}`,
  meta: (vaultId: string, rev: number) => `luciverse/pevv/v1/meta/${vaultId}/${rev}`,
  totp: (vaultId: string) => `luciverse/pevv/v1/totp/${vaultId}`,
  export: (id: string) => `luciverse/pevv/v1/export/${id}`,
  kit: (vaultId: string) => `luciverse/pevv/v1/kit/${vaultId}`,
};

export async function sha256(data: Uint8Array): Promise<Bytes> {
  return toBytes(await subtle().digest('SHA-256', toBytes(data)));
}

export function newVaultKey(): Bytes {
  return randomBytes(32);
}

/** Wrap the raw vault key under a KEK for one slot. */
export async function wrapVaultKey(kek: CryptoKey, vaultKey: Uint8Array, vaultId: string, slotId: string, iv?: Bytes): Promise<Sealed> {
  return seal(kek, vaultKey, aad.slot(vaultId, slotId), iv);
}

export async function unwrapVaultKey(kek: CryptoKey, wrapped: Sealed, vaultId: string, slotId: string): Promise<Bytes> {
  const raw = await open(kek, wrapped, aad.slot(vaultId, slotId));
  if (raw.length !== 32) {
    wipe(raw);
    throw new DecryptError('damaged key slot');
  }
  return raw;
}

export { concat };
