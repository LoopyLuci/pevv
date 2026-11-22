/**
 * Recovery material. Each one-time recovery code (100 random bits, shown once)
 * and the recovery key (256 random bits) wraps the vault key in its own slot via
 * HKDF — they are high-entropy, so no slow KDF is needed. Only a salted SHA-256
 * of each code is kept to find its slot; a used code's slot is deleted.
 */
import { type Bytes, base32Decode, base32Encode, b64, concat, randomBytes, unb64, utf8 } from './bytes';
import { type KdfParams, type Sealed, aad, hkdfAesKey, newKdf, openJson, passwordKek, sealJson, sha256 } from './crypto';

export const RECOVERY_CODE_COUNT = 10;

/** XXXXX-XXXXX-XXXXX-XXXXX (20 base32 chars = 100 bits). */
export function newRecoveryCode(): string {
  const raw = base32Encode(randomBytes(13)).slice(0, 20);
  return raw.match(/.{5}/g)!.join('-');
}

export function normalizeCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z2-7]/g, '');
}

export function isWellFormedCode(code: string): boolean {
  return normalizeCode(code).length === 20;
}

export async function codeHash(code: string, salt: string): Promise<string> {
  return b64(await sha256(concat(unb64(salt), utf8(normalizeCode(code)))));
}

export async function codeKek(code: string, salt: string): Promise<CryptoKey> {
  return hkdfAesKey(utf8(normalizeCode(code)), unb64(salt), 'luciverse/pevv/v1/recovery-code-kek');
}

/** 32 random bytes rendered as 13 groups of 4 base32 chars (+1 char). */
export function newRecoveryKey(): string {
  return base32Encode(randomBytes(32)).match(/.{1,4}/g)!.join('-');
}

export function recoveryKeyBytes(key: string): Bytes {
  const b = base32Decode(key);
  if (b.length !== 32) throw new Error('recovery key must be 52 base32 characters');
  return b;
}

export async function recoveryKeyKek(key: string, salt: string): Promise<CryptoKey> {
  return hkdfAesKey(recoveryKeyBytes(key), unb64(salt), 'luciverse/pevv/v1/recovery-key-kek');
}

/** Encrypted recovery kit file: the recovery key sealed under a separate kit passphrase. */
export interface RecoveryKit {
  format: 'luciverse.pevv.recovery-kit';
  v: 1;
  vaultId: string;
  created: string;
  kdf: KdfParams;
  sealed: Sealed;
  note: string;
}

export async function buildKit(vaultId: string, recoveryKey: string, kitPassphrase: string, kdf?: KdfParams): Promise<RecoveryKit> {
  const params = kdf ?? (await newKdf('standard'));
  const kek = await passwordKek(kitPassphrase, params);
  return {
    format: 'luciverse.pevv.recovery-kit',
    v: 1,
    vaultId,
    created: new Date().toISOString(),
    kdf: params,
    sealed: await sealJson(kek, { recoveryKey }, aad.kit(vaultId)),
    note: 'PEVV recovery kit. Open PEVV → Locked → Use recovery kit, choose this file and enter the kit passphrase. Keep it offline.',
  };
}

export async function openKit(kit: RecoveryKit, kitPassphrase: string): Promise<string> {
  if (kit?.format !== 'luciverse.pevv.recovery-kit' || kit.v !== 1) throw new Error('not a PEVV recovery kit');
  const kek = await passwordKek(kitPassphrase, kit.kdf);
  const { recoveryKey } = await openJson<{ recoveryKey: string }>(kek, kit.sealed, aad.kit(kit.vaultId));
  recoveryKeyBytes(recoveryKey);
  return recoveryKey;
}
