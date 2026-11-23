/**
 * Vault key rotation, run when a device is revoked. The old key is useless afterwards: every sealed value is
 * re-sealed under a fresh key and every key slot is re-wrapped. Kotlin twin: android/.../core/Rotate.kt (golden
 * vectors in tests/sync-scenarios/rotation.json hold both to the same bytes).
 *
 * Format: items, the sealed meta and the authenticator secret are sealed directly under the vault key (there are no
 * per-item keys), so all of them are re-sealed. The file becomes `v: 2` with `keyEpoch` >= 1; clients that only know
 * `v: 1` refuse such a file cleanly (validateFile) instead of mixing two keys. AAD strings and HKDF labels do not change.
 *
 * A slot can only be re-wrapped with the secret that opens it, which a device that is unlocked with one factor does not
 * have. So: the password slot is re-made from the password given, recovery codes and the recovery key are issued again
 * (the caller shows them), and passkey (PRF) and USB-key slots are re-wrapped only if their secret is supplied. The rest
 * are removed and reported in `dropped`, never left pointing at the old key.
 */
import { type Bytes, b64, ctEqual, randomBytes } from './bytes';
import { type KdfParams, aad, openJson, passwordKek, sealJson, unwrapVaultKey, wrapVaultKey } from './crypto';
import { type EntryRecord, type Slot, type VaultFile, newId } from './model';
import { codeHash, codeKek, recoveryKeyKek } from './recovery';
import { parseKeyFile } from './usbkey';
import { type Session, prfKek, readMeta, sessionFromRaw, usbKek, validateFile } from './vault';
import { keyEpoch } from './merge';

export interface RotatePlan {
  /** The master password for the new password slot. The caller must have checked it is the current one. */
  password: string;
  kdf: KdfParams;
  /** Fresh recovery codes to wrap (the caller generated them and shows them once). Empty/absent: none. */
  recoveryCodes?: string[];
  recoveryKey?: string;
  /** credId -> PRF output of that passkey, for every passkey slot to keep. */
  prf?: Record<string, Uint8Array>;
  /** Text of each `.pevvkey` file whose unlock slot is to be kept. */
  usbKeyFiles?: string[];
  /** Remove slot kinds this client does not know instead of refusing the rotation. */
  dropUnknown?: boolean;
}

export interface RotateOptions {
  iv?: (aad: string, plain: Uint8Array) => Bytes | Promise<Bytes>;
  rng?: (n: number) => Bytes;
  newId?: () => string;
  newKey?: Bytes;
  now?: number;
}

export interface DroppedSlot { id: string; type: string; name?: string }
export interface RotateResult { file: VaultFile; session: Session; dropped: DroppedSlot[] }

export async function rotateVaultKey(file: VaultFile, session: Session, plan: RotatePlan, opts: RotateOptions = {}): Promise<RotateResult> {
  validateFile(file);
  const rng = opts.rng ?? randomBytes;
  const mkId = opts.newId ?? newId;
  const known = new Set(['password', 'prf', 'usb-key', 'recovery-code', 'recovery-key']);
  const unknown = file.slots.filter((s) => !known.has(s.type));
  if (unknown.length && !plan.dropUnknown) throw new Error('unknown-slot');

  const raw = opts.newKey ?? rng(32);
  const next = await sessionFromRaw(raw);
  const ivFor = async (a: string, value: unknown) => (opts.iv ? opts.iv(a, new TextEncoder().encode(JSON.stringify(value))) : undefined);
  const seal = async (value: unknown, a: string) => sealJson(next.key, value, a, await ivFor(a, value));
  const wrap = async (kek: CryptoKey, a: string, slotId: string) => {
    const iv = opts.iv ? await opts.iv(a, raw) : undefined;
    return wrapVaultKey(kek, raw, file.id, slotId, iv);
  };

  const rev = file.rev + 1;
  const entries: EntryRecord[] = [];
  for (const r of file.entries) {
    const data = await openJson<unknown>(session.key, r.sealed, aad.entry(file.id, r.id, r.ver));
    entries.push({ id: r.id, ver: r.ver, sealed: await seal(data, aad.entry(file.id, r.id, r.ver)) });
  }
  const meta = await readMeta(file, session);
  const totp = file.totp ? await seal(await openJson<unknown>(session.key, file.totp, aad.totp(file.id)), aad.totp(file.id)) : null;

  const dropped: DroppedSlot[] = unknown.map((s) => ({ id: s.id, type: s.type }));
  const slots: Slot[] = [];
  const pwId = mkId();
  slots.push({ id: pwId, type: 'password', wrapped: await wrap(await passwordKek(plan.password, plan.kdf), aad.slot(file.id, pwId), pwId) });

  const secrets = (plan.usbKeyFiles ?? []).map((t) => parseKeyFile(t).secret);
  for (const s of file.slots) {
    if (s.type === 'prf') {
      const out = plan.prf?.[s.credId];
      let ok = false;
      if (out) {
        try {
          const old = await unwrapVaultKey(await prfKek(out, s.salt), s.wrapped, file.id, s.id);
          ok = ctEqual(old, session.raw);
        } catch { ok = false; }
      }
      if (!ok || !out) { dropped.push({ id: s.id, type: s.type }); continue; }
      const id = mkId();
      const salt = b64(rng(32));
      slots.push({ id, type: 'prf', credId: s.credId, salt, wrapped: await wrap(await prfKek(out, salt), aad.slot(file.id, id), id) });
    } else if (s.type === 'usb-key') {
      let secret: Bytes | null = null;
      for (const c of secrets) {
        try {
          const old = await unwrapVaultKey(await usbKek(c, s.salt), s.wrapped, file.id, s.id);
          if (ctEqual(old, session.raw)) { secret = c; break; }
        } catch { /* not this file */ }
      }
      if (!secret) { dropped.push({ id: s.id, type: s.type, name: s.name }); continue; }
      const id = mkId();
      const salt = b64(rng(32));
      slots.push({ id, type: 'usb-key', name: s.name, salt, wrapped: await wrap(await usbKek(secret, salt), aad.slot(file.id, id), id) });
    }
  }
  for (const code of plan.recoveryCodes ?? []) {
    const id = mkId();
    const salt = b64(rng(16));
    slots.push({ id, type: 'recovery-code', salt, hash: await codeHash(code, salt), wrapped: await wrap(await codeKek(code, salt), aad.slot(file.id, id), id) });
  }
  if (plan.recoveryKey) {
    const id = mkId();
    const salt = b64(rng(16));
    slots.push({ id, type: 'recovery-key', salt, wrapped: await wrap(await recoveryKeyKek(plan.recoveryKey, salt), aad.slot(file.id, id), id) });
  }
  for (const s of file.slots) {
    if ((s.type === 'recovery-code' && !(plan.recoveryCodes ?? []).length) || (s.type === 'recovery-key' && !plan.recoveryKey)) dropped.push({ id: s.id, type: s.type });
  }

  const out: VaultFile = {
    ...file,
    v: 2,
    rev,
    updated: opts.now ?? Date.now(),
    kdf: plan.kdf,
    slots,
    totp,
    meta: await seal(meta, aad.meta(file.id, rev)),
    entries,
  };
  out.keyEpoch = keyEpoch(file) + 1;
  return { file: out, session: next, dropped };
}
