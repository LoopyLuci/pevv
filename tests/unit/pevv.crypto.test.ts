import { describe, expect, it } from 'vitest';
import { b64, base32Decode, base32Encode, unb64, utf8 } from '@/pevv/bytes';
import { ARGON2_MIN, DecryptError, type KdfParams, PBKDF2_MIN_ITER, aad, aesKeyFromRaw, open, seal, stretch, validateKdf } from '@/pevv/crypto';
import * as V from '@/pevv/vault';
import { hotp, totpAt, verifyTotp, otpauthUri, parseOtpauth, limiterDelay, limiterRecord, limiterBlocked } from '@/pevv/totp';
import { buildKit, codeHash, isWellFormedCode, newRecoveryCode, newRecoveryKey, normalizeCode, openKit, recoveryKeyBytes } from '@/pevv/recovery';
import { emptyEntry } from '@/pevv/model';

const salt = () => b64(crypto.getRandomValues(new Uint8Array(16)));
const fastArgon = (): KdfParams => ({ alg: 'argon2id', ...ARGON2_MIN, salt: salt() });
const fastPbkdf2 = (): KdfParams => ({ alg: 'pbkdf2-sha256', iter: PBKDF2_MIN_ITER, salt: salt() });

describe('PEVV KDF', () => {
  it('rejects weak parameters', () => {
    expect(() => validateKdf({ alg: 'pbkdf2-sha256', iter: 100_000, salt: salt() })).toThrow(/600000|600 000|≥/);
    expect(() => validateKdf({ alg: 'argon2id', m: 1024, t: 1, p: 1, salt: salt() })).toThrow();
    expect(() => validateKdf({ alg: 'argon2id', ...ARGON2_MIN, salt: b64(new Uint8Array(8)) })).toThrow(/salt/);
  });

  it('Argon2id is deterministic per salt and differs across salts', async () => {
    const k = fastArgon();
    const a = await stretch('correct horse battery staple', k);
    const b = await stretch('correct horse battery staple', k);
    const c = await stretch('correct horse battery staple', { ...k, salt: salt() });
    expect(a.length).toBe(32);
    expect(b64(a)).toBe(b64(b));
    expect(b64(a)).not.toBe(b64(c));
  });

  it('normalises Unicode passwords (NFC) so composed/decomposed forms match', async () => {
    const k = fastArgon();
    const composed = await stretch('caf\u00e9-pässwörd', k);
    const decomposed = await stretch('cafe\u0301-pa\u0308sswo\u0308rd', k);
    expect(b64(composed)).toBe(b64(decomposed));
  });

  it('PBKDF2 fallback (≥600k) derives 32 bytes', async () => {
    const out = await stretch('pw-for-fallback', fastPbkdf2());
    expect(out.length).toBe(32);
  }, 30_000);
});

describe('AES-256-GCM with AAD', () => {
  it('round-trips and fails closed on wrong AAD / tamper', async () => {
    const key = await aesKeyFromRaw(crypto.getRandomValues(new Uint8Array(32)));
    const s = await seal(key, utf8('secret value'), aad.entry('v', 'e', 1));
    expect(new TextDecoder().decode(await open(key, s, aad.entry('v', 'e', 1)))).toBe('secret value');
    await expect(open(key, s, aad.entry('v', 'e', 2))).rejects.toBeInstanceOf(DecryptError);
    const ct = unb64(s.ct); ct[0] = ct[0]! ^ 1;
    await expect(open(key, { ...s, ct: b64(ct) }, aad.entry('v', 'e', 1))).rejects.toBeInstanceOf(DecryptError);
  });

  it('uses a fresh IV for every seal', async () => {
    const key = await aesKeyFromRaw(crypto.getRandomValues(new Uint8Array(32)));
    const ivs = new Set<string>();
    for (let i = 0; i < 50; i++) ivs.add((await seal(key, utf8('x'), 'a')).iv);
    expect(ivs.size).toBe(50);
  });
});

describe('vault engine', () => {
  it('create → write → lock → unlock round trip; wrong password fails', async () => {
    const { file, session } = await V.createVault('Tr0ub4dor&3-but-longer', fastArgon());
    expect(JSON.stringify(file)).not.toContain('Tr0ub4dor');
    let meta = await V.readMeta(file, session);
    const r = await V.putEntry(file, session, meta, null, { ...emptyEntry('login'), title: 'GitHub', username: 'me', password: 'hunter2-very-secret', site: 'https://github.com' });
    meta = r.meta;
    const raw = JSON.stringify(r.file);
    expect(raw).not.toContain('hunter2');
    expect(raw).not.toContain('GitHub');
    V.endSession(session);
    const s2 = await V.unlockWithPassword(r.file, 'Tr0ub4dor&3-but-longer');
    const d = await V.decryptAll(r.file, s2);
    expect(d.entries).toHaveLength(1);
    expect(d.entries[0]!.password).toBe('hunter2-very-secret');
    expect(d.warnings).toEqual([]);
    await expect(V.unlockWithPassword(r.file, 'wrong password')).rejects.toBeInstanceOf(DecryptError);
  });

  it('detects an entry rolled back to an older ciphertext (AAD binds the version)', async () => {
    const { file, session } = await V.createVault('a-long-master-pass', fastArgon());
    let meta = await V.readMeta(file, session);
    const r1 = await V.putEntry(file, session, meta, null, { ...emptyEntry('apikey'), title: 'k', key: 'v1' });
    meta = r1.meta;
    const r2 = await V.putEntry(r1.file, session, meta, r1.entry.id, { ...emptyEntry('apikey'), title: 'k', key: 'v2' });
    const tampered = { ...r2.file, entries: r1.file.entries };
    const d = await V.decryptAll(tampered, session);
    expect(d.warnings.join(' ')).toMatch(/index/);
    const swapped = { ...r2.file, entries: [{ ...r1.file.entries[0]!, ver: 2 }] };
    const d2 = await V.decryptAll(swapped, session);
    expect(d2.entries).toHaveLength(0);
    expect(d2.warnings.join(' ')).toMatch(/could not be decrypted/);
  });

  it('change password re-wraps the same vault key', async () => {
    const { file, session } = await V.createVault('old-password-123', fastArgon());
    const meta = await V.readMeta(file, session);
    const f2 = await V.changePassword(file, session, meta, 'new-password-456', fastArgon());
    await expect(V.unlockWithPassword(f2, 'old-password-123')).rejects.toBeInstanceOf(DecryptError);
    const s = await V.unlockWithPassword(f2, 'new-password-456');
    expect(b64(s.raw)).toBe(b64(session.raw));
  });

  it('PRF slot unlocks with the right PRF output only', async () => {
    const { file, session } = await V.createVault('pw-pw-pw-pw', fastArgon());
    const meta = await V.readMeta(file, session);
    const prf = crypto.getRandomValues(new Uint8Array(32));
    const f2 = await V.addPrfSlot(file, session, meta, 'cred-1', prf);
    const s = await V.unlockWithPrf(f2, 'cred-1', prf);
    expect(b64(s.raw)).toBe(b64(session.raw));
    await expect(V.unlockWithPrf(f2, 'cred-1', crypto.getRandomValues(new Uint8Array(32)))).rejects.toBeInstanceOf(DecryptError);
    await expect(V.unlockWithPrf(f2, 'cred-2', prf)).rejects.toThrow();
  });

  it('TOTP requirement is integrity-protected in sealed meta', async () => {
    const { file, session } = await V.createVault('pw-pw-pw-pw', fastArgon());
    const meta = await V.readMeta(file, session);
    const r = await V.setTotp(file, session, meta, { secret: 'JBSWY3DPEHPK3PXP' });
    const stripped = { ...r.file, require: { totp: false, passkey: false } };
    const d = await V.decryptAll(stripped, session);
    expect(d.meta.require.totp).toBe(true);
    expect(d.warnings.join(' ')).toMatch(/altered/);
  });

  it('encrypted export / import round trip', async () => {
    const entries = [{ ...emptyEntry('env'), id: 'x', ver: 1, title: 'DB', name: 'DB_URL', value: 'postgres://u:p@h/db', env: 'prod' }];
    const exp = await V.exportEncrypted(entries, { environments: ['dev', 'prod'] }, 'export-pass-1', fastArgon());
    expect(JSON.stringify(exp)).not.toContain('postgres');
    const back = await V.importEncrypted(exp, 'export-pass-1');
    expect(back.entries[0]!.value).toBe('postgres://u:p@h/db');
    await expect(V.importEncrypted(exp, 'nope')).rejects.toBeInstanceOf(DecryptError);
  });
});

describe('recovery', () => {
  it('codes are 100-bit, well formed, one-time', async () => {
    const c = newRecoveryCode();
    expect(c).toMatch(/^[A-Z2-7]{5}(-[A-Z2-7]{5}){3}$/);
    expect(isWellFormedCode(c.toLowerCase().replace(/-/g, ' '))).toBe(true);
    const { file, session } = await V.createVault('pw-pw-pw-pw', fastArgon());
    const meta = await V.readMeta(file, session);
    const { file: f2, codes } = await V.replaceRecoveryCodes(file, session, meta, 3);
    expect(codes).toHaveLength(3);
    // Only salted hashes are stored.
    for (const code of codes) expect(JSON.stringify(f2)).not.toContain(normalizeCode(code));
    const slot = f2.slots.find((s) => s.type === 'recovery-code')!;
    expect((slot as { hash: string }).hash).toBe(await codeHash(codes[0]!, (slot as { salt: string }).salt));
    const { session: s, slotId } = await V.unlockWithRecoveryCode(f2, codes[1]!.toLowerCase());
    expect(b64(s.raw)).toBe(b64(session.raw));
    const f3 = await V.consumeSlot(f2, session, meta, slotId);
    await expect(V.unlockWithRecoveryCode(f3, codes[1]!)).rejects.toThrow(/already used|unknown/);
    await expect(V.unlockWithRecoveryCode(f3, codes[0]!)).resolves.toBeTruthy();
  });

  it('recovery key + encrypted kit', async () => {
    const { file, session } = await V.createVault('pw-pw-pw-pw', fastArgon());
    const meta = await V.readMeta(file, session);
    const { file: f2, key } = await V.replaceRecoveryKey(file, session, meta);
    expect(recoveryKeyBytes(key)).toHaveLength(32);
    const kit = await buildKit(f2.id, key, 'kit passphrase!', fastArgon());
    expect(JSON.stringify(kit)).not.toContain(key);
    const back = await openKit(kit, 'kit passphrase!');
    const s = await V.unlockWithRecoveryKey(f2, back);
    expect(b64(s.raw)).toBe(b64(session.raw));
    await expect(openKit(kit, 'wrong')).rejects.toBeInstanceOf(DecryptError);
    expect(newRecoveryKey()).not.toBe(newRecoveryKey());
  });
});

describe('TOTP / HOTP (RFC 4226 + RFC 6238 vectors)', () => {
  const ascii = (s: string) => new TextEncoder().encode(s);
  it('HOTP vectors', async () => {
    const want = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
    for (let i = 0; i < want.length; i++) expect(await hotp(ascii('12345678901234567890'), i)).toBe(want[i]);
  });

  it('TOTP vectors SHA-1 / SHA-256 / SHA-512', async () => {
    const times = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];
    const cases = [
      { alg: 'SHA-1' as const, seed: '12345678901234567890', want: ['94287082', '07081804', '14050471', '89005924', '69279037', '65353130'] },
      { alg: 'SHA-256' as const, seed: '12345678901234567890123456789012', want: ['46119246', '68084774', '67062674', '91819424', '90698825', '77737706'] },
      { alg: 'SHA-512' as const, seed: '1234567890123456789012345678901234567890123456789012345678901234', want: ['90693936', '25091201', '99943326', '93441116', '38618901', '47863826'] },
    ];
    for (const c of cases) {
      const secret = base32Encode(ascii(c.seed));
      for (let i = 0; i < times.length; i++) {
        expect(await totpAt({ secret, digits: 8, algorithm: c.alg }, times[i]! * 1000)).toBe(c.want[i]);
      }
    }
  });

  it('verifies within ±1 step and rejects replays', async () => {
    const cfg = { secret: 'JBSWY3DPEHPK3PXP' };
    const now = 1_700_000_000_000;
    const code = await totpAt(cfg, now - 30_000);
    const step = await verifyTotp(cfg, code, now);
    expect(step).not.toBeNull();
    expect(await verifyTotp(cfg, code, now, 1, step)).toBeNull();
    expect(await verifyTotp(cfg, await totpAt(cfg, now - 120_000), now)).toBeNull();
    expect(await verifyTotp(cfg, 'abc123', now)).toBeNull();
  });

  it('otpauth URI round trip (Google Authenticator / Authy format)', () => {
    const uri = otpauthUri({ secret: 'JBSWY3DPEHPK3PXP' }, 'player');
    expect(uri).toMatch(/^otpauth:\/\/totp\/PEVV%3Aplayer\?secret=JBSWY3DPEHPK3PXP&issuer=PEVV$/);
    expect(parseOtpauth(uri).secret).toBe('JBSWY3DPEHPK3PXP');
    expect(parseOtpauth('otpauth://totp/x?secret=GEZDGNBV&algorithm=SHA256&digits=8&period=60')).toMatchObject({ algorithm: 'SHA-256', digits: 8, period: 60 });
    expect(() => parseOtpauth('otpauth://hotp/x?secret=GEZDGNBV')).toThrow();
    expect(() => parseOtpauth('not base32!')).toThrow();
    expect(base32Decode(base32Encode(new Uint8Array([1, 2, 3, 250])))).toEqual(new Uint8Array([1, 2, 3, 250]));
  });

  it('attempt limiter backs off exponentially after 5 failures', () => {
    expect(limiterDelay(4)).toBe(0);
    expect(limiterDelay(5)).toBe(30_000);
    expect(limiterDelay(6)).toBe(60_000);
    expect(limiterDelay(50)).toBe(3_600_000);
    let st = { fails: 0, until: 0 };
    for (let i = 0; i < 5; i++) st = limiterRecord(st, false, 1000);
    expect(limiterBlocked(st, 1000)).toBe(30_000);
    expect(limiterRecord(st, true)).toEqual({ fails: 0, until: 0 });
  });
});
