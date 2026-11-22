import { describe, expect, it } from 'vitest';
import { b64 } from '@/pevv/bytes';
import { ARGON2_MIN, DecryptError, type KdfParams } from '@/pevv/crypto';
import { deviceKind, deviceNeedsWrite, mergeDevices, mergeRoster, sameRoster } from '@/pevv/devices';
import type { VaultDevice } from '@/pevv/model';
import { normalizeCode } from '@/pevv/recovery';
import * as V from '@/pevv/vault';

const salt = () => b64(crypto.getRandomValues(new Uint8Array(16)));
const fastArgon = (): KdfParams => ({ alg: 'argon2id', ...ARGON2_MIN, salt: salt() });

const dev = (p: Partial<VaultDevice> & { id: string }): VaultDevice => ({
  name: p.id, kind: 'desktop', added: 1, seen: 1, agent: 'Chrome · Linux', ...p,
});

describe('PEVV devices', () => {
  it('classifies a phone, a tablet and a computer', () => {
    expect(deviceKind('Mozilla/5.0 (Linux; Android 14; Pixel) AppleWebKit Mobile')).toBe('phone');
    expect(deviceKind('Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)')).toBe('tablet');
    expect(deviceKind('Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0')).toBe('desktop');
  });

  it('merges by id and keeps the newer sighting', () => {
    const merged = mergeDevices(
      [dev({ id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', name: 'Desk', seen: 10, added: 5 }), dev({ id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', seen: 3 })],
      [dev({ id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', name: 'Renamed', seen: 20, added: 9 }), dev({ id: 'cccccccccccccccc-cccc-cccc-cccc-cccccccccccc', seen: 8 })],
    );
    const a = merged.find((d) => d.id.startsWith('aaaaaaaa'))!;
    expect(a.name).toBe('Renamed');
    expect(a.added).toBe(5);
    expect(merged.map((d) => d.id[0])).toEqual(['a', 'c', 'b']);
  });

  it('does not rewrite a device that was seen recently with the same name', () => {
    const prev = dev({ id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', seen: 1_000 });
    expect(deviceNeedsWrite(prev, { ...prev, seen: 1_000 + 60_000 })).toBe(false);
    expect(deviceNeedsWrite(prev, { ...prev, name: 'Phone', seen: 1_000 + 60_000 })).toBe(true);
    expect(deviceNeedsWrite(undefined, prev)).toBe(true);
  });

  it('unions devices and does not bring a removed device back', () => {
    const desk = dev({ id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', name: 'Computer', seen: 10 });
    const phone = dev({ id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', name: 'Phone', kind: 'phone', seen: 20 });
    const merged = mergeRoster(
      { devices: [desk], revokedDevices: [] },
      { devices: [desk, phone], revokedDevices: [] },
    );
    expect(merged.devices.map((d) => d.name)).toEqual(['Phone', 'Computer']);
    const removed = mergeRoster(merged, { devices: [desk, phone], revokedDevices: [phone.id] });
    expect(removed.devices.map((d) => d.id)).toEqual([desk.id]);
    expect(removed.revokedDevices).toEqual([phone.id]);
    expect(sameRoster(removed, mergeRoster(removed, { devices: [phone], revokedDevices: [] }))).toBe(true);
  });
});

describe('PEVV portable export', () => {
  it('carries the authenticator, recovery codes and passkeys, not their secrets in the clear', async () => {
    const { file, session } = await V.createVault('same-master-pw', fastArgon());
    const meta = await V.readMeta(file, session);
    const totp = await V.setTotp(file, session, meta, { secret: 'JBSWY3DPEHPK3PXP' });
    const meta2 = await V.readMeta(totp.file, session);
    const { file: withCodes, codes } = await V.replaceRecoveryCodes(totp.file, session, meta2, 2);
    const meta3 = await V.readMeta(withCodes, session);
    const prf = crypto.getRandomValues(new Uint8Array(32));
    const withPrf = await V.addPrfSlot(withCodes, session, meta3, 'cred-yubi', prf);
    const enrolled = { ...withPrf, passkeys: [...withPrf.passkeys, { id: 'cred-yubi', name: 'Blue YubiKey', mode: 'prf' as const, publicKey: null, alg: -7, transports: ['usb'], prfSalt: null, created: 1, lastUsed: null, signCount: 0, rpId: 'luciverse.app' }] };
    const exp = await V.exportPortable(enrolled, 'export-password-ok', fastArgon());
    const raw = JSON.stringify(exp);
    expect(exp.v).toBe(2);
    expect(exp.id).toBe(enrolled.id);
    expect(raw).not.toContain('JBSWY3DPEHPK3PXP');
    expect(raw).not.toContain('same-master-pw');
    expect(raw).not.toContain('Blue YubiKey');
    for (const code of codes) expect(raw).not.toContain(normalizeCode(code));
    expect(V.peekExport(raw)).toBe(2);
    await expect(V.openExport(exp, 'wrong-password')).rejects.toBeInstanceOf(DecryptError);
    const opened = await V.openExport(exp, 'export-password-ok');
    expect(opened.kind).toBe('vault');
    if (opened.kind !== 'vault') return;
    const back = await V.unlockWithPassword(opened.file, 'same-master-pw');
    const d = await V.decryptAll(opened.file, back);
    expect(d.totp?.secret).toBe('JBSWY3DPEHPK3PXP');
    expect(d.meta.require.totp).toBe(true);
    const viaCode = await V.unlockWithRecoveryCode(opened.file, codes[0]!);
    expect(b64(viaCode.session.raw)).toBe(b64(session.raw));
    const viaPrf = await V.unlockWithPrf(opened.file, 'cred-yubi', prf);
    expect(b64(viaPrf.raw)).toBe(b64(session.raw));
    expect(opened.file.passkeys[0]?.name).toBe('Blue YubiKey');
  });
});
