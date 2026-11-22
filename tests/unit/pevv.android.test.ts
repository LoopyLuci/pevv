/**
 * Cross-compatibility with the Android app (android/). The fixture android/app/src/test/resources/vectors/kotlin-made.json was
 * written by the Kotlin engine (KotlinFixtureTest). Everything here opens it with the web app's own code: any failure means the Kotlin
 * port wrote something the other clients cannot read. Refresh it with `PEVV_WRITE_FIXTURES=1 ./gradlew :app:testDebugUnitTest`
 * (in android/), and the TypeScript-made vectors with `node scripts/android-vectors.mjs`.
 */
import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { b64url, unb64, unb64url } from '@/pevv/bytes';
import * as V from '@/pevv/vault';
import { validateKdf } from '@/pevv/crypto';
import { openKit } from '@/pevv/recovery';
import { openHandoff, unpackFrames } from '@/pevv/qr';
import { totpAt } from '@/pevv/totp';
import { derSignatureToRaw, signAssertion, verifyAssertion, PASSKEY_PROVIDER_AAGUID, isPasskeyEntry } from '@/pevv/passkeyProvider';
import type { Entry, VaultFile } from '@/pevv/model';

const dir = join(process.cwd(), 'android', 'app', 'src', 'test', 'resources', 'vectors');
const fixturePath = join(dir, 'kotlin-made.json');
const have = existsSync(fixturePath);
const hexBytes = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));

interface Fixture {
  password: string;
  file: VaultFile;
  vaultKeyHex: string;
  recoveryCodes: string[];
  recoveryKey: string;
  usbKeyFile: string;
  prf: { credId: string; outputHex: string };
  expectedEntries: Array<{ id: string; ver: number; data: Record<string, unknown> }>;
  expectedMeta: Record<string, unknown>;
  expectedTotp: { secret: string };
  exportV2: { password: string; file: Parameters<typeof V.openExport>[0] };
  kit: { passphrase: string; file: Parameters<typeof openKit>[0]; recoveryKey: string };
  qr: { frames: string[]; vaultText: string };
  handoff: { key: string; envelope: Parameters<typeof openHandoff>[0]; plain: string; now: number };
  passkey: { rpId: string; item: Entry; clientDataHashHex: string; authDataHex: string; signatureHex: string; creationAuthDataHex: string };
  totpCode: { unixMs: number; code: string };
}

const fx = (have ? JSON.parse(readFileSync(fixturePath, 'utf8')) : null) as Fixture | null;

describe('Android app: vaults written by the Kotlin engine open in the web code', () => {
  it('has the fixture (run the Kotlin tests with PEVV_WRITE_FIXTURES=1 to refresh it)', () => {
    expect(have).toBe(true);
  });

  it.skipIf(!have)('is a valid vault file with floor-respecting KDF parameters', () => {
    V.validateFile(fx!.file);
    validateKdf(fx!.file.kdf);
  });

  it.skipIf(!have)('opens with the password and decrypts every item, the meta and the authenticator secret', async () => {
    const f = fx!;
    const session = await V.unlockWithPassword(f.file, f.password);
    expect(Buffer.from(session.raw).toString('hex')).toBe(f.vaultKeyHex);
    const d = await V.decryptAll(f.file, session);
    expect(d.warnings).toEqual([]);
    expect(d.entries).toHaveLength(f.expectedEntries.length);
    for (const want of f.expectedEntries) {
      const got = d.entries.find((e) => e.id === want.id)!;
      expect(got.ver).toBe(want.ver);
      const { id: _i, ver: _v, ...data } = got;
      expect(data).toEqual(want.data);
    }
    expect(d.meta).toEqual(f.expectedMeta);
    expect(d.totp?.secret).toBe(f.expectedTotp.secret);
    // the edit kept the old password in the item's history, and unknown fields rode along
    const login = d.entries.find((e) => e.type === 'login')!;
    expect(login.password).toBe('changed-password');
    expect(login.history[0]?.field).toBe('password');
    expect((login as unknown as Record<string, unknown>).futureField).toEqual({ x: 1 });
    // the Kotlin-made passkey is the same item kind the desktop provider uses
    expect(d.entries.filter(isPasskeyEntry.bind(null))).toHaveLength(1);
  });

  it.skipIf(!have)('opens with every other slot type', async () => {
    const f = fx!;
    const raw = (s: { raw: Uint8Array }) => Buffer.from(s.raw).toString('hex');
    for (const code of f.recoveryCodes) expect(raw((await V.unlockWithRecoveryCode(f.file, code)).session)).toBe(f.vaultKeyHex);
    expect(raw(await V.unlockWithRecoveryKey(f.file, f.recoveryKey))).toBe(f.vaultKeyHex);
    expect(raw(await V.unlockWithUsbKey(f.file, f.usbKeyFile))).toBe(f.vaultKeyHex);
    expect(raw(await V.unlockWithPrf(f.file, f.prf.credId, hexBytes(f.prf.outputHex)))).toBe(f.vaultKeyHex);
  });

  it.skipIf(!have)('a wrong password does not open it', async () => {
    await expect(V.unlockWithPassword(fx!.file, 'wrong')).rejects.toThrow();
  });

  it.skipIf(!have)('opens the Kotlin portable export, recovery kit, offline QR frames and handoff', async () => {
    const f = fx!;
    const opened = await V.openExport(f.exportV2.file, f.exportV2.password);
    expect(opened.kind).toBe('vault');
    if (opened.kind === 'vault') expect(opened.file.id).toBe(f.file.id);
    expect(await openKit(f.kit.file, f.kit.passphrase)).toBe(f.kit.recoveryKey);
    const viaFrames = await unpackFrames(f.qr.frames);
    expect(JSON.stringify(viaFrames)).toBe(f.qr.vaultText);
    expect(await openHandoff(f.handoff.envelope, f.handoff.key, f.handoff.now)).toBe(f.handoff.plain);
  });

  it.skipIf(!have)('reads the Kotlin passkey and verifies its assertion signature (DER, ES256)', async () => {
    const p = fx!.passkey;
    const item = p.item as unknown as Parameters<typeof signAssertion>[0];
    const pub = unb64url((p.item as unknown as { passkeyPublicKey: string }).passkeyPublicKey);
    const hash = hexBytes(p.clientDataHashHex);
    const authData = hexBytes(p.authDataHex);
    const sig = hexBytes(p.signatureHex);
    expect(await verifyAssertion(pub, authData, hash, sig)).toBe(true);
    expect(derSignatureToRaw(sig)).toHaveLength(64);
    // flags: UP | BE | BS | UV
    expect(authData[32]).toBe(0x01 | 0x04 | 0x08 | 0x10);
    // the TypeScript signer accepts the PKCS#8 key Kotlin wrote
    const again = await signAssertion(item, hash, true);
    expect(await verifyAssertion(pub, again.authData, hash, again.signature)).toBe(true);
    // the creation authData carries the PEVV AAGUID and the same public key
    const created = hexBytes(p.creationAuthDataHex);
    const aaguid = Buffer.from(created.slice(37, 53)).toString('hex');
    expect(aaguid).toBe(PASSKEY_PROVIDER_AAGUID.replace(/-/g, ''));
    expect(b64url(created.slice(created.length - 32))).toBe(b64url(pub.slice(33, 65)));
  });

  it.skipIf(!have)('computes the same TOTP code', async () => {
    const f = fx!;
    expect(await totpAt({ secret: f.expectedTotp.secret, digits: 6, period: 30 }, f.totpCode.unixMs)).toBe(f.totpCode.code);
  });

  it.skipIf(!have)('base64 of every sealed value is plain RFC 4648 with 12-byte IVs', () => {
    const f = fx!;
    const seals = [f.file.meta, ...f.file.entries.map((e) => e.sealed), ...f.file.slots.map((s) => s.wrapped)];
    for (const s of seals) {
      expect(unb64(s.iv)).toHaveLength(12);
      expect(unb64(s.ct).length).toBeGreaterThanOrEqual(16);
      expect(s.iv).toMatch(/^[A-Za-z0-9+/]+=*$/);
    }
  });
});
