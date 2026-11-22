import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ARGON2_MIN, DecryptError } from '@/pevv/crypto';
import * as S from '@/pevv/store';
import * as V from '@/pevv/vault';
import { KEY_FILE_FORMAT, gateCheck, gateMatches, newKeyFile, parseKeyFile } from '@/pevv/usbkey';
import { setNative } from '@/pevv/native';
import { b64, randomBytes } from '@/pevv/bytes';
import type { Slot, VaultFile } from '@/pevv/model';

const fast = async () => ({ alg: 'argon2id' as const, ...ARGON2_MIN, salt: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))) });

beforeEach(() => {
  localStorage.clear();
  S.__resetForTests();
  S.__setKdfFactory(fast);
});
afterEach(() => {
  S.__resetForTests();
  setNative(null);
});

describe('key file format', () => {
  it('makes a 32-byte secret and parses it back', () => {
    const k = newKeyFile('vault1');
    expect(k.secret.length).toBe(32);
    const p = parseKeyFile(k.text);
    expect(p.file.format).toBe(KEY_FILE_FORMAT);
    expect(p.file.vault).toBe('vault1');
    expect(b64(p.secret)).toBe(b64(k.secret));
  });

  it('refuses anything that is not a key file', () => {
    expect(() => parseKeyFile('hello')).toThrow(/not a PEVV key file/);
    expect(() => parseKeyFile('{}')).toThrow(/not a PEVV key file/);
    expect(() => parseKeyFile(JSON.stringify({ format: KEY_FILE_FORMAT, v: 1, vault: 'x', secret: b64(randomBytes(16)) }))).toThrow(/damaged/);
    expect(() => parseKeyFile(JSON.stringify({ format: KEY_FILE_FORMAT, v: 1, vault: 'x', secret: '***' }))).toThrow(/damaged/);
  });

  it('gate checks only match their own secret', async () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    const check = await gateCheck(a);
    expect(await gateMatches(a, check)).toBe(true);
    expect(await gateMatches(b, check)).toBe(false);
    expect(await gateMatches(a, 'not base64 !!')).toBe(false);
  });
});

describe('usb-key slot (engine)', () => {
  async function freshVault() {
    const { file, session } = await V.createVault('correct horse battery', await fast());
    const meta = await V.readMeta(file, session);
    return { file, session, meta };
  }

  it('wraps the vault key: the key file alone unlocks, another file does not', async () => {
    const { file, session, meta } = await freshVault();
    const made = await V.addUsbKey(file, session, meta, 'Blue stick', 'unlock');
    expect(made.file.slots.filter((s) => s.type === 'usb-key')).toHaveLength(1);
    const opened = await V.unlockWithUsbKey(made.file, made.text);
    expect(b64(opened.raw)).toBe(b64(session.raw));
    await expect(V.unlockWithUsbKey(made.file, newKeyFile(file.id).text)).rejects.toBeInstanceOf(DecryptError);
  });

  it('several key files (a backup drive) each open the vault', async () => {
    const { file, session, meta } = await freshVault();
    const one = await V.addUsbKey(file, session, meta, 'Main', 'unlock');
    const two = await V.addUsbKey(one.file, session, one.meta, 'Backup', 'unlock');
    expect(V.usbKeySlots(two.file)).toHaveLength(2);
    expect(b64((await V.unlockWithUsbKey(two.file, one.text)).raw)).toBe(b64(session.raw));
    expect(b64((await V.unlockWithUsbKey(two.file, two.text)).raw)).toBe(b64(session.raw));
  });

  it('is bound to the file content and the slot, not to anything else', async () => {
    const { file, session, meta } = await freshVault();
    const made = await V.addUsbKey(file, session, meta, 'Main', 'unlock');
    const slot = V.usbKeySlots(made.file)[0]!;
    // Moving the wrapped key under another slot id breaks the GCM AAD.
    const moved: VaultFile = { ...made.file, slots: made.file.slots.map((s) => (s.id === slot.id ? { ...s, id: 'otherid' } as Slot : s)) };
    await expect(V.unlockWithUsbKey(moved, made.text)).rejects.toBeInstanceOf(DecryptError);
    // The `vault` hint inside the file is not part of the binding.
    const edited = JSON.stringify({ ...parseKeyFile(made.text).file, vault: 'something else' });
    expect(b64((await V.unlockWithUsbKey(made.file, edited)).raw)).toBe(b64(session.raw));
  });

  it('second-factor mode adds a gate record and no slot: the file alone opens nothing', async () => {
    const { file, session, meta } = await freshVault();
    const made = await V.addUsbKey(file, session, meta, 'Second', 'second-factor');
    expect(V.usbKeySlots(made.file)).toHaveLength(0);
    expect(made.meta.usbKeys).toHaveLength(1);
    await expect(V.unlockWithUsbKey(made.file, made.text)).rejects.toBeInstanceOf(DecryptError);
    expect(await V.checkUsbKeyFactor(made.file, session, made.meta, made.text)).toBe(true);
    expect(await V.checkUsbKeyFactor(made.file, session, made.meta, newKeyFile(file.id).text)).toBe(false);
    // The meta is sealed: the plaintext file does not show the gate hash.
    expect(JSON.stringify(made.file)).not.toContain(made.meta.usbKeys![0]!.check);
  });

  it('removing a key drops its slot or gate, and the requirement with the last gate', async () => {
    const { file, session, meta } = await freshVault();
    const s = await V.addUsbKey(file, session, meta, 'Slot', 'unlock');
    const g = await V.addUsbKey(s.file, session, s.meta, 'Gate', 'second-factor');
    const req = await V.setRequireUsbKey(g.file, session, g.meta, true);
    expect(req.file.require.usbKey).toBe(true);
    const gateId = req.meta.usbKeys![0]!.id;
    const slotId = V.usbKeySlots(req.file)[0]!.id;
    const noGate = await V.removeUsbKey(req.file, session, req.meta, gateId);
    expect(noGate.meta.usbKeys).toHaveLength(0);
    expect(noGate.meta.require.usbKey).toBe(false);
    const noSlot = await V.removeUsbKey(noGate.file, session, noGate.meta, slotId);
    expect(V.usbKeySlots(noSlot.file)).toHaveLength(0);
    await expect(V.unlockWithUsbKey(noSlot.file, s.text)).rejects.toBeInstanceOf(DecryptError);
  });

  it('survives a password change and a JSON round trip', async () => {
    const { file, session, meta } = await freshVault();
    const made = await V.addUsbKey(file, session, meta, 'Main', 'unlock');
    const changed = await V.changePassword(made.file, session, made.meta, 'a new long password', await fast());
    const again = JSON.parse(JSON.stringify(changed)) as VaultFile;
    V.validateFile(again);
    expect(b64((await V.unlockWithUsbKey(again, made.text)).raw)).toBe(b64(session.raw));
    expect(b64((await V.unlockWithPassword(again, 'a new long password')).raw)).toBe(b64(session.raw));
  });

  it('counts key files in the recovery status', async () => {
    const { file, session, meta } = await freshVault();
    const made = await V.addUsbKey(file, session, meta, 'Main', 'unlock');
    expect(V.recoveryStatus(made.file).usb).toBe(1);
  });
});

describe('older clients and unknown slot types', () => {
  it('ignore a usb-key slot (and any other unknown type) when unlocking by password', async () => {
    const { file, session, meta } = await V.createVault('correct horse battery', await fast()).then(async (r) => ({ ...r, meta: await V.readMeta(r.file, r.session) }));
    const made = await V.addUsbKey(file, session, meta, 'Main', 'unlock');
    const future = { id: 'zz', type: 'quantum-ring', blob: 'whatever' } as unknown as Slot;
    // The file as a client that predates usb-key sees it: slots it cannot interpret are simply skipped.
    const mixed: VaultFile = { ...made.file, slots: [future, ...made.file.slots] };
    V.validateFile(mixed);
    expect(b64((await V.unlockWithPassword(mixed, 'correct horse battery')).raw)).toBe(b64(session.raw));
    await expect(V.unlockWithPrf(mixed, 'nope', randomBytes(32))).rejects.toBeInstanceOf(DecryptError);
    await expect(V.unlockWithRecoveryKey(mixed, 'x')).rejects.toBeInstanceOf(DecryptError);
    await expect(V.unlockWithRecoveryCode(mixed, 'AAAAA-AAAAA-AAAAA-AAAAA')).rejects.toBeInstanceOf(DecryptError);
    expect(V.recoveryStatus(mixed)).toMatchObject({ codes: 0, key: false, prf: 0 });
    // Password change keeps the foreign slots intact.
    const changed = await V.changePassword(mixed, session, made.meta, 'another long password', await fast());
    expect(changed.slots.some((s) => s.type === ('quantum-ring' as Slot['type']))).toBe(true);
    expect(V.usbKeySlots(changed)).toHaveLength(1);
  });

  it('validateFile accepts unknown slot types and rejects a malformed usb-key slot', async () => {
    const { file } = await V.createVault('correct horse battery', await fast());
    const unknown = { ...file, slots: [...file.slots, { id: 'a', type: 'tomorrow' }] };
    expect(() => V.validateFile(unknown)).not.toThrow();
    const bad = { ...file, slots: [...file.slots, { id: 'a', type: 'usb-key', name: 3 }] };
    expect(() => V.validateFile(bad)).toThrow(/not a PEVV vault file/);
    const noType = { ...file, slots: [...file.slots, { id: 'a' }] };
    expect(() => V.validateFile(noType)).toThrow(/not a PEVV vault file/);
  });

  it('an old vault without usbKeys or require.usbKey opens and shows no key-file requirement', async () => {
    const { file, session } = await V.createVault('correct horse battery', await fast());
    const old = { ...file, require: { totp: false, passkey: false } };
    const d = await V.decryptAll(old, session);
    expect(d.warnings).toEqual([]);
    expect(d.meta.require.usbKey).toBeFalsy();
  });
});

describe('store flows', () => {
  async function unlockedStore() {
    await S.createVault('correct horse battery');
    return S.usePevv.getState();
  }

  it('a failed write to the drive leaves the vault untouched', async () => {
    await unlockedStore();
    await new Promise((r) => setTimeout(r, 100)); // let the device roster write settle
    const before = S.usePevv.getState().file!;
    await expect(S.addUsbKey('Stick', 'unlock', async () => { throw new Error('drive removed'); })).rejects.toThrow('drive removed');
    expect(S.usePevv.getState().file).toBe(before);
    expect(V.usbKeySlots(S.usePevv.getState().file!)).toHaveLength(0);
  });

  it('unlocks with the key file after a lock, and refuses a wrong one', async () => {
    await unlockedStore();
    let text = '';
    await S.addUsbKey('Stick', 'unlock', async (t) => { text = t; });
    S.lock('manual' as never);
    expect(S.usePevv.getState().status).toBe('locked');
    await expect(S.unlockUsbKey(newKeyFile(S.usePevv.getState().file!.id).text)).rejects.toThrow();
    expect(S.usePevv.getState().status).toBe('locked');
    await S.unlockUsbKey(text);
    expect(S.usePevv.getState().status).toBe('unlocked');
  });

  it('as a second factor: password first, then the file, and the file alone cannot open it', async () => {
    await unlockedStore();
    let text = '';
    await S.addUsbKey('Stick', 'second-factor', async (t) => { text = t; });
    await S.setRequireUsbKey(true);
    S.lock('manual' as never);
    await expect(S.unlockUsbKey(text)).rejects.toThrow(/No USB key file is set up/);
    await S.unlockPassword('correct horse battery');
    expect(S.usePevv.getState().status).toBe('second-factor');
    expect(S.usePevv.getState().pending.usbKey).toBe(true);
    await expect(S.verifySecondUsbKey(newKeyFile('x').text)).rejects.toThrow(/does not belong/);
    expect(S.usePevv.getState().status).toBe('second-factor');
    await S.verifySecondUsbKey(text);
    expect(S.usePevv.getState().status).toBe('unlocked');
  });

  it('a slot key file satisfies the requirement by itself', async () => {
    await unlockedStore();
    let gateText = '';
    let slotText = '';
    await S.addUsbKey('Gate', 'second-factor', async (t) => { gateText = t; });
    await S.addUsbKey('Slot', 'unlock', async (t) => { slotText = t; });
    await S.setRequireUsbKey(true);
    S.lock('manual' as never);
    await S.unlockUsbKey(slotText);
    expect(S.usePevv.getState().status).toBe('unlocked');
    S.lock('manual' as never);
    await S.unlockPassword('correct horse battery');
    expect(S.usePevv.getState().status).toBe('second-factor');
    await S.verifySecondUsbKey(gateText);
    expect(S.usePevv.getState().status).toBe('unlocked');
  });

  it('refuses to require a key file before one is enrolled', async () => {
    await unlockedStore();
    await expect(S.setRequireUsbKey(true)).rejects.toThrow(/Add a second-factor key file first/);
  });
});
