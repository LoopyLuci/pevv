import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type Bytes, b64url, concat, toBytes, unb64url, utf8 } from '@/pevv/bytes';
import { ARGON2_MIN, sha256 } from '@/pevv/crypto';
import * as S from '@/pevv/store';
import { createNative, toNativeError } from '@/pevv/desktop/native';
import type { DesktopIpc } from '@/pevv/desktop/bridge';
import { NativeError, setNative, unlockGate, type NativeApi, type NativePrfResult } from '@/pevv/native';
import { currentRpId, inDesktopApp, passkeyEnrolAvailable, passkeysBlocked, registerPasskey, webauthnAvailable } from '@/pevv/webauthn';

const fast = async () => ({ alg: 'argon2id' as const, ...ARGON2_MIN, salt: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))) });
const RP = 'localhost';

/** What browsers (and the Rust shell) do to a PRF input before it reaches hmac-secret. */
async function prfSalt(input: Uint8Array): Promise<Bytes> {
  return sha256(concat(utf8('WebAuthn PRF\0'), input));
}

function rawToDer(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0]! & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

/** One FIDO2 key. The browser side and the native (Rust shell) side are two doors to the same key. */
async function fakeKey(prf: boolean) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const credId = crypto.getRandomValues(new Uint8Array(16));
  const hmacKey = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  let counter = 0;
  const hmacSecret = async (input: Uint8Array) => new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, await prfSalt(input)));
  const sign = async (rpId: string, challengeB64: string, origin: string) => {
    counter++;
    const authData = concat(await sha256(utf8(rpId)), new Uint8Array([0x05, 0, 0, 0, counter]));
    const clientDataJson = JSON.stringify({ type: 'webauthn.get', challenge: challengeB64, origin, crossOrigin: false });
    const signed = concat(authData, await sha256(utf8(clientDataJson)));
    const signature = rawToDer(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, signed)));
    return { authData, clientDataJson, signature };
  };
  const browser = {
    create: vi.fn(async ({ publicKey }: { publicKey: PublicKeyCredentialCreationOptions }) => {
      const first = (publicKey.extensions as { prf?: { eval?: { first: BufferSource } } }).prf?.eval?.first;
      const out = first && prf ? await hmacSecret(toBytes(first as ArrayBuffer)) : null;
      return {
        rawId: credId.buffer,
        response: { getPublicKey: () => spki.buffer, getPublicKeyAlgorithm: () => -7, getTransports: () => ['usb'] },
        getClientExtensionResults: () => (first ? { prf: { enabled: prf, ...(out ? { results: { first: out } } : {}) } } : {}),
      };
    }),
    get: vi.fn(async ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => {
      const s = await sign(publicKey.rpId!, b64url(toBytes(publicKey.challenge as ArrayBuffer)), location.origin);
      const evalBy = (publicKey.extensions as { prf?: { evalByCredential?: Record<string, { first: BufferSource }> } } | undefined)?.prf?.evalByCredential;
      const salt = evalBy?.[b64url(credId)]?.first;
      const out = prf && salt ? await hmacSecret(toBytes(salt as ArrayBuffer)) : null;
      return {
        rawId: credId.buffer,
        response: { authenticatorData: s.authData.buffer, clientDataJSON: utf8(s.clientDataJson).buffer, signature: s.signature.buffer },
        getClientExtensionResults: () => (out ? { prf: { results: { first: out } } } : {}),
      };
    }),
  };
  const nativeCalls: Array<{ credentials: Array<{ id: string; salt1?: string }>; challenge: string; requireUv: boolean; pin?: string }> = [];
  const native = vi.fn(async (req: { credentials: Array<{ id: string; salt1?: string }>; challenge: string; requireUv: boolean; pin?: string }): Promise<NativePrfResult> => {
    nativeCalls.push(req);
    const c = req.credentials.find((x) => x.id === b64url(credId));
    if (!c) throw new NativeError('no match', 'no-device');
    const s = await sign(RP, req.challenge, `https://${RP}`);
    const out = c.salt1 ? await hmacSecret(unb64url(c.salt1)) : null;
    return {
      credentialId: b64url(credId), prf1: out ? b64url(out) : null, prf2: null,
      authenticatorData: b64url(s.authData), clientDataJson: s.clientDataJson, signature: b64url(s.signature),
    };
  });
  return { browser, native, nativeCalls, credId };
}

function installBrowser(b: { create: unknown; get: unknown }) {
  (window as unknown as { PublicKeyCredential: unknown }).PublicKeyCredential = function PublicKeyCredential() {};
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create: b.create, get: b.get } });
}

function asDesktop(native: NativeApi) {
  (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: undefined });
  setNative(native);
}

function nativeApi(prf: (req: never) => Promise<NativePrfResult>, extra: Partial<NativeApi['passkey']> = {}, available = true): NativeApi {
  return {
    passkey: { support: { available, rpId: RP, platform: 'test', reason: available ? null : 'too old', appPin: true }, prf: prf as never, askPin: async () => null, ...extra },
    usb: {
      volumes: async () => [], readKeyFile: async () => '', writeKeyFile: async () => undefined, devices: async () => [],
      presence: async () => ({ designation: null, present: null }), setPresence: async () => undefined,
    },
  };
}

beforeEach(() => {
  localStorage.clear();
  S.__resetForTests();
  S.__setKdfFactory(fast);
});
afterEach(() => {
  delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
  setNative(null);
  S.__resetForTests();
});

describe('native passkey unlock (desktop)', () => {
  async function enrolOnSite(prf: boolean) {
    const key = await fakeKey(prf);
    installBrowser(key.browser);
    await S.createVault('correct horse battery');
    await S.addPasskey('YubiKey', { wantPrf: true });
    return key;
  }

  it('unlocks a PRF slot made on the site through the native bridge', async () => {
    const key = await enrolOnSite(true);
    S.lock('manual');
    const rec = S.usePevv.getState().file!.passkeys[0]!;
    expect(rec.mode).toBe('prf');
    asDesktop(nativeApi(key.native));
    expect(inDesktopApp()).toBe(true);
    expect(currentRpId()).toBe(RP);
    expect(webauthnAvailable()).toBe(true);
    expect(passkeysBlocked()).toBe(false);
    expect(S.prfPasskeys()).toHaveLength(1);
    await S.unlockPasskey();
    expect(S.usePevv.getState().status).toBe('unlocked');
    expect(key.native).toHaveBeenCalledTimes(1);
    const req = key.nativeCalls[0]!;
    // The slot's own PRF input goes over, as base64url of the raw bytes the browser would have used.
    expect(req.credentials).toEqual([{ id: rec.id, salt1: b64url(Uint8Array.from(atob(rec.prfSalt!), (c) => c.charCodeAt(0))) }]);
    expect(req.requireUv).toBe(true);
    expect(unb64url(req.challenge)).toHaveLength(32);
  });

  it('asks for the PIN, retries with it, and stops when the person cancels', async () => {
    const key = await enrolOnSite(true);
    S.lock('manual');
    let first = true;
    const prf = vi.fn(async (req: { pin?: string }) => {
      if (!req.pin) throw new NativeError('Enter your security key PIN.', 'pin-required');
      if (req.pin !== '1234' && first) { first = false; throw new NativeError('wrong', 'pin-invalid'); }
      return key.native(req as never);
    });
    const askPin = vi.fn(async (retry: boolean) => (retry ? '1234' : '9999'));
    asDesktop(nativeApi(prf as never, { askPin }));
    await S.unlockPasskey();
    expect(S.usePevv.getState().status).toBe('unlocked');
    expect(askPin.mock.calls.map((c) => c[0])).toEqual([false, true]);
    expect(prf.mock.calls.map((c) => (c[0] as { pin?: string }).pin)).toEqual([undefined, '9999', '1234']);

    S.lock('manual');
    const cancel = nativeApi(vi.fn(async () => { throw new NativeError('Enter your security key PIN.', 'pin-required'); }) as never, { askPin: async () => null });
    setNative(cancel);
    await expect(S.unlockPasskey()).rejects.toThrow('cancelled');
    expect(S.usePevv.getState().status).toBe('locked');
  });

  it('passes shell errors through as readable messages', async () => {
    await enrolOnSite(true);
    S.lock('manual');
    asDesktop(nativeApi((async () => { throw new NativeError('No security key found.', 'no-device'); }) as never));
    await expect(S.unlockPasskey()).rejects.toThrow('No security key found.');
    expect(S.usePevv.getState().error).toBe('No security key found.');
  });

  it('only offers passkeys of the site rpId', async () => {
    const key = await enrolOnSite(true);
    S.lock('manual');
    const f = S.usePevv.getState().file!;
    S.usePevv.setState({ file: { ...f, passkeys: f.passkeys.map((p) => ({ ...p, rpId: 'other.example' })) } });
    asDesktop(nativeApi(key.native));
    expect(S.prfPasskeys()).toHaveLength(0);
    await expect(S.unlockPasskey()).rejects.toThrow(/No passkey on this vault can unlock/);
    expect(key.native).not.toHaveBeenCalled();
  });

  it('a 2FA-only passkey is verified as a second factor through the native path', async () => {
    const key = await enrolOnSite(false);
    expect(S.usePevv.getState().file!.passkeys[0]!.mode).toBe('2fa');
    await S.setRequirePasskey(true);
    S.lock('manual');
    asDesktop(nativeApi(key.native));
    await S.unlockPassword('correct horse battery');
    expect(S.usePevv.getState().status).toBe('second-factor');
    await S.verifySecondPasskey();
    expect(S.usePevv.getState().status).toBe('unlocked');
    expect(key.nativeCalls[0]!.credentials[0]!.salt1).toBeUndefined();
  });

  it('a tampered signature from the shell is rejected', async () => {
    const key = await enrolOnSite(false);
    await S.setRequirePasskey(true);
    S.lock('manual');
    asDesktop(nativeApi((async (req: never) => {
      const r = await key.native(req);
      const sig = unb64url(r.signature);
      sig[sig.length - 1] = sig[sig.length - 1]! ^ 1;
      return { ...r, signature: b64url(sig) };
    }) as never));
    await S.unlockPassword('correct horse battery');
    await expect(S.verifySecondPasskey()).rejects.toThrow();
    expect(S.usePevv.getState().status).toBe('second-factor');
  });

  it('new passkeys cannot be made in the desktop app', async () => {
    const key = await fakeKey(true);
    asDesktop(nativeApi(key.native));
    expect(passkeyEnrolAvailable()).toBe(false);
    await expect(registerPasskey({ vaultId: 'v', name: 'x', exclude: [], wantPrf: true })).rejects.toThrow(/added in the PEVV web app/);
  });

  it('is blocked with the reason when the shell says it is unavailable', () => {
    asDesktop(nativeApi((async () => { throw new Error('unused'); }) as never, {}, false));
    expect(webauthnAvailable()).toBe(false);
    expect(passkeysBlocked()).toBe(true);
  });
});

describe('desktop native bridge', () => {
  it('turns shell errors into NativeError', () => {
    expect(toNativeError({ code: 'pin-required', message: 'PIN please' })).toMatchObject({ code: 'pin-required', message: 'PIN please' });
    expect(toNativeError('boom')).toMatchObject({ code: 'failed', message: 'boom' });
    expect(toNativeError(new NativeError('x', 'y'))).toMatchObject({ code: 'y' });
  });

  it('maps commands to the shell and degrades when passkey_support is missing', async () => {
    const calls: Array<{ cmd: string; args: Record<string, unknown> | undefined }> = [];
    const ipc: DesktopIpc = {
      invoke: (async (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args });
        if (cmd === 'passkey_support') throw new Error('no such command');
        if (cmd === 'usb_keyfile_write') throw { code: 'failed', message: 'exists' };
        return [] as never;
      }) as DesktopIpc['invoke'],
      listen: async () => () => undefined,
    };
    const n = await createNative(ipc, async () => null);
    expect(n.passkey.support.available).toBe(false);
    await n.usb.volumes();
    await n.usb.readKeyFile('E:\\');
    await expect(n.usb.writeKeyFile('E:\\', 'x')).rejects.toMatchObject({ message: 'exists', code: 'failed' });
    await n.usb.setPresence({ id: 'usb:1:2:3', name: 'Mouse', requireToUnlock: false });
    expect(calls.map((c) => c.cmd)).toEqual(['passkey_support', 'usb_volumes', 'usb_keyfile_read', 'usb_keyfile_write', 'presence_set']);
    expect(calls[2]!.args).toEqual({ path: 'E:\\' });
    // The page never sends an rpId.
    expect(JSON.stringify(calls)).not.toMatch(/rpId/);
  });
});

describe('presence unlock gate', () => {
  const withPresence = (state: unknown) => ({ ...nativeApi((async () => { throw new Error('unused'); }) as never), usb: { ...nativeApi((async () => undefined) as never).usb, presence: async () => state as never } });

  it('passes without a native shell or a designation', async () => {
    expect(await unlockGate()).toBeNull();
    setNative(withPresence({ designation: null, present: null }));
    expect(await unlockGate()).toBeNull();
  });

  it('only blocks when required, designated and absent', async () => {
    const d = { id: 'usb:1:2:3', name: 'Mouse', requireToUnlock: true };
    setNative(withPresence({ designation: d, present: false }));
    expect(await unlockGate()).toMatch(/Plug in "Mouse"/);
    setNative(withPresence({ designation: d, present: true }));
    expect(await unlockGate()).toBeNull();
    setNative(withPresence({ designation: d, present: null }));
    expect(await unlockGate()).toBeNull();
    setNative(withPresence({ designation: { ...d, requireToUnlock: false }, present: false }));
    expect(await unlockGate()).toBeNull();
    setNative({ ...withPresence({}), usb: { ...withPresence({}).usb, presence: async () => { throw new Error('x'); } } });
    expect(await unlockGate()).toBeNull();
  });

  it('stops a password unlock while the device is absent, but not a recovery path', async () => {
    await S.createVault('correct horse battery');
    S.lock('manual');
    setNative(withPresence({ designation: { id: 'a', name: 'Mouse', requireToUnlock: true }, present: false }));
    await expect(S.unlockPassword('correct horse battery')).rejects.toThrow(/Plug in "Mouse"/);
    expect(S.usePevv.getState().status).toBe('locked');
    setNative(withPresence({ designation: { id: 'a', name: 'Mouse', requireToUnlock: true }, present: true }));
    await S.unlockPassword('correct horse battery');
    expect(S.usePevv.getState().status).toBe('unlocked');
  });
});
