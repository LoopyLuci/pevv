import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { b64url, concat, toBytes, utf8 } from '@/pevv/bytes';
import { ARGON2_MIN, sha256 } from '@/pevv/crypto';
import * as S from '@/pevv/store';
import { derToRaw, verifyAssertion } from '@/pevv/webauthn';
import { totpAt } from '@/pevv/totp';
import { envNamesInSource, expandVars, parseDotenv, reuseGroups, serializeDotenv, siteMatches, emptyEntry, applyEdit } from '@/pevv/model';
import { DEFAULT_GEN, generatePassphrase, generatePassword, isCommonPassword, strength } from '@/pevv/gen';

const fast = async () => ({ alg: 'argon2id' as const, ...ARGON2_MIN, salt: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))) });

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

/** Fake authenticator: ES256 keys + deterministic PRF (HMAC of the salt), like CTAP2 hmac-secret. */
async function fakeAuthenticator(opts: { prf: boolean; prfOnCreate?: boolean }) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const credId = crypto.getRandomValues(new Uint8Array(16));
  const hmacKey = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  let counter = 0;
  const prfEval = async (salt: BufferSource) => new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, toBytes(salt as ArrayBuffer)));
  const create = vi.fn(async ({ publicKey }: { publicKey: PublicKeyCredentialCreationOptions }) => {
    const prfIn = (publicKey.extensions as { prf?: { eval?: { first: BufferSource } } }).prf;
    const results = opts.prf && opts.prfOnCreate && prfIn?.eval ? { first: await prfEval(prfIn.eval.first) } : undefined;
    return {
      rawId: credId.buffer,
      response: { getPublicKey: () => spki.buffer, getPublicKeyAlgorithm: () => -7, getTransports: () => ['usb'] },
      getClientExtensionResults: () => (prfIn ? { prf: { enabled: opts.prf, ...(results ? { results } : {}) } } : {}),
    };
  });
  const get = vi.fn(async ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => {
    counter++;
    const rpHash = await sha256(utf8(publicKey.rpId!));
    const authData = concat(rpHash, new Uint8Array([0x05, 0, 0, 0, counter]));
    const clientData = utf8(JSON.stringify({ type: 'webauthn.get', challenge: b64url(toBytes(publicKey.challenge as ArrayBuffer)), origin: location.origin, crossOrigin: false }));
    const signed = concat(authData, await sha256(clientData));
    const sig = rawToDer(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, signed)));
    const evalBy = (publicKey.extensions as { prf?: { evalByCredential?: Record<string, { first: BufferSource }> } } | undefined)?.prf?.evalByCredential;
    const salt = evalBy?.[b64url(credId)]?.first;
    const out = opts.prf && salt ? await prfEval(salt) : null;
    return {
      rawId: credId.buffer,
      response: { authenticatorData: authData.buffer, clientDataJSON: clientData.buffer, signature: sig.buffer },
      getClientExtensionResults: () => (out ? { prf: { results: { first: out } } } : {}),
    };
  });
  return { create, get, spki, kp };
}

function installWebAuthn(fake: { create: unknown; get: unknown }) {
  (window as unknown as { PublicKeyCredential: unknown }).PublicKeyCredential = function PublicKeyCredential() {};
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create: fake.create, get: fake.get } });
}

beforeEach(() => {
  localStorage.clear();
  S.__resetForTests();
  S.__setKdfFactory(fast);
});
afterEach(() => S.__resetForTests());

describe('PEVV store flows', () => {
  it('create, save entries, lock drops plaintext, unlock restores', async () => {
    await S.createVault('my long master password');
    expect(S.usePevv.getState().status).toBe('unlocked');
    const e = await S.saveEntry(null, { type: 'login', title: 'Supabase', site: 'luciverse:supabase-signin', username: 'me@example.com', password: 'S3cret-pass-1234!' });
    expect(localStorage.getItem(S.VAULT_KEY)).not.toContain('S3cret');
    S.lock();
    expect(S.usePevv.getState().entries).toEqual([]);
    await expect(S.unlockPassword('nope nope nope')).rejects.toThrow(/wrong/);
    await S.unlockPassword('my long master password');
    expect(S.usePevv.getState().entries.find((x) => x.id === e.id)?.password).toBe('S3cret-pass-1234!');
  });

  it('rate-limits password guesses after 5 failures', async () => {
    await S.createVault('my long master password');
    S.lock();
    for (let i = 0; i < 5; i++) await expect(S.unlockPassword(`bad-${i}`)).rejects.toThrow(/wrong/);
    await expect(S.unlockPassword('my long master password')).rejects.toThrow(/Too many attempts/);
  });

  it('PRF passkey (mocked authenticator) unlocks without the password', async () => {
    const fake = await fakeAuthenticator({ prf: true });
    installWebAuthn(fake);
    await S.createVault('my long master password');
    await S.saveEntry(null, { type: 'env', name: 'API_TOKEN', value: 'tok-123', env: 'dev' });
    const rec = await S.addPasskey('YubiKey 5C', { wantPrf: true });
    expect(rec.mode).toBe('prf');
    expect(fake.get).toHaveBeenCalledTimes(1); // extra touch to evaluate PRF
    S.lock();
    await S.unlockPasskey();
    expect(S.usePevv.getState().status).toBe('unlocked');
    expect(S.envVars().API_TOKEN).toBe('tok-123');
  });

  it('falls back to passkey-as-second-factor when PRF is unavailable', async () => {
    const fake = await fakeAuthenticator({ prf: false });
    installWebAuthn(fake);
    await S.createVault('my long master password');
    const rec = await S.addPasskey('Old key', { wantPrf: true });
    expect(rec.mode).toBe('2fa');
    await S.setRequirePasskey(true);
    S.lock();
    await expect(S.unlockPasskey()).rejects.toThrow(/master password/);
    await S.unlockPassword('my long master password');
    expect(S.usePevv.getState().status).toBe('second-factor');
    expect(S.usePevv.getState().entries).toEqual([]);
    await S.verifySecondPasskey();
    expect(S.usePevv.getState().status).toBe('unlocked');
  });

  it('TOTP gate after password; recovery code bypasses and forces a new password, then is burned', async () => {
    await S.createVault('my long master password');
    const cfg = S.startTotpEnrollment();
    await S.confirmTotpEnrollment(cfg, await totpAt(cfg, Date.now()));
    const codes = await S.newRecoveryCodes();
    S.lock();
    await S.unlockPassword('my long master password');
    expect(S.usePevv.getState().status).toBe('second-factor');
    await expect(S.verifySecondTotp('000000')).rejects.toThrow();
    await S.verifySecondTotp(await totpAt(cfg, Date.now() + 30_000));
    expect(S.usePevv.getState().status).toBe('unlocked');
    S.lock();
    await S.unlockRecoveryCode(codes[0]!);
    expect(S.usePevv.getState().status).toBe('set-password');
    await S.finishRecovery('a brand new master password');
    expect(S.usePevv.getState().status).toBe('unlocked');
    S.lock();
    await expect(S.unlockRecoveryCode(codes[0]!)).rejects.toThrow(/already used|unknown/);
    await S.unlockPassword('a brand new master password');
    expect(S.usePevv.getState().status).toBe('second-factor');
  });

  it('program env access needs an explicit grant', async () => {
    await S.createVault('my long master password');
    await S.saveEntry(null, { type: 'env', name: 'TOKEN', value: 'abc', env: 'dev' });
    await S.saveEntry(null, { type: 'env', name: 'OTHER', value: 'zzz', env: 'dev' });
    const p = S.requestProgramEnv('/programs/a.js', ['TOKEN']);
    expect(S.usePevv.getState().envRequest?.names).toEqual(['TOKEN']);
    await S.answerEnvRequest('always');
    expect(await p).toEqual({ TOKEN: 'abc' });
    expect(await S.requestProgramEnv('/programs/a.js', ['TOKEN'])).toEqual({ TOKEN: 'abc' });
    const q = S.requestProgramEnv('/programs/a.js', ['OTHER']);
    await S.answerEnvRequest('deny');
    expect(await q).toBeNull();
  });

  it('.env import/export and environments', async () => {
    await S.createVault('my long master password');
    const n = await S.importDotenvText('staging', 'A=1\nexport B="two words"\n# c\nC=\'x y\'\n');
    expect(n).toBe(3);
    expect(S.usePevv.getState().meta?.environments).toContain('staging');
    expect(S.envVars('staging')).toEqual({ A: '1', B: 'two words', C: 'x y' });
    expect(S.exportDotenvText('staging')).toBe('A=1\nB="two words"\nC="x y"\n');
  });

  it('autofill is off by default and same-origin only', async () => {
    await S.createVault('my long master password');
    await S.saveEntry(null, { type: 'login', title: 'a', site: 'luciverse:supabase-signin', username: 'u' });
    await S.saveEntry(null, { type: 'login', title: 'b', site: 'https://evil.example', username: 'x' });
    expect(S.autofillCandidates('supabase-signin')).toEqual([]);
    S.setPrefs({ autofill: true });
    expect(S.autofillCandidates('supabase-signin').map((e) => e.title)).toEqual(['a']);
    S.lock();
    expect(S.autofillCandidates('supabase-signin')).toEqual([]);
  });
});

describe('WebAuthn assertion verification', () => {
  it('rejects a wrong challenge or origin', async () => {
    const fake = await fakeAuthenticator({ prf: false });
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const r = await fake.get({ publicKey: { challenge, rpId: location.hostname } as PublicKeyCredentialRequestOptions });
    const base = {
      spki: fake.spki, alg: -7, authData: toBytes(r.response.authenticatorData as ArrayBuffer), clientDataJSON: toBytes(r.response.clientDataJSON as ArrayBuffer),
      signature: toBytes(r.response.signature as ArrayBuffer), challenge, origin: location.origin, rpId: location.hostname, prevSignCount: 0,
    };
    await expect(verifyAssertion(base)).resolves.toEqual({ signCount: 1 });
    await expect(verifyAssertion({ ...base, challenge: new Uint8Array(32) })).rejects.toThrow(/challenge/);
    await expect(verifyAssertion({ ...base, origin: 'https://evil.example' })).rejects.toThrow(/origin/);
    await expect(verifyAssertion({ ...base, rpId: 'evil.example' })).rejects.toThrow(/rpId/);
    await expect(verifyAssertion({ ...base, prevSignCount: 5 })).rejects.toThrow(/counter/);
    expect(derToRaw(rawToDer(new Uint8Array(64).fill(7)))).toEqual(new Uint8Array(64).fill(7));
  });
});

describe('PEVV model helpers', () => {
  it('generator honours sets, length and is unbiased enough', () => {
    const pw = generatePassword({ ...DEFAULT_GEN, length: 32 });
    expect(pw).toHaveLength(32);
    expect(pw).toMatch(/[a-z]/); expect(pw).toMatch(/[A-Z]/); expect(pw).toMatch(/\d/); expect(pw).toMatch(/[^A-Za-z0-9]/);
    expect(pw).not.toMatch(/[Il1O0o]/);
    expect(generatePassword({ ...DEFAULT_GEN, upper: false, digits: false, symbols: false, length: 12 })).toMatch(/^[a-z]{12}$/);
    const phrase = generatePassphrase({ words: 5, separator: '-', capitalize: true, number: false });
    expect(phrase.split('-')).toHaveLength(5);
  });

  it('strength meter flags common and weak passwords', () => {
    expect(strength('password123').common).toBe(true);
    expect(strength('password123').score).toBe(0);
    expect(isCommonPassword('P@ssw0rd!')).toBe(true);
    expect(strength('qwertyuiop').score).toBeLessThan(2);
    expect(strength(generatePassword({ ...DEFAULT_GEN, length: 24 })).score).toBe(4);
    expect(strength('Correct-Horse-Battery-Staple-Moon').score).toBeGreaterThanOrEqual(3);
  });

  it('reuse groups, edit history', () => {
    const a = { ...emptyEntry('login'), id: 'a', ver: 1, password: 'same' };
    const b = { ...emptyEntry('login'), id: 'b', ver: 1, password: 'same' };
    const c = { ...emptyEntry('login'), id: 'c', ver: 1, password: 'diff' };
    const g = reuseGroups([a, b, c]);
    expect(g.get('a')).toEqual(['a', 'b']);
    expect(g.has('c')).toBe(false);
    const edited = applyEdit(a, { password: 'new' }, 5);
    expect(edited.history[0]).toEqual({ at: 5, field: 'password', value: 'same' });
  });

  it('.env parse / serialize', () => {
    const vars = parseDotenv('# hi\nexport A=1\nB = "multi\\nline \\"q\\""\nC=plain # comment\nD=\'single $x\'\n9BAD=x\nE="spans\nlines"\n');
    expect(vars).toEqual([
      { name: 'A', value: '1' }, { name: 'B', value: 'multi\nline "q"' }, { name: 'C', value: 'plain' }, { name: 'D', value: 'single $x' }, { name: 'E', value: 'spans\nlines' },
    ]);
    expect(parseDotenv(serializeDotenv(vars))).toEqual(vars);
  });

  it('$VAR expansion and env.get detection', () => {
    expect(expandVars('run $FILE --shots ${SHOTS} \\$HOME $NOPE', { FILE: 'bell.qlang', SHOTS: '100' })).toEqual({
      text: 'run bell.qlang --shots 100 $HOME $NOPE', used: ['FILE', 'SHOTS'], missing: ['NOPE'],
    });
    expect(envNamesInSource("const a = env.get('API_KEY'); env.get(\"B\"); env.get(x)")).toEqual(['API_KEY', 'B']);
  });

  it('autofill site matching never crosses origins', () => {
    const o = 'https://vault.example.test';
    expect(siteMatches('luciverse:supabase-signin', 'supabase-signin', o)).toBe(true);
    expect(siteMatches('https://vault.example.test/passport', 'x', o)).toBe(true);
    expect(siteMatches('vault.example.test', 'x', o)).toBe(true);
    expect(siteMatches('https://vault.example.test.evil.com', 'x', o)).toBe(false);
    expect(siteMatches('http://vault.example.test', 'x', o)).toBe(false);
    expect(siteMatches('luciverse:other-form', 'supabase-signin', o)).toBe(false);
  });
});
