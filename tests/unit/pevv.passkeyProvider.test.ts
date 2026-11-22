import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PBKDF2_MIN_ITER, type KdfParams } from '@/pevv/crypto';
import { b64, b64url, concat, randomBytes, unb64url, utf8 } from '@/pevv/bytes';
import { applyEdit, emptyEntry, entrySubtitle, reuseGroups, type Entry, type EntryData } from '@/pevv/model';
import * as V from '@/pevv/vault';
import {
  COSE_ES256, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV, PASSKEY_PROVIDER_AAGUID, ProviderFailure, buildAuthData, coseKeyEs256, createPasskey, derSignatureToRaw,
  handleProviderRequest, isPasskeyEntry, passkeysForRp, rawSignatureToDer, sha256, signAssertion, uuidBytes, validRpId, verifyAssertion,
  type PasskeyEntry, type ProviderGetResult, type ProviderHost, type ProviderMakeResult, type ProviderRequest,
} from '@/pevv/passkeyProvider';
import { answerRequest, credentialMeta, sectionVisible, type ProviderSupport } from '@/pevv/desktop/provider';
import { fillLogin, matchLogins } from '@/pevv/desktop/link';
import { offerFor } from '@/pevv/desktop/autotypeHost';
import { filterEntries } from '@/pevv/ui/ItemsView';

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h: string): Uint8Array => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));

/** RFC 6979 A.2.5: ECDSA P-256 with SHA-256, message "sample". */
const RFC6979 = {
  ux: '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6',
  uy: '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299',
  r: 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
  s: 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
};

describe('authenticator data and COSE key (known vectors)', () => {
  it('rpIdHash is SHA-256 of the rp id (the WebAuthn test value for example.com)', async () => {
    expect(hex(await sha256(utf8('example.com')))).toBe('a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947');
  });

  it('the ES256 COSE key is the canonical CBOR map {1:2, 3:-7, -1:1, -2:x, -3:y}', () => {
    const cose = coseKeyEs256(unhex(RFC6979.ux), unhex(RFC6979.uy));
    expect(hex(cose)).toBe(`a5010203262001215820${RFC6979.ux}225820${RFC6979.uy}`);
    expect(cose.length).toBe(77);
    expect(COSE_ES256).toBe(-7);
    expect(() => coseKeyEs256(new Uint8Array(31), new Uint8Array(32))).toThrow();
  });

  it('assertion authenticatorData is 37 bytes: hash, flags, big-endian sign count', async () => {
    const h = await sha256(utf8('example.com'));
    const ad = buildAuthData(h, FLAG_UP | FLAG_UV, 0x01020304);
    expect(ad.length).toBe(37);
    expect(hex(ad.slice(0, 32))).toBe(hex(h));
    expect(ad[32]).toBe(0x05);
    expect(hex(ad.slice(33))).toBe('01020304');
  });

  it('registration authenticatorData appends aaguid, id length, id and the COSE key', async () => {
    const h = await sha256(utf8('example.com'));
    const cose = coseKeyEs256(unhex(RFC6979.ux), unhex(RFC6979.uy));
    const id = unhex('00112233445566778899aabbccddeeff');
    const ad = buildAuthData(h, FLAG_UP | FLAG_AT, 0, { aaguid: PASSKEY_PROVIDER_AAGUID, credentialId: id, cosePublicKey: cose });
    expect(ad.length).toBe(37 + 16 + 2 + id.length + cose.length);
    expect(ad[32]).toBe(0x41);
    expect(hex(ad.slice(37, 53))).toBe(PASSKEY_PROVIDER_AAGUID.replace(/-/g, ''));
    expect(hex(ad.slice(53, 55))).toBe('0010');
    expect(hex(ad.slice(55, 71))).toBe(hex(id));
    expect(hex(ad.slice(71))).toBe(hex(cose));
    expect(() => buildAuthData(new Uint8Array(31), 0, 0)).toThrow();
  });

  it('the AAGUID is a valid v4 UUID and matches the Rust shell', () => {
    expect(PASSKEY_PROVIDER_AAGUID).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(uuidBytes(PASSKEY_PROVIDER_AAGUID).length).toBe(16);
    const rust = readFileSync('desktop/src-tauri/src/provider_core.rs', 'utf8');
    expect(rust).toContain(`"${PASSKEY_PROVIDER_AAGUID}"`);
  });
});

describe('ES256 signatures', () => {
  it('DER encoding of the RFC 6979 signature pads both integers (high bit set)', () => {
    const raw = concat(unhex(RFC6979.r), unhex(RFC6979.s));
    const der = rawSignatureToDer(raw);
    expect(hex(der)).toBe(`3046022100${RFC6979.r}022100${RFC6979.s}`);
    expect(hex(derSignatureToRaw(der))).toBe(hex(raw));
  });

  it('DER encoding drops redundant leading zeros and keeps the length right', () => {
    const r = concat(new Uint8Array(30), new Uint8Array([0x01, 0x02]));
    const s = concat(new Uint8Array([0x00, 0x7f]), new Uint8Array(30).fill(9));
    const der = rawSignatureToDer(concat(r, s));
    // r is 0x0102 (2 bytes, high bit clear), s starts 0x007f (one zero dropped, no pad needed).
    expect(hex(der.slice(0, 6))).toBe('302502020102');
    expect(der.length).toBe(2 + der[1]!);
    expect(hex(derSignatureToRaw(der))).toBe(hex(concat(r, s)));
    expect(() => rawSignatureToDer(new Uint8Array(63))).toThrow();
    expect(() => derSignatureToRaw(new Uint8Array([0x30, 0x00]))).toThrow();
  });

  it('verifies the RFC 6979 known-answer signature through the same check a relying party runs', async () => {
    const pub = concat(new Uint8Array([4]), unhex(RFC6979.ux), unhex(RFC6979.uy));
    const der = rawSignatureToDer(concat(unhex(RFC6979.r), unhex(RFC6979.s)));
    // authData || clientDataHash is just the signed message: "sam" + "ple".
    expect(await verifyAssertion(pub, utf8('sam'), utf8('ple'), der)).toBe(true);
    expect(await verifyAssertion(pub, utf8('sam'), utf8('plf'), der)).toBe(false);
  });
});

describe('creating and using a credential', () => {
  const hash = (): Uint8Array => randomBytes(32);

  it('createPasskey returns a vault item and registration data that agree with each other', async () => {
    const made = await createPasskey({ rpId: 'example.com', rpName: 'Example', userHandle: b64url(utf8('user-1')), userName: 'ada', userVerified: true }, 1234);
    const d = made.data;
    expect(d.type).toBe('passkey');
    expect(d).toMatchObject({ rpId: 'example.com', rpName: 'Example', userName: 'ada', signCount: 0, created: 1234, userHandle: b64url(utf8('user-1')) });
    expect(unb64url(d.credentialId).length).toBe(32);
    expect(unb64url(d.passkeyPublicKey).length).toBe(65);
    const ad = made.authData;
    expect(ad[32]).toBe(FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
    expect(hex(ad.slice(33, 37))).toBe('00000000');
    expect(hex(ad.slice(37, 53))).toBe(PASSKEY_PROVIDER_AAGUID.replace(/-/g, ''));
    const idLen = (ad[53]! << 8) | ad[54]!;
    expect(idLen).toBe(32);
    expect(hex(ad.slice(55, 55 + idLen))).toBe(hex(unb64url(d.credentialId)));
    const pub = unb64url(d.passkeyPublicKey);
    expect(hex(ad.slice(55 + idLen))).toBe(hex(coseKeyEs256(pub.slice(1, 33), pub.slice(33))));
    expect(hex(ad.slice(0, 32))).toBe(hex(await sha256(utf8('example.com'))));
  });

  it('flags drop UV when nobody verified', async () => {
    const made = await createPasskey({ rpId: 'example.com', userHandle: b64url(utf8('u')), userName: 'a', userVerified: false });
    expect(made.authData[32]! & FLAG_UV).toBe(0);
  });

  it('refuses a bad rp id or user handle', async () => {
    await expect(createPasskey({ rpId: 'https://example.com', userHandle: 'AA', userName: 'a', userVerified: true })).rejects.toThrow('bad-rp');
    await expect(createPasskey({ rpId: 'example.com', userHandle: '', userName: 'a', userVerified: true })).rejects.toThrow('bad-user');
    expect(['example.com', 'a-b.example.co.uk', 'localhost'].every(validRpId)).toBe(true);
    expect(['', 'Example.com', 'a b.com', 'a.com:8080', 'a/b', '-a.com', 'a..com'].some(validRpId)).toBe(false);
  });

  it('an assertion verifies against the public key, counts up, and binds the client data hash', async () => {
    const made = await createPasskey({ rpId: 'example.com', userHandle: b64url(utf8('u1')), userName: 'ada', userVerified: true });
    const item = made.data;
    const pub = unb64url(item.passkeyPublicKey);
    const h = hash();
    const a1 = await signAssertion(item, h, true);
    expect(a1.signCount).toBe(1);
    expect(a1.authData.length).toBe(37);
    expect(a1.authData[32]).toBe(FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS);
    expect(await verifyAssertion(pub, a1.authData, h, a1.signature)).toBe(true);
    expect(await verifyAssertion(pub, a1.authData, hash(), a1.signature)).toBe(false);
    expect(a1.userHandle).toBe(item.userHandle);
    const a2 = await signAssertion({ ...item, signCount: a1.signCount }, h, true);
    expect(a2.signCount).toBe(2);
    expect(hex(a2.authData.slice(33, 37))).toBe('00000002');
    await expect(signAssertion(item, new Uint8Array(31), true)).rejects.toThrow('bad-hash');
  });
});

/* ───────────── the shell's requests ───────────── */

function item(over: Partial<EntryData> = {}, id = 'p1'): Entry {
  return { ...emptyEntry('passkey', 1), id, ver: 1, title: 'example.com (passkey)', rpId: 'example.com', credentialId: 'Y3JlZDE', userHandle: 'dTE', userName: 'ada', passkeyPrivateKey: 'x', passkeyPublicKey: 'y', signCount: 0, ...over };
}

class Host implements ProviderHost {
  entriesNow: Entry[] = [];
  isUnlocked = true;
  makeAnswer = true;
  getAnswer: string | null | 'first' = 'first';
  saved: Array<{ id: string | null; data: Partial<EntryData> }> = [];
  asked: unknown[] = [];
  unlocked() { return this.isUnlocked; }
  entries() { return this.entriesNow; }
  async saveEntry(id: string | null, data: Partial<EntryData>) {
    this.saved.push({ id, data });
    if (id) this.entriesNow = this.entriesNow.map((e) => (e.id === id ? { ...e, ...data } as Entry : e));
    else this.entriesNow = [...this.entriesNow, { ...emptyEntry('passkey', 1), ...data, id: `new${this.entriesNow.length}`, ver: 1 } as Entry];
  }
  async confirmMake(r: { rpId: string; userName: string }) { this.asked.push(r); return this.makeAnswer; }
  async confirmGet(r: { rpId: string; choices: Array<{ id: string; userName: string }> }) { this.asked.push(r); return this.getAnswer === 'first' ? r.choices[0]!.id : this.getAnswer; }
}

const makeReq = (over: Partial<Extract<ProviderRequest, { op: 'make' }>> = {}): ProviderRequest => ({
  id: 1, op: 'make', rpId: 'example.com', rpName: 'Example', clientDataHash: b64url(new Uint8Array(32).fill(7)), user: { id: b64url(utf8('u1')), name: 'ada' }, excludeCredentialIds: [], requireUv: true, ...over,
});
const getReq = (over: Partial<Extract<ProviderRequest, { op: 'get' }>> = {}): ProviderRequest => ({
  id: 2, op: 'get', rpId: 'example.com', clientDataHash: b64url(new Uint8Array(32).fill(9)), allowCredentialIds: [], requireUv: true, ...over,
});
const code = async (p: Promise<unknown>): Promise<string> => p.then(() => 'ok', (e: unknown) => (e instanceof ProviderFailure ? e.code : 'other'));

describe('handling Windows requests in the webview', () => {
  it('refuses everything while the vault is locked, before asking the person anything', async () => {
    const h = new Host();
    h.isUnlocked = false;
    expect(await code(handleProviderRequest(h, makeReq()))).toBe('locked');
    expect(await code(handleProviderRequest(h, getReq()))).toBe('locked');
    expect(h.asked).toEqual([]);
  });

  it('make: confirms, stores one sealed-able item and returns authenticatorData that holds its key', async () => {
    const h = new Host();
    const r = (await handleProviderRequest(h, makeReq())) as ProviderMakeResult;
    expect(h.asked).toEqual([{ rpId: 'example.com', userName: 'ada' }]);
    expect(h.saved).toHaveLength(1);
    const data = h.saved[0]!.data as EntryData;
    expect(h.saved[0]!.id).toBeNull();
    expect(data.type).toBe('passkey');
    expect(r.credentialId).toBe(data.credentialId);
    const ad = unb64url(r.authData);
    const pub = unb64url(data.passkeyPublicKey!);
    expect(hex(ad.slice(-77))).toBe(hex(coseKeyEs256(pub.slice(1, 33), pub.slice(33))));
  });

  it('make: declined, excluded, and malformed requests store nothing', async () => {
    const h = new Host();
    h.makeAnswer = false;
    expect(await code(handleProviderRequest(h, makeReq()))).toBe('declined');
    h.makeAnswer = true;
    h.entriesNow = [item()];
    expect(await code(handleProviderRequest(h, makeReq({ excludeCredentialIds: ['Y3JlZDE'] })))).toBe('excluded');
    // An excluded id that belongs to another site is not a match.
    h.entriesNow = [item({ rpId: 'other.com' })];
    expect(await code(handleProviderRequest(h, makeReq({ excludeCredentialIds: ['Y3JlZDE'] })))).toBe('ok');
    h.saved = [];
    expect(await code(handleProviderRequest(h, makeReq({ rpId: 'Bad Host' })))).toBe('bad-request');
    expect(await code(handleProviderRequest(h, makeReq({ clientDataHash: 'AAAA' })))).toBe('bad-request');
    expect(await code(handleProviderRequest(h, makeReq({ user: { id: '', name: 'x' } })))).toBe('bad-request');
    expect(h.saved).toEqual([]);
  });

  it('get: signs with the right credential, saves the new counter first, and verifies', async () => {
    const h = new Host();
    await handleProviderRequest(h, makeReq());
    const stored = h.entriesNow[0] as PasskeyEntry;
    const hash = new Uint8Array(32).fill(9);
    const r = (await handleProviderRequest(h, getReq({ allowCredentialIds: [stored.credentialId] }))) as ProviderGetResult;
    expect(h.saved.at(-1)).toEqual({ id: stored.id, data: { signCount: 1 } });
    expect(r.userHandle).toBe(stored.userHandle);
    expect(await verifyAssertion(unb64url(stored.passkeyPublicKey), unb64url(r.authData), hash, unb64url(r.signature))).toBe(true);
    const again = (await handleProviderRequest(h, getReq())) as ProviderGetResult;
    expect(hex(unb64url(again.authData).slice(33, 37))).toBe('00000002');
  });

  it('get: only this site, only the allowed ids, and the person picks among several', async () => {
    const h = new Host();
    h.entriesNow = [item({ credentialId: 'a' }, 'a'), item({ credentialId: 'b', userName: 'bob' }, 'b'), item({ rpId: 'other.com', credentialId: 'c' }, 'c')];
    h.getAnswer = null;
    expect(await code(handleProviderRequest(h, getReq()))).toBe('declined');
    expect(h.asked.at(-1)).toEqual({ rpId: 'example.com', choices: [{ id: 'a', userName: 'ada' }, { id: 'b', userName: 'bob' }] });
    expect(await code(handleProviderRequest(h, getReq({ allowCredentialIds: ['c'] })))).toBe('no-credential');
    expect(await code(handleProviderRequest(h, getReq({ rpId: 'nope.com' })))).toBe('no-credential');
    // An answer that is not one of the offered ids is a decline, never a signature.
    h.getAnswer = 'c';
    expect(await code(handleProviderRequest(h, getReq()))).toBe('declined');
  });

  it('answerRequest turns failures into stable codes and never throws', async () => {
    const h = new Host();
    const store = { unlocked: () => h.isUnlocked, entries: () => h.entriesNow, saveEntry: (i: string | null, d: Partial<Entry>) => h.saveEntry(i, d), onUnlockedChange: () => () => undefined, onEntriesChange: () => () => undefined };
    h.isUnlocked = false;
    expect(await answerRequest(store, makeReq())).toEqual({ ok: false, code: 'locked' });
    h.isUnlocked = true;
    expect(await answerRequest(store, getReq())).toEqual({ ok: false, code: 'no-credential' });
  });
});

describe('the settings section and Windows metadata', () => {
  const sup = (over: Partial<ProviderSupport> = {}): ProviderSupport => ({ compiled: true, os: 'windows', build: 26100, minBuild: 26100, apiPresent: true, packaged: true, registered: null, enabled: null, reason: null, ...over });
  it('is hidden on Linux and on Windows older than the minimum build, and while unknown', () => {
    expect(sectionVisible(sup())).toBe(true);
    expect(sectionVisible(sup({ os: 'linux', build: null }))).toBe(false);
    expect(sectionVisible(sup({ build: 19045 }))).toBe(false);
    expect(sectionVisible(sup({ build: null }))).toBe(false);
    expect(sectionVisible(null)).toBe(false);
  });

  it('credential metadata carries ids and names but never key material', () => {
    const meta = credentialMeta([item(), emptyEntry('login', 1) as unknown as Entry, item({ rpId: undefined as unknown as string }, 'bad')]);
    expect(meta).toEqual([{ credentialId: 'Y3JlZDE', rpId: 'example.com', rpName: 'example.com', userHandle: 'dTE', userName: 'ada', userDisplayName: 'ada' }]);
    expect(JSON.stringify(meta)).not.toMatch(/passkeyPrivateKey|passkeyPublicKey/);
  });
});

/* ───────────── older clients and every other path ignore it ───────────── */

describe('the passkey item kind is invisible to everything that does not know it', () => {
  const kdf = (): KdfParams => ({ alg: 'pbkdf2-sha256', iter: PBKDF2_MIN_ITER, salt: b64(randomBytes(16)) });

  it('rides through a sealed vault untouched, and the vault file still validates', async () => {
    const { file: f0, session } = await V.createVault('correct horse battery', kdf());
    let file = f0;
    let meta = await V.readMeta(file, session);
    const made = await createPasskey({ rpId: 'example.com', userHandle: 'dTE', userName: 'ada', userVerified: true });
    const login: EntryData = { ...emptyEntry('login', 1), title: 'Router', site: 'https://example.com', username: 'ada', password: 'pw' };
    ({ file, meta } = await V.putEntry(file, session, meta, null, made.data));
    ({ file, meta } = await V.putEntry(file, session, meta, null, login));
    expect(() => V.validateFile(JSON.parse(JSON.stringify(file)))).not.toThrow();
    // The private key is inside the sealed record, not beside it.
    expect(JSON.stringify(file)).not.toContain(made.data.passkeyPrivateKey);
    const { entries, warnings } = await V.decryptAll(file, session);
    expect(warnings).toEqual([]);
    const pk = entries.find((e) => e.type === 'passkey')!;
    expect(isPasskeyEntry(pk)).toBe(true);
    expect(pk.passkeyPrivateKey).toBe(made.data.passkeyPrivateKey);
    expect(passkeysForRp(entries, 'example.com')).toHaveLength(1);
    expect(passkeysForRp(entries, 'sub.example.com')).toHaveLength(0);

    // Item list, login matching, auto-type, reuse and counts: none of them sees it.
    expect(filterEntries(entries, { kind: 'all' }, '').map((e) => e.title)).toEqual(['Router']);
    expect(filterEntries(entries, { kind: 'type', type: 'passkey' }, '')).toEqual([]);
    expect(matchLogins(entries, 'https://example.com').map((l) => l.title)).toEqual(['Router']);
    expect(() => fillLogin(entries, 'https://example.com', pk.id)).toThrow('no-match');
    expect(offerFor(entries, { title: 'x', process: 'x.exe', known: false })).toEqual([]);
    expect(reuseGroups(entries).size).toBe(0);
    expect(entrySubtitle(pk)).toBe('ada · example.com');
  });

  it('a client that predates the kind keeps the item as an opaque bag: its own edits spread the fields back', () => {
    const prev = item({ title: 'old name' });
    const edited = applyEdit(prev, { title: 'renamed' }, 9);
    for (const k of ['rpId', 'credentialId', 'userHandle', 'userName', 'passkeyPrivateKey', 'passkeyPublicKey', 'signCount'] as const) expect(edited[k]).toBe(prev[k]);
    // A kind nobody here knows (a future one) is equally inert: nothing selects it, nothing breaks.
    const future = { ...item(), type: 'passkey-v2' as unknown as 'passkey' } as Entry;
    expect(isPasskeyEntry(future)).toBe(false);
    expect(filterEntries([future], { kind: 'type', type: 'login' }, '')).toEqual([]);
    expect(matchLogins([future], 'https://example.com')).toEqual([]);
    expect(passkeysForRp([future], 'example.com')).toEqual([]);
  });

  it('is deleted like any entry, which removes the key', async () => {
    const { file: f0, session } = await V.createVault('correct horse battery', kdf());
    let file = f0;
    let meta = await V.readMeta(file, session);
    const made = await createPasskey({ rpId: 'example.com', userHandle: 'dTE', userName: 'ada', userVerified: true });
    const put = await V.putEntry(file, session, meta, null, made.data);
    ({ file, meta } = await V.removeEntry(put.file, session, put.meta, put.entry.id));
    expect((await V.decryptAll(file, session)).entries).toEqual([]);
  });
});
