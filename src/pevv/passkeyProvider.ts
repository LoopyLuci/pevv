/**
 * PEVV as a passkey provider for other sites (desktop app, Windows 11 plugin authenticator).
 *
 * A passkey PEVV makes for another site is one more vault item, `type: 'passkey'`, sealed like every
 * other entry: the P-256 private key sits inside the encrypted item, next to the rpId, credential id,
 * user handle, user name and sign count. The Rust shell decodes the CTAP request and hands the pieces
 * here; this file does the WebAuthn authenticator work (credential creation, assertion signing) with
 * WebCrypto and returns authenticatorData and a signature. See docs/PEVV_DESKTOP.md.
 *
 * Older clients do not know the kind. The vault entry is one sealed JSON object and they keep fields
 * they do not know, so such an item rides along in their copy untouched; every view and every
 * login/autofill path in this client (and theirs) selects by `type`, so nothing else touches it.
 */
import { type Bytes, b64url, concat, ctEqual, randomBytes, toBytes, unb64url, utf8 } from './bytes';
import type { Entry, EntryData } from './model';
import { emptyEntry } from './model';

/** The authenticator's AAGUID. Fixed: it names "PEVV" to relying parties and must match the Rust shell. */
export const PASSKEY_PROVIDER_AAGUID = '661cf2bd-74e1-42fd-93d3-7e2ed09cf977';

/** The item kind stored in the vault. */
export const PASSKEY_KIND = 'passkey';

/** COSE algorithm id of ES256. */
export const COSE_ES256 = -7;

/** authenticatorData flags (WebAuthn level 3, section 6.1). */
export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
/** Backup eligible and backed up: a PEVV passkey lives in the vault file and goes wherever the vault goes. */
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;

/* ───────────── small encoders ───────────── */

export function uuidBytes(uuid: string): Bytes {
  const hex = uuid.replace(/-/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error('not a UUID');
  const out = new Uint8Array(16) as Bytes;
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function sha256(data: Uint8Array): Promise<Bytes> {
  return toBytes(await crypto.subtle.digest('SHA-256', data as BufferSource));
}

function u32be(n: number): Bytes {
  const b = new Uint8Array(4) as Bytes;
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

/**
 * The COSE_Key of an ES256 public key, in CTAP2 canonical CBOR (RFC 9052):
 * `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`. Fixed shape, so it is written out instead of using a CBOR library.
 */
export function coseKeyEs256(x: Uint8Array, y: Uint8Array): Bytes {
  if (x.length !== 32 || y.length !== 32) throw new Error('P-256 coordinates must be 32 bytes');
  return concat(
    new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), x,
    new Uint8Array([0x22, 0x58, 0x20]), y,
  );
}

/** WebCrypto signs ECDSA as raw r||s; WebAuthn wants the ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`. */
export function rawSignatureToDer(raw: Uint8Array): Bytes {
  if (raw.length !== 64) throw new Error('an ES256 signature is 64 bytes');
  const int = (v: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    const body = v.slice(i);
    return body[0]! & 0x80 ? concat(new Uint8Array([0]), body) : body;
  };
  const r = int(raw.slice(0, 32));
  const s = int(raw.slice(32));
  // Both integers are at most 33 bytes, so every length fits in one byte.
  return concat(new Uint8Array([0x30, 2 + r.length + 2 + s.length, 0x02, r.length]), r, new Uint8Array([0x02, s.length]), s);
}

/** The inverse of `rawSignatureToDer` (used to check signatures in tests and by `verifyAssertion`). */
export function derSignatureToRaw(der: Uint8Array): Bytes {
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2 || der[2] !== 0x02) throw new Error('bad DER signature');
  const rl = der[3]!;
  if (der[4 + rl] !== 0x02) throw new Error('bad DER signature');
  const sl = der[5 + rl]!;
  if (6 + rl + sl !== der.length) throw new Error('bad DER signature');
  const fit = (v: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < v.length && v[i] === 0) i++;
    const body = v.slice(i);
    if (body.length > 32) throw new Error('bad DER signature');
    return concat(new Uint8Array(32 - body.length), body);
  };
  return concat(fit(der.slice(4, 4 + rl)), fit(der.slice(6 + rl)));
}

export interface AttestedCredentialData { aaguid: string; credentialId: Uint8Array; cosePublicKey: Uint8Array }

/** authenticatorData: rpIdHash(32) | flags(1) | signCount(4) | [aaguid(16) | idLen(2) | id | coseKey]. */
export function buildAuthData(rpIdHash: Uint8Array, flags: number, signCount: number, attested?: AttestedCredentialData): Bytes {
  if (rpIdHash.length !== 32) throw new Error('rpIdHash must be 32 bytes');
  const head = concat(rpIdHash, new Uint8Array([flags & 0xff]), u32be(signCount));
  if (!attested) return head;
  if (attested.credentialId.length === 0 || attested.credentialId.length > 1023) throw new Error('bad credential id length');
  const len = new Uint8Array([attested.credentialId.length >> 8, attested.credentialId.length & 0xff]);
  return concat(head, uuidBytes(attested.aaguid), len, attested.credentialId, attested.cosePublicKey);
}

/* ───────────── the vault item ───────────── */

export interface PasskeyFields {
  rpId: string;
  rpName?: string;
  /** base64url */
  credentialId: string;
  /** base64url */
  userHandle: string;
  userName: string;
  userDisplayName?: string;
  /** PKCS#8 private key, base64url. Inside the sealed item; never leaves the vault in the clear. */
  passkeyPrivateKey: string;
  /** base64url of the uncompressed point (65 bytes), kept so the public half needs no key import. */
  passkeyPublicKey: string;
  signCount: number;
}

export type PasskeyEntry = Entry & PasskeyFields & { type: 'passkey' };

export function isPasskeyEntry(e: EntryData): e is EntryData & PasskeyFields & { type: 'passkey' } {
  const p = e as Partial<PasskeyFields>;
  return e.type === PASSKEY_KIND && typeof p.rpId === 'string' && typeof p.credentialId === 'string' && typeof p.passkeyPrivateKey === 'string';
}

/** Passkeys in the list that belong to `rpId` (exactly; a passkey never matches a parent or sibling domain). */
export function passkeysForRp(entries: readonly Entry[], rpId: string): PasskeyEntry[] {
  return entries.filter((e): e is PasskeyEntry => isPasskeyEntry(e) && e.rpId === rpId);
}

/** A relying party id is a registrable-looking host: lowercase labels, no scheme, port, path or spaces. */
export function validRpId(rpId: string): boolean {
  return rpId.length > 0 && rpId.length <= 253 && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(rpId);
}

/* ───────────── operations ───────────── */

export interface MakeRequest {
  rpId: string;
  rpName?: string | undefined;
  /** base64url */
  userHandle: string;
  userName: string;
  userDisplayName?: string | undefined;
  /** Whether the person confirmed (and the vault was unlocked) just now. */
  userVerified: boolean;
}

/** Create the credential: a fresh P-256 key and the vault item holding it. */
export async function createPasskey(req: MakeRequest, now = Date.now()): Promise<{ data: EntryData & PasskeyFields; authData: Bytes; credentialId: string }> {
  if (!validRpId(req.rpId)) throw new Error('bad-rp');
  if (unb64url(req.userHandle).length < 1 || unb64url(req.userHandle).length > 64) throw new Error('bad-user');
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pub = toBytes(await crypto.subtle.exportKey('raw', pair.publicKey));
  const pkcs8 = toBytes(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  // 32 random bytes: unguessable, and says nothing about the key or the vault.
  const credId = randomBytes(32);
  const data: EntryData & PasskeyFields = {
    ...emptyEntry('passkey', now),
    title: `${req.rpId} (passkey)`,
    rpId: req.rpId,
    ...(req.rpName ? { rpName: req.rpName } : {}),
    credentialId: b64url(credId),
    userHandle: req.userHandle,
    userName: req.userName,
    ...(req.userDisplayName ? { userDisplayName: req.userDisplayName } : {}),
    passkeyPrivateKey: b64url(pkcs8),
    passkeyPublicKey: b64url(pub),
    signCount: 0,
  };
  const authData = buildAuthData(
    await sha256(utf8(req.rpId)),
    FLAG_UP | FLAG_BE | FLAG_BS | FLAG_AT | (req.userVerified ? FLAG_UV : 0),
    0,
    { aaguid: PASSKEY_PROVIDER_AAGUID, credentialId: credId, cosePublicKey: coseKeyEs256(pub.slice(1, 33), pub.slice(33, 65)) },
  );
  return { data, authData, credentialId: data.credentialId };
}

export interface Assertion { credentialId: string; authData: Bytes; signature: Bytes; userHandle: string; userName: string; signCount: number }

/** Sign an assertion with a stored passkey. `clientDataHash` is the 32-byte hash the browser built. */
export async function signAssertion(item: PasskeyFields, clientDataHash: Uint8Array, userVerified: boolean): Promise<Assertion> {
  if (clientDataHash.length !== 32) throw new Error('bad-hash');
  const key = await crypto.subtle.importKey('pkcs8', unb64url(item.passkeyPrivateKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const signCount = (item.signCount | 0) + 1;
  const authData = buildAuthData(await sha256(utf8(item.rpId)), FLAG_UP | FLAG_BE | FLAG_BS | (userVerified ? FLAG_UV : 0), signCount);
  const raw = toBytes(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, concat(authData, clientDataHash)));
  return { credentialId: item.credentialId, authData, signature: rawSignatureToDer(raw), userHandle: item.userHandle, userName: item.userName, signCount };
}

/** Check an assertion the way a relying party would (tests, and a self-check the shell can ask for). */
export async function verifyAssertion(publicKeyRaw: Uint8Array, authData: Uint8Array, clientDataHash: Uint8Array, derSignature: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey('raw', publicKeyRaw as BufferSource, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derSignatureToRaw(derSignature) as BufferSource, concat(authData, clientDataHash) as BufferSource);
}

/* ───────────── the shell's requests ───────────── */

/** What the Rust shell sends for one Windows request (all byte strings base64url). */
export type ProviderRequest =
  | { id: number; op: 'make'; rpId: string; rpName?: string; clientDataHash: string; user: { id: string; name: string; displayName?: string }; excludeCredentialIds: string[]; requireUv: boolean }
  | { id: number; op: 'get'; rpId: string; clientDataHash: string; allowCredentialIds: string[]; requireUv: boolean };

/** What the webview hands back: error is one of the stable codes the shell maps to an HRESULT. */
export type ProviderError = 'locked' | 'declined' | 'excluded' | 'no-credential' | 'bad-request' | 'failed';
export class ProviderFailure extends Error {
  constructor(readonly code: ProviderError, message?: string) { super(message ?? code); }
}

export interface ProviderHost {
  unlocked(): boolean;
  entries(): Entry[];
  saveEntry(id: string | null, data: Partial<EntryData>): Promise<unknown>;
  /** Ask the person; resolves with the chosen entry id for `get`, or true/false for `make`. null = declined. */
  confirmMake(req: { rpId: string; userName: string }): Promise<boolean>;
  confirmGet(req: { rpId: string; choices: Array<{ id: string; userName: string }> }): Promise<string | null>;
  audit?(detail: string): void;
}

export interface ProviderMakeResult { credentialId: string; authData: string }
export interface ProviderGetResult { credentialId: string; authData: string; signature: string; userHandle: string; userName: string }

export async function handleProviderRequest(host: ProviderHost, req: ProviderRequest): Promise<ProviderMakeResult | ProviderGetResult> {
  if (!host.unlocked()) throw new ProviderFailure('locked');
  if (!validRpId(req.rpId)) throw new ProviderFailure('bad-request', 'bad rp id');
  const hash = unb64url(req.clientDataHash);
  if (hash.length !== 32) throw new ProviderFailure('bad-request', 'bad client data hash');
  if (req.op === 'make') {
    const mine = passkeysForRp(host.entries(), req.rpId);
    const handle = unb64url(req.user.id);
    if (handle.length < 1 || handle.length > 64) throw new ProviderFailure('bad-request', 'bad user handle');
    // excludeList: a credential PEVV already holds for this site stops a duplicate (WebAuthn: InvalidStateError).
    if (mine.some((p) => req.excludeCredentialIds.includes(p.credentialId))) throw new ProviderFailure('excluded');
    if (!(await host.confirmMake({ rpId: req.rpId, userName: req.user.name }))) throw new ProviderFailure('declined');
    const made = await createPasskey({ rpId: req.rpId, rpName: req.rpName, userHandle: req.user.id, userName: req.user.name, userDisplayName: req.user.displayName, userVerified: true });
    await host.saveEntry(null, made.data);
    host.audit?.(`created a passkey for ${req.rpId}`);
    return { credentialId: made.credentialId, authData: b64url(made.authData) };
  }
  let candidates = passkeysForRp(host.entries(), req.rpId);
  if (req.allowCredentialIds.length) candidates = candidates.filter((p) => req.allowCredentialIds.some((a) => ctEqual(utf8(a), utf8(p.credentialId))));
  if (!candidates.length) throw new ProviderFailure('no-credential');
  const chosen = await host.confirmGet({ rpId: req.rpId, choices: candidates.map((p) => ({ id: p.id, userName: p.userName })) });
  const item = chosen === null ? undefined : candidates.find((p) => p.id === chosen);
  if (!item) throw new ProviderFailure('declined');
  const a = await signAssertion(item, hash, true);
  // Persist the counter before returning the signature: a crash must never reuse a count.
  await host.saveEntry(item.id, { signCount: a.signCount } as Partial<EntryData>);
  host.audit?.(`signed in to ${req.rpId} with a passkey`);
  return { credentialId: a.credentialId, authData: b64url(a.authData), signature: b64url(a.signature), userHandle: a.userHandle, userName: a.userName };
}
