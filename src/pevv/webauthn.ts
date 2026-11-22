/**
 * WebAuthn for PEVV — passkeys, platform authenticators and security keys
 * (YubiKey, Titan, SoloKey…). No server: rpId is the current host, challenges
 * are random per ceremony and assertions are verified locally against the
 * public key captured at registration.
 *
 * Two modes per authenticator:
 *  - `prf`: the PRF extension (CTAP2 hmac-secret) returns a 32-byte secret that
 *    is HKDF'd into a KEK wrapping the vault key → the passkey alone unlocks.
 *  - `2fa`: no PRF on this authenticator/browser → it is a second-factor gate
 *    on top of the master password (signature verified locally).
 */
import { type Bytes, b64, b64url, concat, ctEqual, fromUtf8, randomBytes, toBytes, unb64, unb64url, utf8 } from './bytes';
import { sha256 } from './crypto';
import { NativeError, getNative } from './native';

export interface PasskeyRecord {
  id: string; // credential id, base64url
  name: string;
  mode: 'prf' | '2fa';
  /** SPKI public key, base64 (for local assertion checks). */
  publicKey: string | null;
  alg: number; // COSE: -7 ES256, -8 EdDSA, -257 RS256
  transports: string[];
  /** Random PRF input for this credential, base64 (only for prf). */
  prfSalt: string | null;
  created: number;
  lastUsed: number | null;
  signCount: number;
  rpId: string;
}

/**
 * True inside a browser extension page (the PEVV extension's vault screen).
 * There the WebAuthn rpId would be the extension id, so passkeys made on the
 * web app cannot be used and new ones would only work in the extension.
 */
export function inExtensionPage(): boolean {
  return typeof location !== 'undefined' && /^(chrome|moz|safari-web|ms-browser)-extension:$/.test(location.protocol);
}

/**
 * True inside the PEVV desktop app (Tauri). Its origin is `tauri://localhost` or
 * `http://tauri.localhost`, not the web app, so passkeys bound to the
 * site's rpId cannot be used there and new ones would only work in the app.
 */
export function inDesktopApp(): boolean {
  if (typeof window === 'undefined') return false;
  if ('__TAURI_INTERNALS__' in window) return true;
  return typeof location !== 'undefined' && (location.protocol === 'tauri:' || location.hostname === 'tauri.localhost');
}

/** True when the desktop shell can ask the OS or a USB key for the passkey secrets (see src-tauri/src/passkey.rs). */
export function nativePasskeysAvailable(): boolean {
  return inDesktopApp() && !!getNative()?.passkey.support.available;
}

/** Where passkeys cannot be used at all: an extension page, or the desktop app without the native bridge. */
export function passkeysBlocked(): boolean {
  return inExtensionPage() || (inDesktopApp() && !nativePasskeysAvailable());
}

/** Can an existing passkey be asked for an assertion here (browser WebAuthn, or the desktop native bridge)? */
export function webauthnAvailable(): boolean {
  if (typeof window === 'undefined' || inExtensionPage()) return false;
  if (inDesktopApp()) return nativePasskeysAvailable();
  return typeof window.PublicKeyCredential !== 'undefined' && !!navigator.credentials?.create;
}

/** Can a NEW passkey be created here? Not in the desktop app: enrolment stays in the web app, so the rpId is the web app's host. */
export function passkeyEnrolAvailable(): boolean {
  return typeof window !== 'undefined' && !inExtensionPage() && !inDesktopApp() && typeof window.PublicKeyCredential !== 'undefined' && !!navigator.credentials?.create;
}

/** The rpId passkeys are made for: the page's host, or the site's rpId compiled into the desktop app. */
export function currentRpId(): string {
  if (inDesktopApp()) return getNative()?.passkey.support.rpId || location.hostname;
  return location.hostname;
}

/** WebAuthn rejects IP-literal origins ("invalid domain"); passkeys need a host name such as localhost. */
export function rpIdIsIp(host: string = typeof location !== 'undefined' ? location.hostname : ''): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':') || host.startsWith('[');
}

type PrfResults = { enabled?: boolean; results?: { first?: ArrayBuffer | ArrayBufferView } };

function prfOf(cred: PublicKeyCredential): PrfResults | undefined {
  try {
    return (cred.getClientExtensionResults() as { prf?: PrfResults }).prf;
  } catch {
    return undefined;
  }
}

export interface RegisterResult {
  record: PasskeyRecord;
  /** PRF output when the authenticator returned one during create(). */
  prfOutput: Bytes | null;
}

export async function registerPasskey(opts: {
  vaultId: string;
  name: string;
  exclude: string[];
  wantPrf: boolean;
  authenticator?: 'platform' | 'cross-platform';
}): Promise<RegisterResult> {
  if (inDesktopApp()) throw new Error('New passkeys are added in the PEVV web app; the desktop app can use them to unlock.');
  if (!passkeyEnrolAvailable()) throw new Error('WebAuthn is not available in this browser');
  if (rpIdIsIp()) throw new Error(`Passkeys need a domain name, not an IP address. Open ${location.protocol}//localhost${location.port ? ':' + location.port : ''} instead of ${location.host}.`);
  const prfSalt = randomBytes(32);
  const pk: PublicKeyCredentialCreationOptions = {
    rp: { id: currentRpId(), name: 'PEVV' },
    user: { id: randomBytes(16), name: `pevv-${opts.vaultId.slice(0, 8)}`, displayName: `PEVV vault (${opts.name})` },
    challenge: randomBytes(32),
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -8 },
      { type: 'public-key', alg: -257 },
    ],
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
      ...(opts.authenticator ? { authenticatorAttachment: opts.authenticator } : {}),
    },
    excludeCredentials: opts.exclude.map((id) => ({ type: 'public-key' as const, id: unb64url(id) })),
    timeout: 120_000,
    attestation: 'none',
    extensions: (opts.wantPrf ? { prf: { eval: { first: prfSalt } } } : {}) as AuthenticationExtensionsClientInputs,
  };
  const cred = (await navigator.credentials.create({ publicKey: pk })) as PublicKeyCredential | null;
  if (!cred) throw new Error('registration was cancelled');
  const resp = cred.response as AuthenticatorAttestationResponse;
  let spki: string | null = null;
  let alg = -7;
  try {
    const k = resp.getPublicKey?.();
    if (k) spki = b64(new Uint8Array(k));
    alg = resp.getPublicKeyAlgorithm?.() ?? -7;
  } catch { /* older browsers */ }
  const prf = prfOf(cred);
  const prfOutput = prf?.results?.first ? toBytes(prf.results.first) : null;
  const mode: PasskeyRecord['mode'] = opts.wantPrf && (prf?.enabled || prfOutput) ? 'prf' : '2fa';
  let transports: string[] = [];
  try { transports = resp.getTransports?.() ?? []; } catch { /* ignore */ }
  return {
    record: {
      id: b64url(new Uint8Array(cred.rawId)),
      name: opts.name.slice(0, 60) || 'Passkey',
      mode,
      publicKey: spki,
      alg,
      transports,
      prfSalt: mode === 'prf' ? b64(prfSalt) : null,
      created: Date.now(),
      lastUsed: null,
      signCount: 0,
      rpId: currentRpId(),
    },
    prfOutput: mode === 'prf' ? prfOutput : null,
  };
}

export interface AssertionResult {
  credId: string;
  prfOutput: Bytes | null;
  signCount: number;
  verified: boolean;
}

/** One get() ceremony; evaluates PRF for every prf-mode credential offered. */
export async function assertPasskey(records: PasskeyRecord[], opts: { requireUv?: boolean } = {}): Promise<AssertionResult> {
  if (!webauthnAvailable()) throw new Error(inDesktopApp() ? getNative()?.passkey.support.reason ?? 'Passkeys are not available in this app.' : 'WebAuthn is not available in this browser');
  if (!records.length) throw new Error('no passkeys registered');
  if (inDesktopApp()) return assertNative(records, opts);
  if (rpIdIsIp()) throw new Error(`Passkeys need a domain name, not an IP address. Open ${location.protocol}//localhost${location.port ? ':' + location.port : ''} instead of ${location.host}.`);
  const challenge = randomBytes(32);
  const evalByCredential: Record<string, { first: Bytes }> = {};
  for (const r of records) if (r.mode === 'prf' && r.prfSalt) evalByCredential[r.id] = { first: unb64(r.prfSalt) };
  const pk: PublicKeyCredentialRequestOptions = {
    challenge,
    rpId: currentRpId(),
    allowCredentials: records.map((r) => ({ type: 'public-key' as const, id: unb64url(r.id), ...(r.transports.length ? { transports: r.transports as AuthenticatorTransport[] } : {}) })),
    userVerification: opts.requireUv ? 'required' : 'preferred',
    timeout: 120_000,
    extensions: (Object.keys(evalByCredential).length ? { prf: { evalByCredential } } : {}) as AuthenticationExtensionsClientInputs,
  };
  const cred = (await navigator.credentials.get({ publicKey: pk })) as PublicKeyCredential | null;
  if (!cred) throw new Error('cancelled');
  const credId = b64url(new Uint8Array(cred.rawId));
  const rec = records.find((r) => r.id === credId);
  if (!rec) throw new Error('unknown authenticator');
  const resp = cred.response as AuthenticatorAssertionResponse;
  const authData = toBytes(resp.authenticatorData);
  const clientData = toBytes(resp.clientDataJSON);
  const sig = toBytes(resp.signature);
  let verified = false;
  let signCount = rec.signCount;
  if (rec.publicKey) {
    const v = await verifyAssertion({
      spki: unb64(rec.publicKey), alg: rec.alg, authData, clientDataJSON: clientData, signature: sig,
      challenge, origin: location.origin, rpId: rec.rpId, prevSignCount: rec.signCount, requireUv: !!opts.requireUv,
    });
    verified = true;
    signCount = v.signCount;
  } else {
    // No public key captured (very old browser) — still check challenge/origin/rpId binding.
    checkClientData(clientData, challenge, location.origin);
    await checkAuthData(authData, rec.rpId, !!opts.requireUv);
  }
  const prf = prfOf(cred);
  const out = prf?.results?.first ? toBytes(prf.results.first) : null;
  return { credId, prfOutput: rec.mode === 'prf' ? out : null, signCount, verified };
}

/**
 * The desktop path: the shell asks Windows or the USB key (same rpId, same PRF salts as the site),
 * the page verifies the signature locally exactly like the browser path, against the site's origin.
 */
async function assertNative(records: PasskeyRecord[], opts: { requireUv?: boolean }): Promise<AssertionResult> {
  const native = getNative()!;
  const rpId = native.passkey.support.rpId;
  const mine = records.filter((r) => !r.rpId || r.rpId === rpId);
  if (!mine.length) throw new Error('None of these passkeys belong to the PEVV web app, so the desktop app cannot use them.');
  const challenge = randomBytes(32);
  const credentials = mine.map((r) => ({ id: r.id, ...(r.mode === 'prf' && r.prfSalt ? { salt1: b64url(unb64(r.prfSalt)) } : {}) }));
  let pin: string | undefined;
  let res;
  for (let attempt = 0; ; attempt++) {
    try {
      res = await native.passkey.prf({ credentials, challenge: b64url(challenge), requireUv: !!opts.requireUv, ...(pin ? { pin } : {}) });
      break;
    } catch (e) {
      const code = e instanceof NativeError ? e.code : '';
      if ((code === 'pin-required' || code === 'pin-invalid') && attempt < 3) {
        const p = await native.passkey.askPin(code === 'pin-invalid');
        if (!p) throw new Error('cancelled');
        pin = p;
        continue;
      }
      throw e instanceof Error ? e : new Error(String(e));
    }
  }
  const rec = mine.find((r) => r.id === res.credentialId);
  if (!rec) throw new Error('unknown authenticator');
  const authData = unb64url(res.authenticatorData);
  const clientData = utf8(res.clientDataJson);
  const origin = `https://${rpId}`;
  let verified = false;
  let signCount = rec.signCount;
  if (rec.publicKey) {
    const v = await verifyAssertion({
      spki: unb64(rec.publicKey), alg: rec.alg, authData, clientDataJSON: clientData, signature: unb64url(res.signature),
      challenge, origin, rpId: rec.rpId || rpId, prevSignCount: rec.signCount, requireUv: !!opts.requireUv,
    });
    verified = true;
    signCount = v.signCount;
  } else {
    checkClientData(clientData, challenge, origin);
    await checkAuthData(authData, rec.rpId || rpId, !!opts.requireUv);
  }
  const prfOutput = rec.mode === 'prf' && res.prf1 ? unb64url(res.prf1) : null;
  return { credId: rec.id, prfOutput, signCount, verified };
}

function checkClientData(clientDataJSON: Uint8Array, challenge: Uint8Array, origin: string): void {
  const cd = JSON.parse(fromUtf8(clientDataJSON)) as { type?: string; challenge?: string; origin?: string; crossOrigin?: boolean };
  if (cd.type !== 'webauthn.get') throw new Error('assertion: wrong type');
  if (cd.challenge !== b64url(challenge)) throw new Error('assertion: challenge mismatch');
  if (cd.origin !== origin) throw new Error('assertion: origin mismatch');
  if (cd.crossOrigin) throw new Error('assertion: cross-origin not allowed');
}

async function checkAuthData(authData: Uint8Array, rpId: string, requireUv: boolean): Promise<number> {
  if (authData.length < 37) throw new Error('assertion: short authenticator data');
  const rpHash = await sha256(utf8(rpId));
  if (!ctEqual(authData.slice(0, 32), rpHash)) throw new Error('assertion: rpId mismatch');
  const flags = authData[32]!;
  if (!(flags & 0x01)) throw new Error('assertion: user not present');
  if (requireUv && !(flags & 0x04)) throw new Error('assertion: user not verified');
  return ((authData[33]! << 24) >>> 0) + (authData[34]! << 16) + (authData[35]! << 8) + authData[36]!;
}

/** DER ECDSA signature → raw r‖s (WebCrypto format). */
export function derToRaw(der: Uint8Array, size = 32): Bytes {
  let i = 0;
  if (der[i++] !== 0x30) throw new Error('bad DER');
  let len = der[i++]!;
  if (len & 0x80) i += len & 0x7f;
  const read = (): Uint8Array => {
    if (der[i++] !== 0x02) throw new Error('bad DER int');
    len = der[i++]!;
    let v = der.slice(i, i + len);
    i += len;
    while (v.length > size && v[0] === 0) v = v.slice(1);
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
  };
  return concat(read(), read());
}

export async function verifyAssertion(a: {
  spki: Uint8Array;
  alg: number;
  authData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
  challenge: Uint8Array;
  origin: string;
  rpId: string;
  prevSignCount: number;
  requireUv?: boolean;
}): Promise<{ signCount: number }> {
  checkClientData(a.clientDataJSON, a.challenge, a.origin);
  const signCount = await checkAuthData(a.authData, a.rpId, !!a.requireUv);
  if (signCount !== 0 && a.prevSignCount !== 0 && signCount <= a.prevSignCount) throw new Error('assertion: signature counter went backwards (cloned key?)');
  const signed = concat(a.authData, await sha256(a.clientDataJSON));
  let ok = false;
  const spki = toBytes(a.spki);
  if (a.alg === -7) {
    const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRaw(a.signature), signed);
  } else if (a.alg === -257) {
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, toBytes(a.signature), signed);
  } else if (a.alg === -8) {
    const key = await crypto.subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
    ok = await crypto.subtle.verify('Ed25519', key, toBytes(a.signature), signed);
  } else {
    throw new Error(`unsupported algorithm ${a.alg}`);
  }
  if (!ok) throw new Error('assertion: bad signature');
  return { signCount };
}
