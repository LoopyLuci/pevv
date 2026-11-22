/**
 * Move a locked PEVV vault to another device with a QR code.
 *
 * Two carriers, same rule: the master password is checked on the device that
 * already has the vault, and it is never placed in the code.
 *
 * - Handoff (one small code): the vault file is sealed with a random AES-256-GCM
 *   key. Ciphertext is written into the account's cloud save. The QR holds only
 *   that key, in the URL hash, so a server never sees it. Expires in 3 minutes.
 * - Offline codes: the vault file itself (already encrypted) is gzipped, split
 *   and shown as one or more codes. The other device scans them in the app.
 *   No account and no network. Useless without the master password.
 */
import { PUBLIC_URL } from './host/config';
import { b64, b64url, randomBytes, unb64, unb64url } from './bytes';
import type { VaultFile } from './model';
import { validateFile } from './vault';

export const HANDOFF_TTL_MS = 3 * 60 * 1000;
/** How long a shown cloud QR keeps its upload. Matches the seal used for a transfer. */
export const QR_HOLD_MS = 10 * 60 * 1000;
export const HANDOFF_PATH = '/vault/pevv-handoff.json';
/** Bytes of base64url per offline code. Stays in a version the phone can read. */
const CHUNK = 520;
const MAX_FRAMES = 12;

export interface HandoffEnvelope {
  v: 1;
  exp: number;
  iv: string;
  ct: string;
}

export async function sealHandoff(json: string, now = Date.now(), ttl = HANDOFF_TTL_MS): Promise<{ key: string; envelope: HandoffEnvelope }> {
  const raw = randomBytes(32);
  const iv = randomBytes(12);
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(json)));
  return { key: b64url(raw), envelope: { v: 1, exp: now + ttl, iv: b64(iv), ct: b64(ct) } };
}

export async function openHandoff(envelope: HandoffEnvelope, keyB64: string, now = Date.now()): Promise<string> {
  if (!envelope || envelope.v !== 1 || typeof envelope.exp !== 'number' || now > envelope.exp) throw new Error('qr-expired');
  try {
    const key = await crypto.subtle.importKey('raw', unb64url(keyB64), 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(envelope.iv) }, key, unb64(envelope.ct));
    return new TextDecoder().decode(pt);
  } catch (e) {
    if ((e as Error).message === 'qr-expired') throw e;
    throw new Error('qr-damaged');
  }
}

async function pipe(data: Uint8Array, stream: CompressionStream | DecompressionStream): Promise<Uint8Array> {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(copy);
      controller.close();
    },
  });
  const reader = source.pipeThrough(stream as unknown as ReadableWritablePair<Uint8Array, Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) { chunks.push(value); n += value.byteLength; }
  }
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.byteLength; }
  return out;
}

async function sha8(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', copy));
  return [...digest.subarray(0, 4)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function packVault(file: VaultFile): Promise<string[]> {
  validateFile(file);
  const gz = await pipe(new TextEncoder().encode(JSON.stringify(file)), new CompressionStream('gzip'));
  const data = b64url(gz);
  const crc = await sha8(gz);
  const n = Math.max(1, Math.ceil(data.length / CHUNK));
  if (n > MAX_FRAMES) throw new Error('qr-too-big');
  const frames: string[] = [];
  for (let i = 0; i < n; i++) frames.push(`PEVV1|${i}|${n}|${crc}|${data.slice(i * CHUNK, (i + 1) * CHUNK)}`);
  return frames;
}

const FRAME = /^PEVV1\|(\d+)\|(\d+)\|([0-9a-f]{8})\|([A-Za-z0-9_-]*)$/;

export function parseFrame(text: string): { i: number; n: number; crc: string; chunk: string } | null {
  const m = FRAME.exec(text.trim());
  if (!m) return null;
  const i = Number(m[1]);
  const n = Number(m[2]);
  if (!Number.isInteger(i) || !Number.isInteger(n) || n < 1 || n > MAX_FRAMES || i < 0 || i >= n) return null;
  return { i, n, crc: m[3]!, chunk: m[4]! };
}

export async function unpackFrames(frames: string[]): Promise<VaultFile> {
  const parts = new Map<number, { i: number; n: number; crc: string; chunk: string }>();
  for (const raw of frames) {
    const p = parseFrame(raw);
    if (!p) throw new Error('qr-damaged');
    parts.set(p.i, p);
  }
  const first = [...parts.values()][0];
  if (!first || parts.size !== first.n) throw new Error('qr-incomplete');
  let data = '';
  for (let i = 0; i < first.n; i++) {
    const p = parts.get(i);
    if (!p || p.n !== first.n || p.crc !== first.crc) throw new Error('qr-damaged');
    data += p.chunk;
  }
  const gz = unb64url(data);
  if (await sha8(gz) !== first.crc) throw new Error('qr-damaged');
  let file: unknown;
  try { file = JSON.parse(new TextDecoder().decode(await pipe(gz, new DecompressionStream('gzip')))); }
  catch { throw new Error('qr-damaged'); }
  validateFile(file);
  return file;
}

export type ScanHit = { kind: 'handoff'; key: string; xfer?: string } | { kind: 'frame'; frame: string };

/** Accept a raw code or a PEVV web-app URL whose query or hash carries `pevvq=…`. */
export function parseScan(text: string): ScanHit | null {
  let token = text.trim();
  const at = token.indexOf('pevvq=');
  if (at >= 0) {
    token = token.slice(at + 6).split('&')[0]!.split('#')[0]!;
    try { token = decodeURIComponent(token); } catch { /* keep the raw token */ }
  }
  if (token.startsWith('H.')) {
    const rest = token.slice(2);
    const dot = rest.indexOf('.');
    const key = dot < 0 ? rest : rest.slice(0, dot);
    const xfer = dot < 0 ? '' : rest.slice(dot + 1);
    if (!/^[A-Za-z0-9_-]{20,}$/.test(key)) return null;
    if (xfer && !/^[A-Za-z0-9_-]{16,80}$/.test(xfer)) return null;
    return xfer ? { kind: 'handoff', key, xfer } : { kind: 'handoff', key };
  }
  if (parseFrame(token)) return { kind: 'frame', frame: token };
  return null;
}

/** Where another phone can open a vault QR when this page cannot be opened from another device. Empty when the build has none (VITE_PEVV_PUBLIC_URL). */
const PUBLIC_SITE = PUBLIC_URL;

/** A link the other phone can open. The token is in the query as well as the hash: Android drops #fragments from a scanned link, and the hash alone never starts the transfer. */
export function shareUrl(token: string, base?: string): string {
  let root = base;
  if (!root && typeof location !== 'undefined') {
    const host = location.hostname;
    // The Android app, a dev server, a file, or the browser extension: another phone cannot open these, so link the public site (if the build has one).
    const embedded = host === 'appassets.androidplatform.net' || host === 'localhost' || host === '127.0.0.1' || host === 'tauri.localhost'
      || ['file:', 'tauri:', 'chrome-extension:', 'moz-extension:'].includes(location.protocol);
    root = embedded ? PUBLIC_SITE : `${location.origin}${location.pathname}`;
  }
  // No page another device can open: the QR carries the bare code, which PEVV's own scanner accepts.
  if (!root) return token;
  const hashAt = root.indexOf('#');
  const noHash = hashAt >= 0 ? root.slice(0, hashAt) : root;
  const q = `pevvq=${encodeURIComponent(token)}`;
  return `${noHash}${noHash.includes('?') ? '&' : '?'}${q}#${q}`;
}

export function readHashToken(href: string): string | null {
  const hit = parseScan(href);
  if (!hit) return null;
  return hit.kind === 'handoff' ? (hit.xfer ? `H.${hit.key}.${hit.xfer}` : `H.${hit.key}`) : hit.frame;
}

export function stripHashToken(): void {
  if (typeof location === 'undefined' || typeof history === 'undefined') return;
  if (!location.href.includes('pevvq=')) return;
  const url = new URL(location.href);
  url.searchParams.delete('pevvq');
  if (url.hash.includes('pevvq=')) url.hash = '';
  history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
}
