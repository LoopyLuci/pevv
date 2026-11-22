/** Byte helpers for PEVV (no dependencies). */

export type Bytes = Uint8Array<ArrayBuffer>;

export function randomBytes(n: number): Bytes {
  const out = new Uint8Array(new ArrayBuffer(n));
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function b64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

export function unb64(s: string): Bytes {
  const bin = atob(s);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64url(bytes: Uint8Array): string {
  return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64url(s: string): Bytes {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return unb64(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
}

export function toBytes(buf: ArrayBuffer | ArrayBufferView): Bytes {
  // Cross-realm safe (jsdom, workers): check for views first, not `instanceof ArrayBuffer`.
  if (!ArrayBuffer.isView(buf)) return new Uint8Array(new Uint8Array(buf as ArrayBuffer)).slice() as Bytes;
  const v = buf;
  const out = new Uint8Array(new ArrayBuffer(v.byteLength));
  out.set(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
  return out;
}

export function concat(...parts: Uint8Array[]): Bytes {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(new ArrayBuffer(n));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** Constant-time equality for equal-length byte strings. */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** Best-effort wipe of key material held in JS memory. */
export function wipe(b: Uint8Array | null | undefined): void {
  if (b) b.fill(0);
}

const enc = new TextEncoder();
const dec = new TextDecoder();
export const utf8 = (s: string): Bytes => toBytes(enc.encode(s));
export const fromUtf8 = (b: Uint8Array): string => dec.decode(b);

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(input: string): Bytes {
  const s = input.toUpperCase().replace(/[\s=-]/g, '');
  if (!/^[A-Z2-7]*$/.test(s)) throw new Error('invalid base32');
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const c of s) {
    value = (value << 5) | B32.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return toBytes(new Uint8Array(out));
}
