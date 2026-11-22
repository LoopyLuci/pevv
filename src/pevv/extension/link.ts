/**
 * The extension's side of the link to the PEVV desktop app (Chrome native messaging).
 *
 * The browser starts `pevv-native-host`, which relays to the running app. After a one-time
 * pairing (the person approves a short fingerprint in the app) both sides hold a 256-bit secret
 * and every message carries a counter and an HMAC-SHA256 over it: the app rejects forged and
 * replayed requests, and this side rejects forged replies. Only the secret and the counter are
 * stored; logins and passwords are never cached here (see worker.ts for how a fill uses them).
 *
 * No chrome.* calls: the port, storage, clock and randomness are injected so the whole flow
 * runs under unit tests with a mocked `connectNative`. Protocol notes: docs/PEVV_EXTENSION.md.
 */

export const HOST_NAME = 'com.luciverse.pevv';
export const LINK_VERSION = 1;
const TAG = 'pevv-nm1';
export const REQUEST_MS = 15_000;
/** The app waits up to 120 s for the person to approve a pairing. */
export const PAIR_MS = 130_000;
/** The port (and with it the host process) is closed after this long without traffic. */
export const IDLE_MS = 30_000;

export interface NativePort {
  postMessage(message: unknown): void;
  disconnect(): void;
  readonly onMessage: { addListener(cb: (message: unknown) => void): void };
  readonly onDisconnect: { addListener(cb: () => void): void };
}

/** What is stored in chrome.storage.local under STORE.link. */
export interface LinkSecret { secret: string; n: number; at: number }

export interface LinkDeps {
  connectNative(name: string): NativePort;
  load(): Promise<LinkSecret | null>;
  save(s: LinkSecret | null): Promise<void>;
  now(): number;
  random(n: number): Uint8Array;
  /** `chrome.runtime.lastError?.message`, read inside the disconnect handler. */
  lastError(): string | undefined;
}

/** `code` is stable: `app-not-running`, `locked`, `host-missing`, `host-forbidden`, `not-paired`, `bad-mac`, `timeout`, … */
export class LinkError extends Error {
  constructor(readonly code: string, message?: string) {
    super(message ?? code);
    this.name = 'LinkError';
  }
}

const enc = new TextEncoder();

export function b64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function unb64(s: string): Uint8Array {
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

const hex = (b: ArrayBuffer | Uint8Array): string => Array.from(new Uint8Array(b as ArrayBuffer), (x) => x.toString(16).padStart(2, '0')).join('');

/** What both sides sign. Must match `mac_input` in desktop/src-tauri/src/link_proto.rs. */
export function macInput(dir: 'ext' | 'app', n: number, kind: string, body: string): string {
  return `${TAG}|${dir}|${n}|${kind.length}:${kind}|${body}`;
}

async function hmac(secret: Uint8Array, text: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', secret as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(text)));
}

export const signMessage = (secret: Uint8Array, dir: 'ext' | 'app', n: number, kind: string, body: string): Promise<string> => hmac(secret, macInput(dir, n, kind, body));

function same(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/** `XXXXX-XXXXX`: what the app shows when it asks to approve this pairing. */
export async function fingerprintOf(secret: Uint8Array): Promise<string> {
  const h = await crypto.subtle.digest('SHA-256', new Uint8Array([...enc.encode(`${TAG}|pair|`), ...secret]));
  const t = hex(new Uint8Array(h).subarray(0, 5)).toUpperCase();
  return `${t.slice(0, 5)}-${t.slice(5)}`;
}

export interface PairingView { fingerprint: string; state: 'waiting' | 'denied' | 'error'; error: string | null }

interface Waiter { resolve(m: unknown): void; reject(e: Error): void; timer: ReturnType<typeof setTimeout> }

export class AppLink {
  private port: NativePort | null = null;
  private waiter: Waiter | null = null;
  private chain: Promise<unknown> = Promise.resolve();
  private requests: Promise<unknown> = Promise.resolve();
  private idle: ReturnType<typeof setTimeout> | null = null;
  private pair: PairingView | null = null;

  constructor(private readonly deps: LinkDeps) {}

  async isPaired(): Promise<boolean> { return !!(await this.deps.load()); }

  pairing(): PairingView | null { return this.pair; }

  /** Forget the secret on this side (the app keeps its half until the person removes it there). */
  async forget(): Promise<void> {
    this.pair = null;
    await this.deps.save(null);
  }

  close(): void {
    if (this.idle) clearTimeout(this.idle);
    this.idle = null;
    const p = this.port;
    this.port = null;
    try { p?.disconnect(); } catch { /* already gone */ }
  }

  private connect(): NativePort {
    if (this.port) return this.port;
    const port = this.deps.connectNative(HOST_NAME);
    this.port = port;
    port.onMessage.addListener((m) => {
      const w = this.waiter;
      if (!w) return; // nothing asked: ignore anything unsolicited
      this.waiter = null;
      clearTimeout(w.timer);
      w.resolve(m);
    });
    port.onDisconnect.addListener(() => {
      const msg = this.deps.lastError() ?? '';
      if (this.port === port) this.port = null;
      const w = this.waiter;
      if (!w) return;
      this.waiter = null;
      clearTimeout(w.timer);
      // Chrome words these; match loosely.
      const code = /not found/i.test(msg) ? 'host-missing' : /forbidden/i.test(msg) ? 'host-forbidden' : 'host-exited';
      w.reject(new LinkError(code, msg || code));
    });
    return port;
  }

  /** One message out, one message in. Serialized, so replies cannot be mixed up. */
  private send(message: unknown, timeoutMs: number): Promise<unknown> {
    const run = (): Promise<unknown> => new Promise((resolve, reject) => {
      if (this.idle) clearTimeout(this.idle);
      let port: NativePort;
      try { port = this.connect(); } catch (e) { reject(new LinkError('host-missing', (e as Error).message)); return; }
      const timer = setTimeout(() => {
        if (this.waiter?.timer === timer) this.waiter = null;
        this.close();
        reject(new LinkError('timeout', 'The PEVV desktop app did not answer.'));
      }, timeoutMs);
      this.waiter = { resolve, reject, timer };
      try { port.postMessage(message); } catch (e) {
        clearTimeout(timer);
        this.waiter = null;
        this.close();
        reject(new LinkError('host-exited', (e as Error).message));
      }
    }).finally(() => {
      if (this.port) this.idle = setTimeout(() => this.close(), IDLE_MS);
    });
    const next = this.chain.then(run, run);
    this.chain = next.catch(() => undefined);
    return next;
  }

  /** Ask the host to start the app (no secret needed). */
  async launch(): Promise<void> {
    const r = await this.send({ v: LINK_VERSION, type: 'launch' }, 15_000) as { type?: string; code?: string; ok?: boolean };
    if (r?.type === 'error') throw new LinkError(r.code ?? 'error');
  }

  /**
   * Start pairing: make a secret, send it with a fingerprint the person compares in the app,
   * and finish in the background. Returns the fingerprint at once for the popup to show.
   */
  async startPair(): Promise<PairingView> {
    if (this.pair?.state === 'waiting') return this.pair;
    const secret = this.deps.random(32);
    const view: PairingView = { fingerprint: await fingerprintOf(secret), state: 'waiting', error: null };
    this.pair = view;
    void (async () => {
      try {
        const r = await this.send({ v: LINK_VERSION, type: 'pair', secret: b64(secret) }, PAIR_MS) as { type?: string; code?: string; mac?: string };
        if (r?.type === 'error') {
          view.state = r.code === 'pair-denied' ? 'denied' : 'error';
          view.error = r.code ?? 'error';
          return;
        }
        // Only the app that was given the secret can sign this.
        if (r?.type !== 'pair-ok' || typeof r.mac !== 'string' || !same(await signMessage(secret, 'app', 0, 'pair-ok', ''), r.mac)) {
          view.state = 'error';
          view.error = 'bad-reply';
          return;
        }
        await this.deps.save({ secret: b64(secret), n: 0, at: this.deps.now() });
        this.pair = null;
      } catch (e) {
        view.state = 'error';
        view.error = e instanceof LinkError ? e.code : (e as Error).message;
      } finally {
        secret.fill(0);
      }
    })();
    return view;
  }

  /**
   * An authenticated request. Resolves with the app's answer (`ok: true` fields); an app-side
   * refusal (`locked`, `no-match`, …) rejects with that code.
   */
  request<T extends Record<string, unknown> = Record<string, unknown>>(kind: string, body: Record<string, unknown> = {}, timeoutMs = REQUEST_MS): Promise<T> {
    // Counter, signature, send and check are one step at a time: two requests must not pick the same
    // counter, nor reach the app in a different order than their counters.
    const run = (): Promise<T> => this.requestNow<T>(kind, body, timeoutMs);
    const next = this.requests.then(run, run);
    this.requests = next.catch(() => undefined);
    return next;
  }

  private async requestNow<T extends Record<string, unknown>>(kind: string, body: Record<string, unknown>, timeoutMs: number): Promise<T> {
    const stored = await this.deps.load();
    if (!stored) throw new LinkError('not-paired', 'Not paired with the desktop app.');
    const secret = unb64(stored.secret);
    // Strictly increasing, and a wall-clock floor so a lost counter cannot fall behind the app's.
    const n = Math.max(stored.n + 1, this.deps.now());
    await this.deps.save({ ...stored, n });
    const text = JSON.stringify(body);
    const reply = await this.send({ v: LINK_VERSION, n, type: kind, body: text, mac: await signMessage(secret, 'ext', n, kind, text) }, timeoutMs) as {
      v?: number; n?: number; type?: string; body?: unknown; mac?: unknown; code?: string;
    };
    if (reply?.type === 'error') {
      // The app does not know this secret any more (or it no longer matches): pairing is over.
      if (reply.code === 'not-paired' || reply.code === 'bad-mac') await this.forget();
      throw new LinkError(reply.code ?? 'error');
    }
    if (reply?.v !== LINK_VERSION || reply.n !== n || reply.type !== kind || typeof reply.body !== 'string' || typeof reply.mac !== 'string'
      || !same(await signMessage(secret, 'app', n, kind, reply.body), reply.mac)) {
      throw new LinkError('bad-reply', 'The desktop app sent a reply that does not check out.');
    }
    const parsed = JSON.parse(reply.body) as { ok?: boolean; error?: string } & T;
    if (!parsed.ok) throw new LinkError(parsed.error ?? 'error');
    return parsed;
  }
}
