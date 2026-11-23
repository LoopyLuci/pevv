/**
 * Browser lane for a vault move between devices (originally the Transferd lane from the same author).
 *
 * The device showing the QR keeps the ciphertext in memory and hands it to
 * whoever scanned the code. The key stays in the QR and is never sent. No
 * account is required: a separate anonymous socket (its own session, never the
 * sync account) is used only because the relay channels are private
 * (see docs/SYNC_SELF_HOSTING.md for the Realtime policy). Needs
 * VITE_PEVV_SYNC_URL / VITE_PEVV_SYNC_ANON_KEY; without them every call throws
 * 'qr-nosync' and the UI falls back to the offline QR frames and files.
 */
import { createClient, type RealtimeChannel, type SupabaseClient } from '@supabase/supabase-js';
import { b64url, randomBytes } from '../bytes';
import { SYNC_ANON_KEY, SYNC_URL, syncConfigured } from './config';
import { currentAccount, getClient } from './cloud';
export const FRAME = 48_000;

export function newTransferToken(): string {
  return b64url(randomBytes(16));
}

export function relayTopic(token: string): string {
  return `pevv:${token}`;
}

export function splitBody(body: string, frame = FRAME): string[] {
  const out: string[] = [];
  for (let i = 0; i < body.length; i += frame) out.push(body.slice(i, i + frame));
  return out.length ? out : [''];
}

export interface Pulled {
  got: number;
  total: number;
  body: string | null;
}

let relayP: Promise<SupabaseClient | null> | null = null;

function relay(): Promise<SupabaseClient | null> {
  if (!syncConfigured()) return Promise.resolve(null);
  relayP ??= (async () => {
    const client = createClient(SYNC_URL, SYNC_ANON_KEY, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: false, storageKey: 'pevv-relay' },
    });
    const { data } = await client.auth.getSession();
    if (!data.session) {
      const { error } = await client.auth.signInAnonymously();
      if (error) throw new Error(error.message);
    }
    return client;
  })().catch((e) => {
    relayP = null;
    throw e;
  });
  return relayP;
}

/**
 * The live device lane (`pevv:d:<vaultId>`) is limited by the server to sessions that own a synced copy of that vault
 * (supabase/migrations/0002_pevv_hardening.sql), so a signed-in device uses its account session. Without an account it
 * falls back to the anonymous relay session, which works on servers that still run the open lane (`open_roster`).
 */
async function rosterClient(): Promise<SupabaseClient | null> {
  if (currentAccount()) {
    const c = await getClient();
    if (c) return c;
  }
  return relay();
}

function subscribe(ch: RealtimeChannel): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('qr-nosync')), 8000);
    ch.subscribe((status) => {
      if (status === 'SUBSCRIBED') { clearTimeout(t); resolve(); }
      else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') { clearTimeout(t); reject(new Error('qr-nosync')); }
    });
  });
}

interface Sender { ch: RealtimeChannel; timer: ReturnType<typeof setInterval> }
const senders = new Map<string, Sender>();

/** Keep sending until the QR is closed, so a late scan still receives the vault. */
export async function putTransfer(token: string, body: string, onProgress?: (got: number, total: number) => void): Promise<void> {
  const client = await relay();
  if (!client) throw new Error('qr-nosync');
  const parts = splitBody(body);
  const total = parts.length;
  onProgress?.(0, total);
  const ch = client.channel(relayTopic(token), { config: { private: true, broadcast: { self: false, ack: false } } });
  let busy = false;
  const flush = async () => {
    if (busy) return;
    busy = true;
    try {
      for (let seq = 0; seq < total; seq++) {
        const res = await ch.send({ type: 'broadcast', event: 'part', payload: { seq, total, body: parts[seq] } });
        if (res !== 'ok') return;
      }
    } finally { busy = false; }
  };
  ch.on('broadcast', { event: 'want' }, () => { void flush().catch(() => undefined); });
  await subscribe(ch);
  const timer = setInterval(() => { void flush().catch(() => undefined); }, 800);
  senders.set(token, { ch, timer });
  void flush().catch(() => undefined);
  onProgress?.(total, total);
}

interface Inbox { ch: RealtimeChannel; parts: string[]; total: number }
const boxes = new Map<string, Inbox>();

function packed(slot: Inbox): Pulled {
  const total = slot.total;
  const got = slot.parts.filter(Boolean).length;
  if (!total || got < total) return { got, total, body: null };
  const parts = slot.parts.slice(0, total);
  if (parts.some((p) => !p)) return { got, total, body: null };
  return { got, total, body: parts.join('') };
}

async function inboxFor(token: string): Promise<Inbox> {
  const have = boxes.get(token);
  if (have) return have;
  const client = await relay();
  if (!client) throw new Error('qr-nosync');
  const slot: Inbox = { ch: null as unknown as RealtimeChannel, parts: [], total: 0 };
  const ch = client.channel(relayTopic(token), { config: { private: true, broadcast: { self: false, ack: false } } });
  slot.ch = ch;
  ch.on('broadcast', { event: 'part' }, ({ payload }) => {
    const seq = Number(payload?.seq);
    const total = Number(payload?.total);
    const body = typeof payload?.body === 'string' ? payload.body : '';
    if (!Number.isInteger(seq) || seq < 0 || seq > 10000) return;
    if (!Number.isInteger(total) || total < 1 || total > 10000) return;
    if (body.length > FRAME) return;
    slot.total = total;
    slot.parts[seq] = body;
  });
  boxes.set(token, slot);
  try { await subscribe(ch); }
  catch (e) { boxes.delete(token); void ch.unsubscribe(); throw e; }
  return slot;
}

/** Ask the device showing the QR, and keep listening until the vault arrives. */
export async function pullTransfer(token: string, onProgress?: (got: number, total: number) => void): Promise<Pulled> {
  const slot = await inboxFor(token);
  const deadline = Date.now() + 8000;
  let lastWant = 0;
  while (Date.now() < deadline) {
    const now = packed(slot);
    onProgress?.(now.got, now.total);
    if (now.body) return now;
    if (Date.now() - lastWant > 700) {
      lastWant = Date.now();
      void slot.ch.send({ type: 'broadcast', event: 'want', payload: { t: Date.now() } }).catch(() => undefined);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return packed(slot);
}

export async function dropTransfer(token: string): Promise<void> {
  const sent = senders.get(token);
  const box = boxes.get(token);
  senders.delete(token);
  boxes.delete(token);
  if (sent) {
    clearInterval(sent.timer);
    await sent.ch.unsubscribe();
  }
  if (box && box.ch !== sent?.ch) await box.ch.unsubscribe();
}

/** Topic for an already-paired vault. The id is unguessable; the body is the encrypted file. */
export function rosterTopic(vaultId: string): string {
  return `pevv:d:${vaultId}`;
}

const ROSTER_PARTS = 8;

function peekRev(body: string): number {
  const m = /"rev":(\d+)/.exec(body);
  return m ? Number(m[1]) : 0;
}

interface RosterGen { parts: string[]; total: number }

function takePart(incoming: Map<string, RosterGen>, payload: { gen?: unknown; seq?: unknown; total?: unknown; body?: unknown }): string | null {
  const gen = typeof payload?.gen === 'string' ? payload.gen.slice(0, 80) : '';
  const seq = Number(payload?.seq);
  const total = Number(payload?.total);
  const body = typeof payload?.body === 'string' ? payload.body : '';
  if (!gen || !Number.isInteger(seq) || seq < 0 || seq >= ROSTER_PARTS) return null;
  if (!Number.isInteger(total) || total < 1 || total > ROSTER_PARTS) return null;
  if (body.length > FRAME) return null;
  let slot = incoming.get(gen);
  if (!slot) {
    if (incoming.size > 4) incoming.clear();
    slot = { parts: [], total };
    incoming.set(gen, slot);
  }
  slot.total = total;
  slot.parts[seq] = body;
  if (slot.parts.filter(Boolean).length < total) return null;
  const parts = slot.parts.slice(0, total);
  if (parts.some((p) => !p)) return null;
  incoming.delete(gen);
  return parts.join('');
}

export interface RosterLink {
  publish(body: string): void;
  /** Ask whoever is on this vault to send their copy. */
  ask(): void;
  close(): Promise<void>;
}

/**
 * Live copy of one vault between devices that already have it.
 * No account. The key stays on the devices; only ciphertext is sent.
 */
export async function joinRoster(vaultId: string, onFile: (body: string) => void): Promise<RosterLink> {
  if (!/^[0-9a-f-]{8,64}$/i.test(vaultId)) throw new Error('roster-id');
  const client = await rosterClient();
  if (!client) throw new Error('qr-nosync');
  const ch = client.channel(rosterTopic(vaultId), { config: { private: true, broadcast: { self: false, ack: false } } });
  let current = '';
  let gen = '';
  let busy = false;
  let closed = false;
  const incoming = new Map<string, RosterGen>();

  const flush = async () => {
    if (busy || closed || !current) return;
    const parts = splitBody(current);
    if (parts.length > ROSTER_PARTS) return;
    busy = true;
    const mine = gen;
    try {
      for (let seq = 0; seq < parts.length; seq++) {
        if (closed || gen !== mine) return;
        const res = await ch.send({ type: 'broadcast', event: 'rpart', payload: { gen: mine, seq, total: parts.length, body: parts[seq] } });
        if (res !== 'ok') return;
      }
    } finally {
      busy = false;
      if (!closed && gen !== mine) void flush();
    }
  };

  ch.on('broadcast', { event: 'rhave' }, ({ payload }) => {
    const rev = Number(payload?.rev);
    const id = typeof payload?.id === 'string' ? payload.id : '';
    if (id && id !== vaultId) return;
    const localRev = current ? peekRev(current) : -1;
    if (Number.isInteger(rev) && rev > localRev) {
      void ch.send({ type: 'broadcast', event: 'rwant', payload: { rev: localRev } }).catch(() => undefined);
    }
  });
  ch.on('broadcast', { event: 'rwant' }, () => { void flush().catch(() => undefined); });
  ch.on('broadcast', { event: 'rpart' }, ({ payload }) => {
    const body = takePart(incoming, payload ?? {});
    if (body) onFile(body);
  });

  try { await subscribe(ch); }
  catch (e) { void ch.unsubscribe(); throw e; }

  const timer = setInterval(() => {
    if (closed || !current) return;
    void ch.send({ type: 'broadcast', event: 'rhave', payload: { id: vaultId, rev: peekRev(current) } }).catch(() => undefined);
  }, 3000);
  // Ask once on join so a device that opened second still receives the newer copy.
  void ch.send({ type: 'broadcast', event: 'rwant', payload: { rev: -1 } }).catch(() => undefined);

  return {
    publish(body: string) {
      if (closed || !body || body === current || body.length > ROSTER_PARTS * FRAME) return;
      current = body;
      gen = `${peekRev(body)}:${body.length}:${Date.now()}`;
      void ch.send({ type: 'broadcast', event: 'rhave', payload: { id: vaultId, rev: peekRev(body) } }).catch(() => undefined);
      void flush().catch(() => undefined);
    },
    ask() {
      if (closed) return;
      void ch.send({ type: 'broadcast', event: 'rwant', payload: { rev: current ? peekRev(current) : -1 } }).catch(() => undefined);
    },
    async close() {
      closed = true;
      clearInterval(timer);
      await ch.unsubscribe();
    },
  };
}
