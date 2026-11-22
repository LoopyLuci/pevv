import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AppLink, IDLE_MS, LinkError, b64, fingerprintOf, macInput, signMessage, unb64, type LinkDeps, type LinkSecret, type NativePort,
} from '@/pevv/extension/link';
import { answer, fillLogin, matchLogins, planOffer, queueOffer, useLinkUi, type LinkStoreApi } from '@/pevv/desktop/link';
import type { Entry } from '@/pevv/model';
import { firefoxManifest, type ExtManifest } from '../../scripts/extension-package.mjs';

/** The app's side of the protocol in miniature (mirrors desktop/src-tauri/src/link_core.rs). */
class FakeApp {
  secret: Uint8Array | null = null;
  lastN = 0;
  approve = true;
  locked = false;
  seen: Array<{ type: string; body: Record<string, unknown> }> = [];
  corruptReply: ((m: Record<string, unknown>) => Record<string, unknown>) | null = null;
  errorCode: string | null = null;

  async handle(msg: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (this.errorCode) return { v: 1, type: 'error', code: this.errorCode };
    if (msg.type === 'launch') return { v: 1, type: 'launch', ok: true };
    if (msg.type === 'pair') {
      if (!this.approve) return { v: 1, type: 'error', code: 'pair-denied' };
      this.secret = unb64(msg.secret as string);
      this.lastN = 0;
      return { v: 1, type: 'pair-ok', mac: await signMessage(this.secret, 'app', 0, 'pair-ok', '') };
    }
    const n = msg.n as number;
    const kind = msg.type as string;
    const body = msg.body as string;
    if (!this.secret) return { v: 1, type: 'error', code: 'not-paired' };
    if ((await signMessage(this.secret, 'ext', n, kind, body)) !== msg.mac) return { v: 1, type: 'error', code: 'bad-mac' };
    if (n <= this.lastN) return { v: 1, type: 'error', code: 'replay' };
    this.lastN = n;
    const parsed = JSON.parse(body) as Record<string, unknown>;
    this.seen.push({ type: kind, body: parsed });
    let result: Record<string, unknown>;
    if (kind === 'status') result = { ok: true, locked: this.locked };
    else if (this.locked && (kind === 'match' || kind === 'fill')) result = { ok: false, error: 'locked' };
    else if (kind === 'fill') result = { ok: true, username: 'ada', password: 'pw-secret' };
    else result = { ok: true };
    const replyBody = JSON.stringify(result);
    const reply = { v: 1, n, type: kind, body: replyBody, mac: await signMessage(this.secret, 'app', n, kind, replyBody) };
    return this.corruptReply ? this.corruptReply(reply) : reply;
  }
}

function setup(opts: { connectError?: string } = {}) {
  const app = new FakeApp();
  let stored: LinkSecret | null = null;
  const saves: Array<LinkSecret | null> = [];
  let clock = 1_000_000;
  let lastError: string | undefined;
  const ports: Array<{ port: NativePort; closed: boolean; sent: unknown[] }> = [];
  const deps: LinkDeps = {
    connectNative: () => {
      const msgL: Array<(m: unknown) => void> = [];
      const disL: Array<() => void> = [];
      const rec = { closed: false, sent: [] as unknown[], port: null as unknown as NativePort };
      rec.port = {
        postMessage: (m) => {
          rec.sent.push(m);
          if (opts.connectError) { lastError = opts.connectError; queueMicrotask(() => disL.forEach((f) => f())); return; }
          void app.handle(m as Record<string, unknown>).then((r) => msgL.forEach((f) => f(r)));
        },
        disconnect: () => { rec.closed = true; },
        onMessage: { addListener: (cb) => msgL.push(cb) },
        onDisconnect: { addListener: (cb) => disL.push(cb) },
      };
      ports.push(rec);
      return rec.port;
    },
    load: async () => stored,
    save: async (v) => { stored = v; saves.push(v); },
    now: () => clock,
    random: (n) => new Uint8Array(n).fill(7),
    lastError: () => lastError,
  };
  const link = new AppLink(deps);
  return { app, link, ports, saves, tick: (ms: number) => { clock += ms; }, get stored() { return stored; }, setStored: (s: LinkSecret | null) => { stored = s; } };
}

async function paired() {
  const t = setup();
  const v = await t.link.startPair();
  expect(v.state).toBe('waiting');
  await vi.waitFor(() => expect(t.stored).not.toBeNull());
  return t;
}

describe('cross-implementation vectors (same values asserted in link_proto.rs)', () => {
  const secret = new Uint8Array(32).fill(9);
  const body = '{"origin":"https://a.test"}';

  it('signs requests and replies the way the app does', async () => {
    expect(macInput('ext', 5, 'match', body)).toBe(`pevv-nm1|ext|5|5:match|${body}`);
    expect(await signMessage(secret, 'ext', 5, 'match', body)).toBe('1bac7ce604724d707159559384566f55f3352faa0cdcc99e344193dab97341b7');
    expect(await signMessage(secret, 'app', 5, 'match', body)).toBe('305759b490a220bee736ae1cd1337c8465b9835300362f2b6480262a074263cd');
  });

  it('shows the same pairing fingerprint as the app', async () => {
    expect(await fingerprintOf(new Uint8Array(32).fill(1))).toBe('9D7A8-1A787');
  });
});

describe('AppLink pairing', () => {
  it('pairs: fingerprint first, secret stored only after the app proves it got it', async () => {
    const t = setup();
    const v = await t.link.startPair();
    expect(v.fingerprint).toBe(await fingerprintOf(new Uint8Array(32).fill(7)));
    expect(t.stored).toBeNull();
    await vi.waitFor(() => expect(t.stored).not.toBeNull());
    expect(unb64(t.stored!.secret)).toEqual(new Uint8Array(32).fill(7));
    expect(t.stored!.n).toBe(0);
    expect(t.link.pairing()).toBeNull();
    expect(await t.link.isPaired()).toBe(true);
    // The secret never appears in what was sent after the pair message.
    const sentAfter = JSON.stringify(t.ports[0]!.sent.slice(1));
    expect(sentAfter).not.toContain(t.stored!.secret);
  });

  it('a declined pairing stores nothing and says so', async () => {
    const t = setup();
    t.app.approve = false;
    await t.link.startPair();
    await vi.waitFor(() => expect(t.link.pairing()?.state).toBe('denied'));
    expect(t.stored).toBeNull();
  });

  it('refuses a pair-ok that was not signed with the secret', async () => {
    const t = setup();
    t.app.corruptReply = null;
    const real = t.app.handle.bind(t.app);
    t.app.handle = async (m) => { const r = await real(m); return m.type === 'pair' ? { ...r, mac: '00'.repeat(32) } : r; };
    await t.link.startPair();
    await vi.waitFor(() => expect(t.link.pairing()?.state).toBe('error'));
    expect(t.link.pairing()?.error).toBe('bad-reply');
    expect(t.stored).toBeNull();
  });

  it('reports a missing host', async () => {
    const t = setup({ connectError: 'Specified native messaging host not found.' });
    await t.link.startPair();
    await vi.waitFor(() => expect(t.link.pairing()?.error).toBe('host-missing'));
  });
});

describe('AppLink requests', () => {
  beforeEach(() => { vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] }); });
  afterEach(() => { vi.useRealTimers(); });

  it('sends signed, increasing counters and verifies the signed reply', async () => {
    const t = await paired();
    const r = await t.link.request<{ locked: boolean }>('status');
    expect(r.locked).toBe(false);
    await t.link.request('status');
    expect(t.app.seen.map((s) => s.type)).toEqual(['status', 'status']);
    const sent = t.ports[0]!.sent.slice(1) as Array<{ n: number }>;
    expect(sent[1]!.n).toBeGreaterThan(sent[0]!.n);
    // The counter was stored before the second message went out.
    expect(t.saves.filter(Boolean).at(-1)!.n).toBe(sent[1]!.n);
  });

  it('keeps counters ahead of the wall clock floor and of the stored value', async () => {
    const t = await paired();
    t.setStored({ ...t.stored!, n: 5_000_000 });
    t.app.lastN = 0;
    await t.link.request('status');
    expect((t.ports[0]!.sent.at(-1) as { n: number }).n).toBe(5_000_001);
  });

  it('rejects a reply with a bad MAC, wrong counter, wrong type or tampered body', async () => {
    const t = await paired();
    for (const corrupt of [
      (m: Record<string, unknown>) => ({ ...m, mac: '0'.repeat(64) }),
      (m: Record<string, unknown>) => ({ ...m, n: (m.n as number) + 1 }),
      (m: Record<string, unknown>) => ({ ...m, type: 'lock' }),
      (m: Record<string, unknown>) => ({ ...m, body: '{"ok":true,"locked":false,"x":1}' }),
    ]) {
      t.app.corruptReply = corrupt;
      await expect(t.link.request('status')).rejects.toMatchObject({ code: 'bad-reply' });
    }
    t.app.corruptReply = null;
    await expect(t.link.request('status')).resolves.toMatchObject({ ok: true });
  });

  it('does not accept a request-signed reply (direction is part of the MAC)', async () => {
    const t = await paired();
    t.app.corruptReply = (m) => ({ ...m, mac: 'x' });
    const orig = t.app.handle.bind(t.app);
    t.app.handle = async (msg) => {
      const r = await orig(msg);
      if (!r.body) return r;
      return { ...r, mac: await signMessage(t.app.secret!, 'ext', r.n as number, r.type as string, r.body as string) };
    };
    t.app.corruptReply = null;
    await expect(t.link.request('status')).rejects.toMatchObject({ code: 'bad-reply' });
  });

  it('turns app refusals into LinkError codes and forgets a dead pairing', async () => {
    const t = await paired();
    t.app.locked = true;
    await expect(t.link.request('match', { origin: 'https://a.test' })).rejects.toMatchObject({ code: 'locked' });
    expect(await t.link.isPaired()).toBe(true);
    t.app.errorCode = 'not-paired';
    await expect(t.link.request('status')).rejects.toBeInstanceOf(LinkError);
    expect(await t.link.isPaired()).toBe(false);
    await expect(t.link.request('status')).rejects.toMatchObject({ code: 'not-paired' });
  });

  it('reports app-not-running from the host without touching the pairing', async () => {
    const t = await paired();
    t.app.errorCode = 'app-not-running';
    await expect(t.link.request('status')).rejects.toMatchObject({ code: 'app-not-running' });
    expect(await t.link.isPaired()).toBe(true);
  });

  it('maps browser disconnect messages', async () => {
    const t = setup({ connectError: 'Access to the specified native messaging host is forbidden.' });
    t.setStored({ secret: b64(new Uint8Array(32).fill(1)), n: 0, at: 1 });
    await expect(t.link.request('status')).rejects.toMatchObject({ code: 'host-forbidden' });
    const u = setup({ connectError: 'Native host has exited.' });
    u.setStored({ secret: b64(new Uint8Array(32).fill(1)), n: 0, at: 1 });
    await expect(u.link.request('status')).rejects.toMatchObject({ code: 'host-exited' });
  });

  it('times out when nothing answers, and answers one request at a time', async () => {
    const t = await paired();
    const orig = t.app.handle.bind(t.app);
    let hold = true;
    t.app.handle = async (m) => (hold ? new Promise<Record<string, unknown>>(() => undefined) : orig(m));
    const sentBefore = t.ports.flatMap((p2) => p2.sent).length;
    const p = t.link.request('status', {}, 1000);
    const rejected = expect(p).rejects.toMatchObject({ code: 'timeout' });
    // Signing is real async work: wait until the message is out (its timer exists) before moving the clock.
    for (let i = 0; i < 500 && t.ports.flatMap((p2) => p2.sent).length === sentBefore; i++) await new Promise((r) => setImmediate(r));
    await vi.advanceTimersByTimeAsync(1001);
    await rejected;
    hold = false;
    // Two at once: the second is not posted until the first is answered.
    const before = t.ports.flatMap((p2) => p2.sent).length;
    const a = t.link.request('status');
    const b = t.link.request('status');
    await Promise.all([a, b]);
    expect(t.ports.flatMap((p2) => p2.sent).length - before).toBe(2);
    expect(t.app.seen.length).toBe(2);
  });

  it('closes the port after the idle time so the host process can exit', async () => {
    const t = await paired();
    await t.link.request('status');
    const port = t.ports.at(-1)!;
    expect(port.closed).toBe(false);
    await vi.advanceTimersByTimeAsync(IDLE_MS + 1);
    expect(port.closed).toBe(true);
    await t.link.request('status');
    expect(t.ports.length).toBeGreaterThan(1);
  });

  it('can ask the host to launch the app', async () => {
    const t = setup();
    await t.link.launch();
    expect(t.ports[0]!.sent[0]).toEqual({ v: 1, type: 'launch' });
    t.app.errorCode = 'app-not-running';
    await expect(t.link.launch()).rejects.toMatchObject({ code: 'app-not-running' });
  });
});

describe('extension package and ids', () => {
  const manifest = JSON.parse(readFileSync('extension/manifest.json', 'utf8')) as ExtManifest & { key: string; permissions: string[]; optional_permissions: string[] };
  const ids = (JSON.parse(readFileSync('desktop/src-tauri/extension-ids.json', 'utf8')) as { ids: string[] }).ids;

  it('derives the extension id from the pinned key and lists it for the app', () => {
    const der = Buffer.from(manifest.key, 'base64');
    const id = [...createHash('sha256').update(der).digest().subarray(0, 16)].map((b) => String.fromCharCode(97 + (b >> 4)) + String.fromCharCode(97 + (b & 15))).join('');
    expect(id).toMatch(/^[a-p]{32}$/);
    expect(ids).toContain(id);
  });

  it('asks for nativeMessaging only as an optional permission (no install warning)', () => {
    expect(manifest.permissions).not.toContain('nativeMessaging');
    expect(manifest.optional_permissions).toEqual(['nativeMessaging']);
  });

  it('keeps Chrome-only fields out of the Firefox manifest', () => {
    const ff = firefoxManifest(manifest) as unknown as Record<string, unknown>;
    expect(ff.key).toBeUndefined();
    expect(ff.optional_permissions).toBeUndefined();
  });
});

describe('desktop side: exact origin and offers', () => {
  const login = (id: string, site: string | undefined, username = 'u', password = 'p', type: Entry['type'] = 'login'): Entry =>
    ({ id, ver: 1, type, title: `T-${id}`, site, username, password, tags: [], favorite: false, created: 1, updated: 1, history: [] }) as Entry;
  const entries = [
    login('1', 'https://a.test'),
    login('2', 'a.test'),
    login('3', 'http://a.test'),
    login('4', 'https://a.test:8443'),
    login('5', 'https://sub.a.test'),
    login('6', 'luciverse:notes'),
    login('7', undefined),
    login('8', 'https://a.test', 'x', 'p', 'apikey'),
    login('9', 'https://b.test', 'bob', 'bobpw'),
  ];

  it('matches only logins saved for the exact origin (scheme, host, port)', () => {
    expect(matchLogins(entries, 'https://a.test').map((l) => l.id)).toEqual(['1', '2']);
    expect(matchLogins(entries, 'http://a.test').map((l) => l.id)).toEqual(['3']);
    expect(matchLogins(entries, 'https://a.test:8443').map((l) => l.id)).toEqual(['4']);
    expect(matchLogins(entries, 'https://evil.test')).toEqual([]);
    expect(matchLogins(entries, 'https://a.test.evil.test')).toEqual([]);
    expect(JSON.stringify(matchLogins(entries, 'https://b.test'))).not.toContain('bobpw');
  });

  it('fill hands out credentials only for an id saved for that origin', () => {
    expect(fillLogin(entries, 'https://b.test', '9')).toEqual({ username: 'bob', password: 'bobpw' });
    expect(() => fillLogin(entries, 'https://a.test', '9')).toThrow('no-match');
    expect(() => fillLogin(entries, 'https://sub.a.test', '1')).toThrow('no-match');
    expect(() => fillLogin(entries, 'https://a.test', '6')).toThrow('no-match');
    expect(() => fillLogin(entries, 'https://a.test', '8')).toThrow('no-match');
    expect(() => fillLogin(entries, 'https://a.test', 'nope')).toThrow('no-match');
  });

  const store = (unlocked: boolean): LinkStoreApi => ({ unlocked: () => unlocked, entries: () => entries, onUnlockedChange: () => () => undefined, saveEntry: async () => undefined });

  it('answers nothing while locked, except that offers wait', () => {
    expect(() => answer(store(false), { id: 1, kind: 'match', body: { origin: 'https://a.test' } })).toThrow('locked');
    expect(() => answer(store(false), { id: 1, kind: 'fill', body: { origin: 'https://b.test', id: '9' } })).toThrow('locked');
    useLinkUi.setState({ offers: [] });
    expect(answer(store(false), { id: 1, kind: 'save-offer', body: { origin: 'https://a.test', username: 'n', password: 'pw' } })).toEqual({ queued: true });
    expect(useLinkUi.getState().offers).toHaveLength(1);
    expect(answer(store(true), { id: 2, kind: 'match', body: { origin: 'https://b.test' } })).toEqual({ logins: [{ id: '9', title: 'T-9', username: 'bob' }] });
    expect(() => answer(store(true), { id: 3, kind: 'wat', body: {} })).toThrow('unknown-type');
  });

  it('plans offers: create, update the same user, skip an unchanged password', () => {
    expect(planOffer(entries, { origin: 'https://b.test', username: 'carol', password: 'x' })).toEqual({ kind: 'create' });
    expect(planOffer(entries, { origin: 'https://b.test', username: ' BOB ', password: 'new' })).toEqual({ kind: 'update', id: '9' });
    expect(planOffer(entries, { origin: 'https://b.test', username: 'bob', password: 'bobpw' })).toEqual({ kind: 'same' });
    useLinkUi.setState({ offers: [] });
    expect(queueOffer(entries, true, { origin: 'https://b.test', username: 'bob', password: 'bobpw' })).toBe(false);
    expect(queueOffer(entries, true, { origin: 'https://b.test', username: 'bob', password: 'changed' })).toBe(true);
    expect(queueOffer(entries, true, { origin: 'https://b.test', username: 'bob', password: 'changed2' })).toBe(true);
    expect(useLinkUi.getState().offers).toHaveLength(1);
  });
});
