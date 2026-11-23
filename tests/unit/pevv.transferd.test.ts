import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  EVENT, chooseLane, pullStaged, refreshStatus, revokePeer, setEnabled, startTransferd, useTransferd, type TransferdIpc, type TransferdStatus,
} from '@/pevv/desktop/transferd';
import { VAULT_FORMAT, type VaultFile } from '@/pevv/model';
import { PSTR } from '@/pevv/i18n';

function file(id: string, rev: number): VaultFile {
  return {
    format: VAULT_FORMAT, v: 1, id, created: 1, updated: 1, rev,
    kdf: { alg: 'pbkdf2-sha256', iter: 600_000, salt: 'AAAA' },
    slots: [], passkeys: [], require: { totp: false, passkey: false }, totp: null,
    meta: { iv: 'a', ct: 'b' }, entries: [],
  };
}

const NODE = 'a'.repeat(64);

function status(over: Partial<TransferdStatus> = {}): TransferdStatus {
  return {
    available: true, enabled: true, running: true, deviceName: 'Laptop', nodeId: NODE, fingerprint: [], seedProtection: 'os-keystore',
    relays: [], direct: [], peers: [], pending: [], invite: null, lastSync: null, lastError: null, staged: false, ...over,
  };
}

/** The Rust shell in miniature: a status, a one-file staging slot and an event table. */
class FakeShell implements TransferdIpc {
  st = status();
  staged: string | null = null;
  calls: Array<{ cmd: string; args: Record<string, unknown> | undefined }> = [];
  handlers: Array<(p: { kind?: string }) => void> = [];
  failRevoke = false;

  async invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
    this.calls.push({ cmd, args });
    if (cmd === 'transport_take_staged') { const s = this.staged; this.staged = null; return s as T; }
    if (cmd === 'transport_peer_revoke') {
      if (this.failRevoke) throw 'bad-node-id';
      this.st = { ...this.st, peers: this.st.peers.map((p) => (p.nodeId === args!.nodeId ? { ...p, state: 'revoked' as const } : p)) };
    }
    if (cmd === 'transport_enable') this.st = { ...this.st, enabled: !!args!.enabled, running: !!args!.enabled };
    return this.st as T;
  }
  async listen<P>(_event: string, fn: (payload: P) => void): Promise<() => void> {
    const h = fn as (p: { kind?: string }) => void;
    this.handlers.push(h);
    return () => { this.handlers = this.handlers.filter((x) => x !== h); };
  }
  emit(kind: string): void { for (const h of this.handlers) h({ kind }); }
  count(cmd: string): number { return this.calls.filter((c) => c.cmd === cmd).length; }
}

function fakeStore() {
  const merged: Array<{ f: VaultFile; source: string }> = [];
  let writeListener: (() => void) | null = null;
  return {
    merged,
    write: () => writeListener?.(),
    api: {
      reconcileRemote: vi.fn(async (f: VaultFile, source: 'cloud' | 'peer') => { merged.push({ f, source }); return true; }),
      onVaultWrite: (fn: () => void) => { writeListener = fn; return () => { writeListener = null; }; },
      device: () => ({ id: 'dev-1', name: 'Laptop' }),
    },
  };
}

beforeEach(() => { useTransferd.setState({ status: null }); });
afterEach(() => { vi.useRealTimers(); });

describe('lane choice (Transferd with Supabase as the automatic fallback)', () => {
  const peer = (reachable: boolean | null, state: 'approved' | 'revoked' = 'approved') => ({ nodeId: NODE, name: 'P', state, reachable });
  it('prefers a reachable approved peer', () => {
    expect(chooseLane({ running: true, peers: [peer(true)] }, true)).toBe('transferd');
    expect(chooseLane({ running: true, peers: [peer(true)] }, false)).toBe('transferd');
  });
  it('falls back to the cloud copy when no peer answers, the transport is off or the peer is removed', () => {
    expect(chooseLane({ running: true, peers: [peer(false)] }, true)).toBe('cloud');
    expect(chooseLane({ running: true, peers: [peer(null)] }, true)).toBe('cloud');
    expect(chooseLane({ running: false, peers: [peer(true)] }, true)).toBe('cloud');
    expect(chooseLane({ running: true, peers: [peer(true, 'revoked')] }, true)).toBe('cloud');
    expect(chooseLane(null, true)).toBe('cloud');
  });
  it('is none when neither lane is on', () => {
    expect(chooseLane({ running: true, peers: [peer(false)] }, false)).toBe('none');
    expect(chooseLane(null, false)).toBe('none');
  });
});

describe('a peer file goes through the same merge as the cloud copy', () => {
  it('hands the staged file to reconcileRemote as source "peer"', async () => {
    const shell = new FakeShell();
    const store = fakeStore();
    shell.staged = JSON.stringify(file('v', 7));
    expect(await pullStaged(shell, store.api)).toBe(true);
    expect(store.merged).toHaveLength(1);
    expect(store.merged[0]!.source).toBe('peer');
    expect(store.merged[0]!.f.rev).toBe(7);
    // The shell gives a file out once.
    expect(await pullStaged(shell, store.api)).toBe(false);
    expect(store.merged).toHaveLength(1);
  });

  it('ignores anything that is not a vault file', async () => {
    const shell = new FakeShell();
    const store = fakeStore();
    shell.staged = '{"format":"other"}';
    expect(await pullStaged(shell, store.api)).toBe(false);
    shell.staged = 'not json';
    expect(await pullStaged(shell, store.api)).toBe(false);
    expect(store.merged).toHaveLength(0);
  });

  it('a "staged" event pulls the file; other events only refresh the status', async () => {
    const shell = new FakeShell();
    const store = fakeStore();
    const stop = await startTransferd(shell, store.api, { intervalMs: 1e9 });
    expect(EVENT).toBe('transport-event');
    shell.staged = JSON.stringify(file('v', 3));
    shell.emit('staged');
    await vi.waitFor(() => expect(store.merged).toHaveLength(1));
    const before = shell.count('transport_status');
    shell.emit('pair-request');
    await vi.waitFor(() => expect(shell.count('transport_status')).toBe(before + 1));
    stop();
    expect(shell.handlers).toHaveLength(0);
  });
});

describe('push after a local write', () => {
  it('debounces writes into one sync while the transport runs', async () => {
    vi.useFakeTimers();
    const shell = new FakeShell();
    const store = fakeStore();
    const stop = await startTransferd(shell, store.api, { intervalMs: 1e9, debounceMs: 400 });
    const base = shell.count('transport_sync_now');
    store.write(); store.write(); store.write();
    await vi.advanceTimersByTimeAsync(399);
    expect(shell.count('transport_sync_now')).toBe(base);
    await vi.advanceTimersByTimeAsync(2);
    expect(shell.count('transport_sync_now')).toBe(base + 1);
    stop();
  });

  it('does nothing while the transport is off (the cloud lane is unaffected)', async () => {
    vi.useFakeTimers();
    const shell = new FakeShell();
    shell.st = status({ enabled: false, running: false });
    const store = fakeStore();
    const stop = await startTransferd(shell, store.api, { intervalMs: 1000, debounceMs: 10 });
    store.write();
    await vi.advanceTimersByTimeAsync(5000);
    expect(shell.count('transport_sync_now')).toBe(0);
    expect(shell.calls.every((c) => c.cmd === 'transport_status')).toBe(true);
    stop();
  });

  it('syncs on a timer as a safety net', async () => {
    vi.useFakeTimers();
    const shell = new FakeShell();
    const store = fakeStore();
    const stop = await startTransferd(shell, store.api, { intervalMs: 1000, debounceMs: 10 });
    const base = shell.count('transport_sync_now');
    await vi.advanceTimersByTimeAsync(2500);
    expect(shell.count('transport_sync_now')).toBeGreaterThanOrEqual(base + 2);
    stop();
  });
});

describe('removing a peer', () => {
  it('stops the transport using it first, then runs the existing key rotation', async () => {
    const shell = new FakeShell();
    shell.st = status({ peers: [{ nodeId: NODE, name: 'Phone', state: 'approved', reachable: true }] });
    const order: string[] = [];
    const rotate = vi.fn(async () => { order.push('rotate'); return { codes: ['c'] }; });
    const orig = shell.invoke.bind(shell);
    shell.invoke = (async <T,>(cmd: string, args?: Record<string, unknown>) => { order.push(cmd); return orig<T>(cmd, args); }) as typeof shell.invoke;
    const r = await revokePeer(shell, NODE, rotate);
    expect(order).toEqual(['transport_peer_revoke', 'rotate']);
    expect(r).toEqual({ codes: ['c'] });
    expect(useTransferd.getState().status?.peers[0]!.state).toBe('revoked');
  });

  it('does not rotate when the revoke failed', async () => {
    const shell = new FakeShell();
    shell.failRevoke = true;
    const rotate = vi.fn(async () => 1);
    await expect(revokePeer(shell, NODE, rotate)).rejects.toBe('bad-node-id');
    expect(rotate).not.toHaveBeenCalled();
  });
});

describe('settings calls', () => {
  it('switching on hands the shell this device id and name; off sends no device', async () => {
    const shell = new FakeShell();
    await setEnabled(shell, true, { id: 'dev-1', name: 'Laptop' });
    expect(shell.calls.at(-1)).toEqual({ cmd: 'transport_enable', args: { enabled: true, deviceId: 'dev-1', name: 'Laptop' } });
    await setEnabled(shell, false, null);
    expect(shell.calls.at(-1)!.args).toEqual({ enabled: false, deviceId: null, name: null });
  });

  it('refreshStatus never throws and keeps the last status', async () => {
    const shell = new FakeShell();
    expect(await refreshStatus(shell)).not.toBeNull();
    shell.invoke = (async () => { throw new Error('no shell'); }) as typeof shell.invoke;
    expect(await refreshStatus(shell)).toBeNull();
    expect(useTransferd.getState().status).not.toBeNull();
  });
});

describe('strings', () => {
  it('English and Spanish have the same Transferd keys', () => {
    const keys = (l: 'en' | 'es') => Object.keys(PSTR[l]).filter((k) => k.startsWith('tfd')).sort();
    expect(keys('en').length).toBeGreaterThan(20);
    expect(keys('es')).toEqual(keys('en'));
  });
});
