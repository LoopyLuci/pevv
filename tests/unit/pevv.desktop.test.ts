import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EVENT_LOCK, EVENT_VAULT_CHANGED, seedDesktop, startDesktopBridge, type DesktopIpc, type StoreApi } from '@/pevv/desktop/bridge';
import { VAULT_FORMAT, type VaultFile } from '@/pevv/model';
import { VAULT_KEY } from '@/pevv/store';
import { inDesktopApp, passkeysBlocked, webauthnAvailable } from '@/pevv/webauthn';
import { PSTR } from '@/pevv/i18n';

function file(id: string, rev: number): VaultFile {
  return {
    format: VAULT_FORMAT, v: 1, id, created: 1, updated: 1, rev,
    kdf: { alg: 'pbkdf2-sha256', iter: 600_000, salt: 'AAAA' },
    slots: [], passkeys: [], require: { totp: false, passkey: false }, totp: null,
    meta: { iv: 'a', ct: 'b' }, entries: [],
  };
}

/** The Rust side in miniature: one file, the same rev rule, a listener table. */
class FakeShell implements DesktopIpc {
  disk: string | null = null;
  calls: Array<{ cmd: string; args: Record<string, unknown> | undefined }> = [];
  handlers = new Map<string, Array<() => void>>();
  failNextWriteWithConflict = false;

  async invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
    this.calls.push({ cmd, args });
    if (cmd === 'vault_read') return this.disk as T;
    if (cmd === 'vault_write') {
      if (this.failNextWriteWithConflict) {
        this.failNextWriteWithConflict = false;
        this.disk = JSON.stringify(file('a', 99));
        throw { code: 'rev-conflict', current_rev: 99, message: 'older' };
      }
      this.disk = args!.json as string;
      return (JSON.parse(this.disk) as VaultFile).rev as T;
    }
    if (cmd === 'vault_clear') { this.disk = null; return undefined as T; }
    return undefined as T;
  }
  async listen(event: string, fn: () => void): Promise<() => void> {
    const l = this.handlers.get(event) ?? [];
    l.push(fn);
    this.handlers.set(event, l);
    return () => { this.handlers.set(event, (this.handlers.get(event) ?? []).filter((x) => x !== fn)); };
  }
  emit(event: string): void { for (const f of this.handlers.get(event) ?? []) f(); }
  writes(): VaultFile[] { return this.calls.filter((c) => c.cmd === 'vault_write').map((c) => JSON.parse(c.args!.json as string) as VaultFile); }
}

function fakeStore(initial: VaultFile | null = null) {
  let listener: ((f: VaultFile | null) => void) | null = null;
  let has = !!initial;
  let clip: ((v: string, s: number) => Promise<boolean>) | null = null;
  const api = {
    reconcileRemote: vi.fn(async (_r: VaultFile, _s: 'cloud' | 'peer') => true),
    adoptRemote: vi.fn(async (_r: VaultFile) => { has = true; return true; }),
    lock: vi.fn(),
  };
  const store: StoreApi = {
    onVaultWrite: (fn) => { listener = fn; return () => { listener = null; }; },
    reconcileRemote: api.reconcileRemote,
    adoptRemote: api.adoptRemote,
    hasFile: () => has,
    lock: api.lock,
    setNativeClipboard: (fn) => { clip = fn; },
  };
  return { store, api, write: (f: VaultFile | null) => { has = !!f; listener?.(f); }, clip: () => clip, listening: () => listener !== null };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

describe('desktop bridge: seeding', () => {
  beforeEach(() => localStorage.clear());

  it('starts the page from the file on disk', async () => {
    const sh = new FakeShell();
    sh.disk = JSON.stringify(file('a', 3));
    await seedDesktop(sh);
    expect((JSON.parse(localStorage.getItem(VAULT_KEY)!) as VaultFile).rev).toBe(3);
    expect(sh.writes()).toHaveLength(0);
  });

  it('pushes a newer page copy to disk, with the rev it saw as the floor', async () => {
    const sh = new FakeShell();
    sh.disk = JSON.stringify(file('a', 3));
    localStorage.setItem(VAULT_KEY, JSON.stringify(file('a', 5)));
    await seedDesktop(sh);
    expect(sh.writes().map((f) => f.rev)).toEqual([5]);
    expect(sh.calls.find((c) => c.cmd === 'vault_write')!.args!.expectedRev).toBe(3);
  });

  it('writes an existing page vault to an empty disk, and does nothing when both are empty', async () => {
    const sh = new FakeShell();
    await seedDesktop(sh);
    expect(sh.writes()).toHaveLength(0);
    localStorage.setItem(VAULT_KEY, JSON.stringify(file('a', 1)));
    await seedDesktop(sh);
    expect(sh.writes().map((f) => f.id)).toEqual(['a']);
  });

  it('ignores junk on disk', async () => {
    const sh = new FakeShell();
    sh.disk = '{"x":1}';
    await seedDesktop(sh);
    expect(localStorage.getItem(VAULT_KEY)).toBeNull();
  });
});

describe('desktop bridge: mirror and fold-in', () => {
  it('mirrors a vault write to disk', async () => {
    const sh = new FakeShell();
    const s = fakeStore();
    await startDesktopBridge(sh, s.store);
    s.write(file('a', 1));
    await settle();
    expect(sh.writes().map((f) => f.rev)).toEqual([1]);
  });

  it('does not overwrite a newer copy another instance wrote', async () => {
    const sh = new FakeShell();
    sh.disk = JSON.stringify(file('a', 9));
    const s = fakeStore(file('a', 2));
    await startDesktopBridge(sh, s.store);
    s.write(file('a', 3));
    await settle();
    expect(sh.writes()).toHaveLength(0);
  });

  it('folds in a rev-conflict instead of losing the other copy', async () => {
    const sh = new FakeShell();
    const s = fakeStore(file('a', 2));
    await startDesktopBridge(sh, s.store);
    sh.failNextWriteWithConflict = true;
    s.write(file('a', 3));
    await settle();
    expect(s.api.reconcileRemote).toHaveBeenCalledTimes(1);
    expect(s.api.reconcileRemote.mock.calls[0]![0].rev).toBe(99);
    expect(s.api.reconcileRemote.mock.calls[0]![1]).toBe('peer');
  });

  it('folds a change made by another instance into an open vault like a paired device', async () => {
    const sh = new FakeShell();
    const s = fakeStore(file('a', 1));
    await startDesktopBridge(sh, s.store);
    sh.disk = JSON.stringify(file('a', 4));
    sh.emit(EVENT_VAULT_CHANGED);
    await settle();
    expect(s.api.reconcileRemote).toHaveBeenCalledTimes(1);
    expect(s.api.adoptRemote).not.toHaveBeenCalled();
  });

  it('adopts the file when this window has no vault yet', async () => {
    const sh = new FakeShell();
    const s = fakeStore(null);
    await startDesktopBridge(sh, s.store);
    sh.disk = JSON.stringify(file('a', 1));
    sh.emit(EVENT_VAULT_CHANGED);
    await settle();
    expect(s.api.adoptRemote).toHaveBeenCalledTimes(1);
  });

  it('does not fold its own write back in', async () => {
    const sh = new FakeShell();
    const s = fakeStore();
    await startDesktopBridge(sh, s.store);
    s.write(file('a', 1));
    await settle();
    sh.emit(EVENT_VAULT_CHANGED);
    await settle();
    expect(s.api.reconcileRemote).not.toHaveBeenCalled();
    expect(s.api.adoptRemote).not.toHaveBeenCalled();
  });

  it('removes the file (to a backup) when the vault is reset', async () => {
    const sh = new FakeShell();
    sh.disk = JSON.stringify(file('a', 1));
    const s = fakeStore(file('a', 1));
    await startDesktopBridge(sh, s.store);
    s.write(null);
    await settle();
    expect(sh.calls.some((c) => c.cmd === 'vault_clear')).toBe(true);
    expect(sh.disk).toBeNull();
  });
});

describe('desktop bridge: lock and clipboard', () => {
  it('locks the vault on the shell lock event', async () => {
    const sh = new FakeShell();
    const s = fakeStore(file('a', 1));
    await startDesktopBridge(sh, s.store);
    sh.emit(EVENT_LOCK);
    expect(s.api.lock).toHaveBeenCalledWith('hidden');
  });

  it('hands copy and clear to the shell', async () => {
    const sh = new FakeShell();
    const s = fakeStore();
    await startDesktopBridge(sh, s.store);
    await expect(s.clip()!('hunter2', 30)).resolves.toBe(true);
    const c = sh.calls.find((x) => x.cmd === 'clipboard_copy')!;
    expect(c.args).toEqual({ text: 'hunter2', clearAfterSecs: 30 });
  });

  it('stops everything when asked', async () => {
    const sh = new FakeShell();
    const s = fakeStore();
    const stop = await startDesktopBridge(sh, s.store);
    stop();
    expect(s.listening()).toBe(false);
    expect(s.clip()).toBeNull();
    sh.emit(EVENT_LOCK);
    expect(s.api.lock).not.toHaveBeenCalled();
  });
});

describe('desktop app detection', () => {
  afterEach(() => { delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__; });

  it('is false in a normal page and true inside Tauri', () => {
    expect(inDesktopApp()).toBe(false);
    expect(passkeysBlocked()).toBe(false);
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    expect(inDesktopApp()).toBe(true);
    expect(passkeysBlocked()).toBe(true);
    expect(webauthnAvailable()).toBe(false);
  });

  it('has the passkey explanation in English and Spanish', () => {
    expect(PSTR.en.passkeyDesktop).toMatch(/desktop app/);
    expect(PSTR.es.passkeyDesktop).toMatch(/escritorio/);
  });
});
