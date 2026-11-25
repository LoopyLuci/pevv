import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  checkForUpdate, dismissUpdate, installUpdate, installWhenSafe, nextStep, normalizeMode, startUpdater, useUpdate,
  type UpdateCtx, type UpdateInfo, type UpdateIpc, type UpdateMode,
} from '@/pevv/desktop/updater';
import { PSTR } from '@/pevv/i18n';
import { DEFAULT_PREFS } from '@/pevv/store';

const INFO: UpdateInfo = { version: '0.3.0', current: '0.2.0', notes: 'Fixes' };

/** The Rust shell in miniature: an enabled flag, one offered update, and a call log. */
class FakeShell implements UpdateIpc {
  enabled = true;
  offer: UpdateInfo | null = INFO;
  failCheck: string | null = null;
  failDownload: string | null = null;
  calls: string[] = [];
  async invoke<T>(cmd: string): Promise<T> {
    this.calls.push(cmd);
    if (cmd === 'update_enabled') return this.enabled as T;
    if (cmd === 'update_check') {
      if (this.failCheck) throw this.failCheck;
      return this.offer as T;
    }
    if (cmd === 'update_download' && this.failDownload) throw this.failDownload;
    return undefined as T;
  }
  count(cmd: string): number { return this.calls.filter((c) => c === cmd).length; }
}

function ctx(mode: UpdateMode, safe = true): UpdateCtx & { safeNow: boolean } {
  const c = { safeNow: safe, mode: () => mode, safe: () => c.safeNow };
  return c;
}

beforeEach(() => useUpdate.setState({ phase: 'idle', info: null, dismissed: null, error: null, quiet: false }));
afterEach(() => vi.useRealTimers());

describe('nextStep (the decision table)', () => {
  it('manual always asks and never downloads or installs by itself', () => {
    for (const safe of [true, false]) {
      expect(nextStep('manual', 'found', safe)).toBe('prompt');
      expect(nextStep('manual', 'downloaded', safe)).toBe('prompt');
    }
  });

  it('auto-download fetches, then asks "Restart to update"', () => {
    expect(nextStep('download', 'found', true)).toBe('download');
    expect(nextStep('download', 'downloaded', true)).toBe('prompt-restart');
    expect(nextStep('download', 'downloaded', false)).toBe('prompt-restart');
  });

  it('auto-install fetches, then installs only when it is safe to restart', () => {
    expect(nextStep('install', 'found', false)).toBe('download');
    expect(nextStep('install', 'downloaded', true)).toBe('install');
    expect(nextStep('install', 'downloaded', false)).toBe('wait');
  });

  it('an unknown stored mode falls back to manual, and manual is the default', () => {
    expect(normalizeMode('install')).toBe('install');
    expect(normalizeMode(undefined)).toBe('manual');
    expect(normalizeMode('yes please')).toBe('manual');
    expect(DEFAULT_PREFS.updateMode).toBe('manual');
  });
});

describe('updater flow', () => {
  it('stays off and never asks the endpoint while the pubkey is the placeholder', async () => {
    const sh = new FakeShell();
    sh.enabled = false;
    await checkForUpdate(sh, false, ctx('install'));
    expect(useUpdate.getState().phase).toBe('disabled');
    expect(sh.calls).toEqual(['update_enabled']);
  });

  it('manual: offers the update and neither downloads nor installs', async () => {
    const sh = new FakeShell();
    await checkForUpdate(sh, false, ctx('manual'));
    expect(useUpdate.getState().phase).toBe('available');
    expect(sh.count('update_download')).toBe(0);
    expect(sh.count('update_install')).toBe(0);
  });

  it('installs on click only, and only from available or ready', async () => {
    const sh = new FakeShell();
    await installUpdate(sh);
    expect(sh.calls).toEqual([]);
    await checkForUpdate(sh, false, ctx('manual'));
    await installUpdate(sh);
    expect(sh.count('update_install')).toBe(1);
    expect(useUpdate.getState()).toMatchObject({ phase: 'installing', quiet: false });
  });

  it('auto-download: downloads in the background and asks for a restart without installing', async () => {
    const sh = new FakeShell();
    await checkForUpdate(sh, false, ctx('download'));
    expect(sh.count('update_download')).toBe(1);
    expect(sh.count('update_install')).toBe(0);
    expect(useUpdate.getState()).toMatchObject({ phase: 'ready', quiet: false });
    await installUpdate(sh);
    expect(sh.count('update_install')).toBe(1);
  });

  it('auto-install with the vault unlocked waits silently and never restarts mid-edit', async () => {
    const sh = new FakeShell();
    const c = ctx('install', false);
    await checkForUpdate(sh, false, c);
    expect(useUpdate.getState()).toMatchObject({ phase: 'ready', quiet: true });
    await installWhenSafe(sh, c);
    expect(sh.count('update_install')).toBe(0);
    c.safeNow = true; // the vault locked
    await installWhenSafe(sh, c);
    expect(sh.count('update_install')).toBe(1);
    expect(useUpdate.getState().quiet).toBe(true);
  });

  it('auto-install with the vault locked installs straight away', async () => {
    const sh = new FakeShell();
    await checkForUpdate(sh, false, ctx('install', true));
    expect(sh.count('update_download')).toBe(1);
    expect(sh.count('update_install')).toBe(1);
  });

  it('installWhenSafe does nothing outside the silent mode', async () => {
    const sh = new FakeShell();
    const c = ctx('download', true);
    await checkForUpdate(sh, false, c);
    await installWhenSafe(sh, c);
    expect(sh.count('update_install')).toBe(0);
  });

  it('a failed download is not installed, and is only reported for a manual check', async () => {
    const sh = new FakeShell();
    sh.failDownload = 'bad signature';
    await checkForUpdate(sh, false, ctx('install', true));
    expect(sh.count('update_install')).toBe(0);
    expect(useUpdate.getState().phase).toBe('idle');
    await checkForUpdate(sh, true, ctx('install', true));
    expect(useUpdate.getState()).toMatchObject({ phase: 'error', error: 'bad signature' });
  });

  it('"Later" hides that version from background checks but not from a manual one', async () => {
    const sh = new FakeShell();
    const c = ctx('manual');
    await checkForUpdate(sh, false, c);
    dismissUpdate();
    await checkForUpdate(sh, false, c);
    expect(useUpdate.getState().phase).toBe('idle');
    await checkForUpdate(sh, true, c);
    expect(useUpdate.getState().phase).toBe('available');
  });

  it('reports up to date, and errors only for a manual check', async () => {
    const sh = new FakeShell();
    sh.offer = null;
    await checkForUpdate(sh, true, ctx('manual'));
    expect(useUpdate.getState().phase).toBe('upToDate');
    sh.failCheck = 'network down';
    await checkForUpdate(sh, false, ctx('manual'));
    expect(useUpdate.getState().phase).toBe('idle');
    await checkForUpdate(sh, true, ctx('manual'));
    expect(useUpdate.getState()).toMatchObject({ phase: 'error', error: 'network down' });
  });

  it('checks on start and daily, and skips while the setting is off', async () => {
    vi.useFakeTimers();
    const sh = new FakeShell();
    let on = true;
    const stop = startUpdater(sh, () => on, 1000, ctx('manual'));
    await vi.advanceTimersByTimeAsync(0);
    expect(sh.count('update_check')).toBe(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(sh.count('update_check')).toBe(2);
    on = false;
    await vi.advanceTimersByTimeAsync(3000);
    expect(sh.count('update_check')).toBe(2);
    stop();
  });

  it('has English and Spanish strings for every mode', () => {
    for (const k of ['updTitle', 'updToggle', 'updPromptTitle', 'updPromptBody', 'updNow', 'updLater', 'updCheckNow', 'updModeLabel', 'updModeManual', 'updModeDownload', 'updModeInstall', 'updModeNote', 'updReadyTitle', 'updReadyBody', 'updRestart'] as const) {
      expect(PSTR.en[k]).toBeTruthy();
      expect(PSTR.es[k]).toBeTruthy();
    }
    expect(PSTR.es.updRestart).not.toBe(PSTR.en.updRestart);
  });
});
