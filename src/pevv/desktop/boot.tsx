/**
 * PEVV desktop (Tauri) entry: the same standalone UI as the Android app and
 * the extension vault screen, with the vault ciphertext mirrored to a file by
 * the Rust shell. See docs/PEVV_DESKTOP.md.
 */
import '../../styles/globals.css';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { seedDesktop, startDesktopBridge, type DesktopIpc } from './bridge';
import { createNative } from './native';
import { startLink } from './link';
import { startTransferd } from './transferd';
import { describeDevice, localDeviceId } from '../devices';
import { startAutoType } from './autotypeHost';
import { startCli } from './cli';
import { startProvider } from './provider';
import { askPin } from './pin';
import { setNative } from '../native';

const ipc: DesktopIpc = {
  invoke: (cmd, args) => invoke(cmd, args),
  listen: (event, fn) => listen(event, () => fn()),
};

/** First run only: the desktop app clears a copied secret after 30 s (the web default is 20 s). */
function seedPrefs(): void {
  try {
    if (localStorage.getItem('lv-pevv-prefs') === null) {
      localStorage.setItem('lv-pevv-prefs', JSON.stringify({ autoLockMin: 5, lockOnHide: true, clipboardSec: 30, autofill: false, sync: false, revealReauthSec: 120 }));
    }
  } catch { /* blocked storage */ }
}

/** The auto-type chooser window: a tiny page with no vault, just the titles the shell sends it. */
async function bootChooser(): Promise<void> {
  document.documentElement.classList.add('lv-pevv-app', 'lv-pevv-desktop');
  document.body.style.margin = '0';
  document.body.style.overflow = 'hidden';
  const [{ createElement }, { createRoot }, { Chooser }] = await Promise.all([import('react'), import('react-dom/client'), import('./AutoType')]);
  createRoot(document.getElementById('root')!).render(createElement(Chooser, { ipc: { invoke: (cmd, args) => invoke(cmd, args), listen: (event, fn) => listen(event, (e) => fn(e.payload as never)) } }));
}

async function boot(): Promise<void> {
  if ((window as unknown as { __PEVV_CHOOSER__?: boolean }).__PEVV_CHOOSER__) return bootChooser();
  document.documentElement.classList.add('lv-pevv-app', 'lv-pevv-desktop');
  // Release builds: no webview context menu (reload / inspect). Inputs keep keyboard cut/copy/paste.
  if (import.meta.env.PROD) document.addEventListener('contextmenu', (e) => e.preventDefault());
  seedPrefs();
  await seedDesktop(ipc);
  // Native passkeys, USB key files and the presence lock: filled in before the UI renders so it can offer them.
  setNative(await createNative(ipc, askPin));
  const [{ StrictMode, createElement }, { createRoot }, { initLocale }, store, { PevvStandalone }] = await Promise.all([
    import('react'),
    import('react-dom/client'),
    import('../host/locale'),
    import('../store'),
    import('../ui/PevvStandalone'),
  ]);
  await startDesktopBridge(ipc, {
    onVaultWrite: store.onVaultWrite,
    reconcileRemote: store.reconcileRemote,
    adoptRemote: store.adoptRemote,
    hasFile: () => !!store.usePevv.getState().file,
    lock: store.lock,
    setNativeClipboard: store.setNativeClipboard,
  });
  // The browser-extension link: relays from the shell to the unlocked vault, and the prompts it needs.
  const pevv = store.usePevv;
  await startLink(
    { invoke: (cmd, args) => invoke(cmd, args), listen: (event, fn) => listen(event, (e) => fn(e.payload as never)) },
    {
      unlocked: () => pevv.getState().status === 'unlocked',
      entries: () => pevv.getState().entries,
      onUnlockedChange: (fn) => pevv.subscribe((s, prev) => { if ((s.status === 'unlocked') !== (prev.status === 'unlocked')) fn(s.status === 'unlocked'); }),
      saveEntry: (id, patch) => store.saveEntry(id, patch),
      cli: {
        hasEnv: (name) => !!pevv.getState().meta?.environments.includes(name),
        activeEnv: () => pevv.getState().meta?.activeEnv ?? 'dev',
        envForProgram: (programId) => store.envForProgram(programId),
        envVars: (env) => store.envVars(env),
      },
    },
  );
  // Direct device link (Transferd): a no-op until the person switches it on in Settings. A peer's file goes through the same merge as the cloud copy.
  await startTransferd(
    { invoke: (cmd, args) => invoke(cmd, args), listen: (event, fn) => listen(event, (e) => fn(e.payload as never)) },
    { reconcileRemote: store.reconcileRemote, onVaultWrite: (fn) => store.onVaultWrite(() => fn()), device: () => ({ id: localDeviceId(), name: describeDevice().name }) },
  );
  // Global-hotkey auto-type into other programs, and `pevv` (the command-line tool): both ask the unlocked vault here.
  const shell = { invoke: <T,>(cmd: string, args?: Record<string, unknown>) => invoke<T>(cmd, args), listen: <P,>(event: string, fn: (payload: P) => void) => listen<P>(event, (e) => fn(e.payload)) };
  await startAutoType(shell, {
    unlocked: () => pevv.getState().status === 'unlocked',
    entries: () => pevv.getState().entries,
    copySecret: (value, itemId) => store.copySecret(value, itemId),
    clipboardSec: () => pevv.getState().prefs.clipboardSec,
    audit: (item, detail) => store.audit('autotype', item, detail),
  });
  await startCli(shell, (purpose, detail) => store.audit(purpose, undefined, detail));
  // Windows passkey provider: Windows' MakeCredential / GetAssertion arrive from the shell (a no-op unless the shell has the feature).
  await startProvider(shell, {
    unlocked: () => pevv.getState().status === 'unlocked',
    entries: () => pevv.getState().entries,
    onUnlockedChange: (fn) => pevv.subscribe((s, prev) => { if ((s.status === 'unlocked') !== (prev.status === 'unlocked')) fn(s.status === 'unlocked'); }),
    onEntriesChange: (fn) => pevv.subscribe((s, prev) => { if (s.entries !== prev.entries) fn(); }),
    saveEntry: (id, patch) => store.saveEntry(id, patch),
    audit: (detail) => store.audit('passkey-provider', undefined, detail),
  });
  const { LinkPrompts } = await import('./BrowserLink');
  const { CliPrompts } = await import('./CliAccess');
  const { ProviderPrompts } = await import('./PasskeyProvider');
  const promptRoot = document.createElement('div');
  document.body.appendChild(promptRoot);
  createRoot(promptRoot).render(createElement('div', null, createElement(LinkPrompts), createElement(CliPrompts), createElement(ProviderPrompts)));
  void initLocale();
  createRoot(document.getElementById('root')!).render(createElement(StrictMode, null, createElement(PevvStandalone)));
}

void boot();
