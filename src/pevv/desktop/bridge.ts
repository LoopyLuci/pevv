/**
 * Keeps the PEVV screen (the normal standalone UI, whose ciphertext lives in
 * localStorage) and the vault file the desktop shell keeps in the OS app-data
 * folder on the same copy. Only the encrypted VaultFile crosses; the Rust side
 * never sees a key. Same idea as the browser extension bridge, with a file
 * store behind `vault_read` / `vault_write` instead of chrome.storage.
 */
import type { VaultFile } from '../model';
import { PAGE_VAULT_KEY, parseFile, pickCopy, shouldMirror } from '../extension/bridge';

/** The two things the shell lends the page. Injected so tests need no Tauri. */
export interface DesktopIpc {
  invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
  listen(event: string, fn: () => void): Promise<() => void>;
}

export const EVENT_LOCK = 'lock';
export const EVENT_VAULT_CHANGED = 'vault-changed';

async function readDisk(ipc: DesktopIpc): Promise<VaultFile | null> {
  return parseFile(await ipc.invoke<string | null>('vault_read'));
}

/** Run before the PEVV store module loads (it reads localStorage at import). */
export async function seedDesktop(ipc: DesktopIpc): Promise<void> {
  let page: VaultFile | null = null;
  try { page = parseFile(localStorage.getItem(PAGE_VAULT_KEY)); } catch { /* blocked storage */ }
  const disk = await readDisk(ipc);
  const pick = pickCopy(page, disk);
  if (!pick) return;
  if (pick !== page) localStorage.setItem(PAGE_VAULT_KEY, JSON.stringify(pick));
  if (pick !== disk) await ipc.invoke('vault_write', { json: JSON.stringify(pick), expectedRev: disk && disk.id === pick.id ? disk.rev : null });
}

export interface StoreApi {
  onVaultWrite(fn: (f: VaultFile | null) => void): () => void;
  reconcileRemote(remote: VaultFile, source: 'cloud' | 'peer'): Promise<boolean>;
  adoptRemote(remote: VaultFile): Promise<boolean>;
  hasFile(): boolean;
  lock(reason: 'hidden'): void;
  /** Hand clipboard work to the shell: it clears after N seconds if the clipboard is unchanged. */
  setNativeClipboard(fn: ((value: string, sec: number) => Promise<boolean>) | null): void;
}

function isRevConflict(e: unknown): boolean {
  return typeof e === 'object' && e !== null && (e as { code?: unknown }).code === 'rev-conflict';
}

/**
 * Mirror vault writes to disk, fold changes made elsewhere (another instance, a
 * sync tool) back in like a live paired device, and lock on the shell `lock` event.
 * Resolves to a function that stops it.
 */
export async function startDesktopBridge(ipc: DesktopIpc, store: StoreApi): Promise<() => void> {
  let writing = '';
  let chain: Promise<void> = Promise.resolve();

  const fold = async (remote: VaultFile): Promise<void> => {
    await (store.hasFile() ? store.reconcileRemote(remote, 'peer') : store.adoptRemote(remote));
  };

  const mirror = async (f: VaultFile | null): Promise<void> => {
    if (!f) { writing = ''; await ipc.invoke('vault_clear'); return; }
    const disk = await readDisk(ipc);
    if (!shouldMirror(f, disk)) return;
    const json = JSON.stringify(f);
    writing = json;
    try {
      await ipc.invoke('vault_write', { json, expectedRev: disk && disk.id === f.id ? disk.rev : null });
    } catch (e) {
      // The file moved on between our read and write: take its copy instead of overwriting it.
      if (!isRevConflict(e)) throw e;
      const now = await readDisk(ipc);
      if (now) await fold(now);
    }
  };

  const off = store.onVaultWrite((f) => {
    chain = chain.then(() => mirror(f)).catch(() => undefined);
  });

  const onChanged = (): void => {
    chain = chain.then(async () => {
      const remote = await readDisk(ipc);
      if (!remote || JSON.stringify(remote) === writing) return;
      await fold(remote);
    }).catch(() => undefined);
  };

  store.setNativeClipboard(async (value, sec) => {
    await ipc.invoke('clipboard_copy', { text: value, clearAfterSecs: sec });
    return true;
  });

  const unlisten = await Promise.all([
    ipc.listen(EVENT_LOCK, () => store.lock('hidden')),
    ipc.listen(EVENT_VAULT_CHANGED, onChanged),
  ]);
  return () => {
    off();
    store.setNativeClipboard(null);
    for (const u of unlisten) u();
  };
}
