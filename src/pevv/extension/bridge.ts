/**
 * Keeps the vault screen (an extension page using the normal PEVV store, which
 * keeps its ciphertext in localStorage) and the service worker (which reads
 * chrome.storage.local) on the same ciphertext file. Only the encrypted
 * VaultFile crosses; the two sides unlock separately.
 */
import type { VaultFile } from '../model';
import { validateFile } from '../vault';
import { STORE } from './protocol';

/** Same key as `VAULT_KEY` in store.ts. Not imported: the store reads it at module load, so it must be seeded first. */
export const PAGE_VAULT_KEY = 'lv-pevv-vault-v1';

export function parseFile(v: unknown): VaultFile | null {
  if (!v) return null;
  try {
    const f = (typeof v === 'string' ? JSON.parse(v) : v) as unknown;
    validateFile(f);
    return f;
  } catch {
    return null;
  }
}

/**
 * Which copy both sides should start from. The extension copy wins unless the
 * page holds a newer revision of the same vault. A different vault in the
 * extension store replaces the page copy: the worker and the page must agree.
 */
export function pickCopy(page: VaultFile | null, ext: VaultFile | null): VaultFile | null {
  if (!ext) return page;
  if (!page || page.id !== ext.id) return ext;
  return page.rev > ext.rev ? page : ext;
}

/** Should the page's write go to the extension store? Not if the worker already wrote a newer revision. */
export function shouldMirror(next: VaultFile, ext: VaultFile | null): boolean {
  if (!ext || ext.id !== next.id) return true;
  return next.rev >= ext.rev && JSON.stringify(ext) !== JSON.stringify(next);
}

async function readExt(): Promise<VaultFile | null> {
  return parseFile((await chrome.storage.local.get(STORE.vault))[STORE.vault]);
}

/** Run before the PEVV store module loads. */
export async function seedPage(): Promise<void> {
  let page: VaultFile | null = null;
  try { page = parseFile(localStorage.getItem(PAGE_VAULT_KEY)); } catch { /* blocked storage */ }
  const ext = await readExt();
  const pick = pickCopy(page, ext);
  if (!pick) return;
  if (pick !== page) localStorage.setItem(PAGE_VAULT_KEY, JSON.stringify(pick));
  if (pick !== ext) await chrome.storage.local.set({ [STORE.vault]: JSON.stringify(pick) });
}

interface StoreApi {
  onVaultWrite(fn: (f: VaultFile | null) => void): () => void;
  reconcileRemote(remote: VaultFile, source: 'cloud' | 'peer'): Promise<boolean>;
  adoptRemote(remote: VaultFile): Promise<boolean>;
  hasFile(): boolean;
}

export function startBridge(store: StoreApi): () => void {
  let writing = '';
  const off = store.onVaultWrite((f) => {
    void (async () => {
      if (!f) { await chrome.storage.local.remove(STORE.vault); return; }
      if (!shouldMirror(f, await readExt())) return;
      writing = JSON.stringify(f);
      await chrome.storage.local.set({ [STORE.vault]: writing });
    })();
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !(STORE.vault in changes)) return;
    const raw = changes[STORE.vault]!.newValue;
    if (typeof raw === 'string' && raw === writing) return;
    const remote = parseFile(raw);
    if (!remote) return;
    // The worker saved a login or used a code: fold it in like a live paired device.
    void (store.hasFile() ? store.reconcileRemote(remote, 'peer') : store.adoptRemote(remote));
  });
  return off;
}
