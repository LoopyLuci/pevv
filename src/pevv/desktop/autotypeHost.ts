/**
 * Auto-type in the webview that holds the unlocked vault. The Rust shell reads the foreground
 * window when the hotkey fires and asks here which entries match; the shell shows the chooser
 * (a separate window with no vault access), and when the person picks an entry the shell asks
 * here to build the keys. Secrets go to the shell only at that moment, to be typed.
 */
import type { Entry } from '../model';
import { DEFAULT_SEQUENCE, hasAutoType, matchAutoType, parseSequence, resolveSequence } from '../autotype';
import type { LinkIpc } from './link';

export const EVENT_REQUEST = 'autotype-request';
export const EVENT_RUN = 'autotype-run';

export interface AutoTypeStoreApi {
  unlocked(): boolean;
  entries(): Entry[];
  /** Copy a secret with the app's usual clear timer; false if the clipboard failed. */
  copySecret(value: string, itemId: string): Promise<boolean>;
  clipboardSec(): number;
  /** Write a line to the encrypted activity log (id and short detail, never a secret). */
  audit(item: string, detail: string): void;
}

interface RequestEvent { id: number; title: string; process: string; known: boolean; mode: 'type' | 'clipboard' }
interface RunEvent { id: number; entryId: string; mode: 'type' | 'clipboard' }

/** What the chooser may be told about an entry: never a secret. */
export function candidateOf(e: Entry): { id: string; title: string; username: string } {
  return { id: e.id, title: e.title.slice(0, 80), username: (e.username ?? '').slice(0, 80) };
}

/** Entries to offer for a request. Without a known window (Wayland) every auto-type entry is offered. */
export function offerFor(entries: Entry[], req: Pick<RequestEvent, 'title' | 'process' | 'known'>): Entry[] {
  return req.known ? matchAutoType(entries, { title: req.title, process: req.process }) : entries.filter(hasAutoType);
}

/** Run one confirmed request. Resolves to an error message to show, or null if the shell has the answer. */
export async function runConfirmed(ipc: LinkIpc, store: AutoTypeStoreApi, run: RunEvent): Promise<string | null> {
  const e = store.entries().find((x) => x.id === run.entryId);
  if (!store.unlocked() || !e || e.type !== 'login') return 'The vault was locked or the entry is gone.';
  const parsed = parseSequence(e.autoType?.sequence?.trim() || DEFAULT_SEQUENCE);
  if (!parsed.ok) return parsed.error;
  if (run.mode === 'clipboard') {
    if (!e.password) return 'This entry has no password to copy.';
    const ok = await store.copySecret(e.password, e.id);
    if (!ok) return 'The clipboard could not be used.';
    store.audit(e.id, 'copied (no typing here)');
    const sec = store.clipboardSec();
    await ipc.invoke('autotype_finish', { id: run.id, ok: true, message: `Typing is not possible on this system, so the password was copied${sec ? ` and clears in ${sec} s` : ''}. Paste it into the window.` });
    return null;
  }
  let actions;
  try { actions = await resolveSequence(parsed.tokens, e); } catch (err) { return (err as Error).message; }
  store.audit(e.id, 'typed into another program');
  try {
    await ipc.invoke('autotype_type', { id: run.id, actions });
  } catch {
    // The shell recorded why (window changed, elevated window, ...) and shows it in the chooser.
  }
  return null;
}

/** Wire the shell's auto-type events to the vault. Resolves to a function that stops it. */
export async function startAutoType(ipc: LinkIpc, store: AutoTypeStoreApi): Promise<() => void> {
  const offReq = await ipc.listen<RequestEvent>(EVENT_REQUEST, (req) => {
    void (async () => {
      if (!store.unlocked()) return;
      const hits = offerFor(store.entries(), req);
      await ipc.invoke('autotype_offer', { id: req.id, candidates: hits.map(candidateOf) }).catch(() => undefined);
    })();
  });
  const offRun = await ipc.listen<RunEvent>(EVENT_RUN, (run) => {
    void (async () => {
      const problem = await runConfirmed(ipc, store, run).catch((e: Error) => e.message);
      if (problem) await ipc.invoke('autotype_finish', { id: run.id, ok: false, message: problem }).catch(() => undefined);
    })();
  });
  return () => { offReq(); offRun(); };
}

export interface AutoTypeSupport { context: boolean; typing: boolean; session: string; note: string | null }
export interface AutoTypeSettings {
  enabled: boolean;
  hotkey: string;
  defaultHotkey: string;
  registered: boolean;
  error: string | null;
  support: AutoTypeSupport;
}
