/**
 * The webview's half of the Windows passkey provider. The Rust shell (feature `win-passkey-provider`)
 * receives MakeCredential / GetAssertion from Windows, decodes the CTAP request and emits it here as
 * `passkey-provider-request`, because only this page holds the unlocked vault. The answer goes back
 * with `passkey_provider_respond`. The crypto is in ../passkeyProvider.ts; this file is the wiring and
 * the "does the person agree" prompts.
 */
import { create } from 'zustand';
import type { Entry } from '../model';
import { type ProviderHost, type ProviderRequest, ProviderFailure, handleProviderRequest, isPasskeyEntry } from '../passkeyProvider';

export const EVENT_PROVIDER_REQUEST = 'passkey-provider-request';
/** Windows gave up on a request (the person closed its dialog): drop the PEVV card for it. */
export const EVENT_PROVIDER_CANCEL = 'passkey-provider-cancel';

export interface ProviderIpc {
  invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
  listen<P>(event: string, fn: (payload: P) => void): Promise<() => void>;
}

/** What `passkey_provider_support` answers. */
export interface ProviderSupport {
  /** The shell was built with the `win-passkey-provider` feature. */
  compiled: boolean;
  /** "windows", "linux", ... */
  os: string;
  /** Windows build number (26100 is Windows 11 24H2), when known. */
  build: number | null;
  /** The lowest build this app expects the plugin API on. */
  minBuild: number;
  /** The OS is new enough and the plugin API is present in it. */
  apiPresent: boolean;
  /** The app runs from an MSIX package (the plugin API refuses anything else). */
  packaged: boolean;
  /** Registered with Windows by `passkey_provider_register`; null if unknown. */
  registered: boolean | null;
  /** The person switched it on in Windows Settings; null if unknown. */
  enabled: boolean | null;
  reason: string | null;
}

/** Windows 11, 24H2 or later; older Windows and every other OS never show the section. */
export function sectionVisible(s: ProviderSupport | null): boolean {
  return !!s && s.os === 'windows' && s.build !== null && s.build >= s.minBuild;
}

export type Prompt =
  | { id: number; reqId: number; kind: 'make'; rpId: string; userName: string }
  | { id: number; reqId: number; kind: 'get'; rpId: string; choices: Array<{ id: string; userName: string }> };

interface ProviderUiState { prompts: Prompt[] }
export const useProviderUi = create<ProviderUiState>()(() => ({ prompts: [] }));

const waiting = new Map<number, (answer: unknown) => void>();
let nextPrompt = 1;

function ask<T>(p: Prompt extends infer P ? (P extends Prompt ? Omit<P, 'id'> : never) : never): Promise<T> {
  const id = nextPrompt++;
  return new Promise<T>((resolve) => {
    waiting.set(id, (a) => resolve(a as T));
    useProviderUi.setState({ prompts: [...useProviderUi.getState().prompts, { ...p, id } as Prompt] });
  });
}

/** The person's answer to a prompt: `true`/`false` for a new passkey, the entry id (or null) for a sign-in. */
export function answerProviderPrompt(id: number, answer: boolean | string | null): void {
  useProviderUi.setState({ prompts: useProviderUi.getState().prompts.filter((p) => p.id !== id) });
  waiting.get(id)?.(answer);
  waiting.delete(id);
}

/** Drop (decline) pending prompts: all of them (on lock), or those of one Windows request (it was cancelled). */
export function declineProviderPrompts(reqId?: number): void {
  for (const p of useProviderUi.getState().prompts) if (reqId === undefined || p.reqId === reqId) answerProviderPrompt(p.id, p.kind === 'make' ? false : null);
}

export interface ProviderStoreApi {
  unlocked(): boolean;
  entries(): Entry[];
  onUnlockedChange(fn: (unlocked: boolean) => void): () => void;
  /** Calls `fn` whenever the list of entries changes. */
  onEntriesChange(fn: () => void): () => void;
  saveEntry(id: string | null, patch: Partial<Entry>): Promise<unknown>;
  audit?(detail: string): void;
}

let api: { ipc: ProviderIpc; store: ProviderStoreApi } | null = null;

/** For the settings section; null until `startProvider` ran (outside the desktop app). */
export function providerIpc(): ProviderIpc | null {
  return api?.ipc ?? null;
}

/** The metadata Windows may keep so it can list this authenticator's accounts (never a key). */
export interface CredentialMeta { credentialId: string; rpId: string; rpName: string; userHandle: string; userName: string; userDisplayName: string }

export function credentialMeta(entries: readonly Entry[]): CredentialMeta[] {
  const out: CredentialMeta[] = [];
  for (const e of entries) {
    if (!isPasskeyEntry(e)) continue;
    out.push({ credentialId: e.credentialId, rpId: e.rpId, rpName: e.rpName ?? e.rpId, userHandle: e.userHandle ?? '', userName: e.userName ?? '', userDisplayName: e.userDisplayName ?? e.userName ?? '' });
  }
  return out;
}

function hostFor(store: ProviderStoreApi, reqId: number): ProviderHost {
  return {
    unlocked: () => store.unlocked(),
    entries: () => store.entries(),
    saveEntry: (id, data) => store.saveEntry(id, data),
    confirmMake: (r) => ask<boolean>({ kind: 'make', reqId, rpId: r.rpId, userName: r.userName }),
    confirmGet: (r) => ask<string | null>({ kind: 'get', reqId, rpId: r.rpId, choices: r.choices }),
    ...(store.audit ? { audit: (d: string) => store.audit?.(d) } : {}),
  };
}

/** Answer one request the shell relayed; the reply is `{ ok: true, value }` or `{ ok: false, code }`. */
export async function answerRequest(store: ProviderStoreApi, req: ProviderRequest): Promise<{ ok: true; value: unknown } | { ok: false; code: string }> {
  try {
    return { ok: true, value: await handleProviderRequest(hostFor(store, req.id), req) };
  } catch (e) {
    return { ok: false, code: e instanceof ProviderFailure ? e.code : 'failed' };
  }
}

/** Wire the shell's events to the vault. Resolves to a function that stops it. */
export async function startProvider(ipc: ProviderIpc, store: ProviderStoreApi): Promise<() => void> {
  api = { ipc, store };
  let sent = '';
  const sync = (): void => {
    if (!store.unlocked()) return;
    const credentials = credentialMeta(store.entries());
    // Only when the passkey list changed: every edit of any item fires this.
    const sig = JSON.stringify(credentials);
    if (sig === sent) return;
    sent = sig;
    void ipc.invoke('passkey_provider_sync', { credentials }).catch(() => { sent = ''; });
  };
  const offReq = await ipc.listen<ProviderRequest>(EVENT_PROVIDER_REQUEST, (req) => {
    void answerRequest(store, req).then((r) => ipc.invoke('passkey_provider_respond', { id: req.id, ok: r.ok, value: r.ok ? r.value : r.code }).catch(() => undefined));
  });
  const offCancel = await ipc.listen<{ id: number }>(EVENT_PROVIDER_CANCEL, (c) => declineProviderPrompts(c.id));
  const offUnlock = store.onUnlockedChange((u) => { if (u) sync(); else declineProviderPrompts(); });
  const offEntries = store.onEntriesChange(sync);
  sync();
  return () => { offReq(); offCancel(); offUnlock(); offEntries(); api = null; };
}
