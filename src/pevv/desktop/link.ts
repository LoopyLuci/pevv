/**
 * The desktop app's side of the browser-extension link, in the webview. The Rust shell
 * authenticates the extension and relays `match` / `fill` / `save-offer` here, because only
 * this page holds the unlocked vault. This is where the exact-origin rule is enforced: the
 * shell checks the origin is a bare http(s) origin, but whether a login may be handed out for
 * it is decided here, against the saved site of each login, and nothing the extension says
 * about "which logins match" is trusted (it only names an id).
 */
import { create } from 'zustand';
import type { Entry } from '../model';
import { loginMatchesOrigin } from '../extension/core';
import { resolveCliEnv, type CliVault } from '../cli';

export const EVENT_PROMPT = 'link-prompt';
export const EVENT_REQUEST = 'link-request';
export const OFFER_TTL_MS = 5 * 60_000;
const MAX_OFFERS = 5;

export interface LinkIpc {
  invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
  listen<P>(event: string, fn: (payload: P) => void): Promise<() => void>;
}

export interface LinkStoreApi {
  /** Is the vault unlocked right now? */
  unlocked(): boolean;
  entries(): Entry[];
  /** Calls `fn` on every lock / unlock. */
  onUnlockedChange(fn: (unlocked: boolean) => void): () => void;
  saveEntry(id: string | null, patch: Partial<Entry>): Promise<unknown>;
  /** The vault's environments, for `pevv run` / `pevv env` (the shell asks with `cli-env`). */
  cli?: CliVault;
}

export interface LoginHit { id: string; title: string; username: string }

/** Logins saved for exactly this origin. Titles and usernames only. */
export function matchLogins(entries: Entry[], origin: string): LoginHit[] {
  return entries
    .filter((e) => e.type === 'login' && loginMatchesOrigin(e.site, origin))
    .map((e) => ({ id: e.id, title: e.title, username: e.username ?? '' }));
}

/** One login's credentials, only if its saved site is exactly `origin`. */
export function fillLogin(entries: Entry[], origin: string, id: string): { username: string; password: string } {
  const e = entries.find((x) => x.id === id);
  if (!e || e.type !== 'login' || !loginMatchesOrigin(e.site, origin) || !e.password) throw new Error('no-match');
  return { username: e.username ?? '', password: e.password };
}

const sameUser = (a: string | undefined, b: string | undefined): boolean => (a ?? '').trim().toLowerCase() === (b ?? '').trim().toLowerCase();

export interface OfferView { id: number; origin: string; username: string; password: string; at: number }
export interface PairPrompt { id: number; extId: string; fingerprint: string }

interface LinkUiState { prompts: PairPrompt[]; offers: OfferView[] }
export const useLinkUi = create<LinkUiState>()(() => ({ prompts: [], offers: [] }));

export type OfferPlan = { kind: 'create' } | { kind: 'update'; id: string } | { kind: 'same' };

/** What saving this offer would do: add a login for the origin, update one with the same user, or nothing. */
export function planOffer(entries: Entry[], o: Pick<OfferView, 'origin' | 'username' | 'password'>): OfferPlan {
  const hit = entries.find((e) => e.type === 'login' && loginMatchesOrigin(e.site, o.origin) && sameUser(e.username, o.username));
  if (!hit) return { kind: 'create' };
  return hit.password === o.password ? { kind: 'same' } : { kind: 'update', id: hit.id };
}

let nextOffer = 1;

export function queueOffer(entries: Entry[], unlocked: boolean, o: { origin: string; username: string; password: string }, now = Date.now()): boolean {
  if (unlocked && planOffer(entries, o).kind === 'same') return false;
  const fresh = useLinkUi.getState().offers.filter((x) => now - x.at < OFFER_TTL_MS && !(x.origin === o.origin && sameUser(x.username, o.username)));
  useLinkUi.setState({ offers: [...fresh, { id: nextOffer++, ...o, at: now }].slice(-MAX_OFFERS) });
  return true;
}

export function dropOffer(id: number): void {
  useLinkUi.setState({ offers: useLinkUi.getState().offers.filter((o) => o.id !== id) });
}

export function hostOf(origin: string): string {
  try { return new URL(origin).host; } catch { return origin; }
}

let api: { ipc: LinkIpc; store: LinkStoreApi } | null = null;

/** Save a queued offer (needs the vault unlocked). */
export async function acceptOffer(id: number): Promise<'saved' | 'updated' | 'same'> {
  const o = useLinkUi.getState().offers.find((x) => x.id === id);
  if (!o || !api) throw new Error('That offer is gone.');
  const { store } = api;
  if (!store.unlocked()) throw new Error('Unlock PEVV to save this login.');
  const plan = planOffer(store.entries(), o);
  if (plan.kind === 'update') await store.saveEntry(plan.id, { password: o.password });
  else if (plan.kind === 'create') await store.saveEntry(null, { type: 'login', title: hostOf(o.origin), site: o.origin, username: o.username, password: o.password });
  dropOffer(id);
  return plan.kind === 'create' ? 'saved' : plan.kind === 'update' ? 'updated' : 'same';
}

export async function answerPrompt(id: number, approve: boolean): Promise<void> {
  useLinkUi.setState({ prompts: useLinkUi.getState().prompts.filter((p) => p.id !== id) });
  await api?.ipc.invoke('link_prompt_answer', { id, approve });
}

interface Req { id: number; kind: string; body: Record<string, unknown> }

/** Answer one relayed request. Throws an error code string the shell passes back to the extension. */
export function answer(store: LinkStoreApi, req: Req): Record<string, unknown> {
  const origin = typeof req.body.origin === 'string' ? req.body.origin : '';
  if (req.kind === 'save-offer') {
    const queued = queueOffer(store.entries(), store.unlocked(), { origin, username: String(req.body.username ?? ''), password: String(req.body.password ?? '') });
    return { queued };
  }
  if (!store.unlocked()) throw new Error('locked');
  if (req.kind === 'match') return { logins: matchLogins(store.entries(), origin) };
  if (req.kind === 'fill') return fillLogin(store.entries(), origin, String(req.body.id ?? ''));
  // Only the shell's own `pevv` policy asks this (the extension's kinds are whitelisted in Rust); the shell
  // shows the names to the person and only then hands the values to the tool.
  if (req.kind === 'cli-env' && store.cli) return { ...resolveCliEnv(store.cli, req.body) };
  throw new Error('unknown-type');
}

/** Wire the shell's events to the vault. Resolves to a function that stops it. */
export async function startLink(ipc: LinkIpc, store: LinkStoreApi): Promise<() => void> {
  api = { ipc, store };
  const report = (u: boolean): void => { void ipc.invoke('link_report_state', { unlocked: u }).catch(() => undefined); };
  report(store.unlocked());
  const offUnlock = store.onUnlockedChange(report);
  const offReq = await ipc.listen<Req>(EVENT_REQUEST, (req) => {
    void (async () => {
      try {
        await ipc.invoke('link_respond', { id: req.id, ok: true, value: answer(store, req) });
      } catch (e) {
        const code = (e as Error).message;
        await ipc.invoke('link_respond', { id: req.id, ok: false, value: /^[a-z-]{1,30}$/.test(code) ? code : 'failed' }).catch(() => undefined);
      }
    })();
  });
  const offPrompt = await ipc.listen<{ kind: string; id: number; extId?: string; fingerprint?: string }>(EVENT_PROMPT, (p) => {
    const rest = useLinkUi.getState().prompts.filter((x) => x.id !== p.id);
    useLinkUi.setState({ prompts: p.kind === 'pair' && p.extId && p.fingerprint ? [...rest, { id: p.id, extId: p.extId, fingerprint: p.fingerprint }] : rest });
  });
  // A pairing that arrived before this window was listening.
  void ipc.invoke<PairPrompt[]>('link_prompts').then((list) => useLinkUi.setState({ prompts: list }), () => undefined);
  return () => { offUnlock(); offReq(); offPrompt(); api = null; };
}

export interface LinkState {
  enabled: boolean;
  hostExists: boolean;
  registered: string[];
  paired: Array<{ extId: string; at: number }>;
  unsupported: string | null;
  serverError: string | null;
}

/** For the settings section; null until `startLink` ran (i.e. outside the desktop app). */
export function linkIpc(): LinkIpc | null {
  return api?.ipc ?? null;
}
