/**
 * PEVV extension service worker. The only place the vault key exists.
 *
 * Chrome stops an idle MV3 worker after about 30 s. The key is never written to
 * any storage (not even storage.session) to survive that. Instead, while the
 * vault is unlocked, the worker makes a cheap extension API call every 20 s,
 * which Chrome counts as activity. That ends at the auto-lock deadline (1–60
 * minutes, no "never"). If Chrome stops the worker anyway, the key is gone and
 * the vault is simply locked: it fails closed.
 *
 * Linked mode (Use the PEVV desktop app): the vault stays in the desktop app. This worker then
 * only relays: it asks the app for matches and, at the moment a page redeems a fill ticket,
 * for that one login. Nothing the app returns is kept.
 */
import type { VaultFile } from '../model';
import { validateFile } from '../vault';
import type { LimiterState } from '../totp';
import { ExtVault, TICKET_MS } from './core';
import { AppLink, LinkError, type LinkSecret } from './link';
import {
  type AppState, type ContentRequest, type ExtSettings, type LinkView, type LoginRef, type PopupRequest, type PopupState, type Redeemed, type Reply,
  DEFAULT_SETTINGS, STORE, clampAutoLock, originOf,
} from './protocol';

const LOCK_ALARM = 'pevv-lock';
const KEEPALIVE_MS = 20_000;
const SCRIPT_ID = 'pevv-autofill';

let settings: ExtSettings = { ...DEFAULT_SETTINGS };

/** One exact origin. A wildcard grant ("on all sites") is not an approval of any one site. */
const exactOrigin = (o: string): boolean => !o.includes('*') && originOf(o) === o;
let keepalive: ReturnType<typeof setInterval> | null = null;

function parseVault(v: unknown): VaultFile | null {
  if (!v) return null;
  try {
    const f = (typeof v === 'string' ? JSON.parse(v) : v) as unknown;
    validateFile(f);
    return f;
  } catch {
    return null;
  }
}

const link = new AppLink({
  connectNative: (name) => chrome.runtime.connectNative(name),
  load: async () => ((await chrome.storage.local.get(STORE.link))[STORE.link] as LinkSecret | undefined) ?? null,
  save: async (v) => { if (v) await chrome.storage.local.set({ [STORE.link]: v }); else await chrome.storage.local.remove(STORE.link); },
  now: () => Date.now(),
  random: (n) => crypto.getRandomValues(new Uint8Array(n)),
  lastError: () => chrome.runtime.lastError?.message,
});

/** A fill the popup started in linked mode. The login itself is fetched from the app when the page redeems it. */
type AppTicket = { origin: string; exp: number } & ({ kind: 'login'; id: string } | { kind: 'generated'; password: string });
const appTickets = new Map<number, AppTicket>();

const hasNativePermission = (): Promise<boolean> => chrome.permissions.contains({ permissions: ['nativeMessaging'] }).catch(() => false);

/** Linked mode: the setting is on, Chrome granted the permission, and the app is paired. */
async function linkedMode(): Promise<boolean> {
  return settings.useDesktop && await hasNativePermission() && await link.isPaired();
}

function appState(e: unknown): AppState {
  const code = e instanceof LinkError ? e.code : '';
  if (code === 'app-not-running') return 'not-running';
  if (code === 'host-missing' || code === 'host-forbidden') return code;
  return 'error';
}

type AppLogin = { id: string; title: string; username: string };
const asRefs = (logins: AppLogin[] | undefined, origin: string): LoginRef[] =>
  (logins ?? []).slice(0, 50).map((l) => ({ id: String(l.id), title: String(l.title ?? ''), username: String(l.username ?? ''), site: origin, matches: true }));

async function linkView(): Promise<{ view: LinkView; unlocked: boolean }> {
  const permission = await hasNativePermission();
  const paired = permission && await link.isPaired();
  const mode = settings.useDesktop && paired ? 'app' : 'standalone';
  const view: LinkView = { permission, enabled: settings.useDesktop, paired, mode, app: null, pairing: link.pairing(), error: null };
  let unlocked = false;
  // While a pairing waits for the person, the connection is busy: do not queue status checks behind it.
  if (mode === 'app' && view.pairing?.state !== 'waiting') {
    try {
      unlocked = !(await link.request<{ locked: boolean }>('status')).locked;
      view.app = unlocked ? 'unlocked' : 'locked';
    } catch (e) {
      view.app = appState(e);
      if (view.app === 'error') view.error = (e as Error).message;
    }
  }
  return { view, unlocked };
}

const vault = new ExtVault({
  readVault: async () => parseVault((await chrome.storage.local.get(STORE.vault))[STORE.vault]),
  writeVault: async (f) => { await chrome.storage.local.set({ [STORE.vault]: JSON.stringify(f) }); },
  loadLimiter: async (k) => {
    const all = ((await chrome.storage.local.get(STORE.limiter))[STORE.limiter] ?? {}) as Record<string, LimiterState>;
    return all[k] ?? { fails: 0, until: 0 };
  },
  saveLimiter: async (k, st) => {
    const all = ((await chrome.storage.local.get(STORE.limiter))[STORE.limiter] ?? {}) as Record<string, LimiterState>;
    await chrome.storage.local.set({ [STORE.limiter]: { ...all, [k]: st } });
  },
  loadNever: async () => ((await chrome.storage.local.get(STORE.never))[STORE.never] as string[] | undefined) ?? [],
  saveNever: async (list) => { await chrome.storage.local.set({ [STORE.never]: list }); },
  onChange: (status, lockAt) => {
    const live = status === 'unlocked' || status === 'second-factor';
    if (live && !keepalive) keepalive = setInterval(() => { void chrome.runtime.getPlatformInfo(); vault.expire(); }, KEEPALIVE_MS);
    if (!live && keepalive) { clearInterval(keepalive); keepalive = null; }
    if (live && lockAt) void chrome.alarms.create(LOCK_ALARM, { when: lockAt });
    else void chrome.alarms.clear(LOCK_ALARM);
  },
});

async function loadSettings(): Promise<void> {
  const raw = (await chrome.storage.local.get(STORE.settings))[STORE.settings] as Partial<ExtSettings> | undefined;
  settings = { ...DEFAULT_SETTINGS, ...(raw ?? {}) };
  settings.useDesktop = settings.useDesktop !== false;
  settings.autoLockMin = clampAutoLock(settings.autoLockMin);
  settings.autofillOrigins = (settings.autofillOrigins ?? []).filter(exactOrigin);
  vault.setSettings(settings);
}

async function saveSettings(patch: Partial<ExtSettings>): Promise<void> {
  settings = { ...settings, ...patch };
  settings.autoLockMin = clampAutoLock(settings.autoLockMin);
  settings.useDesktop = settings.useDesktop !== false;
  settings.autofillOrigins = [...new Set((settings.autofillOrigins ?? []).filter(exactOrigin))];
  vault.setSettings(settings);
  await chrome.storage.local.set({ [STORE.settings]: settings });
  await syncContentScripts();
}

/** The inline button runs only on origins the user approved and Chrome still grants. */
async function syncContentScripts(): Promise<void> {
  const granted: string[] = [];
  for (const o of settings.autofillOrigins) {
    if (await chrome.permissions.contains({ origins: [`${o}/*`] }).catch(() => false)) granted.push(o);
  }
  await chrome.scripting.unregisterContentScripts({ ids: [SCRIPT_ID] }).catch(() => undefined);
  if (!granted.length) return;
  await chrome.scripting.registerContentScripts([{
    id: SCRIPT_ID, matches: granted.map((o) => `${o}/*`), js: ['content.js'], runAt: 'document_idle', allFrames: false, persistAcrossSessions: true,
  }]);
}

const ready = (async () => {
  await loadSettings();
  await vault.load();
  chrome.idle.setDetectionInterval(60);
  await syncContentScripts().catch(() => undefined);
})();

async function badge(tabId: number): Promise<void> {
  const on = vault.hasOffer(tabId);
  await chrome.action.setBadgeBackgroundColor({ color: '#c44dd4', tabId }).catch(() => undefined);
  await chrome.action.setBadgeText({ text: on ? '1' : '', tabId }).catch(() => undefined);
}

async function runInTab(tabId: number): Promise<unknown> {
  await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ['content.js'] });
  const r = await chrome.tabs.sendMessage<Reply>(tabId, { type: 'pevv-run' }, { frameId: 0 });
  if (!r || !r.ok) throw new Error(r && !r.ok ? r.error : 'The page did not answer.');
  return r.value;
}

async function appMatches(origin: string): Promise<LoginRef[]> {
  try { return asRefs((await link.request<{ logins?: AppLogin[] }>('match', { origin })).logins, origin); } catch { return []; }
}

async function popupState(tabId: number | null, url: string | null): Promise<PopupState> {
  const origin = originOf(url);
  const { view, unlocked } = await linkView();
  const base = { settings, origin, autofillHere: !!origin && settings.autofillOrigins.includes(origin), link: view };
  if (view.mode === 'app') {
    // The app owns the vault: this browser's copy is not consulted, and no offer is kept here.
    return { ...base, status: unlocked ? 'unlocked' : 'locked', blocked: null, error: view.error, lockAt: null, matches: unlocked && origin ? await appMatches(origin) : [], offer: null };
  }
  return { ...base, status: vault.status, blocked: vault.blocked, error: vault.error, lockAt: vault.lockAt, matches: vault.matches(origin), offer: vault.offerFor(tabId) };
}

const linkSnapshot = async (): Promise<LinkView> => (await linkView()).view;

async function onPopup(m: PopupRequest): Promise<unknown> {
  switch (m.type) {
    case 'state': return popupState(m.tabId, m.url);
    case 'unlock': return vault.unlock(m.password);
    case 'totp': return vault.verifyCode(m.code);
    case 'lock':
      if (await linkedMode()) { await link.request('lock').catch(() => undefined); return 'locked'; }
      vault.lock(); return vault.status;
    case 'link-enable':
      await saveSettings({ useDesktop: true });
      if (await hasNativePermission() && !(await link.isPaired())) await link.startPair();
      return linkSnapshot();
    case 'link-disable': await saveSettings({ useDesktop: false }); link.close(); return linkSnapshot();
    case 'link-pair': await link.startPair(); return linkSnapshot();
    case 'link-unlock': await link.request('unlock-request'); return linkSnapshot();
    case 'link-launch': await link.launch(); return linkSnapshot();
    case 'link-forget': await link.forget(); link.close(); return linkSnapshot();
    case 'search': vault.touch(); return vault.search(m.q, originOf(m.url));
    case 'fill': {
      const origin = originOf(m.url);
      if (!origin) throw new Error('PEVV only fills http and https pages.');
      if (await linkedMode()) {
        appTickets.set(m.tabId, { kind: 'login', origin, id: m.id, exp: Date.now() + TICKET_MS });
        try { return await runInTab(m.tabId); } finally { appTickets.delete(m.tabId); }
      }
      vault.issueFill(m.tabId, origin, m.id);
      try { return await runInTab(m.tabId); } finally { vault.dropTicket(m.tabId); }
    }
    case 'fill-generated': {
      const origin = originOf(m.url);
      if (!origin) throw new Error('PEVV only fills http and https pages.');
      if (await linkedMode()) {
        appTickets.set(m.tabId, { kind: 'generated', origin, password: m.password, exp: Date.now() + TICKET_MS });
        try { return await runInTab(m.tabId); } finally { appTickets.delete(m.tabId); }
      }
      vault.issueGenerated(m.tabId, origin, m.password);
      try { return await runInTab(m.tabId); } finally { vault.dropTicket(m.tabId); void badge(m.tabId); }
    }
    case 'offer': {
      if (m.action === 'save') await vault.acceptOffer(m.tabId);
      else if (m.action === 'never') await vault.neverOffer(m.tabId);
      else vault.dismissOffer(m.tabId);
      await badge(m.tabId);
      return true;
    }
    case 'settings': await saveSettings(m.patch); return settings;
  }
}

/** A page redeems a linked-mode ticket: the login comes from the app now, for exactly this origin. */
async function redeemFromApp(t: AppTicket, origin: string): Promise<Redeemed> {
  if (t.exp < Date.now()) throw new Error('Nothing to fill. Choose the login in PEVV again.');
  if (t.origin !== origin) throw new Error('The page changed before the fill.');
  if (t.kind === 'generated') {
    // The app shows the save offer; this side keeps nothing.
    void link.request('save-offer', { origin, username: '', password: t.password }).catch(() => undefined);
    return { kind: 'generated', password: t.password };
  }
  const r = await link.request<{ username?: string; password?: string }>('fill', { origin, id: t.id }).catch((e: unknown) => {
    const code = e instanceof LinkError ? e.code : '';
    throw new Error(code === 'locked' ? 'The PEVV desktop app is locked.' : code === 'no-match' ? 'That login is not saved for this site.' : 'The PEVV desktop app did not give the login.');
  });
  return { kind: 'login', username: r.username ?? '', password: r.password ?? '' };
}

async function onContent(m: ContentRequest, tabId: number, origin: string): Promise<unknown> {
  const approved = settings.autofillOrigins.includes(origin);
  const linked = await linkedMode();
  switch (m.type) {
    case 'cs-hello': return { inline: approved };
    case 'cs-redeem': {
      const t = appTickets.get(tabId);
      if (t) { appTickets.delete(tabId); return redeemFromApp(t, origin); }
      return vault.redeem(tabId, origin);
    }
    case 'cs-list':
      if (!approved) throw new Error('Autofill is off for this site.');
      if (linked) {
        try { return asRefs((await link.request<{ logins?: AppLogin[] }>('match', { origin })).logins, origin); } catch (e) {
          throw new Error(e instanceof LinkError && e.code === 'locked' ? 'locked' : 'The PEVV desktop app is not available.');
        }
      }
      if (vault.status !== 'unlocked') throw new Error('locked');
      return vault.matches(origin);
    case 'cs-fill':
      if (!approved) throw new Error('Autofill is off for this site.');
      if (linked) return redeemFromApp({ kind: 'login', origin, id: m.id, exp: Date.now() + TICKET_MS }, origin);
      return vault.fillById(origin, m.id);
    case 'cs-offer': {
      if (!approved) return false;
      if (linked) {
        if (!m.password) return false;
        return link.request('save-offer', { origin, username: m.username, password: m.password }).then(() => true, () => false);
      }
      const ok = await vault.offerSave(tabId, origin, m.username, m.password);
      await badge(tabId);
      return ok;
    }
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;
  const fromPage = !!sender.tab && !(sender.url ?? '').startsWith(chrome.runtime.getURL(''));
  const run = async (): Promise<unknown> => {
    await ready;
    vault.expire();
    if (fromPage) {
      // Top frame only; the origin comes from Chrome, never from the message.
      const tabId = sender.tab?.id;
      const origin = sender.origin ?? originOf(sender.url);
      if (tabId === undefined || sender.frameId !== 0 || !origin || originOf(origin) !== origin) throw new Error('PEVV only fills the top page.');
      return onContent(msg as ContentRequest, tabId, origin);
    }
    return onPopup(msg as PopupRequest);
  };
  run().then(
    (value) => sendResponse({ ok: true, value } satisfies Reply),
    (e: Error) => sendResponse({ ok: false, error: e.message } satisfies Reply),
  );
  return true;
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !(STORE.vault in changes)) return;
  void ready.then(() => vault.external(parseVault(changes[STORE.vault]!.newValue)));
});

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name !== LOCK_ALARM) return;
  void ready.then(() => { if (!vault.expire() && vault.lockAt !== null && Date.now() >= vault.lockAt) vault.lock(); });
});

// Screen locked → lock. ("idle" alone does not lock; the auto-lock timer covers it.)
chrome.idle.onStateChanged.addListener((s) => { if (s === 'locked') vault.lock(); });

// Last browser window closed → lock, even if Chrome keeps running in the background.
chrome.windows.onRemoved.addListener(() => {
  void chrome.windows.getAll().then((w) => { if (w.length === 0) vault.lock(); });
});

chrome.tabs.onRemoved.addListener((tabId) => { vault.forgetTab(tabId); vault.dismissOffer(tabId); });

// Chrome can close the popup while its permission prompt is open, so the popup
// may never send the new list. A site granted here (or in Chrome's own "Site
// access" menu) is the user's approval for that one origin.
chrome.permissions.onAdded.addListener((p) => {
  const added = (p.origins ?? []).map((o) => originOf(o.replace(/\/\*$/, '/'))).filter((o): o is string => !!o && exactOrigin(o));
  if (!added.length) return;
  void ready.then(() => saveSettings({ autofillOrigins: [...settings.autofillOrigins, ...added] }));
});

chrome.permissions.onRemoved.addListener((p) => {
  const gone = new Set((p.origins ?? []).map((o) => originOf(o.replace(/\/\*$/, '/'))).filter(Boolean));
  if (!gone.size) return;
  void ready.then(() => saveSettings({ autofillOrigins: settings.autofillOrigins.filter((o) => !gone.has(o)) }));
});

chrome.runtime.onSuspend.addListener(() => vault.lock());
