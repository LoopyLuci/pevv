/**
 * Messages between the PEVV extension's popup, content script and service
 * worker. Only the worker holds the vault key. The content script never gets
 * more than one username and password, and only for its own top-level origin.
 */

/** chrome.storage.local keys. Only ciphertext and non-secret settings live here. */
export const STORE = {
  vault: 'pevv.vault',
  settings: 'pevv.settings',
  never: 'pevv.never',
  limiter: 'pevv.limit',
  /** Pairing with the desktop app: the shared secret and the request counter. Never the vault. */
  link: 'pevv.link',
} as const;

export interface ExtSettings {
  /** Minutes of no use before the worker forgets the key. 1–60. There is no "never". */
  autoLockMin: number;
  /** Origins the user approved for the inline fill button and save offers. */
  autofillOrigins: string[];
  /** Use the PEVV desktop app (when linked) instead of this browser's own copy of the vault. */
  useDesktop: boolean;
}

export const DEFAULT_SETTINGS: ExtSettings = { autoLockMin: 5, autofillOrigins: [], useDesktop: true };
export const AUTO_LOCK_MIN = 1;
export const AUTO_LOCK_MAX = 60;

export type ExtStatus = 'none' | 'locked' | 'second-factor' | 'unlocked';

/** What the popup may see about a login. Never the password. */
export interface LoginRef { id: string; title: string; username: string; site: string; matches: boolean }

export interface OfferView { origin: string; username: string; update: boolean; title: string; locked: boolean }

/** The desktop app as the popup sees it. */
export type AppState = 'unlocked' | 'locked' | 'not-running' | 'host-missing' | 'host-forbidden' | 'error';

export interface LinkView {
  /** Chrome has granted the optional nativeMessaging permission. */
  permission: boolean;
  /** The "Use the PEVV desktop app" setting. */
  enabled: boolean;
  /** A shared secret with the app exists. */
  paired: boolean;
  /** Fills and logins come from the app (enabled, permitted and paired). */
  mode: 'app' | 'standalone';
  app: AppState | null;
  /** While pairing: the code the app shows too. */
  pairing: { fingerprint: string; state: 'waiting' | 'denied' | 'error'; error: string | null } | null;
  error: string | null;
}

export interface PopupState {
  status: ExtStatus;
  /** Plain reason when the vault cannot be unlocked here (e.g. it requires a passkey). */
  blocked: string | null;
  error: string | null;
  lockAt: number | null;
  settings: ExtSettings;
  origin: string | null;
  matches: LoginRef[];
  offer: OfferView | null;
  autofillHere: boolean;
  link: LinkView;
}

export type PopupRequest =
  | { type: 'state'; tabId: number | null; url: string | null }
  | { type: 'unlock'; password: string }
  | { type: 'totp'; code: string }
  | { type: 'lock' }
  | { type: 'search'; q: string; url: string | null }
  | { type: 'fill'; tabId: number; url: string; id: string }
  | { type: 'fill-generated'; tabId: number; url: string; password: string }
  | { type: 'offer'; tabId: number; action: 'save' | 'dismiss' | 'never' }
  | { type: 'settings'; patch: Partial<ExtSettings> }
  /** Turn the desktop link on (the popup asked Chrome for the permission first) and pair if needed. */
  | { type: 'link-enable' }
  | { type: 'link-disable' }
  | { type: 'link-pair' }
  /** Ask the app to come forward so the person can unlock it (starts it if it is not running). */
  | { type: 'link-unlock' }
  | { type: 'link-launch' }
  /** Drop the pairing on this side. */
  | { type: 'link-forget' };

export type ContentRequest =
  /** First message from a page: is the inline button allowed on this origin? */
  | { type: 'cs-hello' }
  /** Redeem the one-time ticket the popup created for this tab. */
  | { type: 'cs-redeem' }
  /** Inline button (approved hosts): logins for this page, titles only. */
  | { type: 'cs-list' }
  /** Inline button: one login, by id, for this page. */
  | { type: 'cs-fill'; id: string }
  /** A form with a password was submitted. */
  | { type: 'cs-offer'; username: string; password: string };

export type ContentCommand = { type: 'pevv-run' };

export type Redeemed =
  | { kind: 'login'; username: string; password: string }
  | { kind: 'generated'; password: string };

export type Reply<T = unknown> = { ok: true; value: T } | { ok: false; error: string };

export function originOf(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    return u.origin;
  } catch {
    return null;
  }
}

export function clampAutoLock(min: number): number {
  if (!Number.isFinite(min)) return DEFAULT_SETTINGS.autoLockMin;
  return Math.min(AUTO_LOCK_MAX, Math.max(AUTO_LOCK_MIN, Math.round(min)));
}
