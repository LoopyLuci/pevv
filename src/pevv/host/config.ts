/**
 * Build-time configuration. Everything here is optional: with nothing set PEVV
 * is fully local (no network at all) and the sync / vault-QR relay features
 * report themselves as unavailable. See docs/SYNC_SELF_HOSTING.md.
 */
const env = import.meta.env as Record<string, string | undefined>;

const clean = (v: string | undefined): string => (v ?? '').trim();

/** Base URL of your Supabase project (https://<ref>.supabase.co). Empty = sync off. */
export const SYNC_URL = clean(env.VITE_PEVV_SYNC_URL).replace(/\/+$/, '');
/** The project's anon (public) key. Row Level Security is what protects the data, not this key. */
export const SYNC_ANON_KEY = clean(env.VITE_PEVV_SYNC_ANON_KEY);
/**
 * Public https URL of your hosted PEVV web app, for vault-QR links that another phone can open
 * (the extension, the desktop app and localhost cannot be opened from another device). Empty = the QR carries the bare code.
 */
export const PUBLIC_URL = clean(env.VITE_PEVV_PUBLIC_URL);

/** True when both sync values are present. */
export function syncConfigured(): boolean {
  return !!SYNC_URL && !!SYNC_ANON_KEY;
}
