/** The CSP from tauri.conf.json with `connect-src` widened to the sync origin (https + wss), or unchanged. Kept free of Vite so unit tests can import it. */
export function cspFor(baseCsp, syncUrl) {
  if (!syncUrl) return baseCsp;
  let u;
  try { u = new URL(syncUrl); } catch { throw new Error(`VITE_PEVV_SYNC_URL is not a URL: ${syncUrl}`); }
  if (u.protocol !== 'https:') throw new Error('VITE_PEVV_SYNC_URL must be https:// for the desktop build');
  const extra = `${u.origin} wss://${u.host}`;
  return baseCsp.replace(/connect-src ([^;]*)/, (_m, v) => `connect-src ${v} ${extra}`);
}
