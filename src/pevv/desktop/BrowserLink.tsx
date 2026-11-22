/**
 * Desktop-only UI for the browser-extension link: the prompts the person must answer (approve a
 * pairing, save a login the extension offered) and the settings section. Plain English: this is
 * a security prompt for the one app that ships it.
 */
import { useCallback, useEffect, useState } from 'react';
import { usePevv } from '../store';
import { Section, btn, btnDanger, btnPrimary } from '../ui/common';
import { acceptOffer, answerPrompt, dropOffer, hostOf, linkIpc, useLinkUi, type LinkState } from './link';

/** Modal cards over the whole window. Rendered in their own React root by the desktop boot. */
export function LinkPrompts() {
  const { prompts, offers } = useLinkUi();
  const unlocked = usePevv((s) => s.status === 'unlocked');
  const [err, setErr] = useState<string | null>(null);
  if (!prompts.length && !offers.length) return null;
  return (
    <div className="fixed inset-0 z-[9999] flex flex-col items-center justify-center gap-3 bg-black/60 p-4" role="dialog" aria-modal="true" data-testid="link-prompts">
      {prompts.map((p) => (
        <section key={p.id} className="flex w-full max-w-md flex-col gap-3 rounded-lg border border-accent-cyan/50 bg-[#0b1226] p-4 text-ink-primary" data-testid="link-pair-prompt">
          <h2 className="text-sm font-semibold text-accent-cyan">Link a browser extension?</h2>
          <p className="text-xs text-ink-secondary">The PEVV browser extension wants to use this app to fill logins. Approve only if the extension in your browser shows this same code.</p>
          <code className="rounded bg-space-deep px-3 py-2 text-center font-mono text-lg tracking-widest text-cyan-100" data-testid="link-fingerprint">{p.fingerprint}</code>
          <p className="break-all text-[0.65rem] text-ink-muted">Extension {p.extId}</p>
          <div className="flex gap-2">
            <button type="button" className={btnPrimary} onClick={() => void answerPrompt(p.id, true)} data-testid="link-approve">Approve</button>
            <button type="button" className={btnDanger} onClick={() => void answerPrompt(p.id, false)} data-testid="link-deny">Decline</button>
          </div>
        </section>
      ))}
      {offers.map((o) => (
        <section key={o.id} className="flex w-full max-w-md flex-col gap-2 rounded-lg border border-accent-gold/50 bg-[#0b1226] p-4 text-ink-primary" data-testid="link-offer">
          <h2 className="text-sm font-semibold text-accent-gold">Save this login?</h2>
          <p className="text-xs text-ink-secondary">The browser offered a login for <b>{hostOf(o.origin)}</b>{o.username ? ` (${o.username})` : ''}.</p>
          {!unlocked && <p className="text-xs text-accent-gold">Unlock PEVV to save it.</p>}
          {err && <p className="text-xs text-red-300" role="alert">{err}</p>}
          <div className="flex gap-2">
            <button type="button" className={btnPrimary} disabled={!unlocked} onClick={() => void acceptOffer(o.id).then(() => setErr(null), (e: Error) => setErr(e.message))} data-testid="link-offer-save">Save</button>
            <button type="button" className={btn} onClick={() => dropOffer(o.id)}>Not now</button>
          </div>
        </section>
      ))}
    </div>
  );
}

function ago(ms: number): string {
  return ms ? new Date(ms).toLocaleDateString() : '';
}

/** Settings: switch the browser link on or off, see what is registered, remove a pairing. */
export function BrowserLinkSection() {
  const [st, setSt] = useState<LinkState | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const call = useCallback(async (cmd: string, args?: Record<string, unknown>) => {
    const ipc = linkIpc();
    if (!ipc) return;
    try { setSt(await ipc.invoke<LinkState>(cmd, args)); setErr(null); } catch (e) { setErr(typeof e === 'string' ? e : (e as Error).message); }
  }, []);
  useEffect(() => { void call('link_state'); }, [call]);
  if (!linkIpc()) return null;
  return (
    <Section title="Browser extension link" testId="pevv-browser-link">
      <p className="text-xs text-ink-muted">Lets the PEVV extension in Chrome, Edge or Brave ask this app for logins. The vault stays here; the extension gets one login only after you unlock, only for the exact site it was saved for.</p>
      {st && (
        <>
          <label className="flex items-center gap-2 text-xs text-ink-secondary">
            <input type="checkbox" checked={st.enabled} disabled={!!st.unsupported} onChange={(e) => void call('link_set_enabled', { enabled: e.target.checked })} data-testid="pevv-browser-link-toggle" />
            Allow browser extensions to link to this app
          </label>
          {st.unsupported === 'appimage' && <p className="text-xs text-accent-gold">The AppImage build cannot register itself with browsers (its path changes on every start). Use the .deb package.</p>}
          {!st.hostExists && !st.unsupported && <p className="text-xs text-accent-gold">The link helper (pevv-native-host) was not found next to this app, so browsers cannot reach it.</p>}
          {st.serverError && <p className="text-xs text-red-300">The link could not start: {st.serverError}</p>}
          {st.enabled && st.registered.length > 0 && <p className="text-xs text-ink-secondary" data-testid="pevv-browser-link-registered">Registered for: {st.registered.join(', ')}.</p>}
          {st.paired.length > 0 && (
            <ul className="flex flex-col gap-1">
              {st.paired.map((p) => (
                <li key={p.extId} className="flex items-center gap-2 text-xs text-ink-secondary">
                  <span className="min-w-0 flex-1 truncate">Extension {p.extId}{p.at ? ` (paired ${ago(p.at)})` : ''}</span>
                  <button type="button" className={btnDanger} onClick={() => void call('link_unpair', { extId: p.extId })}>Remove</button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {err && <p className="text-xs text-red-300" role="alert">{err}</p>}
    </Section>
  );
}
