/**
 * PEVV extension popup: locked / search / generate. It talks only to the
 * service worker. It never receives a stored password; fills go straight from
 * the worker to the page.
 */
import { PevvLogo } from '../brand/PevvLogo';
import { StrictMode, useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '@/styles/globals.css';
import { DEFAULT_GEN, generatePassword, strength } from '../gen';
import { type LinkView, type LoginRef, type PopupRequest, type PopupState, type Reply, originOf } from './protocol';

const btn = 'inline-flex min-h-8 items-center justify-center gap-1 rounded-md border border-cyan-500/30 bg-space-surface/60 px-2.5 text-xs text-cyan-50 hover:bg-accent-cyan/15 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-cyan disabled:opacity-40';
const btnPrimary = 'inline-flex min-h-8 items-center justify-center gap-1 rounded-md border border-accent-cyan/60 bg-accent-cyan/20 px-2.5 text-xs font-semibold text-accent-cyan hover:bg-accent-cyan/30 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-cyan disabled:opacity-40';
const input = 'min-h-8 w-full rounded-md border border-space-border bg-space-deep/80 px-2 text-sm text-ink-primary placeholder:text-ink-muted focus:border-accent-cyan focus:outline-none';

async function call<T>(m: PopupRequest): Promise<T> {
  const r = await chrome.runtime.sendMessage<Reply<T>>(m);
  if (!r) throw new Error('PEVV did not answer. Try again.');
  if (!r.ok) throw new Error(r.error);
  return r.value;
}

interface Tab { id: number | null; url: string | null }

function openVaultScreen(): void {
  void chrome.tabs.create({ url: chrome.runtime.getURL('extension/vault.html') });
  window.close();
}

function hostOf(origin: string | null): string {
  if (!origin) return '';
  try { return new URL(origin).host; } catch { return origin; }
}

function Locked({ st, refresh }: { st: PopupState; refresh: () => void }) {
  const [pw, setPw] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const go = async (m: PopupRequest) => {
    setBusy(true); setErr(null);
    try { await call(m); setPw(''); setCode(''); refresh(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  if (st.status === 'none') {
    return (
      <div className="flex flex-col gap-2" data-testid="ext-none">
        <p className="text-sm text-ink-secondary">There is no vault in this browser yet.</p>
        <p className="text-xs text-ink-muted">Open the vault screen to scan a vault QR from your phone or the site, open an encrypted export, or make a new vault.</p>
        <button type="button" className={btnPrimary} onClick={openVaultScreen} data-testid="ext-open-vault">Open the vault screen</button>
      </div>
    );
  }
  if (st.status === 'second-factor') {
    return (
      <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); void go({ type: 'totp', code }); }} data-testid="ext-2fa">
        <label className="flex flex-col gap-1 text-xs text-ink-secondary">Authenticator code
          <input className={input} inputMode="numeric" autoComplete="one-time-code" autoFocus value={code} onChange={(e) => setCode(e.target.value)} data-testid="ext-totp" />
        </label>
        <button type="submit" className={btnPrimary} disabled={busy || code.length < 6}>Verify</button>
        {err && <p className="text-xs text-red-300" role="alert" data-testid="ext-error">{err}</p>}
      </form>
    );
  }
  return (
    <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); void go({ type: 'unlock', password: pw }); }} data-testid="ext-locked">
      <label className="flex flex-col gap-1 text-xs text-ink-secondary">Master password
        <input className={input} type="password" autoComplete="current-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} data-testid="ext-password" />
      </label>
      <button type="submit" className={btnPrimary} disabled={busy || !pw} data-testid="ext-unlock">{busy ? 'Unlocking…' : 'Unlock'}</button>
      {(err ?? st.blocked) && <p className="text-xs text-red-300" role="alert" data-testid="ext-error">{err ?? st.blocked}</p>}
      <p className="text-[0.65rem] text-ink-muted">Recovery code or kit? Use the <button type="button" className="underline" onClick={openVaultScreen}>vault screen</button>.</p>
    </form>
  );
}

function LoginRow({ l, tab, onDone }: { l: LoginRef; tab: Tab; onDone: (msg: string, err?: boolean) => void }) {
  const fill = async () => {
    if (tab.id === null || !tab.url) return;
    try { await call({ type: 'fill', tabId: tab.id, url: tab.url, id: l.id }); window.close(); }
    catch (e) { onDone((e as Error).message, true); }
  };
  return (
    <li className="flex items-center gap-2 rounded-md px-1 py-1 hover:bg-space-surface/60" data-testid="ext-login">
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm text-cyan-50">{l.title}</p>
        <p className="truncate text-[0.65rem] text-ink-muted">{[l.username, l.matches ? '' : hostOf(l.site) || l.site].filter(Boolean).join(' · ')}</p>
      </div>
      {l.matches
        ? <button type="button" className={btnPrimary} onClick={() => void fill()} data-testid="ext-fill">Fill</button>
        : <span className="text-[0.6rem] text-ink-muted" title="PEVV fills a login only on the site it was saved for.">other site</span>}
    </li>
  );
}

function Generator({ tab, onDone }: { tab: Tab; onDone: (msg: string, err?: boolean) => void }) {
  const [len, setLen] = useState(DEFAULT_GEN.length);
  const [symbols, setSymbols] = useState(true);
  const [pw, setPw] = useState(() => generatePassword(DEFAULT_GEN));
  const regen = useCallback((l = len, s = symbols) => setPw(generatePassword({ ...DEFAULT_GEN, length: l, symbols: s })), [len, symbols]);
  const fill = async () => {
    if (tab.id === null || !tab.url) return;
    try { await call({ type: 'fill-generated', tabId: tab.id, url: tab.url, password: pw }); onDone('Filled. PEVV will offer to save it.'); }
    catch (e) { onDone((e as Error).message, true); }
  };
  const s = strength(pw);
  return (
    <section className="flex flex-col gap-2 rounded-md border border-space-border p-2" data-testid="ext-generator">
      <h2 className="text-xs font-medium text-ink-secondary">Generate</h2>
      <code className="break-all rounded bg-space-deep px-2 py-1 font-mono text-xs text-cyan-100" data-testid="ext-generated">{pw}</code>
      <p className="text-[0.62rem] text-ink-muted">{Math.round(s.bits)} bits</p>
      <div className="flex items-center gap-2 text-xs text-ink-secondary">
        <input type="range" min={12} max={64} value={len} aria-label="Length" onChange={(e) => { const l = Number(e.target.value); setLen(l); regen(l, symbols); }} />
        <span className="w-6 text-right">{len}</span>
        <label className="flex items-center gap-1"><input type="checkbox" checked={symbols} onChange={(e) => { setSymbols(e.target.checked); regen(len, e.target.checked); }} />!@#</label>
      </div>
      <div className="flex gap-2">
        <button type="button" className={btn} onClick={() => regen()}>New</button>
        <button type="button" className={btnPrimary} disabled={tab.id === null || !originOf(tab.url)} onClick={() => void fill()} data-testid="ext-fill-generated">Fill the focused field</button>
      </div>
    </section>
  );
}

function Unlocked({ st, tab, refresh }: { st: PopupState; tab: Tab; refresh: () => void }) {
  const [q, setQ] = useState('');
  const [found, setFound] = useState<LoginRef[] | null>(null);
  const [msg, setMsg] = useState<{ text: string; err: boolean } | null>(null);
  const done = (text: string, err = false) => setMsg({ text, err });
  useEffect(() => {
    if (!q.trim()) { setFound(null); return; }
    let live = true;
    void call<LoginRef[]>({ type: 'search', q, url: tab.url }).then((r) => { if (live) setFound(r); });
    return () => { live = false; };
  }, [q, tab.url]);
  const offer = async (action: 'save' | 'dismiss' | 'never') => {
    if (tab.id === null) return;
    try { await call({ type: 'offer', tabId: tab.id, action }); if (action === 'save') done('Saved to the vault.'); refresh(); }
    catch (e) { done((e as Error).message, true); }
  };
  const toggleAutofill = async (on: boolean) => {
    const origin = st.origin;
    if (!origin) return;
    try {
      const perm = { origins: [`${origin}/*`] };
      if (on && !(await chrome.permissions.request(perm))) { done('Chrome did not grant access to this site.', true); return; }
      if (!on) await chrome.permissions.remove(perm).catch(() => false);
      const list = on ? [...st.settings.autofillOrigins, origin] : st.settings.autofillOrigins.filter((o) => o !== origin);
      await call({ type: 'settings', patch: { autofillOrigins: list } });
      done(on ? 'Reload the page to see the fill button.' : 'Autofill is off for this site.');
      refresh();
    } catch (e) { done((e as Error).message, true); }
  };
  const list = found ?? st.matches;
  return (
    <div className="flex flex-col gap-2" data-testid="ext-unlocked">
      {st.offer && (
        <section className="flex flex-col gap-1.5 rounded-md border border-accent-gold/50 bg-accent-gold/5 p-2" data-testid="ext-offer">
          <p className="text-xs text-accent-gold">{st.offer.update ? 'Update the saved password' : 'Save this login'} for <b>{hostOf(st.offer.origin)}</b>{st.offer.username ? ` (${st.offer.username})` : ''}?</p>
          <div className="flex flex-wrap gap-1.5">
            <button type="button" className={btnPrimary} onClick={() => void offer('save')} data-testid="ext-offer-save">{st.offer.update ? 'Update' : 'Save'}</button>
            <button type="button" className={btn} onClick={() => void offer('dismiss')}>Not now</button>
            <button type="button" className={btn} onClick={() => void offer('never')}>Never for this site</button>
          </div>
        </section>
      )}
      {st.link.mode !== 'app' && <input type="search" className={input} placeholder="Search logins" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search logins" data-testid="ext-search" />}
      <section>
        <h2 className="mb-1 text-xs font-medium text-ink-secondary">{found ? 'Results' : st.origin ? `For ${hostOf(st.origin)}` : 'This page cannot be filled'}</h2>
        {list.length ? <ul className="flex max-h-52 flex-col overflow-y-auto">{list.map((l) => <LoginRow key={l.id} l={l} tab={tab} onDone={done} />)}</ul>
          : <p className="text-xs text-ink-muted" data-testid="ext-no-match">{found ? 'Nothing found.' : 'No login saved for this site.'}</p>}
      </section>
      {msg && <p className={`text-xs ${msg.err ? 'text-red-300' : 'text-accent-green'}`} role="status" data-testid="ext-msg">{msg.text}</p>}
      <Generator tab={tab} onDone={done} />
      {st.origin && (
        <label className="flex items-start gap-2 text-[0.7rem] text-ink-secondary">
          <input type="checkbox" className="mt-0.5" checked={st.autofillHere} onChange={(e) => void toggleAutofill(e.target.checked)} data-testid="ext-autofill-here" />
          Show the fill button and save offers on {hostOf(st.origin)}
        </label>
      )}
    </div>
  );
}

const LINK_TEXT: Record<string, string> = {
  'host-missing': 'The PEVV desktop app is not installed, or its browser link is switched off (open the app and check Settings, Browser link).',
  'host-forbidden': 'This browser does not allow this extension to talk to the PEVV desktop app. Reinstall the app, or check that this is the official PEVV extension.',
  'app-not-running': 'The PEVV desktop app is not running.',
  'pair-denied': 'Pairing was declined in the desktop app.',
  busy: 'The desktop app is already asking about another pairing.',
  timeout: 'The desktop app did not answer in time.',
  disabled: 'The browser link is switched off in the desktop app.',
  'origin-denied': 'The desktop app does not accept this extension.',
};

/** Desktop-app link: turn it on, pair it, and show what the app is doing. */
function LinkBox({ link, refresh }: { link: LinkView; refresh: () => void }) {
  const [err, setErr] = useState<string | null>(null);
  const waiting = link.pairing?.state === 'waiting';
  const locked = link.mode === 'app' && link.app === 'locked';
  useEffect(() => {
    if (!waiting && !locked) return;
    const t = setInterval(refresh, 1500);
    return () => clearInterval(t);
  }, [waiting, locked, refresh]);
  const run = async (m: PopupRequest) => {
    setErr(null);
    try { await call(m); } catch (e) { setErr((e as Error).message); }
    refresh();
  };
  // The permission prompt needs this click, so it is requested here, not in the worker.
  const enable = async () => {
    setErr(null);
    try {
      if (!(await chrome.permissions.request({ permissions: ['nativeMessaging'] }))) { setErr('Chrome did not allow talking to the desktop app.'); return; }
      await call({ type: 'link-enable' });
    } catch (e) { setErr((e as Error).message); }
    refresh();
  };
  const own = <button type="button" className={btn} onClick={() => void run({ type: 'link-disable' })} data-testid="ext-link-off">Use this browser&apos;s vault instead</button>;
  const note = err ? <p className="text-xs text-red-300" role="alert">{err}</p> : null;
  if (link.mode === 'app') {
    const say = (t: string) => <p className="text-xs text-ink-secondary" data-testid="ext-link-state">{t}</p>;
    if (link.app === 'unlocked') {
      return <div className="flex items-center gap-2 text-[0.65rem] text-ink-muted" data-testid="ext-link-app">PEVV desktop app: unlocked <span className="flex-1" />{own}</div>;
    }
    return (
      <section className="flex flex-col gap-2 rounded-md border border-space-border p-2" data-testid="ext-link-app" data-app={link.app ?? 'unknown'}>
        {link.app === 'locked' && say('The PEVV desktop app is locked. Unlock it there; this popup follows.')}
        {link.app === 'not-running' && say(LINK_TEXT['app-not-running']!)}
        {(link.app === 'host-missing' || link.app === 'host-forbidden') && say(LINK_TEXT[link.app]!)}
        {link.app === 'error' && say(link.error ? (LINK_TEXT[link.error] ?? link.error) : 'The desktop app did not answer.')}
        {note}
        <div className="flex flex-wrap gap-1.5">
          {(link.app === 'locked' || link.app === 'not-running') && <button type="button" className={btnPrimary} onClick={() => void run({ type: 'link-unlock' })} data-testid="ext-link-unlock">{link.app === 'locked' ? 'Unlock in the app' : 'Start and unlock'}</button>}
          {link.app === 'not-running' && <button type="button" className={btn} onClick={() => void run({ type: 'link-launch' })}>Start the app</button>}
          {link.app && link.app !== 'locked' && link.app !== 'not-running' && <button type="button" className={btn} onClick={() => void run({ type: 'link-forget' })}>Unpair</button>}
          {own}
        </div>
      </section>
    );
  }
  if (link.permission && link.enabled && !link.paired) {
    const p = link.pairing;
    return (
      <section className="flex flex-col gap-2 rounded-md border border-accent-cyan/40 p-2" data-testid="ext-link-pair">
        {waiting && p ? (
          <>
            <p className="text-xs text-ink-secondary">Check that the PEVV desktop app shows this code, then approve it there.</p>
            <code className="rounded bg-space-deep px-2 py-1 text-center font-mono text-sm tracking-widest text-cyan-100" data-testid="ext-link-code">{p.fingerprint}</code>
          </>
        ) : (
          <>
            <p className="text-xs text-ink-secondary">{p ? (LINK_TEXT[p.error ?? ''] ?? 'Pairing did not finish.') : 'Pair this browser with the PEVV desktop app.'}</p>
            <button type="button" className={btnPrimary} onClick={() => void run({ type: 'link-pair' })} data-testid="ext-link-pair-go">Pair with the desktop app</button>
          </>
        )}
        {note}
        <button type="button" className={btn} onClick={() => void run({ type: 'link-disable' })}>Not now</button>
      </section>
    );
  }
  return (
    <div className="flex flex-col gap-1" data-testid="ext-link-offer">
      <button type="button" className={btn} onClick={() => void enable()} title="Needs Chrome's permission to talk to the PEVV desktop app. The vault stays in the app.">Use the PEVV desktop app</button>
      {note}
    </div>
  );
}

function Popup() {
  const [tab, setTab] = useState<Tab>({ id: null, url: null });
  const [st, setSt] = useState<PopupState | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const refresh = useCallback(() => {
    void (async () => {
      try {
        const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
        const cur = { id: t?.id ?? null, url: t?.url ?? null };
        setTab(cur);
        setSt(await call<PopupState>({ type: 'state', tabId: cur.id, url: cur.url }));
      } catch (e) { setErr((e as Error).message); }
    })();
  }, []);
  useEffect(() => { refresh(); }, [refresh]);
  const minutes = st?.lockAt ? Math.max(1, Math.round((st.lockAt - Date.now()) / 60_000)) : null;
  return (
    <div className="flex w-[340px] flex-col gap-3 bg-[#070b16] p-3 text-ink-primary" data-testid="ext-popup" data-status={st?.status ?? 'loading'}>
      <header className="flex items-center gap-2">
        <span className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-accent-cyan"><PevvLogo size={20} small /> PEVV</span>
        <span className="flex-1" />
        <button type="button" className={btn} onClick={openVaultScreen} title="Items, import, QR, settings">Vault</button>
        {st?.status === 'unlocked' && <button type="button" className={btn} onClick={() => void call({ type: 'lock' }).then(refresh)} aria-label="Lock now" data-testid="ext-lock">🔒</button>}
      </header>
      {err && <p className="text-xs text-red-300">{err}</p>}
      {st && <LinkBox link={st.link} refresh={refresh} />}
      {!st ? <p className="text-xs text-ink-muted">Loading</p>
        : st.status === 'unlocked' ? <Unlocked st={st} tab={tab} refresh={refresh} />
          : st.link.mode === 'app' ? null
            : <Locked st={st} refresh={refresh} />}
      {st && st.status !== 'none' && st.link.mode !== 'app' && (
        <footer className="flex items-center gap-2 border-t border-space-border/60 pt-2 text-[0.62rem] text-ink-muted">
          <span className="flex-1">{minutes ? `Locks in ${minutes} min, or when the screen locks.` : 'Locked.'}</span>
          <label className="flex items-center gap-1">Auto-lock
            <select className="rounded bg-space-deep px-1 text-ink-secondary" value={st.settings.autoLockMin} onChange={(e) => void call({ type: 'settings', patch: { autoLockMin: Number(e.target.value) } }).then(refresh)} data-testid="ext-autolock">
              {[1, 2, 5, 10, 15, 30, 60].map((m) => <option key={m} value={m}>{m} min</option>)}
            </select>
          </label>
        </footer>
      )}
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<StrictMode><Popup /></StrictMode>);
