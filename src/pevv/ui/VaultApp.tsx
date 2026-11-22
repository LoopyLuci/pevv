/**
 * PEVV main app: the whole vault UI (items, tools, devices, settings), mounted by every client.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { usePT } from '../i18n';
import type { EntryData, EntryType } from '../model';
import { answerEnvRequest, lock, touch, usePevv, type View } from '../store';
import { LockedView, SecondFactorView, SetPasswordView, SetupView } from './AuthViews';
import { PevvBrand } from '../brand/PevvLogo';
import { EntryDetail, EntryEditor, EnvToolbar, ItemList, Sidebar, TYPE_ICON, TYPE_LABEL, TYPE_ORDER, filterEntries, type Filter } from './ItemsView';
import { ActivityView, DevicesView, GeneratorView, HealthView, SettingsView } from './ToolsViews';
import { QrMove, QrWaitPanel } from './QrShare';
import { btn, btnPrimary, input } from './common';

function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [w, setW] = useState(900);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const m = () => setW(el.getBoundingClientRect().width || 900);
    m();
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(m) : null;
    ro?.observe(el);
    return () => ro?.disconnect();
  }, []);
  return [ref, w];
}

export function EnvRequestDialog() {
  const { t } = usePT();
  const req = usePevv((s) => s.envRequest);
  const status = usePevv((s) => s.status);
  if (!req || status !== 'unlocked') return null;
  return (
    <div className="absolute inset-0 z-20 flex items-center justify-center bg-black/60 p-3" role="alertdialog" aria-modal="true" aria-labelledby="pevv-envreq-title" data-testid="pevv-env-request">
      <div className="flex w-full max-w-md flex-col gap-3 rounded-xl border border-accent-gold/50 bg-space-deep p-4">
        <h3 id="pevv-envreq-title" className="font-display text-base text-accent-gold">{t('envReqTitle')}</h3>
        <p className="text-xs text-ink-secondary">{t('envReqBody', { program: req.programId })}</p>
        <ul className="flex flex-wrap gap-1">{req.names.map((n) => <li key={n} className="rounded bg-space-surface px-2 py-0.5 font-mono text-xs text-cyan-100">{n}</li>)}</ul>
        <p className="text-[0.62rem] text-ink-muted">{t('envReqNote')}</p>
        <div className="flex flex-wrap gap-2">
          <button type="button" className={btnPrimary} autoFocus onClick={() => void answerEnvRequest('once')} data-testid="pevv-env-allow-once">{t('allowOnce')}</button>
          <button type="button" className={btn} onClick={() => void answerEnvRequest('always')} data-testid="pevv-env-allow-always">{t('allowAlways')}</button>
          <button type="button" className={btn} onClick={() => void answerEnvRequest('deny')} data-testid="pevv-env-deny">{t('deny')}</button>
        </div>
      </div>
    </div>
  );
}

function Unlocked({ embedded }: { embedded?: boolean | undefined }) {
  const { t } = usePT();
  const entries = usePevv((s) => s.entries);
  const view = usePevv((s) => s.view);
  const selected = usePevv((s) => s.selected);
  const meta = usePevv((s) => s.meta);
  const warnings = usePevv((s) => s.warnings);
  const [filter, setFilter] = useState<Filter>({ kind: 'all' });
  const [q, setQ] = useState('');
  const [editing, setEditing] = useState<{ id: string | null; type: EntryType; prefill?: Partial<EntryData> } | null>(null);
  const [newMenu, setNewMenu] = useState(false);
  const [mobilePane, setMobilePane] = useState<'nav' | 'list' | 'detail'>('list');
  const [ref, width] = useWidth<HTMLDivElement>();
  const searchRef = useRef<HTMLInputElement>(null);
  const narrow = width < 680;
  const setView = (v: View) => { usePevv.setState({ view: v }); setEditing(null); if (narrow) setMobilePane(v === 'items' ? 'list' : 'detail'); };
  const select = (id: string | null) => { usePevv.setState({ selected: id, view: 'items' }); setEditing(null); if (narrow && id) setMobilePane('detail'); };
  const items = useMemo(() => filterEntries(entries, filter, q), [entries, filter, q]);
  const draft = usePevv((s) => s.draft);
  useEffect(() => {
    if (!draft) return;
    usePevv.setState({ draft: null, view: 'items' });
    setEditing({ id: null, type: 'env', prefill: { name: draft.name, ...(draft.env ? { env: draft.env } : {}) } });
    if (narrow) setMobilePane('detail');
  }, [draft, narrow]);
  const entry = entries.find((e) => e.id === selected) ?? null;
  const defaultEnv = filter.kind === 'env' ? filter.env : meta?.activeEnv ?? 'dev';

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const root = ref.current;
      if (!root || !root.isConnected || root.getClientRects().length === 0) return;
      if (e.key === '/' && !(e.target as HTMLElement)?.closest('input,textarea,select')) { e.preventDefault(); searchRef.current?.focus(); }
      if (e.altKey && (e.code === 'KeyN')) { e.preventDefault(); setEditing({ id: null, type: filter.kind === 'env' ? 'env' : 'login' }); usePevv.setState({ view: 'items' }); if (narrow) setMobilePane('detail'); }
      if (e.ctrlKey && e.shiftKey && e.code === 'KeyL') { e.preventDefault(); lock('manual'); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [filter, narrow, ref]);

  const startNew = (type: EntryType, prefill?: Partial<EntryData>) => {
    setNewMenu(false);
    usePevv.setState({ view: 'items' });
    setEditing({ id: null, type, ...(prefill ? { prefill } : {}) });
    if (narrow) setMobilePane('detail');
  };

  const main = (() => {
    if (view === 'generator') return <GeneratorView onUse={(pw) => startNew('login', { password: pw })} />;
    if (view === 'audit') return <HealthView onOpen={(id) => select(id)} />;
    if (view === 'settings') return <SettingsView />;
    if (view === 'qr') return <QrMove />;
    if (view === 'activity') return <ActivityView onOpen={(id) => select(id)} />;
    if (view === 'devices') return <DevicesView />;
    if (editing) {
      const ed = editing.id ? entries.find((e) => e.id === editing.id) ?? null : null;
      return (
        <EntryEditor
          key={editing.id ?? `new-${editing.type}`}
          entry={ed}
          {...(editing.prefill ? { prefill: editing.prefill } : {})}
          type={editing.type}
          defaultEnv={defaultEnv}
          onDone={(id) => { setEditing(null); if (id) usePevv.setState({ selected: id }); else if (narrow) setMobilePane('list'); }}
        />
      );
    }
    if (entry) return <EntryDetail entry={entry} onEdit={() => setEditing({ id: entry.id, type: entry.type })} {...(narrow ? { onBack: () => setMobilePane('list') } : {})} />;
    return <p className="m-auto p-6 text-center text-xs text-ink-muted">{t('selectItem')}</p>;
  })();

  const list = (
    <div className="flex h-full min-h-0 flex-col">
      {filter.kind === 'env' && view === 'items' && <EnvToolbar env={filter.env} />}
      <div className="min-h-0 flex-1 overflow-y-auto">
        <ItemList items={items} selected={selected} onSelect={(id) => select(id)} />
      </div>
    </div>
  );

  return (
    <div ref={ref} className="relative flex h-full min-h-0 w-full flex-col" onPointerDown={() => touch()} onKeyDown={() => touch()} data-testid="pevv-unlocked">
      <header className="flex shrink-0 flex-wrap items-center gap-2 border-b border-cyan-500/20 px-2 py-1.5">
        {narrow && <button type="button" className={btn} aria-label={t('vaultNav')} onClick={() => setMobilePane(mobilePane === 'nav' ? 'list' : 'nav')} data-testid="pevv-nav-toggle">☰</button>}
        {!embedded && <span className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-accent-cyan"><PevvBrand size={20} /> PEVV</span>}
        <input
          ref={searchRef}
          type="search"
          className={`${input} min-h-8 min-w-[8rem] flex-1`}
          placeholder={t('searchPh')}
          aria-label={t('search')}
          value={q}
          onChange={(e) => { setQ(e.target.value); if (view !== 'items') usePevv.setState({ view: 'items' }); if (narrow) setMobilePane('list'); }}
          data-testid="pevv-search"
        />
        <div className="relative">
          <button type="button" className={btnPrimary} aria-haspopup="menu" aria-expanded={newMenu} onClick={() => setNewMenu((v) => !v)} data-testid="pevv-new">＋ {t('new')}</button>
          {newMenu && (
            <div role="menu" className="absolute right-0 top-full z-30 mt-1 flex w-44 flex-col rounded-md border border-cyan-500/30 bg-space-deep p-1 shadow-lg">
              {TYPE_ORDER.map((ty) => (
                <button key={ty} type="button" role="menuitem" className="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs hover:bg-space-surface" onClick={() => startNew(ty)} data-testid={`pevv-new-${ty}`}>
                  <span aria-hidden className="w-4 text-center">{TYPE_ICON[ty]}</span>{t(TYPE_LABEL[ty])}
                </button>
              ))}
            </div>
          )}
        </div>
        <span className="hidden font-mono text-[0.62rem] text-ink-muted sm:inline" title={t('activeEnv')} data-testid="pevv-active-env">$ {meta?.activeEnv}</span>
        <button type="button" className={btn} onClick={() => setView('qr')} data-testid="pevv-open-qr">{t('qrMoveTitle')}</button>
        <button type="button" className={btn} onClick={() => lock('manual')} data-testid="pevv-lock" aria-label={t('lockNow')} title={`${t('lockNow')} · Ctrl+Shift+L`}>🔒</button>
      </header>
      {warnings.length > 0 && <p className="shrink-0 bg-accent-gold/10 px-2 py-1 text-[0.65rem] text-accent-gold" data-testid="pevv-warnings">⚠ {warnings[0]}{warnings.length > 1 ? ` (+${warnings.length - 1})` : ''}</p>}
      {narrow ? (
        <div className="min-h-0 flex-1 overflow-hidden">
          {mobilePane === 'nav' && <Sidebar filter={filter} setFilter={(f) => { setFilter(f); setMobilePane('list'); }} view={view} setView={setView} />}
          {mobilePane === 'list' && list}
          {mobilePane === 'detail' && <div className="flex h-full min-h-0 flex-col">{main}</div>}
        </div>
      ) : (
        <div className="grid min-h-0 flex-1 grid-cols-[minmax(9rem,12rem)_minmax(12rem,18rem)_1fr] overflow-hidden">
          <div className="min-h-0 border-r border-space-border/60">
            <Sidebar filter={filter} setFilter={setFilter} view={view} setView={setView} />
          </div>
          <div className="min-h-0 border-r border-space-border/60">{list}</div>
          <div className="flex min-h-0 flex-col">{main}</div>
        </div>
      )}
      <EnvRequestDialog />
    </div>
  );
}

export function VaultApp({ embedded }: { embedded?: boolean }) {
  const status = usePevv((s) => s.status);
  return (
    <div className="flex h-full min-h-0 w-full flex-col overflow-hidden text-ink-primary" data-testid={embedded ? 'pevv-app-embedded' : 'pevv-app'} data-status={status}>
      <QrWaitPanel />
      {status === 'none' && <div className="min-h-0 flex-1 overflow-y-auto"><SetupView /></div>}
      {status === 'locked' && <div className="min-h-0 flex-1 overflow-y-auto"><LockedView /></div>}
      {status === 'second-factor' && <div className="min-h-0 flex-1 overflow-y-auto"><SecondFactorView /></div>}
      {status === 'set-password' && <div className="min-h-0 flex-1 overflow-y-auto"><SetPasswordView /></div>}
      {status === 'unlocked' && <Unlocked embedded={embedded} />}
    </div>
  );
}
