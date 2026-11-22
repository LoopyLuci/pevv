/** PEVV items: scrolling sidebar (categories, environments, tags, tools), list, detail and editor. */
import { useEffect, useMemo, useRef, useState } from 'react';
import { usePT, type PKey } from '../i18n';
import { type Entry, type EntryData, type EntryType, ENTRY_TYPES, ENV_NAME, entrySubtitle, matchesQuery, reuseGroups } from '../model';
import { BRAND_LABEL, cardBrand, cvvValid, expiryState, formatCardNumber, inspectSshPrivate, luhnValid, normExpiry, parseSshPublic, sshFingerprint } from '../extra';
import { DEFAULT_GEN, generatePassword, strength } from '../gen';
import { parseOtpauth, totpAt } from '../totp';
import { normalizeAutoType, parseSequence } from '../autotype';
import { inDesktopApp } from '../webauthn';
import { AutoTypeFields } from '../desktop/AutoType';
import { addEnvironment, addFolder, audit, deleteEntry, deleteFolder, exportDotenvText, importDotenvText, renameFolder, restoreHistory, saveEntry, setActiveEnv, usePevv, type View } from '../store';
import { CopyButton, ErrorLine, StrengthMeter, btn, btnDanger, btnPrimary, download, input, label, readFileText, useReauthGate, useTotpTick } from './common';

export type Filter =
  | { kind: 'all' } | { kind: 'fav' } | { kind: 'type'; type: EntryType } | { kind: 'env'; env: string } | { kind: 'tag'; tag: string } | { kind: 'folder'; folder: string };

export const TYPE_ICON: Record<EntryType, string> = { login: '👤', env: '$', note: '📝', apikey: '🗝', card: '💳', ssh: '⌨', identity: '🪪', passkey: '🔑' };
export const TYPE_LABEL: Record<EntryType, PKey> = { login: 'tLogin', env: 'tEnv', note: 'tNote', apikey: 'tApiKey', card: 'tCard', ssh: 'tSsh', identity: 'tIdentity', passkey: 'tPasskey' };
/** Order in menus and the sidebar. */
export const TYPE_ORDER: EntryType[] = ['login', 'env', 'apikey', 'note', 'card', 'ssh', 'identity'];
void ENTRY_TYPES;

export function Sidebar({ filter, setFilter, view, setView }: { filter: Filter; setFilter: (f: Filter) => void; view: View; setView: (v: View) => void }) {
  const { t } = usePT();
  const entries = usePevv((s) => s.entries);
  const meta = usePevv((s) => s.meta);
  const tags = useMemo(() => [...new Set(entries.flatMap((e) => e.tags))].sort(), [entries]);
  const [newEnv, setNewEnv] = useState<string | null>(null);
  const [newFolder, setNewFolder] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<{ from: string; to: string } | null>(null);
  const folders = meta?.folders ?? [];
  const count = (f: (e: Entry) => boolean) => entries.filter(f).length;
  const item = (active: boolean, onClick: () => void, icon: string, text: string, n?: number, testId?: string) => (
    <button
      type="button"
      onClick={onClick}
      data-testid={testId}
      aria-current={active ? 'true' : undefined}
      className={`flex min-h-8 w-full items-center gap-2 rounded-md px-2 text-left text-xs ${active ? 'bg-accent-cyan/20 text-accent-cyan' : 'text-ink-secondary hover:bg-space-surface'}`}
    >
      <span aria-hidden className="w-4 text-center">{icon}</span>
      <span className="min-w-0 flex-1 truncate">{text}</span>
      {n !== undefined && <span className="tabular-nums text-[0.6rem] text-ink-muted">{n}</span>}
    </button>
  );
  const isItems = view === 'items';
  return (
    <nav className="flex h-full min-h-0 flex-col gap-3 overflow-y-auto p-2" aria-label={t('vaultNav')} data-testid="pevv-sidebar">
      <div className="flex flex-col gap-0.5">
        {item(isItems && filter.kind === 'all', () => { setView('items'); setFilter({ kind: 'all' }); }, '∗', t('allItems'), count((e) => e.type !== 'passkey'), 'pevv-nav-all')}
        {item(isItems && filter.kind === 'fav', () => { setView('items'); setFilter({ kind: 'fav' }); }, '★', t('favorites'), count((e) => e.favorite), 'pevv-nav-fav')}
        {TYPE_ORDER.filter((ty) => ty === 'login' || ty === 'env' || ty === 'note' || ty === 'apikey' || count((e) => e.type === ty) > 0 || (filter.kind === 'type' && filter.type === ty)).map((ty) =>
          item(isItems && filter.kind === 'type' && filter.type === ty, () => { setView('items'); setFilter({ kind: 'type', type: ty }); }, TYPE_ICON[ty], t(TYPE_LABEL[ty]), count((e) => e.type === ty), `pevv-nav-${ty}`))}
      </div>
      <div className="flex flex-col gap-0.5">
        <p className="px-2 font-mono text-[0.6rem] uppercase tracking-wider text-ink-muted">{t('environments')}</p>
        {(meta?.environments ?? []).map((env) => (
          <div key={env} className="flex items-center gap-1">
            <div className="min-w-0 flex-1">{item(isItems && filter.kind === 'env' && filter.env === env, () => { setView('items'); setFilter({ kind: 'env', env }); }, meta?.activeEnv === env ? '●' : '○', env, count((e) => e.type === 'env' && (e.env ?? 'dev') === env), `pevv-nav-env-${env}`)}</div>
          </div>
        ))}
        {newEnv === null ? (
          <button type="button" className="min-h-8 rounded-md px-2 text-left text-xs text-ink-muted hover:bg-space-surface" onClick={() => setNewEnv('')} data-testid="pevv-add-env">＋ {t('addEnvironment')}</button>
        ) : (
          <form className="flex gap-1 px-1" onSubmit={(e) => { e.preventDefault(); void addEnvironment(newEnv).then(() => setNewEnv(null)).catch(() => undefined); }}>
            <input autoFocus className={`${input} min-h-8 text-xs`} value={newEnv} onChange={(e) => setNewEnv(e.target.value)} placeholder="staging" aria-label={t('addEnvironment')} data-testid="pevv-add-env-name" />
            <button type="submit" className={btn}>OK</button>
          </form>
        )}
      </div>
      <div className="flex flex-col gap-0.5" data-testid="pevv-folders">
        <p className="px-2 font-mono text-[0.6rem] uppercase tracking-wider text-ink-muted">{t('folders')}</p>
        {folders.map((f) => (
          renaming?.from === f ? (
            <form key={f} className="flex gap-1 px-1" onSubmit={(e) => { e.preventDefault(); void renameFolder(f, renaming.to).then(() => { setRenaming(null); if (filter.kind === 'folder' && filter.folder === f) setFilter({ kind: 'folder', folder: renaming.to.trim() }); }).catch(() => undefined); }}>
              <input autoFocus className={`${input} min-h-8 text-xs`} value={renaming.to} onChange={(e) => setRenaming({ from: f, to: e.target.value })} aria-label={t('renameFolder')} data-testid="pevv-folder-rename-name" onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); setRenaming(null); } }} />
              <button type="submit" className={btn}>OK</button>
            </form>
          ) : (
            <div key={f} className="group flex items-center gap-0.5">
              <div className="min-w-0 flex-1">{item(isItems && filter.kind === 'folder' && filter.folder === f, () => { setView('items'); setFilter({ kind: 'folder', folder: f }); }, '📁', f, count((e) => e.folder === f), `pevv-nav-folder-${f}`)}</div>
              <button type="button" className="hidden h-7 w-6 rounded text-[0.65rem] text-ink-muted hover:bg-space-surface group-hover:block group-focus-within:block" title={t('renameFolder')} aria-label={`${t('renameFolder')}: ${f}`} onClick={() => setRenaming({ from: f, to: f })} data-testid={`pevv-folder-rename-${f}`}>✎</button>
              <button type="button" className="hidden h-7 w-6 rounded text-[0.65rem] text-ink-muted hover:bg-space-surface group-hover:block group-focus-within:block" title={t('deleteFolder')} aria-label={`${t('deleteFolder')}: ${f}`} onClick={() => { void deleteFolder(f).then(() => { if (filter.kind === 'folder' && filter.folder === f) setFilter({ kind: 'all' }); }); }} data-testid={`pevv-folder-delete-${f}`}>✕</button>
            </div>
          )
        ))}
        {newFolder === null ? (
          <button type="button" className="min-h-8 rounded-md px-2 text-left text-xs text-ink-muted hover:bg-space-surface" onClick={() => setNewFolder('')} data-testid="pevv-add-folder">＋ {t('addFolder')}</button>
        ) : (
          <form className="flex gap-1 px-1" onSubmit={(e) => { e.preventDefault(); void addFolder(newFolder).then(() => setNewFolder(null)).catch(() => undefined); }}>
            <input autoFocus className={`${input} min-h-8 text-xs`} value={newFolder} onChange={(e) => setNewFolder(e.target.value)} placeholder="Work" aria-label={t('addFolder')} data-testid="pevv-add-folder-name" onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); setNewFolder(null); } }} />
            <button type="submit" className={btn}>OK</button>
          </form>
        )}
      </div>
      {tags.length > 0 && (
        <div className="flex flex-col gap-0.5">
          <p className="px-2 font-mono text-[0.6rem] uppercase tracking-wider text-ink-muted">{t('tags')}</p>
          {tags.map((tag) => item(isItems && filter.kind === 'tag' && filter.tag === tag, () => { setView('items'); setFilter({ kind: 'tag', tag }); }, '#', tag, count((e) => e.tags.includes(tag))))}
        </div>
      )}
      <div className="mt-auto flex flex-col gap-0.5 border-t border-space-border/60 pt-2">
        {item(view === 'generator', () => setView('generator'), '⚄', t('generator'), undefined, 'pevv-nav-generator')}
        {item(view === 'audit', () => setView('audit'), '♥', t('securityHealth'), undefined, 'pevv-nav-health')}
        {item(view === 'activity', () => setView('activity'), '☰', t('activity'), undefined, 'pevv-nav-activity')}
        {item(view === 'devices', () => setView('devices'), '⧉', t('devices'), meta?.devices.length, 'pevv-nav-devices')}
        {item(view === 'settings', () => setView('settings'), '⚙', t('settings'), undefined, 'pevv-nav-settings')}
        {item(view === 'qr', () => setView('qr'), '▣', t('qrMoveTitle'), undefined, 'pevv-nav-qr')}
      </div>
    </nav>
  );
}

export function filterEntries(entries: Entry[], f: Filter, q: string): Entry[] {
  return entries
    // Passkeys PEVV holds for other sites are managed in Settings, never listed, edited or copied from here.
    .filter((e) => e.type !== 'passkey')
    .filter((e) => (f.kind === 'all' ? true : f.kind === 'fav' ? e.favorite : f.kind === 'type' ? e.type === f.type : f.kind === 'env' ? e.type === 'env' && (e.env ?? 'dev') === f.env : f.kind === 'folder' ? e.folder === f.folder : e.tags.includes(f.tag)))
    .filter((e) => matchesQuery(e, q))
    .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.title.localeCompare(b.title));
}

export function ItemList({ items, selected, onSelect }: { items: Entry[]; selected: string | null; onSelect: (id: string) => void }) {
  const { t } = usePT();
  const reuse = reuseGroups(usePevv.getState().entries);
  if (!items.length) return <p className="p-4 text-center text-xs text-ink-muted" data-testid="pevv-empty">{t('noItems')}</p>;
  return (
    <ul className="flex flex-col gap-0.5 p-1" data-testid="pevv-list" role="listbox" aria-label={t('items')}>
      {items.map((e) => {
        const weak = (e.type === 'login' && e.password && strength(e.password).score <= 1) || reuse.has(e.id) || (e.type === 'card' && (expiryState(e.expiry) === 'expired' || (!!e.number && !luhnValid(e.number))));
        return (
          <li key={e.id} role="option" aria-selected={selected === e.id}>
            <button
              type="button"
              onClick={() => onSelect(e.id)}
              data-testid={`pevv-item-${e.id}`}
              data-title={e.title}
              className={`flex min-h-11 w-full items-center gap-2 rounded-md px-2 text-left ${selected === e.id ? 'bg-accent-cyan/20' : 'hover:bg-space-surface'}`}
            >
              <span aria-hidden className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-cyan-500/30 bg-space-deep text-xs text-accent-cyan">{TYPE_ICON[e.type]}</span>
              <span className="flex min-w-0 flex-1 flex-col">
                <span className="truncate text-sm text-cyan-50">{e.title}{e.favorite && <span className="ml-1 text-accent-gold" aria-label={t('favorite')}>★</span>}</span>
                <span className="truncate text-[0.65rem] text-ink-muted">{entrySubtitle(e)}</span>
              </span>
              {weak && <span className="text-[0.6rem] text-accent-gold" title={t('needsAttention')}>⚠</span>}
            </button>
          </li>
        );
      })}
    </ul>
  );
}

function Field({ name, value, secret, mono, testId, copy = true, itemId, display, multiline }: { name: string; value?: string | undefined; secret?: boolean; mono?: boolean; testId: string; copy?: boolean; itemId?: string; display?: string; multiline?: boolean }) {
  const { t } = usePT();
  const [shown, setShown] = useState(false);
  const [gateNode, gate] = useReauthGate();
  if (!value) return null;
  return (
    <div className="flex flex-col gap-1 rounded-md border border-space-border/60 bg-space-deep/40 p-2">
      <span className="text-[0.62rem] uppercase tracking-wider text-ink-muted">{name}</span>
      <div className="flex flex-wrap items-center gap-2">
        <span className={`min-w-0 flex-1 break-all text-sm ${mono || secret ? 'font-mono' : ''} ${multiline ? 'max-h-40 overflow-y-auto whitespace-pre-wrap text-xs' : ''}`} data-testid={testId}>
          {secret && !shown ? '•'.repeat(Math.min(16, Math.max(8, value.length))) : display ?? value}
        </span>
        {secret && (
          <button type="button" className={btn} data-testid={`${testId}-reveal`} onClick={() => (shown ? setShown(false) : gate(() => { setShown(true); if (itemId) audit('reveal', itemId, name); }))}>
            {shown ? t('hide') : t('reveal')}
          </button>
        )}
        {copy && <CopyButton value={value} testId={`${testId}-copy`} {...(secret && itemId ? { itemId } : {})} />}
      </div>
      {gateNode}
    </div>
  );
}

function TotpCode({ secret }: { secret: string }) {
  const { t } = usePT();
  const [code, setCode] = useState('');
  let cfg: ReturnType<typeof parseOtpauth> | null = null;
  try { cfg = parseOtpauth(secret); } catch { cfg = null; }
  const left = useTotpTick(cfg?.period ?? 30);
  useEffect(() => {
    if (!cfg) return;
    void totpAt(cfg, Date.now()).then(setCode);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [secret, left === (cfg?.period ?? 30)]);
  if (!cfg) return <p className="text-xs text-red-300">{t('badTotp')}</p>;
  return (
    <div className="flex items-center gap-2 rounded-md border border-space-border/60 bg-space-deep/40 p-2">
      <span className="text-[0.62rem] uppercase tracking-wider text-ink-muted">{t('oneTimeCode')}</span>
      <span className="font-mono text-lg tracking-widest text-accent-cyan" data-testid="pevv-entry-totp">{code.replace(/(\d{3})(\d+)/, '$1 $2')}</span>
      <span className="text-[0.65rem] tabular-nums text-ink-muted">{left}s</span>
      <CopyButton value={code} />
    </div>
  );
}

export function EntryDetail({ entry, onEdit, onBack }: { entry: Entry; onEdit: () => void; onBack?: () => void }) {
  const { t, locale } = usePT();
  const [confirmDel, setConfirmDel] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [gateNode, gate] = useReauthGate();
  const reuse = reuseGroups(usePevv.getState().entries).get(entry.id);
  const s = entry.type === 'login' && entry.password ? strength(entry.password) : null;
  const fmt = new Intl.DateTimeFormat(locale === 'es' ? 'es' : 'en-US', { dateStyle: 'medium', timeStyle: 'short' });
  return (
    <article className="flex min-h-0 flex-col gap-2 overflow-y-auto p-3" data-testid="pevv-detail">
      <header className="flex flex-wrap items-center gap-2">
        {onBack && <button type="button" className={btn} onClick={onBack} aria-label={t('back')}>←</button>}
        <span aria-hidden className="text-lg">{TYPE_ICON[entry.type]}</span>
        <h3 className="min-w-0 flex-1 truncate font-display text-base text-cyan-50" data-testid="pevv-detail-title">{entry.title}</h3>
        <button type="button" className={btn} aria-pressed={entry.favorite} onClick={() => void saveEntry(entry.id, { favorite: !entry.favorite })} data-testid="pevv-fav-toggle">{entry.favorite ? '★' : '☆'}</button>
        <button type="button" className={btn} onClick={onEdit} data-testid="pevv-edit">{t('edit')}</button>
      </header>
      {entry.type === 'login' && (
        <>
          <Field name={t('site')} value={entry.site} testId="pevv-entry-site" />
          <Field name={t('username')} value={entry.username} testId="pevv-entry-username" />
          <Field name={t('password')} value={entry.password} secret itemId={entry.id} testId="pevv-entry-password" />
          {s && <StrengthMeter value={entry.password!} testId="pevv-detail-strength" />}
          {entry.totp && <TotpCode secret={entry.totp} />}
        </>
      )}
      {entry.type === 'env' && (
        <>
          <Field name={t('envName')} value={entry.name} mono testId="pevv-entry-name" />
          <Field name={t('envValue')} value={entry.value} secret itemId={entry.id} testId="pevv-entry-value" />
          <p className="text-[0.65rem] text-ink-muted">{t('environment')}: <span className="font-mono">{entry.env ?? 'dev'}</span> · {t('terminalUse', { name: entry.name ?? '' })}</p>
        </>
      )}
      {entry.type === 'apikey' && (
        <>
          <Field name={t('service')} value={entry.service} testId="pevv-entry-service" />
          <Field name={t('apiKey')} value={entry.key} secret itemId={entry.id} testId="pevv-entry-key" />
        </>
      )}
      {entry.type === 'card' && <CardDetail entry={entry} />}
      {entry.type === 'ssh' && <SshDetail entry={entry} />}
      {entry.type === 'identity' && (
        <>
          <Field name={t('fullName')} value={entry.fullName} testId="pevv-entry-fullname" />
          <Field name={t('email')} value={entry.email} testId="pevv-entry-email" />
          <Field name={t('phone')} value={entry.phone} testId="pevv-entry-phone" />
          <Field name={t('address')} value={entry.address} testId="pevv-entry-address" multiline />
        </>
      )}
      {entry.folder && <p className="text-[0.65rem] text-ink-muted" data-testid="pevv-entry-folder">📁 {entry.folder}</p>}
      {entry.type === 'note' ? <Field name={t('secureNote')} value={entry.notes} secret itemId={entry.id} testId="pevv-entry-note" /> : <Field name={t('notes')} value={entry.notes} testId="pevv-entry-notes" copy={false} />}
      {reuse && <p className="rounded border border-accent-gold/40 bg-accent-gold/10 px-2 py-1 text-xs text-accent-gold">⚠ {t('reusedWarn', { n: reuse.length - 1 })}</p>}
      {entry.tags.length > 0 && <p className="flex flex-wrap gap-1">{entry.tags.map((tag) => <span key={tag} className="rounded-full border border-space-border px-2 text-[0.65rem] text-ink-secondary">#{tag}</span>)}</p>}
      <p className="text-[0.62rem] text-ink-muted">{t('created')} {fmt.format(entry.created)} · {t('updated')} {fmt.format(entry.updated)} · v{entry.ver}</p>
      {entry.history.length > 0 && (
        <div className="flex flex-col gap-1">
          <button type="button" className={btn} onClick={() => (showHistory ? setShowHistory(false) : gate(() => setShowHistory(true)))} data-testid="pevv-history-toggle">
            {showHistory ? t('hideHistory') : t('showHistory', { n: entry.history.length })}
          </button>
          {gateNode}
          {showHistory && (
            <ul className="flex flex-col gap-1" data-testid="pevv-history">
              {entry.history.map((h, i) => (
                <li key={i} className="flex flex-wrap items-center gap-2 rounded border border-space-border/60 p-1.5 text-xs">
                  <span className="text-ink-muted">{fmt.format(h.at)}</span>
                  <span className="text-ink-secondary">{h.field}</span>
                  <span className="min-w-0 flex-1 break-all font-mono">{h.value}</span>
                  <CopyButton value={h.value} itemId={entry.id} />
                  <button type="button" className={btn} onClick={() => void restoreHistory(entry.id, i).catch(() => undefined)} data-testid={`pevv-history-restore-${i}`}>{t('restore')}</button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      <div className="mt-2 flex gap-2 border-t border-space-border/60 pt-2">
        {!confirmDel ? (
          <button type="button" className={btnDanger} onClick={() => setConfirmDel(true)} data-testid="pevv-delete">{t('delete')}</button>
        ) : (
          <>
            <span className="text-xs text-red-200">{t('confirmDelete')}</span>
            <button type="button" className={btnDanger} onClick={() => void deleteEntry(entry.id)} data-testid="pevv-delete-confirm">{t('deleteForever')}</button>
            <button type="button" className={btn} onClick={() => setConfirmDel(false)}>{t('cancel')}</button>
          </>
        )}
      </div>
    </article>
  );
}

export function EntryEditor({ entry, type, onDone, defaultEnv, prefill }: { entry: Entry | null; type: EntryType; onDone: (id: string | null) => void; defaultEnv: string; prefill?: Partial<EntryData> }) {
  const { t } = usePT();
  const [d, setD] = useState<Partial<EntryData>>(() => (entry ? { ...entry } : { type, title: '', tags: [], ...(type === 'env' ? { env: defaultEnv } : {}), ...prefill }));
  const [tagText, setTagText] = useState((entry?.tags ?? []).join(', '));
  const [showPw, setShowPw] = useState(false);
  const busy = usePevv((s) => s.busy);
  const firstRef = useRef<HTMLInputElement>(null);
  useEffect(() => { firstRef.current?.focus(); }, []);
  const ty = (entry?.type ?? type) as EntryType;
  const up = (p: Partial<EntryData>) => setD((x) => ({ ...x, ...p }));
  const reuse = ty === 'login' && d.password ? usePevv.getState().entries.filter((e) => e.id !== entry?.id && e.type === 'login' && e.password === d.password).length : 0;
  const envs = usePevv.getState().meta?.environments ?? ['dev'];
  let totpErr = false;
  if (d.totp) { try { parseOtpauth(d.totp); } catch { totpErr = true; } }
  const nameErr = ty === 'env' && !!d.name && !ENV_NAME.test(d.name);
  const folders = usePevv.getState().meta?.folders ?? [];
  const cardNumErr = ty === 'card' && !!d.number && !luhnValid(d.number);
  const cvvErr = ty === 'card' && !cvvValid(d.cvv, d.number);
  const expErr = ty === 'card' && !!d.expiry && !normExpiry(d.expiry);
  const sshInfo = ty === 'ssh' ? inspectSshPrivate(d.privateKey) : null;
  const submit = async () => {
    const tags = [...new Set(tagText.split(',').map((x) => x.trim().replace(/^#/, '')).filter(Boolean))].slice(0, 20);
    // Auto-type belongs to the desktop app; other clients leave the field exactly as it is.
    const desktopAt = inDesktopApp() && ty === 'login';
    if (desktopAt && d.autoType?.sequence?.trim() && !parseSequence(d.autoType.sequence).ok) return;
    try {
      const extra: Partial<EntryData> = ty === 'card' ? { ...(d.number ? { number: formatCardNumber(d.number) } : {}), ...(d.expiry && normExpiry(d.expiry) ? { expiry: normExpiry(d.expiry)! } : {}) } : {};
      if (desktopAt) extra.autoType = normalizeAutoType(d.autoType);
      const saved = await saveEntry(entry?.id ?? null, { ...d, ...extra, type: ty, tags });
      onDone(saved.id);
    } catch { /* shown */ }
  };
  return (
    <form className="flex min-h-0 flex-col gap-2 overflow-y-auto p-3" data-testid="pevv-editor" onSubmit={(e) => { e.preventDefault(); void submit(); }}>
      <h3 className="font-display text-base text-cyan-50">{entry ? t('editItem') : t('newItemOf', { type: t(TYPE_LABEL[ty]) })}</h3>
      <label className={label}>{t('title')}<input ref={firstRef} className={input} value={d.title ?? ''} onChange={(e) => up({ title: e.target.value })} data-testid="pevv-f-title" maxLength={120} /></label>
      {ty === 'login' && (
        <>
          <label className={label}>{t('site')}<input className={input} value={d.site ?? ''} onChange={(e) => up({ site: e.target.value })} placeholder="https://example.com  ·  luciverse:supabase-signin" data-testid="pevv-f-site" /></label>
          <label className={label}>{t('username')}<input className={input} autoComplete="off" value={d.username ?? ''} onChange={(e) => up({ username: e.target.value })} data-testid="pevv-f-username" /></label>
          <label className={label}>
            {t('password')}
            <div className="flex gap-1">
              <input type={showPw ? 'text' : 'password'} autoComplete="new-password" className={`${input} font-mono`} value={d.password ?? ''} onChange={(e) => up({ password: e.target.value })} data-testid="pevv-f-password" />
              <button type="button" className={btn} onClick={() => setShowPw((v) => !v)} aria-label={showPw ? t('hide') : t('reveal')}>{showPw ? '🙈' : '👁'}</button>
              <button type="button" className={btn} onClick={() => { up({ password: generatePassword(DEFAULT_GEN) }); setShowPw(true); }} data-testid="pevv-f-generate">⚄ {t('generate')}</button>
            </div>
          </label>
          <StrengthMeter value={d.password ?? ''} testId="pevv-editor-strength" />
          {reuse > 0 && <p className="text-xs text-accent-gold" data-testid="pevv-reuse-warning">⚠ {t('reusedWarn', { n: reuse })}</p>}
          <label className={label}>{t('totpSecret')}<input className={`${input} font-mono`} autoComplete="off" value={d.totp ?? ''} onChange={(e) => up({ totp: e.target.value })} placeholder="otpauth://totp/…  ·  JBSWY3DPEHPK3PXP" data-testid="pevv-f-totp" /></label>
          {totpErr && <p className="text-xs text-red-300">{t('badTotp')}</p>}
          {inDesktopApp() && <AutoTypeFields value={d.autoType} onChange={(v) => up({ autoType: v })} />}
        </>
      )}
      {ty === 'env' && (
        <>
          <label className={label}>{t('envName')}<input className={`${input} font-mono`} value={d.name ?? ''} onChange={(e) => up({ name: e.target.value.toUpperCase().replace(/\s/g, '_') })} placeholder="DATABASE_URL" data-testid="pevv-f-name" /></label>
          {nameErr && <p className="text-xs text-red-300">{t('badEnvName')}</p>}
          <label className={label}>{t('envValue')}<textarea className={`${input} min-h-16 py-1 font-mono`} value={d.value ?? ''} onChange={(e) => up({ value: e.target.value })} data-testid="pevv-f-value" spellCheck={false} /></label>
          <label className={label}>{t('environment')}
            <select className={input} value={d.env ?? defaultEnv} onChange={(e) => up({ env: e.target.value })} data-testid="pevv-f-env">
              {envs.map((x) => <option key={x} value={x}>{x}</option>)}
            </select>
          </label>
        </>
      )}
      {ty === 'apikey' && (
        <>
          <label className={label}>{t('service')}<input className={input} value={d.service ?? ''} onChange={(e) => up({ service: e.target.value })} data-testid="pevv-f-service" /></label>
          <label className={label}>{t('apiKey')}<input type={showPw ? 'text' : 'password'} className={`${input} font-mono`} autoComplete="off" value={d.key ?? ''} onChange={(e) => up({ key: e.target.value })} data-testid="pevv-f-key" /></label>
          <label className="flex items-center gap-2 text-xs text-ink-secondary"><input type="checkbox" checked={showPw} onChange={(e) => setShowPw(e.target.checked)} /> {t('reveal')}</label>
        </>
      )}
      {ty === 'card' && (
        <>
          <label className={label}>{t('cardholder')}<input className={input} autoComplete="off" value={d.cardholder ?? ''} onChange={(e) => up({ cardholder: e.target.value })} data-testid="pevv-f-cardholder" /></label>
          <label className={label}>{t('cardNumber')} {d.number && <span className="normal-case text-ink-muted">· {BRAND_LABEL[cardBrand(d.number)]}</span>}
            <input className={`${input} font-mono`} inputMode="numeric" autoComplete="off" value={d.number ?? ''} onChange={(e) => up({ number: e.target.value.replace(/[^\d ]/g, '').slice(0, 23) })} onBlur={() => d.number && up({ number: formatCardNumber(d.number) })} data-testid="pevv-f-number" />
          </label>
          {cardNumErr && <p className="text-xs text-accent-gold" data-testid="pevv-card-luhn">⚠ {t('cardInvalid')}</p>}
          <div className="grid grid-cols-3 gap-2">
            <label className={label}>{t('expiry')}<input className={`${input} font-mono`} inputMode="numeric" autoComplete="off" placeholder="MM/YY" value={d.expiry ?? ''} onChange={(e) => up({ expiry: e.target.value.slice(0, 7) })} onBlur={() => { const n = normExpiry(d.expiry); if (n) up({ expiry: n }); }} data-testid="pevv-f-expiry" /></label>
            <label className={label}>{t('cvv')}<input type={showPw ? 'text' : 'password'} className={`${input} font-mono`} inputMode="numeric" autoComplete="off" value={d.cvv ?? ''} onChange={(e) => up({ cvv: e.target.value.replace(/\D/g, '').slice(0, 4) })} data-testid="pevv-f-cvv" /></label>
            <label className={label}>{t('pin')}<input type={showPw ? 'text' : 'password'} className={`${input} font-mono`} inputMode="numeric" autoComplete="off" value={d.pin ?? ''} onChange={(e) => up({ pin: e.target.value.replace(/\D/g, '').slice(0, 12) })} data-testid="pevv-f-pin" /></label>
          </div>
          {expErr && <p className="text-xs text-red-300">{t('expiryInvalid')}</p>}
          {cvvErr && <p className="text-xs text-red-300">{t('cvvInvalid')}</p>}
          <label className="flex items-center gap-2 text-xs text-ink-secondary"><input type="checkbox" checked={showPw} onChange={(e) => setShowPw(e.target.checked)} /> {t('reveal')}</label>
        </>
      )}
      {ty === 'ssh' && (
        <>
          <p className="text-[0.65rem] text-ink-muted">{t('sshHint')}</p>
          <label className={label}>{t('privateKey')}<textarea className={`${input} min-h-28 py-1 font-mono text-[0.65rem]`} spellCheck={false} autoComplete="off" value={d.privateKey ?? ''} onChange={(e) => up({ privateKey: e.target.value })} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" data-testid="pevv-f-privatekey" /></label>
          {sshInfo && sshInfo.format !== 'unknown' && <p className={`text-xs ${sshInfo.encrypted ? 'text-accent-green' : 'text-accent-gold'}`} data-testid="pevv-ssh-protection">{sshInfo.encrypted ? `✓ ${t('keyEncrypted', { c: sshInfo.cipher ?? '' })}` : `⚠ ${t('keyUnencrypted')}`}</p>}
          <label className={label}>{t('publicKey')}<textarea className={`${input} min-h-12 py-1 font-mono text-[0.65rem]`} spellCheck={false} value={d.publicKey ?? ''} onChange={(e) => up({ publicKey: e.target.value.trim() })} placeholder="ssh-ed25519 AAAA… you@host" data-testid="pevv-f-publickey" /></label>
          <label className={label}>{t('passphrase')}<input type={showPw ? 'text' : 'password'} className={`${input} font-mono`} autoComplete="off" value={d.passphrase ?? ''} onChange={(e) => up({ passphrase: e.target.value })} data-testid="pevv-f-passphrase" /></label>
          <label className="flex items-center gap-2 text-xs text-ink-secondary"><input type="checkbox" checked={showPw} onChange={(e) => setShowPw(e.target.checked)} /> {t('reveal')}</label>
        </>
      )}
      {ty === 'identity' && (
        <>
          <label className={label}>{t('fullName')}<input className={input} autoComplete="off" value={d.fullName ?? ''} onChange={(e) => up({ fullName: e.target.value })} data-testid="pevv-f-fullname" /></label>
          <label className={label}>{t('email')}<input type="email" className={input} autoComplete="off" value={d.email ?? ''} onChange={(e) => up({ email: e.target.value })} data-testid="pevv-f-email" /></label>
          <label className={label}>{t('phone')}<input type="tel" className={input} autoComplete="off" value={d.phone ?? ''} onChange={(e) => up({ phone: e.target.value })} data-testid="pevv-f-phone" /></label>
          <label className={label}>{t('address')}<textarea className={`${input} min-h-14 py-1`} value={d.address ?? ''} onChange={(e) => up({ address: e.target.value })} data-testid="pevv-f-address" /></label>
        </>
      )}
      <label className={label}>{ty === 'note' ? t('secureNote') : t('notes')}<textarea className={`${input} ${ty === 'note' ? 'min-h-40' : 'min-h-16'} py-1`} value={d.notes ?? ''} onChange={(e) => up({ notes: e.target.value })} data-testid="pevv-f-notes" /></label>
      <label className={label}>{t('folder')}
        <select className={input} value={d.folder ?? ''} onChange={(e) => up({ folder: e.target.value })} data-testid="pevv-f-folder">
          <option value="">{t('noFolder')}</option>
          {folders.map((f) => <option key={f} value={f}>{f}</option>)}
          {d.folder && !folders.includes(d.folder) && <option value={d.folder}>{d.folder}</option>}
        </select>
      </label>
      <label className={label}>{t('tagsComma')}<input className={input} value={tagText} onChange={(e) => setTagText(e.target.value)} placeholder="work, cloud" data-testid="pevv-f-tags" /></label>
      <label className="flex items-center gap-2 text-xs text-ink-secondary"><input type="checkbox" checked={!!d.favorite} onChange={(e) => up({ favorite: e.target.checked })} /> {t('favorite')}</label>
      <ErrorLine />
      <div className="flex gap-2">
        <button type="submit" className={btnPrimary} disabled={busy || nameErr || totpErr || expErr || cvvErr || (ty === 'env' && !d.name)} data-testid="pevv-save">{t('save')}</button>
        <button type="button" className={btn} onClick={() => onDone(entry?.id ?? null)}>{t('cancel')}</button>
      </div>
    </form>
  );
}

/** Environment toolbar shown above the list when an environment is selected. */
export function EnvToolbar({ env }: { env: string }) {
  const { t } = usePT();
  const active = usePevv((s) => s.meta?.activeEnv);
  const [gateNode, gate] = useReauthGate();
  const [msg, setMsg] = useState<string | null>(null);
  return (
    <div className="flex flex-col gap-1 border-b border-space-border/60 p-2" data-testid="pevv-env-toolbar">
      <div className="flex flex-wrap items-center gap-1">
        <span className="font-mono text-xs text-cyan-100">{env}</span>
        {active === env ? (
          <span className="rounded-full bg-accent-green/20 px-2 text-[0.6rem] text-accent-green" data-testid="pevv-env-active">{t('activeEnv')}</span>
        ) : (
          <button type="button" className={btn} onClick={() => void setActiveEnv(env)} data-testid="pevv-env-use">{t('useEnv')}</button>
        )}
        <label className={`${btn} cursor-pointer`}>
          {t('importEnv')}
          <input type="file" accept=".env,text/plain,*/*" className="sr-only" data-testid="pevv-env-import" onChange={async (e) => {
            const f = e.target.files?.[0];
            e.target.value = '';
            if (!f) return;
            try { const n = await importDotenvText(env, await readFileText(f)); setMsg(t('importedN', { n })); } catch (err) { setMsg((err as Error).message); }
          }} />
        </label>
        <button type="button" className={btn} data-testid="pevv-env-export" onClick={() => gate(() => download(`${env}.env`, exportDotenvText(env), 'text/plain'), t('reauthExport'))}>{t('exportEnv')}</button>
      </div>
      {msg && <p className="text-[0.65rem] text-ink-secondary">{msg}</p>}
      {gateNode}
    </div>
  );
}

function CardDetail({ entry }: { entry: Entry }) {
  const { t } = usePT();
  const st = expiryState(entry.expiry);
  const brand = cardBrand(entry.number);
  return (
    <>
      <div className="flex items-center gap-2 rounded-md border border-cyan-500/30 bg-gradient-to-br from-space-deep to-space-surface p-3" data-testid="pevv-card-face">
        <span className="font-display text-sm text-cyan-50">{BRAND_LABEL[brand]}</span>
        <span className="ml-auto font-mono text-xs text-ink-secondary">•••• {(entry.number ?? '').replace(/\D/g, '').slice(-4)}</span>
        {st === 'expired' && <span className="rounded-full bg-red-500/20 px-2 text-[0.6rem] text-red-200" data-testid="pevv-card-expired">{t('expired')}</span>}
        {st === 'soon' && <span className="rounded-full bg-accent-gold/20 px-2 text-[0.6rem] text-accent-gold" data-testid="pevv-card-soon">{t('expiresSoon')}</span>}
      </div>
      <Field name={t('cardholder')} value={entry.cardholder} testId="pevv-entry-cardholder" />
      <Field name={t('cardNumber')} value={entry.number} secret itemId={entry.id} display={formatCardNumber(entry.number)} testId="pevv-entry-number" />
      {entry.number && !luhnValid(entry.number) && <p className="text-xs text-accent-gold">⚠ {t('cardInvalid')}</p>}
      <Field name={t('validThru')} value={entry.expiry} mono testId="pevv-entry-expiry" />
      <Field name={t('cvv')} value={entry.cvv} secret itemId={entry.id} testId="pevv-entry-cvv" />
      <Field name={t('pin')} value={entry.pin} secret itemId={entry.id} testId="pevv-entry-pin" />
    </>
  );
}

function SshDetail({ entry }: { entry: Entry }) {
  const { t } = usePT();
  const [fp, setFp] = useState<string | null>(null);
  useEffect(() => { let on = true; void sshFingerprint(entry.publicKey).then((f) => { if (on) setFp(f); }); return () => { on = false; }; }, [entry.publicKey]);
  const pub = parseSshPublic(entry.publicKey);
  const priv = inspectSshPrivate(entry.privateKey);
  return (
    <>
      {pub && <p className="font-mono text-[0.7rem] text-ink-secondary" data-testid="pevv-ssh-type">{pub.type}{pub.bits ? ` · ${pub.bits} bits` : ''}{pub.comment ? ` · ${pub.comment}` : ''}</p>}
      {fp && <Field name={t('fingerprint')} value={fp} mono testId="pevv-entry-fingerprint" />}
      <Field name={t('publicKey')} value={entry.publicKey} mono multiline testId="pevv-entry-publickey" />
      <Field name={t('privateKey')} value={entry.privateKey} secret multiline itemId={entry.id} testId="pevv-entry-privatekey" />
      {priv && priv.format !== 'unknown' && <p className={`text-xs ${priv.encrypted ? 'text-accent-green' : 'text-accent-gold'}`}>{priv.encrypted ? `✓ ${t('keyEncrypted', { c: priv.cipher ?? '' })}` : `⚠ ${t('keyUnencrypted')}`}</p>}
      <Field name={t('passphrase')} value={entry.passphrase} secret itemId={entry.id} testId="pevv-entry-passphrase" />
    </>
  );
}
