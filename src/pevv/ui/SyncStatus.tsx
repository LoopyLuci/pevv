/**
 * Plain-language sync status: last synced, pending changes, conflicts that were resolved (with the kept versions of the
 * items that lost) and errors. Fed by syncStatus.ts; the kept versions come from the items themselves (`conflicts`).
 */
import { useState } from 'react';
import { usePT, type PKey } from '../i18n';
import { usePevv } from '../store';
import { agoParts, useSyncStatus, type SyncErrorCode } from '../syncStatus';
import type { ConflictCopy, Entry } from '../model';
import { btn } from './common';

const ERR_KEY: Record<SyncErrorCode, PKey> = {
  offline: 'syncErrOffline', 'rate-limited': 'syncErrRate', 'too-large': 'syncErrTooLarge', 'rejected-revoked': 'syncErrRevoked',
  'rejected-stale-key': 'syncErrStaleKey', 'rejected-key': 'syncErrKey', 'rejected-vault': 'syncErrVault', denied: 'syncErrDenied',
  'rev-regressed': 'syncErrRegress', unknown: 'syncErrUnknown',
};

const SECRET = /pass|key|pin|cvv|number|secret|totp|value/i;

function KeptVersions({ entry }: { entry: Entry }) {
  const { t, locale } = usePT();
  const [shown, setShown] = useState(false);
  const fmt = new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' });
  const list = (entry.conflicts ?? []) as ConflictCopy[];
  const differing = (c: ConflictCopy) => Object.keys(c.data).filter((k) => !['history', 'updated', 'created', 'conflicts'].includes(k) && JSON.stringify(c.data[k]) !== JSON.stringify((entry as unknown as Record<string, unknown>)[k]));
  return (
    <li className="flex flex-col gap-1 rounded-md border border-space-border/70 bg-space-surface/40 p-2 text-xs" data-testid={`pevv-kept-${entry.id}`}>
      <span className="font-medium text-cyan-50">{entry.title || entry.id.slice(0, 6)}</span>
      <ul className="flex flex-col gap-1">
        {list.map((c, i) => (
          <li key={`${c.at}-${i}`} className="text-ink-secondary">
            {t('syncVersionAt', { when: c.at ? fmt.format(c.at) : '—' })}
            <ul className="ml-3 list-disc text-ink-muted">
              {differing(c).map((k) => {
                const v = c.data[k];
                const text = typeof v === 'string' ? v : JSON.stringify(v);
                return <li key={k}>{k}: {shown ? text : SECRET.test(k) ? '••••••••' : text}</li>;
              })}
            </ul>
          </li>
        ))}
      </ul>
      <button type="button" className={btn} onClick={() => setShown((v) => !v)}>{shown ? t('syncHideValues') : t('syncShowValues')}</button>
    </li>
  );
}

export function SyncStatusPanel() {
  const { t } = usePT();
  const st = useSyncStatus();
  const entries = usePevv((s) => s.entries);
  const [open, setOpen] = useState(false);
  const [kept, setKept] = useState(false);
  const [parts, n] = agoParts(st.lastSyncedAt);
  const when = parts === 'never' ? '' : t(({ justNow: 'syncJustNow', minutes: 'syncMinutes', hours: 'syncHours', days: 'syncDays' } as const)[parts], { n });
  const withKept = entries.filter((e) => (e.conflicts ?? []).length > 0);
  return (
    <div className="flex flex-col gap-2 rounded-md border border-space-border/70 bg-space-surface/40 p-2 text-xs text-ink-secondary" data-testid="pevv-sync-status">
      <p className="font-medium text-cyan-50">{t('syncStatus')}</p>
      <p data-testid="pevv-sync-last">{parts === 'never' ? t('syncNever') : t('syncLast', { when })}{st.busy ? ` · ${t('syncBusy')}` : ''}</p>
      <p data-testid="pevv-sync-pending">{st.pending ? t('syncPendingYes') : t('syncPendingNo')}</p>
      {st.needsUnlock && <p className="text-amber-300" role="status" data-testid="pevv-sync-needs-unlock">{t('syncNeedsUnlock')}</p>}
      {st.error && <p className="text-amber-300" role="alert" data-testid="pevv-sync-error">{t(ERR_KEY[st.error])}</p>}
      <div className="flex flex-col gap-1">
        <button type="button" className={btn} onClick={() => setOpen((v) => !v)} aria-expanded={open}>{t('syncConflictsTitle')}{st.resolved.length ? ` (${st.resolved.length})` : ''}</button>
        {open && (st.resolved.length === 0 ? <p className="text-ink-muted" data-testid="pevv-sync-no-conflicts">{t('syncConflictsNone')}</p> : (
          <ul className="flex flex-col gap-1" data-testid="pevv-sync-conflicts">
            {st.resolved.map((c, i) => (
              <li key={`${c.id}-${c.at}-${i}`}>
                {c.kind === 'edited-both'
                  ? t('syncConflictEdited', { title: c.title || c.id.slice(0, 6), kept: c.kept === 'local' ? t('syncKeptHere') : t('syncKeptOther') })
                  : t('syncConflictDeleted', { title: c.title || c.id.slice(0, 6) })}
              </li>
            ))}
          </ul>
        ))}
      </div>
      <div className="flex flex-col gap-1">
        <button type="button" className={btn} onClick={() => setKept((v) => !v)} aria-expanded={kept} data-testid="pevv-sync-kept-toggle">{kept ? t('syncHideVersions') : t('syncShowVersions')}</button>
        {kept && <p className="text-ink-muted">{t('syncKeptIntro')}</p>}
        {kept && (withKept.length === 0 ? <p className="text-ink-muted">{t('syncKeptNone')}</p> : <ul className="flex flex-col gap-2" data-testid="pevv-sync-kept">{withKept.map((e) => <KeptVersions key={e.id} entry={e} />)}</ul>)}
      </div>
    </div>
  );
}
