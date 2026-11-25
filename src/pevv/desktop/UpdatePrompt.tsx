/**
 * Desktop-only UI for the auto-updater: the "Update now" / "Restart to update" / "Later" card and the
 * Settings section (mode, on/off, check now). English and Spanish through the shared dictionary.
 */
import { invoke } from '@tauri-apps/api/core';
import { usePT } from '../i18n';
import { setPrefs, usePevv } from '../store';
import { Section, btn, btnPrimary, input } from '../ui/common';
import { checkForUpdate, dismissUpdate, installUpdate, normalizeMode, useUpdate, type UpdateIpc, type UpdateMode } from './updater';

export const updateIpc: UpdateIpc = { invoke: (cmd, args) => invoke(cmd, args) };

/** Modal card over the window when a signed update was found (manual) or downloaded (restart to update). Silent installs show nothing. */
export function UpdatePrompt() {
  const { t } = usePT();
  const phase = useUpdate((s) => s.phase);
  const info = useUpdate((s) => s.info);
  const quiet = useUpdate((s) => s.quiet);
  if ((phase !== 'available' && phase !== 'ready' && phase !== 'installing') || !info || quiet) return null;
  const ready = phase === 'ready';
  return (
    <div className="fixed inset-0 z-[9997] flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" data-testid="update-prompt">
      <section className="flex w-full max-w-md flex-col gap-3 rounded-lg border border-accent-cyan/50 bg-[#0b1226] p-4 text-ink-primary">
        <h2 className="text-sm font-semibold text-accent-cyan">{ready ? t('updReadyTitle', { v: info.version }) : t('updPromptTitle', { v: info.version })}</h2>
        <p className="text-xs text-ink-secondary">{ready ? t('updReadyBody') : t('updPromptBody', { c: info.current })}</p>
        {info.notes && <p className="max-h-32 overflow-auto whitespace-pre-wrap text-xs text-ink-muted">{info.notes}</p>}
        {phase === 'installing' && <p className="text-xs text-ink-secondary" role="status">{t('updInstalling')}</p>}
        <div className="flex gap-2">
          <button type="button" className={btnPrimary} disabled={phase === 'installing'} onClick={() => void installUpdate(updateIpc)} data-testid="update-now">{ready ? t('updRestart') : t('updNow')}</button>
          <button type="button" className={btn} disabled={phase === 'installing'} onClick={dismissUpdate} data-testid="update-later">{t('updLater')}</button>
        </div>
      </section>
    </div>
  );
}

export function UpdateSection() {
  const { t } = usePT();
  const on = usePevv((s) => s.prefs.autoUpdate);
  const mode = usePevv((s) => normalizeMode(s.prefs.updateMode));
  const phase = useUpdate((s) => s.phase);
  const error = useUpdate((s) => s.error);
  return (
    <Section title={t('updTitle')} testId="pevv-updates">
      <p className="text-xs text-ink-muted">{t('updIntro')}</p>
      <label className="flex flex-col gap-1 text-xs text-ink-secondary">
        {t('updModeLabel')}
        <select className={input} value={mode} onChange={(e) => setPrefs({ updateMode: e.target.value as UpdateMode })} data-testid="pevv-update-mode">
          <option value="manual">{t('updModeManual')}</option>
          <option value="download">{t('updModeDownload')}</option>
          <option value="install">{t('updModeInstall')}</option>
        </select>
      </label>
      <p className="text-xs text-ink-muted">{t('updModeNote')}</p>
      <label className="flex items-center gap-2 text-xs text-ink-secondary">
        <input type="checkbox" checked={on} onChange={(e) => setPrefs({ autoUpdate: e.target.checked })} data-testid="pevv-autoupdate" /> {t('updToggle')}
      </label>
      <div className="flex items-center gap-2">
        <button type="button" className={btn} disabled={phase === 'checking' || phase === 'downloading' || phase === 'installing'} onClick={() => void checkForUpdate(updateIpc, true)} data-testid="pevv-update-check">{t('updCheckNow')}</button>
        <span className="text-xs text-ink-secondary" role="status" data-testid="pevv-update-state">
          {phase === 'checking' || phase === 'downloading' ? t('updChecking') : phase === 'upToDate' ? t('updUpToDate') : phase === 'disabled' ? t('updDisabled') : phase === 'error' && error ? t('updFailed', { e: error }) : ''}
        </span>
      </div>
    </Section>
  );
}
