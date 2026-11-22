/** USB key file and presence lock UI. The key-file reader works in every client; creating one and the presence lock are desktop-only. */
import { useCallback, useEffect, useState } from 'react';
import { usePT } from '../i18n';
import { addUsbKey, removeUsbKey, setRequireUsbKey, usePevv } from '../store';
import { getNative, type PresenceState, type UsbDevice, type UsbVolume } from '../native';
import { usbKeySlots } from '../vault';
import { ErrorLine, Section, btn, btnDanger, btnPrimary, input, label, readFileText, useReauthGate } from './common';

/**
 * Hands the text of a key file to `onText`: from a file the person picks (all clients), or
 * from a removable drive the desktop app finds.
 */
export function UsbKeyReader({ onText, busy }: { onText: (text: string) => void; busy?: boolean }) {
  const { t } = usePT();
  const native = getNative();
  const [volumes, setVolumes] = useState<UsbVolume[]>([]);
  const [note, setNote] = useState<string | null>(null);
  const refresh = useCallback(() => {
    if (!native) return;
    void native.usb.volumes().then((v) => { setVolumes(v.filter((x) => x.hasKeyFile)); setNote(null); }, () => setVolumes([]));
  }, [native]);
  useEffect(refresh, [refresh]);
  return (
    <div className="flex flex-col gap-2" data-testid="pevv-usbkey-reader">
      {native && volumes.map((v) => (
        <button key={v.path} type="button" className={btnPrimary} disabled={busy} data-testid="pevv-usbkey-drive"
          onClick={() => void native.usb.readKeyFile(v.path).then(onText, (e: Error) => setNote(e.message))}>
          💾 {t('usbKeyFromDrive', { label: v.label || v.path })}
        </button>
      ))}
      {native && !volumes.length && (
        <p className="text-xs text-ink-muted">{t('usbKeyNoFile')} <button type="button" className="underline" onClick={refresh}>{t('usbKeyRefresh')}</button></p>
      )}
      <label className={label}>
        {t('usbKeyChoose')}
        <input type="file" className="text-xs" data-testid="pevv-usbkey-file" onChange={async (e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          try { onText(await readFileText(f)); } catch (err) { setNote((err as Error).message); }
          e.target.value = '';
        }} />
      </label>
      {note && <p className="text-xs text-accent-red">{note}</p>}
    </div>
  );
}

/** Settings: create, list and remove key files; require one after the password. */
export function UsbKeySection() {
  const { t } = usePT();
  const file = usePevv((s) => s.file);
  const meta = usePevv((s) => s.meta);
  const busy = usePevv((s) => s.busy);
  const native = getNative();
  const [volumes, setVolumes] = useState<UsbVolume[]>([]);
  const [drive, setDrive] = useState('');
  const [name, setName] = useState('');
  const [mode, setMode] = useState<'unlock' | 'second-factor'>('unlock');
  const [msg, setMsg] = useState<string | null>(null);
  const [gateNode, gate] = useReauthGate();
  const refresh = useCallback(() => {
    if (!native) return;
    void native.usb.volumes().then((v) => { setVolumes(v); setDrive((d) => (v.some((x) => x.path === d) ? d : v[0]?.path ?? '')); }, () => setVolumes([]));
  }, [native]);
  useEffect(refresh, [refresh]);
  const slots = file ? usbKeySlots(file) : [];
  const gates = meta?.usbKeys ?? [];
  const create = () => gate(() => {
    if (!native || !drive) return;
    setMsg(null);
    void addUsbKey(name, mode, (text) => native.usb.writeKeyFile(drive, text).catch((e: Error) => {
      throw new Error(e.message === 'exists' ? t('usbKeyExists') : e.message);
    })).then(() => { setName(''); setMsg(t('usbKeyDone')); refresh(); }, () => undefined);
  });
  return (
    <Section title={t('usbKeyTitle')} testId="pevv-usbkey">
      <p className="text-xs text-ink-secondary">{t('usbKeyIntro')}</p>
      <p className="rounded border border-accent-gold/40 bg-accent-gold/5 p-2 text-xs text-accent-gold" data-testid="pevv-usbkey-weak">{t('usbKeyWeak')}</p>
      {(slots.length > 0 || gates.length > 0) && (
        <div className="flex flex-col gap-1">
          <h4 className="text-xs text-ink-secondary">{t('usbKeyList')}</h4>
          <ul className="flex flex-col gap-1" data-testid="pevv-usbkey-list">
            {[...slots.map((s) => ({ id: s.id, name: s.name, kind: t('usbKeyKindUnlock') })), ...gates.map((g) => ({ id: g.id, name: g.name, kind: t('usbKeyKindSecond') }))].map((k) => (
              <li key={k.id} className="flex flex-wrap items-center gap-2 rounded border border-space-border/60 p-2 text-xs">
                <span aria-hidden>💾</span>
                <span className="min-w-0 flex-1 truncate text-cyan-50">{k.name}</span>
                <span className="rounded-full bg-accent-gold/20 px-2 text-[0.6rem] text-accent-gold">{k.kind}</span>
                <button type="button" className={btnDanger} onClick={() => gate(() => void removeUsbKey(k.id).catch(() => undefined))}>{t('remove')}</button>
              </li>
            ))}
          </ul>
        </div>
      )}
      {native ? (
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-end gap-2">
            <label className={`${label} min-w-[10rem] flex-1`}>
              {t('usbKeyDrive')}
              <select className={input} value={drive} onChange={(e) => setDrive(e.target.value)} data-testid="pevv-usbkey-drive-select">
                {!volumes.length && <option value="">{t('usbKeyNoDrive')}</option>}
                {volumes.map((v) => <option key={v.path} value={v.path}>{v.label || v.path} ({v.path}){v.hasKeyFile ? ' ✓' : ''}</option>)}
              </select>
            </label>
            <button type="button" className={btn} onClick={refresh}>{t('usbKeyRefresh')}</button>
          </div>
          <input className={`${input} max-w-xs`} value={name} onChange={(e) => setName(e.target.value)} placeholder={t('usbKeyName')} aria-label={t('usbKeyName')} data-testid="pevv-usbkey-name" />
          <label className="flex items-center gap-2 text-xs text-ink-secondary">
            <input type="radio" name="usbmode" checked={mode === 'unlock'} onChange={() => setMode('unlock')} /> {t('usbKeyModeUnlock')}
          </label>
          <label className="flex items-center gap-2 text-xs text-ink-secondary">
            <input type="radio" name="usbmode" checked={mode === 'second-factor'} onChange={() => setMode('second-factor')} /> {t('usbKeyModeSecond')}
          </label>
          <div><button type="button" className={btnPrimary} disabled={busy || !drive} onClick={create} data-testid="pevv-usbkey-create">＋ {t('usbKeyCreate')}</button></div>
        </div>
      ) : (
        <p className="text-xs text-ink-muted">{t('usbKeyDesktopOnly')}</p>
      )}
      {msg && <p className="text-xs text-accent-green" data-testid="pevv-usbkey-msg">{msg}</p>}
      <label className="flex items-center gap-2 text-xs text-ink-secondary">
        <input type="checkbox" disabled={!gates.length} checked={!!meta?.require.usbKey} onChange={(e) => void setRequireUsbKey(e.target.checked).catch(() => undefined)} data-testid="pevv-require-usbkey" />
        {t('usbKeyRequire')}
      </label>
      <ErrorLine />
      {gateNode}
    </Section>
  );
}

/** Settings (desktop): the presence-lock device. Never an unlock factor. */
export function PresenceSection() {
  const { t } = usePT();
  const native = getNative();
  const [devices, setDevices] = useState<UsbDevice[]>([]);
  const [state, setState] = useState<PresenceState>({ designation: null, present: null });
  const [pick, setPick] = useState('');
  const [error, setError] = useState<string | null>(null);
  const refresh = useCallback(() => {
    if (!native) return;
    void Promise.all([native.usb.devices(), native.usb.presence()]).then(([d, s]) => { setDevices(d); setState(s); setError(null); }, (e: Error) => setError(e.message));
  }, [native]);
  useEffect(refresh, [refresh]);
  if (!native) return null;
  const des = state.designation;
  const save = (next: { id: string; name: string; requireToUnlock: boolean } | null) => {
    void native.usb.setPresence(next).then(refresh, (e: Error) => setError(e.message));
  };
  const describe = (d: UsbDevice) => `${d.name || t('presenceDevice')} (${d.vid}:${d.pid}${d.serial ? '' : ', port'})`;
  return (
    <Section title={t('presenceTitle')} testId="pevv-presence">
      <p className="text-xs text-ink-secondary">{t('presenceIntro')}</p>
      <p className="rounded border border-accent-gold/40 bg-accent-gold/5 p-2 text-xs text-accent-gold" data-testid="pevv-presence-weak">{t('presenceWeak')}</p>
      {des && (
        <p className="text-xs text-cyan-50" data-testid="pevv-presence-current">
          {des.name} · {t('presenceNow', { state: state.present === null ? t('presenceUnknown') : state.present ? t('presenceHere') : t('presenceGone') })}
        </p>
      )}
      <div className="flex flex-wrap items-end gap-2">
        <label className={`${label} min-w-[10rem] flex-1`}>
          {t('presenceDevice')}
          <select className={input} value={pick} onChange={(e) => setPick(e.target.value)} data-testid="pevv-presence-select">
            <option value="">{t('presenceNone')}</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{describe(d)}</option>)}
          </select>
        </label>
        <button type="button" className={btn} onClick={refresh}>{t('presenceRefresh')}</button>
        <button type="button" className={btnPrimary} disabled={!pick} data-testid="pevv-presence-set"
          onClick={() => { const d = devices.find((x) => x.id === pick); if (d) save({ id: d.id, name: describe(d), requireToUnlock: des?.requireToUnlock ?? false }); }}>{t('presenceSet')}</button>
        {des && <button type="button" className={btnDanger} onClick={() => save(null)}>{t('presenceClear')}</button>}
      </div>
      {des && (
        <label className="flex items-center gap-2 text-xs text-ink-secondary">
          <input type="checkbox" checked={des.requireToUnlock} onChange={(e) => save({ ...des, requireToUnlock: e.target.checked })} data-testid="pevv-presence-require" />
          {t('presenceRequire')}
        </label>
      )}
      {error && <p className="text-xs text-accent-red">{error}</p>}
    </Section>
  );
}
