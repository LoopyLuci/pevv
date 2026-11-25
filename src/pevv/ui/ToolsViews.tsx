/** PEVV generator, security health and settings. */
import { useMemo, useState } from 'react';
import { usePT } from '../i18n';
import { DEFAULT_GEN, DEFAULT_PHRASE, type GenOpts, type PhraseOpts, generatePassphrase, generatePassword, generatorEntropy, phraseEntropy } from '../gen';
import { reuseGroups } from '../model';
import { auditCsv, watchtower } from '../extra';
import { syncEnabled } from '../host/cloud';
import { SyncAccountBox } from './SyncAccount';
import { SyncStatusPanel } from './SyncStatus';
import { otpauthUri, type TotpConfig } from '../totp';
import {
  addPasskey, clearAudit, importCsvText, linkProgramEnv, renamePasskey, changeMasterPassword, confirmTotpEnrollment, destroyVault, disableTotp, exportVault, importVault, lock, newRecoveryCodes, newRecoveryKit,
  removePasskey, renameThisDevice, revokeAndRotate, revokeDevice, revokeGrant, setPrefs, setRequirePasskey, startTotpEnrollment, usePevv,
} from '../store';
import { recoveryStatus, peekExport } from '../vault';
import { localDeviceId } from '../devices';
import { inDesktopApp, inExtensionPage, nativePasskeysAvailable, passkeyEnrolAvailable, webauthnAvailable } from '../webauthn';
import { getNative } from '../native';
import { PresenceSection, UsbKeySection } from './UsbViews';
import { BrowserLinkSection } from '../desktop/BrowserLink';
import { TransferdSection } from '../desktop/TransferdPanel';
import { AutoTypeSection } from '../desktop/AutoType';
import { CliAccessSection } from '../desktop/CliAccess';
import { PasskeyProviderSection } from '../desktop/PasskeyProvider';
import { UpdateSection } from '../desktop/UpdatePrompt';
import { NewPasswordFields } from './AuthViews';
import { CopyButton, ErrorLine, QrCode, Section, btn, btnDanger, btnPrimary, download, input, label, readFileText, useReauthGate } from './common';
import { QrScanBox, QrShareButton } from './QrShare';

export function GeneratorView({ onUse }: { onUse: (pw: string) => void }) {
  const { t } = usePT();
  const [mode, setMode] = useState<'password' | 'phrase'>('password');
  const [g, setG] = useState<GenOpts>(DEFAULT_GEN);
  const [p, setP] = useState<PhraseOpts>(DEFAULT_PHRASE);
  const [seed, setSeed] = useState(0);
  const value = useMemo(() => (mode === 'password' ? generatePassword(g) : generatePassphrase(p)), [mode, g, p, seed]); // eslint-disable-line react-hooks/exhaustive-deps
  const bits = mode === 'password' ? generatorEntropy(g) : phraseEntropy(p);
  const chk = (k: keyof GenOpts, text: string) => (
    <label className="flex items-center gap-2 text-xs text-ink-secondary"><input type="checkbox" checked={!!g[k]} onChange={(e) => setG({ ...g, [k]: e.target.checked })} data-testid={`pevv-gen-${k}`} /> {text}</label>
  );
  return (
    <div className="flex min-h-0 flex-col gap-3 overflow-y-auto p-3" data-testid="pevv-generator">
      <div className="flex gap-1" role="tablist">
        <button type="button" role="tab" aria-selected={mode === 'password'} className={mode === 'password' ? btnPrimary : btn} onClick={() => setMode('password')}>{t('genPassword')}</button>
        <button type="button" role="tab" aria-selected={mode === 'phrase'} className={mode === 'phrase' ? btnPrimary : btn} onClick={() => setMode('phrase')} data-testid="pevv-gen-phrase">{t('genPassphrase')}</button>
      </div>
      <output className="break-all rounded-md border border-cyan-500/30 bg-space-deep p-3 font-mono text-base text-cyan-50" data-testid="pevv-gen-output">{value}</output>
      <p className="text-[0.65rem] text-ink-muted">≈ {bits} {t('bits')} · {t('genOffline')}</p>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={btn} onClick={() => setSeed((s) => s + 1)} data-testid="pevv-gen-again">⟳ {t('regenerate')}</button>
        <CopyButton value={value} testId="pevv-gen-copy" />
        <button type="button" className={btnPrimary} onClick={() => onUse(value)}>{t('useInNewLogin')}</button>
      </div>
      {mode === 'password' ? (
        <div className="flex flex-col gap-2">
          <label className={label}>{t('length')}: {g.length}<input type="range" min={8} max={128} value={g.length} onChange={(e) => setG({ ...g, length: +e.target.value })} data-testid="pevv-gen-length" /></label>
          {chk('lower', 'a–z')}{chk('upper', 'A–Z')}{chk('digits', '0–9')}{chk('symbols', '!@#…')}{chk('avoidAmbiguous', t('avoidAmbiguous'))}
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          <label className={label}>{t('words')}: {p.words}<input type="range" min={4} max={12} value={p.words} onChange={(e) => setP({ ...p, words: +e.target.value })} /></label>
          <label className={label}>{t('separator')}<input className={`${input} max-w-[6rem]`} maxLength={3} value={p.separator} onChange={(e) => setP({ ...p, separator: e.target.value })} /></label>
          <label className="flex items-center gap-2 text-xs text-ink-secondary"><input type="checkbox" checked={p.capitalize} onChange={(e) => setP({ ...p, capitalize: e.target.checked })} /> {t('capitalize')}</label>
          <label className="flex items-center gap-2 text-xs text-ink-secondary"><input type="checkbox" checked={p.number} onChange={(e) => setP({ ...p, number: e.target.checked })} /> {t('addNumber')}</label>
          <p className="text-[0.62rem] text-ink-muted">{t('effCredit')}</p>
        </div>
      )}
    </div>
  );
}

export function HealthView({ onOpen }: { onOpen: (id: string) => void }) {
  const { t } = usePT();
  const entries = usePevv((s) => s.entries);
  const file = usePevv((s) => s.file);
  const meta = usePevv((s) => s.meta);
  const warnings = usePevv((s) => s.warnings);
  const reuse = reuseGroups(entries);
  const w = useMemo(() => watchtower(entries, reuse), [entries]); // eslint-disable-line react-hooks/exhaustive-deps
  const { weak, common, reused, old } = w;
  const rec = file ? recoveryStatus(file) : { codes: 0, key: false, prf: 0, usb: 0 };
  const list = (title: string, items: typeof entries, testId: string) => (
    <Section title={`${title} (${items.length})`} testId={testId}>
      {items.length === 0 ? <p className="text-xs text-accent-green">✓ {t('allGood')}</p> : (
        <ul className="flex flex-col gap-1">{items.map((e) => <li key={e.id}><button type="button" className="text-left text-xs text-accent-cyan underline" onClick={() => onOpen(e.id)}>{e.title}</button></li>)}</ul>
      )}
    </Section>
  );
  return (
    <div className="flex min-h-0 flex-col gap-3 overflow-y-auto p-3" data-testid="pevv-health">
      <div className="flex items-center gap-3 rounded-md border border-cyan-500/30 bg-space-deep/60 p-3" data-testid="pevv-health-score">
        <span className={`font-display text-3xl tabular-nums ${w.score >= 90 ? 'text-accent-green' : w.score >= 60 ? 'text-accent-gold' : 'text-red-300'}`}>{w.score}</span>
        <span className="flex flex-col"><span className="text-xs text-cyan-50">{t('watchScore')}</span><span className="text-[0.62rem] text-ink-muted">{t('healthLocal')}</span></span>
      </div>
      <p className="text-xs text-ink-secondary">{t('healthIntro')}</p>
      {warnings.length > 0 && (
        <Section title={t('integrity')} testId="pevv-integrity">
          <ul className="list-disc pl-4 text-xs text-accent-gold">{warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </Section>
      )}
      <Section title={t('protection')}>
        <ul className="flex flex-col gap-1 text-xs">
          <li>{file?.kdf.alg === 'argon2id' ? '✓' : '•'} {t('kdfLine', { alg: file?.kdf.alg === 'argon2id' ? `Argon2id ${Math.round((file.kdf.m) / 1024)} MiB × ${file.kdf.t}` : `PBKDF2-SHA256 × ${file?.kdf.alg === 'pbkdf2-sha256' ? file.kdf.iter.toLocaleString() : ''}` })}</li>
          <li>{meta?.require.totp ? '✓' : '○'} {t('totpLine')}</li>
          <li>{(file?.passkeys.length ?? 0) > 0 ? '✓' : '○'} {t('passkeyLine', { n: file?.passkeys.length ?? 0, prf: rec.prf })}</li>
          <li>{rec.codes > 0 ? '✓' : '⚠'} {t('codesLine', { n: rec.codes })}</li>
          <li>{rec.key ? '✓' : '○'} {t('kitLine')}</li>
        </ul>
      </Section>
      {list(t('weakPw'), weak, 'pevv-health-weak')}
      {list(t('commonPw'), common, 'pevv-health-common')}
      {list(t('reusedPw'), reused, 'pevv-health-reused')}
      {list(t('oldPw'), old, 'pevv-health-old')}
      {list(t('insecureSites'), w.insecure, 'pevv-health-insecure')}
      {list(t('duplicates'), w.duplicates, 'pevv-health-duplicates')}
      {list(t('no2fa'), w.no2fa, 'pevv-health-no2fa')}
      {entries.some((e) => e.type === 'card') && list(t('cardsExpired'), w.cardsExpired, 'pevv-health-cards-expired')}
      {entries.some((e) => e.type === 'card') && list(t('cardsSoon'), w.cardsSoon, 'pevv-health-cards-soon')}
      {entries.some((e) => e.type === 'card') && list(t('cardsInvalid'), w.cardsInvalid, 'pevv-health-cards-invalid')}
      {entries.some((e) => e.type === 'ssh') && list(t('sshUnprotected'), w.sshUnprotected, 'pevv-health-ssh')}
    </div>
  );
}

function PasskeySection() {
  const { t } = usePT();
  const file = usePevv((s) => s.file);
  const meta = usePevv((s) => s.meta);
  const busy = usePevv((s) => s.busy);
  const [name, setName] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  const supported = passkeyEnrolAvailable();
  const native = getNative();
  const add = async (authenticator?: 'platform' | 'cross-platform') => {
    setMsg(null);
    try {
      const rec = await addPasskey(name || (authenticator === 'platform' ? t('thisDevice') : t('securityKey')), { wantPrf: true, ...(authenticator ? { authenticator } : {}) });
      setName('');
      setMsg(rec.mode === 'prf' ? t('passkeyPrfOk') : t('passkey2faOnly'));
    } catch { /* shown */ }
  };
  return (
    <Section title={t('passkeys')} testId="pevv-passkeys">
      <p className="text-xs text-ink-secondary">{t('passkeysIntro')}</p>
      {!supported && !inDesktopApp() && <p className="text-xs text-accent-gold" data-testid="pevv-passkey-unsupported">{t(inExtensionPage() ? 'passkeyExtension' : 'noWebauthn')}</p>}
      {inDesktopApp() && nativePasskeysAvailable() && (
        <p className="text-xs text-ink-secondary" data-testid="pevv-passkey-desktop">{t('passkeyDesktopEnrol')}{native?.passkey.support.appPin ? ` ${t('passkeyDesktopPin')}` : ''}</p>
      )}
      {inDesktopApp() && !webauthnAvailable() && (
        <p className="text-xs text-accent-gold" data-testid="pevv-passkey-unsupported">{t('passkeyDesktop')}{native?.passkey.support.reason ? ` ${native.passkey.support.reason}` : ''}</p>
      )}
      <ul className="flex flex-col gap-1" data-testid="pevv-passkey-list">
        {(file?.passkeys ?? []).map((p) => (
          <li key={p.id} className="flex flex-wrap items-center gap-2 rounded border border-space-border/60 p-2 text-xs">
            <span aria-hidden>🔑</span>
            {renaming?.id === p.id ? (
              <form className="flex min-w-0 flex-1 gap-1" onSubmit={(e) => { e.preventDefault(); void renamePasskey(p.id, renaming.name).then(() => setRenaming(null), () => undefined); }}>
                <input autoFocus className={`${input} min-h-8 text-xs`} value={renaming.name} maxLength={40} onChange={(e) => setRenaming({ id: p.id, name: e.target.value })} aria-label={t('rename')} data-testid="pevv-passkey-rename-name" />
                <button type="submit" className={btn}>OK</button>
              </form>
            ) : (
              <span className="flex min-w-0 flex-1 flex-col">
                <span className="truncate text-cyan-50" data-testid="pevv-passkey-label">{p.name}</span>
                <span className="text-[0.6rem] text-ink-muted">{p.lastUsed ? t('lastUsed', { d: new Date(p.lastUsed).toLocaleDateString() }) : t('neverUsed')}</span>
              </span>
            )}
            <span className={`rounded-full px-2 text-[0.6rem] ${p.mode === 'prf' ? 'bg-accent-green/20 text-accent-green' : 'bg-accent-gold/20 text-accent-gold'}`} data-testid={`pevv-passkey-mode-${p.mode}`}>
              {p.mode === 'prf' ? t('modePrf') : t('mode2fa')}
            </span>
            <span className="text-[0.6rem] text-ink-muted">{p.transports.join(', ')}</span>
            {renaming?.id !== p.id && <button type="button" className={btn} onClick={() => setRenaming({ id: p.id, name: p.name })} data-testid="pevv-passkey-rename">{t('rename')}</button>}
            <button type="button" className={btnDanger} onClick={() => void removePasskey(p.id)}>{t('remove')}</button>
          </li>
        ))}
      </ul>
      {supported && (
        <div className="flex flex-wrap gap-2">
          <input className={`${input} max-w-xs`} value={name} onChange={(e) => setName(e.target.value)} placeholder={t('passkeyName')} aria-label={t('passkeyName')} data-testid="pevv-passkey-name" />
          <button type="button" className={btnPrimary} disabled={busy} onClick={() => void add()} data-testid="pevv-passkey-add">＋ {t('addPasskey')}</button>
          <button type="button" className={btn} disabled={busy} onClick={() => void add('cross-platform')}>＋ {t('addSecurityKey')}</button>
        </div>
      )}
      {msg && <p className="text-xs text-ink-secondary" data-testid="pevv-passkey-msg">{msg}</p>}
      <label className="flex items-center gap-2 text-xs text-ink-secondary">
        <input type="checkbox" disabled={!file?.passkeys.length} checked={!!meta?.require.passkey} onChange={(e) => void setRequirePasskey(e.target.checked).catch(() => undefined)} data-testid="pevv-require-passkey" />
        {t('requirePasskey')}
      </label>
    </Section>
  );
}

function TotpSection() {
  const { t } = usePT();
  const totp = usePevv((s) => s.totp);
  const busy = usePevv((s) => s.busy);
  const [enroll, setEnroll] = useState<TotpConfig | null>(null);
  const [code, setCode] = useState('');
  const [gateNode, gate] = useReauthGate();
  const uri = enroll ? otpauthUri(enroll, 'vault') : '';
  return (
    <Section title={t('totpTitle')} testId="pevv-totp">
      <p className="text-xs text-ink-secondary">{t('totpIntro')}</p>
      {totp && !enroll && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-accent-green" data-testid="pevv-totp-on">✓ {t('totpOn')}</span>
          <button type="button" className={btnDanger} onClick={() => gate(() => void disableTotp().catch(() => undefined))}>{t('turnOff')}</button>
        </div>
      )}
      {!totp && !enroll && <button type="button" className={btnPrimary} onClick={() => setEnroll(startTotpEnrollment())} data-testid="pevv-totp-enroll">{t('setUpTotp')}</button>}
      {enroll && (
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-start gap-3">
            <QrCode text={uri} testId="pevv-totp-qr" />
            <div className="flex min-w-0 flex-1 flex-col gap-1 text-xs">
              <p className="text-ink-secondary">{t('scanQr')}</p>
              <p className="text-ink-muted">{t('orEnterKey')}</p>
              <code className="break-all rounded bg-space-deep p-1 font-mono text-cyan-100" data-testid="pevv-totp-secret">{enroll.secret.match(/.{1,4}/g)!.join(' ')}</code>
              <p className="text-[0.6rem] text-ink-muted">SHA-1 · 6 {t('digits')} · 30 s</p>
            </div>
          </div>
          <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); void confirmTotpEnrollment(enroll, code).then(() => { setEnroll(null); setCode(''); }, () => setCode('')); }}>
            <input inputMode="numeric" autoComplete="one-time-code" maxLength={6} className={`${input} max-w-[10rem] font-mono tracking-[0.3em]`} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} aria-label={t('authenticatorCode')} data-testid="pevv-totp-confirm-code" />
            <button type="submit" className={btnPrimary} disabled={busy || code.length !== 6} data-testid="pevv-totp-confirm">{t('verifyAndTurnOn')}</button>
            <button type="button" className={btn} onClick={() => setEnroll(null)}>{t('cancel')}</button>
          </form>
        </div>
      )}
      {gateNode}
      <p className="text-[0.62rem] text-ink-muted">{t('gateHonesty')}</p>
    </Section>
  );
}

function RecoverySection() {
  const { t } = usePT();
  const file = usePevv((s) => s.file);
  const busy = usePevv((s) => s.busy);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [kitPw, setKitPw] = useState('');
  const [kitKey, setKitKey] = useState<string | null>(null);
  const [gateNode, gate] = useReauthGate();
  const rec = file ? recoveryStatus(file) : { codes: 0, key: false, prf: 0, usb: 0 };
  return (
    <Section title={t('recovery')} testId="pevv-recovery">
      <p className="text-xs text-ink-secondary">{t('recoveryIntro')}</p>
      <p className="text-xs" data-testid="pevv-codes-left">{t('codesLine', { n: rec.codes })}</p>
      <button type="button" className={btnPrimary} disabled={busy} data-testid="pevv-codes-generate" onClick={() => gate(() => void newRecoveryCodes().then(setCodes, () => undefined))}>
        {rec.codes ? t('regenCodes') : t('genCodes')}
      </button>
      {codes && (
        <div className="flex flex-col gap-2 rounded-md border border-accent-gold/40 bg-accent-gold/5 p-2">
          <p className="text-xs text-accent-gold">{t('codesOnce')}</p>
          <ol className="grid grid-cols-1 gap-1 font-mono text-xs text-cyan-50 sm:grid-cols-2" data-testid="pevv-codes">
            {codes.map((c) => <li key={c}>{c}</li>)}
          </ol>
          <div className="flex gap-2">
            <CopyButton value={codes.join('\n')} />
            <button type="button" className={btn} onClick={() => download('pevv-recovery-codes.txt', `PEVV recovery codes (each works once)\nVault ${file?.id}\n\n${codes.join('\n')}\n`, 'text/plain')}>{t('download')}</button>
            <button type="button" className={btn} onClick={() => setCodes(null)} data-testid="pevv-codes-done">{t('iSavedThem')}</button>
          </div>
        </div>
      )}
      <div className="flex flex-col gap-2 border-t border-space-border/60 pt-2">
        <p className="text-xs text-ink-secondary">{t('kitIntro')}</p>
        <div className="flex flex-wrap gap-2">
          <input type="password" className={`${input} max-w-xs`} value={kitPw} onChange={(e) => setKitPw(e.target.value)} placeholder={t('kitPassphrase')} aria-label={t('kitPassphrase')} data-testid="pevv-kit-new-pass" />
          <button type="button" className={btn} disabled={busy || kitPw.length < 10} data-testid="pevv-kit-create" onClick={() => gate(() => void newRecoveryKit(kitPw).then(({ kit, key }) => {
            download(`pevv-recovery-kit-${kit.vaultId.slice(0, 8)}.json`, JSON.stringify(kit, null, 2));
            setKitKey(key);
            setKitPw('');
          }, () => undefined))}>{t('createKit')}</button>
        </div>
        {kitPw && kitPw.length < 10 && <p className="text-[0.62rem] text-ink-muted">{t('kitMin')}</p>}
        {kitKey && (
          <div className="flex flex-col gap-1 rounded-md border border-accent-gold/40 bg-accent-gold/5 p-2 text-xs">
            <p className="text-accent-gold">{t('kitKeyOnce')}</p>
            <code className="break-all font-mono text-cyan-50" data-testid="pevv-kit-key">{kitKey}</code>
            <div className="flex gap-2"><CopyButton value={kitKey} /><button type="button" className={btn} onClick={() => setKitKey(null)}>{t('iSavedThem')}</button></div>
          </div>
        )}
      </div>
      {gateNode}
    </Section>
  );
}

export function DevicesView() {
  const { t, locale } = usePT();
  const meta = usePevv((s) => s.meta);
  const busy = usePevv((s) => s.busy);
  const me = localDeviceId();
  const [name, setName] = useState('');
  const [editing, setEditing] = useState(false);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [rotate, setRotate] = useState(true);
  const [pw, setPw] = useState('');
  const [rotateError, setRotateError] = useState<string | null>(null);
  const [rotated, setRotated] = useState<{ codes: string[]; recoveryKey: string | null; dropped: string[] } | null>(null);
  const [gateNode, gate] = useReauthGate();
  const devices = meta?.devices ?? [];
  const doRemove = (id: string) => {
    setRotateError(null);
    const done = () => { setConfirm(null); setPw(''); };
    if (!rotate) { void revokeDevice(id).then(done).catch(() => undefined); return; }
    void revokeAndRotate(id, pw)
      .then((r) => { setRotated({ codes: r.codes, recoveryKey: r.recoveryKey, dropped: r.dropped.map((d) => d.name ?? d.type) }); done(); })
      .catch((e: Error) => setRotateError(e.message));
  };
  const fmt = new Intl.DateTimeFormat(locale === 'es' ? 'es' : 'en-US', { dateStyle: 'medium', timeStyle: 'short' });
  const ago = (seen: number) => {
    const s = Math.max(0, Date.now() - seen);
    if (s < 60_000) return t('seenJust');
    if (s < 3_600_000) return t('seenMin', { n: Math.floor(s / 60_000) });
    if (s < 86_400_000) return t('seenHour', { n: Math.floor(s / 3_600_000) });
    return t('seenDay', { n: Math.floor(s / 86_400_000) });
  };
  const kindKey = (k: string) => (k === 'phone' ? 'kindPhone' : k === 'tablet' ? 'kindTablet' : k === 'desktop' ? 'kindDesktop' : 'kindUnknown');
  return (
    <div className="flex min-h-0 flex-col gap-3 overflow-y-auto p-3" data-testid="pevv-devices">
      {gateNode}
      <Section title={t('devices')}>
        <p className="text-xs text-ink-secondary">{t('devicesIntro')}</p>
        {devices.length === 0 ? <p className="text-xs text-ink-muted">{t('noOtherDevices')}</p> : (
          <ul className="flex flex-col gap-2">
            {devices.map((d) => (
              <li key={d.id} className="flex flex-col gap-1 rounded-md border border-space-border/70 bg-space-surface/40 p-2 text-xs" data-testid={`pevv-device-${d.id === me ? 'self' : d.id}`}>
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-medium text-cyan-50">{d.name}</span>
                  {d.id === me && <span className="rounded bg-accent-cyan/15 px-1.5 text-[0.62rem] text-accent-cyan">{t('thisDevice')}</span>}
                </div>
                <p className="text-ink-muted">{t(kindKey(d.kind) as 'kindDesktop')}{d.agent ? ` · ${d.agent}` : ''}</p>
                <p className="text-ink-secondary">{t('lastOpened', { when: ago(d.seen) })} · {t('addedOn', { when: d.added ? fmt.format(d.added) : '—' })}</p>
                {d.id === me ? (
                  editing ? (
                    <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); void renameThisDevice(name).then(() => setEditing(false)).catch(() => undefined); }}>
                      <input className={`${input} max-w-xs`} value={name} onChange={(e) => setName(e.target.value)} maxLength={40} aria-label={t('deviceName')} data-testid="pevv-device-name" />
                      <button type="submit" className={btn} disabled={busy || !name.trim()}>{t('renameDevice')}</button>
                      <button type="button" className={btn} onClick={() => setEditing(false)}>{t('cancel')}</button>
                    </form>
                  ) : (
                    <button type="button" className={btn} onClick={() => { setName(d.name); setEditing(true); }} data-testid="pevv-device-rename">{t('renameDevice')}</button>
                  )
                ) : confirm === d.id ? (
                  <div className="flex flex-col gap-2">
                    <label className="flex items-start gap-2 text-ink-secondary"><input type="checkbox" checked={rotate} onChange={(e) => setRotate(e.target.checked)} className="mt-0.5" data-testid="pevv-device-rotate" /> <span>{t('removeRotate')}<br /><span className="text-[0.62rem] text-ink-muted">{t('rotateWhy')}</span></span></label>
                    {rotate && <input type="password" className={`${input} max-w-xs`} value={pw} onChange={(e) => setPw(e.target.value)} placeholder={t('rotatePassword')} aria-label={t('rotatePassword')} autoComplete="current-password" data-testid="pevv-device-rotate-password" />}
                    {rotateError && <p className="text-amber-300" role="alert">{rotateError}</p>}
                    <div className="flex flex-wrap gap-2">
                      <button type="button" className={btnDanger} disabled={busy || (rotate && !pw)} data-testid="pevv-device-remove-confirm" onClick={() => gate(() => doRemove(d.id), t('reauthExport'))}>{t('confirmRemoveDevice')}</button>
                      <button type="button" className={btn} onClick={() => { setConfirm(null); setPw(''); }}>{t('cancel')}</button>
                    </div>
                  </div>
                ) : (
                  <button type="button" className={btnDanger} data-testid={`pevv-device-remove-${d.id}`} onClick={() => setConfirm(d.id)}>{t('removeDevice')}</button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>
      {rotated && (
        <Section title={t('rotateNewCodes')} testId="pevv-rotated">
          <p className="text-xs text-ink-secondary">{t('rotateDone')}</p>
          {rotated.codes.length > 0 && <pre className="select-all rounded-md bg-space-surface/60 p-2 text-xs" data-testid="pevv-rotated-codes">{rotated.codes.join('\n')}</pre>}
          {rotated.recoveryKey && <><p className="text-xs text-ink-secondary">{t('rotateNewKey')}</p><pre className="select-all rounded-md bg-space-surface/60 p-2 text-xs">{rotated.recoveryKey}</pre></>}
          {rotated.dropped.length > 0 && <p className="text-xs text-amber-300">{t('rotateDropped', { list: rotated.dropped.join(', ') })}</p>}
          <button type="button" className={btn} onClick={() => setRotated(null)}>{t('iSavedThem')}</button>
        </Section>
      )}
      <ErrorLine />
    </div>
  );
}

export function SettingsView() {
  const { t } = usePT();
  const prefs = usePevv((s) => s.prefs);
  const meta = usePevv((s) => s.meta);
  const busy = usePevv((s) => s.busy);
  const file = usePevv((s) => s.file);
  const [changing, setChanging] = useState(false);
  const [expPw, setExpPw] = useState('');
  const [impPw, setImpPw] = useState('');
  const [impText, setImpText] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [del, setDel] = useState('');
  const [gateNode, gate] = useReauthGate();
  const sel = (value: number, opts: [number, string][], on: (v: number) => void, testId: string) => (
    <select className={`${input} max-w-[12rem]`} value={value} onChange={(e) => on(+e.target.value)} data-testid={testId}>
      {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  );
  return (
    <div className="flex min-h-0 flex-col gap-3 overflow-y-auto p-3" data-testid="pevv-settings">
      {gateNode}
      <Section title={t('masterPassword')}>
        <p className="text-xs text-ink-muted">{file?.kdf.alg === 'argon2id' ? `Argon2id · ${Math.round(file.kdf.m / 1024)} MiB · t=${file.kdf.t}` : `PBKDF2-SHA256 · ${file?.kdf.alg === 'pbkdf2-sha256' ? file.kdf.iter.toLocaleString() : ''}`}</p>
        {!changing ? (
          <button type="button" className={btn} onClick={() => gate(() => setChanging(true))} data-testid="pevv-change-pw">{t('changePassword')}</button>
        ) : (
          <NewPasswordFields busy={busy} submitLabel={t('saveNewPassword')} testPrefix="pevv-chpw" onSubmit={(pw, strong) => void changeMasterPassword(pw, strong ? 'strong' : 'standard').then(() => { setChanging(false); setMsg(t('passwordChanged')); }, () => undefined)} />
        )}
      </Section>
      <Section title={t('qrMoveTitle')} testId="pevv-qr-move">
        <QrShareButton />
        <QrScanBox />
      </Section>
      <PasskeySection />
      <UsbKeySection />
      <PresenceSection />
      {inDesktopApp() && <BrowserLinkSection />}
      {inDesktopApp() && <TransferdSection />}
      {inDesktopApp() && <AutoTypeSection />}
      {inDesktopApp() && <CliAccessSection />}
      {inDesktopApp() && <PasskeyProviderSection />}
      {inDesktopApp() && <UpdateSection />}
      <TotpSection />
      <RecoverySection />
      <Section title={t('behavior')} testId="pevv-behavior">
        <label className={label}>{t('autoLock')}{sel(prefs.autoLockMin, [[1, '1 min'], [5, '5 min'], [15, '15 min'], [30, '30 min'], [60, '60 min'], [0, t('onlyOnHide')]], (v) => setPrefs({ autoLockMin: v }), 'pevv-autolock')}</label>
        <label className="flex items-center gap-2 text-xs text-ink-secondary"><input type="checkbox" checked={prefs.lockOnHide} onChange={(e) => setPrefs({ lockOnHide: e.target.checked })} data-testid="pevv-lockonhide" /> {t('lockOnHide')}</label>
        <label className={label}>{t('clipboardClear')}{sel(prefs.clipboardSec, [[10, '10 s'], [20, '20 s'], [30, '30 s'], [60, '60 s'], [0, t('never')]], (v) => setPrefs({ clipboardSec: v }), 'pevv-clipboard')}</label>
        <label className={label}>{t('revealWindow')}{sel(prefs.revealReauthSec, [[0, t('always')], [60, '1 min'], [120, '2 min'], [300, '5 min']], (v) => setPrefs({ revealReauthSec: v }), 'pevv-reveal-window')}</label>
        <label className="flex items-start gap-2 text-xs text-ink-secondary">
          <input type="checkbox" checked={prefs.sync} disabled={!syncEnabled()} onChange={(e) => setPrefs({ sync: e.target.checked })} data-testid="pevv-sync" className="mt-0.5" />
          <span>{t('syncVault')}<br /><span className="text-[0.62rem] text-ink-muted">{syncEnabled() ? t('syncHint') : t('syncOff')}</span></span>
        </label>
        {syncEnabled() && <SyncAccountBox />}
        {syncEnabled() && <SyncStatusPanel />}
      </Section>
      <ProjectEnvSection />
      <Section title={t('programAccess')} testId="pevv-grants">
        {Object.keys(meta?.grants ?? {}).length === 0 ? <p className="text-xs text-ink-muted">{t('noGrants')}</p> : (
          <ul className="flex flex-col gap-1">
            {Object.entries(meta!.grants).map(([pid, names]) => (
              <li key={pid} className="flex flex-wrap items-center gap-2 text-xs">
                <span className="font-mono text-cyan-100">{pid}</span>
                <span className="text-ink-muted">{names.join(', ')}</span>
                <button type="button" className={btnDanger} onClick={() => void revokeGrant(pid)}>{t('revoke')}</button>
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title={t('dataTitle')} testId="pevv-data">
        <p className="text-xs text-ink-secondary">{t('exportIntro')}</p>
        <p className="text-xs text-ink-muted">{t('exportFactors')}</p>
        <div className="flex flex-wrap gap-2">
          <input type="password" className={`${input} max-w-xs`} value={expPw} onChange={(e) => setExpPw(e.target.value)} placeholder={t('exportPassword')} aria-label={t('exportPassword')} data-testid="pevv-export-pass" />
          <button type="button" className={btn} disabled={busy || expPw.length < 10} data-testid="pevv-export" onClick={() => gate(() => void exportVault(expPw).then((txt) => { download(`pevv-export-${new Date().toISOString().slice(0, 10)}.json`, txt); setExpPw(''); setMsg(t('exported')); }, () => undefined), t('reauthExport'))}>{t('exportEncrypted')}</button>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input type="file" accept=".json,application/json" className="text-xs" data-testid="pevv-import-file" onChange={async (e) => { const f = e.target.files?.[0]; if (f) setImpText(await readFileText(f)); }} />
          <input type="password" className={`${input} max-w-xs`} value={impPw} onChange={(e) => setImpPw(e.target.value)} placeholder={t('exportPassword')} aria-label={t('importPassword')} data-testid="pevv-import-pass" />
          <button type="button" className={btn} disabled={busy || !impText || !impPw} data-testid="pevv-import" onClick={() => void importVault(impText!, impPw).then((n) => { setMsg(peekExport(impText!) === 2 ? t('restoredVault') : t('importedN', { n })); setImpPw(''); setImpText(null); }, () => undefined)}>{t('importEncrypted')}</button>
        </div>
        <div className="flex flex-col gap-1 border-t border-space-border/60 pt-2" data-testid="pevv-csv">
          <p className="text-xs text-cyan-50">{t('importCsv')}</p>
          <p className="text-[0.62rem] text-ink-muted">{t('importCsvHint')}</p>
          <input type="file" accept=".csv,.json,text/csv,application/json" className="text-xs" data-testid="pevv-import-csv" disabled={busy} onChange={async (e) => {
            const f = e.target.files?.[0];
            e.target.value = '';
            if (!f) return;
            try { const r = await importCsvText(await readFileText(f)); setMsg(t('importedCsv', { n: r.added, src: r.source, skip: r.skipped })); } catch { /* shown */ }
          }} />
        </div>
        <div className="flex flex-col gap-1 border-t border-space-border/60 pt-2">
          <p className="text-xs text-red-200">{t('deleteVaultHint')}</p>
          <div className="flex flex-wrap gap-2">
            <input className={`${input} max-w-[10rem]`} value={del} onChange={(e) => setDel(e.target.value)} placeholder="DELETE" aria-label={t('typeDelete')} data-testid="pevv-delete-vault-confirm" />
            <button type="button" className={btnDanger} disabled={del !== 'DELETE'} data-testid="pevv-delete-vault" onClick={() => gate(() => destroyVault())}>{t('deleteVault')}</button>
          </div>
        </div>
      </Section>
      {msg && <p className="text-xs text-accent-green" role="status">{msg}</p>}
      <ErrorLine />
      <button type="button" className={btn} onClick={() => lock('manual')}>🔒 {t('lockNow')}</button>
    </div>
  );
}

function ProjectEnvSection() {
  const { t } = usePT();
  const meta = usePevv((s) => s.meta);
  const ids = useMemo(() => {
    const set = new Set<string>();
    for (const k of Object.keys(meta?.projectEnv ?? {})) set.add(k);
    for (const k of Object.keys(meta?.grants ?? {})) if (k.startsWith('project:')) set.add(k);
    return [...set].sort();
  }, [meta]);
  const envs = meta?.environments ?? [];
  return (
    <Section title={t('projectEnvs')} testId="pevv-project-envs">
      <p className="text-xs text-ink-secondary">{t('projectEnvHint')}</p>
      {ids.length === 0 ? <p className="text-xs text-ink-muted">—</p> : (
        <ul className="flex flex-col gap-1">
          {ids.map((pid) => (
            <li key={pid} className="flex flex-wrap items-center gap-2 text-xs">
              <span className="min-w-0 flex-1 truncate font-mono text-cyan-100">{pid.replace(/^project:/, '')}</span>
              <select className={`${input} max-w-[10rem]`} value={meta?.projectEnv?.[pid] ?? ''} onChange={(e) => void linkProgramEnv(pid, e.target.value || null).catch(() => undefined)} data-testid={`pevv-project-env-${pid.replace(/^project:/, '')}`} aria-label={`${t('environment')}: ${pid}`}>
                <option value="">{t('useActiveEnv')} ({meta?.activeEnv})</option>
                {envs.map((e) => <option key={e} value={e}>{e}</option>)}
              </select>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

export function ActivityView({ onOpen }: { onOpen: (id: string) => void }) {
  const { t, locale } = usePT();
  const log = usePevv((s) => s.audit);
  const entries = usePevv((s) => s.entries);
  const [q, setQ] = useState('');
  const title = (id: string) => entries.find((e) => e.id === id)?.title ?? '(deleted)';
  const fmt = new Intl.DateTimeFormat(locale === 'es' ? 'es' : 'en-US', { dateStyle: 'short', timeStyle: 'medium' });
  const shown = log.filter((r) => !q || `${r.ev} ${r.detail ?? ''} ${r.item ? title(r.item) : ''}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="flex min-h-0 flex-col gap-2 overflow-y-auto p-3" data-testid="pevv-activity">
      <p className="text-xs text-ink-secondary">{t('activityIntro')}</p>
      <div className="flex flex-wrap gap-2">
        <input type="search" className={`${input} max-w-xs`} value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('search')} aria-label={t('search')} data-testid="pevv-activity-search" />
        <button type="button" className={btn} disabled={!log.length} onClick={() => download(`pevv-activity-${new Date().toISOString().slice(0, 10)}.csv`, auditCsv(log, title), 'text/csv')} data-testid="pevv-activity-export">{t('exportActivity')}</button>
        <button type="button" className={btnDanger} disabled={!log.length} onClick={() => clearAudit()} data-testid="pevv-activity-clear">{t('clearActivity')}</button>
      </div>
      {shown.length === 0 ? <p className="text-xs text-ink-muted">{t('noActivity')}</p> : (
        <ol className="flex flex-col gap-0.5" data-testid="pevv-activity-list">
          {shown.map((r, i) => (
            <li key={`${r.at}-${i}`} className="flex flex-wrap items-baseline gap-2 rounded px-1.5 py-1 text-xs odd:bg-space-surface/40" data-ev={r.ev}>
              <span className="tabular-nums text-[0.65rem] text-ink-muted">{fmt.format(r.at)}</span>
              <span className="font-mono text-accent-cyan">{r.ev}</span>
              {r.item && <button type="button" className="text-left text-cyan-50 underline" onClick={() => onOpen(r.item!)}>{title(r.item)}</button>}
              {r.detail && <span className="text-ink-secondary">{r.detail}</span>}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
