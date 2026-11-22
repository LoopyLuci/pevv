/** PEVV first-run setup, unlock, second factor and recovery screens. */
import { useEffect, useRef, useState } from 'react';
import { usePT } from '../i18n';
import { strength } from '../gen';
import type { RecoveryKit } from '../recovery';
import {
  claimSyncedVault, createVault, finishRecovery, installFromExport, pendingQrToken, prfPasskeys, unlockPassword, unlockPasskey, unlockRecoveryCode, unlockRecoveryKit,
  unlockUsbKey, usePevv, verifySecondPasskey, verifySecondTotp, verifySecondUsbKey,
} from '../store';
import { peekExport } from '../vault';
import { currentAccount, onSyncAccount, syncEnabled, useCloudFiles } from '../host/cloud';
import { SyncAccountBox } from './SyncAccount';
import { inDesktopApp, passkeysBlocked, webauthnAvailable } from '../webauthn';
import { UsbKeyReader } from './UsbViews';
import { ErrorLine, StrengthMeter, btn, btnPrimary, input, label, readFileText } from './common';
import { QrScanBox, QrShareButton } from './QrShare';
import { PevvBrand } from '../brand/PevvLogo';
import { unlockVaultBio, vaultBioEnrolled } from '../deviceBio';

function Shell({ title, children, testId }: { title: string; children: React.ReactNode; testId: string }) {
  return (
    <div className="mx-auto flex w-full max-w-lg flex-col gap-3 p-4" data-testid={testId}>
      <div className="flex items-center gap-2">
        <span aria-hidden className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/40 bg-space-deep text-xl"><PevvBrand size={30} /></span>
        <div>
          <h2 className="font-display text-lg text-cyan-50">{title}</h2>
          <p className="text-[0.65rem] uppercase tracking-wider text-ink-muted">Password &amp; Environment Variable Vault</p>
        </div>
      </div>
      {children}
    </div>
  );
}

export function NewPasswordFields({ onSubmit, submitLabel, busy, testPrefix }: { onSubmit: (pw: string, strong: boolean) => void; submitLabel: string; busy: boolean; testPrefix: string }) {
  const { t } = usePT();
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [strong, setStrong] = useState(false);
  const [show, setShow] = useState(false);
  const s = strength(pw);
  const tooWeak = pw.length < 10 || s.common || s.score < 2;
  const mismatch = pw2.length > 0 && pw !== pw2;
  return (
    <form className="flex flex-col gap-3" onSubmit={(e) => { e.preventDefault(); if (!tooWeak && pw === pw2) onSubmit(pw, strong); }}>
      <label className={label}>
        {t('masterPassword')}
        <input autoFocus type={show ? 'text' : 'password'} autoComplete="new-password" className={input} value={pw} onChange={(e) => setPw(e.target.value)} data-testid={`${testPrefix}-password`} />
      </label>
      <StrengthMeter value={pw} />
      <label className={label}>
        {t('confirmPassword')}
        <input type={show ? 'text' : 'password'} autoComplete="new-password" className={input} value={pw2} onChange={(e) => setPw2(e.target.value)} data-testid={`${testPrefix}-confirm`} />
      </label>
      {mismatch && <p className="text-xs text-red-300">{t('mismatch')}</p>}
      {pw && tooWeak && <p className="text-xs text-accent-gold">{t('needStronger')}</p>}
      <label className="flex items-center gap-2 text-xs text-ink-secondary"><input type="checkbox" checked={show} onChange={(e) => setShow(e.target.checked)} /> {t('showPassword')}</label>
      <label className="flex items-center gap-2 text-xs text-ink-secondary"><input type="checkbox" checked={strong} onChange={(e) => setStrong(e.target.checked)} /> {t('strongKdf')}</label>
      <button type="submit" className={btnPrimary} disabled={busy || tooWeak || pw !== pw2} data-testid={`${testPrefix}-submit`}>
        {busy ? t('deriving') : submitLabel}
      </button>
    </form>
  );
}

export function SetupView() {
  const { t } = usePT();
  const busy = usePevv((s) => s.busy);
  const [ack, setAck] = useState(false);
  const [mode, setMode] = useState<'new' | 'have'>(() => (pendingQrToken() || navigator.userAgent.includes('PevvAndroid') ? 'have' : 'new'));
  return (
    <Shell title={mode === 'new' ? t('setupTitle') : t('haveVault')} testId="pevv-setup">
      <div className="sticky top-0 z-10 flex gap-2 bg-space-deep py-1">
        <button type="button" className={mode === 'have' ? btnPrimary : btn} onClick={() => setMode('have')} data-testid="pevv-mode-have">{t('haveVault')}</button>
        <button type="button" className={mode === 'new' ? btnPrimary : btn} onClick={() => setMode('new')} data-testid="pevv-mode-new">{t('newVault')}</button>
      </div>
      {mode === 'new' ? (
        <>
          <p className="text-sm text-ink-secondary">{t('setupIntro')}</p>
          <ul className="list-disc space-y-1 pl-5 text-xs text-ink-secondary">
            <li>{t('setupPoint1')}</li>
            <li>{t('setupPoint2')}</li>
            <li>{t(inDesktopApp() ? 'setupPoint3Desktop' : 'setupPoint3')}</li>
          </ul>
          <label className="flex items-start gap-2 rounded-md border border-accent-gold/40 bg-accent-gold/5 p-2 text-xs text-accent-gold">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} data-testid="pevv-setup-ack" className="mt-0.5" />
            {t('setupAck')}
          </label>
          {ack && <NewPasswordFields busy={busy} submitLabel={t('createVault')} testPrefix="pevv-setup" onSubmit={(pw, strong) => void createVault(pw, strong ? 'strong' : 'standard').catch(() => undefined)} />}
        </>
      ) : (
        <HaveVault />
      )}
      <ErrorLine />
    </Shell>
  );
}

function HaveVault() {
  const { t } = usePT();
  const busy = usePevv((s) => s.busy);
  const files = useCloudFiles((s) => s.files);
  const found = files.some((f) => f.path === '/vault/pevv.vault.json');
  const [account, setAccount] = useState(currentAccount());
  const [note, setNote] = useState<string | null>(null);
  const [fileText, setFileText] = useState<string | null>(null);
  const [exportPw, setExportPw] = useState('');
  const [master, setMaster] = useState('');
  const [master2, setMaster2] = useState('');
  const ver = fileText ? peekExport(fileText) : 0;
  useEffect(() => onSyncAccount(setAccount), []);
  const check = () => {
    void claimSyncedVault({ retryRevoked: true }).then((ok) => setNote(ok ? null : (account && syncEnabled() ? t('fromAccountWaiting') : account ? t('fromAccountNone') : t('fromAccountSignedOut'))));
  };
  useEffect(() => { if (found) void claimSyncedVault(); }, [found]);
  const weak = master.length < 10 || master !== master2;
  // The vault QR, an encrypted file and live device exchange never need an account. The optional account route
  // exists only in builds that configured a sync backend (VITE_PEVV_SYNC_URL).
  const showAccount = syncEnabled();
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-ink-secondary">{t(inDesktopApp() ? 'haveIntroDesktop' : 'haveIntro')}</p>
      <QrScanBox />
      <div className="rounded-md border border-space-border p-3">
        <h3 className="text-sm font-medium text-cyan-50">{t('fromFile')}</h3>
        <p className="mt-1 text-xs text-ink-secondary">{t('fromFileBody')}</p>
        <input type="file" accept=".json,application/json" className="mt-2 text-xs" data-testid="pevv-setup-import-file" onChange={async (e) => {
          const f = e.target.files?.[0];
          if (f) setFileText(await readFileText(f));
        }} />
        <label className={label}>{t('exportPw')}<input type="password" autoComplete="off" className={input} value={exportPw} onChange={(e) => setExportPw(e.target.value)} data-testid="pevv-setup-export-pw" /></label>
        {ver === 2 && <p className="text-xs text-ink-secondary">{t('fromFileFull')}</p>}
        {ver === 1 && (
          <>
            <p className="text-xs text-accent-gold">{t('legacyExport')}</p>
            <label className={label}>{t('thisDevicePw')}<input type="password" autoComplete="new-password" className={input} value={master} onChange={(e) => setMaster(e.target.value)} data-testid="pevv-setup-master" /></label>
            <label className={label}>{t('confirmPassword')}<input type="password" autoComplete="new-password" className={input} value={master2} onChange={(e) => setMaster2(e.target.value)} data-testid="pevv-setup-master2" /></label>
          </>
        )}
        {ver === 0 && fileText && <p className="text-xs text-red-200">{t('qrDamaged')}</p>}
        <button type="button" className={btnPrimary} disabled={busy || !fileText || exportPw.length < 10 || ver === 0 || (ver === 1 && weak)} data-testid="pevv-setup-import" onClick={() => void installFromExport(fileText!, exportPw, ver === 1 ? master : undefined).catch(() => undefined)}>{busy ? t('deriving') : t('openExport')}</button>
      </div>
      {showAccount && (
        <div className="rounded-md border border-space-border p-3" data-testid="pevv-from-account">
          <h3 className="text-sm font-medium text-cyan-50">{t('fromAccount')}</h3>
          <p className="mt-1 text-xs text-ink-secondary">{t('fromAccountBody')}</p>
          {found && <p className="mt-2 text-xs text-accent-green">{t('fromAccountFound')}</p>}
          <div className="mt-2"><SyncAccountBox /></div>
          {note && <p className="mt-2 text-xs text-accent-gold">{note}</p>}
          <button type="button" className={`${btn} mt-2`} disabled={busy} onClick={check} data-testid="pevv-claim">{found ? t('useAccountVault') : t('checkAgain')}</button>
        </div>
      )}
    </div>
  );
}

type LockMode = 'password' | 'code' | 'kit' | 'usb';

export function LockedView() {
  const { t } = usePT();
  const busy = usePevv((s) => s.busy);
  const [mode, setMode] = useState<LockMode>('password');
  const [pw, setPw] = useState('');
  const [code, setCode] = useState('');
  const [kit, setKit] = useState<RecoveryKit | null>(null);
  const [kitPw, setKitPw] = useState('');
  const pwRef = useRef<HTMLInputElement>(null);
  const prf = prfPasskeys();
  const hasUsb = usePevv((s) => !!s.file?.slots.some((x) => x.type === 'usb-key'));
  const bio = vaultBioEnrolled();
  useEffect(() => { usePevv.setState({ error: null }); }, [mode]);
  useEffect(() => {
    const w = window as unknown as { __luciVaultUnlock?: (pw: string) => void };
    w.__luciVaultUnlock = (secret) => { void unlockPassword(secret).catch(() => undefined); };
    if (bio) unlockVaultBio();
  }, [bio]);
  return (
    <Shell title={t('lockedTitle')} testId="pevv-locked">
      {mode === 'password' && (
        <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); void unlockPassword(pw).then(() => setPw(''), () => pwRef.current?.select()); }}>
          <label className={label}>
            {t('masterPassword')}
            <input ref={pwRef} autoFocus type="password" autoComplete="current-password" className={input} value={pw} onChange={(e) => setPw(e.target.value)} data-testid="pevv-unlock-password" />
          </label>
          <button type="submit" className={btnPrimary} disabled={!pw || busy} data-testid="pevv-unlock-submit">{busy ? t('deriving') : t('unlock')}</button>
          {bio && (
            <button type="button" className={btn} disabled={busy} onClick={() => unlockVaultBio()} data-testid="pevv-unlock-bio">{t('unlockBio')}</button>
          )}
          {prf.length > 0 && webauthnAvailable() && (
            <button type="button" className={btn} disabled={busy} onClick={() => void unlockPasskey().catch(() => undefined)} data-testid="pevv-unlock-passkey">
              🔑 {t('unlockPasskey')}
            </button>
          )}
        </form>
      )}
      {mode === 'code' && (
        <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); void unlockRecoveryCode(code).catch(() => undefined); }}>
          <p className="text-xs text-ink-secondary">{t('recoveryCodeHint')}</p>
          <input autoFocus className={`${input} font-mono uppercase`} value={code} onChange={(e) => setCode(e.target.value)} placeholder="XXXXX-XXXXX-XXXXX-XXXXX" aria-label={t('recoveryCode')} data-testid="pevv-recovery-code" />
          <button type="submit" className={btnPrimary} disabled={busy || code.replace(/[^a-z2-7]/gi, '').length !== 20} data-testid="pevv-recovery-submit">{t('useRecoveryCode')}</button>
        </form>
      )}
      {mode === 'kit' && (
        <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); if (kit) void unlockRecoveryKit(kit, kitPw).catch(() => undefined); }}>
          <p className="text-xs text-ink-secondary">{t('kitHint')}</p>
          <input type="file" accept=".json,application/json" className="text-xs" data-testid="pevv-kit-file" onChange={async (e) => {
            const f = e.target.files?.[0];
            if (!f) return;
            try { setKit(JSON.parse(await readFileText(f)) as RecoveryKit); usePevv.setState({ error: null }); } catch (err) { usePevv.setState({ error: (err as Error).message }); }
          }} />
          <input type="password" className={input} value={kitPw} onChange={(e) => setKitPw(e.target.value)} placeholder={t('kitPassphrase')} aria-label={t('kitPassphrase')} data-testid="pevv-kit-pass" />
          <button type="submit" className={btnPrimary} disabled={busy || !kit || !kitPw}>{t('useRecoveryKit')}</button>
        </form>
      )}
      {mode === 'usb' && (
        <div className="flex flex-col gap-2">
          <p className="text-xs text-ink-secondary">{t('usbKeyInsertHint')}</p>
          <UsbKeyReader busy={busy} onText={(text) => void unlockUsbKey(text).catch(() => undefined)} />
        </div>
      )}
      <ErrorLine />
      <div className="flex flex-wrap gap-2 border-t border-space-border/60 pt-2 text-xs">
        {mode !== 'password' && <button type="button" className={btn} onClick={() => setMode('password')}>{t('backToPassword')}</button>}
        {mode !== 'code' && <button type="button" className={btn} onClick={() => setMode('code')} data-testid="pevv-mode-code">{t('useRecoveryCode')}</button>}
        {mode !== 'kit' && <button type="button" className={btn} onClick={() => setMode('kit')}>{t('useRecoveryKit')}</button>}
        {hasUsb && mode !== 'usb' && <button type="button" className={btn} onClick={() => setMode('usb')} data-testid="pevv-mode-usb">💾 {t('unlockUsbKey')}</button>}
      </div>
      <p className="text-[0.65rem] text-ink-muted">{t('noBackdoor')}</p>
      <QrShareButton />
    </Shell>
  );
}

export function SecondFactorView() {
  const { t } = usePT();
  const pending = usePevv((s) => s.pending);
  const busy = usePevv((s) => s.busy);
  const [code, setCode] = useState('');
  return (
    <Shell title={t('secondFactor')} testId="pevv-2fa">
      <p className="text-xs text-ink-secondary">{t('secondFactorHint')}</p>
      {pending.totp && (
        <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); void verifySecondTotp(code).then(() => setCode(''), () => setCode('')); }}>
          <label className={label}>
            {t('authenticatorCode')}
            <input autoFocus inputMode="numeric" autoComplete="one-time-code" maxLength={8} className={`${input} font-mono tracking-[0.3em]`} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} data-testid="pevv-totp-code" />
          </label>
          <button type="submit" className={btnPrimary} disabled={busy || code.length < 6} data-testid="pevv-totp-submit">{t('verify')}</button>
        </form>
      )}
      {!pending.totp && pending.passkey && <p className="text-xs text-accent-green">✓ {t('totpOk')}</p>}
      {pending.usbKey && (
        <div className="flex flex-col gap-2" data-testid="pevv-2fa-usbkey">
          <p className="text-xs text-ink-secondary">{t('usbKeyInsert')}: {t('usbKeyInsertHint')}</p>
          <UsbKeyReader busy={busy} onText={(text) => void verifySecondUsbKey(text).catch(() => undefined)} />
        </div>
      )}
      {pending.passkey && passkeysBlocked() && <p className="text-xs text-accent-gold" data-testid="pevv-2fa-passkey-ext">{t(inDesktopApp() ? 'passkeyDesktop' : 'passkeyExtension')}</p>}
      {pending.passkey && !passkeysBlocked() && (
        <button type="button" className={btnPrimary} disabled={busy} onClick={() => void verifySecondPasskey().catch(() => undefined)} data-testid="pevv-2fa-passkey">
          🔑 {t('touchKey')}
        </button>
      )}
      <ErrorLine />
      <p className="text-[0.65rem] text-ink-muted">{t('gateHonesty')}</p>
    </Shell>
  );
}

export function SetPasswordView() {
  const { t } = usePT();
  const busy = usePevv((s) => s.busy);
  return (
    <Shell title={t('recoveredTitle')} testId="pevv-set-password">
      <p className="text-xs text-ink-secondary">{t('recoveredHint')}</p>
      <NewPasswordFields busy={busy} submitLabel={t('saveNewPassword')} testPrefix="pevv-newpw" onSubmit={(pw) => void finishRecovery(pw).catch(() => undefined)} />
      <ErrorLine />
    </Shell>
  );
}
