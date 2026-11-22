/** Sign in to the optional sync backend (email link). Shown only when the build has sync configured. */
import { useEffect, useState } from 'react';
import { usePT } from '../i18n';
import { currentAccount, onSyncAccount, sendMagicLink, signOut, startSync, syncEnabled, type SyncAccount } from '../host/cloud';
import { btn, input } from './common';

export function SyncAccountBox() {
  const { t } = usePT();
  const [account, setAccount] = useState<SyncAccount | null>(currentAccount());
  const [email, setEmail] = useState('');
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { startSync(); return onSyncAccount(setAccount); }, []);
  if (!syncEnabled()) return null;
  if (account) {
    return (
      <div className="flex flex-wrap items-center gap-2 text-xs text-ink-secondary" data-testid="pevv-sync-account">
        <span className="min-w-0 flex-1 truncate">{t('syncSignedInAs')} {account.email ?? t('syncAnonymous')}</span>
        <button type="button" className={btn} onClick={() => void signOut()} data-testid="pevv-sync-signout">{t('syncSignOut')}</button>
      </div>
    );
  }
  return (
    <form
      className="flex flex-col gap-2 text-xs text-ink-secondary"
      data-testid="pevv-sync-signin"
      onSubmit={(e) => {
        e.preventDefault();
        setBusy(true);
        setNote(null);
        sendMagicLink(email).then(() => setNote(t('syncLinkSent')), (err: Error) => setNote(err.message)).finally(() => setBusy(false));
      }}
    >
      <label className="flex flex-col gap-1">{t('syncEmail')}<input type="email" required className={input} value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" data-testid="pevv-sync-email" /></label>
      <button type="submit" className={btn} disabled={busy || !email.includes('@')} data-testid="pevv-sync-send">{t('syncSendLink')}</button>
      {note && <p className="text-accent-gold">{note}</p>}
    </form>
  );
}
