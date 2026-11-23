/**
 * Settings section: the direct device link (Transferd). Off by default, no relay unless the person adds one.
 * The shell does the networking; this only shows its status and asks it to pair, approve and remove peers.
 * Removing a peer also runs the existing vault-key rotation (docs/SYNC.md).
 */
import { useCallback, useEffect, useState } from 'react';
import { usePT } from '../i18n';
import { rotateKey, usePevv } from '../store';
import { CopyButton, QrCode, Section, btn, btnDanger, btnPrimary, input, label } from '../ui/common';
import { chooseLane, refreshStatus, revokePeer, setEnabled, transferdDevice, transferdIpc, useTransferd, type TransferdStatus } from './transferd';

interface Rotated { codes: string[]; recoveryKey: string | null; dropped: string[] }

const short = (id: string): string => `${id.slice(0, 8)}…${id.slice(-4)}`;
const lines = (s: string): string[] => s.split('\n').map((x) => x.trim()).filter(Boolean);

export function TransferdSection() {
  const { t, locale } = usePT();
  const ipc = transferdIpc();
  const status = useTransferd((s) => s.status);
  const cloudOn = usePevv((s) => s.prefs.sync);
  const [err, setErr] = useState<string | null>(null);
  const [relays, setRelays] = useState('');
  const [direct, setDirect] = useState('');
  const [joinText, setJoinText] = useState('');
  const [joined, setJoined] = useState<{ nodeId: string; sas: string[] } | null>(null);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [pw, setPw] = useState('');
  const [rotated, setRotated] = useState<Rotated | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (ipc) void refreshStatus(ipc); }, [ipc]);
  useEffect(() => { if (status) { setRelays(status.relays.join('\n')); setDirect(status.direct.join('\n')); } }, [status?.relays.join('|'), status?.direct.join('|')]); // eslint-disable-line react-hooks/exhaustive-deps

  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    try { const r = await fn(); setErr(null); return r; } catch (e) { setErr(typeof e === 'string' ? e : (e as Error).message); return undefined; } finally { setBusy(false); }
  }, []);
  if (!ipc) return null;
  const call = (cmd: string, args?: Record<string, unknown>) => run(async () => { useTransferd.setState({ status: await ipc.invoke<TransferdStatus>(cmd, args) }); });
  const errText = (e: string): string => (e === 'not-in-this-build' ? t('tfdUnavailable') : e);
  const fmt = new Intl.DateTimeFormat(locale === 'es' ? 'es' : 'en-US', { dateStyle: 'medium', timeStyle: 'short' });
  const lane = chooseLane(status, cloudOn);

  return (
    <Section title={t('tfdTitle')} testId="pevv-transferd">
      <p className="text-xs text-ink-muted">{t('tfdIntro')}</p>
      {status && !status.available && <p className="text-xs text-accent-gold" data-testid="pevv-transferd-unavailable">{t('tfdUnavailable')}</p>}
      {status?.available && (
        <>
          <label className="flex items-center gap-2 text-xs text-ink-secondary">
            <input type="checkbox" checked={status.enabled} disabled={busy} onChange={(e) => void run(() => setEnabled(ipc, e.target.checked, transferdDevice()))} data-testid="pevv-transferd-toggle" />
            {t('tfdEnable')}
          </label>
          {status.enabled && !status.running && !status.lastError && <p className="text-xs text-ink-muted">{t('tfdStarting')}</p>}
          {status.running && status.nodeId && (
            <div className="flex flex-col gap-1 text-xs text-ink-secondary" data-testid="pevv-transferd-identity">
              <p>{t('tfdNode')}: <code className="break-all font-mono text-cyan-50">{short(status.nodeId)}</code> <CopyButton value={status.nodeId} /></p>
              {status.fingerprint.length > 0 && <p>{t('tfdWords')}: <b className="text-cyan-50">{status.fingerprint.join(' ')}</b></p>}
              <p className="text-ink-muted">{status.seedProtection === 'os-keystore' ? t('tfdSeedOs') : t('tfdSeedFile')}</p>
              <p data-testid="pevv-transferd-lane">{t(lane === 'transferd' ? 'tfdLaneDirect' : lane === 'cloud' ? 'tfdLaneCloud' : 'tfdLaneNone')}{status.lastSync ? ` ${t('tfdLastSync', { when: fmt.format(status.lastSync) })}` : ''}</p>
            </div>
          )}
          {status.lastError && <p className="text-xs text-amber-300" role="alert" data-testid="pevv-transferd-error">{errText(status.lastError)}</p>}

          <div className="flex flex-col gap-2">
            <label className={label}>{t('tfdRelays')}
              <textarea className={`${input} min-h-16 font-mono`} value={relays} onChange={(e) => setRelays(e.target.value)} spellCheck={false} data-testid="pevv-transferd-relays" />
            </label>
            <p className="text-[0.62rem] text-ink-muted">{t('tfdRelaysHint')}</p>
            <label className={label}>{t('tfdDirect')}
              <textarea className={`${input} min-h-12 font-mono`} value={direct} onChange={(e) => setDirect(e.target.value)} spellCheck={false} data-testid="pevv-transferd-direct" />
            </label>
            <div><button type="button" className={btn} disabled={busy} onClick={() => void call('transport_set_addresses', { relays: lines(relays), direct: lines(direct) })} data-testid="pevv-transferd-save">{t('tfdSave')}</button></div>
          </div>

          {status.running && (
            <>
              <div className="flex flex-col gap-2" data-testid="pevv-transferd-invite">
                {status.invite ? (
                  <>
                    <p className="text-xs text-ink-secondary">{t('tfdInviteHint')}</p>
                    <QrCode text={status.invite.text} size={200} testId="pevv-transferd-qr" />
                    <code className="max-h-20 overflow-y-auto break-all rounded bg-space-deep px-2 py-1 font-mono text-[0.62rem] text-cyan-100" data-testid="pevv-transferd-invite-text">{status.invite.text}</code>
                    <p className="text-[0.62rem] text-ink-muted">{t('tfdInviteExpires', { when: fmt.format(status.invite.expiresAt) })}</p>
                    <div className="flex gap-2"><CopyButton value={status.invite.text} /><button type="button" className={btn} onClick={() => void call('transport_invite_cancel')}>{t('tfdCancelInvite')}</button></div>
                  </>
                ) : (
                  <div><button type="button" className={btnPrimary} disabled={busy} onClick={() => void run(async () => { await ipc.invoke('transport_invite_create', {}); await refreshStatus(ipc); })} data-testid="pevv-transferd-add">{t('tfdAdd')}</button></div>
                )}
              </div>

              {status.pending.map((p) => (
                <div key={p.nodeId} className="flex flex-col gap-2 rounded-md border border-accent-cyan/50 bg-space-surface/40 p-2 text-xs" data-testid="pevv-transferd-pending">
                  <p className="text-cyan-50">{t('tfdPending', { name: p.name || short(p.nodeId) })}</p>
                  <p className="text-ink-secondary">{t('tfdCompare')}</p>
                  <code className="rounded bg-space-deep px-3 py-2 text-center font-mono text-sm tracking-wide text-cyan-100" data-testid="pevv-transferd-sas">{p.sas.join(' ')}</code>
                  <div className="flex gap-2">
                    <button type="button" className={btnPrimary} disabled={busy} onClick={() => void call('transport_pair_confirm', { nodeId: p.nodeId, approved: true })} data-testid="pevv-transferd-approve">{t('tfdApprove')}</button>
                    <button type="button" className={btnDanger} disabled={busy} onClick={() => void call('transport_pair_confirm', { nodeId: p.nodeId, approved: false })} data-testid="pevv-transferd-decline">{t('tfdDecline')}</button>
                  </div>
                </div>
              ))}

              <div className="flex flex-col gap-2" data-testid="pevv-transferd-join">
                <label className={label}>{t('tfdJoinTitle')}
                  <input className={`${input} font-mono`} value={joinText} onChange={(e) => setJoinText(e.target.value)} placeholder="tdov2:…" spellCheck={false} autoComplete="off" data-testid="pevv-transferd-join-input" />
                </label>
                <div><button type="button" className={btn} disabled={busy || !joinText.trim()} onClick={() => void run(async () => { const d = transferdDevice(); setJoined(await ipc.invoke('transport_join', { invite: joinText.trim(), name: d?.name ?? null })); setJoinText(''); await refreshStatus(ipc); })} data-testid="pevv-transferd-join-go">{t('tfdJoin')}</button></div>
                {joined && (
                  <div className="flex flex-col gap-1 text-xs text-ink-secondary" data-testid="pevv-transferd-joined">
                    <p>{t('tfdJoined')}</p>
                    <code className="rounded bg-space-deep px-3 py-2 text-center font-mono text-sm tracking-wide text-cyan-100" data-testid="pevv-transferd-join-sas">{joined.sas.join(' ')}</code>
                  </div>
                )}
              </div>
            </>
          )}

          <div className="flex flex-col gap-2" data-testid="pevv-transferd-peers">
            <h3 className="text-xs font-semibold text-cyan-50">{t('tfdPeers')}</h3>
            {status.peers.length === 0 && <p className="text-xs text-ink-muted">{t('tfdNoPeers')}</p>}
            <ul className="flex flex-col gap-2">
              {status.peers.map((p) => (
                <li key={p.nodeId} className="flex flex-col gap-1 rounded-md border border-space-border/70 bg-space-surface/40 p-2 text-xs" data-testid={`pevv-transferd-peer-${p.nodeId.slice(0, 8)}`}>
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="font-medium text-cyan-50">{p.name || short(p.nodeId)}</span>
                    <code className="font-mono text-ink-muted">{short(p.nodeId)}</code>
                    <span className="text-ink-secondary">{p.state === 'revoked' ? t('tfdRevoked') : p.reachable === true ? t('tfdReachable') : p.reachable === false ? t('tfdUnreachable') : t('tfdUntried')}</span>
                  </div>
                  {p.state === 'approved' && (confirm === p.nodeId ? (
                    <div className="flex flex-col gap-2">
                      <p className="text-ink-muted">{t('tfdRevokeNote')}</p>
                      <input type="password" className={`${input} max-w-xs`} value={pw} onChange={(e) => setPw(e.target.value)} placeholder={t('rotatePassword')} aria-label={t('rotatePassword')} autoComplete="current-password" data-testid="pevv-transferd-rotate-password" />
                      <div className="flex flex-wrap gap-2">
                        <button type="button" className={btnDanger} disabled={busy || !pw} data-testid="pevv-transferd-revoke-confirm"
                          onClick={() => void run(async () => {
                            const r = await revokePeer(ipc, p.nodeId, () => rotateKey(pw));
                            if (r) setRotated({ codes: r.codes, recoveryKey: r.recoveryKey, dropped: r.dropped.map((d) => d.name ?? d.type) });
                            setConfirm(null); setPw('');
                          })}>{t('tfdRevokeConfirm')}</button>
                        <button type="button" className={btn} onClick={() => { setConfirm(null); setPw(''); }}>{t('cancel')}</button>
                      </div>
                    </div>
                  ) : (
                    <div><button type="button" className={btnDanger} onClick={() => setConfirm(p.nodeId)} data-testid={`pevv-transferd-revoke-${p.nodeId.slice(0, 8)}`}>{t('tfdRevoke')}</button></div>
                  ))}
                </li>
              ))}
            </ul>
          </div>
          {rotated && (
            <div className="flex flex-col gap-2 rounded-md border border-accent-gold/40 bg-accent-gold/5 p-2 text-xs" data-testid="pevv-transferd-rotated">
              <p className="text-ink-secondary">{t('rotateDone')}</p>
              {rotated.codes.length > 0 && <pre className="select-all rounded-md bg-space-surface/60 p-2">{rotated.codes.join('\n')}</pre>}
              {rotated.recoveryKey && <><p className="text-ink-secondary">{t('rotateNewKey')}</p><pre className="select-all rounded-md bg-space-surface/60 p-2">{rotated.recoveryKey}</pre></>}
              {rotated.dropped.length > 0 && <p className="text-amber-300">{t('rotateDropped', { list: rotated.dropped.join(', ') })}</p>}
              <div><button type="button" className={btn} onClick={() => setRotated(null)}>{t('iSavedThem')}</button></div>
            </div>
          )}
        </>
      )}
      {err && <p className="text-xs text-red-300" role="alert">{errText(err)}</p>}
    </Section>
  );
}
