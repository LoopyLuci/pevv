/** Small shared PEVV UI pieces. */
import { useEffect, useRef, useState, type ReactNode } from 'react';
import qrcode from 'qrcode-generator';
import { QR_LEVEL, QR_MARGIN } from '../qr';
import { strength as measure } from '../gen';
import { usePT, type PKey } from '../i18n';
import { copySecret, needsReauth, reauthPasskey, reauthPassword, usePevv } from '../store';

export const btn = 'inline-flex min-h-9 items-center justify-center gap-1 rounded-md border border-cyan-500/30 bg-space-surface/60 px-3 text-xs text-cyan-50 hover:bg-accent-cyan/15 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-cyan disabled:opacity-40';
export const btnPrimary = 'inline-flex min-h-9 items-center justify-center gap-1 rounded-md border border-accent-cyan/60 bg-accent-cyan/20 px-3 text-xs font-semibold text-accent-cyan hover:bg-accent-cyan/30 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-cyan disabled:opacity-40';
export const btnDanger = 'inline-flex min-h-9 items-center justify-center gap-1 rounded-md border border-accent-red/50 bg-accent-red/10 px-3 text-xs text-red-200 hover:bg-accent-red/25 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-red disabled:opacity-40';
export const input = 'min-h-9 w-full rounded-md border border-space-border bg-space-deep/80 px-2 text-sm text-ink-primary placeholder:text-ink-muted focus:border-accent-cyan focus:outline-none';
export const label = 'flex flex-col gap-1 text-xs text-ink-secondary';

export function download(name: string, text: string, type = 'application/json'): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function readFileText(file: File): Promise<string> {
  if (file.size > 2_000_000) return Promise.reject(new Error('file is larger than 2 MB'));
  return file.text();
}

export function Section({ title, children, testId }: { title: string; children: ReactNode; testId?: string }) {
  return (
    <section className="flex flex-col gap-2 rounded-lg border border-space-border/70 bg-space-deep/50 p-3" data-testid={testId}>
      <h3 className="font-mono text-[0.68rem] uppercase tracking-wider text-cyan-200/80">{title}</h3>
      {children}
    </section>
  );
}

const QR_ERROR: Partial<Record<string, PKey>> = {
  'qr-expired': 'qrExpired',
  'qr-damaged': 'qrDamaged',
  'qr-different': 'qrDifferent',
  'qr-too-big': 'qrTooBig',
  'qr-incomplete': 'qrIncomplete',
  'qr-signed-out': 'qrWaitSignedOut',
  'qr-nosync': 'qrWaitNoSync',
  'device-revoked': 'deviceRevoked',
  'device-self': 'deviceSelf',
  'device-name': 'deviceNameInvalid',
  'export-older': 'exportOlder',
  'export-needs-master': 'exportNeedsMaster',
};

export function ErrorLine() {
  const error = usePevv((s) => s.error);
  const { t } = usePT();
  if (!error) return null;
  const key = QR_ERROR[error];
  return <p role="alert" className="rounded border border-accent-red/40 bg-accent-red/10 px-2 py-1 text-xs text-red-200" data-testid="pevv-error">{key ? t(key) : error}</p>;
}

export function StrengthMeter({ value, testId = 'pevv-strength' }: { value: string; testId?: string }) {
  const { t } = usePT();
  const s = measure(value);
  if (!value) return null;
  const labels: PKey[] = ['sVeryWeak', 'sWeak', 'sFair', 'sGood', 'sStrong'];
  const colors = ['bg-accent-red', 'bg-orange-400', 'bg-accent-gold', 'bg-lime-400', 'bg-accent-green'];
  return (
    <div className="flex flex-col gap-1" data-testid={testId} data-score={s.score}>
      <div className="flex gap-1" aria-hidden>
        {[0, 1, 2, 3, 4].map((i) => <span key={i} className={`h-1.5 flex-1 rounded ${i <= s.score ? colors[s.score] : 'bg-space-border'}`} />)}
      </div>
      <p className="text-[0.65rem] text-ink-muted">
        {t(labels[s.score]!)} · ~{s.bits} {t('bits')}
        {s.common && <> · <span className="text-red-300">{t('wCommon')}</span></>}
        {!s.common && s.warnings.includes('sequence') && <> · {t('wSequence')}</>}
        {!s.common && s.warnings.includes('repeats') && <> · {t('wRepeats')}</>}
        {s.warnings.includes('short') && <> · {t('wShort')}</>}
      </p>
    </div>
  );
}

export function CopyButton({ value, testId, labelKey = 'copy', itemId }: { value: string; testId?: string; labelKey?: PKey; itemId?: string }) {
  const { t } = usePT();
  const [done, setDone] = useState(false);
  const secs = usePevv((s) => s.prefs.clipboardSec);
  return (
    <button
      type="button"
      className={btn}
      data-testid={testId}
      onClick={async () => {
        const ok = await copySecret(value, itemId);
        setDone(ok);
        if (ok) setTimeout(() => setDone(false), 1500);
      }}
      title={secs > 0 ? t('copyClears', { n: secs }) : t(labelKey)}
    >
      {done ? t('copied') : t(labelKey)}
    </button>
  );
}

/** Inline re-authentication (password or passkey) gating reveal / export. */
export function Reauth({ onDone, reason }: { onDone: () => void; reason: string }) {
  const { t } = usePT();
  const [pw, setPw] = useState('');
  const busy = usePevv((s) => s.busy);
  const hasPasskey = usePevv((s) => (s.file?.passkeys.length ?? 0) > 0);
  return (
    <form
      className="flex flex-col gap-2 rounded-md border border-accent-gold/40 bg-accent-gold/5 p-2"
      data-testid="pevv-reauth"
      onSubmit={async (e) => {
        e.preventDefault();
        try { await reauthPassword(pw); setPw(''); onDone(); } catch { /* error shown */ }
      }}
    >
      <p className="text-xs text-ink-secondary">{reason}</p>
      <div className="flex flex-wrap gap-2">
        <input type="password" autoComplete="current-password" className={`${input} max-w-xs flex-1`} value={pw} onChange={(e) => setPw(e.target.value)} aria-label={t('masterPassword')} placeholder={t('masterPassword')} data-testid="pevv-reauth-password" />
        <button type="submit" className={btnPrimary} disabled={!pw || busy} data-testid="pevv-reauth-submit">{t('confirm')}</button>
        {hasPasskey && <button type="button" className={btn} disabled={busy} onClick={async () => { try { await reauthPasskey(); onDone(); } catch { /* shown */ } }}>{t('usePasskey')}</button>}
      </div>
      <ErrorLine />
    </form>
  );
}

/** Run `fn` now if recently authenticated, otherwise show <Reauth> first. */
export function useReauthGate(): [ReactNode, (fn: () => void, reason?: string) => void] {
  const [pending, setPending] = useState<{ fn: () => void; reason: string } | null>(null);
  const { t } = usePT();
  const gate = (fn: () => void, reason?: string) => {
    if (!needsReauth()) { fn(); return; }
    setPending({ fn, reason: reason ?? t('reauthReason') });
  };
  const node = pending ? <Reauth reason={pending.reason} onDone={() => { const f = pending.fn; setPending(null); f(); }} /> : null;
  return [node, gate];
}

/** Always black on pure white (also in dark mode), a quiet zone of QR_MARGIN modules, lowest version the text allows, shrinks to fit a narrow screen. */
export function QrCode({ text, size = 280, testId, level = QR_LEVEL }: { text: string; size?: number; testId?: string; level?: 'L' | 'M' | 'Q' | 'H' }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || !text) return;
    const qr = qrcode(0, level);
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    const margin = QR_MARGIN;
    const scale = Math.max(3, Math.floor(size / (n + margin * 2)));
    const total = (n + margin * 2) * scale;
    canvas.width = total;
    canvas.height = total;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, total, total);
    ctx.fillStyle = '#000000';
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) {
      if (qr.isDark(r, c)) ctx.fillRect((c + margin) * scale, (r + margin) * scale, scale, scale);
    }
  }, [text, size, level]);
  if (!text) return null;
  return (
    <canvas
      ref={ref}
      role="img"
      aria-label="QR code"
      data-testid={testId}
      style={{ width: size, maxWidth: '100%', height: 'auto', aspectRatio: '1 / 1', background: '#fff', padding: 0, borderRadius: 8, imageRendering: 'pixelated' }}
    />
  );
}

/** Seconds left in the current TOTP period (re-renders every second). */
export function useTotpTick(period = 30): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);
  return period - (Math.floor(now / 1000) % period);
}
