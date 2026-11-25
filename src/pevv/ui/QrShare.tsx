/** Show a vault QR after the master password checks out, and scan one on a new device. */
import { useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';
import { syncEnabled } from '../host/cloud';
import { usePT } from '../i18n';
import { FrameAssembler, packVault, parseScan, unpackFrames, QR_HOLD_MS } from '../qr';
import {
  clearHandoff, confirmPasswordForQr, consumePendingQr, dismissQrWait, installVaultCopy, openVault, publishHandoff, rememberQrToken, usePevv,
} from '../store';
import { ErrorLine, QrCode, btn, btnPrimary, input, label } from './common';

type Detector = { detect: (src: CanvasImageSource) => Promise<{ rawValue?: string }[]> };

function barcodeDetector(): Detector | null {
  const Ctor = (globalThis as { BarcodeDetector?: new (o: { formats: string[] }) => Detector }).BarcodeDetector;
  if (!Ctor) return null;
  try { return new Ctor({ formats: ['qr_code'] }); } catch { return null; }
}

async function openCamera(): Promise<MediaStream> {
  const md = navigator.mediaDevices;
  if (!md?.getUserMedia) throw new Error('no-camera');
  try {
    return await md.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
  } catch {
    return await md.getUserMedia({ video: true, audio: false });
  }
}

export function QrMove() {
  return (
    <div className="flex min-h-0 flex-col gap-3 overflow-y-auto p-3" data-testid="pevv-qr-page">
      <QrShareButton />
      <QrScanBox />
    </div>
  );
}

export function QrShareButton() {
  const { t } = usePT();
  const [open, setOpen] = useState(false);
  return (
    <div className="flex flex-col gap-2 rounded-md border border-cyan-500/30 bg-cyan-500/5 p-3" data-testid="pevv-qr-share-box">
      <h3 className="text-sm font-medium text-cyan-50">{t('importWithQr')}</h3>
      <p className="text-xs text-ink-secondary">{t('qrShareHint')}</p>
      {open ? <QrSharePanel onClose={() => setOpen(false)} /> : (
        <button type="button" className={`${btnPrimary} min-h-11`} data-testid="pevv-qr-share" onClick={() => setOpen(true)}>{t('importWithQr')}</button>
      )}
    </div>
  );
}

function QrSharePanel({ onClose }: { onClose: () => void }) {
  const { t } = usePT();
  const busy = usePevv((s) => s.busy);
  const wait = usePevv((s) => s.qrWait);
  const [pw, setPw] = useState('');
  const [url, setUrl] = useState<string | null>(null);
  const [frames, setFrames] = useState<string[] | null>(null);
  const [left, setLeft] = useState(Math.round(QR_HOLD_MS / 1000));
  const [showOffline, setShowOffline] = useState(false);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const close = () => {
    setPw('');
    setUrl(null);
    setFrames(null);
    clearHandoff();
    onCloseRef.current();
  };
  useEffect(() => () => { clearHandoff(); }, []);
  useEffect(() => {
    if (!url && !frames) return;
    let alive = true;
    const end = Date.now() + QR_HOLD_MS;
    const id = window.setInterval(() => {
      if (!alive) return;
      const s = Math.max(0, Math.round((end - Date.now()) / 1000));
      setLeft(s);
      if (s === 0) {
        alive = false;
        setPw('');
        setUrl(null);
        setFrames(null);
        clearHandoff();
        onCloseRef.current();
      }
    }, 500);
    return () => { alive = false; window.clearInterval(id); };
  }, [url, frames]);
  const reveal = async () => {
    const password = pw;
    setPw('');
    await confirmPasswordForQr(password);
    const file = usePevv.getState().file;
    if (!file) return;
    let handoff: string | null = null;
    if (syncEnabled()) {
      try { handoff = await publishHandoff(); } catch (e) {
        const msg = (e as Error).message;
        if (msg !== 'qr-signed-out' && msg !== 'qr-nosync') {
          usePevv.setState({ error: msg });
          return;
        }
      }
    }
    let packed: string[] | null = null;
    try { packed = await packVault(file); } catch (e) {
      if ((e as Error).message !== 'qr-too-big') throw e;
    }
    if (!handoff && !packed) {
      usePevv.setState({ error: 'qr-too-big' });
      return;
    }
    setUrl(handoff);
    setFrames(packed);
    setShowOffline(!handoff);
    setLeft(Math.round(QR_HOLD_MS / 1000));
  };
  if (url || frames) {
    return (
      <div className="flex flex-col items-center gap-3" data-testid="pevv-qr-shown">
        <p className="text-xs text-ink-secondary">{t('qrKeepOpen')}</p>
        <p className="text-xs text-accent-gold">{t('qrAnyone', { n: left })}</p>
        {url && (
          <div className="flex flex-col items-center gap-2">
            <QrCode text={url} size={320} testId="pevv-qr-image" />
            <p className="text-center text-xs text-ink-secondary">{t('qrCameraHint')}</p>
          </div>
        )}
        {!url && <p className="text-xs text-ink-secondary">{t('qrNeedAccount')}</p>}
        {frames && frames.length > 0 && (
          <div className="flex w-full flex-col items-center gap-2">
            {url && (
              <button type="button" className={btn} data-testid="pevv-qr-offline-toggle" onClick={() => setShowOffline((v) => !v)}>{t('qrOffline')}</button>
            )}
            {showOffline && (
              <>
                <p className="text-center text-xs text-ink-secondary">{t('qrOfflineHint')}</p>
                <FrameReel frames={frames} />
              </>
            )}
          </div>
        )}
        <button type="button" className={`${btn} min-h-11`} onClick={close} data-testid="pevv-qr-close">{t('close')}</button>
        <ErrorLine />
      </div>
    );
  }
  return (
    <form className="flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); void reveal().catch(() => undefined); }}>
      <label className={label}>
        {t('masterPassword')}
        <input autoFocus type="password" autoComplete="current-password" className={input} value={pw} onChange={(e) => setPw(e.target.value)} data-testid="pevv-qr-password" />
      </label>
      <div className="flex flex-wrap gap-2">
        <button type="submit" className={`${btnPrimary} min-h-11`} disabled={busy || !pw} data-testid="pevv-qr-submit">{busy ? t('deriving') : t('qrShow')}</button>
        <button type="button" className={`${btn} min-h-11`} onClick={close}>{t('cancel')}</button>
      </div>
      {wait && wait.total > 0 && <p className="text-xs text-cyan-100" data-testid="pevv-qr-sending">{t('qrSending', { got: wait.got, total: wait.total })}</p>}
      <ErrorLine />
    </form>
  );
}

function FrameReel({ frames }: { frames: string[] }) {
  const { t } = usePT();
  const [i, setI] = useState(0);
  // More than one frame: cycle by themselves; the scanner takes them in any order.
  const [pause, setPause] = useState(false);
  useEffect(() => {
    if (pause || frames.length < 2) return;
    const id = window.setInterval(() => setI((n) => (n + 1) % frames.length), 800);
    return () => window.clearInterval(id);
  }, [pause, frames.length]);
  const text = frames[i] ?? '';
  return (
    <div className="flex flex-col items-center gap-2">
      <QrCode text={text} size={320} testId="pevv-qr-frame" />
      <p className="font-mono text-xs text-cyan-100" data-testid="pevv-qr-frame-n">{t('qrFrame', { i: i + 1, n: frames.length })}</p>
      {frames.length > 1 && (
        <div className="flex gap-2">
          <button type="button" className={btn} onClick={() => setPause((v) => !v)} data-testid="pevv-qr-pause">{pause ? t('qrResume') : t('qrPause')}</button>
          <button type="button" className={btn} onClick={() => { setPause(true); setI((n) => (n + 1) % frames.length); }}>{t('qrNext')}</button>
        </div>
      )}
    </div>
  );
}

export function QrScanBox() {
  const { t } = usePT();
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState<{ got: number; need: number } | null>(null);
  const [camError, setCamError] = useState(false);
  return (
    <div className="rounded-md border border-cyan-500/30 bg-cyan-500/5 p-3" data-testid="pevv-qr-scan-box">
      <h3 className="text-sm font-medium text-cyan-50">{t('qrScan')}</h3>
      <p className="mt-1 text-xs text-ink-secondary">{t('qrScanHint')}</p>
      {progress && <p className="mt-2 text-xs text-cyan-100">{t('qrFrame', { i: progress.got, n: progress.need })}</p>}
      {!scanning ? (
        <button type="button" className={`${btnPrimary} mt-2 min-h-11`} data-testid="pevv-qr-scan" onClick={() => { setCamError(false); setScanning(true); }}>{t('qrScan')}</button>
      ) : (
        <Scanner
          onProgress={setProgress}
          onCameraError={() => setCamError(true)}
          onDone={() => setScanning(false)}
        />
      )}
      {camError && <p className="mt-2 text-xs text-accent-gold">{t('qrCameraOff')}</p>}
      <PhotoFallback onDone={() => setScanning(false)} />
      <ErrorLine />
    </div>
  );
}

export function QrWaitPanel() {
  const { t } = usePT();
  const wait = usePevv((s) => s.qrWait);
  const [, tick] = useState(0);
  useEffect(() => {
    if (!wait || wait.step === 'done') return;
    const id = window.setInterval(() => tick((n) => n + 1), 500);
    return () => window.clearInterval(id);
  }, [wait]);
  if (!wait) return null;
  const left = Math.max(0, Math.ceil((QR_HOLD_MS - (Date.now() - wait.started)) / 1000));
  const stalled = wait.step === 'cloud' && wait.checks >= 2 && wait.total === 0;
  const pct = wait.total > 0
    ? Math.min(100, Math.round((wait.got / wait.total) * 100))
    : wait.step === 'installing' ? 92
    : wait.step === 'signed-out' || wait.step === 'nosync' || stalled ? 20
    : wait.step === 'expired' ? 100
    : Math.min(85, 25 + wait.checks * 8);
  const label = wait.step === 'installing' ? t('qrWaitInstall')
    : wait.step === 'nosync' ? t('qrWaitNoSync')
    : wait.step === 'expired' ? t('qrWaitExpired')
    : stalled ? t('qrWaitEmpty', { n: wait.checks })
    : wait.checks === 0 && wait.total === 0 ? t('qrWaitStart')
    : wait.total > 0 ? t('qrWaitParts', { got: wait.got, total: wait.total, s: left })
    : t('qrWaitCloud', { n: wait.checks, s: left });
  return (
    <div className="mt-2" data-testid="pevv-qr-waiting">
      <div className="h-2 overflow-hidden rounded-full bg-space-surface" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} data-testid="pevv-qr-progress">
        <div className={`h-full transition-[width] duration-500 ${wait.step === 'expired' || wait.step === 'signed-out' || wait.step === 'nosync' || stalled ? 'bg-accent-gold' : 'bg-accent-cyan'}`} style={{ width: `${pct}%` }} />
      </div>
      <p className="mt-1 text-xs text-cyan-100">{label}</p>
      <ErrorLine />
      <button type="button" className={`${btn} mt-2 min-h-11`} onClick={() => dismissQrWait()} data-testid="pevv-qr-wait-stop">{t('qrWaitDismiss')}</button>
    </div>
  );
}

function useFrameSink(onProgress: (p: { got: number; need: number }) => void, onDone: () => void) {
  const parts = useRef(new FrameAssembler());
  const done = useRef(false);
  return async (raw: string) => {
    if (done.current) return;
    const hit = parseScan(raw);
    if (!hit) return;
    if (hit.kind === 'handoff') {
      done.current = true;
      rememberQrToken(hit.xfer ? `H.${hit.key}.${hit.xfer}` : `H.${hit.key}`);
      usePevv.setState({ error: null, qrWait: { step: 'cloud', checks: 0, got: 0, total: 0, started: Date.now() } });
      onDone();
      await consumePendingQr();
      return;
    }
    const got = parts.current.add(hit.frame);
    if (!got) return;
    onProgress({ got: got.got, need: got.need });
    if (!got.complete) return;
    done.current = true;
    try {
      await installVaultCopy(await unpackFrames(parts.current.frames()));
      openVault();
    } catch (e) {
      done.current = false;
      parts.current.reset();
      usePevv.setState({ error: (e as Error).message });
    }
    onDone();
  };
}

function Scanner({ onProgress, onCameraError, onDone }: { onProgress: (p: { got: number; need: number }) => void; onCameraError: () => void; onDone: () => void }) {
  const { t } = usePT();
  const videoRef = useRef<HTMLVideoElement>(null);
  const viewRef = useRef<HTMLCanvasElement>(null);
  const [needTap, setNeedTap] = useState(false);
  const onCameraErrorRef = useRef(onCameraError);
  onCameraErrorRef.current = onCameraError;
  const accept = useFrameSink(onProgress, onDone);
  const acceptRef = useRef(accept);
  acceptRef.current = accept;
  useEffect(() => {
    let stop = false;
    let stream: MediaStream | null = null;
    let timer = 0;
    const video = videoRef.current;
    if (!video) return;
    video.muted = true;
    video.defaultMuted = true;
    video.playsInline = true;
    video.setAttribute('muted', '');
    video.setAttribute('playsinline', '');
    video.setAttribute('webkit-playsinline', '');
    const detector = barcodeDetector();
    const decode = async () => {
      if (stop || !video.videoWidth) return;
      const view = viewRef.current;
      const side = Math.min(video.videoWidth, video.videoHeight, 720);
      const sx = Math.floor((video.videoWidth - side) / 2);
      const sy = Math.floor((video.videoHeight - side) / 2);
      if (view) {
        if (view.width !== side) { view.width = side; view.height = side; }
        view.getContext('2d')?.drawImage(video, sx, sy, side, side, 0, 0, side, side);
      }
      try {
        if (detector) {
          const codes = await detector.detect(video);
          const value = codes.find((c) => c.rawValue)?.rawValue;
          if (value) await acceptRef.current(value);
        }
        const shot = view?.getContext('2d')?.getImageData(0, 0, side, side);
        if (shot) {
          const hit = jsQR(shot.data, shot.width, shot.height, { inversionAttempts: 'attemptBoth' });
          if (hit?.data) await acceptRef.current(hit.data);
        }
      } catch { /* one bad frame should not stop the camera */ }
    };
    const tick = () => {
      if (stop) return;
      void decode();
      timer = window.setTimeout(tick, 200);
    };
    void (async () => {
      try {
        stream = await openCamera();
      } catch {
        if (!stop) onCameraErrorRef.current();
        return;
      }
      if (stop || !videoRef.current) { stream.getTracks().forEach((tr) => tr.stop()); return; }
      video.srcObject = stream;
      // Continuous autofocus where the browser allows it, so a blurred frame recovers by itself.
      try { await stream.getVideoTracks()[0]?.applyConstraints({ advanced: [{ focusMode: 'continuous' } as MediaTrackConstraintSet] }); } catch { /* not supported */ }
      const play = async () => {
        try { await video.play(); setNeedTap(false); } catch { if (!stop) setNeedTap(true); }
      };
      video.onloadedmetadata = () => { void play(); };
      await play();
      tick();
    })();
    return () => {
      stop = true;
      window.clearTimeout(timer);
      stream?.getTracks().forEach((tr) => tr.stop());
      video.srcObject = null;
    };
  }, []);
  return (
    <div className="mt-2">
      <video
        ref={videoRef}
        muted
        playsInline
        autoPlay
        data-testid="pevv-qr-video"
        style={{ position: 'absolute', width: 1, height: 1, opacity: 0, pointerEvents: 'none' }}
      />
      <canvas ref={viewRef} className="aspect-square w-full max-w-xs rounded-md bg-black" aria-label="Camera" />
      {needTap && (
        <button type="button" className={`${btnPrimary} mt-2 min-h-11`} onClick={() => { const v = videoRef.current; if (!v) return; v.muted = true; void v.play().then(() => setNeedTap(false), () => setNeedTap(true)); }}>
          {t('qrScan')}
        </button>
      )}
    </div>
  );
}

function PhotoFallback({ onDone }: { onDone: () => void }) {
  const { t } = usePT();
  const accept = useFrameSink(() => undefined, onDone);
  return (
    <label className="mt-2 flex flex-col gap-1 text-xs text-ink-secondary">
      {t('qrPhoto')}
      <input type="file" accept="image/*" capture="environment" className="text-xs" data-testid="pevv-qr-photo" onChange={async (e) => {
        const file = e.target.files?.[0];
        e.target.value = '';
        if (!file) return;
        try {
          const bmp = await createImageBitmap(file);
          const canvas = document.createElement('canvas');
          canvas.width = bmp.width;
          canvas.height = bmp.height;
          const ctx = canvas.getContext('2d');
          if (!ctx) return;
          ctx.drawImage(bmp, 0, 0);
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const hit = jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
          if (hit?.data) await accept(hit.data);
          else usePevv.setState({ error: 'qr-damaged' });
        } catch {
          usePevv.setState({ error: 'qr-damaged' });
        }
      }} />
    </label>
  );
}
