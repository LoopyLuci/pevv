/**
 * The webview's half of the auto-updater. The Rust shell (updater.rs) fetches the release manifest,
 * checks the minisign signature against the pubkey in tauri.conf.json, and installs. This file decides
 * when to ask (on start, then daily, only while the "check automatically" setting is on) and holds the
 * state for the prompt. What happens after a check depends on the mode chosen in Settings > Updates:
 * manual (default) asks first; download fetches in the background and asks "Restart to update"; install
 * downloads and installs by itself, but only while the vault is locked (never over an unlocked vault or a
 * half-finished setup). The shell verifies the signature in every mode.
 */
import { create } from 'zustand';
import { usePevv } from '../store';

export const CHECK_EVERY_MS = 24 * 60 * 60 * 1000;

export interface UpdateIpc {
  invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
}

export interface UpdateInfo { version: string; current: string; notes: string | null }

export type UpdateMode = 'manual' | 'download' | 'install';
export const UPDATE_MODES: readonly UpdateMode[] = ['manual', 'download', 'install'];

/** Where the update is: just offered by the endpoint, or already downloaded and verified. */
export type UpdateStage = 'found' | 'downloaded';
/** What to do next: ask the person, fetch it, ask "Restart to update", install now, or wait for a safe moment. */
export type UpdateStep = 'prompt' | 'download' | 'prompt-restart' | 'install' | 'wait';

/**
 * The decision table. `safe` means a restart cannot hurt: the vault is locked (or none exists), not unlocked,
 * not mid-unlock and not mid-setup. Only the silent mode ever acts without a click, and only when `safe`.
 */
export function nextStep(mode: UpdateMode, stage: UpdateStage, safe: boolean): UpdateStep {
  if (mode === 'manual') return 'prompt';
  if (stage === 'found') return 'download';
  if (mode === 'download') return 'prompt-restart';
  return safe ? 'install' : 'wait';
}

export function normalizeMode(v: unknown): UpdateMode {
  return UPDATE_MODES.includes(v as UpdateMode) ? (v as UpdateMode) : 'manual';
}

export type UpdatePhase = 'idle' | 'checking' | 'available' | 'downloading' | 'ready' | 'installing' | 'upToDate' | 'disabled' | 'error';

interface UpdateUi {
  phase: UpdatePhase;
  info: UpdateInfo | null;
  /** A version the person pressed "Later" on: not offered again until a newer one shows up or the app restarts. */
  dismissed: string | null;
  error: string | null;
  /** The silent mode is waiting for a safe moment or installing: no prompt is shown. */
  quiet: boolean;
}

export const useUpdate = create<UpdateUi>(() => ({ phase: 'idle', info: null, dismissed: null, error: null, quiet: false }));

/** What the decision needs to know about the app; the default reads the settings and the vault state. */
export interface UpdateCtx {
  mode(): UpdateMode;
  safe(): boolean;
}

export const defaultCtx: UpdateCtx = {
  mode: () => normalizeMode(usePevv.getState().prefs.updateMode),
  safe: () => { const s = usePevv.getState().status; return s === 'locked' || s === 'none'; },
};

const msg = (e: unknown): string => (typeof e === 'string' ? e : (e as Error).message);

async function doInstall(ipc: UpdateIpc, quiet: boolean): Promise<void> {
  useUpdate.setState({ phase: 'installing', error: null, quiet });
  try {
    await ipc.invoke('update_install');
  } catch (e) {
    useUpdate.setState({ phase: 'error', error: msg(e), quiet: false });
  }
}

function applyDownloaded(ipc: UpdateIpc, ctx: UpdateCtx, manual: boolean): Promise<void> | void {
  const step = nextStep(ctx.mode(), 'downloaded', ctx.safe());
  if (step === 'install') return doInstall(ipc, true);
  if (step === 'wait') { useUpdate.setState({ phase: 'ready', quiet: true }); return; }
  const info = useUpdate.getState().info;
  if (!manual && info && useUpdate.getState().dismissed === info.version) useUpdate.setState({ phase: 'idle', quiet: false });
  else useUpdate.setState({ phase: 'ready', quiet: false });
}

/** Ask the shell. `manual` (the Check now button) ignores an earlier "Later" and reports "up to date" / errors. */
export async function checkForUpdate(ipc: UpdateIpc, manual = false, ctx: UpdateCtx = defaultCtx): Promise<void> {
  const cur = useUpdate.getState().phase;
  if (cur === 'installing' || cur === 'downloading') return;
  useUpdate.setState({ phase: 'checking', error: null });
  try {
    if (!(await ipc.invoke<boolean>('update_enabled'))) {
      useUpdate.setState({ phase: 'disabled' });
      return;
    }
    const info = await ipc.invoke<UpdateInfo | null>('update_check');
    if (!info) {
      useUpdate.setState({ phase: 'upToDate', info: null, quiet: false });
      return;
    }
    useUpdate.setState({ info });
    if (nextStep(ctx.mode(), 'found', ctx.safe()) === 'prompt') {
      if (!manual && useUpdate.getState().dismissed === info.version) useUpdate.setState({ phase: 'idle' });
      else useUpdate.setState({ phase: 'available', quiet: false });
      return;
    }
    useUpdate.setState({ phase: 'downloading', quiet: ctx.mode() === 'install' });
    try {
      await ipc.invoke('update_download');
    } catch (e) {
      useUpdate.setState({ phase: manual ? 'error' : 'idle', error: msg(e), quiet: false });
      return;
    }
    await applyDownloaded(ipc, ctx, manual);
  } catch (e) {
    useUpdate.setState({ phase: manual ? 'error' : 'idle', error: msg(e) });
  }
}

export function dismissUpdate(): void {
  const { info } = useUpdate.getState();
  useUpdate.setState({ phase: 'idle', dismissed: info?.version ?? null });
}

/** The "Update now" / "Restart to update" button. The shell verifies the signature, installs and restarts. */
export async function installUpdate(ipc: UpdateIpc): Promise<void> {
  const { phase } = useUpdate.getState();
  if (phase !== 'available' && phase !== 'ready') return;
  await doInstall(ipc, false);
}

/** Silent mode: a downloaded update waits for the vault to be locked; call this when the vault state changes. */
export async function installWhenSafe(ipc: UpdateIpc, ctx: UpdateCtx = defaultCtx): Promise<void> {
  const { phase, quiet } = useUpdate.getState();
  if (phase === 'ready' && quiet && ctx.mode() === 'install' && ctx.safe()) await doInstall(ipc, true);
}

/** Check now, then every day while the setting stays on; also installs a waiting silent update when the vault locks. Returns a stop function. */
export function startUpdater(ipc: UpdateIpc, enabled: () => boolean = () => usePevv.getState().prefs.autoUpdate, every = CHECK_EVERY_MS, ctx: UpdateCtx = defaultCtx): () => void {
  const tick = () => { if (enabled()) void checkForUpdate(ipc, false, ctx); };
  tick();
  const timer = setInterval(tick, every);
  const unsub = usePevv.subscribe((s, prev) => { if (s.status !== prev.status) void installWhenSafe(ipc, ctx); });
  return () => { clearInterval(timer); unsub(); };
}
