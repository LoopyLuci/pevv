/**
 * The desktop app's side of device sync over Transferd (docs/TRANSPORT.md), in the webview.
 *
 * The Rust shell runs the transport (off by default, no relay unless the person adds one) and only
 * ever handles the **sealed** vault file. A file a peer sends is held by the shell; this module
 * takes it and hands it to `reconcileRemote(file, 'peer')`, the same merge the cloud copy and the
 * live roster use (`merge.ts`, see docs/SYNC.md), so there is one set of CAS and merge rules and
 * a locked window still stages the copy instead of installing it. Supabase stays a second lane:
 * nothing here switches it off, so when no peer is reachable the cloud copy carries on by itself.
 */
import { create } from 'zustand';
import { parseFile } from '../extension/bridge';
import type { VaultFile } from '../model';

export const EVENT = 'transport-event';
/** Reconcile with the peers this often while the transport runs (a safety net; writes push at once). */
export const SYNC_INTERVAL_MS = 30_000;
/** Same debounce as the cloud mirror. */
export const WRITE_DEBOUNCE_MS = 400;

export interface TransferdIpc {
  invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
  listen<P>(event: string, fn: (payload: P) => void): Promise<() => void>;
}

export interface TransferdPeer { nodeId: string; name: string; state: 'approved' | 'revoked'; reachable: boolean | null }
export interface TransferdPending { nodeId: string; name: string; sas: string[] }
export interface TransferdInvite { text: string; expiresAt: number }

export interface TransferdStatus {
  available: boolean;
  enabled: boolean;
  running: boolean;
  deviceName: string;
  nodeId: string | null;
  fingerprint: string[];
  seedProtection: 'os-keystore' | 'file-permissions' | null;
  relays: string[];
  direct: string[];
  peers: TransferdPeer[];
  pending: TransferdPending[];
  invite: TransferdInvite | null;
  lastSync: number | null;
  lastError: string | null;
  staged: boolean;
}

export interface TransferdStoreApi {
  reconcileRemote(remote: VaultFile, source: 'cloud' | 'peer'): Promise<boolean>;
  /** Calls `fn` after every local vault write. Returns a function that stops it. */
  onVaultWrite(fn: () => void): () => void;
  /** This device's PEVV roster id and name, handed to the shell when the transport is switched on. */
  device(): { id: string; name: string };
}

export type Lane = 'transferd' | 'cloud' | 'none';

/**
 * Which lane carries the vault right now. A reachable Transferd peer is preferred; otherwise the
 * cloud copy (when sync is on) takes over by itself, so the person is never left without a lane
 * they turned on. Pure: the UI and tests use it; the actual lanes run side by side.
 */
export function chooseLane(s: Pick<TransferdStatus, 'running' | 'peers'> | null, cloudOn: boolean): Lane {
  const peerUp = !!s?.running && s.peers.some((p) => p.state === 'approved' && p.reachable === true);
  if (peerUp) return 'transferd';
  return cloudOn ? 'cloud' : 'none';
}

interface TransferdUi { status: TransferdStatus | null }
export const useTransferd = create<TransferdUi>()(() => ({ status: null }));

let api: { ipc: TransferdIpc; store: TransferdStoreApi } | null = null;

/** For the settings section; null until `startTransferd` ran (i.e. outside the desktop app). */
export function transferdIpc(): TransferdIpc | null {
  return api?.ipc ?? null;
}

export function transferdDevice(): { id: string; name: string } | null {
  return api?.store.device() ?? null;
}

function setStatus(s: TransferdStatus): TransferdStatus {
  useTransferd.setState({ status: s });
  return s;
}

/** Ask the shell for the status (never throws). */
export async function refreshStatus(ipc: TransferdIpc): Promise<TransferdStatus | null> {
  try { return setStatus(await ipc.invoke<TransferdStatus>('transport_status')); } catch { return null; }
}

/** Take the file a peer sent (if any) and merge it like any other remote copy. */
export async function pullStaged(ipc: TransferdIpc, store: Pick<TransferdStoreApi, 'reconcileRemote'>): Promise<boolean> {
  let text: string | null = null;
  try { text = await ipc.invoke<string | null>('transport_take_staged'); } catch { return false; }
  const file = parseFile(text);
  if (!file) return false;
  try { return await store.reconcileRemote(file, 'peer'); } catch { return false; }
}

/**
 * Remove a peer: the shell stops the transport using it at once, then the existing key rotation
 * (`rotateKey`, "Also change the vault key") makes what it already holds worthless. `rotate`
 * runs only if the revoke worked. Resolves to whatever `rotate` returns.
 */
export async function revokePeer<R>(ipc: TransferdIpc, nodeId: string, rotate: (() => Promise<R>) | null): Promise<R | null> {
  setStatus(await ipc.invoke<TransferdStatus>('transport_peer_revoke', { nodeId }));
  return rotate ? rotate() : null;
}

/** Switch the transport on or off for this device. */
export async function setEnabled(ipc: TransferdIpc, enabled: boolean, device: { id: string; name: string } | null): Promise<TransferdStatus> {
  return setStatus(await ipc.invoke<TransferdStatus>('transport_enable', { enabled, deviceId: device?.id ?? null, name: device?.name ?? null }));
}

export interface StartOptions { intervalMs?: number; debounceMs?: number }

/** Wire the shell's events and the vault's writes to the lane. Resolves to a function that stops it. */
export async function startTransferd(ipc: TransferdIpc, store: TransferdStoreApi, opts: StartOptions = {}): Promise<() => void> {
  api = { ipc, store };
  let timer: ReturnType<typeof setTimeout> | null = null;
  let stopped = false;

  const running = (): boolean => !!useTransferd.getState().status?.running;
  const kick = async (): Promise<void> => {
    if (stopped || !running()) return;
    try { setStatus(await ipc.invoke<TransferdStatus>('transport_sync_now')); } catch { /* the status says why */ }
    await pullStaged(ipc, store);
  };

  const offWrite = store.onVaultWrite(() => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => { timer = null; void kick(); }, opts.debounceMs ?? WRITE_DEBOUNCE_MS);
  });
  const interval = setInterval(() => { void kick(); }, opts.intervalMs ?? SYNC_INTERVAL_MS);
  const off = await ipc.listen<{ kind?: string }>(EVENT, (p) => {
    if (p?.kind === 'staged') void pullStaged(ipc, store);
    else void refreshStatus(ipc);
  });

  const first = await refreshStatus(ipc);
  if (first?.running) void kick();
  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    clearInterval(interval);
    offWrite();
    off();
    api = null;
    useTransferd.setState({ status: null });
  };
}
