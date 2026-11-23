/**
 * What the sync status panel shows, in one small store with no dependencies on the rest of PEVV
 * (so host/cloud.ts, sync.ts and store.ts can all report into it). Plain facts only: times, counts, error codes.
 * Item titles of resolved conflicts are held in memory for the current session and never persisted here.
 */
import { create } from 'zustand';

export type SyncErrorCode = 'offline' | 'rate-limited' | 'too-large' | 'rejected-revoked' | 'rejected-stale-key' | 'rejected-key' | 'rejected-vault' | 'denied' | 'rev-regressed' | 'unknown';

export interface ResolvedConflict { id: string; title: string; kind: 'edited-both' | 'deleted-vs-edited'; kept: 'local' | 'remote'; at: number }

export interface SyncStatus {
  /** ms epoch of the last successful push or pull; 0 = never */
  lastSyncedAt: number;
  /** this device has changes the server does not have yet */
  pending: boolean;
  /** a push or pull is running */
  busy: boolean;
  error: SyncErrorCode | null;
  /** the newest resolved conflicts of this session, newest first (at most 20) */
  resolved: ResolvedConflict[];
  /** the vault key was rotated elsewhere: unlock again with the master password */
  needsUnlock: boolean;
}

export const useSyncStatus = create<SyncStatus>()(() => ({
  lastSyncedAt: 0, pending: false, busy: false, error: null, resolved: [], needsUnlock: false,
}));

export function reportSynced(now = Date.now()): void {
  useSyncStatus.setState({ lastSyncedAt: now, pending: false, error: null });
}
/** A successful pull: the server answered, but this device may still have changes to send. */
export function reportPulled(now = Date.now()): void {
  useSyncStatus.setState({ lastSyncedAt: now, error: null });
}
export const reportPending = (pending: boolean): void => useSyncStatus.setState({ pending });
export const reportBusy = (busy: boolean): void => useSyncStatus.setState({ busy });
export const reportError = (error: SyncErrorCode | null): void => useSyncStatus.setState({ error });
export const reportNeedsUnlock = (needsUnlock: boolean): void => useSyncStatus.setState({ needsUnlock });
export function reportConflicts(list: Array<Omit<ResolvedConflict, 'at'>>, at = Date.now()): void {
  if (!list.length) return;
  useSyncStatus.setState((s) => ({ resolved: [...list.map((c) => ({ ...c, at })), ...s.resolved].slice(0, 20) }));
}

/** "just now", "5 minutes ago"... via the caller's translator; returns [key, n]. */
export function agoParts(ms: number, now = Date.now()): ['never' | 'justNow' | 'minutes' | 'hours' | 'days', number] {
  if (!ms) return ['never', 0];
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 45) return ['justNow', 0];
  if (s < 3600) return ['minutes', Math.max(1, Math.round(s / 60))];
  if (s < 86_400) return ['hours', Math.round(s / 3600)];
  return ['days', Math.round(s / 86_400)];
}
