/**
 * Optional cloud copy of the ENCRYPTED vault file. This is the only thing that ever
 * leaves the device: the server stores an opaque ciphertext blob per signed-in user
 * (table `pevv_blobs`, row-level security, see supabase/pevv_sync.sql) and never sees a key.
 *
 * Everything is a no-op unless VITE_PEVV_SYNC_URL and VITE_PEVV_SYNC_ANON_KEY were set at build time.
 *
 * The small file store below keeps the shape the vault sync code was written against
 * (`files`, `filesLoaded`, `initFiles`, `readFile`, `writeFile`, `removeFile`): a handful of
 * named text bodies. Remote changes arrive by polling (tab focus + every 2 minutes).
 */
import { create } from 'zustand';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { SYNC_ANON_KEY, SYNC_URL, syncConfigured } from './config';
import { type SyncErrorCode, reportBusy, reportError, reportPending, reportPulled, reportSynced } from '../syncStatus';

/** `rev` is the server's row revision (compare-and-swap token); 0 = the server has no row yet. */
export interface CloudFile { path: string; body: string; rev?: number }
export interface SyncAccount { userId: string; email: string | null; anonymous: boolean }

/** The only paths the cloud copy accepts (the server enforces the same list). */
export const CLOUD_PATHS = ['/vault/pevv.vault.json', '/vault/pevv-handoff.json'] as const;

export const syncEnabled = (): boolean => syncConfigured();

let clientP: Promise<SupabaseClient | null> | null = null;
export function getClient(): Promise<SupabaseClient | null> {
  if (!syncConfigured()) return Promise.resolve(null);
  clientP ??= Promise.resolve(createClient(SYNC_URL, SYNC_ANON_KEY, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, storageKey: 'pevv-sync-auth' },
  }));
  return clientP;
}

let account: SyncAccount | null = null;
let accountKnown: Promise<void> | null = null;
const listeners = new Set<(a: SyncAccount | null) => void>();

export const currentAccount = (): SyncAccount | null => account;
export function onSyncAccount(l: (a: SyncAccount | null) => void): () => void {
  listeners.add(l);
  return () => { listeners.delete(l); };
}

type AuthUser = { id: string; email?: string | null; is_anonymous?: boolean } | null | undefined;
const toAccount = (u: AuthUser): SyncAccount | null => (u ? { userId: u.id, email: u.email ?? null, anonymous: !!u.is_anonymous } : null);

function setAccount(a: SyncAccount | null): void {
  const changed = a?.userId !== account?.userId;
  account = a;
  for (const l of listeners) l(a);
  if (changed) {
    useCloudFiles.setState({ files: [], filesLoaded: false });
    if (a) void pullCloud();
    else useCloudFiles.setState({ filesLoaded: true });
  }
}

interface CloudFiles {
  files: CloudFile[];
  filesLoaded: boolean;
  initFiles: () => Promise<void>;
  readFile: (path: string) => CloudFile | undefined;
  writeFile: (path: string, body: string) => CloudFile;
  removeFile: (path: string) => boolean;
}

/** Answer of the `pevv_put` function (supabase/migrations/0002_pevv_hardening.sql). */
export interface PutResult { ok: boolean; error?: string; rev?: number; body?: string }
type ConflictHandler = (path: string, remote: CloudFile) => void;
const conflictHandlers = new Set<ConflictHandler>();
/** Called when a write lost the compare-and-swap: the server holds a newer copy. The handler re-merges and writes again. */
export function onCloudConflict(fn: ConflictHandler): () => void {
  conflictHandlers.add(fn);
  return () => { conflictHandlers.delete(fn); };
}

type PushedHandler = (path: string, body: string) => void;
const pushedHandlers = new Set<PushedHandler>();
/** Called after the server accepted a write (the body is then what the server holds). */
export function onCloudPushed(fn: PushedHandler): () => void {
  pushedHandlers.add(fn);
  return () => { pushedHandlers.delete(fn); };
}

const ERROR_CODES: Record<string, SyncErrorCode> = {
  'rate-limited': 'rate-limited', 'too-large': 'too-large', 'rev-regressed': 'rev-regressed', 'not-allowed': 'denied', 'bad-body': 'denied', 'not-signed-in': 'denied',
};

export const useCloudFiles = create<CloudFiles>()((set, get) => ({
  files: [],
  filesLoaded: false,
  initFiles: async () => {
    if (get().filesLoaded) return;
    if (!syncConfigured()) { set({ filesLoaded: true }); return; }
    startSync();
    await accountKnown;
    if (get().filesLoaded) return;
    if (!account) { set({ filesLoaded: true }); return; }
    await pullCloud();
  },
  readFile: (path) => get().files.find((f) => f.path === path),
  writeFile: (path, body) => {
    if (!(CLOUD_PATHS as readonly string[]).includes(path)) throw new Error('cloud-file-rejected');
    const prev = get().files.find((f) => f.path === path);
    const file: CloudFile = { path, body, rev: prev?.rev ?? 0 };
    set({ files: [...get().files.filter((f) => f.path !== path), file] });
    reportPending(true);
    void push(path, body);
    return file;
  },
  removeFile: (path) => {
    if (!get().files.some((f) => f.path === path)) return false;
    set({ files: get().files.filter((f) => f.path !== path) });
    void removeRemote(path);
    return true;
  },
}));

/**
 * Compare-and-swap write. The server only accepts it when its row is still at the revision this device last saw.
 * On a conflict the newer server copy is stored locally and handed to the conflict handlers (sync.ts re-merges and writes again).
 */
async function push(path: string, body: string, attempt = 0): Promise<void> {
  const c = await getClient();
  if (!c || !account) return;
  const expected = useCloudFiles.getState().files.find((f) => f.path === path)?.rev ?? 0;
  reportBusy(true);
  try {
    const { data, error } = await c.rpc('pevv_put', { p_path: path, p_body: body, p_expected_rev: expected });
    if (error) { reportError('offline'); return; }
    const res = data as PutResult | null;
    if (res?.ok) {
      setRev(path, res.rev ?? expected + 1);
      reportSynced();
      for (const h of pushedHandlers) h(path, body);
      return;
    }
    if (res?.error === 'conflict') {
      // No body in the answer: the row is gone or soft deleted. Learn its revision and write again.
      if (typeof res.body !== 'string') {
        if (attempt < 2) { setRev(path, res.rev ?? 0); await push(path, body, attempt + 1); } else reportError('unknown');
        return;
      }
      const remote: CloudFile = { path, body: res.body, rev: res.rev ?? 0 };
      if (path !== CLOUD_PATHS[0] && attempt < 2) { setRev(path, remote.rev ?? 0); await push(path, body, attempt + 1); return; }
      useCloudFiles.setState({ files: [...useCloudFiles.getState().files.filter((f) => f.path !== path), remote] });
      for (const h of conflictHandlers) h(path, remote);
      return;
    }
    reportError(ERROR_CODES[res?.error ?? ''] ?? 'unknown');
  } catch { reportError('offline'); } finally { reportBusy(false); }
}

function setRev(path: string, rev: number): void {
  const files = useCloudFiles.getState().files;
  useCloudFiles.setState({ files: files.map((f) => (f.path === path ? { ...f, rev } : f)) });
}

async function removeRemote(path: string): Promise<void> {
  const c = await getClient();
  if (!c || !account) return;
  try { await c.rpc('pevv_delete', { p_path: path }); } catch { /* ignore */ }
}

let pulling: Promise<void> | null = null;

/** Ask the server for this account's blobs now. Resolves quietly when sync is off or signed out. */
export function pullCloud(): Promise<void> {
  pulling ??= (async () => {
    try {
      const c = await getClient();
      if (!c || !account) return;
      reportBusy(true);
      const { data, error } = await c.from('pevv_blobs').select('path, body, rev, deleted_at').is('deleted_at', null);
      if (error || !Array.isArray(data)) { reportError('offline'); return; }
      const next = (data as CloudFile[]).filter((r) => (CLOUD_PATHS as readonly string[]).includes(r.path) && typeof r.body === 'string')
        .map((r) => ({ path: r.path, body: r.body, rev: Number(r.rev) || 0 }));
      const cur = useCloudFiles.getState();
      const same = cur.filesLoaded && cur.files.length === next.length && next.every((n) => cur.files.some((f) => f.path === n.path && f.body === n.body && f.rev === n.rev));
      if (!same) useCloudFiles.setState({ files: next, filesLoaded: true });
      else if (!cur.filesLoaded) useCloudFiles.setState({ filesLoaded: true });
      reportPulled();
    } catch { reportError('offline'); } finally { reportBusy(false); pulling = null; }
  })();
  return pulling;
}

let started = false;

/** Safe to call any number of times. Picks up the saved session and polls for other devices' changes. */
export function startSync(): void {
  if (started || !syncConfigured()) return;
  started = true;
  accountKnown = (async () => {
    const c = await getClient();
    if (!c) return;
    const { data } = await c.auth.getSession();
    setAccount(toAccount(data.session?.user));
    c.auth.onAuthStateChange((_e, session) => {
      const next = toAccount(session?.user);
      if (next?.userId !== account?.userId) setAccount(next);
    });
  })();
  globalThis.document?.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && account) void pullCloud();
  });
  globalThis.addEventListener?.('online', () => { if (account) void pullCloud(); });
  setInterval(() => {
    if (account && globalThis.document?.visibilityState !== 'hidden') void pullCloud();
  }, 120_000);
}

/** Passwordless email link. */
export async function sendMagicLink(email: string): Promise<void> {
  const c = await getClient();
  if (!c) throw new Error('Cloud sync is not configured');
  const redirect = globalThis.location && /^https?:$/.test(globalThis.location.protocol) ? `${globalThis.location.origin}${globalThis.location.pathname}` : undefined;
  const { error } = await c.auth.signInWithOtp({ email: email.trim(), options: { shouldCreateUser: true, ...(redirect ? { emailRedirectTo: redirect } : {}) } });
  if (error) throw new Error(error.message);
}

export async function signInAnonymously(): Promise<void> {
  const c = await getClient();
  if (!c) throw new Error('Cloud sync is not configured');
  const { error } = await c.auth.signInAnonymously();
  if (error) throw new Error(error.message);
}

export async function signOut(): Promise<void> {
  const c = await getClient();
  if (c) await c.auth.signOut();
}
