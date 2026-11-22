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

export interface CloudFile { path: string; body: string }
export interface SyncAccount { userId: string; email: string | null; anonymous: boolean }

/** The only paths the cloud copy accepts (the server enforces the same list). */
export const CLOUD_PATHS = ['/vault/pevv.vault.json', '/vault/pevv-handoff.json'] as const;
const MAX_BODY = 262_144;

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
    if (!(CLOUD_PATHS as readonly string[]).includes(path) || body.length > MAX_BODY) throw new Error('cloud-file-rejected');
    const file = { path, body };
    set({ files: [...get().files.filter((f) => f.path !== path), file] });
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

async function push(path: string, body: string): Promise<void> {
  const c = await getClient();
  if (!c || !account) return;
  try {
    await c.from('pevv_blobs').upsert({ user_id: account.userId, path, body }, { onConflict: 'user_id,path' });
  } catch { /* the next pull or write retries */ }
}

async function removeRemote(path: string): Promise<void> {
  const c = await getClient();
  if (!c || !account) return;
  try { await c.from('pevv_blobs').delete().eq('user_id', account.userId).eq('path', path); } catch { /* ignore */ }
}

let pulling: Promise<void> | null = null;

/** Ask the server for this account's blobs now. Resolves quietly when sync is off or signed out. */
export function pullCloud(): Promise<void> {
  pulling ??= (async () => {
    try {
      const c = await getClient();
      if (!c || !account) return;
      const { data, error } = await c.from('pevv_blobs').select('path, body');
      if (error || !Array.isArray(data)) return;
      const next = (data as CloudFile[]).filter((r) => (CLOUD_PATHS as readonly string[]).includes(r.path) && typeof r.body === 'string' && r.body.length <= MAX_BODY);
      const cur = useCloudFiles.getState();
      const same = cur.filesLoaded && cur.files.length === next.length && next.every((n) => cur.files.some((f) => f.path === n.path && f.body === n.body));
      if (!same) useCloudFiles.setState({ files: next, filesLoaded: true });
      else if (!cur.filesLoaded) useCloudFiles.setState({ filesLoaded: true });
    } catch { /* offline: keep what we have */ } finally { pulling = null; }
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
