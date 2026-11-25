/** PEVV data model and pure helpers (generator, strength, reuse, .env, autofill matching). */
import type { KdfParams, Sealed } from './crypto';
import type { PasskeyRecord } from './webauthn';

export const VAULT_FORMAT = 'luciverse.pevv';
export const ENTRY_TYPES = ['login', 'env', 'note', 'apikey', 'card', 'ssh', 'identity', 'passkey'] as const;
export type EntryType = (typeof ENTRY_TYPES)[number];

export interface HistoryItem { at: number; field: string; value: string }

/**
 * The losing side of a sync conflict, kept inside the winning item (sealed with it). Optional and ignored by older
 * clients, which keep it as an unknown field. See docs/SYNC.md.
 */
export interface ConflictCopy { at: number; ver: number; data: Record<string, unknown> }

/**
 * Desktop auto-type for a login: which windows it may type into, and what to type. Optional and
 * ignored by every older client (the entry is one sealed JSON object and unknown fields are kept
 * as they are). A login with no `autoType` is never typed into any window, whatever its `site`.
 */
export interface AutoTypeConfig {
  /** Window-title patterns (`*` and `?` wildcards, any match counts, case-insensitive). */
  windows: string[];
  /** Only this program (file name such as `putty.exe`; the `.exe` is optional). */
  process?: string;
  /** Keys to type; default `{USERNAME}{TAB}{PASSWORD}{ENTER}`. See autotype.ts. */
  sequence?: string;
}

export interface EntryData {
  type: EntryType;
  title: string;
  /** login */
  site?: string;
  username?: string;
  password?: string;
  totp?: string;
  /** Desktop auto-type into other programs (optional; older clients ignore it) */
  autoType?: AutoTypeConfig | undefined;
  /** env var */
  name?: string;
  value?: string;
  env?: string;
  /** api key */
  service?: string;
  key?: string;
  /** payment card */
  cardholder?: string;
  number?: string;
  /** MM/YY */
  expiry?: string;
  cvv?: string;
  pin?: string;
  /** SSH key */
  privateKey?: string;
  publicKey?: string;
  passphrase?: string;
  /** identity */
  fullName?: string;
  email?: string;
  phone?: string;
  address?: string;
  /**
   * passkey PEVV holds for another site (desktop provider; see passkeyProvider.ts). Never shown in the item
   * list, never offered for login or auto-type. Binary values are base64url.
   */
  rpId?: string;
  rpName?: string;
  credentialId?: string;
  userHandle?: string;
  userName?: string;
  userDisplayName?: string;
  /** PKCS#8 P-256 private key, inside the sealed item like a password. */
  passkeyPrivateKey?: string;
  passkeyPublicKey?: string;
  signCount?: number;
  /** all */
  notes?: string;
  /** optional folder (a single location, like 1Password vault sections / Bitwarden folders) */
  folder?: string;
  tags: string[];
  favorite: boolean;
  created: number;
  updated: number;
  history: HistoryItem[];
  /** Versions that lost a sync conflict on this item, newest first (at most 5). */
  conflicts?: ConflictCopy[] | undefined;
}

export interface Entry extends EntryData { id: string; ver: number }

/** On-disk entry: only id + version + ciphertext. Titles, types and tags are encrypted too. */
export interface EntryRecord { id: string; ver: number; sealed: Sealed }

export type Slot =
  | { id: string; type: 'password'; wrapped: Sealed }
  | { id: string; type: 'prf'; credId: string; salt: string; wrapped: Sealed }
  | { id: string; type: 'recovery-code'; hash: string; salt: string; wrapped: Sealed }
  | { id: string; type: 'recovery-key'; salt: string; wrapped: Sealed }
  /** A 32-byte secret in a `.pevvkey` file on a USB drive. Older clients skip slot types they do not know. */
  | { id: string; type: 'usb-key'; name: string; salt: string; wrapped: Sealed };

/** A key file used as a second factor after the master password. It cannot unlock anything on its own. */
export interface UsbKeyGate { id: string; name: string; /** SHA-256 of a domain tag and the file's secret, base64 */ check: string; added: number }

/** Encrypted vault metadata (integrity-protected settings and the entry index). */
export interface VaultMeta {
  environments: string[];
  activeEnv: string;
  /** program id → env var names it may read */
  grants: Record<string, string[]>;
  /** id → version: detects entries added/removed/rolled back outside PEVV */
  index: Record<string, number>;
  /** the authoritative copy of which second factors are required */
  require: { totp: boolean; passkey: boolean; usbKey?: boolean };
  /** Key files that count as the second factor. Sealed with the rest of meta. */
  usbKeys?: UsbKeyGate[];
  totpLastStep: number | null;
  /** How often the authenticator is asked for: every login (default, absent), daily, weekly, monthly or only on a new device. */
  secondFactorRecheck?: 'login' | 'daily' | 'weekly' | 'monthly' | 'new-device' | undefined;
  /** Bumped on a password change, a revoked device or a replaced authenticator; remembered verifications from before stop counting. */
  trustEpoch?: number | undefined;
  /** user folders (names) */
  folders: string[];
  /** program id (e.g. `project:<id>`) → environment it runs with (overrides the active one) */
  projectEnv: Record<string, string>;
  /** Phones, tablets and computers that have unlocked this vault. Sealed with the rest of meta. */
  devices: VaultDevice[];
  /** Device ids removed by the owner. Those copies wipe themselves on the next unlock. */
  revokedDevices: string[];
  /** Device id that wrote this revision (optional; lets other devices reject a write from a revoked one). */
  lastWriter?: string | undefined;
}

export type DeviceKind = 'desktop' | 'phone' | 'tablet' | 'unknown';

export interface VaultDevice {
  id: string;
  name: string;
  kind: DeviceKind;
  added: number;
  seen: number;
  /** Short browser/OS label. Not a hardware serial. */
  agent: string;
}

export interface VaultFile {
  format: typeof VAULT_FORMAT;
  /** 1 = original. 2 = the vault key was rotated at least once (older clients refuse it instead of corrupting it). */
  v: 1 | 2;
  id: string;
  created: number;
  updated: number;
  /** Monotonic revision, bumped on every write (sync uses last-writer-wins on rev). */
  rev: number;
  /** Number of key rotations (absent = 0). Required and >= 1 when `v` is 2. */
  keyEpoch?: number | undefined;
  kdf: KdfParams;
  slots: Slot[];
  passkeys: PasskeyRecord[];
  /** Plaintext hint of required factors (the sealed meta is authoritative). */
  require: { totp: boolean; passkey: boolean; usbKey?: boolean };
  totp: Sealed | null;
  meta: Sealed;
  entries: EntryRecord[];
}

export function newId(): string {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export function emptyEntry(type: EntryType, now = Date.now()): EntryData {
  return { type, title: '', tags: [], favorite: false, created: now, updated: now, history: [] };
}

export const HISTORY_FIELDS = ['password', 'value', 'key', 'totp', 'username', 'number', 'cvv', 'pin', 'privateKey', 'passphrase'] as const;
export const HISTORY_MAX = 20;

/** Merge an edit, recording previous secret values in the entry's (encrypted) history. */
export function applyEdit(prev: EntryData, next: Partial<EntryData>, now = Date.now()): EntryData {
  const history = [...prev.history];
  for (const f of HISTORY_FIELDS) {
    if (f in next && next[f] !== prev[f] && prev[f]) history.unshift({ at: now, field: f, value: String(prev[f]) });
  }
  return { ...prev, ...next, updated: now, history: history.slice(0, HISTORY_MAX) };
}

/** Groups of entries sharing the same secret (logins + API keys). */
export function reuseGroups(entries: Entry[]): Map<string, string[]> {
  const by = new Map<string, string[]>();
  for (const e of entries) {
    const secret = e.type === 'login' ? e.password : e.type === 'apikey' ? e.key : undefined;
    if (!secret) continue;
    const list = by.get(secret) ?? [];
    list.push(e.id);
    by.set(secret, list);
  }
  const out = new Map<string, string[]>();
  for (const ids of by.values()) if (ids.length > 1) for (const id of ids) out.set(id, ids);
  return out;
}

/* ───────────── .env ───────────── */

export const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function parseDotenv(src: string): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  const lines = src.replace(/\r\n?/g, '\n').split('\n');
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]!.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('export ')) line = line.slice(7).trim();
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const name = line.slice(0, eq).trim();
    if (!ENV_NAME.test(name)) continue;
    let value = line.slice(eq + 1).trim();
    if (value.startsWith('"')) {
      // Double-quoted: may span lines; supports \n \t \" \\ escapes.
      let buf = value.slice(1);
      let close = closingQuote(buf);
      while (close < 0 && i + 1 < lines.length) {
        buf += '\n' + lines[++i]!;
        close = closingQuote(buf);
      }
      const raw = close < 0 ? buf : buf.slice(0, close);
      value = raw.replace(/\\(.)/g, (_, c: string) => (c === 'n' ? '\n' : c === 't' ? '\t' : c === 'r' ? '\r' : c));
    } else if (value.startsWith("'")) {
      const end = value.indexOf("'", 1);
      value = end > 0 ? value.slice(1, end) : value.slice(1);
    } else {
      const hash = value.search(/\s#/);
      if (hash >= 0) value = value.slice(0, hash).trim();
    }
    out.push({ name, value });
  }
  return out;
}

function closingQuote(s: string): number {
  for (let k = 0; k < s.length; k++) {
    if (s[k] === '\\') { k++; continue; }
    if (s[k] === '"') return k;
  }
  return -1;
}

export function serializeDotenv(vars: { name: string; value: string }[]): string {
  return vars
    .filter((v) => ENV_NAME.test(v.name))
    .map((v) => {
      const plain = /^[A-Za-z0-9_./:@+-]*$/.test(v.value);
      const val = plain ? v.value : `"${v.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`;
      return `${v.name}=${val}`;
    })
    .join('\n') + '\n';
}

/* ───────────── terminal $VAR expansion ───────────── */

/** Expand $NAME and ${NAME} from `vars`; `\$` escapes; unknown names stay literal. Returns used names. */
export function expandVars(line: string, vars: Record<string, string>): { text: string; used: string[]; missing: string[] } {
  const used: string[] = [];
  const missing: string[] = [];
  const text = line.replace(/\\\$|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, a?: string, b?: string) => {
    if (m === '\\$') return '$';
    const name = (a ?? b)!;
    if (Object.prototype.hasOwnProperty.call(vars, name)) {
      used.push(name);
      return vars[name]!;
    }
    missing.push(name);
    return m;
  });
  return { text, used, missing };
}

/** Static `env.get('NAME')` calls in a hybrid program (names the user must approve). */
export function envNamesInSource(src: string): string[] {
  const out = new Set<string>();
  const re = /\benv\.get\(\s*(['"`])([A-Za-z_][A-Za-z0-9_]*)\1\s*\)/g;
  let m;
  while ((m = re.exec(src))) out.add(m[2]!);
  return [...out].sort();
}

export function usesEnv(src: string): boolean {
  return /\benv\.get\s*\(/.test(src);
}

/* ───────────── autofill matching ───────────── */

/**
 * A login matches a legacy in-app form id only when its `site` is the same origin as the
 * page (scheme + host + port) or the in-app form id `luciverse:<form>`. Never cross-origin.
 */
export function siteMatches(site: string | undefined, formId: string, origin: string): boolean {
  if (!site) return false;
  const s = site.trim();
  const sl = s.toLowerCase();
  const f = `luciverse:${formId}`.toLowerCase();
  // Exact form, the wildcard, or a parent form id (luciverse:notes-note matches formId notes-note:<id>).
  if (sl === f || sl === 'luciverse:*' || (sl.startsWith('luciverse:') && f.startsWith(`${sl}:`))) return true;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
    return u.origin === origin;
  } catch {
    return false;
  }
}

export function entrySecret(e: EntryData): string | undefined {
  switch (e.type) {
    case 'login': return e.password;
    case 'env': return e.value;
    case 'apikey': return e.key;
    case 'card': return e.number;
    case 'ssh': return e.privateKey;
    case 'identity': return e.email ?? e.notes;
    default: return e.notes;
  }
}

export function entrySubtitle(e: EntryData): string {
  if (e.type === 'login') return [e.username, e.site].filter(Boolean).join(' · ');
  if (e.type === 'env') return `${e.env ?? 'default'} · ${e.name ?? ''}`;
  if (e.type === 'apikey') return e.service ?? '';
  if (e.type === 'card') return [e.number ? `•••• ${e.number.replace(/\D/g, '').slice(-4)}` : '', e.expiry].filter(Boolean).join(' · ');
  if (e.type === 'ssh') return (e.publicKey ?? '').trim().split(/\s+/).filter((_, i) => i !== 1).join(' ').slice(0, 60);
  if (e.type === 'identity') return [e.fullName, e.email].filter(Boolean).join(' · ');
  if (e.type === 'passkey') return [e.userName, e.rpId].filter(Boolean).join(' · ');
  return (e.notes ?? '').split('\n')[0]!.slice(0, 60);
}

export function matchesQuery(e: Entry, q: string): boolean {
  const s = q.trim().toLowerCase();
  if (!s) return true;
  return [e.title, e.site, e.username, e.name, e.env, e.service, e.notes, e.folder, e.cardholder, e.fullName, e.email, e.phone, ...e.tags]
    .filter(Boolean)
    .some((v) => String(v).toLowerCase().includes(s));
}
