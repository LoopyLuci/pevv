/**
 * PEVV extras (pure, no I/O): payment-card checks, SSH key inspection, CSV import
 * from other password managers, Watchtower-style health checks and audit events.
 */
import { type Entry, type EntryData, emptyEntry } from './model';
import { strength } from './gen';

/* ───────────── payment cards ───────────── */

export function cardDigits(n: string | undefined): string {
  return (n ?? '').replace(/\D/g, '');
}

/** Luhn checksum (ISO/IEC 7812). */
export function luhnValid(n: string | undefined): boolean {
  const d = cardDigits(n);
  if (d.length < 12 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let x = d.charCodeAt(d.length - 1 - i) - 48;
    if (i % 2 === 1) { x *= 2; if (x > 9) x -= 9; }
    sum += x;
  }
  return sum % 10 === 0;
}

export type CardBrand = 'visa' | 'mastercard' | 'amex' | 'discover' | 'diners' | 'jcb' | 'unionpay' | 'maestro' | 'unknown';

export function cardBrand(n: string | undefined): CardBrand {
  const d = cardDigits(n);
  if (/^4/.test(d)) return 'visa';
  if (/^(5[1-5]|2(2[2-9][1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720))/.test(d)) return 'mastercard';
  if (/^3[47]/.test(d)) return 'amex';
  if (/^(6011|65|64[4-9]|622)/.test(d)) return 'discover';
  if (/^3(0[0-5]|[689])/.test(d)) return 'diners';
  if (/^35(2[89]|[3-8])/.test(d)) return 'jcb';
  if (/^62/.test(d)) return 'unionpay';
  if (/^(50|5[6-9]|6)/.test(d)) return 'maestro';
  return 'unknown';
}

export const BRAND_LABEL: Record<CardBrand, string> = {
  visa: 'Visa', mastercard: 'Mastercard', amex: 'American Express', discover: 'Discover', diners: 'Diners Club', jcb: 'JCB', unionpay: 'UnionPay', maestro: 'Maestro', unknown: 'Card',
};

/** Group digits like the card face: Amex 4-6-5, others 4-4-4-4(-3). */
export function formatCardNumber(n: string | undefined): string {
  const d = cardDigits(n);
  if (cardBrand(d) === 'amex') return [d.slice(0, 4), d.slice(4, 10), d.slice(10, 15)].filter(Boolean).join(' ');
  return d.replace(/(.{4})/g, '$1 ').trim();
}

export function cvvValid(cvv: string | undefined, n: string | undefined): boolean {
  if (!cvv) return true;
  return cardBrand(n) === 'amex' ? /^\d{4}$/.test(cvv) : /^\d{3}$/.test(cvv);
}

/** Normalise "1/27", "01/2027", "0127" → "01/27"; null when unparseable. */
export function normExpiry(raw: string | undefined): string | null {
  const s = (raw ?? '').trim();
  const m = /^(\d{1,2})\s*[/\-. ]?\s*(\d{2}|\d{4})$/.exec(s);
  if (!m) return null;
  const mm = Number(m[1]);
  if (mm < 1 || mm > 12) return null;
  const yy = m[2]!.length === 4 ? m[2]!.slice(2) : m[2]!;
  return `${String(mm).padStart(2, '0')}/${yy}`;
}

export type ExpiryState = 'ok' | 'soon' | 'expired' | 'invalid' | 'none';

/** A card is valid through the last day of its expiry month. "soon" = within `soonDays`. */
export function expiryState(raw: string | undefined, now = Date.now(), soonDays = 60): ExpiryState {
  if (!raw?.trim()) return 'none';
  const n = normExpiry(raw);
  if (!n) return 'invalid';
  const [mm, yy] = n.split('/').map(Number) as [number, number];
  const end = new Date(2000 + yy, mm, 1).getTime(); // first instant of the following month (local)
  if (now >= end) return 'expired';
  if (end - now <= soonDays * 86_400_000) return 'soon';
  return 'ok';
}

/* ───────────── SSH keys ───────────── */

export interface SshPublicInfo { type: string; bits?: number; comment: string; blob: Uint8Array }

function b64decode(s: string): Uint8Array | null {
  try {
    const bin = atob(s.replace(/\s+/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function readStr(b: Uint8Array, off: number): { v: Uint8Array; next: number } | null {
  if (off + 4 > b.length) return null;
  const len = ((b[off]! << 24) | (b[off + 1]! << 16) | (b[off + 2]! << 8) | b[off + 3]!) >>> 0;
  if (off + 4 + len > b.length) return null;
  return { v: b.subarray(off + 4, off + 4 + len), next: off + 4 + len };
}

const ascii = (u: Uint8Array) => String.fromCharCode(...u);

/** Parse an OpenSSH public key line ("ssh-ed25519 AAAA… comment"). */
export function parseSshPublic(line: string | undefined): SshPublicInfo | null {
  const parts = (line ?? '').trim().split(/\s+/);
  if (parts.length < 2) return null;
  const blob = b64decode(parts[1]!);
  if (!blob) return null;
  const t = readStr(blob, 0);
  if (!t || ascii(t.v) !== parts[0]) return null;
  let bits: number | undefined;
  if (parts[0] === 'ssh-rsa') {
    const e = readStr(blob, t.next);
    const n = e && readStr(blob, e.next);
    if (n) { let v = n.v; while (v.length && v[0] === 0) v = v.subarray(1); bits = v.length * 8; }
  } else if (parts[0] === 'ssh-ed25519' || parts[0]!.startsWith('sk-ssh-ed25519')) bits = 256;
  else { const m = /nistp(\d+)/.exec(parts[0]!); if (m) bits = Number(m[1]); }
  return { type: parts[0]!, ...(bits ? { bits } : {}), comment: parts.slice(2).join(' '), blob };
}

/** OpenSSH-style fingerprint: "SHA256:" + unpadded base64 of SHA-256(blob). */
export async function sshFingerprint(line: string | undefined): Promise<string | null> {
  const info = parseSshPublic(line);
  if (!info) return null;
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', info.blob as BufferSource));
  return 'SHA256:' + btoa(String.fromCharCode(...h)).replace(/=+$/, '');
}

export interface SshPrivateInfo { format: 'openssh' | 'pem-rsa' | 'pem-ec' | 'pkcs8' | 'putty' | 'unknown'; encrypted: boolean; cipher?: string; keyType?: string }

/** Inspect a private key without decrypting it (format, whether it is passphrase-protected). */
export function inspectSshPrivate(text: string | undefined): SshPrivateInfo | null {
  const s = (text ?? '').trim();
  if (!s) return null;
  if (/^PuTTY-User-Key-File-\d+:/m.test(s)) {
    const enc = /^Encryption:\s*(\S+)/m.exec(s)?.[1] ?? 'none';
    return { format: 'putty', encrypted: enc !== 'none', ...(enc !== 'none' ? { cipher: enc } : {}), keyType: /^PuTTY-User-Key-File-\d+:\s*(\S+)/m.exec(s)?.[1] ?? '' };
  }
  const m = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(s);
  if (!m) return { format: 'unknown', encrypted: false };
  const label = m[1]!;
  const body = m[2]!;
  if (label === 'OPENSSH PRIVATE KEY') {
    const b = b64decode(body);
    const magic = 'openssh-key-v1\0';
    if (!b || ascii(b.subarray(0, magic.length)) !== magic) return { format: 'openssh', encrypted: false };
    const c = readStr(b, magic.length);
    const kdf = c && readStr(b, c.next);
    const opts = kdf && readStr(b, kdf.next);
    let keyType: string | undefined;
    if (opts && opts.next + 4 <= b.length) {
      const pub = readStr(b, opts.next + 4);
      const ty = pub && readStr(pub.v, 0);
      if (ty) keyType = ascii(ty.v);
    }
    const cipher = c ? ascii(c.v) : 'none';
    return { format: 'openssh', encrypted: cipher !== 'none', ...(cipher !== 'none' ? { cipher } : {}), ...(keyType ? { keyType } : {}) };
  }
  const procEnc = /Proc-Type:\s*4,ENCRYPTED/.test(body);
  if (label === 'RSA PRIVATE KEY') return { format: 'pem-rsa', encrypted: procEnc, keyType: 'ssh-rsa' };
  if (label === 'EC PRIVATE KEY') return { format: 'pem-ec', encrypted: procEnc, keyType: 'ecdsa' };
  if (label === 'ENCRYPTED PRIVATE KEY') return { format: 'pkcs8', encrypted: true };
  if (label === 'PRIVATE KEY') return { format: 'pkcs8', encrypted: false };
  return { format: 'unknown', encrypted: procEnc };
}

/* ───────────── CSV import (Bitwarden, 1Password, Chrome/Edge, Firefox, Safari, generic) ───────────── */

/** RFC 4180 CSV parser (quoted fields, "" escapes, CRLF, embedded newlines). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let q = false;
  const s = text.replace(/^\uFEFF/, '');
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (q) {
      if (c === '"') { if (s[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c;
    } else if (c === '"' && field === '') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && s[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else field += c;
  }
  if (field !== '' || row.length) { row.push(field); if (row.length > 1 || row[0] !== '') rows.push(row); }
  return rows;
}

export type CsvSource = 'bitwarden' | '1password' | 'chrome' | 'firefox' | 'safari' | 'lastpass' | 'proton' | 'keepass' | 'dashlane' | 'nordpass' | 'generic';

export interface CsvImport { source: CsvSource; entries: EntryData[]; skipped: number }

const truthy = (v: string | undefined) => /^(1|true|yes|y)$/i.test((v ?? '').trim());

/** Map a password-manager CSV export to PEVV entries. Unknown columns go to notes. */
export function importCsv(text: string, now = Date.now()): CsvImport {
  const rows = parseCsv(text);
  if (rows.length < 2) return { source: 'generic', entries: [], skipped: 0 };
  const head = rows[0]!.map((h) => h.trim().toLowerCase());
  const col = (...names: string[]) => { for (const n of names) { const i = head.indexOf(n); if (i >= 0) return i; } return -1; };
  const has = (...names: string[]) => names.every((n) => head.includes(n));
  const source: CsvSource =
    has('login_uri', 'login_username') ? 'bitwarden'
      : has('title', 'url', 'username', 'password') && (head.includes('otpauth') || head.includes('archived') || head.includes('tags')) ? '1password'
        : has('type', 'name', 'url', 'email', 'username', 'password') ? 'proton'
          : has('url', 'username', 'password', 'extra', 'grouping') ? 'lastpass'
            : has('url', 'username', 'password', 'httprealm') ? 'firefox'
              : has('title', 'url', 'username', 'password', 'otpauth') ? 'safari'
                : has('group', 'title', 'username', 'password', 'url') ? 'keepass'
                  : has('title', 'password', 'url') && (head.includes('otpsecret') || head.includes('username2')) ? 'dashlane'
                    : head.includes('cardholdername') && has('name', 'url', 'username', 'password') ? 'nordpass'
                      : has('name', 'url', 'username', 'password') ? 'chrome'
                        : 'generic';
  const iTitle = col('name', 'title');
  const iUrl = col('login_uri', 'url', 'website', 'uri', 'origin');
  const iUser = col('login_username', 'username', 'user', 'login');
  const iEmail = col('email', 'itememail');
  const iPass = col('login_password', 'password', 'pass');
  const iTotp = col('login_totp', 'otpauth', 'totp', 'otp', 'otpsecret');
  const iNotes = col('notes', 'note', 'extra', 'comments');
  const iFolder = col('folder', 'grouping', 'group', 'vault');
  const iFav = col('favorite', 'fav');
  const iTags = col('tags');
  const iType = col('type');
  const iArch = col('archived');
  const iCard = col('cardnumber', 'number');
  const iCvv = col('cvc', 'cvv', 'verificationnumber');
  const iExp = col('expirydate', 'expiry', 'expirationdate');
  const iHolder = col('cardholdername', 'cardholder');
  const known = new Set([iTitle, iUrl, iUser, iEmail, iPass, iTotp, iNotes, iFolder, iFav, iTags, iType, iArch, iCard, iCvv, iExp, iHolder, col('reprompt'), col('fields'), col('httprealm'), col('formactionorigin'), col('guid'), col('timecreated'), col('timelastused'), col('timepasswordchanged'), col('createtime'), col('modifytime'), col('username2'), col('username3'), col('category')].filter((i) => i >= 0));
  const entries: EntryData[] = [];
  let skipped = 0;
  for (const r of rows.slice(1)) {
    const g = (i: number) => (i >= 0 ? (r[i] ?? '').trim() : '');
    const kind = g(iType).toLowerCase();
    const pass = iPass >= 0 ? (r[iPass] ?? '') : '';
    const user = g(iUser) || g(iEmail);
    const cardNumber = g(iCard).replace(/\s+/g, '');
    if (cardNumber) {
      const e = emptyEntry('card', now);
      e.title = (g(iTitle) || 'Card').slice(0, 120);
      e.number = cardNumber;
      if (g(iHolder)) e.cardholder = g(iHolder);
      if (g(iCvv)) e.cvv = g(iCvv);
      const exp = g(iExp);
      const expiry = /^\d{4}$/.test(exp) ? `${exp.slice(0, 2)}/${exp.slice(2)}` : exp;
      if (expiry) e.expiry = expiry;
      if (g(iFolder) && g(iFolder) !== '(none)') e.folder = g(iFolder).slice(0, 40);
      e.tags = ['imported'];
      entries.push(e);
      if (!pass && !user) continue;
    }
    const isNote = kind === 'note' || kind === 'securenote' || (!pass && !user && !g(iUrl) && !!g(iNotes));
    if (!pass && !user && !g(iUrl) && !g(iNotes) && !g(iTitle)) { skipped++; continue; }
    if (kind && !['login', 'alias', 'note', 'securenote', ''].includes(kind)) { skipped++; continue; }
    const e = emptyEntry(isNote ? 'note' : 'login', now);
    let host = '';
    try { host = g(iUrl) ? new URL(/^[a-z][a-z0-9+.-]*:/i.test(g(iUrl)) ? g(iUrl) : `https://${g(iUrl)}`).hostname : ''; } catch { host = ''; }
    e.title = (g(iTitle) || host || user || 'Imported').slice(0, 120);
    if (!isNote) {
      if (g(iUrl)) e.site = g(iUrl);
      if (user) e.username = user;
      if (pass) e.password = pass;
      if (g(iTotp)) e.totp = g(iTotp);
    }
    const emailNote = g(iEmail) && g(iEmail) !== user ? `Email: ${g(iEmail)}` : '';
    const extra = r.map((v, i) => (!known.has(i) && v.trim() ? `${rows[0]![i]}: ${v.trim()}` : '')).filter(Boolean);
    const notes = [iNotes >= 0 ? (r[iNotes] ?? '') : '', emailNote, ...extra].filter((x) => x.trim()).join('\n');
    if (notes) e.notes = notes;
    if (g(iFolder) && g(iFolder) !== '(none)') e.folder = g(iFolder).slice(0, 40);
    if (truthy(g(iFav))) e.favorite = true;
    const tags = g(iTags).split(/[;,]/).map((x) => x.trim()).filter(Boolean);
    if (truthy(g(iArch))) tags.push('archived');
    e.tags = [...new Set(['imported', ...tags])].slice(0, 20);
    entries.push(e);
  }
  return { source, entries, skipped };
}

function rec(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null;
}
function str(v: unknown): string {
  return typeof v === 'string' ? v.trim() : '';
}

/** Proton Pass unencrypted JSON (the file from Settings → Export → JSON). Encrypted PGP exports are refused. */
export function importProtonJson(text: string, now = Date.now()): CsvImport | null {
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return null; }
  const root = rec(parsed);
  const vaults = rec(root?.vaults);
  if (!vaults) return null;
  const entries: EntryData[] = [];
  let skipped = 0;
  for (const vault of Object.values(vaults)) {
    const v = rec(vault);
    if (!v) continue;
    const folder = str(v.name).slice(0, 40);
    const items = Array.isArray(v.items) ? v.items : [];
    for (const item of items) {
      const data = rec(rec(item)?.data);
      if (!data) { skipped++; continue; }
      const meta = rec(data.metadata);
      const content = rec(data.content) ?? {};
      const type = str(data.type);
      const title = (str(meta?.name) || 'Imported').slice(0, 120);
      const note = str(meta?.note);
      if (type === 'login' || type === 'alias') {
        const e = emptyEntry('login', now);
        e.title = title;
        const urls = Array.isArray(content.urls) ? content.urls.map(str).filter(Boolean) : [];
        if (urls[0]) e.site = urls[0];
        const user = str(content.itemUsername) || str(content.itemEmail);
        if (user) e.username = user;
        if (str(content.password)) e.password = str(content.password);
        if (str(content.totpUri)) e.totp = str(content.totpUri);
        const bits = [note, str(content.itemEmail) && str(content.itemEmail) !== user ? `Email: ${str(content.itemEmail)}` : '', urls.slice(1).join('\n')].filter(Boolean);
        if (bits.length) e.notes = bits.join('\n');
        if (folder) e.folder = folder;
        e.tags = ['imported'];
        if (!e.password && !e.username && !e.site && !e.notes) { skipped++; continue; }
        entries.push(e);
      } else if (type === 'note') {
        const e = emptyEntry('note', now);
        e.title = title;
        if (note) e.notes = note;
        if (folder) e.folder = folder;
        e.tags = ['imported'];
        entries.push(e);
      } else if (type === 'creditCard') {
        const e = emptyEntry('card', now);
        e.title = title;
        e.cardholder = str(content.cardholderName);
        e.number = str(content.number).replace(/\s+/g, '');
        e.cvv = str(content.verificationNumber);
        const exp = str(content.expirationDate);
        e.expiry = /^\d{4}$/.test(exp) ? `${exp.slice(0, 2)}/${exp.slice(2)}` : exp;
        if (str(content.pin)) e.pin = str(content.pin);
        if (note) e.notes = note;
        if (folder) e.folder = folder;
        e.tags = ['imported'];
        if (!e.number && !e.cardholder) { skipped++; continue; }
        entries.push(e);
      } else skipped++;
    }
  }
  return { source: 'proton', entries, skipped };
}

/** Bitwarden unencrypted JSON (.json export, not the encrypted one). */
export function importBitwardenJson(text: string, now = Date.now()): CsvImport | null {
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return null; }
  const root = rec(parsed);
  if (!root || !Array.isArray(root.items)) return null;
  const folders = new Map<string, string>();
  if (Array.isArray(root.folders)) {
    for (const f of root.folders) {
      const fr = rec(f);
      if (fr && str(fr.id)) folders.set(str(fr.id), str(fr.name).slice(0, 40));
    }
  }
  const entries: EntryData[] = [];
  let skipped = 0;
  for (const item of root.items) {
    const it = rec(item);
    if (!it) { skipped++; continue; }
    const type = typeof it.type === 'number' ? it.type : -1;
    const title = (str(it.name) || 'Imported').slice(0, 120);
    const note = str(it.notes);
    const folder = folders.get(str(it.folderId)) || '';
    if (type === 1) {
      const login = rec(it.login) ?? {};
      const e = emptyEntry('login', now);
      e.title = title;
      const uris = Array.isArray(login.uris) ? login.uris : [];
      const uri = str(rec(uris[0])?.uri);
      if (uri) e.site = uri;
      if (str(login.username)) e.username = str(login.username);
      if (str(login.password)) e.password = str(login.password);
      if (str(login.totp)) e.totp = str(login.totp);
      if (note) e.notes = note;
      if (folder) e.folder = folder;
      e.tags = ['imported'];
      entries.push(e);
    } else if (type === 2) {
      const e = emptyEntry('note', now);
      e.title = title;
      if (note) e.notes = note;
      if (folder) e.folder = folder;
      e.tags = ['imported'];
      entries.push(e);
    } else if (type === 3) {
      const card = rec(it.card) ?? {};
      const e = emptyEntry('card', now);
      e.title = title;
      e.cardholder = str(card.cardholderName);
      e.number = str(card.number).replace(/\s+/g, '');
      e.cvv = str(card.code);
      const month = str(card.expMonth);
      const year = str(card.expYear);
      if (month && year) e.expiry = `${month.padStart(2, '0')}/${year.slice(-2)}`;
      if (note) e.notes = note;
      if (folder) e.folder = folder;
      e.tags = ['imported'];
      if (!e.number && !e.cardholder) { skipped++; continue; }
      entries.push(e);
    } else skipped++;
  }
  return { source: 'bitwarden', entries, skipped };
}

/** CSV or an unencrypted Proton Pass / Bitwarden JSON export. */
export function importManagerExport(text: string, now = Date.now()): CsvImport {
  const t = text.replace(/^\uFEFF/, '').trim();
  if (t.startsWith('-----BEGIN PGP')) throw new Error('This Proton Pass export is still encrypted. Export an unencrypted JSON or CSV, import it, then delete the file.');
  if (t.startsWith('{')) {
    const proton = importProtonJson(t, now);
    if (proton && (proton.entries.length || proton.skipped)) return proton;
    const bw = importBitwardenJson(t, now);
    if (bw && (bw.entries.length || bw.skipped)) return bw;
    throw new Error('That JSON is not an unencrypted Proton Pass or Bitwarden export.');
  }
  return importCsv(t, now);
}

/* ───────────── Watchtower ───────────── */

export function insecureSite(site: string | undefined): boolean {
  const s = (site ?? '').trim().toLowerCase();
  if (!s.startsWith('http://')) return false;
  try {
    const h = new URL(s).hostname;
    return !(h === 'localhost' || h.endsWith('.localhost') || h === '127.0.0.1' || h === '[::1]');
  } catch {
    return true;
  }
}

function siteKey(site: string | undefined): string {
  const s = (site ?? '').trim();
  if (!s) return '';
  try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`).hostname.replace(/^www\./, '').toLowerCase(); } catch { return s.toLowerCase(); }
}

export interface Watchtower {
  weak: Entry[]; common: Entry[]; reused: Entry[]; old: Entry[]; insecure: Entry[]; duplicates: Entry[];
  no2fa: Entry[]; cardsExpired: Entry[]; cardsSoon: Entry[]; cardsInvalid: Entry[]; sshUnprotected: Entry[];
  score: number;
}

/**
 * Local-only health report (no network: no breach lookups leave the device).
 * `score` is 0–100: the share of secret-bearing items with no finding.
 */
export function watchtower(entries: Entry[], reuse: Map<string, string[]>, now = Date.now()): Watchtower {
  const logins = entries.filter((e) => e.type === 'login' && e.password);
  const weak = logins.filter((e) => strength(e.password!).score <= 1);
  const common = logins.filter((e) => strength(e.password!).common);
  const old = logins.filter((e) => now - e.updated > 365 * 86_400_000);
  const reused = entries.filter((e) => reuse.has(e.id));
  const insecure = entries.filter((e) => e.type === 'login' && insecureSite(e.site));
  const seen = new Map<string, Entry[]>();
  for (const e of entries) {
    if (e.type !== 'login' || !e.username || !siteKey(e.site)) continue;
    const k = `${siteKey(e.site)}\u0000${e.username.toLowerCase()}`;
    seen.set(k, [...(seen.get(k) ?? []), e]);
  }
  const duplicates = [...seen.values()].filter((l) => l.length > 1).flat();
  const no2fa = logins.filter((e) => !e.totp && /^https?:\/\//i.test(e.site ?? ''));
  const cards = entries.filter((e) => e.type === 'card');
  const cardsExpired = cards.filter((e) => expiryState(e.expiry, now) === 'expired');
  const cardsSoon = cards.filter((e) => expiryState(e.expiry, now) === 'soon');
  const cardsInvalid = cards.filter((e) => (e.number && !luhnValid(e.number)) || expiryState(e.expiry, now) === 'invalid');
  const sshUnprotected = entries.filter((e) => e.type === 'ssh' && e.privateKey && inspectSshPrivate(e.privateKey)?.encrypted === false && !e.passphrase);
  const flagged = new Set([...weak, ...common, ...reused, ...insecure, ...duplicates, ...cardsExpired, ...cardsInvalid, ...sshUnprotected].map((e) => e.id));
  const pool = entries.filter((e) => ['login', 'apikey', 'card', 'ssh'].includes(e.type));
  const score = pool.length ? Math.round((100 * pool.filter((e) => !flagged.has(e.id)).length) / pool.length) : 100;
  return { weak, common, reused, old, insecure, duplicates, no2fa, cardsExpired, cardsSoon, cardsInvalid, sshUnprotected, score };
}

/* ───────────── audit log ───────────── */

export const AUDIT_EVENTS = [
  'unlock', 'unlock-passkey', 'unlock-usb-key', 'unlock-recovery', 'lock', 'create', 'edit', 'delete', 'restore', 'reveal', 'copy', 'export', 'import', 'export-env', 'import-env',
  'password-change', 'passkey-add', 'passkey-remove', 'passkey-rename', 'totp-on', 'totp-off', 'grant', 'revoke', 'env-link', 'recovery-new', 'folder',
  'device-rename', 'device-revoke', 'usb-key-add', 'usb-key-remove',
  'autotype', 'cli-run', 'cli-env', 'passkey-provider',
] as const;
export type AuditEvent = (typeof AUDIT_EVENTS)[number];
export interface AuditRecord { at: number; ev: AuditEvent; item?: string; detail?: string }
export const AUDIT_MAX = 500;

export function appendAudit(log: AuditRecord[], rec: AuditRecord): AuditRecord[] {
  const next = [rec, ...log];
  return next.length > AUDIT_MAX ? next.slice(0, AUDIT_MAX) : next;
}

/** CSV of the audit log (titles only — never secrets). */
export function auditCsv(log: AuditRecord[], titleOf: (id: string) => string): string {
  const esc = (v: string) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  return ['time,event,item,detail', ...log.map((r) => [new Date(r.at).toISOString(), r.ev, r.item ? titleOf(r.item) : '', r.detail ?? ''].map(esc).join(','))].join('\n') + '\n';
}
