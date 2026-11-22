/**
 * The PEVV extension's vault engine, run by the service worker.
 *
 * Holds the vault key only as a non-extractable WebCrypto key in memory, never
 * in any storage. The raw key bytes are wiped right after import. Decrypted
 * logins are reduced to a title / site / username index; a password is
 * decrypted only for the one fill that asked for it. Locking drops all of it.
 *
 * No chrome.* calls here: storage, the clock and the limiter are injected so
 * the whole flow runs under unit tests.
 */
import { aad, openJson } from '../crypto';
import { type EntryData, type VaultFile, type VaultMeta, applyEdit, emptyEntry } from '../model';
import { type LimiterState, type TotpConfig, limiterBlocked, limiterRecord, verifyTotp } from '../totp';
import * as V from '../vault';
import { type ExtSettings, type ExtStatus, type LoginRef, type OfferView, type Redeemed, DEFAULT_SETTINGS, clampAutoLock } from './protocol';

export interface CoreDeps {
  readVault(): Promise<VaultFile | null>;
  writeVault(file: VaultFile): Promise<void>;
  loadLimiter(key: string): Promise<LimiterState>;
  saveLimiter(key: string, st: LimiterState): Promise<void>;
  loadNever(): Promise<string[]>;
  saveNever(list: string[]): Promise<void>;
  now?: () => number;
  /** Called whenever the status or the lock deadline changes (badge, alarms, keep-alive). */
  onChange?: (status: ExtStatus, lockAt: number | null) => void;
}

export const TICKET_MS = 30_000;
export const OFFER_MS = 5 * 60_000;

export const PASSKEY_BLOCKED =
  'This vault asks for a passkey or security key after the password. Passkeys made in the PEVV web app do not work inside a browser extension, so it cannot be unlocked here. Link the PEVV desktop app instead: it unlocks with passkeys and security keys itself, and this extension fills from it.';

interface LoginIndex { id: string; title: string; site: string; username: string }

type Ticket =
  | { tabId: number; origin: string; exp: number; kind: 'login'; id: string }
  | { tabId: number; origin: string; exp: number; kind: 'generated'; password: string };

interface Offer { origin: string; username: string; password: string; exp: number }

/**
 * Same rule as the vault page: a login fills only on the exact origin it was
 * saved for (scheme, host and port). In-app `luciverse:` form ids never fill a web page.
 */
export function loginMatchesOrigin(site: string | undefined, origin: string): boolean {
  if (!site) return false;
  const s = site.trim();
  if (!s || /^luciverse:/i.test(s)) return false;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
    return u.origin === origin;
  } catch {
    return false;
  }
}

function sameUser(a: string | undefined, b: string | undefined): boolean {
  return (a ?? '').trim().toLowerCase() === (b ?? '').trim().toLowerCase();
}

export class ExtVault {
  private file: VaultFile | null = null;
  private key: CryptoKey | null = null;
  private meta: VaultMeta | null = null;
  private totp: TotpConfig | null = null;
  private logins: LoginIndex[] = [];
  private tickets = new Map<number, Ticket>();
  private offers = new Map<number, Offer>();
  private queue: Promise<unknown> = Promise.resolve();
  status: ExtStatus = 'none';
  lockAt: number | null = null;
  blocked: string | null = null;
  error: string | null = null;
  settings: ExtSettings = { ...DEFAULT_SETTINGS };

  constructor(private deps: CoreDeps) {}

  private now(): number { return this.deps.now ? this.deps.now() : Date.now(); }

  private emit(): void { this.deps.onChange?.(this.status, this.lockAt); }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private session(): V.Session {
    if (!this.key || !this.file) throw new Error('The vault is locked.');
    // vault.ts only uses `key` to seal. The raw bytes were wiped at unlock.
    return { raw: new Uint8Array(0) as V.Session['raw'], key: this.key };
  }

  /** Load the stored ciphertext. Call once at worker start and after storage changes. */
  async load(): Promise<void> {
    const f = await this.deps.readVault();
    this.file = f;
    if (!f) { this.lock(); return; }
    if (this.status === 'none') { this.status = 'locked'; this.emit(); }
  }

  hasVault(): boolean { return !!this.file; }

  setSettings(s: Partial<ExtSettings>): void {
    this.settings = { ...this.settings, ...s, autoLockMin: clampAutoLock(s.autoLockMin ?? this.settings.autoLockMin) };
    if (this.status === 'unlocked') this.touch();
  }

  /** Push the auto-lock deadline out after real use. */
  touch(): void {
    if (this.status !== 'unlocked') return;
    this.lockAt = this.now() + this.settings.autoLockMin * 60_000;
    this.emit();
  }

  /** Lock if the deadline passed (alarms can fire late; every request checks too). */
  expire(): boolean {
    if ((this.status === 'unlocked' || this.status === 'second-factor') && this.lockAt !== null && this.now() >= this.lockAt) {
      this.lock();
      return true;
    }
    return false;
  }

  lock(): void {
    this.key = null;
    this.meta = null;
    this.totp = null;
    this.logins = [];
    this.tickets.clear();
    this.offers.clear();
    this.lockAt = null;
    this.status = this.file ? 'locked' : 'none';
    this.emit();
  }

  private limiterKey(kind: string): string { return `${kind}:${this.file?.id ?? 'none'}`; }

  private async guard(kind: string): Promise<void> {
    const ms = limiterBlocked(await this.deps.loadLimiter(this.limiterKey(kind)), this.now());
    if (ms > 0) throw new Error(`Too many attempts. Try again in ${Math.ceil(ms / 1000)} s.`);
  }

  private async record(kind: string, ok: boolean): Promise<void> {
    const k = this.limiterKey(kind);
    await this.deps.saveLimiter(k, limiterRecord(await this.deps.loadLimiter(k), ok, this.now()));
  }

  async unlock(password: string): Promise<ExtStatus> {
    return this.serial(async () => {
      this.error = null;
      await this.load();
      const file = this.file;
      if (!file) throw new Error('There is no vault in this browser yet. Open the vault screen to add one.');
      if (file.require.passkey) { this.blocked = PASSKEY_BLOCKED; throw new Error(PASSKEY_BLOCKED); }
      await this.guard('pw');
      let s: V.Session;
      try {
        s = await V.unlockWithPassword(file, password);
      } catch (e) {
        if ((e as Error).name === 'DecryptError') await this.record('pw', false);
        throw e;
      }
      await this.record('pw', true);
      const key = s.key;
      V.endSession(s);
      // The sealed meta is authoritative; the plaintext hint can be stripped.
      const meta = await V.readMeta(file, { raw: new Uint8Array(0) as V.Session['raw'], key });
      if (meta.require.passkey) { this.blocked = PASSKEY_BLOCKED; throw new Error(PASSKEY_BLOCKED); }
      this.blocked = null;
      this.key = key;
      this.meta = meta;
      this.lockAt = this.now() + this.settings.autoLockMin * 60_000;
      if (meta.require.totp) {
        if (!file.totp) { this.lock(); throw new Error('The vault requires an authenticator code but its secret is missing.'); }
        this.totp = await openJson<TotpConfig>(key, file.totp, aad.totp(file.id));
        this.status = 'second-factor';
        this.emit();
        return this.status;
      }
      await this.finish();
      return this.status;
    });
  }

  async verifyCode(code: string): Promise<ExtStatus> {
    return this.serial(async () => {
      if (this.status !== 'second-factor' || !this.totp || !this.meta) throw new Error('Not waiting for a code.');
      await this.guard('totp');
      const step = await verifyTotp(this.totp, code, this.now(), 1, this.meta.totpLastStep);
      await this.record('totp', step !== null);
      if (step === null) throw new Error('That code is not valid. Check your authenticator app and the device clock.');
      this.totp = null;
      // Record the used step so the same code cannot unlock twice (same as the vault page).
      await this.write((file, meta) => V.saveMeta(file, this.session(), { ...meta, totpLastStep: step }).then((f) => ({ file: f })));
      await this.finish();
      return this.status;
    });
  }

  private async finish(): Promise<void> {
    await this.reindex();
    this.status = 'unlocked';
    this.touch();
  }

  private async reindex(): Promise<void> {
    const file = this.file;
    if (!file || !this.key) return;
    const d = await V.decryptAll(file, this.session());
    this.meta = d.meta;
    this.logins = d.entries
      .filter((e) => e.type === 'login')
      .map((e) => ({ id: e.id, title: e.title || e.site || 'Login', site: e.site ?? '', username: e.username ?? '' }));
  }

  /**
   * Run a write on the newest stored copy, so an edit made in the vault screen
   * a moment ago is not overwritten.
   */
  private async write(fn: (file: VaultFile, meta: VaultMeta) => Promise<{ file: VaultFile }>): Promise<void> {
    const cur = this.file;
    if (!cur || !this.key) throw new Error('The vault is locked.');
    const latest = (await this.deps.readVault()) ?? cur;
    if (latest.id !== cur.id) { this.file = latest; this.lock(); throw new Error('The vault in this browser changed. Unlock it again.'); }
    const base = latest.rev >= cur.rev ? latest : cur;
    const meta = await V.readMeta(base, this.session());
    const { file } = await fn(base, meta);
    await this.deps.writeVault(file);
    this.file = file;
    this.meta = meta;
  }

  /** The vault screen (or a second worker instance) wrote a new copy. */
  async external(next: VaultFile | null): Promise<void> {
    return this.serial(async () => {
      const cur = this.file;
      if (!next) { this.file = null; this.lock(); return; }
      if (cur && next.id === cur.id && next.rev === cur.rev) return;
      if (cur && next.id === cur.id && next.rev < cur.rev) return;
      this.file = next;
      if (!cur || next.id !== cur.id) { this.lock(); return; }
      if (this.status === 'unlocked') {
        try { await this.reindex(); } catch { this.lock(); }
      } else if (this.status === 'second-factor') {
        this.lock();
      } else {
        this.emit();
      }
    });
  }

  private openLogins(origin: string): LoginIndex[] {
    return this.logins.filter((l) => loginMatchesOrigin(l.site, origin));
  }

  private ref(l: LoginIndex, origin: string | null): LoginRef {
    return { id: l.id, title: l.title, username: l.username, site: l.site, matches: !!origin && loginMatchesOrigin(l.site, origin) };
  }

  matches(origin: string | null): LoginRef[] {
    if (this.status !== 'unlocked' || !origin) return [];
    return this.openLogins(origin).map((l) => this.ref(l, origin));
  }

  search(q: string, origin: string | null): LoginRef[] {
    if (this.status !== 'unlocked') return [];
    const s = q.trim().toLowerCase();
    const list = s ? this.logins.filter((l) => [l.title, l.site, l.username].some((v) => v.toLowerCase().includes(s))) : this.logins;
    return list.slice(0, 50).map((l) => this.ref(l, origin));
  }

  private async decryptLogin(id: string): Promise<{ username: string; password: string }> {
    const file = this.file;
    if (!file || !this.key) throw new Error('The vault is locked.');
    const rec = file.entries.find((e) => e.id === id);
    if (!rec) throw new Error('That login is no longer in the vault.');
    const d = await openJson<EntryData>(this.key, rec.sealed, aad.entry(file.id, rec.id, rec.ver));
    if (d.type !== 'login' || !d.password) throw new Error('That item has no password.');
    return { username: d.username ?? '', password: d.password };
  }

  /** The popup asked to fill a login into a tab. The content script redeems it once. */
  issueFill(tabId: number, origin: string, id: string): void {
    if (this.status !== 'unlocked') throw new Error('The vault is locked.');
    const l = this.logins.find((x) => x.id === id);
    if (!l || !loginMatchesOrigin(l.site, origin)) throw new Error('That login is not saved for this site.');
    this.tickets.set(tabId, { tabId, origin, id, kind: 'login', exp: this.now() + TICKET_MS });
    this.touch();
  }

  issueGenerated(tabId: number, origin: string, password: string): void {
    if (!password) throw new Error('Nothing to fill.');
    this.tickets.set(tabId, { tabId, origin, password, kind: 'generated', exp: this.now() + TICKET_MS });
    this.touch();
  }

  dropTicket(tabId: number): void { this.tickets.delete(tabId); }

  /** Content script in `tabId`, top frame at `origin`, redeems its ticket. One use, 30 s. */
  async redeem(tabId: number, origin: string): Promise<Redeemed> {
    const t = this.tickets.get(tabId);
    this.tickets.delete(tabId);
    if (!t || t.exp < this.now()) throw new Error('Nothing to fill. Choose the login in PEVV again.');
    if (t.origin !== origin) throw new Error('The page changed before the fill.');
    if (t.kind === 'generated') {
      this.offers.set(tabId, { origin, username: '', password: t.password, exp: this.now() + OFFER_MS });
      return { kind: 'generated', password: t.password };
    }
    if (this.status !== 'unlocked') throw new Error('The vault is locked.');
    const c = await this.decryptLogin(t.id);
    this.touch();
    return { kind: 'login', ...c };
  }

  /** Inline button on an approved host: one login by id, only if it is saved for that origin. */
  async fillById(origin: string, id: string): Promise<Redeemed> {
    if (this.status !== 'unlocked') throw new Error('locked');
    const l = this.logins.find((x) => x.id === id);
    if (!l || !loginMatchesOrigin(l.site, origin)) throw new Error('That login is not saved for this site.');
    const c = await this.decryptLogin(id);
    this.touch();
    return { kind: 'login', ...c };
  }

  async offerSave(tabId: number, origin: string, username: string, password: string): Promise<boolean> {
    if (!password) return false;
    if ((await this.deps.loadNever()).includes(origin)) return false;
    if (this.status === 'unlocked') {
      for (const l of this.openLogins(origin)) {
        if (!sameUser(l.username, username)) continue;
        const c = await this.decryptLogin(l.id).catch(() => null);
        if (c && c.password === password) return false;
      }
    }
    const prev = this.offers.get(tabId);
    // A generated password filled a moment ago: keep it and add the username the form sent.
    this.offers.set(tabId, { origin, username: username || (prev?.origin === origin ? prev.username : ''), password, exp: this.now() + OFFER_MS });
    return true;
  }

  offerFor(tabId: number | null): OfferView | null {
    if (tabId === null) return null;
    const o = this.offers.get(tabId);
    if (!o) return null;
    if (o.exp < this.now()) { this.offers.delete(tabId); return null; }
    const existing = this.status === 'unlocked' ? this.openLogins(o.origin).find((l) => sameUser(l.username, o.username)) : undefined;
    let host = o.origin;
    try { host = new URL(o.origin).host; } catch { /* keep origin */ }
    return { origin: o.origin, username: o.username, update: !!existing, title: existing?.title ?? host, locked: this.status !== 'unlocked' };
  }

  hasOffer(tabId: number): boolean { return !!this.offerFor(tabId); }

  async acceptOffer(tabId: number): Promise<void> {
    return this.serial(async () => {
      const o = this.offers.get(tabId);
      if (!o || o.exp < this.now()) throw new Error('That save offer expired.');
      if (this.status !== 'unlocked') throw new Error('Unlock the vault to save this login.');
      const existing = this.openLogins(o.origin).find((l) => sameUser(l.username, o.username));
      const file = this.file!;
      let data: EntryData;
      if (existing) {
        const rec = file.entries.find((e) => e.id === existing.id)!;
        const prev = await openJson<EntryData>(this.key!, rec.sealed, aad.entry(file.id, rec.id, rec.ver));
        data = applyEdit(prev, { password: o.password }, this.now());
      } else {
        let host = o.origin;
        try { host = new URL(o.origin).host; } catch { /* keep */ }
        data = { ...emptyEntry('login', this.now()), title: host, site: o.origin, username: o.username, password: o.password };
      }
      await this.write((f, meta) => V.putEntry(f, this.session(), meta, existing?.id ?? null, data));
      this.offers.delete(tabId);
      await this.reindex();
      this.touch();
    });
  }

  dismissOffer(tabId: number): void { this.offers.delete(tabId); }

  async neverOffer(tabId: number): Promise<void> {
    const o = this.offers.get(tabId);
    this.offers.delete(tabId);
    if (!o) return;
    const list = await this.deps.loadNever();
    if (!list.includes(o.origin)) await this.deps.saveNever([...list, o.origin]);
  }

  forgetTab(tabId: number): void {
    this.tickets.delete(tabId);
  }
}
