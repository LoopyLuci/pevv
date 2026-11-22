import { describe, expect, it } from 'vitest';
import { type KdfParams, PBKDF2_MIN_ITER, aad, openJson } from '@/pevv/crypto';
import { b64, randomBytes } from '@/pevv/bytes';
import { type EntryData, type VaultFile, emptyEntry } from '@/pevv/model';
import { type LimiterState, newTotpSecret, totpAt } from '@/pevv/totp';
import * as V from '@/pevv/vault';
import { ExtVault, OFFER_MS, PASSKEY_BLOCKED, TICKET_MS, loginMatchesOrigin } from '@/pevv/extension/core';

const kdf = (): KdfParams => ({ alg: 'pbkdf2-sha256', iter: PBKDF2_MIN_ITER, salt: b64(randomBytes(16)) });
const PW = 'correct horse battery';

function login(site: string, username: string, password: string, title = site): EntryData {
  return { ...emptyEntry('login', 1), title, site, username, password };
}

async function makeVault(items: EntryData[], opts: { totp?: boolean; passkey?: boolean } = {}) {
  const { file: f0, session } = await V.createVault(PW, kdf());
  let file = f0;
  let meta = await V.readMeta(file, session);
  for (const d of items) ({ file, meta } = await V.putEntry(file, session, meta, null, d));
  let secret: string | null = null;
  if (opts.totp) {
    secret = newTotpSecret();
    ({ file, meta } = await V.setTotp(file, session, meta, { secret }));
  }
  if (opts.passkey) {
    meta = { ...meta, require: { ...meta.require, passkey: true } };
    file = await V.saveMeta(file, session, meta);
  }
  return { file, session, secret };
}

function harness(initial: VaultFile | null, clock = { t: 1_000_000 }) {
  const box = { file: initial, writes: 0 };
  const limits = new Map<string, LimiterState>();
  let never: string[] = [];
  const vault = new ExtVault({
    readVault: async () => box.file,
    writeVault: async (f) => { box.file = f; box.writes++; },
    loadLimiter: async (k) => limits.get(k) ?? { fails: 0, until: 0 },
    saveLimiter: async (k, st) => { limits.set(k, st); },
    loadNever: async () => never,
    saveNever: async (l) => { never = l; },
    now: () => clock.t,
  });
  return { vault, box, clock, limits, never: () => never };
}

async function readEntries(file: VaultFile): Promise<EntryData[]> {
  const s = await V.unlockWithPassword(file, PW);
  return (await V.decryptAll(file, s)).entries;
}

describe('loginMatchesOrigin', () => {
  it('matches only the exact origin a login was saved for', () => {
    expect(loginMatchesOrigin('https://example.com/login', 'https://example.com')).toBe(true);
    expect(loginMatchesOrigin('example.com', 'https://example.com')).toBe(true);
    expect(loginMatchesOrigin('https://example.com', 'http://example.com')).toBe(false);
    expect(loginMatchesOrigin('https://example.com', 'https://evil-example.com')).toBe(false);
    expect(loginMatchesOrigin('https://example.com', 'https://a.example.com')).toBe(false);
    expect(loginMatchesOrigin('https://example.com:8443', 'https://example.com')).toBe(false);
    expect(loginMatchesOrigin('luciverse:*', 'https://example.com')).toBe(false);
    expect(loginMatchesOrigin('', 'https://example.com')).toBe(false);
  });
});

describe('ExtVault', () => {
  it('starts locked, rejects a wrong password and counts the failure', async () => {
    const { file } = await makeVault([login('https://example.com', 'ada', 'pw-1')]);
    const h = harness(file);
    await h.vault.load();
    expect(h.vault.status).toBe('locked');
    await expect(h.vault.unlock('wrong password')).rejects.toThrow(/wrong master password/);
    expect([...h.limits.values()][0]!.fails).toBe(1);
    expect(h.vault.matches('https://example.com')).toEqual([]);
  });

  it('says there is no vault when storage is empty', async () => {
    const h = harness(null);
    await h.vault.load();
    expect(h.vault.status).toBe('none');
    await expect(h.vault.unlock(PW)).rejects.toThrow(/no vault/i);
  });

  it('unlocks, lists only same-origin logins and never exposes passwords to the popup', async () => {
    const { file } = await makeVault([
      login('https://example.com', 'ada', 'pw-1', 'Example'),
      login('https://other.org', 'bob', 'pw-2', 'Other'),
    ]);
    const h = harness(file);
    await h.vault.load();
    expect(await h.vault.unlock(PW)).toBe('unlocked');
    const m = h.vault.matches('https://example.com');
    expect(m.map((x) => x.username)).toEqual(['ada']);
    expect(JSON.stringify(m)).not.toContain('pw-1');
    const all = h.vault.search('', 'https://example.com');
    expect(all).toHaveLength(2);
    expect(all.find((x) => x.username === 'bob')!.matches).toBe(false);
    expect(JSON.stringify(all)).not.toMatch(/pw-1|pw-2/);
  });

  it('fills through a one-time ticket bound to tab and origin', async () => {
    const { file } = await makeVault([login('https://example.com', 'ada', 'pw-1'), login('https://other.org', 'bob', 'pw-2')]);
    const h = harness(file);
    await h.vault.load();
    await h.vault.unlock(PW);
    const [ex] = h.vault.matches('https://example.com');
    const other = h.vault.search('bob', null)[0]!;
    expect(() => h.vault.issueFill(7, 'https://example.com', other.id)).toThrow(/not saved for this site/);

    h.vault.issueFill(7, 'https://example.com', ex!.id);
    await expect(h.vault.redeem(7, 'https://evil.test')).rejects.toThrow(/page changed/);
    // The failed attempt used up the ticket.
    await expect(h.vault.redeem(7, 'https://example.com')).rejects.toThrow(/Nothing to fill/);

    h.vault.issueFill(7, 'https://example.com', ex!.id);
    await expect(h.vault.redeem(8, 'https://example.com')).rejects.toThrow(/Nothing to fill/);
    h.vault.issueFill(7, 'https://example.com', ex!.id);
    expect(await h.vault.redeem(7, 'https://example.com')).toEqual({ kind: 'login', username: 'ada', password: 'pw-1' });
    await expect(h.vault.redeem(7, 'https://example.com')).rejects.toThrow(/Nothing to fill/);

    h.vault.issueFill(7, 'https://example.com', ex!.id);
    h.clock.t += TICKET_MS + 1;
    await expect(h.vault.redeem(7, 'https://example.com')).rejects.toThrow(/Nothing to fill/);
  });

  it('forgets everything on lock and on the auto-lock deadline', async () => {
    const { file } = await makeVault([login('https://example.com', 'ada', 'pw-1')]);
    const h = harness(file);
    h.vault.setSettings({ autoLockMin: 2 });
    await h.vault.load();
    await h.vault.unlock(PW);
    expect(h.vault.lockAt).toBe(h.clock.t + 2 * 60_000);
    const id = h.vault.matches('https://example.com')[0]!.id;
    h.vault.issueFill(1, 'https://example.com', id);
    h.vault.lock();
    expect(h.vault.status).toBe('locked');
    expect(h.vault.matches('https://example.com')).toEqual([]);
    await expect(h.vault.redeem(1, 'https://example.com')).rejects.toThrow();

    await h.vault.unlock(PW);
    h.clock.t += 60_000;
    expect(h.vault.expire()).toBe(false);
    h.vault.touch();
    h.clock.t += 2 * 60_000 - 1;
    expect(h.vault.expire()).toBe(false);
    h.clock.t += 1;
    expect(h.vault.expire()).toBe(true);
    expect(h.vault.status).toBe('locked');
    await expect(h.vault.fillById('https://example.com', id)).rejects.toThrow(/locked/);
  });

  it('clamps auto-lock to 1–60 minutes (no "never")', () => {
    const h = harness(null);
    h.vault.setSettings({ autoLockMin: 0 });
    expect(h.vault.settings.autoLockMin).toBe(1);
    h.vault.setSettings({ autoLockMin: 10_000 });
    expect(h.vault.settings.autoLockMin).toBe(60);
  });

  it('asks for the authenticator code, then records the used step', async () => {
    const { file, secret } = await makeVault([login('https://example.com', 'ada', 'pw-1')], { totp: true });
    const h = harness(file, { t: Date.UTC(2026, 10, 14, 12, 0, 0) });
    await h.vault.load();
    expect(await h.vault.unlock(PW)).toBe('second-factor');
    expect(h.vault.matches('https://example.com')).toEqual([]);
    await expect(h.vault.verifyCode('000000')).rejects.toThrow(/not valid/);
    const code = await totpAt({ secret: secret! }, h.clock.t);
    expect(await h.vault.verifyCode(code)).toBe('unlocked');
    expect(h.box.file!.rev).toBe(file.rev + 1);
    // The same code cannot be used again.
    h.vault.lock();
    await h.vault.unlock(PW);
    await expect(h.vault.verifyCode(code)).rejects.toThrow(/not valid/);
  });

  it('refuses a vault that requires a passkey, before and after decrypting meta', async () => {
    const { file } = await makeVault([], { passkey: true });
    const h = harness(file);
    await h.vault.load();
    await expect(h.vault.unlock(PW)).rejects.toThrow(PASSKEY_BLOCKED);
    expect(h.vault.blocked).toBe(PASSKEY_BLOCKED);
    // Stripping the plaintext hint does not help: the sealed flag still blocks.
    h.box.file = { ...file, require: { totp: false, passkey: false } };
    await h.vault.load();
    await expect(h.vault.unlock(PW)).rejects.toThrow(PASSKEY_BLOCKED);
    expect(h.vault.status).toBe('locked');
  });

  it('offers to save a new login and writes it into the same vault file', async () => {
    const { file } = await makeVault([]);
    const h = harness(file);
    await h.vault.load();
    await h.vault.unlock(PW);
    expect(await h.vault.offerSave(3, 'https://site.test', 'ada', 's3cret!')).toBe(true);
    expect(h.vault.offerFor(3)).toMatchObject({ origin: 'https://site.test', username: 'ada', update: false, locked: false });
    await h.vault.acceptOffer(3);
    expect(h.vault.offerFor(3)).toBeNull();
    expect(h.box.file!.id).toBe(file.id);
    expect(h.box.file!.rev).toBeGreaterThan(file.rev);
    const saved = await readEntries(h.box.file!);
    expect(saved).toHaveLength(1);
    expect(saved[0]).toMatchObject({ type: 'login', site: 'https://site.test', username: 'ada', password: 's3cret!', title: 'site.test' });
    // Same credentials again: nothing to offer.
    expect(await h.vault.offerSave(3, 'https://site.test', 'ada', 's3cret!')).toBe(false);
  });

  it('updates a changed password and keeps the old one in history', async () => {
    const { file } = await makeVault([login('https://site.test', 'ada', 'old-pw')]);
    const h = harness(file);
    await h.vault.load();
    await h.vault.unlock(PW);
    await h.vault.offerSave(3, 'https://site.test', 'ADA', 'new-pw');
    expect(h.vault.offerFor(3)!.update).toBe(true);
    await h.vault.acceptOffer(3);
    const [e] = await readEntries(h.box.file!);
    expect(e!.password).toBe('new-pw');
    expect(e!.history[0]).toMatchObject({ field: 'password', value: 'old-pw' });
  });

  it('keeps an offer made while locked, needs unlock to save, and drops it on lock or expiry', async () => {
    const { file } = await makeVault([]);
    const h = harness(file);
    await h.vault.load();
    await h.vault.offerSave(4, 'https://site.test', 'ada', 'pw');
    expect(h.vault.offerFor(4)!.locked).toBe(true);
    await expect(h.vault.acceptOffer(4)).rejects.toThrow(/Unlock/);
    h.clock.t += OFFER_MS + 1;
    expect(h.vault.offerFor(4)).toBeNull();
    await h.vault.offerSave(4, 'https://site.test', 'ada', 'pw');
    h.vault.lock();
    expect(h.vault.offerFor(4)).toBeNull();
  });

  it('never offers again for a site the user refused', async () => {
    const { file } = await makeVault([]);
    const h = harness(file);
    await h.vault.load();
    await h.vault.offerSave(5, 'https://nope.test', 'ada', 'pw');
    await h.vault.neverOffer(5);
    expect(h.never()).toEqual(['https://nope.test']);
    expect(await h.vault.offerSave(5, 'https://nope.test', 'ada', 'pw')).toBe(false);
  });

  it('turns a filled generated password into a save offer with the username the form sends', async () => {
    const { file } = await makeVault([]);
    const h = harness(file);
    await h.vault.load();
    await h.vault.unlock(PW);
    h.vault.issueGenerated(9, 'https://new.test', 'Gen-Pass-123!');
    expect(await h.vault.redeem(9, 'https://new.test')).toEqual({ kind: 'generated', password: 'Gen-Pass-123!' });
    expect(h.vault.offerFor(9)).toMatchObject({ origin: 'https://new.test', username: '' });
    await h.vault.offerSave(9, 'https://new.test', 'ada@new.test', 'Gen-Pass-123!');
    expect(h.vault.offerFor(9)!.username).toBe('ada@new.test');
  });

  it('follows writes from the vault screen and locks when the vault is replaced or removed', async () => {
    const { file, session } = await makeVault([login('https://example.com', 'ada', 'pw-1')]);
    const h = harness(file);
    await h.vault.load();
    await h.vault.unlock(PW);
    const meta = await V.readMeta(file, session);
    const { file: newer } = await V.putEntry(file, session, meta, null, login('https://example.com', 'eve', 'pw-3'));
    h.box.file = newer;
    await h.vault.external(newer);
    expect(h.vault.matches('https://example.com').map((m) => m.username).sort()).toEqual(['ada', 'eve']);
    // An older copy is ignored.
    await h.vault.external(file);
    expect(h.vault.matches('https://example.com')).toHaveLength(2);

    const { file: other } = await makeVault([]);
    await h.vault.external(other);
    expect(h.vault.status).toBe('locked');
    await h.vault.external(null);
    expect(h.vault.status).toBe('none');
  });

  it('writes on top of the newest stored copy so a vault-screen edit is not lost', async () => {
    const { file, session } = await makeVault([]);
    const h = harness(file);
    await h.vault.load();
    await h.vault.unlock(PW);
    // The vault screen adds an item; the worker has not seen the change event yet.
    const meta = await V.readMeta(file, session);
    h.box.file = (await V.putEntry(file, session, meta, null, { ...emptyEntry('note', 1), title: 'from page', notes: 'x' })).file;
    await h.vault.offerSave(1, 'https://site.test', 'ada', 'pw');
    await h.vault.acceptOffer(1);
    const titles = (await readEntries(h.box.file!)).map((e) => e.title).sort();
    expect(titles).toEqual(['from page', 'site.test']);
    // Every entry is still bound to its vault, id and version.
    for (const r of h.box.file!.entries) {
      await expect(openJson(session.key, r.sealed, aad.entry(h.box.file!.id, r.id, r.ver))).resolves.toBeTruthy();
    }
  });
});
