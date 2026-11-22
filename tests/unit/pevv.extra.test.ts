/** PEVV M3: cards, SSH keys, CSV import, Watchtower, audit log, folders, per-project environments. */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ARGON2_MIN } from '@/pevv/crypto';
import * as S from '@/pevv/store';
import { emptyEntry, type Entry } from '@/pevv/model';
import {
  appendAudit, auditCsv, cardBrand, cvvValid, expiryState, formatCardNumber, importCsv, insecureSite, inspectSshPrivate, luhnValid, normExpiry, parseCsv,
  parseSshPublic, sshFingerprint, watchtower, AUDIT_MAX,
} from '@/pevv/extra';

const fast = async () => ({ alg: 'argon2id' as const, ...ARGON2_MIN, salt: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))) });

const PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP46tYxlrBWCZDJQacoME/H5NohYKwbdLAlPDnHVBYWN dev@example';
const PUB_FP = 'SHA256:7DbdjQV1+wbM+oNoBKub8UoHwtlWq9cZeiGz+HFV95k'; // from `ssh-keygen -lf`

/** Build an openssh-key-v1 container header (no real key material) with the given cipher. */
function fakeOpenssh(cipher: string): string {
  const enc = new TextEncoder();
  const str = (b: Uint8Array) => { const o = new Uint8Array(4 + b.length); new DataView(o.buffer).setUint32(0, b.length); o.set(b, 4); return o; };
  const pubBlob = Uint8Array.from(atob(PUB.split(' ')[1]!), (c) => c.charCodeAt(0));
  const parts = [enc.encode('openssh-key-v1\0'), str(enc.encode(cipher)), str(enc.encode(cipher === 'none' ? 'none' : 'bcrypt')), str(new Uint8Array(0)), new Uint8Array([0, 0, 0, 1]), str(pubBlob), str(new Uint8Array(8))];
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { all.set(p, o); o += p.length; }
  const b64 = btoa(String.fromCharCode(...all)).replace(/(.{70})/g, '$1\n');
  const tag = ['OPENSSH', 'PRIVATE', 'KEY'].join(' ');
  return `-----BEGIN ${tag}-----\n${b64}\n-----END ${tag}-----\n`;
}

function entry(p: Partial<Entry>): Entry {
  return { ...emptyEntry(p.type ?? 'login'), id: Math.random().toString(36).slice(2), ver: 1, ...p } as Entry;
}

describe('payment cards', () => {
  it('Luhn, brand, formatting, CVV, expiry', () => {
    expect(luhnValid('4111 1111 1111 1111')).toBe(true);
    expect(luhnValid('4111 1111 1111 1112')).toBe(false);
    expect(luhnValid('123')).toBe(false);
    expect(cardBrand('4111111111111111')).toBe('visa');
    expect(cardBrand('5555555555554444')).toBe('mastercard');
    expect(cardBrand('2223003122003222')).toBe('mastercard');
    expect(cardBrand('378282246310005')).toBe('amex');
    expect(cardBrand('6011111111111117')).toBe('discover');
    expect(formatCardNumber('378282246310005')).toBe('3782 822463 10005');
    expect(formatCardNumber('4111111111111111')).toBe('4111 1111 1111 1111');
    expect(cvvValid('123', '4111111111111111')).toBe(true);
    expect(cvvValid('1234', '4111111111111111')).toBe(false);
    expect(cvvValid('1234', '378282246310005')).toBe(true);
    expect(normExpiry('1/27')).toBe('01/27');
    expect(normExpiry('012027')).toBe('01/27');
    expect(normExpiry('13/27')).toBeNull();
    const now = new Date(2026, 10, 12).getTime(); // 12 Nov 2026
    expect(expiryState('11/26', now)).toBe('soon'); // valid through 30 Nov
    expect(expiryState('10/26', now)).toBe('expired');
    expect(expiryState('12/26', now)).toBe('soon');
    expect(expiryState('06/29', now)).toBe('ok');
    expect(expiryState('xx', now)).toBe('invalid');
    expect(expiryState('', now)).toBe('none');
  });
});

describe('SSH keys', () => {
  it('parses public keys and computes the OpenSSH SHA256 fingerprint', async () => {
    const info = parseSshPublic(PUB)!;
    expect(info.type).toBe('ssh-ed25519');
    expect(info.bits).toBe(256);
    expect(info.comment).toBe('dev@example');
    expect(await sshFingerprint(PUB)).toBe(PUB_FP);
    expect(parseSshPublic('ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIP46')).toBeNull(); // type mismatch
    expect(await sshFingerprint('garbage')).toBeNull();
  });
  it('detects whether a private key is passphrase-protected without decrypting it', () => {
    expect(inspectSshPrivate(fakeOpenssh('none'))).toMatchObject({ format: 'openssh', encrypted: false, keyType: 'ssh-ed25519' });
    expect(inspectSshPrivate(fakeOpenssh('aes256-ctr'))).toMatchObject({ format: 'openssh', encrypted: true, cipher: 'aes256-ctr' });
    const rsaTag = ['RSA', 'PRIVATE', 'KEY'].join(' ');
    expect(inspectSshPrivate(`-----BEGIN ${rsaTag}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END ${rsaTag}-----`)).toMatchObject({ format: 'pem-rsa', encrypted: true });
    expect(inspectSshPrivate('PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\n')).toMatchObject({ format: 'putty', encrypted: true });
    expect(inspectSshPrivate('')).toBeNull();
  });
});

describe('CSV import', () => {
  it('parses RFC 4180 (quotes, escaped quotes, embedded newlines, CRLF, BOM)', () => {
    expect(parseCsv('\uFEFFa,b\r\n"x, y","say ""hi""\nthere"\r\n')).toEqual([['a', 'b'], ['x, y', 'say "hi"\nthere']]);
  });
  it('maps Bitwarden, 1Password and Chrome exports', () => {
    const bw = importCsv('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,GitHub,,,0,https://github.com,me,pw1,JBSWY3DPEHPK3PXP\n,,note,Wifi,"SSID: home",,0,,,,\n,,card,Visa,,,0,,,,\n');
    expect(bw.source).toBe('bitwarden');
    expect(bw.entries).toHaveLength(2);
    expect(bw.skipped).toBe(1);
    expect(bw.entries[0]).toMatchObject({ type: 'login', title: 'GitHub', site: 'https://github.com', username: 'me', password: 'pw1', totp: 'JBSWY3DPEHPK3PXP', folder: 'Work', favorite: true });
    expect(bw.entries[1]).toMatchObject({ type: 'note', title: 'Wifi', notes: 'SSID: home' });
    const op = importCsv('Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nMail,mail.example.com,a@b.c,pw2,,false,true,personal;email,hello\n');
    expect(op.source).toBe('1password');
    expect(op.entries[0]!.tags).toEqual(['imported', 'personal', 'email', 'archived']);
    const ch = importCsv('name,url,username,password,note\n,https://www.example.org/login,u,p,\n');
    expect(ch.source).toBe('chrome');
    expect(ch.entries[0]!.title).toBe('www.example.org');
    const proton = importCsv('type,name,url,email,username,password,note,totp,vault\nlogin,Mail,https://mail.example,a@b.c,ada,pw3,hi,otpauth://totp/x,Personal\nalias,Hide,https://shop.example,hide@pm.me,,pw4,,,,\n');
    expect(proton.source).toBe('proton');
    expect(proton.entries[0]).toMatchObject({ title: 'Mail', username: 'ada', password: 'pw3', totp: 'otpauth://totp/x', folder: 'Personal', notes: 'hi\nEmail: a@b.c' });
    expect(proton.entries[1]).toMatchObject({ title: 'Hide', username: 'hide@pm.me', password: 'pw4' });
  });
});

describe('Watchtower', () => {
  it('flags insecure, duplicate, expired, invalid and unprotected items and scores the vault', () => {
    expect(insecureSite('http://example.com')).toBe(true);
    expect(insecureSite('http://localhost:5173')).toBe(false);
    expect(insecureSite('https://example.com')).toBe(false);
    const now = new Date(2026, 10, 12).getTime();
    const es = [
      entry({ type: 'login', title: 'a', site: 'http://shop.example', username: 'me', password: 'Xk#9vL!2qR$7mZ@4', updated: now }),
      entry({ type: 'login', title: 'b', site: 'https://www.shop.example/login', username: 'ME', password: 'Pq!8sT#3wY$6nB@1', updated: now, totp: 'JBSWY3DPEHPK3PXP' }),
      entry({ type: 'card', title: 'old', number: '4111111111111111', expiry: '01/25' }),
      entry({ type: 'card', title: 'typo', number: '4111111111111112', expiry: '01/30' }),
      entry({ type: 'ssh', title: 'k', privateKey: fakeOpenssh('none') }),
      entry({ type: 'ssh', title: 'k2', privateKey: fakeOpenssh('aes256-ctr') }),
    ];
    const w = watchtower(es, new Map(), now);
    expect(w.insecure.map((e) => e.title)).toEqual(['a']);
    expect(w.duplicates.map((e) => e.title).sort()).toEqual(['a', 'b']);
    expect(w.no2fa.map((e) => e.title)).toEqual(['a']);
    expect(w.cardsExpired.map((e) => e.title)).toEqual(['old']);
    expect(w.cardsInvalid.map((e) => e.title)).toEqual(['typo']);
    expect(w.sshUnprotected.map((e) => e.title)).toEqual(['k']);
    expect(w.score).toBe(17); // only k2 is clean (1 of 6)
  });
});

describe('audit helpers', () => {
  it('caps the log and exports titles, never values', () => {
    let log: ReturnType<typeof appendAudit> = [];
    for (let i = 0; i < AUDIT_MAX + 5; i++) log = appendAudit(log, { at: i, ev: 'copy', item: 'x' });
    expect(log).toHaveLength(AUDIT_MAX);
    expect(log[0]!.at).toBe(AUDIT_MAX + 4);
    expect(auditCsv([{ at: 0, ev: 'reveal', item: 'x', detail: 'Pass, word' }], () => 'My "item"')).toContain('"My ""item"""');
  });
});

describe('store: folders, audit, project environments, CSV, cards', () => {
  beforeEach(() => {
    localStorage.clear();
    S.__resetForTests();
    S.__setKdfFactory(fast);
  });
  afterEach(() => S.__resetForTests());

  it('folders: add, assign, rename (moves items), delete (keeps items)', async () => {
    await S.createVault('my long master password');
    await S.addFolder('Work');
    const e = await S.saveEntry(null, { type: 'login', title: 'Jira', folder: 'Work', password: 'x' });
    await S.renameFolder('Work', 'Job');
    expect(S.usePevv.getState().meta!.folders).toEqual(['Job']);
    expect(S.usePevv.getState().entries.find((x) => x.id === e.id)!.folder).toBe('Job');
    await S.deleteFolder('Job');
    expect(S.usePevv.getState().meta!.folders).toEqual([]);
    expect(S.usePevv.getState().entries.find((x) => x.id === e.id)!.folder).toBe('');
    await expect(S.addFolder('a/b')).rejects.toThrow();
  });

  it('audit log is encrypted at rest, survives lock/unlock, and never holds secret values', async () => {
    await S.createVault('my long master password');
    const e = await S.saveEntry(null, { type: 'apikey', title: 'Stripe', key: 'demo_key_SUPERSECRET' });
    await S.copySecret('demo_key_SUPERSECRET', e.id).catch(() => false);
    S.audit('reveal', e.id, 'API key');
    await new Promise((r) => setTimeout(r, 50));
    const raw = Object.keys(localStorage).filter((k) => k.startsWith('lv-pevv-audit-')).map((k) => localStorage.getItem(k)).join('');
    expect(raw).not.toContain('Stripe');
    expect(raw).not.toContain('reveal');
    expect(JSON.stringify(S.usePevv.getState().audit)).not.toContain('SUPERSECRET');
    S.lock('manual');
    expect(S.usePevv.getState().audit).toEqual([]);
    await S.unlockPassword('my long master password');
    await new Promise((r) => setTimeout(r, 50));
    const evs = S.usePevv.getState().audit.map((r) => r.ev);
    expect(evs[0]).toBe('unlock');
    expect(evs).toContain('lock');
    expect(evs).toContain('reveal');
    expect(evs).toContain('create');
  });

  it('per-project environment links override the active environment for program env requests', async () => {
    await S.createVault('my long master password');
    await S.saveEntry(null, { type: 'env', name: 'API', value: 'dev-value', env: 'dev' });
    await S.saveEntry(null, { type: 'env', name: 'API', value: 'prod-value', env: 'prod' });
    await S.updateMeta({ grants: { 'project:demo': ['API'] } });
    expect(await S.requestProgramEnv('project:demo', ['API'])).toEqual({ API: 'dev-value' });
    await S.linkProgramEnv('project:demo', 'prod');
    expect(S.envForProgram('project:demo')).toBe('prod');
    expect(await S.requestProgramEnv('project:demo', ['API'])).toEqual({ API: 'prod-value' });
    await S.linkProgramEnv('project:demo', null);
    expect(S.envForProgram('project:demo')).toBe('dev');
    await expect(S.linkProgramEnv('project:demo', 'nope')).rejects.toThrow();
  });

  it('CSV import creates folders and items; cards and SSH keys round-trip encrypted', async () => {
    await S.createVault('my long master password');
    const r = await S.importCsvText('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nHome,,login,Router,,,0,http://192.168.1.1,admin,hunter2,\n');
    expect(r).toMatchObject({ added: 1, source: 'bitwarden' });
    expect(S.usePevv.getState().meta!.folders).toContain('Home');
    await S.saveEntry(null, { type: 'card', title: 'Visa', number: '4111 1111 1111 1111', expiry: '04/29', cvv: '123' });
    await S.saveEntry(null, { type: 'ssh', title: 'deploy', publicKey: PUB, privateKey: fakeOpenssh('none') });
    const stored = localStorage.getItem(S.VAULT_KEY)!;
    expect(stored).not.toContain('4111');
    expect(stored).not.toContain('hunter2');
    expect(stored).not.toContain('AAAAC3NzaC1lZDI1NTE5');
    S.lock('manual');
    await S.unlockPassword('my long master password');
    const types = S.usePevv.getState().entries.map((e) => e.type).sort();
    expect(types).toEqual(['card', 'login', 'ssh']);
  });

  it('history restore swaps the previous value back in', async () => {
    await S.createVault('my long master password');
    const e = await S.saveEntry(null, { type: 'login', title: 'x', password: 'old-one' });
    await S.saveEntry(e.id, { password: 'new-one' });
    await S.restoreHistory(e.id, 0);
    const now = S.usePevv.getState().entries.find((x) => x.id === e.id)!;
    expect(now.password).toBe('old-one');
    expect(now.history[0]).toMatchObject({ field: 'password', value: 'new-one' });
  });
});
