import { describe, expect, it, vi } from 'vitest';
import { PBKDF2_MIN_ITER, type KdfParams } from '@/pevv/crypto';
import { b64, randomBytes } from '@/pevv/bytes';
import { applyEdit, emptyEntry, type Entry, type EntryData } from '@/pevv/model';
import * as V from '@/pevv/vault';
import {
  DEFAULT_SEQUENCE, MAX_DELAY_MS, globMatch, hasAutoType, matchAutoType, matchesWindow, normalizeAutoType, parseSequence, processMatches, resolveSequence,
  type SeqToken,
} from '@/pevv/autotype';
import { candidateOf, offerFor, runConfirmed, startAutoType, type AutoTypeStoreApi } from '@/pevv/desktop/autotypeHost';
import { hotkeyFromEvent } from '@/pevv/desktop/AutoType';
import type { LinkIpc } from '@/pevv/desktop/link';

function parsed(src: string): SeqToken[] {
  const p = parseSequence(src);
  if (!p.ok) throw new Error(p.error);
  return p.tokens;
}

function login(over: Partial<Entry> = {}): Entry {
  return { ...emptyEntry('login', 1), id: 'e1', ver: 1, title: 'Router', site: 'https://router.test', username: 'ada', password: 'pw-1', ...over };
}

describe('auto-type sequences', () => {
  it('the default sequence is username, tab, password, enter', () => {
    expect(parsed(DEFAULT_SEQUENCE)).toEqual([
      { kind: 'field', field: 'USERNAME' }, { kind: 'key', key: 'tab' }, { kind: 'field', field: 'PASSWORD' }, { kind: 'key', key: 'enter' },
    ]);
  });

  it('tokens are case-insensitive and plain text is kept', () => {
    expect(parsed('login: {username}{Tab}{TOTP} {delay 250}{enter}')).toEqual([
      { kind: 'text', text: 'login: ' }, { kind: 'field', field: 'USERNAME' }, { kind: 'key', key: 'tab' }, { kind: 'field', field: 'TOTP' },
      { kind: 'text', text: ' ' }, { kind: 'delay', ms: 250 }, { kind: 'key', key: 'enter' },
    ]);
  });

  it('{{} and {}} are literal braces', () => {
    expect(parsed('a{{}b{}}c')).toEqual([{ kind: 'text', text: 'a{b}c' }]);
    expect(parsed('{{}USERNAME{}}')).toEqual([{ kind: 'text', text: '{USERNAME}' }]);
  });

  it('rejects what it cannot type, with a reason and a position', () => {
    for (const bad of ['{NOPE}', '{USERNAME', '{DELAY}', '{DELAY abc}', '{DELAY -5}', '{TAB 3}', '{USERNAME x}', '', '{}', `{DELAY ${MAX_DELAY_MS + 1}}`]) {
      const p = parseSequence(bad);
      expect(p.ok, bad).toBe(false);
    }
    const p = parseSequence('abc{NOPE}');
    expect(p.ok === false && p.at).toBe(3);
    expect(parseSequence('x'.repeat(501)).ok).toBe(false);
  });

  it('delays are capped one by one and in total', () => {
    expect(parseSequence('{DELAY 10000}{DELAY 10000}{DELAY 10000}').ok).toBe(true);
    const over = parseSequence('{DELAY 10000}{DELAY 10000}{DELAY 10000}{DELAY 1}');
    expect(over.ok).toBe(false);
  });

  it('an unknown token is quoted only briefly in the error', () => {
    const p = parseSequence(`{${'x'.repeat(60)}}`);
    expect(p.ok === false && p.error.includes('x'.repeat(30))).toBe(false);
    // Field values never pass through the parser at all.
    expect(JSON.stringify(parseSequence('{USERNAME}'))).not.toContain('pw-1');
  });
});

describe('auto-type matching', () => {
  it('glob: * and ? work, case does not matter, the whole title must match', () => {
    expect(globMatch('*putty*', 'admin@host: ~ - PuTTY')).toBe(true);
    expect(globMatch('putty', 'PuTTY')).toBe(true);
    expect(globMatch('putty', 'PuTTY Configuration')).toBe(false);
    expect(globMatch('Login ?', 'Login 2')).toBe(true);
    expect(globMatch('Login ?', 'Login 22')).toBe(false);
    expect(globMatch('*', '')).toBe(true);
    expect(globMatch('a*b*c', 'a--b--c')).toBe(true);
    expect(globMatch('a*b*c', 'a--c--b')).toBe(false);
    expect(globMatch('*.exe', 'x.exe')).toBe(true);
    // Regex characters in a title are just characters.
    expect(globMatch('a.b(c)', 'a.b(c)')).toBe(true);
    expect(globMatch('a.b', 'axb')).toBe(false);
  });

  it('glob stays fast on pathological input', () => {
    const t0 = Date.now();
    expect(globMatch('*a*a*a*a*a*a*a*a*b', 'a'.repeat(5000))).toBe(false);
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it('program names ignore case and .exe', () => {
    expect(processMatches('putty', 'PuTTY.exe')).toBe(true);
    expect(processMatches('putty.exe', 'putty')).toBe(true);
    expect(processMatches('putty', 'puttygen.exe')).toBe(false);
    expect(processMatches('', 'x')).toBe(false);
  });

  it('a window matches on its title pattern and, if set, its program', () => {
    const ctx = { title: 'admin@host: ~ - PuTTY', process: 'putty.exe' };
    expect(matchesWindow({ windows: ['*PuTTY*'] }, ctx)).toBe(true);
    expect(matchesWindow({ windows: ['*PuTTY*'], process: 'putty' }, ctx)).toBe(true);
    expect(matchesWindow({ windows: ['*PuTTY*'], process: 'kitty' }, ctx)).toBe(false);
    expect(matchesWindow({ windows: ['nothing', '*host*'] }, ctx)).toBe(true);
    expect(matchesWindow({ windows: [], process: 'putty.exe' }, ctx)).toBe(true);
    expect(matchesWindow({ windows: ['*Other*'] }, ctx)).toBe(false);
  });

  it('an entry with no auto-type field, or an empty one, never matches', () => {
    const ctx = { title: 'Router - Admin', process: 'chrome.exe' };
    expect(matchesWindow(undefined, ctx)).toBe(false);
    expect(matchesWindow({ windows: [] }, ctx)).toBe(false);
    expect(matchesWindow({ windows: ['', '  '] }, ctx)).toBe(false);
  });

  it('a URL alone never matches a window, even when the title contains it', () => {
    const e = login({ site: 'https://router.test', title: 'router.test' });
    expect(matchAutoType([e], { title: 'https://router.test - Router login', process: 'firefox.exe' })).toEqual([]);
    expect(matchAutoType([e], { title: 'router.test', process: 'router.test' })).toEqual([]);
    expect(hasAutoType(e)).toBe(false);
  });

  it('only logins match, favourites first', () => {
    const at = { windows: ['*VPN*'] };
    const a = login({ id: 'a', title: 'B VPN', autoType: at });
    const b = login({ id: 'b', title: 'A VPN', autoType: at });
    const c = login({ id: 'c', title: 'Fav VPN', autoType: at, favorite: true });
    const note: Entry = { ...emptyEntry('note', 1), id: 'n', ver: 1, title: 'VPN note', autoType: at };
    const other = login({ id: 'o', autoType: { windows: ['*Mail*'] } });
    expect(matchAutoType([a, b, c, note, other], { title: 'Corp VPN client', process: 'vpn.exe' }).map((e) => e.id)).toEqual(['c', 'b', 'a']);
  });

  it('offers all auto-type entries when the window is unknown (Wayland), and only titles', () => {
    const a = login({ id: 'a', autoType: { windows: ['*x*'] } });
    const b = login({ id: 'b' });
    expect(offerFor([a, b], { title: '', process: '', known: false }).map((e) => e.id)).toEqual(['a']);
    expect(offerFor([a, b], { title: 'zzz', process: 'p', known: true })).toEqual([]);
    const c = candidateOf(login({ title: 'T'.repeat(200), password: 'secret-pw' }));
    expect(c.title).toHaveLength(80);
    expect(JSON.stringify(c)).not.toContain('secret-pw');
  });

  it('normalising the editor fields drops blanks, duplicates and the default sequence', () => {
    expect(normalizeAutoType({ windows: [' *a* ', '', '*a*', 'b'], process: ' putty ', sequence: `  ${DEFAULT_SEQUENCE} ` })).toEqual({ windows: ['*a*', 'b'], process: 'putty' });
    expect(normalizeAutoType({ windows: [], sequence: '{PASSWORD}' })).toBeUndefined();
    expect(normalizeAutoType({ windows: ['x'], sequence: '{PASSWORD}{ENTER}' })).toEqual({ windows: ['x'], sequence: '{PASSWORD}{ENTER}' });
    expect(normalizeAutoType(undefined)).toBeUndefined();
  });
});

describe('auto-type keys', () => {
  it('fills the fields and merges neighbouring text', async () => {
    const acts = await resolveSequence(parsed('{USERNAME}{TAB}{PASSWORD}{ENTER}'), login());
    expect(acts).toEqual([{ t: 'text', v: 'ada' }, { t: 'key', v: 'tab' }, { t: 'text', v: 'pw-1' }, { t: 'key', v: 'enter' }]);
    expect(await resolveSequence(parsed('a{USERNAME}b{{}'), login())).toEqual([{ t: 'text', v: 'aadab{' }]);
    expect(await resolveSequence(parsed('{USERNAME}{DELAY 300}{PASSWORD}'), login())).toEqual([{ t: 'text', v: 'ada' }, { t: 'delay', v: 300 }, { t: 'text', v: 'pw-1' }]);
  });

  it('{TOTP} is the code valid now (RFC 6238 vector)', async () => {
    const e = login({ totp: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' });
    expect(await resolveSequence(parsed('{TOTP}'), e, 59_000)).toEqual([{ t: 'text', v: '287082' }]);
    expect(await resolveSequence(parsed('{TOTP}'), e, 1_111_111_109_000)).toEqual([{ t: 'text', v: '081804' }]);
  });

  it('refuses {TOTP} without a secret, and sequences with nothing to type', async () => {
    await expect(resolveSequence(parsed('{TOTP}'), login())).rejects.toThrow(/one-time/);
    await expect(resolveSequence(parsed('{USERNAME}'), login({ username: '' }))).rejects.toThrow(/nothing to type/);
    await expect(resolveSequence(parsed('{DELAY 100}'), login())).rejects.toThrow(/nothing to type/);
  });
});

describe('the entry model carries auto-type without breaking older clients', () => {
  const kdf = (): KdfParams => ({ alg: 'pbkdf2-sha256', iter: PBKDF2_MIN_ITER, salt: b64(randomBytes(16)) });

  it('survives a seal and open through the vault, and an entry without it is unchanged', async () => {
    const { file: f0, session } = await V.createVault('correct horse battery', kdf());
    let file = f0;
    let meta = await V.readMeta(file, session);
    const withAt: EntryData = { ...emptyEntry('login', 1), title: 'Router', username: 'ada', password: 'pw', autoType: { windows: ['*Router*'], process: 'chrome.exe', sequence: '{USERNAME}{TAB}{PASSWORD}' } };
    const plain: EntryData = { ...emptyEntry('login', 1), title: 'Plain', username: 'u', password: 'p' };
    ({ file, meta } = await V.putEntry(file, session, meta, null, withAt));
    ({ file, meta } = await V.putEntry(file, session, meta, null, plain));
    const { entries, warnings } = await V.decryptAll(file, session);
    expect(warnings).toEqual([]);
    expect(entries.find((e) => e.title === 'Router')?.autoType).toEqual(withAt.autoType);
    const p = entries.find((e) => e.title === 'Plain')!;
    expect('autoType' in p).toBe(false);
    expect(hasAutoType(p)).toBe(false);
  });

  it('an older client (which knows nothing of the field) keeps it through its own edits', async () => {
    // Older clients treat an entry as a bag of the fields they know and spread the rest: that is `applyEdit`.
    const prev: EntryData = { ...emptyEntry('login', 1), title: 'Router', password: 'old', autoType: { windows: ['*Router*'] } };
    const edited = applyEdit(prev, { password: 'new' }, 5);
    expect(edited.autoType).toEqual({ windows: ['*Router*'] });
    // And the sealed JSON has plain optional data: no schema that an older reader would reject.
    const wire = JSON.parse(JSON.stringify(edited)) as Record<string, unknown>;
    const { autoType, ...asOldClientSeesIt } = wire;
    expect(autoType).toBeTruthy();
    expect(asOldClientSeesIt.title).toBe('Router');
    expect(asOldClientSeesIt.password).toBe('new');
  });

  it('a future client field next to autoType is also kept', async () => {
    const prev = { ...emptyEntry('login', 1), title: 'x', autoType: { windows: ['a'] }, somethingNew: 7 } as EntryData;
    expect((applyEdit(prev, { title: 'y' }, 2) as unknown as Record<string, unknown>).somethingNew).toBe(7);
  });

  it('a malformed autoType in the file never makes an entry match', () => {
    const e = login({ autoType: 'oops' as never });
    expect(() => matchAutoType([e], { title: 'oops', process: 'x' })).not.toThrow();
    expect(matchAutoType([login({ autoType: { windows: 'x' as never } })], { title: 'x', process: 'x' })).toEqual([]);
  });
});

describe('auto-type in the vault window', () => {
  class Shell implements LinkIpc {
    calls: Array<{ cmd: string; args: Record<string, unknown> | undefined }> = [];
    handlers = new Map<string, Array<(p: never) => void>>();
    failType = false;
    async invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
      this.calls.push({ cmd, args });
      if (cmd === 'autotype_type' && this.failType) throw { code: 'target-changed', message: 'changed' };
      return undefined as T;
    }
    async listen<P>(event: string, fn: (payload: P) => void): Promise<() => void> {
      const l = this.handlers.get(event) ?? [];
      l.push(fn as (p: never) => void);
      this.handlers.set(event, l);
      return () => undefined;
    }
    emit(event: string, payload: unknown): void { for (const f of this.handlers.get(event) ?? []) f(payload as never); }
  }

  function store(entries: Entry[], unlocked = true): AutoTypeStoreApi & { copied: string[]; audits: string[] } {
    const s = {
      copied: [] as string[], audits: [] as string[],
      unlocked: () => unlocked,
      entries: () => entries,
      copySecret: vi.fn(async (v: string) => { s.copied.push(v); return true; }),
      clipboardSec: () => 30,
      audit: (item: string, detail: string) => { s.audits.push(`${item}:${detail}`); },
    };
    return s;
  }

  const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 10));

  it('answers a hotkey request with titles only', async () => {
    const shell = new Shell();
    const e = login({ id: 'a', autoType: { windows: ['*Router*'] } });
    await startAutoType(shell, store([e, login({ id: 'b' })]));
    shell.emit('autotype-request', { id: 7, title: 'Router - Admin', process: 'chrome.exe', known: true, mode: 'type' });
    await flush();
    const offer = shell.calls.find((c) => c.cmd === 'autotype_offer')!;
    expect(offer.args).toEqual({ id: 7, candidates: [{ id: 'a', title: 'Router', username: 'ada' }] });
    expect(JSON.stringify(shell.calls)).not.toContain('pw-1');
  });

  it('ignores a request while locked', async () => {
    const shell = new Shell();
    await startAutoType(shell, store([login({ autoType: { windows: ['*'] } })], false));
    shell.emit('autotype-request', { id: 1, title: 't', process: 'p', known: true, mode: 'type' });
    await flush();
    expect(shell.calls).toEqual([]);
  });

  it('after the pick it sends the keys to type, and nothing before', async () => {
    const shell = new Shell();
    const s = store([login({ id: 'a', autoType: { windows: ['*Router*'], sequence: '{USERNAME}{TAB}{PASSWORD}{ENTER}' } })]);
    await startAutoType(shell, s);
    shell.emit('autotype-run', { id: 9, entryId: 'a', mode: 'type' });
    await flush();
    const t = shell.calls.find((c) => c.cmd === 'autotype_type')!;
    expect(t.args).toEqual({ id: 9, actions: [{ t: 'text', v: 'ada' }, { t: 'key', v: 'tab' }, { t: 'text', v: 'pw-1' }, { t: 'key', v: 'enter' }] });
    expect(s.audits).toEqual(['a:typed into another program']);
    expect(JSON.stringify(s.audits)).not.toContain('pw-1');
  });

  it('a shell-side failure is not reported twice', async () => {
    const shell = new Shell();
    shell.failType = true;
    await startAutoType(shell, store([login({ id: 'a', autoType: { windows: ['*'] } })]));
    shell.emit('autotype-run', { id: 3, entryId: 'a', mode: 'type' });
    await flush();
    expect(shell.calls.map((c) => c.cmd)).toEqual(['autotype_type']);
  });

  it('on a system that cannot type it copies the password and says so', async () => {
    const shell = new Shell();
    const s = store([login({ id: 'a', autoType: { windows: ['*'] } })]);
    expect(await runConfirmed(shell, s, { id: 5, entryId: 'a', mode: 'clipboard' })).toBeNull();
    expect(s.copied).toEqual(['pw-1']);
    const fin = shell.calls.find((c) => c.cmd === 'autotype_finish')!;
    expect(fin.args).toMatchObject({ id: 5, ok: true });
    expect(String(fin.args!.message)).toMatch(/copied.*clears in 30 s/);
    expect(shell.calls.some((c) => c.cmd === 'autotype_type')).toBe(false);
  });

  it('problems before typing come back as a message for the chooser', async () => {
    const shell = new Shell();
    expect(await runConfirmed(shell, store([], true), { id: 1, entryId: 'gone', mode: 'type' })).toMatch(/gone/);
    expect(await runConfirmed(shell, store([login({ id: 'a' })], false), { id: 1, entryId: 'a', mode: 'type' })).toMatch(/locked/);
    expect(await runConfirmed(shell, store([login({ id: 'a', autoType: { windows: ['*'], sequence: '{TOTP}' } })]), { id: 1, entryId: 'a', mode: 'type' })).toMatch(/one-time/);
    expect(await runConfirmed(shell, store([login({ id: 'a', autoType: { windows: ['*'], sequence: '{BAD}' } })]), { id: 1, entryId: 'a', mode: 'type' })).toMatch(/Unknown/);
    expect(shell.calls).toEqual([]);
  });

  it('turns key presses into shortcuts the shell accepts', () => {
    const k = (code: string, mods: Partial<Record<'ctrlKey' | 'altKey' | 'shiftKey' | 'metaKey', boolean>> = {}) => hotkeyFromEvent({ code, ctrlKey: false, altKey: false, shiftKey: false, metaKey: false, ...mods });
    expect(k('KeyA', { ctrlKey: true, altKey: true })).toBe('Ctrl+Alt+A');
    expect(k('Digit7', { ctrlKey: true, shiftKey: true })).toBe('Ctrl+Shift+7');
    expect(k('F9', { altKey: true })).toBe('Alt+F9');
    expect(k('KeyK', { metaKey: true })).toBe('Super+K');
    expect(k('ControlLeft', { ctrlKey: true })).toBeNull();
    expect(k('ShiftLeft', { shiftKey: true })).toBeNull();
  });
});
