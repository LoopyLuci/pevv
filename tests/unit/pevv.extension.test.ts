import { readFileSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { GECKO_ID, firefoxManifest, zipFiles, type ExtManifest } from '../../scripts/extension-package.mjs';
import { afterEach, describe, expect, it } from 'vitest';
import { captured, fillGenerated, fillLogin, targetFrom } from '@/pevv/extension/fields';
import { PAGE_VAULT_KEY, parseFile, pickCopy, shouldMirror } from '@/pevv/extension/bridge';
import { clampAutoLock, originOf } from '@/pevv/extension/protocol';
import { VAULT_FORMAT, type VaultFile } from '@/pevv/model';
import { VAULT_KEY } from '@/pevv/store';

function file(id: string, rev: number): VaultFile {
  return {
    format: VAULT_FORMAT, v: 1, id, created: 1, updated: 1, rev,
    kdf: { alg: 'pbkdf2-sha256', iter: 600_000, salt: 'AAAA' },
    slots: [], passkeys: [], require: { totp: false, passkey: false }, totp: null,
    meta: { iv: 'a', ct: 'b' }, entries: [],
  };
}

describe('extension manifest', () => {
  const m = JSON.parse(readFileSync('extension/manifest.json', 'utf8')) as Record<string, unknown>;
  it('is MV3 with only the permissions the plan allows', () => {
    expect(m.manifest_version).toBe(3);
    expect([...(m.permissions as string[])].sort()).toEqual(['activeTab', 'alarms', 'idle', 'scripting', 'storage']);
  });
  it('asks for no host access at install; hosts are optional and approved one by one', () => {
    expect(m.host_permissions).toBeUndefined();
    expect(m.content_scripts).toBeUndefined();
    expect(JSON.stringify(m)).not.toContain('<all_urls>');
    expect(m.optional_host_permissions).toEqual(['https://*/*', 'http://*/*']);
  });
  it('ships its own PEVV padlock icons, wired to the toolbar button and the extension list', () => {
    const sizes = ['16', '32', '48', '128'];
    const icons = m.icons as Record<string, string>;
    const action = m.action as { default_icon: Record<string, string> };
    for (const sz of sizes) {
      expect(icons[sz]).toBe(`icons/icon-${sz}.png`);
      expect(action.default_icon[sz]).toBe(icons[sz]);
      const png = readFileSync(`extension/${icons[sz]}`);
      expect(png.readUInt32BE(16)).toBe(Number(sz));
      expect(png.readUInt32BE(20)).toBe(Number(sz));
    }
  });
  it('never lets a web page talk to the extension', () => {
    expect(m.externally_connectable).toBeUndefined();
    expect(m.web_accessible_resources).toBeUndefined();
  });
});

describe('extension protocol helpers', () => {
  it('only fills http(s) origins', () => {
    expect(originOf('https://a.test/x?y#z')).toBe('https://a.test');
    expect(originOf('http://localhost:8080/')).toBe('http://localhost:8080');
    expect(originOf('chrome://settings')).toBeNull();
    expect(originOf('file:///C:/x.html')).toBeNull();
    expect(originOf('not a url')).toBeNull();
    expect(originOf(null)).toBeNull();
  });
  it('clamps auto-lock', () => {
    expect(clampAutoLock(5)).toBe(5);
    expect(clampAutoLock(0)).toBe(1);
    expect(clampAutoLock(999)).toBe(60);
    expect(clampAutoLock(Number.NaN)).toBe(5);
  });
});

describe('vault screen bridge', () => {
  it('uses the same localStorage key as the PEVV store', () => {
    expect(PAGE_VAULT_KEY).toBe(VAULT_KEY);
  });
  it('picks the shared copy', () => {
    const a1 = file('a', 1);
    const a2 = file('a', 2);
    const b1 = file('b', 1);
    expect(pickCopy(null, null)).toBeNull();
    expect(pickCopy(a1, null)).toBe(a1);
    expect(pickCopy(null, a1)).toBe(a1);
    expect(pickCopy(a1, a2)).toBe(a2);
    expect(pickCopy(a2, a1)).toBe(a2);
    expect(pickCopy(a2, b1)).toBe(b1);
  });
  it('does not overwrite a newer copy the worker wrote', () => {
    expect(shouldMirror(file('a', 3), null)).toBe(true);
    expect(shouldMirror(file('a', 3), file('a', 4))).toBe(false);
    expect(shouldMirror(file('a', 4), file('a', 4))).toBe(false);
    expect(shouldMirror(file('a', 5), file('a', 4))).toBe(true);
    expect(shouldMirror(file('b', 1), file('a', 9))).toBe(true);
  });
  it('rejects anything that is not a vault file', () => {
    expect(parseFile('{"x":1}')).toBeNull();
    expect(parseFile('nope')).toBeNull();
    expect(parseFile(JSON.stringify(file('a', 1)))!.id).toBe('a');
  });
});

describe('content script field helpers', () => {
  afterEach(() => { document.body.innerHTML = ''; });

  it('fills the username and password of the focused login form and fires input events', () => {
    document.body.innerHTML = `<form><input id="u" type="email"><input id="p" type="password"></form><input id="q" type="text">`;
    const u = document.getElementById('u') as HTMLInputElement;
    const p = document.getElementById('p') as HTMLInputElement;
    const seen: string[] = [];
    u.addEventListener('input', () => seen.push('u'));
    p.addEventListener('input', () => seen.push('p'));
    for (const el of [p, u]) {
      const t = targetFrom(el)!;
      expect(t.password).toBe(p);
      expect(t.username).toBe(u);
    }
    fillLogin(targetFrom(p)!, 'ada@x.test', 'pw-1');
    expect(u.value).toBe('ada@x.test');
    expect(p.value).toBe('pw-1');
    expect(seen).toEqual(['u', 'p']);
  });

  it('does nothing when the focus is not on a login field', () => {
    document.body.innerHTML = `<input id="q" type="text"><textarea id="t"></textarea><form><input type="password" disabled></form>`;
    expect(targetFrom(document.getElementById('q'))).toBeNull();
    expect(targetFrom(document.getElementById('t'))).toBeNull();
    expect(targetFrom(document.body)).toBeNull();
    expect(targetFrom(null)).toBeNull();
  });

  it('prefers an autocomplete=username field', () => {
    document.body.innerHTML = `<form><input id="u" autocomplete="username"><input id="other" type="text"><input id="p" type="password"></form>`;
    expect(targetFrom(document.getElementById('p'))!.username!.id).toBe('u');
  });

  it('fills a generated password into the focused field and the empty confirm field only', () => {
    document.body.innerHTML = `<form><input id="u"><input id="p1" type="password"><input id="p2" type="password"></form><form><input id="x" type="password"></form>`;
    const p1 = document.getElementById('p1') as HTMLInputElement;
    expect(fillGenerated(p1, 'Gen!')).toBe(2);
    expect((document.getElementById('p2') as HTMLInputElement).value).toBe('Gen!');
    expect((document.getElementById('x') as HTMLInputElement).value).toBe('');
    expect(fillGenerated(document.getElementById('u'), 'Gen!')).toBe(0);
  });

  it('captures what a submitted form sends', () => {
    document.body.innerHTML = `<form id="f"><input name="user" value=" ada "><input type="password" value="pw"></form><form id="g"><input value="x"></form>`;
    expect(captured(document.getElementById('f') as HTMLFormElement)).toEqual({ username: 'ada', password: 'pw' });
    expect(captured(document.getElementById('g') as HTMLFormElement)).toBeNull();
  });
});

describe('extension packaging', () => {
  const base = JSON.parse(readFileSync('extension/manifest.json', 'utf8')) as ExtManifest;

  it('builds a Firefox manifest: event page, add-on id, same permissions', () => {
    const ff = firefoxManifest(base);
    expect(ff.background).toEqual({ scripts: ['worker.js'], type: 'module' });
    expect(ff.browser_specific_settings.gecko.id).toBe(GECKO_ID);
    expect(ff.browser_specific_settings.gecko.data_collection_permissions).toEqual({ required: ['none'] });
    expect(ff.minimum_chrome_version).toBeUndefined();
    expect(ff.permissions).toEqual(base.permissions);
    expect(ff.optional_host_permissions).toEqual(base.optional_host_permissions);
    expect(ff.version).toBe(base.version);
    expect(base.background).toEqual({ service_worker: 'worker.js', type: 'module' });
  });

  it('writes zips with forward-slash paths that unpack to the same bytes', () => {
    const files = [{ path: 'manifest.json', data: '{"a":1}' }, { path: 'assets/x.js', data: 'console.log(1);'.repeat(50) }];
    const zip = zipFiles(files);
    const names: string[] = [];
    for (let i = zip.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])); i >= 0; i = zip.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]), i + 4)) {
      const method = zip.readUInt16LE(i + 10);
      const size = zip.readUInt32LE(i + 20);
      const nameLen = zip.readUInt16LE(i + 28);
      const name = zip.toString('utf8', i + 46, i + 46 + nameLen);
      const at = zip.readUInt32LE(i + 42);
      const start = at + 30 + zip.readUInt16LE(at + 26) + zip.readUInt16LE(at + 28);
      const body = zip.subarray(start, start + size);
      const raw = method === 8 ? inflateRawSync(body) : body;
      expect(raw.toString()).toBe(files.find((f) => f.path === name)!.data);
      names.push(name);
    }
    expect(names).toEqual(['manifest.json', 'assets/x.js']);
    expect(() => zipFiles([{ path: 'assets\\x.js', data: '' }])).toThrow(/backslash/);
  });
});
