#!/usr/bin/env node
/**
 * PEVV extension end to end in the installed Firefox, in a fresh profile that
 * has never signed in to a sync account.
 *
 *   npm run build:extension && npm run test:extension:firefox
 *
 * Firefox path: FIREFOX_BIN, else the usual install location. Headed with HEADED=1.
 * Like the Chromium spec, the test copy of the manifest grants the one test host
 * (automation cannot click the toolbar button that grants activeTab).
 */
import { createServer } from 'node:http';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
/* global chrome -- these functions run inside the extension pages */
import { launch } from './bidi.mjs';

const PW = 'correct horse battery staple 42!';
const GECKO_ID = 'pevv@luciverse.pages.dev';
const UUID = '4e5f6a7b-1c2d-4e3f-8a9b-0c1d2e3f4a5b';
const BASE = `moz-extension://${UUID}`;
const LOGIN_HTML = `<!doctype html><html><body>
<form id="login" onsubmit="event.preventDefault(); document.body.dataset.sent = '1'">
  <input id="u" name="email" type="email"><input id="p" name="password" type="password"><button id="go" type="submit">Sign in</button>
</form></body></html>`;

const work = mkdtempSync(join(process.env.PEVV_TMP ?? tmpdir(), 'pevv-ff-'));
const server = createServer((_q, r) => { r.writeHead(200, { 'content-type': 'text/html' }); r.end(LOGIN_HTML); });
await new Promise((r) => server.listen(0, '127.0.0.1', r));
// Firefox match patterns ignore ports, so the test site is a plain host served through this server as an HTTP proxy.
const SITE = 'http://login.pevv.test';
const PROXY_PORT = server.address().port;

const ext = join(work, 'ext');
cpSync('dist-extension-firefox', ext, { recursive: true });
const manifest = JSON.parse(readFileSync(join(ext, 'manifest.json'), 'utf8'));
assert.equal(manifest.browser_specific_settings.gecko.id, GECKO_ID);
manifest.host_permissions = [`${SITE}/*`];
writeFileSync(join(ext, 'manifest.json'), JSON.stringify(manifest));

const ff = await launch({
  profile: join(work, 'profile'),
  prefs: {
    'extensions.webextensions.uuids': JSON.stringify({ [GECKO_ID]: UUID }),
    'network.proxy.type': 1,
    'network.proxy.http': '127.0.0.1',
    'network.proxy.http_port': PROXY_PORT,
    'network.proxy.no_proxies_on': '',
  },
});

const step = (s) => console.log(`  · ${s}`);
async function until(what, f, timeout = 30_000) {
  const end = Date.now() + timeout;
  let last;
  for (;;) {
    try { last = await f(); if (last) return last; } catch (e) { last = e.message; }
    if (Date.now() > end) throw new Error(`timed out: ${what} (last: ${JSON.stringify(last)})`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

// Page helpers, run inside the page.
const byId = (ctx, testId) => ff.eval(ctx, (t) => !!document.querySelector(`[data-testid="${t}"]`), testId);
const click = (ctx, testId) => ff.eval(ctx, (t) => { const el = document.querySelector(`[data-testid="${t}"]`); if (!el) throw new Error(`no ${t}`); el.click(); return true; }, testId);
const fill = (ctx, sel, value) => ff.eval(ctx, (s, v) => {
  const el = document.querySelector(s.startsWith('#') ? s : `[data-testid="${s}"]`);
  if (!el) throw new Error(`no ${s}`);
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}, sel, value);
const send = (ctx, m) => ff.eval(ctx, (msg) => chrome.runtime.sendMessage(msg), m);
const value = (ctx, sel) => ff.eval(ctx, (s) => document.querySelector(s).value, sel);
const boxOf = (ctx, sel) => ff.eval(ctx, (s) => { const r = document.querySelector(s)?.getBoundingClientRect(); return r && r.width ? { x: r.x + r.width / 2, y: r.y + r.height / 2 } : null; }, sel);

let failed = false;
try {
  const installed = await ff.send('webExtension.install', { extensionData: { type: 'path', path: ext } });
  assert.equal(installed.extension, GECKO_ID);
  step('installed as a temporary add-on');

  // 1. Vault screen: create a vault and a login. No account anywhere.
  const vault = await ff.tab(`${BASE}/extension/vault.html`);
  await until('setup screen', () => byId(vault, 'pevv-mode-new'));
  await click(vault, 'pevv-mode-have');
  await until('have-vault screen', () => byId(vault, 'pevv-qr-scan-box'));
  assert.equal(await byId(vault, 'pevv-from-account'), false, 'the account route is not offered without an account');
  await click(vault, 'pevv-mode-new');
  await click(vault, 'pevv-setup-ack');
  await until('password fields', () => byId(vault, 'pevv-setup-password'));
  await fill(vault, 'pevv-setup-password', PW);
  await fill(vault, 'pevv-setup-confirm', PW);
  await click(vault, 'pevv-setup-submit');
  await until('vault unlocked', () => byId(vault, 'pevv-unlocked'), 90_000);
  await click(vault, 'pevv-new');
  await until('new menu', () => byId(vault, 'pevv-new-login'));
  await click(vault, 'pevv-new-login');
  await until('item form', () => byId(vault, 'pevv-f-title'));
  await fill(vault, 'pevv-f-title', 'Firefox test site');
  await fill(vault, 'pevv-f-site', SITE);
  await fill(vault, 'pevv-f-username', 'ada@pevv.test');
  await fill(vault, 'pevv-f-password', 'pw-1');
  await click(vault, 'pevv-save');
  const stored = await until('ciphertext in storage.local', async () => {
    const s = await ff.eval(vault, async () => String((await chrome.storage.local.get('pevv.vault'))['pevv.vault'] ?? ''));
    return s.includes('"entries":[{') && s;
  });
  assert.ok(!stored.includes('pw-1') && !stored.includes('ada@pevv.test'), 'only ciphertext is stored');
  assert.equal(await ff.eval(vault, () => localStorage.getItem('pevv-sync-auth')), null, 'no sync session');
  step('vault screen: vault created, login saved, only ciphertext stored, no account');

  // 2. Popup: unlock with the master password.
  const site = await ff.tab(`${SITE}/login`);
  const pop = await ff.tab(`${BASE}/extension/popup.html`);
  await until('popup locked', () => byId(pop, 'ext-locked'));
  await fill(pop, 'ext-password', 'wrong password');
  await click(pop, 'ext-unlock');
  await until('wrong password refused', () => ff.eval(pop, () => /wrong master password/i.test(document.querySelector('[data-testid="ext-error"]')?.textContent ?? '')));
  await fill(pop, 'ext-password', PW);
  await click(pop, 'ext-unlock');
  await until('popup unlocked', () => ff.eval(pop, () => document.querySelector('[data-testid="ext-popup"]')?.dataset.status === 'unlocked'), 60_000);
  step('popup: wrong password refused, right one unlocks');

  // 3. Fill from the popup.
  const tabId = await ff.eval(pop, async (p) => (await chrome.tabs.query({})).find((t) => t.url?.startsWith(p))?.id ?? null, SITE);
  assert.ok(tabId !== null, 'test tab found');
  const found = (await send(pop, { type: 'search', q: 'ada', url: `${SITE}/login` })).value;
  assert.equal(found[0].matches, true);
  await ff.eval(site, () => { document.querySelector('#p').focus(); return true; });
  assert.equal((await send(pop, { type: 'fill', tabId, url: `${SITE}/login`, id: found[0].id })).ok, true);
  await until('filled', async () => (await value(site, '#u')) === 'ada@pevv.test' && (await value(site, '#p')) === 'pw-1');
  assert.equal((await send(pop, { type: 'fill', tabId, url: 'https://evil.pevv.test/', id: found[0].id })).ok, false, 'never fills another origin');
  step('fill from the popup; another origin is refused');

  // 4. The key survives Firefox's idle event-page timeout (30 s) while unlocked.
  await new Promise((r) => setTimeout(r, 40_000));
  const st = (await send(pop, { type: 'state', tabId, url: `${SITE}/login` })).value;
  assert.equal(st.status, 'unlocked', 'still unlocked after 40 s idle');
  step('still unlocked after 40 s idle (event page kept alive)');

  // 5. Inline button on an approved site: a trusted click fills.
  assert.equal((await send(pop, { type: 'settings', patch: { autofillOrigins: [SITE] } })).ok, true);
  await ff.reload(site);
  const p = await until('password field', () => boxOf(site, '#p'));
  await ff.click(site, p.x, p.y);
  const key = await until('inline 🔐 button', () => boxOf(site, 'pevv-fill'));
  await ff.click(site, key.x, key.y);
  await until('inline fill', async () => (await value(site, '#p')) === 'pw-1' && (await value(site, '#u')) === 'ada@pevv.test');
  step('inline button fills on an approved site');

  // 6. Change the password and submit: an update offer, saved into the same vault.
  const revBefore = JSON.parse(stored).rev;
  await fill(site, '#p', 'pw-2-changed');
  const go = await boxOf(site, '#go');
  await ff.click(site, go.x, go.y);
  await until('form sent', () => ff.eval(site, () => document.body.dataset.sent === '1'));
  await until('update offer', async () => {
    const o = (await send(pop, { type: 'state', tabId, url: `${SITE}/login` })).value.offer;
    return o?.update === true && o.username === 'ada@pevv.test';
  });
  assert.equal((await send(pop, { type: 'offer', tabId, action: 'save' })).ok, true);
  await until('newer revision stored', async () => JSON.parse(await ff.eval(vault, async () => String((await chrome.storage.local.get('pevv.vault'))['pevv.vault']))).rev > revBefore);
  step('save offer updates the vault');

  // 7. Lock: nothing fills any more.
  assert.deepEqual(await send(pop, { type: 'lock' }), { ok: true, value: 'locked' });
  await ff.reload(site);
  await ff.eval(site, () => { document.querySelector('#p').focus(); return true; });
  assert.deepEqual(await send(pop, { type: 'fill', tabId, url: `${SITE}/login`, id: found[0].id }), { ok: false, error: 'The vault is locked.' });
  assert.equal(await value(site, '#p'), '');
  step('locked: fill refused');
  console.log('PEVV Firefox e2e: passed');
} catch (e) {
  failed = true;
  console.error('PEVV Firefox e2e: FAILED\n', e);
} finally {
  await ff.close();
  server.close();
  try { rmSync(work, { recursive: true, force: true }); } catch { /* Firefox may still hold a file */ }
}
process.exit(failed ? 1 : 0);
