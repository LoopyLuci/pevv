/**
 * PEVV without a sync account: two fresh Chromium profiles that have never
 * signed in anywhere. One makes a vault, the other gets it by vault QR (a
 * photo of the code) and fills from it. Nothing here signs in.
 *
 * The QR move goes through the optional Realtime relay (an anonymous socket, not an
 * account), so it needs a sync backend (docs/SYNC_SELF_HOSTING.md) and the network. Build the extension with
 * VITE_PEVV_SYNC_URL and VITE_PEVV_SYNC_ANON_KEY set, then run with PEVV_E2E_SYNC=1:
 *   npm run build:extension && npx playwright test -c playwright.extension.config.ts pevv-extension-no-account
 * Without PEVV_E2E_SYNC=1 the test is skipped (the offline QR frames are covered by unit tests).
 */
import { cpSync, readFileSync, writeFileSync } from 'node:fs';
import { test, expect, chromium, type BrowserContext, type Page, type Worker } from '@playwright/test';

const SITE = 'https://login.pevv.test';
const PW = 'correct horse battery staple 42!';
const LOGIN_HTML = '<!doctype html><html><body><form><input id="u" type="email"><input id="p" type="password"></form></body></html>';

interface Ext { ctx: BrowserContext; sw: Worker; id: string }

async function fresh(name: string, dir: string): Promise<Ext> {
  const ext = `${dir}/ext-${name}`;
  cpSync('dist-extension', ext, { recursive: true });
  const manifest = JSON.parse(readFileSync(`${ext}/manifest.json`, 'utf8')) as Record<string, unknown>;
  manifest.host_permissions = [`${SITE}/*`];
  writeFileSync(`${ext}/manifest.json`, JSON.stringify(manifest));
  const ctx = await chromium.launchPersistentContext(`${dir}/profile-${name}`, {
    channel: 'chromium',
    headless: !process.env.HEADED,
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  await ctx.route(`${SITE}/**`, (r) => r.fulfill({ status: 200, contentType: 'text/html', body: LOGIN_HTML }));
  await ctx.addInitScript(() => {
    try { localStorage.setItem('pevv-locale', JSON.stringify({ state: { locale: 'en' }, version: 0 })); } catch { /* opaque origin */ }
  });
  const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker'));
  return { ctx, sw, id: new URL(sw.url()).host };
}

/** No sync account session anywhere in the extension. */
async function expectNoAccount(page: Page): Promise<void> {
  expect(await page.evaluate(() => localStorage.getItem('pevv-sync-auth'))).toBeNull();
  expect(await page.evaluate(() => Object.keys(localStorage).filter((k) => k.startsWith('sb-')))).toEqual([]);
}

let a: Ext;
let b: Ext;

test.beforeAll(async ({ browserName: _b }, info) => {
  const dir = info.outputPath('.');
  a = await fresh('a', dir);
  b = await fresh('b', dir);
});
test.afterAll(async () => { await a?.ctx.close(); await b?.ctx.close(); });

test('a fresh profile with no sync account makes a vault, moves it by QR, and fills', async () => {
  test.skip(!process.env.PEVV_E2E_SYNC, 'needs a configured sync backend and relay');

  // Profile A: a new vault and one login. No sign-in screen, no account.
  const va = await a.ctx.newPage();
  await va.goto(`chrome-extension://${a.id}/extension/vault.html`);
  await va.getByTestId('pevv-mode-new').click();
  await va.getByTestId('pevv-setup-ack').check();
  await va.getByTestId('pevv-setup-password').fill(PW);
  await va.getByTestId('pevv-setup-confirm').fill(PW);
  await va.getByTestId('pevv-setup-submit').click();
  await expect(va.getByTestId('pevv-unlocked')).toBeVisible({ timeout: 60_000 });
  await va.getByTestId('pevv-new').click();
  await va.getByTestId('pevv-new-login').click();
  await va.getByTestId('pevv-f-title').fill('No-account site');
  await va.getByTestId('pevv-f-site').fill(SITE);
  await va.getByTestId('pevv-f-username').fill('grace@pevv.test');
  await va.getByTestId('pevv-f-password').fill('moved-by-qr');
  await va.getByTestId('pevv-save').click();
  await expectNoAccount(va);

  // Show the vault QR. It must never link chrome-extension://.
  await va.getByTestId('pevv-open-qr').click();
  await va.getByTestId('pevv-qr-share').click();
  await va.getByTestId('pevv-qr-password').fill(PW);
  await va.getByTestId('pevv-qr-submit').click();
  const qr = va.getByTestId('pevv-qr-image');
  await expect(qr).toBeVisible({ timeout: 60_000 });
  const shot = await qr.screenshot();

  // Profile B: "I already have a vault". The account route is not offered (no account, no sign-in screen here).
  const vb = await b.ctx.newPage();
  await vb.goto(`chrome-extension://${b.id}/extension/vault.html`);
  await vb.getByTestId('pevv-mode-have').click();
  await expect(vb.getByTestId('pevv-qr-scan-box')).toBeVisible();
  await expect(vb.getByTestId('pevv-setup-import-file')).toBeVisible();
  await expect(vb.getByTestId('pevv-from-account')).toHaveCount(0);
  await expect(vb.getByText(/sign in/i)).toHaveCount(0);
  await vb.getByTestId('pevv-qr-scan').click();
  await vb.getByTestId('pevv-qr-photo').setInputFiles({ name: 'qr.png', mimeType: 'image/png', buffer: shot });
  await expect(vb.getByTestId('pevv-unlock-password')).toBeVisible({ timeout: 60_000 });
  await vb.getByTestId('pevv-unlock-password').fill(PW);
  await vb.getByTestId('pevv-unlock-submit').click();
  await expect(vb.getByTestId('pevv-unlocked')).toBeVisible({ timeout: 60_000 });
  await expect(vb.getByText('No-account site')).toBeVisible();
  await expectNoAccount(vb);

  // B's popup unlocks the moved vault and fills it.
  await expect.poll(async () => b.sw.evaluate(async () => String((await chrome.storage.local.get('pevv.vault'))['pevv.vault'] ?? '')), { timeout: 15_000 }).toContain('"entries":[{');
  const site = await b.ctx.newPage();
  await site.goto(`${SITE}/login`);
  const pop = await b.ctx.newPage();
  await pop.goto(`chrome-extension://${b.id}/extension/popup.html`);
  await pop.getByTestId('ext-password').fill(PW);
  await pop.getByTestId('ext-unlock').click();
  await expect(pop.getByTestId('ext-popup')).toHaveAttribute('data-status', 'unlocked', { timeout: 30_000 });
  const tabId = await pop.evaluate(async (p) => (await chrome.tabs.query({})).find((t) => t.url?.startsWith(p))?.id ?? -1, SITE);
  const found = (await pop.evaluate((m) => chrome.runtime.sendMessage(m), { type: 'search', q: 'grace', url: `${SITE}/login` }) as { value: { id: string }[] }).value;
  await site.focus('#p');
  expect(await pop.evaluate((m) => chrome.runtime.sendMessage(m), { type: 'fill', tabId, url: `${SITE}/login`, id: found[0]!.id })).toMatchObject({ ok: true });
  await expect(site.locator('#u')).toHaveValue('grace@pevv.test');
  await expect(site.locator('#p')).toHaveValue('moved-by-qr');
});
