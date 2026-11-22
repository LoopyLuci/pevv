/**
 * PEVV browser extension, end to end in real Chromium with the unpacked build.
 *
 * Playwright cannot click the toolbar button, which is what grants `activeTab`.
 * The test copy of the manifest stands in for that grant with a host permission
 * for the one test site. Everything else is the shipped build.
 */
import { cpSync, readFileSync, writeFileSync } from 'node:fs';
import { test, expect, chromium, type BrowserContext, type Page, type Worker } from '@playwright/test';

const SITE = 'https://login.pevv.test';
const PW = 'correct horse battery staple 42!';

const LOGIN_HTML = `<!doctype html><html><body>
<form id="login" onsubmit="event.preventDefault(); document.body.dataset.sent = '1'">
  <input id="u" name="email" type="email"><input id="p" name="password" type="password"><button id="go" type="submit">Sign in</button>
</form>
<form id="signup"><input id="nu" name="new-user"><input id="np1" type="password"><input id="np2" type="password"></form>
</body></html>`;

let ctx: BrowserContext;
let sw: Worker;
let extId: string;

test.beforeAll(async ({ browserName: _b }, info) => {
  const dir = info.outputPath('ext');
  cpSync('dist-extension', dir, { recursive: true });
  const manifest = JSON.parse(readFileSync(`${dir}/manifest.json`, 'utf8')) as Record<string, unknown>;
  manifest.host_permissions = [`${SITE}/*`];
  writeFileSync(`${dir}/manifest.json`, JSON.stringify(manifest));
  ctx = await chromium.launchPersistentContext(info.outputPath('profile'), {
    channel: 'chromium',
    headless: !process.env.HEADED,
    args: [`--disable-extensions-except=${dir}`, `--load-extension=${dir}`],
  });
  await ctx.route(`${SITE}/**`, (r) => r.fulfill({ status: 200, contentType: 'text/html', body: LOGIN_HTML }));
  await ctx.addInitScript(() => {
    try { localStorage.setItem('pevv-locale', JSON.stringify({ state: { locale: 'en' }, version: 0 })); } catch { /* opaque origin */ }
  });
  sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker'));
  extId = new URL(sw.url()).host;
});

test.afterAll(async () => { await ctx?.close(); });

type Reply = { ok: boolean; value?: unknown; error?: string };

async function send(pop: Page, m: unknown): Promise<Reply> {
  return pop.evaluate((msg) => chrome.runtime.sendMessage(msg), m) as Promise<Reply>;
}

async function tabIdOf(pop: Page, prefix: string): Promise<number> {
  const id = await pop.evaluate(async (p) => (await chrome.tabs.query({})).find((t) => t.url?.startsWith(p))?.id ?? null, prefix);
  expect(id).not.toBeNull();
  return id!;
}

test('vault screen → popup unlock → fill, generate, inline fill, save offer, lock', async () => {
  // 1. The vault screen is the standalone PEVV app. Make a vault and a login there.
  const vault = await ctx.newPage();
  await vault.goto(`chrome-extension://${extId}/extension/vault.html`);
  await vault.getByTestId('pevv-mode-new').click();
  await vault.getByTestId('pevv-setup-ack').check();
  await vault.getByTestId('pevv-setup-password').fill(PW);
  await vault.getByTestId('pevv-setup-confirm').fill(PW);
  await vault.getByTestId('pevv-setup-submit').click();
  await expect(vault.getByTestId('pevv-unlocked')).toBeVisible({ timeout: 60_000 });
  await vault.getByTestId('pevv-new').click();
  await vault.getByTestId('pevv-new-login').click();
  await vault.getByTestId('pevv-f-title').fill('PEVV test site');
  await vault.getByTestId('pevv-f-site').fill(SITE);
  await vault.getByTestId('pevv-f-username').fill('ada@pevv.test');
  await vault.getByTestId('pevv-f-password').fill('pw-1');
  await vault.getByTestId('pevv-save').click();

  // Only ciphertext reaches the extension store.
  await expect.poll(async () => sw.evaluate(async () => String((await chrome.storage.local.get('pevv.vault'))['pevv.vault'] ?? '')), { timeout: 15_000 }).toContain('"entries":[{');
  const stored = await sw.evaluate(async () => String((await chrome.storage.local.get(null))['pevv.vault']));
  expect(stored).not.toContain('pw-1');
  expect(stored).not.toContain('ada@pevv.test');

  // 2. Popup: locked → unlock with the master password.
  const site = await ctx.newPage();
  await site.goto(`${SITE}/login`);
  const pop = await ctx.newPage();
  await pop.goto(`chrome-extension://${extId}/extension/popup.html`);
  await expect(pop.getByTestId('ext-locked')).toBeVisible();
  await pop.setViewportSize({ width: 360, height: 640 });
  await pop.screenshot({ path: test.info().outputPath('popup-locked.png') });
  await pop.getByTestId('ext-password').fill('wrong password');
  await pop.getByTestId('ext-unlock').click();
  await expect(pop.getByTestId('ext-error')).toContainText(/wrong master password/i, { timeout: 30_000 });
  await pop.getByTestId('ext-password').fill(PW);
  await pop.getByTestId('ext-unlock').click();
  await expect(pop.getByTestId('ext-popup')).toHaveAttribute('data-status', 'unlocked', { timeout: 30_000 });
  await pop.getByTestId('ext-search').fill('ada');
  await expect(pop.getByTestId('ext-login')).toHaveCount(1);
  await pop.screenshot({ path: test.info().outputPath('popup-unlocked.png') });

  // 3. Fill the focused field from the popup.
  const tabId = await tabIdOf(pop, SITE);
  const found = (await send(pop, { type: 'search', q: 'ada', url: `${SITE}/login` })).value as { id: string; matches: boolean }[];
  expect(found[0]!.matches).toBe(true);
  await site.focus('#p');
  const r = await send(pop, { type: 'fill', tabId, url: `${SITE}/login`, id: found[0]!.id });
  expect(r).toMatchObject({ ok: true });
  await expect(site.locator('#u')).toHaveValue('ada@pevv.test');
  await expect(site.locator('#p')).toHaveValue('pw-1');

  // A login is never filled into a page with another origin, whatever the popup says.
  const wrong = await send(pop, { type: 'fill', tabId, url: 'https://evil.pevv.test/', id: found[0]!.id });
  expect(wrong).toMatchObject({ ok: false });

  // 4. Generate into the focused sign-up field (and its confirm field); it becomes a save offer.
  await site.focus('#np1');
  expect(await send(pop, { type: 'fill-generated', tabId, url: `${SITE}/login`, password: 'Gen-Pass-123!x' })).toMatchObject({ ok: true });
  await expect(site.locator('#np1')).toHaveValue('Gen-Pass-123!x');
  await expect(site.locator('#np2')).toHaveValue('Gen-Pass-123!x');
  const st1 = (await send(pop, { type: 'state', tabId, url: `${SITE}/login` })).value as { offer: { username: string } | null };
  expect(st1.offer).toMatchObject({ username: '' });
  await send(pop, { type: 'offer', tabId, action: 'dismiss' });

  // 5. Approve the site for the inline button: focus the field, click the key, it fills.
  expect(await send(pop, { type: 'settings', patch: { autofillOrigins: [SITE] } })).toMatchObject({ ok: true });
  await site.reload();
  await site.click('#p');
  const key = site.locator('pevv-fill');
  await expect(key).toBeVisible();
  await site.screenshot({ path: test.info().outputPath('inline-button.png'), clip: { x: 0, y: 0, width: 500, height: 80 } });
  await key.click();
  await expect(site.locator('#p')).toHaveValue('pw-1');
  await expect(site.locator('#u')).toHaveValue('ada@pevv.test');

  // 6. Change the password and sign in: PEVV offers to update, and saves into the same vault.
  const revBefore = JSON.parse(stored).rev as number;
  await site.fill('#p', 'pw-2-changed');
  await site.click('#go');
  await expect(site.locator('body')).toHaveAttribute('data-sent', '1');
  await expect.poll(async () => ((await send(pop, { type: 'state', tabId, url: `${SITE}/login` })).value as { offer: unknown }).offer).toMatchObject({ update: true, username: 'ada@pevv.test' });
  expect(await send(pop, { type: 'offer', tabId, action: 'save' })).toMatchObject({ ok: true });
  const after = JSON.parse(await sw.evaluate(async () => String((await chrome.storage.local.get(null))['pevv.vault']))) as { rev: number };
  expect(after.rev).toBeGreaterThan(revBefore);
  // The open vault screen folds the worker's write in.
  await expect.poll(async () => vault.evaluate(() => JSON.parse(localStorage.getItem('lv-pevv-vault-v1') ?? '{}').rev)).toBe(after.rev);

  await site.reload();
  await site.focus('#p');
  expect(await send(pop, { type: 'fill', tabId, url: `${SITE}/login`, id: found[0]!.id })).toMatchObject({ ok: true });
  await expect(site.locator('#p')).toHaveValue('pw-2-changed');

  // 7. Lock: nothing fills any more, from the popup or the inline button.
  expect(await send(pop, { type: 'lock' })).toMatchObject({ ok: true, value: 'locked' });
  await site.reload();
  await site.focus('#p');
  expect(await send(pop, { type: 'fill', tabId, url: `${SITE}/login`, id: found[0]!.id })).toMatchObject({ ok: false, error: 'The vault is locked.' });
  await site.click('#p');
  await site.locator('pevv-fill').click();
  await expect(site.locator('#p')).toHaveValue('');
});
