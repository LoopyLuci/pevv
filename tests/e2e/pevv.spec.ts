/** PEVV web app: create / lock / unlock, items, passkeys via a CDP virtual authenticator. */
import { test, expect, type Page } from '@playwright/test';

const PW = 'correct horse battery staple 42!';

async function prep(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('pevv-locale', JSON.stringify({ state: { locale: 'en' }, version: 0 }));
  });
}

async function createVault(page: Page) {
  const app = page.getByTestId('pevv-app');
  await expect(app).toBeVisible();
  await page.getByTestId('pevv-setup-ack').check();
  await page.getByTestId('pevv-setup-password').fill(PW);
  await page.getByTestId('pevv-setup-confirm').fill(PW);
  await page.getByTestId('pevv-setup-submit').click();
  await expect(page.getByTestId('pevv-unlocked')).toBeVisible({ timeout: 30_000 });
}

async function unlock(page: Page) {
  await page.getByTestId('pevv-unlock-password').fill(PW);
  await page.getByTestId('pevv-unlock-submit').click();
}

async function addAuthenticator(page: Page, hasPrf: boolean) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
      automaticPresenceSimulation: true, hasPrf,
    } as never,
  });
  return cdp;
}

test('create, add env var, lock wipes plaintext, wrong password, unlock', async ({ page }) => {
  await prep(page);
  await page.goto('/');
  await createVault(page);
  await page.getByTestId('pevv-new').click();
  await page.getByTestId('pevv-new-env').click();
  await page.getByTestId('pevv-f-name').fill('API_TOKEN');
  await page.getByTestId('pevv-f-value').fill('tok-123-SECRET');
  await page.getByTestId('pevv-save').click();
  await expect(page.getByTestId('pevv-list')).toContainText('API_TOKEN');
  const stored = await page.evaluate(() => localStorage.getItem('lv-pevv-vault-v1') ?? '');
  expect(stored).not.toContain('tok-123-SECRET');
  expect(stored).not.toContain(PW);
  await page.getByTestId('pevv-lock').click();
  await expect(page.getByTestId('pevv-locked')).toBeVisible();
  expect(await page.locator('body').innerText()).not.toContain('API_TOKEN');
  await page.getByTestId('pevv-unlock-password').fill('not the password at all');
  await page.getByTestId('pevv-unlock-submit').click();
  await expect(page.getByTestId('pevv-error')).toBeVisible({ timeout: 30_000 });
  await unlock(page);
  await expect(page.getByTestId('pevv-list')).toContainText('API_TOKEN', { timeout: 30_000 });
});

test('PRF passkey (virtual authenticator) unlocks without the password', async ({ page }) => {
  await prep(page);
  // WebAuthn rejects IP-literal RP IDs, so passkey tests use localhost.
  await page.goto('/');
  await addAuthenticator(page, true);
  await createVault(page);
  await page.getByTestId('pevv-nav-settings').click();
  await page.getByTestId('pevv-passkey-name').fill('Virtual key');
  await page.getByTestId('pevv-passkey-add').click();
  const mode = page.locator('[data-testid^=pevv-passkey-mode-]');
  await expect(mode).toBeVisible({ timeout: 30_000 });
  test.skip((await mode.getAttribute('data-testid')) !== 'pevv-passkey-mode-prf', 'this Chromium build has no virtual PRF');
  await page.getByTestId('pevv-lock').click();
  await page.getByTestId('pevv-unlock-passkey').click();
  await expect(page.getByTestId('pevv-unlocked')).toBeVisible({ timeout: 30_000 });
});

test('non-PRF security key works as a required second factor', async ({ page }) => {
  await prep(page);
  // WebAuthn rejects IP-literal RP IDs, so passkey tests use localhost.
  await page.goto('/');
  await addAuthenticator(page, false);
  await createVault(page);
  await page.getByTestId('pevv-nav-settings').click();
  await page.getByTestId('pevv-passkey-name').fill('Old key');
  await page.getByTestId('pevv-passkey-add').click();
  await expect(page.getByTestId('pevv-passkey-mode-2fa')).toBeVisible({ timeout: 30_000 });
  await page.getByTestId('pevv-require-passkey').check();
  await expect(page.getByTestId('pevv-require-passkey')).toBeChecked();
  await page.getByTestId('pevv-lock').click();
  await unlock(page);
  await expect(page.getByTestId('pevv-2fa-passkey')).toBeVisible({ timeout: 30_000 });
  await page.getByTestId('pevv-2fa-passkey').click();
  await expect(page.getByTestId('pevv-unlocked')).toBeVisible({ timeout: 30_000 });
});

test('M3: card with Luhn check, folder, CSV import, health score, activity log', async ({ page }) => {
  await prep(page);
  await page.goto('/');
  await createVault(page);
  // folder
  await page.getByTestId('pevv-add-folder').click();
  await page.getByTestId('pevv-add-folder-name').fill('Wallet');
  await page.getByTestId('pevv-add-folder-name').press('Enter');
  await expect(page.getByTestId('pevv-nav-folder-Wallet')).toBeVisible();
  // payment card: typo is flagged, then fixed
  await page.getByTestId('pevv-new').click();
  await page.getByTestId('pevv-new-card').click();
  await page.getByTestId('pevv-f-title').fill('Travel Visa');
  await page.getByTestId('pevv-f-number').fill('4111111111111112');
  await expect(page.getByTestId('pevv-card-luhn')).toBeVisible();
  await page.getByTestId('pevv-f-number').fill('4111111111111111');
  await expect(page.getByTestId('pevv-card-luhn')).toBeHidden();
  await page.getByTestId('pevv-f-expiry').fill('1/20');
  await page.getByTestId('pevv-f-cvv').fill('123');
  await page.getByTestId('pevv-f-folder').selectOption('Wallet');
  await page.getByTestId('pevv-save').click();
  await expect(page.getByTestId('pevv-card-face')).toContainText('Visa');
  await expect(page.getByTestId('pevv-card-expired')).toBeVisible();
  await expect(page.getByTestId('pevv-entry-number')).not.toContainText('4111');
  await page.getByTestId('pevv-nav-folder-Wallet').click();
  await expect(page.getByTestId('pevv-list')).toContainText('Travel Visa');
  const stored = await page.evaluate(() => localStorage.getItem('lv-pevv-vault-v1') ?? '');
  expect(stored).not.toContain('4111');
  // CSV import (Bitwarden format)
  await page.getByTestId('pevv-nav-settings').click();
  await page.getByTestId('pevv-import-csv').setInputFiles({
    name: 'bitwarden.csv', mimeType: 'text/csv',
    buffer: Buffer.from('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,Old Forum,,,0,http://forum.example,me,password,\n'),
  });
  await expect(page.getByTestId('pevv-settings')).toContainText('Imported 1 item(s) from bitwarden');
  // health
  await page.getByTestId('pevv-nav-health').click();
  await expect(page.getByTestId('pevv-health-score')).toBeVisible();
  await expect(page.getByTestId('pevv-health-insecure')).toContainText('Old Forum');
  await expect(page.getByTestId('pevv-health-cards-expired')).toContainText('Travel Visa');
  // activity
  await page.getByTestId('pevv-nav-activity').click();
  const act = page.getByTestId('pevv-activity-list');
  await expect(act.locator('[data-ev="create"]').first()).toBeVisible();
  await expect(act.locator('[data-ev="import"]')).toContainText('bitwarden CSV: 1');
  await expect(act).not.toContainText('4111');
});
