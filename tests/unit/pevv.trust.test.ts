import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ARGON2_MIN } from '@/pevv/crypto';
import { toBytes } from '@/pevv/bytes';
import * as S from '@/pevv/store';
import { totpAt, type TotpConfig } from '@/pevv/totp';
import { RECHECK_WINDOW_MS, __setDeviceMac, asRecheck, trustFresh } from '@/pevv/trust';

const fast = async () => ({ alg: 'argon2id' as const, ...ARGON2_MIN, salt: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))) });
const PW = 'my long master password';
const T0 = Date.UTC(2030, 0, 15, 12, 0, 0);
const DAY = 24 * 3_600_000;

/** A device-local secret like the IndexedDB key: HMAC under a key the test never exposes to the stored record. */
async function installDeviceKey(): Promise<void> {
  const k = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  __setDeviceMac(async (d) => toBytes(await crypto.subtle.sign('HMAC', k, d)));
}

const st = () => S.usePevv.getState();
const TRUST_KEY = () => Object.keys(localStorage).find((k) => k.startsWith('lv-pevv-2fa-trust:'))!;

async function codeNow(cfg: TotpConfig) { return totpAt(cfg, Date.now()); }

/** Vault with an authenticator, set to `freq`, locked. Time is faked; every step moves the clock by 31 s so codes never repeat. */
async function setup(freq: Parameters<typeof S.setSecondFactorRecheck>[0]): Promise<TotpConfig> {
  await S.createVault(PW);
  const cfg = S.startTotpEnrollment();
  await S.confirmTotpEnrollment(cfg, await codeNow(cfg));
  vi.setSystemTime(Date.now() + 31_000);
  await S.setSecondFactorRecheck(freq, await codeNow(cfg));
  S.lock();
  return cfg;
}

async function tick(ms: number) { vi.setSystemTime(Date.now() + ms); }

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(T0);
  localStorage.clear();
  S.__resetForTests();
  S.__setKdfFactory(fast);
  await installDeviceKey();
});
afterEach(async () => {
  await new Promise((r) => setTimeout(r, 60)); // let the unlock's background device write finish before the reset
  S.__resetForTests();
  __setDeviceMac(null);
  vi.useRealTimers();
});

describe('trustFresh (window logic)', () => {
  const now = T0;
  it('every login never trusts', () => {
    expect(trustFresh('login', now - 1000, now)).toBe(false);
  });
  it('daily, weekly, monthly windows', () => {
    expect(trustFresh('daily', now - DAY + 1, now)).toBe(true);
    expect(trustFresh('daily', now - DAY, now)).toBe(false);
    expect(trustFresh('weekly', now - 7 * DAY + 1, now)).toBe(true);
    expect(trustFresh('weekly', now - 7 * DAY, now)).toBe(false);
    expect(trustFresh('monthly', now - RECHECK_WINDOW_MS.monthly + 1, now)).toBe(true);
    expect(trustFresh('monthly', now - 30 * DAY, now)).toBe(false);
  });
  it('new device trusts any past verification', () => {
    expect(trustFresh('new-device', now - 400 * DAY, now)).toBe(true);
  });
  it('a timestamp in the future (clock rolled back) is expired, whatever the setting', () => {
    for (const f of ['daily', 'weekly', 'monthly', 'new-device'] as const) expect(trustFresh(f, now + 1, now)).toBe(false);
  });
  it('rejects junk timestamps', () => {
    expect(trustFresh('daily', NaN, now)).toBe(false);
    expect(trustFresh('daily', 0, now)).toBe(false);
    expect(trustFresh('daily', -5, now)).toBe(false);
  });
  it('unknown settings mean every login', () => {
    expect(asRecheck('hourly')).toBe('login');
    expect(asRecheck(undefined)).toBe('login');
    expect(asRecheck('weekly')).toBe('weekly');
  });
});

describe('authenticator frequency in the store', () => {
  it('default is every login', async () => {
    await S.createVault(PW);
    const cfg = S.startTotpEnrollment();
    await S.confirmTotpEnrollment(cfg, await codeNow(cfg));
    S.lock();
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
  });

  it('daily: skips the code inside the window, asks again after it', async () => {
    const cfg = await setup('daily');
    await tick(DAY / 2);
    await S.unlockPassword(PW);
    expect(st().status).toBe('unlocked');
    S.lock();
    await tick(DAY);
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
    await S.verifySecondTotp(await codeNow(cfg));
    expect(st().status).toBe('unlocked');
    S.lock();
    await tick(1000);
    await S.unlockPassword(PW);
    expect(st().status).toBe('unlocked');
  });

  it('the master password is still required (a wrong one gets nowhere)', async () => {
    await setup('monthly');
    await expect(S.unlockPassword('not the password at all')).rejects.toThrow();
    expect(st().status).toBe('locked');
  });

  it('clock rolled back: a verification dated in the future is expired', async () => {
    await setup('weekly');
    await tick(-2 * DAY);
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
  });

  it('new-device: a device that never passed asks once, then never again', async () => {
    const cfg = await setup('new-device');
    await tick(300 * DAY);
    await S.unlockPassword(PW);
    expect(st().status).toBe('unlocked');
    S.lock();
    // A fresh device: same vault copy, no local record.
    localStorage.removeItem(TRUST_KEY());
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
    await S.verifySecondTotp(await codeNow(cfg));
    S.lock();
    await tick(5 * DAY);
    await S.unlockPassword(PW);
    expect(st().status).toBe('unlocked');
  });

  it('editing the stored record does not forge trust', async () => {
    await setup('daily');
    const key = TRUST_KEY();
    const rec = JSON.parse(localStorage.getItem(key)!) as { t: number; mac: string };
    await tick(2 * DAY); // expired
    localStorage.setItem(key, JSON.stringify({ ...rec, t: Date.now() }));
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
    S.lock();
    localStorage.setItem(key, JSON.stringify({ t: Date.now(), mac: 'AAAA' }));
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
  });

  it('a record copied from another device (other device secret) is rejected', async () => {
    await setup('monthly');
    const copied = localStorage.getItem(TRUST_KEY())!;
    S.lock();
    await installDeviceKey(); // this "device" has a different secret
    localStorage.setItem(TRUST_KEY(), copied);
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
  });

  it('no device secret available means nothing is trusted', async () => {
    await setup('monthly');
    S.lock();
    __setDeviceMac(async () => null);
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
  });

  it('changing the setting needs a valid current code', async () => {
    await S.createVault(PW);
    const cfg = S.startTotpEnrollment();
    await S.confirmTotpEnrollment(cfg, await codeNow(cfg));
    vi.setSystemTime(Date.now() + 31_000);
    await expect(S.setSecondFactorRecheck('monthly', '000000')).rejects.toThrow(/not valid/);
    expect(st().meta?.secondFactorRecheck).toBeUndefined();
    await S.setSecondFactorRecheck('monthly', await codeNow(cfg));
    expect(st().meta?.secondFactorRecheck).toBe('monthly');
  });

  it('refuses when no authenticator is on', async () => {
    await S.createVault(PW);
    await expect(S.setSecondFactorRecheck('weekly', '123456')).rejects.toThrow(/authenticator/i);
  });

  it('a password change resets the trust', async () => {
    await setup('monthly');
    await S.unlockPassword(PW);
    expect(st().status).toBe('unlocked');
    await S.reauthPassword(PW);
    await S.changeMasterPassword('another long master password');
    S.lock();
    await S.unlockPassword('another long master password');
    expect(st().status).toBe('second-factor');
  });

  it('revoking a device resets the trust', async () => {
    await setup('monthly');
    await S.unlockPassword(PW);
    await S.revokeDevice('11111111-2222-3333-4444-555555555555');
    S.lock();
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
  });

  it('key rotation resets the trust', async () => {
    await setup('monthly');
    await S.unlockPassword(PW);
    await S.rotateKey(PW);
    S.lock();
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
  });

  it('replacing the authenticator resets the trust', async () => {
    await setup('monthly');
    await S.unlockPassword(PW);
    const old = localStorage.getItem(TRUST_KEY())!;
    await S.disableTotp();
    const cfg2 = S.startTotpEnrollment();
    vi.setSystemTime(Date.now() + 31_000);
    await S.confirmTotpEnrollment(cfg2, await codeNow(cfg2));
    S.lock();
    // The record made before the swap no longer counts.
    localStorage.setItem(TRUST_KEY(), old);
    await S.unlockPassword(PW);
    expect(st().status).toBe('second-factor');
  });
});
