/** The seams to the optional backend: with no build-time configuration PEVV must stay fully local. */
import { describe, expect, it } from 'vitest';
import { CLOUD_PATHS, currentAccount, pullCloud, sendMagicLink, syncEnabled, useCloudFiles } from '@/pevv/host/cloud';
import { SYNC_ANON_KEY, SYNC_URL, syncConfigured } from '@/pevv/host/config';
import { initLocale, useLocaleStore } from '@/pevv/host/locale';
import { FRAME, newTransferToken, pullTransfer, putTransfer, relayTopic, joinRoster, splitBody } from '@/pevv/host/relay';
import { cspFor } from '../../scripts/desktop-csp.mjs';

describe('sync is off when it is not configured', () => {
  it('reports no configuration and no account', () => {
    expect(SYNC_URL).toBe('');
    expect(SYNC_ANON_KEY).toBe('');
    expect(syncConfigured()).toBe(false);
    expect(syncEnabled()).toBe(false);
    expect(currentAccount()).toBeNull();
  });

  it('the cloud file store loads empty and never touches the network', async () => {
    await useCloudFiles.getState().initFiles();
    expect(useCloudFiles.getState().filesLoaded).toBe(true);
    expect(useCloudFiles.getState().files).toEqual([]);
    await expect(pullCloud()).resolves.toBeUndefined();
    await expect(sendMagicLink('a@example.test')).rejects.toThrow(/not configured/);
  });

  it('a vault of any size is cut into frames instead of being refused', () => {
    const body = 'q'.repeat(FRAME * 60 + 7);
    const parts = splitBody(body);
    expect(parts.length).toBe(61);
    expect(parts.every((p) => p.length <= FRAME)).toBe(true);
    expect(parts.join('')).toBe(body);
  });

  it('only the two vault paths are accepted, whatever the size of the body', () => {
    const { writeFile, readFile, removeFile } = useCloudFiles.getState();
    expect(() => writeFile('/vault/other.json', '{}')).toThrow('cloud-file-rejected');
    // No size cap: a body far past the old 262144 limit is written like any other.
    expect(writeFile(CLOUD_PATHS[0], 'x'.repeat(2_000_000)).body.length).toBe(2_000_000);
    expect(writeFile(CLOUD_PATHS[0], '{"a":1}').body).toBe('{"a":1}');
    expect(readFile(CLOUD_PATHS[0])?.body).toBe('{"a":1}');
    expect(removeFile(CLOUD_PATHS[0])).toBe(true);
    expect(readFile(CLOUD_PATHS[0])).toBeUndefined();
  });

  it('the vault-QR relay and device roster report qr-nosync', async () => {
    const token = newTransferToken();
    expect(relayTopic(token)).toBe(`pevv:${token}`);
    await expect(putTransfer(token, '{}')).rejects.toThrow('qr-nosync');
    await expect(pullTransfer(token)).rejects.toThrow('qr-nosync');
    await expect(joinRoster('0123456789abcdef01234567', () => undefined)).rejects.toThrow('qr-nosync');
  });
});

describe('language store', () => {
  it('switches the language and the document attributes', async () => {
    useLocaleStore.getState().setLocale('es');
    expect(useLocaleStore.getState().locale).toBe('es');
    expect(document.documentElement.lang).toBe('es');
    useLocaleStore.getState().setLocale('en');
    await initLocale();
    expect(document.documentElement.lang).toBe('en');
  });
});

describe('desktop build CSP', () => {
  const base = "default-src 'none'; connect-src 'self' ipc: http://ipc.localhost; object-src 'none'";

  it('has no network origin without a sync URL', () => {
    expect(cspFor(base, '')).toBe(base);
  });

  it('adds exactly the sync origin (https and wss) to connect-src', () => {
    expect(cspFor(base, 'https://abc.supabase.co/')).toBe("default-src 'none'; connect-src 'self' ipc: http://ipc.localhost https://abc.supabase.co wss://abc.supabase.co; object-src 'none'");
  });

  it('refuses a non-https or malformed URL', () => {
    expect(() => cspFor(base, 'http://abc.supabase.co')).toThrow(/https/);
    expect(() => cspFor(base, 'not a url')).toThrow(/not a URL/);
  });
});
