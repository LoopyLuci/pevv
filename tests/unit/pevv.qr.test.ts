/** PEVV QR handoff: offline frames round-trip, tamper detection, short-lived sealed handoff. */
import qrcode from 'qrcode-generator';
import { describe, expect, it, vi } from 'vitest';
import type { VaultFile } from '@/pevv/model';
import { openHandoff, packVault, parseScan, sealHandoff, shareUrl, unpackFrames } from '@/pevv/qr';
import { splitBody, relayTopic, rosterTopic } from '@/pevv/host/relay';

function vault(extra = ''): VaultFile {
  return {
    format: 'luciverse.pevv',
    v: 1,
    id: 'vault-qr',
    created: 1,
    updated: 2,
    rev: 4,
    kdf: { alg: 'pbkdf2-sha256', iter: 600_000, salt: 'c2FsdA' },
    slots: [{ id: 'slot', type: 'password', wrapped: { iv: 'aXY', ct: 'Y3Q' + extra } }],
    passkeys: [],
    require: { totp: false, passkey: false },
    totp: null,
    meta: { iv: 'bQ', ct: 'bWV0YQ' },
    entries: [],
  };
}

function fits(text: string): void {
  const qr = qrcode(0, 'L');
  qr.addData(text);
  qr.make();
  expect(qr.getModuleCount()).toBeGreaterThan(20);
}

describe('PEVV QR transfer', () => {
  it('round-trips a vault through offline codes, in any order', async () => {
    const file = vault('small');
    const frames = await packVault(file);
    expect(frames.length).toBeGreaterThan(0);
    expect(frames.length).toBeLessThanOrEqual(12);
    for (const frame of frames) fits(frame);
    const back = await unpackFrames([...frames].reverse());
    expect(back).toEqual(file);
  });

  it('rejects a damaged or incomplete code', async () => {
    const frames = await packVault(vault('x'));
    const broken = frames.map((f, i) => (i === 0 ? f.slice(0, -4) + 'AAAA' : f));
    await expect(unpackFrames(broken)).rejects.toThrow(/qr-damaged|qr-incomplete/);
    if (frames.length > 1) await expect(unpackFrames(frames.slice(1))).rejects.toThrow('qr-incomplete');
  });

  it('refuses a vault that will not fit in a scannable set of codes', async () => {
    const noise = crypto.getRandomValues(new Uint8Array(48_000));
    const extra = Buffer.from(noise).toString('base64url');
    await expect(packVault(vault(extra))).rejects.toThrow('qr-too-big');
  });

  it('seals a handoff the server cannot read, and expires it', async () => {
    const json = JSON.stringify(vault('handoff'));
    const now = 1_700_000_000_000;
    const sealed = await sealHandoff(json, now);
    expect(sealed.envelope.ct).not.toContain('vault-qr');
    expect(JSON.stringify(sealed.envelope)).not.toContain(sealed.key);
    await expect(openHandoff(sealed.envelope, sealed.key, now)).resolves.toBe(json);
    await expect(openHandoff(sealed.envelope, sealed.key, now + 4 * 60 * 1000)).rejects.toThrow('qr-expired');
    const bad = `${sealed.key[0] === 'A' ? 'B' : 'A'}${sealed.key.slice(1)}`;
    await expect(openHandoff(sealed.envelope, bad, now)).rejects.toThrow('qr-damaged');
    const url = shareUrl(`H.${sealed.key}`, 'https://vault.example.test/');
    expect(parseScan(url)).toEqual({ kind: 'handoff', key: sealed.key });
    const moved = shareUrl(`H.${sealed.key}.abcdefghij123456`, 'https://vault.example.test/');
    expect(parseScan(moved)).toEqual({ kind: 'handoff', key: sealed.key, xfer: 'abcdefghij123456' });
    expect(parseScan(moved.split('#')[0]!)).toEqual({ kind: 'handoff', key: sealed.key, xfer: 'abcdefghij123456' });
    expect(moved.startsWith('https://vault.example.test/?pevvq=')).toBe(true);
    expect(url.length).toBeLessThan(180);
    fits(url);
  });

  it('shows the bare code when the QR is shown inside the browser extension and no public URL is configured', () => {
    for (const href of ['chrome-extension://abcdefghijklmnop/extension/vault.html', 'moz-extension://1b5c0e4a-9a51-4f2f-9e4d-6e1f00c0ffee/extension/vault.html']) {
      vi.stubGlobal('location', new URL(href));
      try {
        expect(shareUrl('H.key.abcdefghij123456')).toBe('H.key.abcdefghij123456');
      } finally {
        vi.unstubAllGlobals();
      }
    }
    vi.stubGlobal('location', new URL('https://vault.example.test/pevv.html#x'));
    try {
      expect(shareUrl('H.key').startsWith('https://vault.example.test/pevv.html?pevvq=')).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('reads an offline frame out of a URL hash', async () => {
    const [frame] = await packVault(vault('url'));
    const url = shareUrl(frame!, 'https://vault.example.test/play');
    expect(parseScan(url)).toEqual({ kind: 'frame', frame });
  });

  it('splits a vault of any size into ordered frames', () => {
    const body = 'x'.repeat(100_000);
    const parts = splitBody(body, 48_000);
    expect(parts).toHaveLength(3);
    expect(parts.join('')).toBe(body);
    expect(relayTopic('abc_def-1234567890')).toBe('pevv:abc_def-1234567890');
    expect(rosterTopic('0123456789abcdef01234567')).toBe('pevv:d:0123456789abcdef01234567');
  });
});

describe('PEVV vault-QR public link', () => {
  it('uses VITE_PEVV_PUBLIC_URL for embedded surfaces when the build has one', async () => {
    vi.resetModules();
    vi.stubEnv('VITE_PEVV_PUBLIC_URL', 'https://vault.example.test/app/');
    vi.stubGlobal('location', new URL('chrome-extension://abcdefghijklmnop/extension/vault.html'));
    try {
      const mod = await import('@/pevv/qr');
      expect(mod.shareUrl('H.key.abcdefghij123456').startsWith('https://vault.example.test/app/?pevvq=')).toBe(true);
    } finally {
      vi.unstubAllGlobals();
      vi.unstubAllEnvs();
      vi.resetModules();
    }
  });
});
