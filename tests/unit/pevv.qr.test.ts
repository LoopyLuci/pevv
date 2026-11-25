/** PEVV QR handoff: offline frames round-trip, tamper detection, short-lived sealed handoff. */
import qrcode from 'qrcode-generator';
import { describe, expect, it, vi } from 'vitest';
import type { VaultFile } from '@/pevv/model';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FRAME_CHUNK, FrameAssembler, MAX_FRAMES, MAX_FRAME_VERSION, QR_LEVEL, QR_MARGIN, openHandoff, packVault, parseScan, sealHandoff, shareUrl, splitFrames, unpackFrames } from '@/pevv/qr';
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

  it('packs a large vault into many scannable codes instead of refusing it', async () => {
    const noise = crypto.getRandomValues(new Uint8Array(48_000));
    const extra = Buffer.from(noise).toString('base64url');
    const frames = await packVault(vault(extra));
    expect(frames.length).toBeGreaterThan(48);
    expect(frames.length).toBeLessThanOrEqual(MAX_FRAMES);
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

/** Shared with the Android tests (QrFramesTest.kt): both sides must cut, collect and size codes the same way. */
const vectors = JSON.parse(readFileSync(join(process.cwd(), 'android', 'app', 'src', 'test', 'resources', 'vectors', 'qr-frames.json'), 'utf8')) as {
  chunk: number; maxFrames: number; maxVersion: number;
  split: { data: string; crc: string; frames: string[] }[];
  assemble: { name: string; input: string[]; progress: ([number, number] | null)[] }[];
  versions: { text: string; level: string; version: number }[];
};

/** The lowest QR version that holds the text, found by trying each one. */
function lowestVersion(text: string, level: 'L' | 'M' | 'Q' | 'H'): number {
  for (let v = 1; v <= 40; v++) {
    try {
      const qr = qrcode(v as Parameters<typeof qrcode>[0], level);
      qr.addData(text);
      qr.make();
      return v;
    } catch { /* too small */ }
  }
  throw new Error('too big');
}

describe('PEVV QR frames: shared vectors', () => {
  it('uses the constants the vectors were made with', () => {
    expect(FRAME_CHUNK).toBe(vectors.chunk);
    expect(MAX_FRAMES).toBe(vectors.maxFrames);
    expect(MAX_FRAME_VERSION).toBe(vectors.maxVersion);
    expect(QR_LEVEL).toBe('M');
    expect(QR_MARGIN).toBeGreaterThanOrEqual(4);
  });

  it('cuts data into the same frames', () => {
    for (const c of vectors.split) expect(splitFrames(c.data, c.crc)).toEqual(c.frames);
    expect(() => splitFrames('x'.repeat(FRAME_CHUNK * MAX_FRAMES + 1), 'aaaaaaaa')).toThrow('qr-too-big');
  });

  it('collects frames in any order, with repeats, and drops a stale set', () => {
    for (const c of vectors.assemble) {
      const asm = new FrameAssembler();
      const seen = c.input.map((raw) => { const r = asm.add(raw); return r ? [r.got, r.need] : null; });
      expect(seen, c.name).toEqual(c.progress);
    }
  });

  it('reassembles every split vector and ends complete', async () => {
    for (const c of vectors.split) {
      const asm = new FrameAssembler();
      let last = null;
      for (const f of [...c.frames].reverse()) last = asm.add(f);
      expect(last?.complete).toBe(true);
      expect(asm.frames()).toHaveLength(c.frames.length);
    }
  });

  it('picks the lowest QR version and keeps every frame within the scannable limit', () => {
    for (const v of vectors.versions) {
      const qr = qrcode(0, QR_LEVEL);
      qr.addData(v.text);
      qr.make();
      expect((qr.getModuleCount() - 17) / 4, v.text).toBe(v.version);
      expect(lowestVersion(v.text, QR_LEVEL), v.text).toBe(v.version);
    }
    for (const c of vectors.split) for (const f of c.frames) expect(lowestVersion(f, QR_LEVEL)).toBeLessThanOrEqual(MAX_FRAME_VERSION);
  });
});
