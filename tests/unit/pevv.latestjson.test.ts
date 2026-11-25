import { describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs script without types
import { buildManifest } from '../../scripts/make-latest-json.mjs';

const sigs: Record<string, string> = { 'PEVV_0.2.0_x64-setup.exe.sig': 'SIGWIN\n', 'PEVV_0.2.0_amd64.AppImage.sig': 'SIGLIN\n' };
const readSig = (n: string) => sigs[n]!;
const base = { readSig, tag: 'v0.2.0', repo: 'LoopyLuci/pevv', pubDate: '2026-01-01T00:00:00.000Z' };

describe('make-latest-json', () => {
  it('lists the Windows NSIS installer and the Linux AppImage with their signatures', () => {
    const files = ['PEVV_0.2.0_x64-setup.exe', 'PEVV_0.2.0_x64-setup.exe.sig', 'PEVV_0.2.0_x64_en-US.msi', 'PEVV_0.2.0_amd64.AppImage', 'PEVV_0.2.0_amd64.AppImage.sig', 'pevv_0.2.0_amd64.deb'];
    const m = buildManifest({ ...base, files });
    expect(m.version).toBe('0.2.0');
    expect(m.platforms['windows-x86_64']).toEqual({ signature: 'SIGWIN', url: 'https://github.com/LoopyLuci/pevv/releases/download/v0.2.0/PEVV_0.2.0_x64-setup.exe' });
    expect(m.platforms['linux-x86_64']).toEqual({ signature: 'SIGLIN', url: 'https://github.com/LoopyLuci/pevv/releases/download/v0.2.0/PEVV_0.2.0_amd64.AppImage' });
  });

  it('writes nothing when no installer is signed', () => {
    expect(buildManifest({ ...base, files: ['PEVV_0.2.0_x64-setup.exe', 'PEVV_0.2.0_amd64.AppImage'] })).toBeNull();
  });

  it('lists only the platform that has a signature', () => {
    const m = buildManifest({ ...base, files: ['PEVV_0.2.0_x64-setup.exe', 'PEVV_0.2.0_x64-setup.exe.sig', 'PEVV_0.2.0_amd64.AppImage'] });
    expect(Object.keys(m.platforms)).toEqual(['windows-x86_64']);
  });
});
