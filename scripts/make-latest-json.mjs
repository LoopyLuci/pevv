#!/usr/bin/env node
/**
 * Build the updater manifest `latest.json` that the desktop app fetches (tauri.conf.json > plugins.updater.endpoints).
 *
 *   node scripts/make-latest-json.mjs <assets-dir> <tag> <owner/repo> [notes]
 *
 * Looks in <assets-dir> for `*_x64-setup.exe` + `.sig` (Windows NSIS) and `*_amd64.AppImage` + `.sig` (Linux) and writes
 * <assets-dir>/latest.json with `windows-x86_64` and `linux-x86_64` entries. The `.sig` files are made by `tauri build`
 * when TAURI_SIGNING_PRIVATE_KEY is set. With no `.sig` at all (a fork or a build without the key) nothing is written
 * and the exit code is 0, so the release carries on without an update manifest. Only one of the two present: that
 * platform alone is listed.
 */
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Pure: file names + signatures in, manifest (or null when there is nothing signed) out. */
export function buildManifest({ files, readSig, tag, repo, notes = '', pubDate = new Date().toISOString() }) {
  const base = `https://github.com/${repo}/releases/download/${tag}`;
  const targets = [
    ['windows-x86_64', /_x64-setup\.exe$/],
    ['linux-x86_64', /_amd64\.AppImage$/],
  ];
  const platforms = {};
  for (const [key, re] of targets) {
    const name = files.find((f) => re.test(f) && files.includes(`${f}.sig`));
    if (!name) continue;
    platforms[key] = { signature: readSig(`${name}.sig`).trim(), url: `${base}/${encodeURIComponent(name)}` };
  }
  if (!Object.keys(platforms).length) return null;
  return { version: tag.replace(/^v/, ''), notes, pub_date: pubDate, platforms };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [dir, tag, repo, notes] = process.argv.slice(2);
  if (!dir || !tag || !repo) {
    console.error('usage: make-latest-json.mjs <assets-dir> <tag> <owner/repo> [notes]');
    process.exit(2);
  }
  const manifest = buildManifest({ files: readdirSync(dir), readSig: (n) => readFileSync(join(dir, n), 'utf8'), tag, repo, notes });
  if (!manifest) {
    console.log('No updater signatures found: latest.json not written (releases without TAURI_SIGNING_PRIVATE_KEY carry no update manifest).');
  } else {
    writeFileSync(join(dir, 'latest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`latest.json written for ${manifest.version}: ${Object.keys(manifest.platforms).join(', ')}`);
    if (!existsSync(join(dir, 'latest.json'))) process.exit(1);
  }
}
