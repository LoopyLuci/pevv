#!/usr/bin/env node
/**
 * Build the PEVV desktop app (Tauri 2): the web UI first, then the native bundles
 * (NSIS + MSI on Windows, AppImage + deb on Linux; see desktop/src-tauri/tauri.conf.json).
 *
 * The webview Content-Security-Policy only allows network access to the sync server
 * you configured. It is derived from VITE_PEVV_SYNC_URL at build time and passed to
 * `tauri build --config`, so nothing is hard-coded in tauri.conf.json. With no sync
 * URL the app has no network access at all.
 *
 *   npm run desktop:build [-- --debug --bundles nsis ...]   (extra args go to `tauri build`)
 *   PEVV_RP_ID=pevv.example.com   passkey rpId compiled into the shell (see docs/CLIENT_DESKTOP.md)
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';
import { cspFor } from './desktop-csp.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

function run(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: root, stdio: 'inherit', env: process.env });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await build({ root, configFile: fileURLToPath(new URL('../vite.desktop.config.ts', import.meta.url)) });
  const conf = JSON.parse(readFileSync(new URL('../desktop/src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
  const csp = cspFor(conf.app.security.csp, (process.env.VITE_PEVV_SYNC_URL ?? '').trim());
  const cli = fileURLToPath(new URL('../node_modules/@tauri-apps/cli/tauri.js', import.meta.url));
  run(process.execPath, [cli, 'build', '--config', JSON.stringify({ app: { security: { csp } } }), ...process.argv.slice(2)]);
}
