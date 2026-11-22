#!/usr/bin/env node
/**
 * Build the PEVV browser extension (MV3).
 *
 *   npm run build:extension        → dist-extension/          Chrome, Edge, Brave (load unpacked)
 *                                    dist-extension-firefox/  Firefox (about:debugging → Load Temporary Add-on)
 *   npm run package:extension      → also dist-extension-zips/pevv-extension-{chromium,firefox}-<version>.zip
 *
 * Three passes, because a service worker cannot load split chunks and a content
 * script cannot be an ES module:
 *   1. extension pages (popup + vault screen), normal Vite build
 *   2. worker.js, one ES file (Argon2id WebAssembly inlined)
 *   3. content.js, one classic script
 * Then extension/icons (the PEVV logo) and extension/manifest.json are copied as is (its `version` is the extension's),
 * and the same files get a Firefox manifest (scripts/extension-package.mjs).
 */
import { build } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath, URL } from 'node:url';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { firefoxManifest, zipDir } from './extension-package.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const outDir = process.env.PEVV_EXT_OUT ?? fileURLToPath(new URL('../dist-extension', import.meta.url));
const alias = { '@': fileURLToPath(new URL('../src', import.meta.url)) };
const src = (p) => fileURLToPath(new URL(`../${p}`, import.meta.url));

const common = { root, configFile: false, publicDir: false, logLevel: 'warn', resolve: { alias } };

await build({
  ...common,
  plugins: [react(), tailwindcss()],
  base: '/',
  build: {
    outDir,
    emptyOutDir: true,
    rollupOptions: { input: { popup: src('extension/popup.html'), vault: src('extension/vault.html') } },
  },
});

for (const [name, format] of [['worker', 'es'], ['content', 'iife']]) {
  await build({
    ...common,
    build: {
      outDir,
      emptyOutDir: false,
      copyPublicDir: false,
      lib: { entry: src(`src/pevv/extension/${name}.ts`), formats: [format], name: `pevv_${name}`, fileName: () => `${name}.js` },
      rollupOptions: { output: { inlineDynamicImports: true } },
      minify: true,
    },
  });
}

const manifest = JSON.parse(readFileSync(src('extension/manifest.json'), 'utf8'));
const extVersion = manifest.version;
mkdirSync(outDir, { recursive: true });
cpSync(src('extension/icons'), `${outDir}/icons`, { recursive: true }); // the PEVV padlock (manifest icons)
writeFileSync(`${outDir}/manifest.json`, JSON.stringify(manifest, null, 2) + '\n');
console.log(`PEVV extension ${extVersion} → ${outDir}`);

const ffDir = `${outDir}-firefox`;
rmSync(ffDir, { recursive: true, force: true });
cpSync(outDir, ffDir, { recursive: true });
writeFileSync(`${ffDir}/manifest.json`, JSON.stringify(firefoxManifest(manifest), null, 2) + '\n');
console.log(`PEVV extension ${extVersion} (Firefox) → ${ffDir}`);

if (process.argv.includes('--zip')) {
  const zipOut = `${outDir}-zips`;
  mkdirSync(zipOut, { recursive: true });
  for (const [flavor, dir] of [['chromium', outDir], ['firefox', ffDir]]) {
    const file = `${zipOut}/pevv-extension-${flavor}-${extVersion}.zip`;
    writeFileSync(file, zipDir(dir));
    console.log(`  ${file}`);
  }
}
