import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath, URL } from 'node:url';

/** Tauri serves index.html; the entry here is desktop.html so it does not clash with the web app's index.html. */
function asIndex(): Plugin {
  return {
    name: 'pevv-desktop-index',
    enforce: 'post',
    generateBundle(_o, bundle) {
      const page = bundle['desktop.html'];
      if (!page) return;
      page.fileName = 'index.html';
      bundle['index.html'] = page;
      delete bundle['desktop.html'];
    },
  };
}

/** PEVV desktop (Tauri) web build: the vault UI only. Output feeds desktop/src-tauri. */
export default defineConfig({
  plugins: [react(), tailwindcss(), asIndex()],
  base: '/',
  publicDir: false,
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: { port: 1421, strictPort: true },
  build: {
    outDir: 'dist-desktop',
    emptyOutDir: true,
    rollupOptions: { input: fileURLToPath(new URL('./desktop.html', import.meta.url)) },
  },
});
