import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath, URL } from 'node:url';

/**
 * The standalone PEVV web app (index.html -> src/pevv/boot.tsx). Static files, host anywhere.
 * Sync is optional and read at build time: VITE_PEVV_SYNC_URL, VITE_PEVV_SYNC_ANON_KEY, VITE_PEVV_PUBLIC_URL
 * (docs/SYNC_SELF_HOSTING.md). Set `base` with VITE_PEVV_BASE when serving from a sub-path.
 */
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: process.env.VITE_PEVV_BASE ?? '/',
  publicDir: 'public',
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});
