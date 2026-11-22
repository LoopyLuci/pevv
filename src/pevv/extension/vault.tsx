/**
 * The extension's vault screen: the same standalone PEVV app the Android app
 * ships (items, import, vault QR, devices, settings), opened as an extension
 * tab. It shares the ciphertext with the service worker through bridge.ts.
 */
import '../../styles/globals.css';
import { seedPage, startBridge } from './bridge';

async function boot(): Promise<void> {
  document.documentElement.classList.add('lv-pevv-app', 'lv-pevv-ext');
  await seedPage();
  const [{ StrictMode, createElement }, { createRoot }, { initLocale }, store, { PevvStandalone }] = await Promise.all([
    import('react'),
    import('react-dom/client'),
    import('../host/locale'),
    import('../store'),
    import('../ui/PevvStandalone'),
  ]);
  startBridge({
    onVaultWrite: store.onVaultWrite,
    reconcileRemote: store.reconcileRemote,
    adoptRemote: store.adoptRemote,
    hasFile: () => !!store.usePevv.getState().file,
  });
  void initLocale();
  createRoot(document.getElementById('root')!).render(createElement(StrictMode, null, createElement(PevvStandalone)));
}

void boot();
