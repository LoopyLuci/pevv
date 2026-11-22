/** The standalone PEVV app: the vault UI plus the optional sync, device roster and vault-QR pull. */
import { Suspense, lazy, useEffect } from 'react';
import { openVault, startQrPull } from '../store';
import { startVaultSync } from '../sync';
import { startDeviceRoster } from '../roster';
import { startSync } from '../host/cloud';

const VaultApp = lazy(() => import('./VaultApp').then((m) => ({ default: m.VaultApp })));

export function PevvStandalone() {
  useEffect(() => {
    document.documentElement.classList.add('lv-pevv-app');
    openVault();
    startSync();
    const stop = startVaultSync();
    const stopRoster = startDeviceRoster();
    const stopQr = startQrPull();
    return () => { stop(); stopRoster(); stopQr(); };
  }, []);
  return (
    <div className="flex h-full min-h-0 flex-col bg-[#070b16] text-ink-primary" data-testid="pevv-standalone">
      <Suspense fallback={<p className="p-6 text-sm text-ink-muted">Loading</p>}>
        <VaultApp />
      </Suspense>
    </div>
  );
}
