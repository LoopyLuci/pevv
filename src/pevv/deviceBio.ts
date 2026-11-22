/** Android app bridge. The password is sealed in the device keystore; the page never stores it. */
type VaultBioBridge = {
  can(): string;
  enrolled(): string;
  arm(password: string): void;
  unlock(): void;
  clear(): void;
};

function bridge(): VaultBioBridge | null {
  if (typeof window === 'undefined') return null;
  return (window as unknown as { LuciVault?: VaultBioBridge }).LuciVault ?? null;
}

export function vaultBioAvailable(): boolean {
  return bridge()?.can() === '1';
}

export function vaultBioEnrolled(): boolean {
  return bridge()?.enrolled() === '1';
}

/** After a password unlock, ask the phone to remember it behind biometrics. A cancel skips it until the next launch. */
export function armVaultBio(password: string): void {
  const bio = bridge();
  if (!bio || bio.can() !== '1' || bio.enrolled() === '1' || !password) return;
  try {
    if (sessionStorage.getItem('pevv.bio.skip') === '1') return;
  } catch { /* private mode */ }
  const w = window as unknown as { __luciVaultArmed?: (ok: boolean) => void };
  w.__luciVaultArmed = (ok) => {
    if (!ok) try { sessionStorage.setItem('pevv.bio.skip', '1'); } catch { /* ignore */ }
  };
  bio.arm(password);
}

export function unlockVaultBio(): void {
  bridge()?.unlock();
}

export function clearVaultBio(): void {
  bridge()?.clear();
}
