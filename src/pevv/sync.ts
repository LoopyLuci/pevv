/**
 * Opt-in PEVV sync: mirrors ONLY the ciphertext VaultFile into the cloud file
 * store (host/cloud.ts) at /vault/pevv.vault.json, which is one opaque row in
 * your own Supabase project (docs/SYNC_SELF_HOSTING.md). Remote copies are adopted when
 * they are the same vault with a higher revision (last writer wins on `rev`).
 */
import { onCloudConflict, onCloudPushed, useCloudFiles } from './host/cloud';
import type { VaultFile } from './model';
import { markSynced, onVaultWrite, reconcileRemote, setPrefs, usePevv } from './store';
import { keyEpoch } from './merge';
import { validateFile } from './vault';
import { vaultRevokedLocally } from './devices';

export const SYNC_PATH = '/vault/pevv.vault.json';

let started = false;
let lastWritten = '';
let absorbed = '';

function mirror(file: VaultFile | null): void {
  const lq = useCloudFiles.getState();
  if (!lq.filesLoaded) return;
  // Turning sync off forgets the cloud copy. A later edit on a device that is
  // not syncing must not delete the copy the other device just published.
  if (!file) {
    if (lq.readFile(SYNC_PATH)) lq.removeFile(SYNC_PATH);
    lastWritten = '';
    absorbed = '';
    return;
  }
  if (!usePevv.getState().prefs.sync) return;
  const body = JSON.stringify(file);
  const existing = lq.readFile(SYNC_PATH)?.body;
  if (existing && existing !== body) {
    try {
      const remote = JSON.parse(existing) as VaultFile;
      validateFile(remote);
      // A desktop that still has the pre-pair copy must not overwrite the phone.
      if (remote.id === file.id && (keyEpoch(remote) > keyEpoch(file) || (keyEpoch(remote) === keyEpoch(file) && remote.rev > file.rev))) return;
    } catch { /* replace a file that is not a vault */ }
  }
  if (body === lastWritten || existing === body) return;
  lastWritten = body;
  lq.writeFile(SYNC_PATH, body);
}

function inbound(): void {
  const local = usePevv.getState();
  const f = useCloudFiles.getState().readFile(SYNC_PATH);
  if (!f || f.body === lastWritten || f.body === absorbed) return;
  // An existing vault only takes new items when this device opted in. The
  // device list is still merged, so a phone that enrolled last shows up here.
  try {
    const remote = JSON.parse(f.body) as unknown;
    validateFile(remote);
    if (vaultRevokedLocally(remote.id)) return;
    const hadVault = !!local.file;
    void reconcileRemote(remote, 'cloud').then((ok) => {
      if (!ok) return;
      absorbed = f.body;
      const cur = usePevv.getState().file;
      lastWritten = cur ? JSON.stringify(cur) : f.body;
      if (!hadVault) setPrefs({ sync: true });
    });
  } catch { /* ignore malformed remote copy */ }
}

export function startVaultSync(): () => void {
  if (started) return () => undefined;
  started = true;
  const offWrite = onVaultWrite((f) => mirror(f));
  // The server accepted our copy: it is now the base of the next three-way merge.
  const offPushed = onCloudPushed((path, body) => {
    if (path !== SYNC_PATH) return;
    try { const f = JSON.parse(body) as VaultFile; validateFile(f); markSynced(f); } catch { /* not a vault */ }
  });
  // Our write lost the compare-and-swap: another device wrote first. Merge its copy in, then the merged copy is written again.
  const offConflict = onCloudConflict((path) => {
    if (path !== SYNC_PATH) return;
    lastWritten = '';
    absorbed = '';
    inbound();
  });
  let prevFiles = useCloudFiles.getState().files;
  let prevSync = usePevv.getState().prefs.sync;
  const offFiles = useCloudFiles.subscribe((s) => {
    if (s.files === prevFiles) return;
    const first = prevFiles.length === 0 && s.filesLoaded;
    prevFiles = s.files;
    inbound();
    if (first) mirror(usePevv.getState().file);
  });
  const offPrefs = usePevv.subscribe((s) => {
    if (s.prefs.sync === prevSync) return;
    prevSync = s.prefs.sync;
    if (s.prefs.sync) { void useCloudFiles.getState().initFiles().then(() => { inbound(); mirror(usePevv.getState().file); }); } else mirror(null);
  });
  if (prevSync) void useCloudFiles.getState().initFiles().then(() => { inbound(); mirror(usePevv.getState().file); });
  else void useCloudFiles.getState().initFiles().then(() => inbound());
  return () => { offWrite(); offPushed(); offConflict(); offFiles(); offPrefs(); started = false; };
}
