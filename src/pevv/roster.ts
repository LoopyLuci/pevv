/**
 * Keep the device list (and the rest of the sealed vault) current between
 * phones and computers that already hold this vault. No account and no QR:
 * both apps just have to be open. The master password never leaves the device.
 */
import type { VaultFile } from './model';
import { joinRoster, type RosterLink } from './host/relay';
import { onVaultWrite, reconcileRemote, usePevv } from './store';
import { validateFile } from './vault';

let started = false;

export function startDeviceRoster(): () => void {
  if (started) return () => undefined;
  started = true;
  let link: RosterLink | null = null;
  let joined = '';
  let ticket = 0;
  let closed = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let retry: ReturnType<typeof setTimeout> | null = null;
  let pending: VaultFile | null = null;

  let joining = false;
  let dirty = false;

  const publishNow = () => {
    const file = usePevv.getState().file;
    if (!link || !file || file.id !== joined) return;
    link.publish(JSON.stringify(file));
  };

  const accept = (body: string) => {
    let remote: VaultFile;
    try {
      remote = JSON.parse(body) as VaultFile;
      validateFile(remote);
    } catch { return; }
    if (remote.id !== joined) return;
    pending = remote;
    void reconcileRemote(remote, 'peer').then((ok) => {
      if (ok && pending === remote) pending = null;
    });
  };

  const retarget = async () => {
    if (closed) return;
    if (joining) { dirty = true; return; }
    const id = usePevv.getState().file?.id ?? '';
    if (id === joined && (id ? link : true)) {
      if (id) publishNow();
      return;
    }
    if (id && !/^[0-9a-f-]{8,64}$/i.test(id)) return;
    joining = true;
    dirty = false;
    const my = ++ticket;
    const prev = link;
    link = null;
    joined = id;
    pending = null;
    try {
      if (prev) await prev.close();
      if (closed || my !== ticket || !id) return;
      const next = await joinRoster(id, accept);
      if (closed || my !== ticket || usePevv.getState().file?.id !== id) {
        await next.close();
        return;
      }
      link = next;
      publishNow();
      if (usePevv.getState().status === 'unlocked') next.ask();
    } catch {
      if (my !== ticket || closed) return;
      joined = '';
      link = null;
      if (retry) clearTimeout(retry);
      retry = setTimeout(() => { retry = null; void retarget(); }, 5000);
    } finally {
      joining = false;
      if (dirty && !closed) {
        dirty = false;
        schedule();
      }
    }
  };

  const schedule = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => { timer = null; void retarget(); }, 400);
  };

  const offWrite = onVaultWrite(() => schedule());
  let was = usePevv.getState().status;
  const offStatus = usePevv.subscribe((s) => {
    const fid = s.file?.id ?? '';
    if (fid !== joined) schedule();
    if (s.status === was) return;
    was = s.status;
    if (s.status !== 'unlocked') return;
    if (pending && pending.id === s.file?.id) void reconcileRemote(pending, 'peer');
    link?.ask();
  });
  void retarget();

  return () => {
    closed = true;
    started = false;
    ticket += 1;
    offWrite();
    offStatus();
    if (timer) clearTimeout(timer);
    if (retry) clearTimeout(retry);
    const prev = link;
    link = null;
    if (prev) void prev.close();
  };
}
