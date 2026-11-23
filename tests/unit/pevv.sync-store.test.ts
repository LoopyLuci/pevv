/**
 * Sync behaviour of the store on real objects: merge on reconcile, a locked device keeping its copy until the new one is
 * verified, and key rotation. (The shared cross-client scenarios are tests/unit/pevv.sync-scenarios.test.ts.)
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ARGON2_MIN, aad, sealJson } from '@/pevv/crypto';
import { emptyEntry } from '@/pevv/model';
import type { VaultFile } from '@/pevv/model';
import * as S from '@/pevv/store';
import * as V from '@/pevv/vault';
import { useSyncStatus } from '@/pevv/syncStatus';
import { aesKeyFromRaw } from '@/pevv/crypto';

const fast = async () => ({ alg: 'argon2id' as const, ...ARGON2_MIN, salt: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16)))) });
const state = () => S.usePevv.getState();
const titles = () => state().entries.map((e) => e.title).sort();

/** Another device: opens a copy of the vault with the password and makes its own edit. */
async function otherDevice(file: VaultFile, edit: (s: V.Session, meta: Awaited<ReturnType<typeof V.readMeta>>, f: VaultFile) => Promise<VaultFile>): Promise<VaultFile> {
  const s = await V.unlockWithPassword(file, 'pw');
  const meta = await V.readMeta(file, s);
  return edit(s, meta, file);
}

beforeEach(async () => {
  localStorage.clear();
  S.__setKdfFactory(fast);
  S.destroyVault();
  useSyncStatus.setState({ lastSyncedAt: 0, pending: false, busy: false, error: null, resolved: [], needsUnlock: false });
  await S.createVault('pw');
  S.setPrefs({ sync: true });
});
afterEach(() => { S.destroyVault(); });

describe('reconcile merges instead of replacing', () => {
  it('keeps the edits of both devices even when the other copy has a lower revision', async () => {
    await S.saveEntry(null, { title: 'alpha', type: 'login' });
    const base = state().file!;
    S.markSynced(base);
    const remote = await otherDevice(base, async (s, meta, f) => (await V.putEntry(f, s, meta, null, { ...emptyEntry('login'), title: 'from-phone' })).file);
    await S.saveEntry(null, { title: 'beta', type: 'login' });
    await S.saveEntry(null, { title: 'gamma', type: 'login' });
    expect(state().file!.rev).toBeGreaterThan(remote.rev);
    expect(await S.reconcileRemote(remote, 'peer')).toBe(true);
    expect(titles()).toEqual(['alpha', 'beta', 'from-phone', 'gamma']);
    expect(useSyncStatus.getState().pending).toBe(true);
  });

  it('keeps the loser of a same-item conflict inside the item and says so in plain data', async () => {
    const a = await S.saveEntry(null, { title: 'shared', type: 'login', password: 'p0' });
    const base = state().file!;
    S.markSynced(base);
    const remote = await otherDevice(base, async (s, meta, f) => {
      const data = { ...emptyEntry('login'), title: 'shared', password: 'from-phone', updated: Date.now() + 60_000 };
      return (await V.putEntry(f, s, meta, a.id, data)).file;
    });
    await S.saveEntry(a.id, { password: 'from-laptop' });
    expect(await S.reconcileRemote(remote, 'peer')).toBe(true);
    const item = state().entries.find((e) => e.id === a.id)!;
    expect(item.password).toBe('from-phone');
    expect(item.conflicts).toHaveLength(1);
    expect(item.conflicts![0]!.data.password).toBe('from-laptop');
    expect(useSyncStatus.getState().resolved.map((c) => `${c.kind}/${c.kept}`)).toEqual(['edited-both/remote']);
  });

  it('refuses a copy that was written by a revoked device', async () => {
    await S.saveEntry(null, { title: 'alpha', type: 'login' });
    const base = state().file!;
    S.markSynced(base);
    const revokedId = 'deadbeef-0000-0000-0000-000000000001';
    const remote = await otherDevice(base, async (s, meta, f) => {
      V.setWriterId(revokedId);
      try { return (await V.putEntry(f, s, meta, null, { ...emptyEntry('login'), title: 'planted' })).file; } finally { V.setWriterId(undefined); }
    });
    await S.updateMeta({ revokedDevices: [revokedId] });
    expect(await S.reconcileRemote(remote, 'peer')).toBe(false);
    expect(titles()).toEqual(['alpha']);
    expect(useSyncStatus.getState().error).toBe('rejected-revoked');
  });
});

describe('a locked device does not trust a newer copy it cannot check', () => {
  it('keeps its copy, holds the new one back and refuses it at the next unlock when it does not authenticate', async () => {
    await S.saveEntry(null, { title: 'precious', type: 'login' });
    const mine = state().file!;
    S.lock('manual');
    // Higher revision, same vault id, valid shape, sealed under somebody else's key.
    const evil = await aesKeyFromRaw(crypto.getRandomValues(new Uint8Array(32)));
    const forged: VaultFile = { ...mine, rev: mine.rev + 50, meta: await sealJson(evil, { environments: ['x'] }, aad.meta(mine.id, mine.rev + 50)), entries: [] };
    expect(await S.reconcileRemote(forged, 'cloud')).toBe(false);
    expect(state().file).toEqual(mine);
    expect(JSON.parse(localStorage.getItem(S.VAULT_KEY) ?? '{}').rev).toBe(mine.rev);
    await S.unlockPassword('pw');
    await expect.poll(() => useSyncStatus.getState().error).toBe('rejected-key');
    expect(state().file!.rev).toBeLessThan(forged.rev);
    expect(titles()).toEqual(['precious']);
  });

  it('merges a genuine newer copy at the next unlock', async () => {
    await S.saveEntry(null, { title: 'one', type: 'login' });
    const base = state().file!;
    S.markSynced(base);
    const remote = await otherDevice(base, async (s, meta, f) => (await V.putEntry(f, s, meta, null, { ...emptyEntry('login'), title: 'two' })).file);
    S.lock('manual');
    expect(await S.reconcileRemote(remote, 'cloud')).toBe(false);
    expect(state().file).toEqual(base);
    await S.unlockPassword('pw');
    await expect.poll(titles).toEqual(['one', 'two']);
  });
});

describe('key rotation in the store', () => {
  it('re-keys the vault, keeps every item, refuses a wrong password and turns away stale-key copies', async () => {
    await S.saveEntry(null, { title: 'keep me', type: 'login', password: 'secret' });
    const before = state().file!;
    await expect(S.rotateKey('not the password')).rejects.toThrow();
    expect(state().file).toEqual(before);
    const r = await S.rotateKey('pw');
    expect(r.dropped).toEqual([]);
    const f = state().file!;
    expect(f.v).toBe(2);
    expect(f.keyEpoch).toBe(1);
    expect(titles()).toEqual(['keep me']);
    S.lock('manual');
    await expect(S.unlockPassword('not the password')).rejects.toThrow();
    await S.unlockPassword('pw');
    expect(state().entries[0]!.password).toBe('secret');
    // The copy from before the rotation (old key, epoch 0) is turned away even though a device might hold it.
    expect(await S.reconcileRemote({ ...before, rev: f.rev + 10 }, 'peer')).toBe(false);
    expect(useSyncStatus.getState().error).toBe('rejected-stale-key');
    // A client that only knows v1 refuses the rotated file instead of mixing keys.
    expect(f.v === 1).toBe(false);
  });
});
