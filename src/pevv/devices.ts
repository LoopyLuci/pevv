/**
 * Devices that hold a PEVV vault. The roster lives inside the sealed vault meta
 * (so it syncs and exports with the ciphertext). This device's id stays in
 * localStorage only — it is not an account id.
 *
 * Removing a device writes its id into the sealed revoked list. The copy on
 * that device wipes itself the next time it unlocks. A device that never syncs
 * again still has its local ciphertext until someone deletes it there.
 */
import type { VaultDevice } from './model';

const ID_KEY = 'lv-pevv-device-id';
const NAME_KEY = 'lv-pevv-device-name';
const REVOKED_KEY = 'lv-pevv-revoked-vaults';
const SEEN_WINDOW_MS = 60 * 60 * 1000;
export const DEVICE_SEEN_WINDOW_MS = SEEN_WINDOW_MS;
export const DEVICE_CAP = 40;

export function deviceKind(ua = userAgent()): VaultDevice['kind'] {
  if (/iPad|Tablet|PlayBook|Silk|Kindle/i.test(ua) || (/Android/i.test(ua) && !/Mobile/i.test(ua))) return 'tablet';
  if (/Mobi|iPhone|iPod|Android.+Mobile/i.test(ua)) return 'phone';
  if (/Windows|Macintosh|Linux|CrOS|X11/i.test(ua)) return 'desktop';
  return 'unknown';
}

export function deviceAgent(ua = userAgent()): string {
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\/|Opera/.test(ua) ? 'Opera' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad|iPod/.test(ua) ? 'iOS' : /Mac OS|Macintosh/.test(ua) ? 'macOS' : /Linux|CrOS|X11/.test(ua) ? 'Linux' : '';
  return [browser, os].filter(Boolean).join(' · ').slice(0, 80);
}

function userAgent(): string {
  try { return typeof navigator === 'undefined' ? '' : navigator.userAgent || ''; } catch { return ''; }
}

export function cleanDeviceName(name: string): string {
  // eslint-disable-next-line no-control-regex -- strip control characters from a device name
  return name.replace(/[\u0000-\u001f]/g, '').trim().slice(0, 40);
}

export function localDeviceId(): string {
  try {
    const cur = localStorage.getItem(ID_KEY);
    if (cur && /^[0-9a-f-]{16,64}$/i.test(cur)) return cur;
  } catch { /* private mode */ }
  const id = typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
  try { localStorage.setItem(ID_KEY, id); } catch { /* ignore */ }
  return id;
}

export function localDeviceName(): string {
  try { return cleanDeviceName(localStorage.getItem(NAME_KEY) ?? ''); } catch { return ''; }
}

export function setLocalDeviceName(name: string): void {
  const n = cleanDeviceName(name);
  try {
    if (n) localStorage.setItem(NAME_KEY, n);
    else localStorage.removeItem(NAME_KEY);
  } catch { /* ignore */ }
}

export function describeDevice(prev?: VaultDevice, now = Date.now()): VaultDevice {
  const kind = deviceKind();
  const agent = deviceAgent();
  const custom = localDeviceName();
  const auto = `${kind === 'phone' ? 'Phone' : kind === 'tablet' ? 'Tablet' : kind === 'desktop' ? 'Computer' : 'Device'}${agent ? ` · ${agent}` : ''}`;
  return {
    id: localDeviceId(),
    name: custom || prev?.name || auto,
    kind,
    added: prev?.added ?? now,
    seen: now,
    agent,
  };
}

export function asDevices(v: unknown): VaultDevice[] {
  if (!Array.isArray(v)) return [];
  const out: VaultDevice[] = [];
  for (const d of v) {
    if (!d || typeof d !== 'object') continue;
    const r = d as Partial<VaultDevice>;
    if (typeof r.id !== 'string' || !/^[0-9a-f-]{8,64}$/i.test(r.id)) continue;
    if (typeof r.name !== 'string') continue;
    const kind = r.kind === 'phone' || r.kind === 'tablet' || r.kind === 'desktop' || r.kind === 'unknown' ? r.kind : 'unknown';
    out.push({
      id: r.id,
      name: cleanDeviceName(r.name) || 'Device',
      kind,
      added: typeof r.added === 'number' ? r.added : 0,
      seen: typeof r.seen === 'number' ? r.seen : 0,
      agent: typeof r.agent === 'string' ? r.agent.slice(0, 80) : '',
    });
  }
  return out;
}

/** Union by id. A newer `seen` wins that device's name; `added` stays the earliest. */
export function mergeDevices(a: VaultDevice[], b: VaultDevice[]): VaultDevice[] {
  const map = new Map<string, VaultDevice>();
  for (const d of [...asDevices(a), ...asDevices(b)]) {
    const cur = map.get(d.id);
    if (!cur) { map.set(d.id, d); continue; }
    const newer = d.seen >= cur.seen ? d : cur;
    const older = newer === d ? cur : d;
    map.set(d.id, { ...newer, added: older.added && newer.added ? Math.min(older.added, newer.added) : (older.added || newer.added) });
  }
  return [...map.values()].sort((x, y) => y.seen - x.seen).slice(0, DEVICE_CAP);
}

export interface RosterSlice {
  devices: VaultDevice[];
  revokedDevices: string[];
}

/** Union of two rosters. A removed device stays removed even if the other copy still lists it. */
export function mergeRoster(a: RosterSlice, b: RosterSlice): RosterSlice {
  const revokedDevices = [...new Set([...(a.revokedDevices ?? []), ...(b.revokedDevices ?? [])])]
    .filter((id) => typeof id === 'string' && /^[0-9a-f-]{8,64}$/i.test(id))
    .slice(0, 100);
  const devices = mergeDevices(a.devices, b.devices).filter((d) => !revokedDevices.includes(d.id));
  return { devices, revokedDevices };
}

export function sameRoster(a: RosterSlice, b: RosterSlice): boolean {
  if (a.revokedDevices.length !== b.revokedDevices.length || a.devices.length !== b.devices.length) return false;
  const revoked = new Set(b.revokedDevices);
  if (a.revokedDevices.some((id) => !revoked.has(id))) return false;
  const map = new Map(b.devices.map((d) => [d.id, d]));
  return a.devices.every((d) => {
    const o = map.get(d.id);
    return !!o && o.name === d.name && o.kind === d.kind && o.agent === d.agent && o.seen === d.seen && o.added === d.added;
  });
}

export function deviceNeedsWrite(prev: VaultDevice | undefined, next: VaultDevice, now = next.seen): boolean {
  if (!prev) return true;
  if (prev.name !== next.name || prev.kind !== next.kind || prev.agent !== next.agent) return true;
  return now - prev.seen > SEEN_WINDOW_MS;
}

function readRevoked(): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(REVOKED_KEY) || '[]') as unknown;
    return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
  } catch { return []; }
}

/** This browser was told to drop this vault. Stops cloud sync from installing it again. */
export function vaultRevokedLocally(id: string): boolean {
  return readRevoked().includes(id);
}

export function markVaultRevoked(id: string): void {
  const next = [...new Set([...readRevoked(), id])];
  try { localStorage.setItem(REVOKED_KEY, JSON.stringify(next)); } catch { /* ignore */ }
}

export function clearVaultRevoked(id: string): void {
  const next = readRevoked().filter((x) => x !== id);
  try { localStorage.setItem(REVOKED_KEY, JSON.stringify(next)); } catch { /* ignore */ }
}
