/** Builds the `NativeApi` over the Tauri IPC. Pure plumbing, so tests drive it with a fake shell. */
import type { DesktopIpc } from './bridge';
import {
  NativeError, type NativeApi, type NativePrfResult, type NativeSupport, type PresenceDesignation, type PresenceState, type UsbDevice, type UsbVolume,
} from '../native';

/** Tauri rejects with whatever the Rust command returned: our `{ code, message }`, or a string. */
export function toNativeError(e: unknown): NativeError {
  if (e instanceof NativeError) return e;
  if (e && typeof e === 'object') {
    const o = e as { code?: unknown; message?: unknown };
    return new NativeError(typeof o.message === 'string' ? o.message : 'native request failed', typeof o.code === 'string' ? o.code : 'failed');
  }
  return new NativeError(typeof e === 'string' ? e : 'native request failed', 'failed');
}

async function call<T>(ipc: DesktopIpc, cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await ipc.invoke<T>(cmd, args);
  } catch (e) {
    throw toNativeError(e);
  }
}

export async function createNative(ipc: DesktopIpc, askPin: (retry: boolean) => Promise<string | null>): Promise<NativeApi> {
  let support: NativeSupport;
  try {
    support = await ipc.invoke<NativeSupport>('passkey_support');
  } catch {
    support = { available: false, rpId: '', platform: 'unknown', reason: 'The shell did not answer.', appPin: false };
  }
  return {
    passkey: {
      support,
      prf: (req) => call<NativePrfResult>(ipc, 'passkey_prf', { req }),
      askPin,
    },
    usb: {
      volumes: () => call<UsbVolume[]>(ipc, 'usb_volumes'),
      readKeyFile: (path) => call<string>(ipc, 'usb_keyfile_read', { path }),
      writeKeyFile: (path, content) => call<void>(ipc, 'usb_keyfile_write', { path, content }),
      devices: () => call<UsbDevice[]>(ipc, 'usb_devices'),
      presence: () => call<PresenceState>(ipc, 'presence_get'),
      setPresence: (designation: PresenceDesignation | null) => call<void>(ipc, 'presence_set', { designation }),
    },
  };
}
