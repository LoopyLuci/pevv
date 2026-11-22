/**
 * What the desktop shell lends the PEVV screen beyond the vault file: native passkeys and
 * security keys, USB key-file drives and the presence-lock device. `null` everywhere else
 * (browser, extension, Android), so the shared UI checks `getNative()` and offers these only
 * where they exist. The desktop boot fills it in (src/pevv/desktop/native.ts).
 */
export interface NativePrfCredential {
  /** Credential id, base64url. */
  id: string;
  /** PRF `first` input, base64url (the vault slot's salt). Omitted for a plain assertion. */
  salt1?: string;
  salt2?: string;
}

export interface NativePrfResult {
  credentialId: string;
  prf1: string | null;
  prf2: string | null;
  authenticatorData: string;
  clientDataJson: string;
  signature: string;
}

export interface NativeSupport {
  available: boolean;
  rpId: string;
  platform: string;
  reason: string | null;
  /** The key's PIN is asked for in the app (Linux); on Windows the OS dialog asks. */
  appPin: boolean;
}

export interface UsbVolume { path: string; label: string; hasKeyFile: boolean }
export interface UsbDevice { id: string; vid: string; pid: string; name: string; serial: string | null }
export interface PresenceDesignation { id: string; name: string; requireToUnlock: boolean }
export interface PresenceState { designation: PresenceDesignation | null; present: boolean | null }

/** Thrown for a failed native request; `code` is the shell's stable error code. */
export class NativeError extends Error {
  readonly code: string;
  constructor(message: string, code: string) {
    super(message);
    this.name = 'NativeError';
    this.code = code;
  }
}

export interface NativeApi {
  passkey: {
    support: NativeSupport;
    prf(req: { credentials: NativePrfCredential[]; challenge: string; requireUv: boolean; pin?: string }): Promise<NativePrfResult>;
    /** Ask the person for the key's PIN. Resolves null when they cancel. */
    askPin(retry: boolean): Promise<string | null>;
  };
  usb: {
    volumes(): Promise<UsbVolume[]>;
    readKeyFile(path: string): Promise<string>;
    writeKeyFile(path: string, content: string): Promise<void>;
    devices(): Promise<UsbDevice[]>;
    presence(): Promise<PresenceState>;
    setPresence(d: PresenceDesignation | null): Promise<void>;
  };
}

let current: NativeApi | null = null;

export function setNative(api: NativeApi | null): void {
  current = api;
}

export function getNative(): NativeApi | null {
  return current;
}

/**
 * Soft gate before an unlock starts: with "refuse to unlock while the device is absent" on, the
 * designated USB device must be plugged in. Recovery paths are not gated, so it can never lock the owner out.
 * Returns an error message, or null to go ahead.
 */
export async function unlockGate(): Promise<string | null> {
  const n = current;
  if (!n) return null;
  let s: PresenceState;
  try { s = await n.usb.presence(); } catch { return null; }
  const d = s.designation;
  if (!d || !d.requireToUnlock) return null;
  if (s.present === false) return `Plug in "${d.name}" to unlock (this is a soft check you can turn off in Settings; a recovery code still works).`;
  return null;
}
