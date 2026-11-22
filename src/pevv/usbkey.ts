/**
 * USB key file: a 32-byte random secret in a `.pevvkey` file on a drive the user keeps.
 *
 *  - As a key slot (`usb-key`) it wraps the vault key like the other slots: the secret goes
 *    through HKDF-SHA256 (per-slot salt) into an AES-GCM KEK. The file alone unlocks the vault.
 *  - As a second factor (`meta.usbKeys`) it is only a gate after the master password: the vault
 *    keeps a hash of the secret, sealed in meta.
 *
 * Both are bound to the file's content and nothing else: not the drive's serial number, which
 * any program can read and a clone can copy. A file can be copied without the owner noticing, so
 * this is weaker than a FIDO2 key. Keep it on one drive and keep a backup.
 */
import { type Bytes, b64, concat, ctEqual, randomBytes, unb64, utf8 } from './bytes';
import { sha256 } from './crypto';

export const KEY_FILE_FORMAT = 'luciverse.pevvkey';
export const KEY_FILE_NAME = '.pevvkey';
export const KEY_BYTES = 32;
export const USB_KEK_INFO = 'luciverse/pevv/v1/usb-kek';
const GATE_TAG = 'luciverse/pevv/v1/usb-gate';

export interface KeyFile {
  format: typeof KEY_FILE_FORMAT;
  v: 1;
  /** The vault this file was made for. A hint for people and for picking a file, not a binding. */
  vault: string;
  /** The 32-byte secret, base64. */
  secret: string;
}

export function newKeyFile(vaultId: string): { file: KeyFile; text: string; secret: Bytes } {
  const secret = randomBytes(KEY_BYTES);
  const file: KeyFile = { format: KEY_FILE_FORMAT, v: 1, vault: vaultId, secret: b64(secret) };
  return { file, text: `${JSON.stringify(file, null, 2)}\n`, secret };
}

/** Parse and check the text of a key file. Throws a plain-language error. */
export function parseKeyFile(text: string): { file: KeyFile; secret: Bytes } {
  let j: Partial<KeyFile> | null = null;
  try { j = JSON.parse(text) as Partial<KeyFile>; } catch { /* handled below */ }
  if (!j || j.format !== KEY_FILE_FORMAT || j.v !== 1 || typeof j.secret !== 'string' || typeof j.vault !== 'string') {
    throw new Error('That is not a PEVV key file.');
  }
  let secret: Bytes;
  try { secret = unb64(j.secret); } catch { throw new Error('That key file is damaged.'); }
  if (secret.length !== KEY_BYTES) throw new Error('That key file is damaged.');
  return { file: j as KeyFile, secret };
}

/** What the vault stores to recognise a second-factor key file: a hash of a tag and the secret. */
export async function gateCheck(secret: Uint8Array): Promise<string> {
  const h = await sha256(concat(utf8(GATE_TAG), secret));
  return b64(h);
}

export async function gateMatches(secret: Uint8Array, check: string): Promise<boolean> {
  try { return ctEqual(unb64(await gateCheck(secret)), unb64(check)); } catch { return false; }
}
