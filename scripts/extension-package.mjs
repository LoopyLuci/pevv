/**
 * Packaging helpers for the PEVV extension: the Firefox manifest and the zip
 * writer. Kept free of Vite so the unit tests can import them.
 */
import { crc32, deflateRawSync } from 'node:zlib';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

export const GECKO_ID = 'pevv@luciverse.pages.dev';
export const FIREFOX_MIN = '128.0';

/**
 * Firefox runs MV3 background code as an event page (`background.scripts`),
 * not a service worker, and needs an add-on id. Everything else stays the same.
 */
export function firefoxManifest(base) {
  const m = structuredClone(base);
  delete m.minimum_chrome_version;
  // Chrome-only: the pinned extension id and the desktop-app link (a Chrome native-messaging host).
  delete m.key;
  delete m.optional_permissions;
  m.background = { scripts: [base.background.service_worker], type: base.background.type };
  m.browser_specific_settings = {
    gecko: { id: GECKO_ID, strict_min_version: FIREFOX_MIN, data_collection_permissions: { required: ['none'] } },
  };
  return m;
}

/** Every file under `dir`, as forward-slash paths relative to it, sorted. */
export function listFiles(dir) {
  const out = [];
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else out.push(relative(dir, p).split(sep).join('/'));
    }
  };
  walk(dir);
  return out.sort();
}

/**
 * A plain zip (deflate) of `files` ({ path, data }). Paths always use "/":
 * a zip with "\" separators (what Windows' Compress-Archive wrote for 0.1.0)
 * unpacks into flat file names on Linux and macOS, and Firefox rejects it.
 */
export function zipFiles(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  // 1980-01-01 00:00 in DOS time, so the same build gives the same zip.
  const dosTime = 0;
  const dosDate = (0 << 9) | (1 << 5) | 1;
  for (const { path, data } of files) {
    if (path.includes('\\')) throw new Error(`zip path with a backslash: ${path}`);
    const name = Buffer.from(path, 'utf8');
    const raw = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const packed = deflateRawSync(raw, { level: 9 });
    const useDeflate = packed.length < raw.length;
    const body = useDeflate ? packed : raw;
    const crc = crc32(raw) >>> 0;
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4);
    head.writeUInt16LE(0x0800, 6); // UTF-8 names
    head.writeUInt16LE(useDeflate ? 8 : 0, 8);
    head.writeUInt16LE(dosTime, 10);
    head.writeUInt16LE(dosDate, 12);
    head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(body.length, 18);
    head.writeUInt32LE(raw.length, 22);
    head.writeUInt16LE(name.length, 26);
    head.writeUInt16LE(0, 28);
    locals.push(head, name, body);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(0x031e, 4); // made by: Unix, so unzip keeps "/" as a separator
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(0x0800, 8);
    cen.writeUInt16LE(useDeflate ? 8 : 0, 10);
    cen.writeUInt16LE(dosTime, 12);
    cen.writeUInt16LE(dosDate, 14);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(body.length, 20);
    cen.writeUInt32LE(raw.length, 24);
    cen.writeUInt16LE(name.length, 28);
    cen.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    cen.writeUInt32LE(offset, 42);
    centrals.push(cen, name);
    offset += head.length + name.length + body.length;
  }
  const central = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, central, end]);
}

/** Zip a whole directory. */
export function zipDir(dir) {
  return zipFiles(listFiles(dir).map((path) => ({ path, data: readFileSync(join(dir, path)) })));
}
