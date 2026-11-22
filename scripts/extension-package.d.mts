export type ExtManifest = { background: { service_worker: string; type: string }; [key: string]: any }; // eslint-disable-line @typescript-eslint/no-explicit-any
export const GECKO_ID: string;
export const FIREFOX_MIN: string;
export function firefoxManifest(base: ExtManifest): ExtManifest;
export function listFiles(dir: string): string[];
export function zipFiles(files: { path: string; data: string | Buffer }[]): Buffer;
export function zipDir(dir: string): Buffer;
