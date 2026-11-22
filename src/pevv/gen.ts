/** PEVV password / passphrase generator and offline strength meter (bundles the word lists). */
import { COMMON_PASSWORDS, EFF_SHORT } from './words';

/* ───────────── password generator ───────────── */

export interface GenOpts {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
}

export const DEFAULT_GEN: GenOpts = { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true };

const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
};
const AMBIGUOUS = /[Il1O0o|`'"]/g;

/** Unbiased integer in [0, n) via rejection sampling on a CSPRNG. */
export function randInt(n: number): number {
  if (!(n > 0 && n <= 2 ** 32)) throw new Error('bad range');
  const lim = Math.floor(2 ** 32 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0]! < lim) return buf[0]! % n;
  }
}

export function generatePassword(o: GenOpts): string {
  const pools = (['lower', 'upper', 'digits', 'symbols'] as const)
    .filter((k) => o[k])
    .map((k) => (o.avoidAmbiguous ? SETS[k].replace(AMBIGUOUS, '') : SETS[k]));
  if (!pools.length) pools.push(SETS.lower);
  const len = Math.max(Math.max(8, pools.length), Math.min(128, Math.round(o.length)));
  const all = pools.join('');
  const out: string[] = pools.map((p) => p[randInt(p.length)]!); // at least one of each chosen set
  while (out.length < len) out.push(all[randInt(all.length)]!);
  for (let i = out.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out.join('');
}

export interface PhraseOpts { words: number; separator: string; capitalize: boolean; number: boolean }
export const DEFAULT_PHRASE: PhraseOpts = { words: 6, separator: '-', capitalize: true, number: true };

export function generatePassphrase(o: PhraseOpts): string {
  const n = Math.max(4, Math.min(12, Math.round(o.words)));
  const words = Array.from({ length: n }, () => {
    const w = EFF_SHORT[randInt(EFF_SHORT.length)]!;
    return o.capitalize ? w[0]!.toUpperCase() + w.slice(1) : w;
  });
  if (o.number) {
    const i = randInt(words.length);
    words[i] = words[i]! + String(randInt(10));
  }
  return words.join(o.separator.slice(0, 3));
}

export function generatorEntropy(o: GenOpts): number {
  const size = (['lower', 'upper', 'digits', 'symbols'] as const)
    .filter((k) => o[k])
    .reduce((a, k) => a + (o.avoidAmbiguous ? SETS[k].replace(AMBIGUOUS, '') : SETS[k]).length, 0) || 26;
  return Math.round(o.length * Math.log2(size));
}

export function phraseEntropy(o: PhraseOpts): number {
  return Math.round(o.words * Math.log2(EFF_SHORT.length) + (o.number ? Math.log2(10 * o.words) : 0));
}

/* ───────────── strength (offline) ───────────── */

export interface Strength { score: 0 | 1 | 2 | 3 | 4; bits: number; common: boolean; warnings: string[] }

const KEYBOARD_RUNS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'abcdefghijklmnopqrstuvwxyz'];

export function isCommonPassword(pw: string): boolean {
  const s = pw.toLowerCase();
  if (COMMON_PASSWORDS.has(s)) return true;
  const stripped = s.replace(/[\d!@#$%^&*._-]+$/, '').replace(/^[\d!@#$%^&*._-]+/, '');
  const leet = stripped.replace(/[@4]/g, 'a').replace(/3/g, 'e').replace(/[1!]/g, 'i').replace(/0/g, 'o').replace(/\$|5/g, 's').replace(/7/g, 't');
  return stripped.length >= 4 && (COMMON_PASSWORDS.has(stripped) || COMMON_PASSWORDS.has(leet));
}

export function strength(pw: string): Strength {
  const warnings: string[] = [];
  if (!pw) return { score: 0, bits: 0, common: false, warnings };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  // Effective length: collapse repeats and keyboard/alphabet runs.
  let eff = 0;
  const lower = pw.toLowerCase();
  for (let i = 0; i < pw.length; i++) {
    const c = lower[i]!, p = lower[i - 1];
    if (p === c) { eff += 0.25; continue; }
    const run = p !== undefined && KEYBOARD_RUNS.some((r) => r.includes(p + c) || r.includes(c + p));
    eff += run ? 0.35 : 1;
  }
  const words = lower.split(/[^a-z]+/).filter((w) => w.length >= 3);
  const wordish = words.length >= 4 && words.every((w) => EFF_SHORT.includes(w));
  let bits = wordish ? words.length * Math.log2(EFF_SHORT.length) : eff * Math.log2(Math.max(pool, 2));
  const common = isCommonPassword(pw);
  if (common) { bits = Math.min(bits, 10); warnings.push('common'); }
  if (/(.)\1{2,}/.test(pw)) warnings.push('repeats');
  if (KEYBOARD_RUNS.some((r) => { for (let i = 0; i + 4 <= r.length; i++) if (lower.includes(r.slice(i, i + 4))) return true; return false; })) warnings.push('sequence');
  if (/(19|20)\d\d/.test(pw)) warnings.push('year');
  if (pw.length < 12) warnings.push('short');
  const score: Strength['score'] = bits < 28 ? 0 : bits < 45 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  return { score, bits: Math.round(bits), common, warnings };
}
