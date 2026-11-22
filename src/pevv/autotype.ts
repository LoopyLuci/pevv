/**
 * Auto-type, the pure part: the sequence language, window matching and turning an entry plus a
 * sequence into the keys the desktop shell types. The shell (Rust) reads the foreground window and
 * does the typing; everything that needs the unlocked vault happens here.
 *
 * Matching is by window title (glob) and, optionally, program name, from the entry's own
 * `autoType` field. A site or URL never matches a window: browsers have the extension for that.
 *
 * Sequence language (case-insensitive tokens, everything else is typed as written):
 *   {USERNAME} {PASSWORD} {TOTP}   the entry's fields ({TOTP} is the current one-time code)
 *   {TAB} {ENTER}                  those keys
 *   {DELAY 500}                    wait 500 ms (at most 10 s each, 30 s in all)
 *   {{}  {}}                       a literal { and }
 */
import type { AutoTypeConfig, Entry } from './model';
import { parseOtpauth, totpAt } from './totp';

export const DEFAULT_SEQUENCE = '{USERNAME}{TAB}{PASSWORD}{ENTER}';
export const MAX_SEQUENCE_CHARS = 500;
export const MAX_DELAY_MS = 10_000;
export const MAX_TOTAL_DELAY_MS = 30_000;
export const MAX_TOKENS = 200;
export const MAX_PATTERNS = 10;
export const MAX_PATTERN_CHARS = 200;

export type Field = 'USERNAME' | 'PASSWORD' | 'TOTP';
export type SeqToken =
  | { kind: 'text'; text: string }
  | { kind: 'field'; field: Field }
  | { kind: 'key'; key: 'tab' | 'enter' }
  | { kind: 'delay'; ms: number };

export type ParsedSequence = { ok: true; tokens: SeqToken[] } | { ok: false; error: string; at: number };

/** Parse a sequence. Never throws; the error says what and where, without echoing field contents (there are none here). */
export function parseSequence(src: string): ParsedSequence {
  if (src.length > MAX_SEQUENCE_CHARS) return { ok: false, error: `The sequence is longer than ${MAX_SEQUENCE_CHARS} characters.`, at: MAX_SEQUENCE_CHARS };
  const tokens: SeqToken[] = [];
  let text = '';
  let delay = 0;
  const flush = (): void => { if (text) { tokens.push({ kind: 'text', text }); text = ''; } };
  for (let i = 0; i < src.length; i++) {
    const c = src[i]!;
    if (c !== '{') { text += c; continue; }
    // `{{}` and `{}}` are the literal braces.
    if (src.startsWith('{{}', i)) { text += '{'; i += 2; continue; }
    if (src.startsWith('{}}', i)) { text += '}'; i += 2; continue; }
    const end = src.indexOf('}', i + 1);
    if (end < 0) return { ok: false, error: 'A { has no closing }. Use {{} to type a { itself.', at: i };
    const inner = src.slice(i + 1, end).trim();
    const [name = '', ...rest] = inner.split(/\s+/);
    const up = name.toUpperCase();
    if (up === 'USERNAME' || up === 'PASSWORD' || up === 'TOTP') {
      if (rest.length) return { ok: false, error: `{${up}} takes no argument.`, at: i };
      flush();
      tokens.push({ kind: 'field', field: up });
    } else if (up === 'TAB' || up === 'ENTER') {
      if (rest.length) return { ok: false, error: `{${up}} takes no argument.`, at: i };
      flush();
      tokens.push({ kind: 'key', key: up === 'TAB' ? 'tab' : 'enter' });
    } else if (up === 'DELAY') {
      const arg = rest.join(' ');
      if (!/^\d{1,5}$/.test(arg)) return { ok: false, error: '{DELAY n} needs a number of milliseconds, e.g. {DELAY 500}.', at: i };
      const ms = Number(arg);
      if (ms > MAX_DELAY_MS) return { ok: false, error: `A delay can be at most ${MAX_DELAY_MS} ms.`, at: i };
      delay += ms;
      if (delay > MAX_TOTAL_DELAY_MS) return { ok: false, error: `The delays add up to more than ${MAX_TOTAL_DELAY_MS / 1000} s.`, at: i };
      flush();
      tokens.push({ kind: 'delay', ms });
    } else {
      return { ok: false, error: `Unknown {${name.slice(0, 20)}}. Use {USERNAME}, {PASSWORD}, {TOTP}, {TAB}, {ENTER} or {DELAY n}.`, at: i };
    }
    i = end;
    if (tokens.length > MAX_TOKENS) return { ok: false, error: 'The sequence has too many steps.', at: i };
  }
  flush();
  if (!tokens.length) return { ok: false, error: 'The sequence is empty.', at: 0 };
  return { ok: true, tokens };
}

/* ───────────── matching ───────────── */

/** Case-insensitive glob: `*` any run (including none), `?` any one character. Linear-ish, no regex. */
export function globMatch(pattern: string, text: string): boolean {
  const p = pattern.toLowerCase();
  const t = text.toLowerCase();
  let pi = 0;
  let ti = 0;
  let star = -1;
  let mark = 0;
  while (ti < t.length) {
    if (pi < p.length && (p[pi] === '?' || p[pi] === t[ti])) { pi++; ti++; }
    else if (pi < p.length && p[pi] === '*') { star = pi++; mark = ti; }
    else if (star >= 0) { pi = star + 1; ti = ++mark; }
    else return false;
  }
  while (pi < p.length && p[pi] === '*') pi++;
  return pi === p.length;
}

/** `putty` and `putty.exe` are the same program; case does not matter. */
export function processMatches(want: string, actual: string): boolean {
  const strip = (s: string): string => s.trim().toLowerCase().replace(/\.exe$/, '');
  const w = strip(want);
  return w !== '' && w === strip(actual);
}

export interface WindowCtx { title: string; process: string }

/** Does this entry's own auto-type field accept this window? No field, or an empty one: never. */
export function matchesWindow(cfg: AutoTypeConfig | undefined, ctx: WindowCtx): boolean {
  if (!cfg || typeof cfg !== 'object') return false;
  const titles = patternsOf(cfg).slice(0, MAX_PATTERNS);
  const proc = typeof cfg.process === 'string' ? cfg.process.trim() : '';
  if (!titles.length && !proc) return false;
  if (proc && !processMatches(proc, ctx.process)) return false;
  if (titles.length && !titles.some((p) => globMatch(p.slice(0, MAX_PATTERN_CHARS), ctx.title))) return false;
  return true;
}

/** The usable title patterns of a (possibly hand-edited or damaged) field. */
function patternsOf(cfg: AutoTypeConfig): string[] {
  return Array.isArray(cfg.windows) ? cfg.windows.filter((w): w is string => typeof w === 'string').map((w) => w.trim()).filter(Boolean) : [];
}

export function hasAutoType(e: Entry): boolean {
  const c = e.autoType;
  return e.type === 'login' && !!c && typeof c === 'object' && (patternsOf(c).length > 0 || (typeof c.process === 'string' && !!c.process.trim()));
}

/** The logins whose auto-type field accepts this window; favourites first, then by title. */
export function matchAutoType(entries: Entry[], ctx: WindowCtx): Entry[] {
  return entries
    .filter((e) => e.type === 'login' && matchesWindow(e.autoType, ctx))
    .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.title.localeCompare(b.title));
}

/* ───────────── building the keys ───────────── */

/** What the shell types. Same shape as `autotype_core::Action` in Rust. */
export type Action = { t: 'text'; v: string } | { t: 'key'; v: 'tab' | 'enter' } | { t: 'delay'; v: number };

/** Fill in the fields. `{TOTP}` needs the entry's one-time-code secret and uses the code valid now. */
export async function resolveSequence(tokens: SeqToken[], e: Pick<Entry, 'username' | 'password' | 'totp'>, now = Date.now()): Promise<Action[]> {
  const out: Action[] = [];
  const text = (v: string): void => {
    if (!v) return;
    const last = out[out.length - 1];
    if (last?.t === 'text') last.v += v; else out.push({ t: 'text', v });
  };
  for (const tok of tokens) {
    if (tok.kind === 'text') text(tok.text);
    else if (tok.kind === 'key') out.push({ t: 'key', v: tok.key });
    else if (tok.kind === 'delay') out.push({ t: 'delay', v: tok.ms });
    else if (tok.field === 'USERNAME') text(e.username ?? '');
    else if (tok.field === 'PASSWORD') text(e.password ?? '');
    else {
      if (!e.totp) throw new Error('This entry has no one-time-code secret for {TOTP}.');
      text(await totpAt(parseOtpauth(e.totp), now));
    }
  }
  if (!out.some((a) => a.t !== 'delay')) throw new Error('There is nothing to type for this entry.');
  return out;
}

/** The text to type into the editor's fields, normalised for saving: trimmed, no blanks, no duplicates. */
export function normalizeAutoType(cfg: AutoTypeConfig | undefined): AutoTypeConfig | undefined {
  if (!cfg) return undefined;
  const windows = [...new Set((cfg.windows ?? []).map((w) => w.trim().slice(0, MAX_PATTERN_CHARS)).filter(Boolean))].slice(0, MAX_PATTERNS);
  const process = cfg.process?.trim() || undefined;
  const sequence = cfg.sequence?.trim() && cfg.sequence.trim() !== DEFAULT_SEQUENCE ? cfg.sequence.trim() : undefined;
  if (!windows.length && !process) return undefined;
  return { windows, ...(process ? { process } : {}), ...(sequence ? { sequence } : {}) };
}
