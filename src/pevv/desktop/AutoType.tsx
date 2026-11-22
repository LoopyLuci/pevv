/**
 * Desktop-only UI for auto-type: the small chooser window, the Settings section (hotkey on/off and
 * which keys) and the "Auto-type" fields of a login's editor. The chooser is a separate window that
 * has no access to the vault: it only shows the titles the vault window sent it.
 */
import { useCallback, useEffect, useState } from 'react';
import type { AutoTypeConfig } from '../model';
import { DEFAULT_SEQUENCE, MAX_PATTERNS, parseSequence } from '../autotype';
import { Section, btn, btnPrimary, input, label } from '../ui/common';
import { linkIpc, type LinkIpc } from './link';
import type { AutoTypeSettings } from './autotypeHost';

/* ───────────── hotkey capture ───────────── */

interface KeyInfo { code: string; ctrlKey: boolean; altKey: boolean; shiftKey: boolean; metaKey: boolean }

/** "Ctrl+Alt+A" from a key event, or null while only modifiers (or an unsupported key) are down. */
export function hotkeyFromEvent(e: KeyInfo): string | null {
  const named: Record<string, string> = { Space: 'Space', ArrowUp: 'Up', ArrowDown: 'Down', ArrowLeft: 'Left', ArrowRight: 'Right', Enter: 'Enter', Tab: 'Tab', Backquote: '`', Minus: '-', Equal: '=', Comma: ',', Period: '.', Slash: '/' };
  let key: string | undefined;
  if (/^Key[A-Z]$/.test(e.code)) key = e.code.slice(3);
  else if (/^Digit\d$/.test(e.code)) key = e.code.slice(5);
  else if (/^F\d{1,2}$/.test(e.code)) key = e.code;
  else key = named[e.code];
  if (!key) return null;
  const mods = [e.ctrlKey && 'Ctrl', e.altKey && 'Alt', e.shiftKey && 'Shift', e.metaKey && 'Super'].filter(Boolean) as string[];
  return [...mods, key].join('+');
}

/* ───────────── the chooser window ───────────── */

export interface ChooserView {
  id: number;
  target: { title: string; process: string } | null;
  mode: 'type' | 'clipboard';
  phase: 'matching' | 'choose' | 'working' | 'done' | 'error';
  candidates: Array<{ id: string; title: string; username: string }>;
  message: string | null;
  code: string | null;
}

export const CHOOSER_VIEW_EVENT = 'autotype-view';

/** Always-on-top, never focused: clicking an entry types into the window that is still in front. */
export function Chooser({ ipc }: { ipc: LinkIpc }) {
  const [view, setView] = useState<ChooserView | null>(null);
  useEffect(() => {
    let off: (() => void) | undefined;
    let alive = true;
    void ipc.listen<ChooserView>(CHOOSER_VIEW_EVENT, (v) => setView(v)).then((u) => { if (alive) off = u; else u(); });
    void ipc.invoke<ChooserView | null>('autotype_pending').then((v) => { if (alive && v) setView(v); }, () => undefined);
    return () => { alive = false; off?.(); };
  }, [ipc]);
  const close = useCallback(() => { if (view) void ipc.invoke('autotype_cancel', { id: view.id }).catch(() => undefined); }, [ipc, view]);
  const phase = view?.phase;
  useEffect(() => {
    if (phase !== 'done' || !view) return undefined;
    const t = setTimeout(() => { void ipc.invoke('autotype_cancel', { id: view.id }).catch(() => undefined); }, 1500);
    return () => clearTimeout(t);
  }, [phase, view, ipc]);
  if (!view) return <div className="p-3 text-xs text-ink-muted">PEVV auto-type</div>;
  return (
    <div className="flex h-screen flex-col gap-2 border border-accent-cyan/60 bg-[#0b1226] p-3 text-ink-primary" data-testid="autotype-chooser">
      <h1 className="text-xs font-semibold text-accent-cyan">PEVV auto-type</h1>
      {view.target ? (
        <p className="truncate text-xs text-ink-secondary" data-testid="autotype-target">
          Into <b className="text-cyan-100">{view.target.title || '(untitled window)'}</b> <span className="text-ink-muted">({view.target.process || 'unknown program'})</span>
        </p>
      ) : (
        <p className="text-xs text-accent-gold">PEVV cannot tell which window is in front on this system.</p>
      )}
      {view.mode === 'clipboard' && <p className="text-xs text-accent-gold" data-testid="autotype-clipboard-note">This system does not let PEVV type into other programs. Picking an entry copies its password instead (it clears itself).</p>}
      {view.phase === 'matching' && <p className="text-xs text-ink-muted">Looking for entries…</p>}
      {view.phase === 'choose' && (
        <ul className="flex min-h-0 flex-1 flex-col gap-1 overflow-y-auto" data-testid="autotype-candidates">
          {view.candidates.map((c) => (
            <li key={c.id}>
              <button type="button" className={`${btn} w-full justify-start`} onClick={() => void ipc.invoke('autotype_confirm', { id: view.id, entryId: c.id }).catch(() => undefined)} data-testid="autotype-pick">
                <span className="truncate font-semibold">{c.title || '(untitled)'}</span>
                {c.username && <span className="truncate text-ink-muted"> · {c.username}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
      {view.phase === 'working' && <p className="text-xs text-ink-secondary" data-testid="autotype-working">{view.mode === 'type' ? 'Typing…' : 'Copying…'}</p>}
      {view.phase === 'done' && <p className="text-xs text-accent-green" data-testid="autotype-done">{view.message ?? 'Done.'}</p>}
      {view.phase === 'error' && <p className="text-xs text-red-300" role="alert" data-testid="autotype-error">{view.message ?? 'Something went wrong.'}</p>}
      <div className="mt-auto flex justify-end">
        <button type="button" className={btn} onClick={close} data-testid="autotype-close">{view.phase === 'choose' || view.phase === 'matching' ? 'Cancel' : 'Close'}</button>
      </div>
    </div>
  );
}

/* ───────────── settings ───────────── */

export function AutoTypeSection() {
  const [st, setSt] = useState<AutoTypeSettings | null>(null);
  const [hotkey, setHotkey] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const load = useCallback(async (cmd: string, args?: Record<string, unknown>) => {
    const ipc = linkIpc();
    if (!ipc) return;
    try {
      const s = await ipc.invoke<AutoTypeSettings>(cmd, args);
      setSt(s);
      setHotkey(s.hotkey);
      setErr(null);
    } catch (e) { setErr(typeof e === 'string' ? e : (e as Error).message); }
  }, []);
  useEffect(() => { void load('autotype_settings_get'); }, [load]);
  if (!linkIpc()) return null;
  const save = (enabled: boolean, key: string): void => { void load('autotype_settings_set', { enabled, hotkey: key }); };
  return (
    <Section title="Auto-type into other programs" testId="pevv-autotype">
      <p className="text-xs text-ink-muted">Press the shortcut while another program is in front, pick a login in the small window that appears, and PEVV types it there. It works only while PEVV is unlocked, and only for logins that have an Auto-type setting naming that window (a web address alone never matches). Browsers: use the extension instead.</p>
      {st && (
        <>
          <label className="flex items-center gap-2 text-xs text-ink-secondary">
            <input type="checkbox" checked={st.enabled} onChange={(e) => save(e.target.checked, st.hotkey)} data-testid="pevv-autotype-toggle" />
            Turn on the auto-type shortcut
          </label>
          <label className={label}>Shortcut (click, then press the keys)
            <div className="flex gap-1">
              <input
                className={`${input} font-mono`}
                value={hotkey}
                readOnly
                onKeyDown={(e) => { e.preventDefault(); const k = hotkeyFromEvent(e.nativeEvent); if (k) setHotkey(k); }}
                data-testid="pevv-autotype-hotkey"
              />
              <button type="button" className={btnPrimary} disabled={hotkey === st.hotkey} onClick={() => save(st.enabled, hotkey)} data-testid="pevv-autotype-save">Save</button>
              <button type="button" className={btn} disabled={st.hotkey === st.defaultHotkey} onClick={() => save(st.enabled, st.defaultHotkey)}>Reset</button>
            </div>
          </label>
          {st.enabled && !st.registered && !st.error && <p className="text-xs text-ink-muted">The shortcut is switched on while PEVV is unlocked.</p>}
          {st.registered && <p className="text-xs text-accent-green" data-testid="pevv-autotype-live">The shortcut {st.hotkey} is live.</p>}
          {st.error && <p className="text-xs text-red-300" role="alert">{st.error}</p>}
          {st.support.note && <p className="text-xs text-accent-gold" data-testid="pevv-autotype-note">{st.support.note}</p>}
          <p className="text-[0.65rem] text-ink-muted">PEVV will not type into a program running as administrator, or a Windows security prompt, and stops if the window in front changes while it types. With &quot;Lock when the app goes to the background&quot; on, keep the PEVV window open behind your other programs (not minimised).</p>
        </>
      )}
      {err && !st?.error && <p className="text-xs text-red-300" role="alert">{err}</p>}
    </Section>
  );
}

/* ───────────── the editor's fields ───────────── */

/** Auto-type fields of a login: window patterns (one per line), program, keys. */
export function AutoTypeFields({ value, onChange }: { value: AutoTypeConfig | undefined; onChange: (v: AutoTypeConfig | undefined) => void }) {
  const cfg: AutoTypeConfig = value ?? { windows: [] };
  const seq = cfg.sequence ?? '';
  const parsed = seq.trim() ? parseSequence(seq) : null;
  const set = (patch: Partial<AutoTypeConfig>): void => onChange({ ...cfg, ...patch });
  const broad = cfg.windows.some((w) => /^[*?\s]*$/.test(w) && w.trim()) && !cfg.process?.trim();
  return (
    <fieldset className="flex flex-col gap-2 rounded-md border border-space-border p-2" data-testid="pevv-f-autotype">
      <legend className="px-1 text-xs text-ink-secondary">Auto-type into other programs (desktop app)</legend>
      <label className={label}>Window titles (one pattern per line; * and ? work)
        <textarea className={`${input} min-h-14 py-1 font-mono`} value={cfg.windows.join('\n')} onChange={(e) => set({ windows: e.target.value.split('\n').slice(0, MAX_PATTERNS) })} placeholder={'*PuTTY*\nLogin - Contoso VPN'} spellCheck={false} data-testid="pevv-f-at-windows" />
      </label>
      <label className={label}>Program (optional, e.g. putty.exe)
        <input className={`${input} font-mono`} value={cfg.process ?? ''} onChange={(e) => set({ process: e.target.value })} spellCheck={false} data-testid="pevv-f-at-process" />
      </label>
      <label className={label}>Keys to type (default {DEFAULT_SEQUENCE})
        <input className={`${input} font-mono`} value={seq} onChange={(e) => set({ sequence: e.target.value })} placeholder={DEFAULT_SEQUENCE} spellCheck={false} data-testid="pevv-f-at-sequence" />
      </label>
      <p className="text-[0.65rem] text-ink-muted">{'{USERNAME} {PASSWORD} {TOTP} {TAB} {ENTER} {DELAY 500}. Use {{} for a literal { and {}} for }. Leave the windows and program empty to turn auto-type off for this login.'}</p>
      {parsed && !parsed.ok && <p className="text-xs text-red-300" role="alert" data-testid="pevv-f-at-error">{parsed.error}</p>}
      {broad && <p className="text-xs text-accent-gold">A pattern of only * matches every window. You still confirm each time, but narrow it if you can.</p>}
    </fieldset>
  );
}
