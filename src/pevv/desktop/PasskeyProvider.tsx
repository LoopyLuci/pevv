/**
 * Desktop-only UI for the Windows passkey provider: the confirmation cards shown while Windows is
 * waiting on PEVV, and the settings section (requirements, register, the passkeys PEVV holds).
 */
import { useCallback, useEffect, useState } from 'react';
import { deleteEntry, usePevv } from '../store';
import { Section, btn, btnDanger, btnPrimary } from '../ui/common';
import { isPasskeyEntry, type PasskeyEntry } from '../passkeyProvider';
import { answerProviderPrompt, providerIpc, sectionVisible, useProviderUi, type ProviderSupport } from './provider';

/** Modal cards over the whole window. Rendered in their own React root by the desktop boot. */
export function ProviderPrompts() {
  const prompts = useProviderUi((s) => s.prompts);
  const [pick, setPick] = useState<string>('');
  if (!prompts.length) return null;
  return (
    <div className="fixed inset-0 z-[9998] flex flex-col items-center justify-center gap-3 bg-black/60 p-4" role="dialog" aria-modal="true" data-testid="provider-prompts">
      {prompts.map((p) => (
        <section key={p.id} className="flex w-full max-w-md flex-col gap-3 rounded-lg border border-accent-cyan/50 bg-[#0b1226] p-4 text-ink-primary" data-testid={`provider-${p.kind}`}>
          {p.kind === 'make' ? (
            <>
              <h2 className="text-sm font-semibold text-accent-cyan">Save a passkey in PEVV?</h2>
              <p className="text-xs text-ink-secondary">Windows is creating a passkey for <b>{p.rpId}</b>{p.userName ? ` (${p.userName})` : ''}. PEVV keeps the key in your vault.</p>
              <div className="flex gap-2">
                <button type="button" className={btnPrimary} onClick={() => answerProviderPrompt(p.id, true)} data-testid="provider-make-ok">Save passkey</button>
                <button type="button" className={btnDanger} onClick={() => answerProviderPrompt(p.id, false)} data-testid="provider-make-no">Cancel</button>
              </div>
            </>
          ) : (
            <>
              <h2 className="text-sm font-semibold text-accent-cyan">Sign in to {p.rpId} with PEVV?</h2>
              {p.choices.length > 1 && (
                <ul className="flex flex-col gap-1" role="radiogroup" aria-label="Account">
                  {p.choices.map((c) => (
                    <li key={c.id}>
                      <label className="flex items-center gap-2 text-xs text-ink-secondary">
                        <input type="radio" name={`pick-${p.id}`} checked={(pick || p.choices[0]!.id) === c.id} onChange={() => setPick(c.id)} />
                        {c.userName || '(no name)'}
                      </label>
                    </li>
                  ))}
                </ul>
              )}
              {p.choices.length === 1 && <p className="text-xs text-ink-secondary">Account: <b>{p.choices[0]!.userName || '(no name)'}</b></p>}
              <div className="flex gap-2">
                <button type="button" className={btnPrimary} onClick={() => { const id = p.choices.some((c) => c.id === pick) ? pick : p.choices[0]!.id; setPick(''); answerProviderPrompt(p.id, id); }} data-testid="provider-get-ok">Sign in</button>
                <button type="button" className={btnDanger} onClick={() => answerProviderPrompt(p.id, null)} data-testid="provider-get-no">Cancel</button>
              </div>
            </>
          )}
        </section>
      ))}
    </div>
  );
}

function when(ms: number): string {
  return ms ? new Date(ms).toLocaleDateString() : '';
}

/** Settings: what Windows needs, the switch, and the passkeys PEVV holds. Hidden on Linux and on Windows 10. */
export function PasskeyProviderSection() {
  const [sup, setSup] = useState<ProviderSupport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const entries = usePevv((s) => s.entries);
  const unlocked = usePevv((s) => s.status === 'unlocked');
  const call = useCallback(async (cmd: string) => {
    const ipc = providerIpc();
    if (!ipc) return;
    setBusy(true);
    try { setSup(await ipc.invoke<ProviderSupport>(cmd)); setErr(null); } catch (e) { setErr(typeof e === 'string' ? e : (e as Error).message); } finally { setBusy(false); }
  }, []);
  useEffect(() => { void call('passkey_provider_support'); }, [call]);
  if (!providerIpc() || !sectionVisible(sup) || !sup) return null;
  const mine = entries.filter((e): e is PasskeyEntry => isPasskeyEntry(e) && e.type === 'passkey');
  const ready = sup.compiled && sup.apiPresent && sup.packaged;
  return (
    <Section title="Passkeys for other sites (Windows)" testId="pevv-passkey-provider">
      <p className="text-xs text-ink-muted">PEVV can store the passkeys you create on other sites and apps and use them to sign in, in any browser, through Windows&apos; own passkey dialog.</p>
      <ul className="list-disc pl-5 text-xs text-ink-secondary" data-testid="pevv-provider-requirements">
        <li className={sup.apiPresent ? '' : 'text-accent-gold'}>Windows 11 24H2 or later (build {sup.minBuild}+ with the current updates). This PC: build {sup.build ?? 'unknown'}.</li>
        <li className={sup.packaged ? '' : 'text-accent-gold'}>PEVV installed from the MSIX package, not the .exe or .msi installers. Windows only talks to packaged apps.</li>
        <li className={sup.compiled ? '' : 'text-accent-gold'}>A PEVV build that includes the passkey provider{sup.compiled ? '.' : ' (this one does not).'}</li>
        <li>Turned on by you in Windows: Settings &gt; Accounts &gt; Passkeys &gt; Advanced options, then switch PEVV on. PEVV cannot do that for you.</li>
      </ul>
      {sup.reason && <p className="text-xs text-accent-gold" data-testid="pevv-provider-reason">{sup.reason}</p>}
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={btnPrimary} disabled={!ready || busy || sup.registered === true} onClick={() => void call('passkey_provider_register')} data-testid="pevv-provider-register">Add PEVV to Windows</button>
        <button type="button" className={btn} disabled={!ready || busy || sup.registered !== true} onClick={() => void call('passkey_provider_unregister')} data-testid="pevv-provider-unregister">Remove PEVV from Windows</button>
        <span className="text-xs text-ink-secondary" data-testid="pevv-provider-state">
          {sup.registered === null ? 'Not registered with Windows yet.' : sup.registered ? (sup.enabled === true ? 'Registered and switched on in Windows.' : sup.enabled === false ? 'Registered. Switch it on in Windows Settings.' : 'Registered.') : 'Not registered with Windows yet.'}
        </span>
      </div>
      <h3 className="text-xs font-semibold text-ink-secondary">Passkeys held by PEVV ({mine.length})</h3>
      {!unlocked && <p className="text-xs text-ink-muted">Unlock PEVV to see them.</p>}
      {mine.length === 0 && unlocked && <p className="text-xs text-ink-muted" data-testid="pevv-provider-empty">None yet. When a site offers to create a passkey, choose PEVV in the Windows dialog.</p>}
      <ul className="flex flex-col gap-1" data-testid="pevv-provider-list">
        {mine.map((p) => (
          <li key={p.id} className="flex items-center gap-2 text-xs text-ink-secondary">
            <span className="min-w-0 flex-1 truncate">{p.rpId}{p.userName ? ` · ${p.userName}` : ''}{p.created ? ` · ${when(p.created)}` : ''}</span>
            <button type="button" className={btnDanger} onClick={() => { if (window.confirm(`Delete the passkey for ${p.rpId}${p.userName ? ` (${p.userName})` : ''}? You will not be able to sign in with it again, and the site keeps the public half until you remove it there.`)) void deleteEntry(p.id).catch((e: Error) => setErr(e.message)); }} data-testid={`pevv-provider-delete-${p.id}`}>Delete</button>
          </li>
        ))}
      </ul>
      {err && <p className="text-xs text-red-300" role="alert">{err}</p>}
    </Section>
  );
}
