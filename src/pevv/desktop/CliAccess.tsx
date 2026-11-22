/**
 * Desktop-only UI for the `pevv` command-line tool: the approvals the person must answer (a program
 * asking to use PEVV; a command asking for variables) and the Settings section where they can be
 * revoked. Plain English on purpose: this is a security prompt.
 */
import { useCallback, useEffect, useState } from 'react';
import { Section, btn, btnDanger, btnPrimary } from '../ui/common';
import { answerCli, cliIpc, useCliUi, type CliPrompt, type CliSource, type CliState } from './cli';

function sourceText(s: CliSource): string {
  if (s.kind === 'project') return `project ${s.name} (environment ${s.env})`;
  if (s.kind === 'env') return `environment ${s.env}`;
  return `the active environment (${s.env})`;
}

/** One-line command, shortened so a long argument cannot push the buttons off the card. */
export function commandText(command: string[]): string {
  const line = command.map((a) => (/[\s"']/.test(a) ? JSON.stringify(a) : a)).join(' ');
  return line.length > 300 ? `${line.slice(0, 300)}…` : line;
}

function ClientCard({ p }: { p: Extract<CliPrompt, { kind: 'client' }> }) {
  return (
    <section className="flex w-full max-w-md flex-col gap-3 rounded-lg border border-accent-gold/50 bg-[#0b1226] p-4 text-ink-primary" data-testid="cli-client-prompt">
      <h2 className="text-sm font-semibold text-accent-gold">{p.changed ? 'A program you allowed has changed' : 'Allow a program to use PEVV?'}</h2>
      <p className="text-xs text-ink-secondary">
        {p.changed
          ? 'This program is at the same place as one you allowed before, but the file is different now (an update, or something else). Allow it again only if you expected that.'
          : 'This program wants to talk to PEVV, like the pevv command-line tool does. Allowing it does not give it any secret: each request for variables still asks you.'}
      </p>
      <code className="break-all rounded bg-space-deep px-3 py-2 font-mono text-xs text-cyan-100" data-testid="cli-client-exe">{p.exe}</code>
      <div className="flex gap-2">
        <button type="button" className={btnPrimary} onClick={() => void answerCli(p.id, 'once')} data-testid="cli-client-allow">Allow</button>
        <button type="button" className={btnDanger} onClick={() => void answerCli(p.id, 'deny')} data-testid="cli-client-deny">Don&apos;t allow</button>
      </div>
    </section>
  );
}

function SecretsCard({ p }: { p: Extract<CliPrompt, { kind: 'secrets' }> }) {
  const run = p.purpose === 'run';
  return (
    <section className="flex w-full max-w-md flex-col gap-2 rounded-lg border border-accent-cyan/50 bg-[#0b1226] p-4 text-ink-primary" data-testid="cli-secrets-prompt">
      <h2 className="text-sm font-semibold text-accent-cyan">{run ? 'Run a command with your secrets?' : 'Print your secrets?'}</h2>
      {run ? (
        <>
          <p className="text-xs text-ink-secondary">This command will start with the variables below added to its environment. It never prints them; the program itself can still use or leak them.</p>
          <code className="max-h-24 overflow-auto break-all rounded bg-space-deep px-3 py-2 font-mono text-xs text-cyan-100" data-testid="cli-command">{commandText(p.command)}</code>
          {p.cwd && <p className="break-all text-[0.65rem] text-ink-muted">In {p.cwd}</p>}
        </>
      ) : (
        <p className="text-xs text-accent-gold">The values will be written, as <b>{p.format}</b>, to the output of the program below. If that output is saved or shown anywhere, the secrets go with it.</p>
      )}
      <p className="text-xs text-ink-secondary">From {p.sources.map(sourceText).join(' and ')}:</p>
      <ul className="flex max-h-28 flex-wrap gap-1 overflow-auto" data-testid="cli-names">
        {p.names.map((n) => <li key={n} className="rounded bg-space-deep px-2 py-0.5 font-mono text-[0.7rem] text-cyan-100">{n}</li>)}
      </ul>
      <p className="break-all text-[0.65rem] text-ink-muted">Asked by {p.exe}</p>
      <div className="flex flex-wrap gap-2">
        <button type="button" className={btnPrimary} onClick={() => void answerCli(p.id, 'once')} data-testid="cli-allow-once">{run ? 'Run it' : 'Print them'}</button>
        {run && <button type="button" className={btn} onClick={() => void answerCli(p.id, '8h')} data-testid="cli-allow-8h">Allow this command for 8 h</button>}
        <button type="button" className={btnDanger} onClick={() => void answerCli(p.id, 'deny')} data-testid="cli-deny">Decline</button>
      </div>
    </section>
  );
}

/** Modal cards over the whole window. Rendered in their own React root by the desktop boot. */
export function CliPrompts() {
  const prompts = useCliUi((s) => s.prompts);
  if (!prompts.length) return null;
  return (
    <div className="fixed inset-0 z-[9998] flex flex-col items-center justify-center gap-3 bg-black/60 p-4" role="dialog" aria-modal="true" data-testid="cli-prompts">
      {prompts.map((p) => (p.kind === 'client' ? <ClientCard key={p.id} p={p} /> : <SecretsCard key={p.id} p={p} />))}
    </div>
  );
}

function until(ms: number): string {
  return new Date(ms).toLocaleString();
}

/** Settings: which programs may use PEVV, which commands are allowed for 8 h, and revoking either. */
export function CliAccessSection() {
  const [st, setSt] = useState<CliState | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const call = useCallback(async (cmd: string, args?: Record<string, unknown>) => {
    const ipc = cliIpc();
    if (!ipc) return;
    try { setSt(await ipc.invoke<CliState>(cmd, args)); setErr(null); } catch (e) { setErr(typeof e === 'string' ? e : (e as Error).message); }
  }, []);
  useEffect(() => { void call('cli_state'); }, [call]);
  if (!cliIpc()) return null;
  return (
    <Section title="Command line (pevv)" testId="pevv-cli-access">
      <p className="text-xs text-ink-muted">The <code>pevv</code> tool next to this app (<code>pevv run -- command</code>, <code>pevv env</code>) can ask for your environment variables. PEVV asks you the first time each program calls, and again for every request for secrets.</p>
      {st && (
        <>
          <h4 className="text-xs font-semibold text-ink-secondary">Programs allowed to call PEVV</h4>
          {st.clients.length === 0 ? <p className="text-xs text-ink-muted">None yet.</p> : (
            <ul className="flex flex-col gap-1" data-testid="pevv-cli-clients">
              {st.clients.map((c) => (
                <li key={c.path} className="flex items-center gap-2 text-xs text-ink-secondary">
                  <span className="min-w-0 flex-1 break-all font-mono">{c.path}{c.at ? ` (allowed ${new Date(c.at).toLocaleDateString()})` : ''}</span>
                  <button type="button" className={btnDanger} onClick={() => void call('cli_revoke_client', { path: c.path })}>Revoke</button>
                </li>
              ))}
            </ul>
          )}
          <h4 className="text-xs font-semibold text-ink-secondary">Commands allowed for 8 hours</h4>
          {st.commands.length === 0 ? <p className="text-xs text-ink-muted">None.</p> : (
            <ul className="flex flex-col gap-1" data-testid="pevv-cli-commands">
              {st.commands.map((c) => (
                <li key={c.key} className="flex items-center gap-2 text-xs text-ink-secondary">
                  <span className="min-w-0 flex-1 break-all font-mono">{c.label} <span className="font-sans text-ink-muted">(until {until(c.until)})</span></span>
                  <button type="button" className={btnDanger} onClick={() => void call('cli_revoke_command', { key: c.key })}>Revoke</button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {err && <p className="text-xs text-red-300" role="alert">{err}</p>}
    </Section>
  );
}
