/**
 * The `pevv` command-line tool's approvals, in the webview: "may this program use PEVV at all?" and
 * "may it have these variables now?". The shell does the authenticating (it knows which program is
 * calling) and blocks the tool until the person answers here. Values never reach this module:
 * prompts carry the command and variable *names*.
 */
import { create } from 'zustand';
import type { LinkIpc } from './link';

export const EVENT_CLI_PROMPT = 'cli-prompt';
export const EVENT_CLI_SERVED = 'cli-served';

export interface CliSource { kind: 'project' | 'env' | 'active'; name: string; env: string }

export type CliPrompt =
  | { kind: 'client'; id: number; exe: string; changed: boolean }
  | { kind: 'secrets'; id: number; purpose: 'run' | 'env'; command: string[]; cwd: string; exe: string; format: string | null; sources: CliSource[]; names: string[] };

export type CliAnswer = 'deny' | 'once' | '8h';

interface CliUiState { prompts: CliPrompt[] }
export const useCliUi = create<CliUiState>()(() => ({ prompts: [] }));

let api: LinkIpc | null = null;

export async function answerCli(id: number, answer: CliAnswer): Promise<void> {
  useCliUi.setState({ prompts: useCliUi.getState().prompts.filter((p) => p.id !== id) });
  await api?.invoke('cli_prompt_answer', { id, answer });
}

/** A prompt event from the shell: open one, or close one that was answered or timed out. */
export function applyPromptEvent(p: { kind: string; id: number } & Record<string, unknown>): void {
  const rest = useCliUi.getState().prompts.filter((x) => x.id !== p.id);
  if (p.kind === 'client' || p.kind === 'secrets') useCliUi.setState({ prompts: [...rest, p as unknown as CliPrompt] });
  else useCliUi.setState({ prompts: rest });
}

export interface CliState {
  clients: Array<{ path: string; at: number }>;
  commands: Array<{ key: string; label: string; until: number }>;
}

export function cliIpc(): LinkIpc | null {
  return api;
}

/** Shows `pevv` approvals and writes the activity log line when variables were handed over. */
export async function startCli(ipc: LinkIpc, audit: (purpose: 'cli-run' | 'cli-env', detail: string) => void): Promise<() => void> {
  api = ipc;
  const offPrompt = await ipc.listen<{ kind: string; id: number } & Record<string, unknown>>(EVENT_CLI_PROMPT, applyPromptEvent);
  const offServed = await ipc.listen<{ purpose: string; program: string; variables: number }>(EVENT_CLI_SERVED, (s) => {
    audit(s.purpose === 'env' ? 'cli-env' : 'cli-run', `${String(s.program).slice(0, 40)} · ${Number(s.variables) || 0} variable(s)`);
  });
  void ipc.invoke<Array<{ kind: string; id: number } & Record<string, unknown>>>('cli_prompts').then((list) => list.forEach(applyPromptEvent), () => undefined);
  return () => { offPrompt(); offServed(); api = null; };
}
