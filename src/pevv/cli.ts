/**
 * `pevv run` / `pevv env`, the part that needs the unlocked vault: which variables a request
 * names. It reuses the vault's own concepts instead of adding new ones:
 *
 *  - an environment is one of `meta.environments` and its variables are the `env` items whose
 *    `env` field names it (`envVars(env)` in the store, the same thing `$VAR` expansion and the
 *    terminal's `env` command read);
 *  - `--project NAME` is the program id `project:NAME`: it runs with the environment linked to it
 *    (Settings > Project environments, `vault env link`), else the active environment, exactly
 *    like `envForProgram`;
 *  - `--env ID` names an environment directly; with neither option the active environment is used.
 *
 * Several sources are merged in order (projects, then environments, in the order given); a later
 * source wins a name clash, so `--env prod` after `--project api` overrides what the project's
 * environment sets.
 */
import { ENV_NAME } from './model';

export interface CliVault {
  hasEnv(name: string): boolean;
  activeEnv(): string;
  /** The environment a program runs with: its linked one, else the active one. */
  envForProgram(programId: string): string;
  /** Variables of one environment (empty if locked). */
  envVars(env: string): Record<string, string>;
}

export interface CliSource { kind: 'project' | 'env' | 'active'; name: string; env: string }
export interface CliVars { vars: Array<{ name: string; value: string }>; sources: CliSource[] }

const NAME = /^[\w.:-]{1,64}$/;

/** Throws a short error code (`no-such-env`, `bad-request`) the shell passes back to the tool. */
export function resolveCliEnv(v: CliVault, req: { projects?: unknown; envs?: unknown }): CliVars {
  const list = (x: unknown): string[] => (Array.isArray(x) ? x.filter((n): n is string => typeof n === 'string') : []);
  const projects = list(req.projects);
  const envs = list(req.envs);
  if (projects.length + envs.length > 16 || ![...projects, ...envs].every((n) => NAME.test(n))) throw new Error('bad-request');
  const sources: CliSource[] = [];
  for (const name of projects) sources.push({ kind: 'project', name, env: v.envForProgram(`project:${name}`) });
  for (const name of envs) {
    if (!v.hasEnv(name)) throw new Error('no-such-env');
    sources.push({ kind: 'env', name, env: name });
  }
  if (!sources.length) sources.push({ kind: 'active', name: '', env: v.activeEnv() });
  const merged = new Map<string, string>();
  for (const s of sources) for (const [name, value] of Object.entries(v.envVars(s.env))) if (ENV_NAME.test(name)) merged.set(name, value);
  return { vars: [...merged].map(([name, value]) => ({ name, value })), sources };
}

/** A short line for the activity log: the program (not its arguments, which may hold secrets). */
export function programOf(command: string[]): string {
  return (command[0] ?? '').split(/[\\/]/).pop()?.slice(0, 40) ?? '';
}
