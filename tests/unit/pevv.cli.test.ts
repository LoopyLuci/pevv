import { beforeEach, describe, expect, it } from 'vitest';
import { programOf, resolveCliEnv, type CliVault } from '@/pevv/cli';
import { answer, type LinkIpc, type LinkStoreApi } from '@/pevv/desktop/link';
import { answerCli, applyPromptEvent, startCli, useCliUi, type CliPrompt } from '@/pevv/desktop/cli';
import { commandText } from '@/pevv/desktop/CliAccess';

/** A vault with two environments, one project linked to `prod`, and everything else on the active `dev`. */
function vault(over: Partial<CliVault> = {}): CliVault {
  const vars: Record<string, Record<string, string>> = {
    dev: { API_URL: 'https://dev.test', TOKEN: 'dev-token', 'bad name': 'x', lower_ok: '1' },
    prod: { API_URL: 'https://prod.test', DB: 'postgres://prod' },
    empty: {},
  };
  const linked: Record<string, string> = { 'project:api': 'prod', 'project:gone': 'deleted-env' };
  return {
    hasEnv: (n) => n in vars,
    activeEnv: () => 'dev',
    // Same rule as the store's envForProgram: the linked environment if it still exists, else the active one.
    envForProgram: (pid) => (linked[pid] && linked[pid] in vars ? linked[pid]! : 'dev'),
    envVars: (env) => vars[env] ?? {},
    ...over,
  };
}

describe('pevv run / env: which variables a request names', () => {
  it('with no option it is the active environment, and bad names are left out', () => {
    const r = resolveCliEnv(vault(), {});
    expect(r.sources).toEqual([{ kind: 'active', name: '', env: 'dev' }]);
    expect(Object.fromEntries(r.vars.map((v) => [v.name, v.value]))).toEqual({ API_URL: 'https://dev.test', TOKEN: 'dev-token', lower_ok: '1' });
  });

  it('--project uses the environment linked to project:NAME, else the active one', () => {
    expect(resolveCliEnv(vault(), { projects: ['api'] }).sources).toEqual([{ kind: 'project', name: 'api', env: 'prod' }]);
    expect(resolveCliEnv(vault(), { projects: ['other'] }).sources).toEqual([{ kind: 'project', name: 'other', env: 'dev' }]);
    // A link to an environment that was deleted falls back to the active one.
    expect(resolveCliEnv(vault(), { projects: ['gone'] }).sources[0]!.env).toBe('dev');
  });

  it('--env names an environment directly and it must exist', () => {
    const r = resolveCliEnv(vault(), { envs: ['prod'] });
    expect(r.sources).toEqual([{ kind: 'env', name: 'prod', env: 'prod' }]);
    expect(r.vars.find((v) => v.name === 'DB')?.value).toBe('postgres://prod');
    expect(() => resolveCliEnv(vault(), { envs: ['staging'] })).toThrow('no-such-env');
  });

  it('several sources merge in order and the later one wins a clash', () => {
    const r = resolveCliEnv(vault(), { projects: ['other'], envs: ['prod'] });
    const m = Object.fromEntries(r.vars.map((v) => [v.name, v.value]));
    expect(m.API_URL).toBe('https://prod.test');
    expect(m.TOKEN).toBe('dev-token');
    expect(m.DB).toBe('postgres://prod');
    expect(r.sources.map((s) => s.kind)).toEqual(['project', 'env']);
  });

  it('an environment with no variables gives an empty list (the shell reports it)', () => {
    expect(resolveCliEnv(vault(), { envs: ['empty'] }).vars).toEqual([]);
  });

  it('refuses odd names and too many sources', () => {
    expect(() => resolveCliEnv(vault(), { projects: ['a b'] })).toThrow('bad-request');
    expect(() => resolveCliEnv(vault(), { envs: ['x/y'] })).toThrow('bad-request');
    expect(() => resolveCliEnv(vault(), { projects: Array.from({ length: 17 }, (_, i) => `p${i}`) })).toThrow('bad-request');
    expect(() => resolveCliEnv(vault(), { projects: [5, null] as never })).not.toThrow();
  });

  it('the log line names the program and never its arguments', () => {
    expect(programOf(['C:\\tools\\npm.cmd', '--token', 'sekrit'])).toBe('npm.cmd');
    expect(programOf(['/usr/bin/curl', '-H', 'Authorization: x'])).toBe('curl');
    expect(programOf([])).toBe('');
  });
});

describe('the shell asks the vault window for variables', () => {
  function store(unlocked: boolean, cli?: CliVault): LinkStoreApi {
    return { unlocked: () => unlocked, entries: () => [], onUnlockedChange: () => () => undefined, saveEntry: async () => undefined, ...(cli ? { cli } : {}) };
  }

  it('answers cli-env only when unlocked', () => {
    const r = answer(store(true, vault()), { id: 1, kind: 'cli-env', body: { projects: ['api'], envs: [] } }) as { vars: Array<{ name: string }>; sources: unknown[] };
    expect(r.vars.map((v) => v.name).sort()).toEqual(['API_URL', 'DB']);
    expect(() => answer(store(false, vault()), { id: 1, kind: 'cli-env', body: {} })).toThrow('locked');
  });

  it('is not available to the extension kinds and without a cli vault', () => {
    expect(() => answer(store(true), { id: 1, kind: 'cli-env', body: {} })).toThrow('unknown-type');
    expect(() => answer(store(true, vault()), { id: 1, kind: 'frobnicate', body: {} })).toThrow('unknown-type');
  });
});

describe('pevv approvals in the vault window', () => {
  const client: CliPrompt = { kind: 'client', id: 1, exe: 'C:\\pevv\\pevv.exe', changed: false };
  const secrets: CliPrompt = { kind: 'secrets', id: 2, purpose: 'run', command: ['npm', 'test'], cwd: 'C:\\w', exe: 'C:\\pevv\\pevv.exe', format: null, sources: [{ kind: 'project', name: 'api', env: 'prod' }], names: ['API_URL', 'DB'] };

  beforeEach(() => useCliUi.setState({ prompts: [] }));

  it('opens, replaces and closes prompts by id', () => {
    applyPromptEvent(client as never);
    applyPromptEvent(secrets as never);
    expect(useCliUi.getState().prompts.map((p) => p.id)).toEqual([1, 2]);
    applyPromptEvent({ ...client, exe: 'D:\\other.exe' } as never);
    expect(useCliUi.getState().prompts).toHaveLength(2);
    applyPromptEvent({ kind: 'closed', id: 1 });
    expect(useCliUi.getState().prompts.map((p) => p.id)).toEqual([2]);
  });

  it('carries the command and names but no value', () => {
    expect(JSON.stringify(secrets)).not.toMatch(/https?:|postgres/);
    expect(commandText(['git', 'commit', '-m', 'a message'])).toBe('git commit -m "a message"');
    expect(commandText(['x'.repeat(400)]).length).toBeLessThan(320);
  });

  it('an answer goes back to the shell and removes the card', async () => {
    const calls: Array<[string, unknown]> = [];
    const ipc: LinkIpc = {
      invoke: async <T,>(cmd: string, args?: Record<string, unknown>) => { calls.push([cmd, args]); return (cmd === 'cli_prompts' ? [] : undefined) as T; },
      listen: async () => () => undefined,
    };
    const audits: string[] = [];
    await startCli(ipc, (purpose, detail) => audits.push(`${purpose}:${detail}`));
    applyPromptEvent(secrets as never);
    await answerCli(2, '8h');
    expect(useCliUi.getState().prompts).toEqual([]);
    expect(calls).toContainEqual(['cli_prompt_answer', { id: 2, answer: '8h' }]);
  });

  it('the served event writes one log line with the program and a count', async () => {
    const handlers = new Map<string, (p: never) => void>();
    const ipc: LinkIpc = {
      invoke: async <T,>() => [] as T,
      listen: async <P,>(e: string, fn: (p: P) => void) => { handlers.set(e, fn as (p: never) => void); return () => undefined; },
    };
    const audits: string[] = [];
    await startCli(ipc, (purpose, detail) => audits.push(`${purpose}:${detail}`));
    handlers.get('cli-served')!({ purpose: 'run', program: 'npm', variables: 3 } as never);
    handlers.get('cli-served')!({ purpose: 'env', program: 'pevv', variables: 1 } as never);
    expect(audits).toEqual(['cli-run:npm · 3 variable(s)', 'cli-env:pevv · 1 variable(s)']);
  });
});
