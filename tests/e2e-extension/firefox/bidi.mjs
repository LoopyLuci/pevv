/**
 * A small WebDriver BiDi client for the installed Firefox. Playwright's Firefox
 * cannot load an extension; Firefox's own BiDi can install one temporarily
 * (unsigned is fine for a temporary add-on).
 */
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';

export const FIREFOX = process.env.FIREFOX_BIN
  ?? (process.platform === 'win32' ? 'C:/Program Files/Mozilla Firefox/firefox.exe' : process.platform === 'darwin' ? '/Applications/Firefox.app/Contents/MacOS/firefox' : 'firefox');

function kill(proc) {
  if (process.platform === 'win32') return new Promise((r) => spawn('taskkill', ['/T', '/F', '/PID', String(proc.pid)]).on('exit', r));
  proc.kill('SIGKILL');
  return Promise.resolve();
}

export async function launch({ profile, prefs = {}, headless = !process.env.HEADED }) {
  rmSync(profile, { recursive: true, force: true });
  mkdirSync(profile, { recursive: true });
  writeFileSync(`${profile}/user.js`, Object.entries(prefs).map(([k, v]) => `user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`).join('\n'));
  const args = ['--remote-debugging-port', '0', '--profile', profile, '--no-remote', '--new-instance'];
  if (headless) args.push('--headless');
  const proc = spawn(FIREFOX, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const wsUrl = await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`Firefox did not start (${FIREFOX})`)), 60_000);
    const on = (d) => {
      const m = /WebDriver BiDi listening on (ws:\/\/\S+)/.exec(String(d));
      if (m) { clearTimeout(t); resolve(m[1]); }
    };
    proc.stderr.on('data', on);
    proc.stdout.on('data', on);
    proc.on('exit', (c) => reject(new Error(`Firefox exited (${c})`)));
  });
  const ws = new WebSocket(`${wsUrl.replace(/\/$/, '')}/session`);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = () => j(new Error('BiDi socket failed')); });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (e) => {
    const m = JSON.parse(String(e.data));
    const p = m.id !== undefined ? pending.get(m.id) : undefined;
    if (!p) return;
    pending.delete(m.id);
    if (m.type === 'error') p.reject(new Error(`${p.method}: ${m.error}: ${m.message}`));
    else p.resolve(m.result);
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const i = ++id;
    pending.set(i, { resolve, reject, method });
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  await send('session.new', { capabilities: { alwaysMatch: { acceptInsecureCerts: true } } });

  /** Run `fn(...args)` in the page and return its (JSON) value. */
  const run = async (context, fn, ...args) => {
    const r = await send('script.callFunction', {
      functionDeclaration: String(fn),
      arguments: args.map((value) => ({ type: 'string', value: JSON.stringify(value) })),
      target: { context },
      awaitPromise: true,
      resultOwnership: 'none',
      serializationOptions: { maxObjectDepth: 0 },
    }).catch((e) => ({ type: 'exception', exceptionDetails: { text: e.message } }));
    if (r.type === 'exception') throw new Error(`in page: ${r.exceptionDetails?.text ?? 'error'}`);
    return r.result.type === 'string' ? JSON.parse(r.result.value) : undefined;
  };

  return {
    send,
    /** `fn` gets its arguments as JSON strings; wrap so it can take plain values and return any JSON. */
    eval: (context, fn, ...args) => run(context, `async (...a) => JSON.stringify(await (${String(fn)})(...a.map((x) => JSON.parse(x))) ?? null)`, ...args),
    async tab(url) {
      const { context } = await send('browsingContext.create', { type: 'tab' });
      if (url) await send('browsingContext.navigate', { context, url, wait: 'complete' });
      return context;
    },
    goto: (context, url) => send('browsingContext.navigate', { context, url, wait: 'complete' }),
    reload: (context) => send('browsingContext.reload', { context, wait: 'complete' }),
    /** A trusted click at the centre of the element's box (the inline fill button only accepts trusted clicks). */
    async click(context, x, y) {
      await send('browsingContext.activate', { context });
      await send('input.performActions', {
        context,
        actions: [{ type: 'pointer', id: 'mouse', parameters: { pointerType: 'mouse' }, actions: [
          { type: 'pointerMove', x: Math.round(x), y: Math.round(y) }, { type: 'pointerDown', button: 0 }, { type: 'pointerUp', button: 0 },
        ] }],
      });
    },
    async close() {
      try { await send('browser.close'); } catch { /* already gone */ }
      ws.close();
      await kill(proc);
    },
  };
}
