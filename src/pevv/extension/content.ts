/**
 * PEVV content script. Injected on demand (activeTab) when the user picks a
 * login or a generated password in the popup, and registered on the hosts the
 * user approved for autofill. It never sees the vault key: it asks the worker
 * for one username and password for its own top-level origin.
 */
import type { ContentCommand, ContentRequest, LoginRef, Redeemed, Reply } from './protocol';
import { captured, fillGenerated, fillLogin, isPasswordField, targetFrom } from './fields';

declare global { interface Window { __pevvExt?: boolean } }

function ask<T>(msg: ContentRequest): Promise<Reply<T>> {
  return chrome.runtime.sendMessage<Reply<T>>(msg).catch((e: Error) => ({ ok: false as const, error: e.message }));
}

function apply(r: Redeemed, active: Element | null): { filled: number } {
  if (r.kind === 'generated') {
    const n = fillGenerated(active, r.password);
    if (!n) throw new Error('Click the password field on the page first.');
    return { filled: n };
  }
  const t = targetFrom(active);
  if (!t) throw new Error('Click the password or username field on the page first.');
  fillLogin(t, r.username, r.password);
  return { filled: t.username ? 2 : 1 };
}

let lastFocused: Element | null = null;

function focused(): Element | null {
  const a = document.activeElement;
  if (a && a !== document.body && targetFrom(a)) return a;
  return lastFocused && lastFocused.isConnected ? lastFocused : a;
}

/* ───────────── inline button (approved hosts only) ───────────── */

let host: HTMLElement | null = null;
let shadow: ShadowRoot | null = null;
let anchor: HTMLInputElement | null = null;

function hideButton(): void {
  host?.remove();
  host = null;
  shadow = null;
  anchor = null;
}

function place(): void {
  if (!host || !anchor) return;
  const r = anchor.getBoundingClientRect();
  host.style.top = `${window.scrollY + r.top + Math.max(0, (r.height - 24) / 2)}px`;
  host.style.left = `${window.scrollX + r.right - 28}px`;
}

function note(text: string): void {
  if (!shadow) return;
  const menu = shadow.querySelector('.menu') as HTMLElement;
  menu.replaceChildren();
  const p = document.createElement('p');
  p.textContent = text;
  menu.append(p);
  menu.hidden = false;
}

async function fillOne(id: string): Promise<void> {
  const target = anchor;
  const r = await ask<Redeemed>({ type: 'cs-fill', id });
  if (!r.ok) { note(r.error === 'locked' ? 'PEVV is locked. Unlock it from the toolbar.' : r.error); return; }
  try { apply(r.value, target); hideButton(); } catch (e) { note((e as Error).message); }
}

async function onButton(ev: MouseEvent): Promise<void> {
  // Only a real click by the user, never a click the page script made.
  if (!ev.isTrusted) return;
  ev.preventDefault();
  ev.stopPropagation();
  const r = await ask<LoginRef[]>({ type: 'cs-list' });
  if (!r.ok) { note(r.error === 'locked' ? 'PEVV is locked. Unlock it from the toolbar.' : r.error); return; }
  if (r.value.length === 0) { note('No login saved for this site.'); return; }
  if (r.value.length === 1) { await fillOne(r.value[0]!.id); return; }
  const menu = shadow!.querySelector('.menu') as HTMLElement;
  menu.replaceChildren();
  for (const l of r.value) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = l.username ? `${l.title} · ${l.username}` : l.title;
    b.addEventListener('click', (e) => { if (e.isTrusted) void fillOne(l.id); });
    menu.append(b);
  }
  menu.hidden = false;
}

function showButton(field: HTMLInputElement): void {
  if (anchor === field && host) return;
  hideButton();
  anchor = field;
  host = document.createElement('pevv-fill');
  host.style.cssText = 'position:absolute;z-index:2147483647;width:24px;height:24px;margin:0;padding:0;border:0;';
  shadow = host.attachShadow({ mode: 'closed' });
  shadow.innerHTML = `<style>
    button.key{all:initial;cursor:pointer;width:24px;height:24px;border-radius:6px;background:#12182e;color:#4dd4d4;font:14px/24px system-ui;text-align:center;box-shadow:0 0 0 1px #4dd4d4}
    .menu{position:absolute;top:28px;right:0;min-width:200px;max-width:280px;background:#12182e;color:#e8ecf4;border:1px solid #364266;border-radius:8px;padding:4px;font:12px/1.4 system-ui}
    .menu button{all:initial;display:block;box-sizing:border-box;width:100%;padding:6px 8px;color:#e8ecf4;font:12px/1.4 system-ui;cursor:pointer;border-radius:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .menu button:hover{background:#1c2442}
    .menu p{margin:4px 8px}
  </style><button class="key" type="button" title="Fill from PEVV" aria-label="Fill from PEVV">🔐</button><div class="menu" hidden></div>`;
  shadow.querySelector('button.key')!.addEventListener('click', (e) => void onButton(e as MouseEvent));
  document.documentElement.append(host);
  place();
}

function watchInline(): void {
  document.addEventListener('focusin', (e) => {
    const t = targetFrom(e.target as Element);
    if (t) showButton(t.password === e.target ? t.password : (e.target as HTMLInputElement));
  }, true);
  document.addEventListener('pointerdown', (e) => {
    if (host && e.target !== host && e.target !== anchor) hideButton();
  }, true);
  window.addEventListener('resize', place);
  window.addEventListener('scroll', place, true);
  // Offer to save what a login or sign-up form sends.
  const offer = (root: HTMLFormElement | ParentNode | null) => {
    if (!root) return;
    const c = captured(root);
    if (c) void ask({ type: 'cs-offer', username: c.username, password: c.password });
  };
  document.addEventListener('submit', (e) => offer(e.target as HTMLFormElement), true);
  document.addEventListener('click', (e) => {
    const b = (e.target as Element | null)?.closest?.('button,input[type=submit]') as HTMLButtonElement | HTMLInputElement | null;
    if (!b || !e.isTrusted) return;
    if (b.type !== 'submit' && b.getAttribute('type') !== null) return;
    const root = b.form ?? b.closest('form');
    // Forms without a <form> tag: look at the password field next to the button.
    if (root) offer(root);
    else if (lastFocused && isPasswordField(lastFocused)) offer(lastFocused.parentElement);
  }, true);
}

function main(): void {
  if (window.__pevvExt || window.top !== window) return;
  window.__pevvExt = true;
  document.addEventListener('focusin', (e) => { if (targetFrom(e.target as Element)) lastFocused = e.target as Element; }, true);
  chrome.runtime.onMessage.addListener((msg: unknown, _sender, sendResponse) => {
    if ((msg as ContentCommand)?.type !== 'pevv-run') return;
    const active = focused();
    void ask<Redeemed>({ type: 'cs-redeem' }).then((r) => {
      if (!r.ok) { sendResponse(r); return; }
      try { sendResponse({ ok: true, value: apply(r.value, active) }); } catch (e) { sendResponse({ ok: false, error: (e as Error).message }); }
    });
    return true;
  });
  void ask<{ inline: boolean }>({ type: 'cs-hello' }).then((r) => { if (r.ok && r.value.inline) watchInline(); });
}

main();
