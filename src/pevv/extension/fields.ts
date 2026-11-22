/**
 * DOM helpers for the PEVV content script. They only touch the field the user
 * focused (a password field, or the username field of a form that has one) and
 * the password / username partner in the same form.
 */

const USER_TYPES = new Set(['text', 'email', 'tel', '']);

export function isPasswordField(el: Element | null | undefined): el is HTMLInputElement {
  return !!el && el instanceof HTMLInputElement && el.type === 'password' && !el.disabled && !el.readOnly;
}

function isUserField(el: Element | null | undefined): el is HTMLInputElement {
  if (!el || !(el instanceof HTMLInputElement) || el.disabled || el.readOnly) return false;
  return USER_TYPES.has(el.type) || el.autocomplete === 'username' || el.autocomplete === 'email';
}

function scope(el: HTMLInputElement): ParentNode {
  return el.form ?? el.closest('form') ?? el.ownerDocument;
}

function inputs(root: ParentNode): HTMLInputElement[] {
  return Array.from(root.querySelectorAll('input'));
}

/** The username field that belongs to a password field: the last text-like input before it. */
export function usernameFor(pw: HTMLInputElement): HTMLInputElement | null {
  const list = inputs(scope(pw));
  const at = list.indexOf(pw);
  const hinted = list.find((i) => i !== pw && (i.autocomplete === 'username' || i.autocomplete === 'email') && isUserField(i));
  if (hinted) return hinted;
  for (let i = at - 1; i >= 0; i--) if (isUserField(list[i])) return list[i]!;
  return null;
}

export function passwordFor(user: HTMLInputElement): HTMLInputElement | null {
  const list = inputs(scope(user));
  const at = list.indexOf(user);
  for (let i = at + 1; i < list.length; i++) if (isPasswordField(list[i])) return list[i]!;
  return list.find((i) => isPasswordField(i)) ?? null;
}

export interface Target { password: HTMLInputElement; username: HTMLInputElement | null }

/**
 * Resolve the focused element to a login target. Returns null when the focus is
 * not on a password field or on a username field paired with one.
 */
export function targetFrom(active: Element | null): Target | null {
  if (isPasswordField(active)) return { password: active, username: usernameFor(active) };
  if (isUserField(active)) {
    const pw = passwordFor(active);
    if (pw) return { password: pw, username: active };
  }
  return null;
}

/** Set a value the way a typing user would, so React / Vue / Angular forms see it. */
export function setValue(el: HTMLInputElement, value: string): void {
  const proto = Object.getPrototypeOf(el) as object;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set ?? Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  el.focus();
  if (setter) setter.call(el, value);
  else el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

export function fillLogin(t: Target, username: string, password: string): void {
  if (t.username && username) setValue(t.username, username);
  setValue(t.password, password);
}

/**
 * A generated password goes into the focused password field and any other
 * empty password field of the same form (the "confirm password" box).
 */
export function fillGenerated(active: Element | null, password: string): number {
  if (!isPasswordField(active)) return 0;
  const others = inputs(scope(active)).filter((i) => i !== active && isPasswordField(i) && !i.value);
  setValue(active, password);
  for (const o of others) setValue(o, password);
  return 1 + others.length;
}

/** What a submitted form would send: the first filled password and its username. */
export function captured(form: HTMLFormElement | ParentNode): { username: string; password: string } | null {
  const pw = inputs(form).find((i) => i.type === 'password' && i.value);
  if (!pw) return null;
  const user = usernameFor(pw);
  return { username: user?.value.trim() ?? '', password: pw.value };
}
