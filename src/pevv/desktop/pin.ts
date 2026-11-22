/** A small PIN dialog for security keys on Linux (Windows shows its own). Plain DOM: it runs outside React. */
export function askPin(retry: boolean): Promise<string | null> {
  return new Promise((resolve) => {
    const wrap = document.createElement('div');
    wrap.setAttribute('role', 'dialog');
    wrap.setAttribute('aria-modal', 'true');
    wrap.setAttribute('data-testid', 'pevv-pin-dialog');
    wrap.style.cssText = 'position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.6)';
    const box = document.createElement('form');
    box.style.cssText = 'background:#0b1220;color:#e6f6ff;border:1px solid #2a3b55;border-radius:8px;padding:16px;width:min(22rem,90vw);display:flex;flex-direction:column;gap:8px;font:14px system-ui,sans-serif';
    const title = document.createElement('label');
    title.textContent = retry ? 'That PIN was not right. Security key PIN' : 'Security key PIN';
    const field = document.createElement('input');
    field.type = 'password';
    field.autocomplete = 'off';
    field.setAttribute('aria-label', 'Security key PIN');
    field.style.cssText = 'padding:6px;border-radius:4px;border:1px solid #2a3b55;background:#050a14;color:inherit';
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:8px;justify-content:flex-end';
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.textContent = 'Cancel';
    const ok = document.createElement('button');
    ok.type = 'submit';
    ok.textContent = 'OK';
    row.append(cancel, ok);
    box.append(title, field, row);
    wrap.append(box);
    const done = (v: string | null): void => {
      field.value = '';
      wrap.remove();
      resolve(v);
    };
    cancel.addEventListener('click', () => done(null));
    box.addEventListener('submit', (e) => {
      e.preventDefault();
      done(field.value || null);
    });
    wrap.addEventListener('keydown', (e) => { if (e.key === 'Escape') done(null); });
    document.body.append(wrap);
    field.focus();
  });
}
