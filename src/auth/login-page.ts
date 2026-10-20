import type { Capability } from '../config.js';
import { parseScope } from './scopes.js';

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const CAPABILITY_LABELS: Record<Capability, string> = {
  read: 'Read messages, folders and search results',
  draft: 'Save drafts',
  mark: 'Mark messages read/unread and flag or unflag them',
  move: 'Move messages between folders',
  send: 'Send messages that are in Drafts: real email, from this address'
};

export function renderLoginPage(opts: {
  requestId: string;
  clientName: string;
  scopes: string[];
  mailboxes: Array<{ id: string; address: string }>;
  error?: string;
}): string {
  // One group per mailbox. Everything is ticked by default except send, which
  // the operator has to choose deliberately. Writes are only granted together
  // with read on the same mailbox; the provider enforces that, not this form.
  const groups = opts.mailboxes
    .map((m) => {
      const items = opts.scopes
        .filter((s) => parseScope(s)?.mailbox === m.id)
        .map((s) => {
          const cap = parseScope(s)!.capability;
          const send = cap === 'send';
          return `<label class="scope${send ? ' send' : ''}"><input type="checkbox" name="scope" value="${escapeHtml(s)}"${send ? '' : ' checked'}>
        <span>${escapeHtml(CAPABILITY_LABELS[cap])} <code>${escapeHtml(s)}</code></span></label>`;
        });
      if (items.length === 0) return '';
      return `<fieldset>
        <legend>${escapeHtml(m.address)}</legend>
        ${items.join('\n')}
      </fieldset>`;
    })
    .join('\n');
  const canSend = opts.scopes.some((s) => parseScope(s)?.capability === 'send');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Authorize mailbox access</title>
<style>
  :root { color-scheme: light dark; --fg:#1a1a1a; --bg:#fafafa; --card:#fff; --muted:#666; --line:#e2e2e2; --accent:#2b5dd7; --err:#b3261e; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8e8e8; --bg:#141414; --card:#1e1e1e; --muted:#9a9a9a; --line:#333; --accent:#7ea2ff; --err:#f2b8b5; }
  }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center; padding:16px;
         font:16px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
         color:var(--fg); background:var(--bg); }
  .card { width:100%; max-width:26rem; background:var(--card); border:1px solid var(--line);
          border-radius:12px; padding:28px; }
  h1 { font-size:1.15rem; margin:0 0 4px; }
  p.sub { margin:0 0 20px; color:var(--muted); font-size:.9rem; }
  fieldset { border:0; margin:0 0 20px; padding:0; }
  legend { font-size:.85rem; font-weight:600; padding:0; margin-bottom:8px; }
  label.scope { display:flex; gap:10px; align-items:flex-start; margin-bottom:8px; font-weight:400;
                font-size:.9rem; color:var(--muted); }
  label.scope input { width:auto; margin:.3em 0 0; flex:none; }
  label.scope.send span { color:var(--err); }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.85em; }
  label { display:block; font-size:.85rem; margin-bottom:6px; font-weight:600; }
  input { width:100%; padding:10px 12px; margin-bottom:16px; border:1px solid var(--line);
          border-radius:8px; background:var(--bg); color:var(--fg); font-size:1rem; }
  input:focus { outline:2px solid var(--accent); outline-offset:1px; }
  button { width:100%; padding:11px; border:0; border-radius:8px; background:var(--accent);
           color:#fff; font-size:1rem; font-weight:600; cursor:pointer; }
  button:hover { filter:brightness(1.08); }
  .err { background:color-mix(in srgb, var(--err) 12%, transparent); border:1px solid var(--err);
         color:var(--err); padding:10px 12px; border-radius:8px; font-size:.88rem; margin-bottom:16px; }
  .mailbox { font-size:.85rem; color:var(--muted); border-top:1px solid var(--line);
             margin-top:20px; padding-top:14px; }
</style>
</head>
<body>
  <main class="card">
    <h1>Authorize mailbox access</h1>
    <p class="sub"><strong>${escapeHtml(opts.clientName)}</strong> is requesting access to your ${opts.mailboxes.length > 1 ? 'mailboxes' : 'mailbox'}.</p>
    ${opts.error ? `<div class="err">${escapeHtml(opts.error)}</div>` : ''}
    <form method="POST" action="/login" autocomplete="off">
      <input type="hidden" name="request_id" value="${escapeHtml(opts.requestId)}">
      ${groups}
      <label for="u">Username</label>
      <input id="u" name="username" autocapitalize="none" autocorrect="off" required>
      <label for="p">Password</label>
      <input id="p" name="password" type="password" required>
      <button type="submit">Authorize</button>
    </form>
    <p class="mailbox">${
      canSend
        ? 'It can only send a message that is already in Drafts, from a mailbox ticked for sending. Apart from removing a draft once it is sent, it never deletes.'
        : 'It can never send or permanently delete.'
    }</p>
  </main>
</body>
</html>`;
}

export function renderErrorPage(message: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorization error</title>
<style>:root{color-scheme:light dark}body{margin:0;min-height:100vh;display:grid;place-items:center;
font:16px/1.5 ui-sans-serif,system-ui,sans-serif;padding:16px}main{max-width:26rem;text-align:center}</style>
</head><body><main><h1>Authorization error</h1><p>${escapeHtml(message)}</p></main></body></html>`;
}
