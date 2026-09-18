function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const SCOPE_LABELS: Record<string, string> = {
  'mail:read': 'Read messages, folders and search results',
  'mail:draft': 'Save draft replies (never send)'
};

export function renderLoginPage(opts: {
  requestId: string;
  clientName: string;
  scopes: string[];
  mailbox: string;
  error?: string;
}): string {
  const items = opts.scopes
    .map((s) => `<li><code>${escapeHtml(s)}</code> — ${escapeHtml(SCOPE_LABELS[s] ?? s)}</li>`)
    .join('\n');

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
  ul { margin:0 0 20px; padding-left:1.1rem; font-size:.9rem; color:var(--muted); }
  li { margin-bottom:4px; }
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
    <p class="sub"><strong>${escapeHtml(opts.clientName)}</strong> is requesting access to your mailbox.</p>
    ${opts.error ? `<div class="err">${escapeHtml(opts.error)}</div>` : ''}
    <ul>${items}</ul>
    <form method="POST" action="/login" autocomplete="off">
      <input type="hidden" name="request_id" value="${escapeHtml(opts.requestId)}">
      <label for="u">Username</label>
      <input id="u" name="username" autocapitalize="none" autocorrect="off" required>
      <label for="p">Password</label>
      <input id="p" name="password" type="password" required>
      <button type="submit">Authorize</button>
    </form>
    <p class="mailbox">Mailbox: <code>${escapeHtml(opts.mailbox)}</code><br>
    This grant can read and draft. It can never send or delete.</p>
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
