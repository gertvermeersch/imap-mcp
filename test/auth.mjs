/**
 * Authorization tests: scope enforcement and login throttling.
 *
 * Unlike test/smoke.mjs this needs no IMAP server and no Java — every path it
 * exercises is refused before the mailbox is ever touched. It boots the real
 * dist/index.js in several configurations — one mailbox with various switches
 * off, and three mailboxes — and drives the OAuth flow the way a client does.
 *
 * Usage: node test/auth.mjs   (expects a built dist/)
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SignJWT } from 'jose';
import { hashPassword } from '../dist/auth/password.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const REDIRECT = 'http://127.0.0.1:9999/callback';
const OPERATOR = { username: 'operator', password: 'correct-horse-battery' };

let passed = 0;
let failed = 0;
const failures = [];

function check(name, condition, detail = '') {
  if (condition) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
    console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const s256 = (v) => createHash('sha256').update(v).digest('base64url');

/** The one mailbox a server gets unless a test hands it a MAILBOXES_CONFIG of its own. */
const SINGLE_MAILBOX_YAML = `mailboxes:
  mailbox:
    address: mailbox@example.test
    passwordEnv: PW_MAILBOX
    capabilities: [read, draft, mark, move]
`;

/** Boots dist/index.js on `port` and resolves once /healthz answers. */
async function startServer(port, extraEnv) {
  const stateDir = await mkdtemp(join(tmpdir(), 'imap-mcp-auth-'));
  const defaultFile = join(stateDir, 'mailboxes.yml');
  await writeFile(defaultFile, SINGLE_MAILBOX_YAML);
  const jwtSecret = randomBytes(48).toString('base64');
  const child = spawn(process.execPath, ['dist/index.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      MCP_RESOURCE_URL: `http://127.0.0.1:${port}/mcp`,
      OAUTH_ISSUER_URL: `http://127.0.0.1:${port}`,
      PORT: String(port),
      STATE_DIR: stateDir,
      OPERATOR_USERNAME: OPERATOR.username,
      OPERATOR_PASSWORD_HASH: await hashPassword(OPERATOR.password),
      JWT_SECRET: jwtSecret,
      // Never contacted: every assertion here is refused before IMAP.
      IMAP_HOST: '127.0.0.1',
      IMAP_PORT: '1',
      IMAP_SECURE: 'false',
      MAILBOXES_CONFIG: defaultFile,
      PW_MAILBOX: 'unused',
      ...extraEnv
    },
    stdio: ['ignore', 'ignore', 'pipe']
  });
  child.stderr.on('data', (d) => {
    if (process.env.VERBOSE) process.stderr.write(`[srv] ${d}`);
  });

  const origin = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 80; i++) {
    try {
      if ((await fetch(`${origin}/healthz`)).ok) {
        return {
          origin,
          resource: `${origin}/mcp`,
          jwtSecret,
          async stop() {
            child.kill('SIGTERM');
            await sleep(400);
            await rm(stateDir, { recursive: true, force: true });
          }
        };
      }
    } catch {
      /* not listening yet */
    }
    await sleep(250);
  }
  child.kill('SIGKILL');
  throw new Error(`server on :${port} never became healthy`);
}

function api(srv) {
  return {
    async register(name) {
      const res = await fetch(`${srv.origin}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: name,
          redirect_uris: [REDIRECT],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none'
        })
      });
      return res.json();
    },

    authorizeUrl(clientId, verifier, scope) {
      const url = new URL(`${srv.origin}/authorize`);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', REDIRECT);
      url.searchParams.set('code_challenge', s256(verifier));
      url.searchParams.set('code_challenge_method', 'S256');
      url.searchParams.set('resource', srv.resource);
      if (scope !== undefined) url.searchParams.set('scope', scope);
      return url;
    },

    /** Walks /authorize and returns the rendered consent page plus its request id. */
    async startAuth(clientId, scope) {
      const verifier = randomBytes(32).toString('base64url');
      const res = await fetch(this.authorizeUrl(clientId, verifier, scope), { redirect: 'manual' });
      const html = await res.text();
      return {
        res,
        html,
        verifier,
        requestId: html.match(/name="request_id" value="([^"]+)"/)?.[1]
      };
    },

    /** `scopes` are the boxes left ticked on the consent page. */
    login(requestId, password, scopes = []) {
      const body = new URLSearchParams({
        request_id: requestId,
        username: OPERATOR.username,
        password
      });
      for (const s of scopes) body.append('scope', s);
      return fetch(`${srv.origin}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
        redirect: 'manual'
      });
    },

    async token(clientId, code, verifier) {
      const res = await fetch(`${srv.origin}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          code_verifier: verifier,
          client_id: clientId,
          redirect_uri: REDIRECT,
          resource: srv.resource
        })
      });
      return res.json();
    }
  };
}

/** Mints an access token the way the server does, for scopes the flow cannot produce (legacy ones). */
function mint(srv, scope) {
  return new SignJWT({ scope })
    .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
    .setIssuer(`${srv.origin}/`)
    .setSubject(OPERATOR.username)
    .setAudience(srv.resource)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(new TextEncoder().encode(srv.jwtSecret));
}

const text = (r) => r?.result?.content?.[0]?.text ?? '';
const json = (r) => {
  try {
    return JSON.parse(text(r));
  } catch {
    return undefined;
  }
};

let rpcId = 0;
async function rpc(srv, token, method, params) {
  const res = await fetch(srv.resource, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': '2025-06-18',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params })
  });
  const text = await res.text();
  if (!res.ok) return { status: res.status, error: text };

  // Streamable HTTP may answer as SSE; pull the first data frame out.
  let payload = text;
  if (text.startsWith('event:') || text.includes('\ndata:')) {
    const line = text.split('\n').find((l) => l.startsWith('data:'));
    if (line) payload = line.slice(5).trim();
  }
  return JSON.parse(payload);
}

// ---------------------------------------------------------------------------

const ALL = ['mail:read:mailbox', 'mail:draft:mailbox', 'mail:mark:mailbox', 'mail:move:mailbox'];

async function draftsEnabled() {
  console.log('\nDrafts enabled — scope enforcement');
  const srv = await startServer(8793, { ALLOWED_FOLDERS: 'INBOX,Drafts', ENABLE_DRAFTS: 'true' });
  const c = api(srv);
  try {
    const client = await c.register('auth-test');
    check('dynamic client registration works', !!client.client_id);

    const meta = await (
      await fetch(`${srv.origin}/.well-known/oauth-authorization-server`)
    ).json();
    check(
      'metadata advertises every scope, named for the mailbox',
      JSON.stringify(meta.scopes_supported) === JSON.stringify(ALL),
      JSON.stringify(meta.scopes_supported)
    );

    // Clients request whatever scope the 401 challenge names, so it must not
    // single out mail:read or they never ask for drafts.
    const challenge = await fetch(`${srv.origin}/mcp`, { method: 'POST' });
    const wwwAuth = challenge.headers.get('www-authenticate') ?? '';
    check(
      'unauthenticated challenge does not narrow the scope to mail:read',
      challenge.status === 401 && !/scope="mail:read(:mailbox)?"/.test(wwwAuth),
      wwwAuth
    );

    // A client may narrow itself to read-only; the consent page must say so.
    const auth = await c.startAuth(client.client_id, 'mail:read:mailbox');
    check('login page renders for a read-only request', !!auth.requestId);
    check(
      'consent page lists only the read scope',
      auth.html.includes('mail:read:mailbox') && !auth.html.includes('mail:draft')
    );

    const login = await c.login(auth.requestId, OPERATOR.password, ['mail:read:mailbox']);
    check('correct password redirects with a code', login.status === 302, `status ${login.status}`);
    const code = new URL(login.headers.get('location')).searchParams.get('code');

    const tok = await c.token(client.client_id, code, auth.verifier);
    check('token carries the narrowed scope', tok.scope === 'mail:read:mailbox', JSON.stringify(tok.scope));

    await rpc(srv, tok.access_token, 'initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'auth-test', version: '0' }
    });

    const tools = await rpc(srv, tok.access_token, 'tools/list', {});
    check(
      'create_draft is still listed',
      !!tools.result?.tools?.some((t) => t.name === 'create_draft')
    );

    const denied = await rpc(srv, tok.access_token, 'tools/call', {
      name: 'create_draft',
      arguments: { to: ['x@example.com'], subject: 'hi', body: 'hi' }
    });
    const deniedText = denied.result?.content?.[0]?.text ?? '';
    check(
      'create_draft is refused without mail:draft',
      denied.result?.isError === true && deniedText.includes('mail:draft'),
      JSON.stringify(denied).slice(0, 220)
    );

    for (const [name, scope, args] of [
      ['mark_messages', 'mail:mark:mailbox', { uids: [1], seen: true }],
      ['move_messages', 'mail:move:mailbox', { uids: [1], destination: 'Drafts' }]
    ]) {
      check(
        `${name} is listed`,
        !!tools.result?.tools?.some((t) => t.name === name)
      );
      const refused = await rpc(srv, tok.access_token, 'tools/call', { name, arguments: args });
      const refusedText = refused.result?.content?.[0]?.text ?? '';
      check(
        `${name} is refused without ${scope}`,
        refused.result?.isError === true && refusedText.includes(scope),
        JSON.stringify(refused).slice(0, 220)
      );
    }

    // A grant of one write scope must not unlock the others.
    const markOnly = await c.startAuth(client.client_id, 'mail:read:mailbox mail:mark:mailbox');
    const markLogin = await c.login(markOnly.requestId, OPERATOR.password, [
      'mail:read:mailbox',
      'mail:mark:mailbox'
    ]);
    const markCode = new URL(markLogin.headers.get('location')).searchParams.get('code');
    const markTok = await c.token(client.client_id, markCode, markOnly.verifier);
    const markMoveDenied = await rpc(srv, markTok.access_token, 'tools/call', {
      name: 'move_messages',
      arguments: { uids: [1], destination: 'Drafts' }
    });
    check(
      'mail:mark does not grant move_messages',
      markMoveDenied.result?.isError === true &&
        (markMoveDenied.result?.content?.[0]?.text ?? '').includes('mail:move:mailbox')
    );
    const markAllowed = await rpc(srv, markTok.access_token, 'tools/call', {
      name: 'mark_messages',
      arguments: { uids: [1], seen: true }
    });
    check(
      'mail:mark passes the scope check (then fails on the dead IMAP host)',
      markAllowed.result?.isError === true &&
        !(markAllowed.result?.content?.[0]?.text ?? '').includes('scope')
    );

    // The refusal must be about scope, not a side effect of the dead IMAP host.
    const read = await rpc(srv, tok.access_token, 'tools/call', {
      name: 'search_messages',
      arguments: { folder: 'INBOX' }
    });
    const readText = read.result?.content?.[0]?.text ?? '';
    check(
      'read tools are unaffected by the scope check',
      read.result?.isError === true && !readText.includes('mail:draft'),
      readText.slice(0, 120)
    );

    const scopeless = await c.startAuth(client.client_id, undefined);
    check(
      'a scopeless request is offered everything on offer',
      ALL.every((s) => scopeless.html.includes(s))
    );

    const legacy = await c.startAuth(client.client_id, 'mail:read mail:draft');
    check(
      'a legacy unqualified request is offered those capabilities on the mailbox',
      legacy.html.includes('value="mail:read:mailbox"') &&
        legacy.html.includes('value="mail:draft:mailbox"') &&
        !legacy.html.includes('mail:mark'),
      legacy.res.status
    );

    // Tokens from before scopes named a mailbox must keep working after the upgrade.
    const old = await mint(srv, 'mail:read mail:mark');
    const oldDenied = await rpc(srv, old, 'tools/call', {
      name: 'move_messages',
      arguments: { uids: [1], destination: 'Drafts' }
    });
    const oldAllowed = await rpc(srv, old, 'tools/call', {
      name: 'mark_messages',
      arguments: { uids: [1], seen: true }
    });
    check(
      'a legacy mail:read mail:mark token still reads and marks, and still cannot move',
      oldAllowed.result?.isError === true &&
        !text(oldAllowed).includes('scope') &&
        text(oldDenied).includes('mail:move:mailbox'),
      `${text(oldAllowed).slice(0, 80)} / ${text(oldDenied).slice(0, 80)}`
    );

    console.log('\nDrafts enabled — operator picks the scopes');
    const pick = async (requested, ticked) => {
      const a = await c.startAuth(client.client_id, requested);
      const l = await c.login(a.requestId, OPERATOR.password, ticked);
      const cd = new URL(l.headers.get('location')).searchParams.get('code');
      return (await c.token(client.client_id, cd, a.verifier)).scope;
    };
    const everything = await c.startAuth(client.client_id, ALL.join(' '));
    check(
      'consent page has a checkbox per requested scope',
      (everything.html.match(/type="checkbox" name="scope"/g) ?? []).length === 4
    );
    check(
      'every scope starts ticked',
      ALL.every((s) => everything.html.includes(`value="${s}" checked`))
    );
    check(
      'ticking a subset narrows the grant',
      (await pick(ALL.join(' '), ['mail:read:mailbox', 'mail:mark:mailbox'])) === 'mail:read:mailbox mail:mark:mailbox'
    );
    check(
      'a scope the client never asked for cannot be added by the form',
      (await pick('mail:read:mailbox', ['mail:read:mailbox', 'mail:move:mailbox', 'mail:draft:mailbox'])) ===
        'mail:read:mailbox'
    );

    const empty = await c.startAuth(client.client_id, ALL.join(' '));
    const emptyLogin = await c.login(empty.requestId, OPERATOR.password, ['mail:mark:mailbox']);
    check(
      'a grant without read on any mailbox is refused',
      emptyLogin.status === 401 && (await emptyLogin.text()).includes('at least one mailbox'),
      `status ${emptyLogin.status}`
    );
    const retry = await c.login(empty.requestId, OPERATOR.password, ['mail:read:mailbox']);
    check('...without burning the request: ticking read then succeeds', retry.status === 302, `status ${retry.status}`);

    console.log('\nDrafts enabled — login throttling');
    const target = await c.startAuth(client.client_id, 'mail:read:mailbox');
    for (let i = 1; i <= 5; i++) {
      const res = await c.login(target.requestId, `wrong-${i}`);
      const body = await res.text();
      if (i < 5) {
        check(`guess ${i} is rejected with 401`, res.status === 401, `status ${res.status}`);
      } else {
        check(
          'the 5th guess burns the authorization request',
          res.status === 401 && body.includes('Start the connection again'),
          body.slice(0, 200)
        );
      }
    }

    const blocked = await c.login(target.requestId, 'wrong-again');
    const blockedBody = await blocked.text();
    check('the 6th guess is throttled with 429', blocked.status === 429, `status ${blocked.status}`);
    check(
      '429 carries Retry-After',
      Number(blocked.headers.get('retry-after')) > 0,
      String(blocked.headers.get('retry-after'))
    );
    check(
      'the throttle page explains the wait',
      blockedBody.includes('Too many failed sign-in attempts')
    );

    // The lock is on the address, so a fresh authorization request does not
    // reset it — otherwise the throttle would be trivially bypassed.
    const fresh = await c.startAuth(client.client_id, 'mail:read:mailbox');
    const stillBlocked = await c.login(fresh.requestId, OPERATOR.password, ['mail:read:mailbox']);
    check(
      'a fresh request from the same address is still throttled',
      stillBlocked.status === 429,
      `status ${stillBlocked.status}`
    );
  } finally {
    await srv.stop();
  }
}

async function draftsDisabled() {
  console.log('\nDrafts disabled — mail:draft is not on offer');
  const srv = await startServer(8794, { ENABLE_DRAFTS: 'false' });
  const c = api(srv);
  try {
    const client = await c.register('auth-test-nodrafts');

    const meta = await (
      await fetch(`${srv.origin}/.well-known/oauth-authorization-server`)
    ).json();
    check(
      'metadata no longer advertises mail:draft',
      JSON.stringify(meta.scopes_supported) ===
        JSON.stringify(['mail:read:mailbox', 'mail:mark:mailbox', 'mail:move:mailbox']),
      JSON.stringify(meta.scopes_supported)
    );

    for (const scope of ['mail:draft', 'mail:draft:mailbox']) {
      const asked = await c.startAuth(client.client_id, scope);
      const location = asked.res.headers.get('location') ?? '';
      check(
        `requesting ${scope} is an invalid_scope error`,
        asked.res.status === 302 && location.includes('error=invalid_scope'),
        `${asked.res.status} ${location.slice(0, 160)}`
      );
    }

    const scopeless = await c.startAuth(client.client_id, undefined);
    check(
      'a scopeless request is offered everything except mail:draft',
      scopeless.html.includes('mail:read:mailbox') &&
        scopeless.html.includes('mail:mark:mailbox') &&
        scopeless.html.includes('mail:move:mailbox') &&
        !scopeless.html.includes('mail:draft')
    );
  } finally {
    await srv.stop();
  }
}

async function writesDisabled() {
  console.log('\nMarking and moving disabled — their scopes are not on offer');
  const srv = await startServer(8795, { ENABLE_MARKING: 'false', ENABLE_MOVE: 'false' });
  const c = api(srv);
  try {
    const client = await c.register('auth-test-nomarkmove');

    const meta = await (
      await fetch(`${srv.origin}/.well-known/oauth-authorization-server`)
    ).json();
    check(
      'metadata advertises read and draft only',
      JSON.stringify(meta.scopes_supported) === JSON.stringify(['mail:read:mailbox', 'mail:draft:mailbox']),
      JSON.stringify(meta.scopes_supported)
    );

    for (const scope of ['mail:mark', 'mail:move']) {
      const asked = await c.startAuth(client.client_id, scope);
      const location = asked.res.headers.get('location') ?? '';
      check(
        `requesting ${scope} is an invalid_scope error`,
        asked.res.status === 302 && location.includes('error=invalid_scope'),
        `${asked.res.status} ${location.slice(0, 160)}`
      );
    }

    const auth = await c.startAuth(client.client_id, undefined);
    const login = await c.login(auth.requestId, OPERATOR.password, ['mail:read:mailbox']);
    const code = new URL(login.headers.get('location')).searchParams.get('code');
    const tok = await c.token(client.client_id, code, auth.verifier);
    await rpc(srv, tok.access_token, 'initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'auth-test', version: '0' }
    });
    const tools = await rpc(srv, tok.access_token, 'tools/list', {});
    const names = (tools.result?.tools ?? []).map((t) => t.name);
    check(
      'mark_messages and move_messages are not registered',
      !names.includes('mark_messages') && !names.includes('move_messages'),
      names.join(', ')
    );
  } finally {
    await srv.stop();
  }
}

const MAILBOXES_YAML = `
mailboxes:
  personal:
    address: personal@example.test
    passwordEnv: PW_PERSONAL
    capabilities: [read, draft, mark, move]
  info:
    address: info@example.test
    passwordEnv: PW_INFO
    capabilities: [read, draft]
  agent:
    address: agent@example.test
    name: Example Agent
    passwordEnv: PW_AGENT
    capabilities: [read, draft, send]
    send:
      recipients: reply-only
      maxPerDay: 2
`;

async function multiMailbox() {
  console.log('\nThree mailboxes from MAILBOXES_CONFIG — scopes per mailbox');
  const dir = await mkdtemp(join(tmpdir(), 'imap-mcp-mbx-'));
  const file = join(dir, 'mailboxes.yml');
  await writeFile(file, MAILBOXES_YAML);
  const srv = await startServer(8796, {
    MAILBOXES_CONFIG: file,
    PW_PERSONAL: 'unused',
    PW_INFO: 'unused',
    PW_AGENT: 'unused',
    SMTP_HOST: '127.0.0.1',
    SMTP_PORT: '1'
  });
  const c = api(srv);
  try {
    const client = await c.register('auth-test-multi');
    const meta = await (await fetch(`${srv.origin}/.well-known/oauth-authorization-server`)).json();
    const expected = [
      'mail:read:personal', 'mail:draft:personal', 'mail:mark:personal', 'mail:move:personal',
      'mail:read:info', 'mail:draft:info',
      'mail:read:agent', 'mail:draft:agent', 'mail:send:agent'
    ];
    check(
      'metadata advertises each mailbox\'s own capabilities',
      JSON.stringify(meta.scopes_supported) === JSON.stringify(expected),
      JSON.stringify(meta.scopes_supported)
    );

    const all = await c.startAuth(client.client_id, undefined);
    check(
      'consent page groups the scopes by mailbox',
      ['personal@example.test', 'info@example.test', 'agent@example.test'].every((a) =>
        all.html.includes(`<legend>${a}</legend>`)
      )
    );
    check(
      'send starts unticked; everything else starts ticked',
      all.html.includes('value="mail:send:agent">') &&
        expected.filter((s) => !s.startsWith('mail:send')).every((s) => all.html.includes(`value="${s}" checked`))
    );
    check('consent page says sending is drafts-only', all.html.includes('already in Drafts'));

    const grant = async (ticked) => {
      const a = await c.startAuth(client.client_id, undefined);
      const l = await c.login(a.requestId, OPERATOR.password, ticked);
      const cd = new URL(l.headers.get('location')).searchParams.get('code');
      return c.token(client.client_id, cd, a.verifier);
    };
    const tok = await grant([
      'mail:read:personal',
      'mail:mark:personal',
      'mail:draft:info', // no read on info: must be dropped
      'mail:read:agent',
      'mail:send:agent'
    ]);
    check(
      'a write on a mailbox without read on it is dropped',
      tok.scope === 'mail:read:personal mail:mark:personal mail:read:agent mail:send:agent',
      tok.scope
    );

    const t = tok.access_token;
    await rpc(srv, t, 'initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'auth-test', version: '0' }
    });
    const tools = (await rpc(srv, t, 'tools/list', {})).result?.tools ?? [];
    const tool = (n) => tools.find((x) => x.name === n);
    check('list_mailboxes and send_draft are registered', !!tool('list_mailboxes') && !!tool('send_draft'));
    check(
      'send_draft only accepts the mailboxes that may send',
      JSON.stringify(tool('send_draft')?.inputSchema?.properties?.mailbox?.enum) === '["agent"]',
      JSON.stringify(tool('send_draft')?.inputSchema?.properties?.mailbox)
    );
    check(
      'with several mailboxes, the mailbox argument is required',
      tool('search_messages')?.inputSchema?.required?.includes('mailbox') &&
        tool('search_messages')?.inputSchema?.properties?.mailbox?.enum?.length === 3
    );

    const listed = json(await rpc(srv, t, 'tools/call', { name: 'list_mailboxes', arguments: {} }));
    const byId = Object.fromEntries((listed ?? []).map((m) => [m.id, m]));
    check(
      'list_mailboxes reports what this token was granted',
      JSON.stringify(byId.personal?.access) === '["read","mark"]' &&
        JSON.stringify(byId.personal?.notGranted) === '["draft","move"]' &&
        JSON.stringify(byId.info?.access) === '[]' &&
        JSON.stringify(byId.agent?.access) === '["read","send"]' &&
        byId.agent?.send?.recipients === 'reply-only',
      JSON.stringify(listed)
    );

    const infoRead = await rpc(srv, t, 'tools/call', {
      name: 'search_messages',
      arguments: { mailbox: 'info', folder: 'INBOX' }
    });
    check('reading a mailbox without its read scope is refused', text(infoRead).includes('mail:read:info'), text(infoRead));

    const noMailbox = await rpc(srv, t, 'tools/call', { name: 'search_messages', arguments: { folder: 'INBOX' } });
    check(
      'leaving out the mailbox is an error, not a silent default',
      noMailbox.result?.isError === true || !!noMailbox.error,
      JSON.stringify(noMailbox).slice(0, 160)
    );

    const sendTry = await rpc(srv, t, 'tools/call', { name: 'send_draft', arguments: { mailbox: 'agent', uid: 1 } });
    check(
      'send_draft with mail:send passes the scope check (then fails on the dead IMAP host)',
      sendTry.result?.isError === true && !text(sendTry).includes('scope'),
      text(sendTry)
    );

    const noSend = await grant(['mail:read:agent', 'mail:draft:agent']);
    const sendDenied = await rpc(srv, noSend.access_token, 'tools/call', {
      name: 'send_draft',
      arguments: { mailbox: 'agent', uid: 1 }
    });
    check('send_draft is refused without mail:send:agent', text(sendDenied).includes('mail:send:agent'), text(sendDenied));

    const personalMark = await rpc(srv, noSend.access_token, 'tools/call', {
      name: 'mark_messages',
      arguments: { mailbox: 'personal', uids: [1], seen: true }
    });
    check('a grant on one mailbox does not carry over to another', text(personalMark).includes('mail:read:personal'), text(personalMark));

    const legacy = await c.startAuth(client.client_id, 'mail:read');
    check(
      'a legacy mail:read request is offered read on every mailbox',
      ['personal', 'info', 'agent'].every((m) => legacy.html.includes(`value="mail:read:${m}"`)) &&
        !legacy.html.includes('mail:draft')
    );

    const old = await mint(srv, 'mail:read mail:draft');
    const oldList = json(await rpc(srv, old, 'tools/call', { name: 'list_mailboxes', arguments: {} }));
    check(
      'a legacy token applies to the first (default) mailbox only',
      JSON.stringify(oldList?.map((m) => m.access)) === '[["read","draft"],[],[]]',
      JSON.stringify(oldList?.map((m) => m.access))
    );
  } finally {
    await srv.stop();
    await rm(dir, { recursive: true, force: true });
  }
}

async function badConfig() {
  console.log('\nMailbox file validation');
  const dir = await mkdtemp(join(tmpdir(), 'imap-mcp-bad-'));
  const run = async (yaml, env = {}) => {
    const file = join(dir, `m${++rpcId}.yml`);
    await writeFile(file, yaml);
    return spawnSync(process.execPath, ['dist/index.js'], {
      cwd: ROOT,
      timeout: 15000,
      encoding: 'utf8',
      env: {
        ...process.env,
        MCP_RESOURCE_URL: 'http://127.0.0.1:8797/mcp',
        OAUTH_ISSUER_URL: 'http://127.0.0.1:8797',
        PORT: '8797',
        STATE_DIR: dir,
        OPERATOR_USERNAME: OPERATOR.username,
        OPERATOR_PASSWORD_HASH: 'scrypt$unused-but-long-enough',
        JWT_SECRET: randomBytes(48).toString('base64'),
        IMAP_HOST: '127.0.0.1',
        MAILBOXES_CONFIG: file,
        ...env
      }
    });
  };
  try {
    const absent = await run('', { MAILBOXES_CONFIG: join(dir, 'not-there.yml'), IMAP_USER: 'old@example.test' });
    check(
      'a missing mailboxes file stops startup and says where it looked',
      absent.status !== 0 && absent.stderr.includes('not-there.yml') && absent.stderr.includes('mailboxes.example.yml'),
      absent.stderr.slice(-300)
    );
    check(
      'a leftover IMAP_USER is pointed at the file instead of silently ignored',
      absent.stderr.includes('IMAP_USER and IMAP_PASSWORD are no longer read'),
      absent.stderr.slice(-300)
    );
    const asDir = await run('', { MAILBOXES_CONFIG: dir });
    check(
      'a directory where the file should be is called out',
      asDir.status !== 0 && asDir.stderr.includes('is a directory'),
      asDir.stderr.slice(-300)
    );
    // A blank value (`MAILBOXES_CONFIG=` in an env file) falls back to the image's mount path.
    const blank = await run('', { MAILBOXES_CONFIG: '' });
    check(
      'MAILBOXES_CONFIG defaults to /config/mailboxes.yml',
      blank.status !== 0 && blank.stderr.includes('/config/mailboxes.yml'),
      blank.stderr.slice(-300)
    );
    const missingPw = await run('mailboxes:\n  a:\n    address: a@example.test\n    passwordEnv: PW_NOT_SET_ANYWHERE\n');
    check(
      'a mailbox whose password variable is unset stops startup',
      missingPw.status !== 0 && missingPw.stderr.includes('PW_NOT_SET_ANYWHERE'),
      missingPw.stderr.slice(-200)
    );
    const noSmtp = await run(
      'mailboxes:\n  a:\n    address: a@example.test\n    passwordEnv: PW_A\n    capabilities: [read, send]\n',
      { PW_A: 'x', SMTP_HOST: '' } // blank, as an env_file line "SMTP_HOST=" gives
    );
    check(
      '"send" without an SMTP host stops startup',
      noSmtp.status !== 0 && noSmtp.stderr.includes('SMTP_HOST'),
      noSmtp.stderr.slice(-200)
    );
    const hiddenSent = await run(
      'mailboxes:\n  a:\n    address: a@example.test\n    passwordEnv: PW_A\n    folders: [INBOX, Drafts]\n    capabilities: [read, draft, send]\n',
      { PW_A: 'x', SMTP_HOST: '127.0.0.1' }
    );
    check(
      '"send" with Sent outside the folder allowlist stops startup',
      hiddenSent.status !== 0 && hiddenSent.stderr.includes('"Sent"'),
      hiddenSent.stderr.slice(-200)
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

await draftsEnabled();
await draftsDisabled();
await writesDisabled();
await multiMailbox();
await badConfig();

console.log(`\n${passed} passed, ${failed} failed`);
if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
}
process.exit(failed === 0 ? 0 : 1);
