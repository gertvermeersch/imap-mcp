/**
 * Authorization tests: scope enforcement and login throttling.
 *
 * Unlike test/smoke.mjs this needs no IMAP server and no Java — every path it
 * exercises is refused before the mailbox is ever touched. It boots the real
 * dist/index.js twice, once with drafts enabled and once without, and drives
 * the OAuth flow the way a client does.
 *
 * Usage: node test/auth.mjs   (expects a built dist/)
 */
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
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

/** Boots dist/index.js on `port` and resolves once /healthz answers. */
async function startServer(port, extraEnv) {
  const stateDir = await mkdtemp(join(tmpdir(), 'imap-mcp-auth-'));
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
      JWT_SECRET: randomBytes(48).toString('base64'),
      // Never contacted: every assertion here is refused before IMAP.
      IMAP_HOST: '127.0.0.1',
      IMAP_PORT: '1',
      IMAP_SECURE: 'false',
      IMAP_USER: 'mailbox@example.test',
      IMAP_PASSWORD: 'unused',
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

    login(requestId, password) {
      return fetch(`${srv.origin}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          request_id: requestId,
          username: OPERATOR.username,
          password
        }),
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
      'metadata advertises both scopes',
      JSON.stringify(meta.scopes_supported) === JSON.stringify(['mail:read', 'mail:draft']),
      JSON.stringify(meta.scopes_supported)
    );

    // A client may narrow itself to read-only; the consent page must say so.
    const auth = await c.startAuth(client.client_id, 'mail:read');
    check('login page renders for a read-only request', !!auth.requestId);
    check(
      'consent page lists only the read scope',
      auth.html.includes('mail:read') && !auth.html.includes('mail:draft')
    );

    const login = await c.login(auth.requestId, OPERATOR.password);
    check('correct password redirects with a code', login.status === 302, `status ${login.status}`);
    const code = new URL(login.headers.get('location')).searchParams.get('code');

    const tok = await c.token(client.client_id, code, auth.verifier);
    check('token carries the narrowed scope', tok.scope === 'mail:read', JSON.stringify(tok.scope));

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
      scopeless.html.includes('mail:read') && scopeless.html.includes('mail:draft')
    );

    console.log('\nDrafts enabled — login throttling');
    const target = await c.startAuth(client.client_id, 'mail:read');
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
    const fresh = await c.startAuth(client.client_id, 'mail:read');
    const stillBlocked = await c.login(fresh.requestId, OPERATOR.password);
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
      'metadata advertises mail:read only',
      JSON.stringify(meta.scopes_supported) === JSON.stringify(['mail:read']),
      JSON.stringify(meta.scopes_supported)
    );

    const asked = await c.startAuth(client.client_id, 'mail:draft');
    const location = asked.res.headers.get('location') ?? '';
    check(
      'requesting mail:draft is an invalid_scope error',
      asked.res.status === 302 && location.includes('error=invalid_scope'),
      `${asked.res.status} ${location.slice(0, 160)}`
    );

    const scopeless = await c.startAuth(client.client_id, undefined);
    check(
      'a scopeless request is offered mail:read only',
      scopeless.html.includes('mail:read') && !scopeless.html.includes('mail:draft')
    );
  } finally {
    await srv.stop();
  }
}

await draftsEnabled();
await draftsDisabled();

console.log(`\n${passed} passed, ${failed} failed`);
if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
}
process.exit(failed === 0 ? 0 : 1);
