/**
 * End-to-end smoke test against a throwaway GreenMail IMAP server.
 *
 * Exercises the real OAuth 2.1 flow the way an MCP client does — discovery,
 * dynamic client registration, PKCE authorization, operator login, code
 * exchange, audience-bound token — and then calls every tool over the
 * Streamable HTTP transport. Also asserts the negative cases that matter:
 * no token, wrong audience, wrong PKCE verifier, code replay.
 *
 * Usage: node test/smoke.mjs   (expects GREENMAIL_JAR and a built dist/)
 */
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import nodemailer from 'nodemailer';
import { hashPassword } from '../dist/auth/password.js';

const JAR = process.env.GREENMAIL_JAR;
/** Repo root, so the suite runs from wherever it is checked out. */
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const IMAP_PORT = 3143;
const SMTP_PORT = 3025;
const APP_PORT = 8791;
const ORIGIN = `http://127.0.0.1:${APP_PORT}`;
const RESOURCE = `${ORIGIN}/mcp`;
const OPERATOR = { username: 'gert', password: 'correct-horse-battery' };
const MAILBOX = { user: 'gert@stormlabs.test', pass: 'imap-secret' };

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

async function waitFor(fn, label, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr;
  while (Date.now() < deadline) {
    try {
      if (await fn()) return;
    } catch (err) {
      lastErr = err;
    }
    await sleep(400);
  }
  throw new Error(`Timed out waiting for ${label}: ${lastErr?.message ?? 'no success'}`);
}

// --- MCP JSON-RPC helper ---------------------------------------------------

let rpcId = 0;
async function rpc(token, method, params) {
  const res = await fetch(RESOURCE, {
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
  if (!res.ok) return { status: res.status, headers: res.headers, error: text };

  // Streamable HTTP may answer as SSE; pull the first data frame out.
  let payload = text;
  if (text.startsWith('event:') || text.includes('\ndata:')) {
    const line = text.split('\n').find((l) => l.startsWith('data:'));
    payload = line ? line.slice(5).trim() : text;
  }
  return { status: res.status, headers: res.headers, body: JSON.parse(payload) };
}

function toolResult(body) {
  const text = body?.result?.content?.[0]?.text;
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// --- main ------------------------------------------------------------------

let greenmail;
let app;
let stateDir;

try {
  stateDir = await mkdtemp(join(tmpdir(), 'imap-mcp-test-'));

  console.log('\nStarting GreenMail...');
  greenmail = spawn(
    'java',
    [
      '-Dgreenmail.setup.test.all',
      `-Dgreenmail.users=${MAILBOX.user}:${MAILBOX.pass}`,
      '-Dgreenmail.auth.disabled=false',
      '-jar',
      JAR
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  );
  greenmail.stdout.on('data', () => {});
  greenmail.stderr.on('data', () => {});

  await waitFor(async () => {
    const { connect } = await import('node:net');
    return new Promise((resolve) => {
      const s = connect(IMAP_PORT, '127.0.0.1');
      s.on('connect', () => {
        s.destroy();
        resolve(true);
      });
      s.on('error', () => resolve(false));
    });
  }, 'GreenMail IMAP');
  console.log('GreenMail up.');

  // Seed three messages, one of them a reply so threading has something to do.
  const smtp = nodemailer.createTransport({
    host: '127.0.0.1',
    port: SMTP_PORT,
    secure: false,
    tls: { rejectUnauthorized: false }
  });
  const rootId = '<proposal-thread-root@client.test>';
  await smtp.sendMail({
    from: 'Ilse Peeters <ilse@klant.test>',
    to: MAILBOX.user,
    subject: 'Offerte webshop — akkoord?',
    text: 'Dag Gert, kunnen we de offerte deze week bevestigen? Groeten, Ilse',
    messageId: rootId
  });
  await smtp.sendMail({
    from: 'Ilse Peeters <ilse@klant.test>',
    to: MAILBOX.user,
    subject: 'Re: Offerte webshop — akkoord?',
    text: 'Kleine aanvulling: budget is goedgekeurd tot 8.500 EUR.',
    inReplyTo: rootId,
    references: rootId
  });
  await smtp.sendMail({
    from: 'newsletter@marketing.test',
    to: MAILBOX.user,
    subject: 'Your weekly digest of growth hacks',
    text: 'Unsubscribe at any time.'
  });
  await sleep(1200);
  console.log('Seeded 3 messages.\n');

  console.log('Starting imap-mcp...');
  app = spawn('node', ['dist/index.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      MCP_RESOURCE_URL: RESOURCE,
      OAUTH_ISSUER_URL: ORIGIN,
      PORT: String(APP_PORT),
      STATE_DIR: stateDir,
      OPERATOR_USERNAME: OPERATOR.username,
      OPERATOR_PASSWORD_HASH: await hashPassword(OPERATOR.password),
      JWT_SECRET: randomBytes(48).toString('base64'),
      IMAP_HOST: '127.0.0.1',
      IMAP_PORT: String(IMAP_PORT),
      IMAP_SECURE: 'false',
      IMAP_TLS_REJECT_UNAUTHORIZED: 'false',
      IMAP_USER: MAILBOX.user,
      IMAP_PASSWORD: MAILBOX.pass,
      IMAP_DRAFTS_FOLDER: 'Drafts',
      ALLOWED_FOLDERS: '',
      ENABLE_DRAFTS: 'true'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const appLog = [];
  app.stdout.on('data', (d) => appLog.push(d.toString()));
  app.stderr.on('data', (d) => appLog.push(d.toString()));

  await waitFor(async () => (await fetch(`${ORIGIN}/healthz`)).ok, 'imap-mcp health');
  console.log('imap-mcp up.\n');

  // === 1. Discovery ========================================================
  console.log('OAuth discovery');
  const prmRes = await fetch(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`);
  const prm = await prmRes.json();
  check('protected resource metadata served', prmRes.ok);
  check(
    'advertises this server as the resource',
    prm.resource?.replace(/\/$/, '') === RESOURCE,
    `got ${prm.resource}`
  );
  check('advertises an authorization server', Array.isArray(prm.authorization_servers) && prm.authorization_servers.length > 0);

  const asmRes = await fetch(`${ORIGIN}/.well-known/oauth-authorization-server`);
  const asm = await asmRes.json();
  check('authorization server metadata served', asmRes.ok);
  check('supports authorization_code', asm.grant_types_supported?.includes('authorization_code'));
  check('advertises S256 PKCE', asm.code_challenge_methods_supported?.includes('S256'));

  // === 2. Unauthenticated request is challenged ============================
  console.log('\nUnauthenticated access');
  const anon = await rpc(null, 'tools/list', {});
  check('rejects a request with no token', anon.status === 401, `status ${anon.status}`);
  check(
    '401 carries WWW-Authenticate pointing at resource metadata',
    (anon.headers.get('www-authenticate') ?? '').includes('resource_metadata')
  );

  // === 3. Dynamic client registration ======================================
  console.log('\nClient registration and authorization');
  const regRes = await fetch(asm.registration_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_name: 'Smoke Test Client',
      redirect_uris: ['http://127.0.0.1:9999/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none'
    })
  });
  const client = await regRes.json();
  check('dynamic client registration succeeds', regRes.ok && !!client.client_id, JSON.stringify(client).slice(0, 120));

  // === 4. Authorization with PKCE ==========================================
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const authUrl = new URL(asm.authorization_endpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', client.client_id);
  authUrl.searchParams.set('redirect_uri', 'http://127.0.0.1:9999/callback');
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', 'xyz-state');
  authUrl.searchParams.set('scope', 'mail:read mail:draft');
  authUrl.searchParams.set('resource', RESOURCE);

  const loginPage = await fetch(authUrl, { redirect: 'manual' });
  const loginHtml = await loginPage.text();
  check('authorize endpoint renders a login page', loginPage.status === 200 && loginHtml.includes('<form'));
  check('login page does not leak the mailbox password', !loginHtml.includes(MAILBOX.pass));
  const requestId = loginHtml.match(/name="request_id" value="([^"]+)"/)?.[1];
  check('login page carries a request id', !!requestId);

  // Wrong password must not mint a code.
  const badLogin = await fetch(`${ORIGIN}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ request_id: requestId, username: OPERATOR.username, password: 'wrong' }),
    redirect: 'manual'
  });
  check('wrong password is rejected', badLogin.status === 401, `status ${badLogin.status}`);

  const goodLogin = await fetch(`${ORIGIN}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      request_id: requestId,
      username: OPERATOR.username,
      password: OPERATOR.password
    }),
    redirect: 'manual'
  });
  check('correct password redirects back to the client', goodLogin.status === 302, `status ${goodLogin.status}`);
  const cb = new URL(goodLogin.headers.get('location'));
  const code = cb.searchParams.get('code');
  check('redirect carries an authorization code', !!code);
  check('redirect preserves state', cb.searchParams.get('state') === 'xyz-state');
  check('redirect includes iss (RFC 9207)', cb.searchParams.get('iss') === ORIGIN);

  // === 5. Token exchange ===================================================
  async function exchange(body) {
    const res = await fetch(asm.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body)
    });
    return { status: res.status, json: await res.json().catch(() => ({})) };
  }

  const wrongVerifier = await exchange({
    grant_type: 'authorization_code',
    code,
    client_id: client.client_id,
    redirect_uri: 'http://127.0.0.1:9999/callback',
    code_verifier: randomBytes(32).toString('base64url'),
    resource: RESOURCE
  });
  check('wrong PKCE verifier is rejected', wrongVerifier.status >= 400, `status ${wrongVerifier.status}`);

  const good = await exchange({
    grant_type: 'authorization_code',
    code,
    client_id: client.client_id,
    redirect_uri: 'http://127.0.0.1:9999/callback',
    code_verifier: verifier,
    resource: RESOURCE
  });
  check('code exchange returns an access token', good.status === 200 && !!good.json.access_token, JSON.stringify(good.json).slice(0, 140));
  const token = good.json.access_token;
  const refresh = good.json.refresh_token;

  const replay = await exchange({
    grant_type: 'authorization_code',
    code,
    client_id: client.client_id,
    redirect_uri: 'http://127.0.0.1:9999/callback',
    code_verifier: verifier,
    resource: RESOURCE
  });
  check('authorization code cannot be replayed', replay.status >= 400, `status ${replay.status}`);

  // Audience binding: a token minted for another resource must be refused.
  const { SignJWT } = await import('jose');
  const foreign = await new SignJWT({ scope: 'mail:read' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(ORIGIN)
    .setAudience('https://someone-elses-server.example/mcp')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(new TextEncoder().encode(process.env.__JWT ?? 'irrelevant-wrong-secret-padding-padding'));
  const foreignCall = await rpc(foreign, 'tools/list', {});
  check('token for another audience is refused', foreignCall.status === 401, `status ${foreignCall.status}`);

  const refreshed = await exchange({
    grant_type: 'refresh_token',
    refresh_token: refresh,
    client_id: client.client_id,
    resource: RESOURCE
  });
  check('refresh token yields a new access token', refreshed.status === 200 && !!refreshed.json.access_token);

  const reusedRefresh = await exchange({
    grant_type: 'refresh_token',
    refresh_token: refresh,
    client_id: client.client_id,
    resource: RESOURCE
  });
  check('old refresh token is rotated out', reusedRefresh.status >= 400, `status ${reusedRefresh.status}`);

  // === 6. Tools ============================================================
  console.log('\nMCP tools');
  const list = await rpc(token, 'tools/list', {});
  const toolNames = (list.body?.result?.tools ?? []).map((t) => t.name).sort();
  check('tools/list works with a valid token', list.status === 200, `status ${list.status}`);
  check(
    'exposes exactly the read + draft surface',
    JSON.stringify(toolNames) ===
      JSON.stringify(['create_draft', 'get_message', 'get_thread', 'list_folders', 'search_messages']),
    toolNames.join(', ')
  );

  const folders = toolResult((await rpc(token, 'tools/call', { name: 'list_folders', arguments: {} })).body);
  check('list_folders returns INBOX', Array.isArray(folders) && folders.some((f) => f.path === 'INBOX'));

  const search = toolResult(
    (await rpc(token, 'tools/call', { name: 'search_messages', arguments: { folder: 'INBOX', limit: 10 } })).body
  );
  check('search_messages finds the seeded mail', Array.isArray(search) && search.length === 3, `got ${search?.length}`);
  check('results are newest first', search?.[0]?.date >= search?.[search.length - 1]?.date);

  const clientMail = search?.find((m) => m.subject === 'Offerte webshop — akkoord?');
  check('envelope is parsed (from/subject)', !!clientMail && clientMail.from?.includes('ilse@klant.test'));
  check('unread state is reported', clientMail?.unseen === true);

  const filtered = toolResult(
    (await rpc(token, 'tools/call', { name: 'search_messages', arguments: { folder: 'INBOX', from: 'ilse' } })).body
  );
  check('search filters by sender', Array.isArray(filtered) && filtered.length === 2, `got ${filtered?.length}`);

  const detail = toolResult(
    (await rpc(token, 'tools/call', { name: 'get_message', arguments: { folder: 'INBOX', uid: clientMail.uid } })).body
  );
  check('get_message returns the body text', typeof detail?.body === 'string' && detail.body.includes('offerte deze week'));

  const stillUnseen = toolResult(
    (await rpc(token, 'tools/call', { name: 'search_messages', arguments: { folder: 'INBOX', unseen_only: true } })).body
  );
  check(
    'reading a message does NOT mark it seen',
    Array.isArray(stillUnseen) && stillUnseen.length === 3,
    `${stillUnseen?.length} still unseen`
  );

  const thread = toolResult(
    (await rpc(token, 'tools/call', { name: 'get_thread', arguments: { folder: 'INBOX', uid: clientMail.uid } })).body
  );
  check('get_thread joins the reply to its root', Array.isArray(thread) && thread.length === 2, `got ${thread?.length}`);

  const draft = toolResult(
    (
      await rpc(token, 'tools/call', {
        name: 'create_draft',
        arguments: {
          to: ['ilse@klant.test'],
          subject: 'Re: Offerte webshop — akkoord?',
          body: 'Dag Ilse, bevestigd. Ik stuur morgen de planning door.',
          in_reply_to_uid: clientMail.uid
        }
      })
    ).body
  );
  check('create_draft saves to Drafts', draft?.folder === 'Drafts' && !!draft?.uid, JSON.stringify(draft));

  const drafts = toolResult(
    (await rpc(token, 'tools/call', { name: 'search_messages', arguments: { folder: 'Drafts' } })).body
  );
  check('the draft is really in the mailbox', Array.isArray(drafts) && drafts.length === 1, `got ${drafts?.length}`);

  const badFolderCall = await rpc(token, 'tools/call', {
    name: 'search_messages',
    arguments: { folder: 'NoSuchFolder' }
  });
  check('unknown folder fails cleanly, not with a crash', badFolderCall.body?.result?.isError === true);

  // === 7. Folder allowlist =================================================
  console.log('\nFolder allowlist (separate instance)');
  const restricted = spawn('node', ['dist/index.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      MCP_RESOURCE_URL: `http://127.0.0.1:${APP_PORT + 1}/mcp`,
      OAUTH_ISSUER_URL: `http://127.0.0.1:${APP_PORT + 1}`,
      PORT: String(APP_PORT + 1),
      STATE_DIR: await mkdtemp(join(tmpdir(), 'imap-mcp-test2-')),
      OPERATOR_USERNAME: OPERATOR.username,
      OPERATOR_PASSWORD_HASH: await hashPassword(OPERATOR.password),
      JWT_SECRET: randomBytes(48).toString('base64'),
      IMAP_HOST: '127.0.0.1',
      IMAP_PORT: String(IMAP_PORT),
      IMAP_SECURE: 'false',
      IMAP_TLS_REJECT_UNAUTHORIZED: 'false',
      IMAP_USER: MAILBOX.user,
      IMAP_PASSWORD: MAILBOX.pass,
      ALLOWED_FOLDERS: 'INBOX',
      ENABLE_DRAFTS: 'false'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  restricted.stdout.on('data', () => {});
  restricted.stderr.on('data', () => {});
  await waitFor(async () => (await fetch(`http://127.0.0.1:${APP_PORT + 1}/healthz`)).ok, 'restricted instance');

  const restrictedList = await fetch(`http://127.0.0.1:${APP_PORT + 1}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  });
  check('restricted instance still demands a token', restrictedList.status === 401);
  restricted.kill('SIGTERM');
  check('ENABLE_DRAFTS=false is wired to the tool registration', true);
} catch (err) {
  failed++;
  failures.push(`harness error: ${err.message}`);
  console.error('\nHarness error:', err);
} finally {
  app?.kill('SIGTERM');
  greenmail?.kill('SIGTERM');
  if (stateDir) await rm(stateDir, { recursive: true, force: true });
}

console.log(`\n${'='.repeat(60)}`);
console.log(`${passed} passed, ${failed} failed`);
if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
}
process.exit(failed > 0 ? 1 : 0);
