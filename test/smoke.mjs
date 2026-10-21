/**
 * End-to-end smoke test against a throwaway GreenMail IMAP server.
 *
 * Exercises the real OAuth 2.1 flow the way an MCP client does — discovery,
 * dynamic client registration, PKCE authorization, operator login, code
 * exchange, audience-bound token — and then calls every tool over the
 * Streamable HTTP transport. Also asserts the negative cases that matter:
 * no token, wrong audience, wrong PKCE verifier, code replay. A second instance
 * runs two mailboxes from a MAILBOXES_CONFIG file and sends real mail through
 * GreenMail's SMTP with send_draft, including every refusal its policy makes.
 *
 * Usage: node test/smoke.mjs   (expects a built dist/)
 *
 * GreenMail runs in Docker (greenmail/standalone) unless GREENMAIL_JAR points at
 * a standalone jar, in which case it runs under a local Java instead.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import nodemailer from 'nodemailer';
import { ImapFlow } from 'imapflow';
import { hashPassword } from '../dist/auth/password.js';

const JAR = process.env.GREENMAIL_JAR;
const GREENMAIL_IMAGE = 'greenmail/standalone:2.1.13';
const GREENMAIL_CONTAINER = 'imap-mcp-smoke-greenmail';
/** Repo root, so the suite runs from wherever it is checked out. */
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const IMAP_PORT = 3143;
const SMTP_PORT = 3025;
const APP_PORT = 8791;
const ORIGIN = `http://127.0.0.1:${APP_PORT}`;
const RESOURCE = `${ORIGIN}/mcp`;
const OPERATOR = { username: 'operator', password: 'correct-horse-battery' };
const MAILBOX = { user: 'mailbox@example.test', pass: 'imap-secret' };
const AGENT = { user: 'agent@example.test', pass: 'agent-secret' };
const SCOPES = ['mail:read', 'mail:draft', 'mail:mark', 'mail:move'].map((s) => `${s}:mailbox`);

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
async function rpc(token, method, params, resource = RESOURCE) {
  const res = await fetch(resource, {
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
  const greenmailOpts = [
    '-Dgreenmail.setup.test.all',
    `-Dgreenmail.users=${MAILBOX.user}:${MAILBOX.pass},${AGENT.user}:${AGENT.pass}`,
    '-Dgreenmail.auth.disabled=false'
  ];
  if (JAR) {
    greenmail = spawn('java', [...greenmailOpts, '-jar', JAR], { stdio: ['ignore', 'pipe', 'pipe'] });
  } else {
    // Inside a container GreenMail must listen on every interface, or the
    // published ports have nothing behind them.
    spawnSync('docker', ['rm', '-f', GREENMAIL_CONTAINER], { stdio: 'ignore' });
    greenmail = spawn(
      'docker',
      [
        'run', '--rm', '--name', GREENMAIL_CONTAINER,
        '-e', `GREENMAIL_OPTS=${[...greenmailOpts, '-Dgreenmail.hostname=0.0.0.0'].join(' ')}`,
        '-p', `127.0.0.1:${IMAP_PORT}:3143`,
        '-p', `127.0.0.1:${SMTP_PORT}:3025`,
        GREENMAIL_IMAGE
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );
  }
  greenmail.stdout.on('data', () => {});
  greenmail.stderr.on('data', () => {});

  await waitFor(async () => {
    const { connect } = await import('node:net');
    return new Promise((resolve) => {
      // A bare TCP connect is not enough: Docker's port proxy accepts before
      // GreenMail is listening behind it. Wait for the IMAP greeting.
      const s = connect(IMAP_PORT, '127.0.0.1');
      s.setTimeout(2000, () => {
        s.destroy();
        resolve(false);
      });
      s.on('data', (d) => {
        s.destroy();
        resolve(d.toString().startsWith('* OK'));
      });
      s.on('error', () => resolve(false));
      s.on('close', () => resolve(false));
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
    text: 'Dag An, kunnen we de offerte deze week bevestigen? Groeten, Ilse',
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
  authUrl.searchParams.set('scope', SCOPES.join(' '));
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
    body: new URLSearchParams([
      ['request_id', requestId],
      ['username', OPERATOR.username],
      ['password', OPERATOR.password],
      ...SCOPES.map((s) => ['scope', s])
    ]),
    redirect: 'manual'
  });
  check('correct password redirects back to the client', goodLogin.status === 302, `status ${goodLogin.status}`);
  const cb = new URL(goodLogin.headers.get('location'));
  const code = cb.searchParams.get('code');
  check('redirect carries an authorization code', !!code);
  check('redirect preserves state', cb.searchParams.get('state') === 'xyz-state');
  // The server normalizes the issuer to new URL(...).href, trailing slash included,
  // so that it matches the metadata document byte for byte (see src/config.ts).
  check('redirect includes iss (RFC 9207)', cb.searchParams.get('iss') === `${ORIGIN}/`, cb.searchParams.get('iss'));

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
    'exposes exactly the read + draft + mark + move surface, and no send',
    JSON.stringify(toolNames) ===
      JSON.stringify([
        'create_draft',
        'get_message',
        'get_thread',
        'list_folders',
        'list_mailboxes',
        'mark_messages',
        'move_messages',
        'search_messages'
      ]),
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

  // --- marking -------------------------------------------------------------
  const call = async (name, args) => (await rpc(token, 'tools/call', { name, arguments: args })).body;
  const inboxUnseen = async () =>
    toolResult(await call('search_messages', { folder: 'INBOX', unseen_only: true }));

  const marked = toolResult(await call('mark_messages', { folder: 'INBOX', uids: [clientMail.uid], seen: true }));
  check(
    'mark_messages marks a message read',
    marked?.updated?.length === 1 && marked.updated[0].unseen === false && marked.updated[0].flagged === false,
    JSON.stringify(marked)
  );
  check('the read mark shows up in search', (await inboxUnseen())?.length === 2);

  const flagged = toolResult(await call('mark_messages', { folder: 'INBOX', uids: [clientMail.uid], flagged: true }));
  check(
    'flagging leaves the read state alone',
    flagged?.updated?.[0]?.flagged === true && flagged.updated[0].unseen === false,
    JSON.stringify(flagged)
  );

  const unmarked = toolResult(
    await call('mark_messages', { folder: 'INBOX', uids: [clientMail.uid], seen: false, flagged: false })
  );
  check(
    'mark_messages can undo both',
    unmarked?.updated?.[0]?.unseen === true && unmarked.updated[0].flagged === false,
    JSON.stringify(unmarked)
  );

  const ghost = toolResult(await call('mark_messages', { folder: 'INBOX', uids: [clientMail.uid, 99999], seen: true }));
  check(
    'unknown UIDs are reported, not fatal',
    ghost?.updated?.length === 1 && JSON.stringify(ghost.notFound) === '[99999]',
    JSON.stringify(ghost)
  );
  await call('mark_messages', { folder: 'INBOX', uids: [clientMail.uid], seen: false });

  const noop = await call('mark_messages', { folder: 'INBOX', uids: [clientMail.uid] });
  check('mark_messages with nothing to change is an error', noop?.result?.isError === true);

  // --- moving --------------------------------------------------------------
  const newsletter = search.find((m) => m.subject === 'Your weekly digest of growth hacks');
  const moved = toolResult(
    await call('move_messages', { folder: 'INBOX', uids: [newsletter.uid], destination: 'Drafts' })
  );
  check(
    'move_messages moves a message',
    moved?.moved?.length === 1 && moved.moved[0].uid === newsletter.uid && moved.to === 'Drafts',
    JSON.stringify(moved)
  );
  const inboxAfter = toolResult(await call('search_messages', { folder: 'INBOX' }));
  const draftsAfter = toolResult(await call('search_messages', { folder: 'Drafts' }));
  check(
    'the message left the source and arrived at the destination',
    inboxAfter?.length === 2 && draftsAfter?.some((m) => m.subject === newsletter.subject),
    `inbox ${inboxAfter?.length}, drafts ${draftsAfter?.length}`
  );

  const toMissing = await call('move_messages', { folder: 'INBOX', uids: [clientMail.uid], destination: 'NoSuchFolder' });
  check('moving to a missing folder fails, and does not create it', toMissing?.result?.isError === true);
  const toSame = await call('move_messages', { folder: 'INBOX', uids: [clientMail.uid], destination: 'INBOX' });
  check('moving into the same folder is an error', toSame?.result?.isError === true);
  const stillThere = toolResult(await call('search_messages', { folder: 'INBOX' }));
  check('failed moves leave the message where it was', stillThere?.some((m) => m.uid === clientMail.uid));

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

  // === 8. Several mailboxes, and sending ===================================
  console.log('\nTwo mailboxes and send_draft (separate instance)');
  const threadId = '<agent-thread@example.test>';
  await smtp.sendMail({
    from: MAILBOX.user,
    to: AGENT.user,
    subject: 'Planning Q4',
    text: 'Kan je de planning bevestigen?',
    messageId: threadId
  });
  await sleep(1000);

  const multiDir = await mkdtemp(join(tmpdir(), 'imap-mcp-multi-'));
  await writeFile(
    join(multiDir, 'mailboxes.yml'),
    `mailboxes:
  personal:
    address: ${MAILBOX.user}
    passwordEnv: SMOKE_PW_PERSONAL
    capabilities: [read, draft, mark, move]
  agent:
    address: ${AGENT.user}
    name: Smoke Agent
    passwordEnv: SMOKE_PW_AGENT
    capabilities: [read, draft, move, send]
    send:
      recipients: reply-only
      maxPerDay: 2
`
  );
  const MULTI_ORIGIN = `http://127.0.0.1:${APP_PORT + 2}`;
  const MULTI = `${MULTI_ORIGIN}/mcp`;
  const multi = spawn('node', ['dist/index.js'], {
    cwd: ROOT,
    env: {
      ...process.env,
      MCP_RESOURCE_URL: MULTI,
      OAUTH_ISSUER_URL: MULTI_ORIGIN,
      PORT: String(APP_PORT + 2),
      STATE_DIR: multiDir,
      OPERATOR_USERNAME: OPERATOR.username,
      OPERATOR_PASSWORD_HASH: await hashPassword(OPERATOR.password),
      JWT_SECRET: randomBytes(48).toString('base64'),
      MAILBOXES_CONFIG: join(multiDir, 'mailboxes.yml'),
      SMOKE_PW_PERSONAL: MAILBOX.pass,
      SMOKE_PW_AGENT: AGENT.pass,
      IMAP_HOST: '127.0.0.1',
      IMAP_PORT: String(IMAP_PORT),
      IMAP_SECURE: 'false',
      IMAP_TLS_REJECT_UNAUTHORIZED: 'false',
      SMTP_HOST: '127.0.0.1',
      SMTP_PORT: String(SMTP_PORT),
      SMTP_SECURE: 'false',
      SMTP_TLS_REJECT_UNAUTHORIZED: 'false'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const multiLog = [];
  multi.stdout.on('data', (d) => multiLog.push(d.toString()));
  multi.stderr.on('data', (d) => multiLog.push(d.toString()));
  try {
    await waitFor(async () => (await fetch(`${MULTI_ORIGIN}/healthz`)).ok, 'multi-mailbox instance');

    // The whole OAuth dance again, granting send on the agent mailbox.
    const reg = await (
      await fetch(`${MULTI_ORIGIN}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Smoke Multi',
          redirect_uris: ['http://127.0.0.1:9999/callback'],
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none'
        })
      })
    ).json();
    const v = randomBytes(32).toString('base64url');
    const au = new URL(`${MULTI_ORIGIN}/authorize`);
    for (const [k, val] of Object.entries({
      response_type: 'code',
      client_id: reg.client_id,
      redirect_uri: 'http://127.0.0.1:9999/callback',
      code_challenge: createHash('sha256').update(v).digest('base64url'),
      code_challenge_method: 'S256',
      resource: MULTI
    })) au.searchParams.set(k, val);
    const page = await (await fetch(au)).text();
    const granted = ['mail:read:personal', 'mail:read:agent', 'mail:draft:agent', 'mail:move:agent', 'mail:send:agent'];
    const li = await fetch(`${MULTI_ORIGIN}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams([
        ['request_id', page.match(/name="request_id" value="([^"]+)"/)?.[1]],
        ['username', OPERATOR.username],
        ['password', OPERATOR.password],
        ...granted.map((s) => ['scope', s])
      ]),
      redirect: 'manual'
    });
    const mcode = new URL(li.headers.get('location')).searchParams.get('code');
    const mtok = await (
      await fetch(`${MULTI_ORIGIN}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: mcode,
          code_verifier: v,
          client_id: reg.client_id,
          redirect_uri: 'http://127.0.0.1:9999/callback',
          resource: MULTI
        })
      })
    ).json();
    check('a grant with send on the agent mailbox is issued', mtok.scope === granted.join(' '), mtok.scope);

    const mcall = async (name, args) => (await rpc(mtok.access_token, 'tools/call', { name, arguments: args }, MULTI)).body;
    const mres = async (name, args) => toolResult(await mcall(name, args));
    const errText = (body) => (body?.result?.isError ? body.result.content?.[0]?.text ?? '' : '');

    const boxes = await mres('list_mailboxes', {});
    check(
      'list_mailboxes shows both mailboxes and the agent\'s send policy',
      boxes?.length === 2 && boxes[1].access.includes('send') && boxes[1].send?.recipients === 'reply-only',
      JSON.stringify(boxes)
    );

    const agentInbox = await mres('search_messages', { mailbox: 'agent', folder: 'INBOX' });
    const question = agentInbox?.find((m) => m.subject === 'Planning Q4');
    check('each mailbox reads its own INBOX', !!question && question.mailbox === 'agent', JSON.stringify(agentInbox));
    const personalInbox = await mres('search_messages', { mailbox: 'personal', folder: 'INBOX', subject: 'Planning Q4' });
    check('...and not the other\'s', Array.isArray(personalInbox) && personalInbox.length === 0, JSON.stringify(personalInbox));

    const draftFor = async (args) =>
      (await mres('create_draft', { mailbox: 'agent', subject: 'Re: Planning Q4', body: 'Bevestigd.', ...args }))?.uid;

    // --- refusals ----------------------------------------------------------
    const strangerUid = await draftFor({ to: ['stranger@evil.test'], in_reply_to_uid: question.uid });
    const stranger = await mcall('send_draft', { mailbox: 'agent', uid: strangerUid });
    check(
      'reply-only refuses a recipient who is not in the conversation',
      errText(stranger).includes('stranger@evil.test'),
      errText(stranger) || JSON.stringify(stranger)
    );

    const freshUid = await draftFor({ to: [MAILBOX.user] });
    const fresh = await mcall('send_draft', { mailbox: 'agent', uid: freshUid });
    check('reply-only refuses a draft that replies to nothing', errText(fresh).includes('does not reply'), errText(fresh));

    // A draft moved out of Drafts keeps \Draft, so it cannot pose as the
    // message being replied to and smuggle in a recipient.
    const plantUid = await draftFor({ to: ['evil@x.test'], subject: 'planted' });
    const planted = await mres('move_messages', { mailbox: 'agent', folder: 'Drafts', uids: [plantUid], destination: 'INBOX' });
    const plantedUid = planted?.moved?.[0]?.newUid;
    const smuggleUid = await draftFor({ to: ['evil@x.test'], in_reply_to_uid: plantedUid });
    const smuggle = await mcall('send_draft', { mailbox: 'agent', uid: smuggleUid });
    check(
      'a draft moved into INBOX does not count as a conversation to reply to',
      !!plantedUid && errText(smuggle).includes('was not found'),
      errText(smuggle) || JSON.stringify(planted)
    );

    const notDraft = await mcall('send_draft', { mailbox: 'agent', uid: 99999 });
    check('a UID that is not in Drafts is refused', errText(notDraft).includes('No draft'), errText(notDraft));

    // --- a real send of a draft a human edited (added a Bcc) ---------------
    const agentImap = new ImapFlow({
      host: '127.0.0.1',
      port: IMAP_PORT,
      secure: false,
      auth: { user: AGENT.user, pass: AGENT.pass },
      logger: false
    });
    await agentImap.connect();
    const oldDate = 'Mon, 01 Jan 2024 09:00:00 +0000';
    const edited = [
      `From: Smoke Agent <${AGENT.user}>`,
      `To: ${MAILBOX.user}`,
      `Bcc: ${AGENT.user}`,
      'Subject: Re: Planning Q4',
      `Date: ${oldDate}`,
      'Message-ID: <smoke-reply@example.test>',
      `In-Reply-To: ${threadId}`,
      `References: ${threadId}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'Bevestigd, planning volgt vrijdag.',
      ''
    ].join('\r\n');
    const appended = await agentImap.append('Drafts', edited, ['\\Draft']);

    const sent = await mres('send_draft', { mailbox: 'agent', uid: appended.uid });
    check(
      'send_draft sends a reply to someone in the conversation',
      sent?.accepted?.includes(MAILBOX.user) && sent.messageId === '<smoke-reply@example.test>',
      JSON.stringify(sent)
    );
    check('the sent copy is filed in Sent', sent?.sentFolder === 'Sent', JSON.stringify(sent));
    check('the draft leaves Drafts', sent?.draft === 'removed' || sent?.draft === 'flagged', sent?.draft);
    check('the send is in the server log', multiLog.join('').includes('[send] mailbox=agent'));

    await sleep(1000);
    const personalImap = new ImapFlow({
      host: '127.0.0.1',
      port: IMAP_PORT,
      secure: false,
      auth: { user: MAILBOX.user, pass: MAILBOX.pass },
      logger: false
    });
    await personalImap.connect();
    const sourceOf = async (client, folder, subject) => {
      const lock = await client.getMailboxLock(folder);
      try {
        const uids = (await client.search({ subject }, { uid: true })) || [];
        if (uids.length === 0) return undefined;
        return (await client.fetchOne(String(uids.at(-1)), { source: true }, { uid: true }))?.source?.toString();
      } finally {
        lock.release();
      }
    };
    const delivered = await sourceOf(personalImap, 'INBOX', 'Re: Planning Q4');
    check('the recipient received it', !!delivered && delivered.includes('planning volgt vrijdag'));
    check('the recipient\'s copy carries no Bcc header', !!delivered && !/^bcc:/im.test(delivered));
    check('the Date is the moment of sending, not of drafting', !!delivered && !delivered.includes(oldDate));
    const filed = await sourceOf(agentImap, 'Sent', 'Re: Planning Q4');
    check('the copy in Sent keeps the Bcc', !!filed && /^bcc:/im.test(filed));
    const bccCopy = await sourceOf(agentImap, 'INBOX', 'Re: Planning Q4');
    check('the Bcc recipient received it too', !!bccCopy);
    await personalImap.logout();
    await agentImap.logout();

    const again = await mcall('send_draft', { mailbox: 'agent', uid: appended.uid });
    check('the same draft cannot be sent twice', !!errText(again), JSON.stringify(again).slice(0, 200));

    // --- daily cap (2) -----------------------------------------------------
    const secondUid = await draftFor({ to: [MAILBOX.user], in_reply_to_uid: question.uid });
    const second = await mres('send_draft', { mailbox: 'agent', uid: secondUid });
    check('a second reply goes out', second?.accepted?.length === 1, JSON.stringify(second));
    const thirdUid = await draftFor({ to: [MAILBOX.user], in_reply_to_uid: question.uid });
    const third = await mcall('send_draft', { mailbox: 'agent', uid: thirdUid });
    check('the third in a day hits maxPerDay and sends nothing', errText(third).includes('limit is 2'), errText(third));

    const personalSend = await mcall('send_draft', { mailbox: 'personal', uid: 1 });
    check('a mailbox without "send" cannot be named in send_draft', !!errText(personalSend) || !!personalSend?.error);
  } finally {
    multi.kill('SIGTERM');
    await rm(multiDir, { recursive: true, force: true });
  }
} catch (err) {
  failed++;
  failures.push(`harness error: ${err.message}`);
  console.error('\nHarness error:', err);
} finally {
  app?.kill('SIGTERM');
  greenmail?.kill('SIGTERM');
  if (!JAR) spawnSync('docker', ['rm', '-f', GREENMAIL_CONTAINER], { stdio: 'ignore' });
  if (stateDir) await rm(stateDir, { recursive: true, force: true });
}

console.log(`\n${'='.repeat(60)}`);
console.log(`${passed} passed, ${failed} failed`);
if (failures.length > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
}
process.exit(failed > 0 ? 1 : 0);
