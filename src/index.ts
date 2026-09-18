import express from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { loadConfig } from './config.js';
import { FileStore } from './auth/store.js';
import { ImapMcpOAuthProvider, supportedScopes } from './auth/provider.js';
import { FailureThrottle } from './auth/rate-limit.js';
import { renderErrorPage } from './auth/login-page.js';
import { ImapConnection } from './imap/client.js';
import { Mailbox } from './imap/mailbox.js';
import { buildMcpServer } from './mcp/server.js';

const cfg = loadConfig();

const store = new FileStore(cfg.STATE_DIR);
await store.init();

const provider = new ImapMcpOAuthProvider(cfg, store);
const imap = new ImapConnection(cfg);
const mailbox = new Mailbox(cfg, imap);

const app = express();
app.disable('x-powered-by');
// Traefik terminates TLS; trust it so redirect URIs and logs see the real scheme.
app.set('trust proxy', 1);

const resourceUrl = new URL(cfg.MCP_RESOURCE_URL);

// OAuth 2.1 authorization server + protected resource metadata. Must be
// mounted at the application root: the .well-known paths are absolute.
app.use(
  mcpAuthRouter({
    provider,
    issuerUrl: new URL(cfg.OAUTH_ISSUER_URL),
    resourceServerUrl: resourceUrl,
    resourceName: `IMAP mailbox (${cfg.IMAP_USER})`,
    scopesSupported: supportedScopes(cfg)
  })
);

/**
 * Sign-in throttling, in two layers: one per source address, and a global
 * ceiling so that rotating addresses cannot turn the login form into an oracle.
 * Both live in memory alongside the pending authorization requests they guard —
 * a restart clears them, which is acceptable because every guess still costs a
 * full scrypt, and the provider burns an authorization request after five.
 */
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const GLOBAL_KEY = '*';
const loginFailuresByIp = new FailureThrottle(5, LOGIN_WINDOW_MS);
const loginFailuresGlobal = new FailureThrottle(20, LOGIN_WINDOW_MS);

// The operator login form posts here; the OAuth provider turns a successful
// login into an authorization code and redirects back to the client.
app.post('/login', express.urlencoded({ extended: false, limit: '4kb' }), async (req, res) => {
  const { request_id: requestId, username, password } = req.body ?? {};
  if (
    typeof requestId !== 'string' ||
    typeof username !== 'string' ||
    typeof password !== 'string'
  ) {
    res.status(400).type('html').send(renderErrorPage('Malformed login request.'));
    return;
  }

  // `trust proxy` is set, so req.ip is the client Traefik saw, not Traefik.
  const ip = req.ip ?? 'unknown';
  const wait = Math.max(
    loginFailuresByIp.retryAfter(ip),
    loginFailuresGlobal.retryAfter(GLOBAL_KEY)
  );
  if (wait > 0) {
    console.warn(`[auth] login throttled for ${ip}, ${wait}s remaining`);
    res
      .status(429)
      .type('html')
      .set('Retry-After', String(wait))
      .set('Cache-Control', 'no-store')
      .send(
        renderErrorPage(
          `Too many failed sign-in attempts. Try again in ${Math.ceil(wait / 60)} minute(s).`
        )
      );
    return;
  }

  const result = await provider.completeLogin(requestId, username, password);
  if (!result.ok) {
    // An expired or unknown request never reached a password check, so it is
    // not a guess and must not count against the operator.
    if (result.reason !== 'expired') {
      loginFailuresByIp.recordFailure(ip);
      loginFailuresGlobal.recordFailure(GLOBAL_KEY);
      console.warn(`[auth] failed login from ${ip} (${result.reason})`);
    }
    res.status(401).type('html').set('Cache-Control', 'no-store').send(renderErrorPage(result.error));
    return;
  }

  loginFailuresByIp.clear(ip);
  res.set('Cache-Control', 'no-store').redirect(302, result.redirectTo);
});

const bearer = requireBearerAuth({
  verifier: provider,
  requiredScopes: ['mail:read'],
  resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceUrl)
});

/**
 * Stateless MCP endpoint: a fresh server and transport per request, no session
 * IDs. That matches where the protocol is heading and means Traefik can restart
 * or round-robin this container without breaking a connector mid-conversation.
 */
app.post('/mcp', bearer, express.json({ limit: '4mb' }), async (req, res) => {
  const server = buildMcpServer(cfg, mailbox);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

  res.on('close', () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error('[mcp] request failed:', err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: { code: -32603, message: 'Internal server error' },
        id: null
      });
    }
  }
});

// GET/DELETE on /mcp are only meaningful for the stateful, session-based mode.
for (const method of ['get', 'delete'] as const) {
  app[method]('/mcp', bearer, (_req, res) => {
    res.status(405).set('Allow', 'POST').json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'This server is stateless; use POST.' },
      id: null
    });
  });
}

app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', resource: cfg.MCP_RESOURCE_URL });
});

const server = app.listen(cfg.PORT, () => {
  console.log(`[imap-mcp] listening on :${cfg.PORT}`);
  console.log(`[imap-mcp] resource: ${cfg.MCP_RESOURCE_URL}`);
  console.log(`[imap-mcp] issuer:   ${cfg.OAUTH_ISSUER_URL}`);
  console.log(`[imap-mcp] mailbox:  ${cfg.IMAP_USER}@${cfg.IMAP_HOST}:${cfg.IMAP_PORT}`);
  console.log(`[imap-mcp] drafts:   ${cfg.ENABLE_DRAFTS ? cfg.IMAP_DRAFTS_FOLDER : 'disabled'}`);
});

async function shutdown(signal: string): Promise<void> {
  console.log(`[imap-mcp] ${signal} received, shutting down`);
  server.close();
  await imap.close();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
