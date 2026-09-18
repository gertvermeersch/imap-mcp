import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Response } from 'express';
import { SignJWT, jwtVerify } from 'jose';
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type {
  AuthorizationParams,
  OAuthServerProvider
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { InvalidGrantError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { Config } from '../config.js';
import { FileStore } from './store.js';
import { verifyPassword } from './password.js';
import { renderLoginPage } from './login-page.js';

export const SCOPES = ['mail:read', 'mail:draft'] as const;
export type Scope = (typeof SCOPES)[number];

/**
 * The scopes this deployment actually offers. With ENABLE_DRAFTS=false there is
 * no create_draft tool, so mail:draft is neither advertised in the metadata
 * document nor grantable — asking for it is an invalid_scope error.
 */
export function supportedScopes(cfg: Config): Scope[] {
  return cfg.ENABLE_DRAFTS ? [...SCOPES] : ['mail:read'];
}

/** Outcome of an operator sign-in attempt at POST /login. */
export type LoginResult =
  | { ok: true; redirectTo: string }
  | { ok: false; reason: 'expired' | 'credentials' | 'too_many_attempts'; error: string };

interface PendingAuthorization {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  state?: string;
  resource?: string;
  /** Password guesses spent against this request; see MAX_LOGIN_ATTEMPTS. */
  attempts: number;
  expiresAt: number;
}

interface IssuedCode extends PendingAuthorization {
  used: boolean;
}

const AUTH_REQUEST_TTL_MS = 10 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;
/**
 * Password guesses allowed against a single authorization request. Burning the
 * request after this many failures forces an attacker back through the whole
 * /authorize round trip for every handful of guesses — on top of the per-IP and
 * global throttles that sit in front of POST /login.
 */
const MAX_LOGIN_ATTEMPTS = 5;

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export class ImapMcpOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: FileStore;
  private readonly cfg: Config;
  private readonly secret: Uint8Array;
  /** Authorization requests awaiting operator login. Short-lived, in memory. */
  private readonly pending = new Map<string, PendingAuthorization>();
  /** Issued authorization codes, single use, 60s. */
  private readonly codes = new Map<string, IssuedCode>();

  constructor(cfg: Config, store: FileStore) {
    this.cfg = cfg;
    this.clientsStore = store;
    this.secret = new TextEncoder().encode(cfg.JWT_SECRET);
    setInterval(() => this.sweep(), 60_000).unref();
  }

  private sweep(): void {
    const now = Date.now();
    for (const [k, v] of this.pending) if (v.expiresAt <= now) this.pending.delete(k);
    for (const [k, v] of this.codes) if (v.expiresAt <= now) this.codes.delete(k);
  }

  /**
   * Step 1. The SDK has already validated the client, redirect_uri and PKCE
   * challenge. We park the request and show the operator a login + consent
   * page rather than redirecting straight back with a code.
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const requestId = b64url(randomBytes(24));
    const supported = supportedScopes(this.cfg);
    // A client that names no scope is granted everything this deployment
    // offers; a client that names some is held to exactly those.
    const scopes = params.scopes?.length ? params.scopes : [...supported];

    const unknown = scopes.filter((s) => !supported.includes(s as Scope));
    if (unknown.length > 0) {
      const url = new URL(params.redirectUri);
      url.searchParams.set('error', 'invalid_scope');
      url.searchParams.set('error_description', `Unsupported scope: ${unknown.join(' ')}`);
      if (params.state) url.searchParams.set('state', params.state);
      res.redirect(302, url.toString());
      return;
    }

    this.pending.set(requestId, {
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      scopes,
      state: params.state,
      resource: params.resource?.toString(),
      attempts: 0,
      expiresAt: Date.now() + AUTH_REQUEST_TTL_MS
    });

    res
      .status(200)
      .set('Content-Type', 'text/html; charset=utf-8')
      .set('Cache-Control', 'no-store')
      .send(
        renderLoginPage({
          requestId,
          clientName: client.client_name ?? client.client_id,
          scopes,
          mailbox: this.cfg.IMAP_USER
        })
      );
  }

  /**
   * Step 2. Called by our own POST /login route once the operator submits the
   * form. Verifies the password, then redirects back to the client with a code.
   */
  async completeLogin(
    requestId: string,
    username: string,
    password: string
  ): Promise<LoginResult> {
    const req = this.pending.get(requestId);
    if (!req || req.expiresAt <= Date.now()) {
      this.pending.delete(requestId);
      return {
        ok: false,
        reason: 'expired',
        error: 'This authorization request expired. Start again from Claude.'
      };
    }

    const userOk = safeEqual(username, this.cfg.OPERATOR_USERNAME);
    const passOk = await verifyPassword(password, this.cfg.OPERATOR_PASSWORD_HASH);
    if (!userOk || !passOk) {
      req.attempts += 1;
      if (req.attempts >= MAX_LOGIN_ATTEMPTS) {
        this.pending.delete(requestId);
        return {
          ok: false,
          reason: 'too_many_attempts',
          error: 'Too many failed attempts. Start the connection again from Claude.'
        };
      }
      // Deliberately vague, and the request stays pending for a retry.
      return { ok: false, reason: 'credentials', error: 'Incorrect username or password.' };
    }

    this.pending.delete(requestId);
    const code = b64url(randomBytes(32));
    this.codes.set(code, { ...req, used: false, expiresAt: Date.now() + CODE_TTL_MS });

    const url = new URL(req.redirectUri);
    url.searchParams.set('code', code);
    if (req.state) url.searchParams.set('state', req.state);
    // RFC 9207: let the client detect AS mix-up.
    url.searchParams.set('iss', this.cfg.OAUTH_ISSUER_URL);
    return { ok: true, redirectTo: url.toString() };
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const rec = this.codes.get(authorizationCode);
    if (!rec) throw new InvalidGrantError('Unknown or expired authorization code');
    return rec.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    const rec = this.codes.get(authorizationCode);
    if (!rec || rec.expiresAt <= Date.now()) {
      this.codes.delete(authorizationCode);
      throw new InvalidGrantError('Unknown or expired authorization code');
    }
    if (rec.used) {
      // Replay: burn the code and everything derived from it.
      this.codes.delete(authorizationCode);
      throw new InvalidGrantError('Authorization code already used');
    }
    if (rec.clientId !== client.client_id) {
      throw new InvalidGrantError('Authorization code was issued to another client');
    }
    if (redirectUri && redirectUri !== rec.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    }
    this.assertResourceMatches(resource?.toString() ?? rec.resource);

    rec.used = true;
    this.codes.delete(authorizationCode);
    return this.issueTokens(client.client_id, rec.scopes, rec.resource);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
    const rec = this.clientsStore.getRefreshToken(refreshToken);
    if (!rec) throw new InvalidGrantError('Unknown or expired refresh token');
    if (rec.clientId !== client.client_id) {
      await this.clientsStore.deleteRefreshToken(refreshToken);
      throw new InvalidGrantError('Refresh token was issued to another client');
    }
    this.assertResourceMatches(resource?.toString() ?? rec.resource);

    // Narrowing only: a refresh may not gain scopes it was not granted.
    const granted = rec.scopes;
    const requested = scopes?.length ? scopes : granted;
    const widened = requested.filter((s) => !granted.includes(s));
    if (widened.length > 0) {
      throw new InvalidGrantError(`Cannot widen scope to: ${widened.join(' ')}`);
    }

    // Rotate: OAuth 2.1 requires rotation for public clients.
    await this.clientsStore.deleteRefreshToken(refreshToken);
    return this.issueTokens(client.client_id, requested, rec.resource);
  }

  private assertResourceMatches(resource: string | undefined): void {
    if (!resource) return; // Client omitted it; audience still pinned on issue.
    const normalized = resource.replace(/\/$/, '');
    if (normalized !== this.cfg.MCP_RESOURCE_URL) {
      throw new InvalidGrantError(
        `Token requested for resource ${resource}, which is not this server`
      );
    }
  }

  private async issueTokens(
    clientId: string,
    scopes: string[],
    resource: string | undefined
  ): Promise<OAuthTokens> {
    const now = Math.floor(Date.now() / 1000);
    const accessToken = await new SignJWT({ scope: scopes.join(' ') })
      .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
      .setIssuer(this.cfg.OAUTH_ISSUER_URL)
      .setSubject(this.cfg.OPERATOR_USERNAME)
      .setAudience(this.cfg.MCP_RESOURCE_URL)
      .setIssuedAt(now)
      .setExpirationTime(now + this.cfg.ACCESS_TOKEN_TTL_SECONDS)
      .setJti(b64url(randomBytes(16)))
      .sign(this.secret);

    const refreshToken = b64url(randomBytes(32));
    await this.clientsStore.putRefreshToken(refreshToken, {
      clientId,
      scopes,
      resource: resource ?? this.cfg.MCP_RESOURCE_URL,
      expiresAt: Date.now() + this.cfg.REFRESH_TOKEN_TTL_SECONDS * 1000
    });

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.cfg.ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: refreshToken,
      scope: scopes.join(' ')
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    let payload;
    try {
      ({ payload } = await jwtVerify(token, this.secret, {
        issuer: this.cfg.OAUTH_ISSUER_URL,
        // This is the audience check the MCP spec insists on: a token minted
        // for some other resource must not be accepted here.
        audience: this.cfg.MCP_RESOURCE_URL,
        algorithms: ['HS256']
      }));
    } catch {
      throw new InvalidTokenError('Access token is invalid or expired');
    }

    const scopes = String(payload.scope ?? '').split(' ').filter(Boolean);
    return {
      token,
      clientId: String(payload.aud),
      scopes,
      expiresAt: typeof payload.exp === 'number' ? payload.exp : undefined,
      resource: new URL(this.cfg.MCP_RESOURCE_URL)
    };
  }

  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    // Access tokens are stateless JWTs and expire on their own; refresh tokens
    // we can actually kill.
    await this.clientsStore.deleteRefreshToken(request.token);
  }

  /** Exposed for the smoke test. */
  static s256(verifier: string): string {
    return createHash('sha256').update(verifier).digest('base64url');
  }
}
