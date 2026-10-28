import { createHash, randomBytes } from 'node:crypto';
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
import type { Config, UserConfig } from '../config.js';
import { FileStore } from './store.js';
import { hashPassword, verifyPassword } from './password.js';
import { renderConsentPage, renderLoginPage } from './login-page.js';
import {
  canReadAny,
  effectiveScopes,
  expandRequested,
  parseScope,
  supportedScopes,
  userScopes
} from './scopes.js';

/** Outcome of a sign-in attempt at POST /login: the consent page, or why not. */
export type LoginResult =
  | { ok: true; page: string }
  | { ok: false; reason: 'expired' | 'credentials' | 'too_many_attempts' | 'no_access'; error: string };

/** Outcome of a consent submission at POST /consent. */
export type ConsentResult =
  | { ok: true; redirectTo: string }
  | { ok: false; reason: 'expired'; error: string }
  | { ok: false; reason: 'no_scope'; page: string };

interface PendingAuthorization {
  clientId: string;
  clientName: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  state?: string;
  resource?: string;
  /** Password guesses spent against this request; see MAX_LOGIN_ATTEMPTS. */
  attempts: number;
  expiresAt: number;
}

/** A request whose user has signed in; `scopes` is now what that user may be offered. */
interface SignedInAuthorization extends PendingAuthorization {
  user: string;
}

interface IssuedCode extends SignedInAuthorization {
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

export class ImapMcpOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: FileStore;
  private readonly cfg: Config;
  private readonly secret: Uint8Array;
  /** Authorization requests awaiting sign-in. Short-lived, in memory. */
  private readonly pending = new Map<string, PendingAuthorization>();
  /**
   * Signed-in requests awaiting consent, under a fresh id handed only to the
   * browser that signed in: knowing the id /authorize printed is not enough to
   * submit someone else's consent.
   */
  private readonly consents = new Map<string, SignedInAuthorization>();
  /** Issued authorization codes, single use, 60s. */
  private readonly codes = new Map<string, IssuedCode>();
  private readonly users: Map<string, UserConfig>;
  /**
   * Checked in place of a real hash when the username is unknown, so that a
   * wrong name costs the same scrypt as a wrong password and the response time
   * does not tell which names exist.
   */
  private readonly decoyHash = hashPassword(randomBytes(16).toString('base64'));

  constructor(cfg: Config, store: FileStore) {
    this.cfg = cfg;
    this.clientsStore = store;
    this.secret = new TextEncoder().encode(cfg.JWT_SECRET);
    this.users = new Map(cfg.users.map((u) => [u.id, u]));
    setInterval(() => this.sweep(), 60_000).unref();
  }

  private sweep(): void {
    const now = Date.now();
    for (const [k, v] of this.pending) if (v.expiresAt <= now) this.pending.delete(k);
    for (const [k, v] of this.consents) if (v.expiresAt <= now) this.consents.delete(k);
    for (const [k, v] of this.codes) if (v.expiresAt <= now) this.codes.delete(k);
  }

  /** The user a token or refresh token belongs to, if they still exist. */
  user(id: unknown): UserConfig | undefined {
    return typeof id === 'string' ? this.users.get(id) : undefined;
  }

  /**
   * Step 1. The SDK has already validated the client, redirect_uri and PKCE
   * challenge. We park the request and show a sign-in page rather than
   * redirecting straight back with a code.
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const requestId = b64url(randomBytes(24));
    // A client that names no scope is offered everything this deployment
    // has; a client that names some is held to exactly those.
    const { scopes, unknown } = params.scopes?.length
      ? expandRequested(this.cfg, params.scopes)
      : { scopes: supportedScopes(this.cfg), unknown: [] };

    if (unknown.length > 0) {
      const url = new URL(params.redirectUri);
      url.searchParams.set('error', 'invalid_scope');
      url.searchParams.set('error_description', `Unsupported scope: ${unknown.join(' ')}`);
      if (params.state) url.searchParams.set('state', params.state);
      res.redirect(302, url.toString());
      return;
    }

    const clientName = client.client_name ?? client.client_id;
    this.pending.set(requestId, {
      clientId: client.client_id,
      clientName,
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
      .send(renderLoginPage({ requestId, clientName }));
  }

  /**
   * Step 2. Called by our own POST /login route once the user submits the
   * sign-in form. Verifies the password, then hands back the consent page for
   * that user's own mailboxes.
   */
  async completeLogin(requestId: string, username: string, password: string): Promise<LoginResult> {
    const req = this.pending.get(requestId);
    if (!req || req.expiresAt <= Date.now()) {
      this.pending.delete(requestId);
      return {
        ok: false,
        reason: 'expired',
        error: 'This authorization request expired. Start again from Claude.'
      };
    }

    const user = this.users.get(username);
    const passOk = await verifyPassword(password, user?.passwordHash ?? (await this.decoyHash));
    if (!user || !passOk) {
      req.attempts += 1;
      if (req.attempts >= MAX_LOGIN_ATTEMPTS) {
        this.pending.delete(requestId);
        return {
          ok: false,
          reason: 'too_many_attempts',
          error: 'Too many failed attempts. Start the connection again from Claude.'
        };
      }
      // Deliberately vague — the same words for an unknown name and a wrong
      // password — and the request stays pending for a retry.
      return { ok: false, reason: 'credentials', error: 'Incorrect username or password.' };
    }

    this.pending.delete(requestId);
    // What the client asked for, cut down to what this user may grant. Without
    // read on any mailbox nothing could be granted, so say so now rather than
    // show a consent page that can only fail.
    const offered = userScopes(user).filter((s) => req.scopes.includes(s));
    if (!canReadAny(offered)) {
      return {
        ok: false,
        reason: 'no_access',
        error: `${user.id} has no access to the mailboxes this connection asked for.`
      };
    }

    const consentId = b64url(randomBytes(24));
    const signedIn: SignedInAuthorization = {
      ...req,
      user: user.id,
      scopes: offered,
      expiresAt: Date.now() + AUTH_REQUEST_TTL_MS
    };
    this.consents.set(consentId, signedIn);
    return { ok: true, page: this.consentPage(consentId, signedIn) };
  }

  private consentPage(consentId: string, req: SignedInAuthorization, error?: string): string {
    const mine = new Set(this.users.get(req.user)!.mailboxes.map((m) => m.id));
    return renderConsentPage({
      requestId: consentId,
      clientName: req.clientName,
      user: req.user,
      scopes: req.scopes,
      mailboxes: this.cfg.mailboxes
        .filter((m) => mine.has(m.id))
        .map((m) => ({ id: m.id, address: m.address })),
      ...(error ? { error } : {})
    });
  }

  /**
   * Step 3. Called by our own POST /consent route with the boxes the signed-in
   * user left ticked. Redirects back to the client with a code.
   */
  consent(consentId: string, selectedScopes: string[]): ConsentResult {
    const req = this.consents.get(consentId);
    if (!req || req.expiresAt <= Date.now()) {
      this.consents.delete(consentId);
      return {
        ok: false,
        reason: 'expired',
        error: 'This authorization request expired. Start again from Claude.'
      };
    }

    // The user may narrow what the client asked for, never widen it. A
    // write on a mailbox is only kept alongside read on that same mailbox: being
    // able to move or send in a mailbox you cannot look into makes no sense.
    const ticked = req.scopes.filter((s) => selectedScopes.includes(s));
    const readable = new Set(
      ticked.map(parseScope).filter((p) => p?.capability === 'read').map((p) => p!.mailbox)
    );
    const scopes = ticked.filter((s) => readable.has(parseScope(s)?.mailbox ?? ''));
    if (scopes.length === 0) {
      // The request stays open and the page comes back so a mailbox can be ticked.
      return {
        ok: false,
        reason: 'no_scope',
        page: this.consentPage(consentId, req, 'Grant read access to at least one mailbox to continue.')
      };
    }

    this.consents.delete(consentId);
    const code = b64url(randomBytes(32));
    this.codes.set(code, { ...req, scopes, used: false, expiresAt: Date.now() + CODE_TTL_MS });

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
    return this.issueTokens(client.client_id, rec.user, rec.scopes, rec.resource);
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

    // Refresh tokens from before users existed carry no user; they were all
    // issued to the operator, who is still the only user unless mailboxes.yml
    // now lists users — then nobody can say whose they are.
    const user = this.user(rec.user ?? (this.cfg.multiUser ? undefined : this.cfg.users[0]!.id));
    if (!user) {
      await this.clientsStore.deleteRefreshToken(refreshToken);
      throw new InvalidGrantError('The user this connection was authorized by no longer exists; authorize it again');
    }

    // Narrowing only: a refresh may not gain scopes it was not granted.
    const granted = rec.scopes;
    const requested = scopes?.length ? scopes : granted;
    const widened = requested.filter((s) => !granted.includes(s));
    if (widened.length > 0) {
      throw new InvalidGrantError(`Cannot widen scope to: ${widened.join(' ')}`);
    }

    // And whatever mailboxes.yml has taken away from the user since stays gone.
    const current = effectiveScopes(this.cfg, user, requested);
    if (!canReadAny(current)) {
      await this.clientsStore.deleteRefreshToken(refreshToken);
      throw new InvalidGrantError(`${user.id} no longer has access to the mailboxes this connection was granted; authorize it again`);
    }

    // Rotate: OAuth 2.1 requires rotation for public clients.
    await this.clientsStore.deleteRefreshToken(refreshToken);
    return this.issueTokens(client.client_id, user.id, current, rec.resource);
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
    user: string,
    scopes: string[],
    resource: string | undefined
  ): Promise<OAuthTokens> {
    const now = Math.floor(Date.now() / 1000);
    const accessToken = await new SignJWT({ scope: scopes.join(' ') })
      .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
      .setIssuer(this.cfg.OAUTH_ISSUER_URL)
      .setSubject(user)
      .setAudience(this.cfg.MCP_RESOURCE_URL)
      .setIssuedAt(now)
      .setExpirationTime(now + this.cfg.ACCESS_TOKEN_TTL_SECONDS)
      .setJti(b64url(randomBytes(16)))
      .sign(this.secret);

    const refreshToken = b64url(randomBytes(32));
    await this.clientsStore.putRefreshToken(refreshToken, {
      clientId,
      user,
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

    // Every token names the user it was issued to (before users existed, that
    // was always the operator, whose name is the one user's id). A user who
    // has since been removed from mailboxes.yml holds nothing.
    const user = this.user(payload.sub);
    if (!user) throw new InvalidTokenError('Access token belongs to a user who no longer exists');

    const scopes = effectiveScopes(this.cfg, user, String(payload.scope ?? '').split(' ').filter(Boolean));
    return {
      token,
      clientId: String(payload.aud),
      scopes,
      expiresAt: typeof payload.exp === 'number' ? payload.exp : undefined,
      resource: new URL(this.cfg.MCP_RESOURCE_URL),
      extra: { user: user.id }
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
