import { z } from 'zod';

/**
 * All configuration comes from the environment. Nothing here has a default that
 * would silently weaken security: secrets, the operator password hash and the
 * canonical resource URL must all be supplied explicitly.
 */
const schema = z.object({
  // --- Public identity of this server -------------------------------------
  /**
   * The canonical URI of this MCP server, exactly as claude.ai will address it.
   * Used as the OAuth resource indicator (RFC 8707) and as the JWT audience.
   * No trailing slash, no fragment.
   */
  MCP_RESOURCE_URL: z.url(),
  /** OAuth issuer identifier. Normally the same origin as MCP_RESOURCE_URL. */
  OAUTH_ISSUER_URL: z.url(),
  /** Port the container listens on behind Traefik. */
  PORT: z.coerce.number().int().positive().default(8080),

  // --- Operator login ------------------------------------------------------
  /** Username for the single human who may authorize this connector. */
  OPERATOR_USERNAME: z.string().min(1),
  /** scrypt hash produced by `npm run hash-password`. Never the plaintext. */
  OPERATOR_PASSWORD_HASH: z.string().min(16),

  // --- Token signing -------------------------------------------------------
  /** >=32 random bytes, base64 or hex. Rotating it invalidates all tokens. */
  JWT_SECRET: z.string().min(32),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(3600),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(60 * 60 * 24 * 30),

  // --- Persistence ---------------------------------------------------------
  /** Directory for registered clients and refresh tokens. Mount a volume. */
  STATE_DIR: z.string().default('/data'),

  // --- IMAP (Mailcow, reached over the private subnet) ---------------------
  IMAP_HOST: z.string().min(1),
  IMAP_PORT: z.coerce.number().int().positive().default(993),
  /** true for implicit TLS on 993, false for STARTTLS on 143. */
  IMAP_SECURE: z
    .string()
    .default('true')
    .transform((v) => v !== 'false'),
  /**
   * Set false only if your mail server presents a cert that does not match the private
   * subnet hostname you connect to. Prefer fixing the cert or using the name
   * on it — this is a real downgrade.
   */
  IMAP_TLS_REJECT_UNAUTHORIZED: z
    .string()
    .default('true')
    .transform((v) => v !== 'false'),
  IMAP_USER: z.string().min(1),
  IMAP_PASSWORD: z.string().min(1),
  /** Folder that create_draft appends to. Mailcow's default is "Drafts". */
  IMAP_DRAFTS_FOLDER: z.string().default('Drafts'),

  // --- Guard rails ---------------------------------------------------------
  /** Hard ceiling on messages returned by a single search. */
  MAX_SEARCH_RESULTS: z.coerce.number().int().positive().max(200).default(50),
  /** Truncate message bodies to this many characters before returning them. */
  MAX_BODY_CHARS: z.coerce.number().int().positive().default(20000),
  /**
   * Comma-separated folders the server may read. Empty means all folders.
   * Anything not listed is invisible to the tools.
   */
  ALLOWED_FOLDERS: z
    .string()
    .default('')
    .transform((v) =>
      v
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    ),
  /** Set false to remove create_draft and make the server strictly read-only. */
  ENABLE_DRAFTS: z
    .string()
    .default('true')
    .transform((v) => v !== 'false')
});

export type Config = z.infer<typeof schema>;

function normalizeResourceUrl(raw: string): string {
  const u = new URL(raw);
  u.hash = '';
  // RFC 8707 canonical form: prefer no trailing slash.
  if (u.pathname !== '/' && u.pathname.endsWith('/')) {
    u.pathname = u.pathname.replace(/\/+$/, '');
  }
  if (u.pathname === '/') u.pathname = '';
  return u.toString().replace(/\/$/, '');
}

let cached: Config | undefined;

export function loadConfig(): Config {
  if (cached) return cached;
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid configuration:\n${issues}`);
  }
  cached = {
    ...parsed.data,
    MCP_RESOURCE_URL: normalizeResourceUrl(parsed.data.MCP_RESOURCE_URL),
    // The metadata document publishes the issuer as new URL(issuer).href,
    // which always carries a trailing slash on a bare origin. RFC 9207 has
    // clients compare the "iss" we send back on the redirect against that
    // string byte for byte, so both sides must be spelled the same way or a
    // strict client silently drops the callback.
    OAUTH_ISSUER_URL: new URL(parsed.data.OAUTH_ISSUER_URL).href
  };
  return cached;
}
