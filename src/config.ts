import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/** An optional setting, where a blank value (`SMTP_HOST=` in an env file) means unset. */
const optional = () => z.preprocess((v) => (v === '' ? undefined : v), z.string().min(1).optional());

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
  /** Directory for registered clients, refresh tokens and the send log. Mount a volume. */
  STATE_DIR: z.string().default('/data'),

  // --- Mailboxes -----------------------------------------------------------
  /**
   * Path to a YAML file defining several mailboxes (see mailboxes.example.yml).
   * Unset means the single mailbox described by IMAP_USER/IMAP_PASSWORD. The
   * IMAP_* and SMTP_* connection settings below are the defaults every mailbox
   * in the file inherits.
   */
  MAILBOXES_CONFIG: optional(),

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
  /** The single mailbox's login. Required unless MAILBOXES_CONFIG is set. */
  IMAP_USER: optional(),
  IMAP_PASSWORD: optional(),
  /** Folder that create_draft appends to. Mailcow's default is "Drafts". */
  IMAP_DRAFTS_FOLDER: z.string().default('Drafts'),
  /** Folder that send_draft files a copy of each sent message in. */
  IMAP_SENT_FOLDER: z.string().default('Sent'),

  // --- SMTP submission (only used by mailboxes granted "send") -------------
  SMTP_HOST: optional(),
  SMTP_PORT: z.coerce.number().int().positive().default(465),
  /** true for implicit TLS on 465, false for STARTTLS on 587. */
  SMTP_SECURE: z
    .string()
    .default('true')
    .transform((v) => v !== 'false'),
  SMTP_TLS_REJECT_UNAUTHORIZED: z
    .string()
    .default('true')
    .transform((v) => v !== 'false'),

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
    .transform((v) => v !== 'false'),
  /** Set false to remove mark_messages (read/unread, flag) and the mail:mark scope. */
  ENABLE_MARKING: z
    .string()
    .default('true')
    .transform((v) => v !== 'false'),
  /** Set false to remove move_messages and the mail:move scope. */
  ENABLE_MOVE: z
    .string()
    .default('true')
    .transform((v) => v !== 'false'),
  /**
   * Kill switch for send_draft. Sending is only ever possible for mailboxes
   * whose entry in MAILBOXES_CONFIG lists "send"; false removes it everywhere.
   */
  ENABLE_SEND: z
    .string()
    .default('true')
    .transform((v) => v !== 'false')
});

type EnvConfig = z.infer<typeof schema>;

/** What a token can be allowed to do with one mailbox. */
export const CAPABILITIES = ['read', 'draft', 'mark', 'move', 'send'] as const;
export type Capability = (typeof CAPABILITIES)[number];

export interface ServerSettings {
  host: string;
  port: number;
  secure: boolean;
  tlsRejectUnauthorized: boolean;
}

/**
 * Which addresses send_draft may deliver to: only people already in the thread
 * being replied to, anyone, or an allowlist of addresses and "@domain" entries.
 */
export type RecipientPolicy = 'reply-only' | 'any' | string[];

export interface SendPolicy {
  smtp: ServerSettings;
  recipients: RecipientPolicy;
  /** Rolling 24-hour ceiling on messages sent from this mailbox. */
  maxPerDay: number;
  /** Ceiling on To + Cc + Bcc of a single message. */
  maxRecipients: number;
}

/** One mailbox, fully resolved: env defaults applied, password read. */
export interface MailboxConfig {
  /** Short name used in tool arguments and scopes, e.g. "info". */
  id: string;
  /** The address drafts are written from and the only one sends may use. */
  address: string;
  /** Display name for the From header, if any. */
  name?: string;
  imap: ServerSettings & { user: string; password: string };
  draftsFolder: string;
  sentFolder: string;
  /** Empty means every folder. */
  allowedFolders: string[];
  /** Effective capabilities: the file's list, minus anything switched off globally. */
  capabilities: Capability[];
  send?: SendPolicy;
}

export type Config = EnvConfig & { mailboxes: MailboxConfig[] };

const serverOverride = z
  .object({
    host: z.string().min(1).optional(),
    port: z.number().int().positive().optional(),
    secure: z.boolean().optional(),
    tlsRejectUnauthorized: z.boolean().optional()
  })
  .strict();

const mailboxEntry = z
  .object({
    address: z.email(),
    name: z.string().min(1).optional(),
    /** IMAP/SMTP login. Defaults to the address, which is what Mailcow uses. */
    user: z.string().min(1).optional(),
    /** Name of the env var holding this mailbox's app password — never the password itself. */
    passwordEnv: z.string().regex(/^[A-Z_][A-Z0-9_]*$/, 'must be an environment variable name'),
    folders: z.array(z.string().min(1)).optional(),
    draftsFolder: z.string().min(1).optional(),
    sentFolder: z.string().min(1).optional(),
    capabilities: z.array(z.enum(CAPABILITIES)).default(['read']),
    imap: serverOverride.optional(),
    send: z
      .object({
        recipients: z
          .union([z.enum(['reply-only', 'any']), z.array(z.string().min(3)).min(1)])
          .default('reply-only'),
        maxPerDay: z.number().int().positive().default(20),
        maxRecipients: z.number().int().positive().default(10),
        smtp: serverOverride.optional()
      })
      .strict()
      .optional()
  })
  .strict();

const mailboxFile = z
  .object({
    mailboxes: z
      .record(
        z.string().regex(/^[a-z0-9][a-z0-9_-]{0,31}$/, 'ids are lowercase letters, digits, - and _'),
        mailboxEntry
      )
      .refine((m) => Object.keys(m).length > 0, 'define at least one mailbox')
  })
  .strict();

function enabledCapabilities(env: EnvConfig, wanted: Iterable<Capability>): Capability[] {
  const on: Record<Capability, boolean> = {
    read: true,
    draft: env.ENABLE_DRAFTS,
    mark: env.ENABLE_MARKING,
    move: env.ENABLE_MOVE,
    send: env.ENABLE_SEND
  };
  const set = new Set<Capability>(['read', ...wanted]);
  return CAPABILITIES.filter((c) => set.has(c) && on[c]);
}

/** The pre-multi-mailbox setup: one mailbox, entirely from IMAP_* env vars. Never sends. */
function mailboxFromEnv(env: EnvConfig): MailboxConfig {
  if (!env.IMAP_USER || !env.IMAP_PASSWORD) {
    throw new Error(
      'Invalid configuration:\n  IMAP_USER and IMAP_PASSWORD are required unless MAILBOXES_CONFIG is set'
    );
  }
  // The local part names the mailbox in scopes, so personal@... keeps the id
  // "personal" if this deployment later moves to a MAILBOXES_CONFIG file.
  const local = env.IMAP_USER.split('@')[0] ?? env.IMAP_USER;
  const id = local.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+/, '').slice(0, 32) || 'mailbox';
  return {
    id,
    address: env.IMAP_USER,
    imap: {
      host: env.IMAP_HOST,
      port: env.IMAP_PORT,
      secure: env.IMAP_SECURE,
      tlsRejectUnauthorized: env.IMAP_TLS_REJECT_UNAUTHORIZED,
      user: env.IMAP_USER,
      password: env.IMAP_PASSWORD
    },
    draftsFolder: env.IMAP_DRAFTS_FOLDER,
    sentFolder: env.IMAP_SENT_FOLDER,
    allowedFolders: env.ALLOWED_FOLDERS,
    capabilities: enabledCapabilities(env, ['draft', 'mark', 'move'])
  };
}

function mailboxesFromFile(env: EnvConfig, path: string): MailboxConfig[] {
  let doc: unknown;
  try {
    doc = parseYaml(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`Cannot read MAILBOXES_CONFIG ${path}: ${(err as Error).message}`);
  }
  const parsed = mailboxFile.safeParse(doc);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid mailbox configuration in ${path}:\n${issues}`);
  }

  const problems: string[] = [];
  const out = Object.entries(parsed.data.mailboxes).map(([id, m]): MailboxConfig => {
    const password = process.env[m.passwordEnv];
    if (!password) problems.push(`  ${id}: environment variable ${m.passwordEnv} is not set`);

    const capabilities = enabledCapabilities(env, m.capabilities);
    const draftsFolder = m.draftsFolder ?? env.IMAP_DRAFTS_FOLDER;
    const sentFolder = m.sentFolder ?? env.IMAP_SENT_FOLDER;
    const allowedFolders = m.folders ?? env.ALLOWED_FOLDERS;

    let send: SendPolicy | undefined;
    if (capabilities.includes('send')) {
      const host = m.send?.smtp?.host ?? env.SMTP_HOST;
      if (!host) problems.push(`  ${id}: "send" needs SMTP_HOST or send.smtp.host`);
      // send_draft reads from Drafts and files into Sent; an allowlist that
      // hides either would make every send fail halfway, so refuse to start.
      for (const f of [draftsFolder, sentFolder]) {
        if (allowedFolders.length > 0 && !allowedFolders.includes(f)) {
          problems.push(`  ${id}: "send" needs "${f}" in its folder allowlist`);
        }
      }
      send = {
        smtp: {
          host: host ?? '',
          port: m.send?.smtp?.port ?? env.SMTP_PORT,
          secure: m.send?.smtp?.secure ?? env.SMTP_SECURE,
          tlsRejectUnauthorized: m.send?.smtp?.tlsRejectUnauthorized ?? env.SMTP_TLS_REJECT_UNAUTHORIZED
        },
        recipients: m.send?.recipients ?? 'reply-only',
        maxPerDay: m.send?.maxPerDay ?? 20,
        maxRecipients: m.send?.maxRecipients ?? 10
      };
    } else if (m.send) {
      problems.push(`  ${id}: has a "send" section but "send" is not in its capabilities`);
    }

    return {
      id,
      address: m.address,
      ...(m.name ? { name: m.name } : {}),
      imap: {
        host: m.imap?.host ?? env.IMAP_HOST,
        port: m.imap?.port ?? env.IMAP_PORT,
        secure: m.imap?.secure ?? env.IMAP_SECURE,
        tlsRejectUnauthorized: m.imap?.tlsRejectUnauthorized ?? env.IMAP_TLS_REJECT_UNAUTHORIZED,
        user: m.user ?? m.address,
        password: password ?? ''
      },
      draftsFolder,
      sentFolder,
      allowedFolders,
      capabilities,
      ...(send ? { send } : {})
    };
  });

  if (problems.length > 0) {
    throw new Error(`Invalid mailbox configuration in ${path}:\n${problems.join('\n')}`);
  }
  return out;
}

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
  const env = parsed.data;
  cached = {
    ...env,
    // The first mailbox is the default: tokens issued before scopes named a
    // mailbox ("mail:read") are read as applying to it.
    mailboxes: env.MAILBOXES_CONFIG ? mailboxesFromFile(env, env.MAILBOXES_CONFIG) : [mailboxFromEnv(env)],
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
