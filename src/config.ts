import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

const DEFAULT_MAILBOXES_CONFIG = '/config/mailboxes.yml';

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
  /**
   * The single human who may authorize this connector, with every mailbox.
   * Required unless mailboxes.yml has a `users:` section, and refused with one:
   * then each user signs in with their own password and gets their own mailboxes.
   */
  OPERATOR_USERNAME: optional(),
  /** scrypt hash produced by `npm run hash-password`. Never the plaintext. */
  OPERATOR_PASSWORD_HASH: optional(),

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
   * YAML file defining the mailboxes, one or many (see mailboxes.example.yml).
   * The Docker image expects it mounted at the default path, so only tests and
   * bare-metal runs ever set this. The IMAP_* and SMTP_* connection settings
   * below are the defaults every mailbox in the file inherits.
   */
  MAILBOXES_CONFIG: z.preprocess((v) => (v === '' ? undefined : v), z.string().min(1).default(DEFAULT_MAILBOXES_CONFIG)),

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

/** One person who can sign in, and what they may grant in which mailbox. */
export interface UserConfig {
  /** The sign-in name, also the `sub` of every token issued to them. */
  id: string;
  passwordHash: string;
  /**
   * Their mailboxes, in file order, each with what this user may do in it: the
   * mailbox's own capabilities, narrowed by the user's entry.
   */
  mailboxes: Array<{ id: string; capabilities: Capability[] }>;
}

export type Config = EnvConfig & {
  mailboxes: MailboxConfig[];
  users: UserConfig[];
  /** True when mailboxes.yml lists users; false for the single OPERATOR_* login. */
  multiUser: boolean;
};

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

const userEntry = z
  .object({
    /** Name of the env var holding this user's scrypt hash — never the hash or password itself. */
    passwordHashEnv: z.string().regex(/^[A-Z_][A-Z0-9_]*$/, 'must be an environment variable name'),
    /**
     * A list of mailbox ids gives the user everything those mailboxes offer;
     * a map of id to capabilities narrows it per mailbox.
     */
    mailboxes: z.union([
      z.array(z.string().min(1)).min(1),
      z
        .record(z.string().min(1), z.array(z.enum(CAPABILITIES)))
        .refine((m) => Object.keys(m).length > 0, 'give the user at least one mailbox')
    ])
  })
  .strict();

const mailboxFile = z
  .object({
    users: z
      .record(
        z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/, 'user names are letters, digits, ., _, @ and -'),
        userEntry
      )
      .refine((u) => Object.keys(u).length > 0, 'define at least one user, or leave out users:')
      .optional(),
    mailboxes: z
      .record(
        z.string().regex(/^[a-z0-9][a-z0-9_-]{0,31}$/, 'ids are lowercase letters, digits, - and _'),
        mailboxEntry
      )
      .refine((m) => Object.keys(m).length > 0, 'define at least one mailbox')
  })
  .strict();

type MailboxFile = z.infer<typeof mailboxFile>;

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

function readMailboxFile(path: string): unknown {
  try {
    return parseYaml(readFileSync(path, 'utf8'));
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      // Deployments from before the file was mandatory configured one mailbox in .env.
      const legacy = process.env.IMAP_USER
        ? ' IMAP_USER and IMAP_PASSWORD are no longer read: describe that mailbox in the file instead.'
        : '';
      throw new Error(
        `No mailbox configuration at ${path}. Mount mailboxes.yml there (see mailboxes.example.yml).${legacy}`
      );
    }
    if (code === 'EISDIR') {
      throw new Error(
        `${path} is a directory: Docker creates one when the host file it mounts from does not exist. Create mailboxes.yml and recreate the container.`
      );
    }
    throw new Error(`Cannot read mailbox configuration ${path}: ${(err as Error).message}`);
  }
}

function parseMailboxFile(path: string): MailboxFile {
  const doc = readMailboxFile(path);
  const parsed = mailboxFile.safeParse(doc);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid mailbox configuration in ${path}:\n${issues}`);
  }
  return parsed.data;
}

function mailboxesFromFile(env: EnvConfig, file: MailboxFile, path: string): MailboxConfig[] {
  const problems: string[] = [];
  const out = Object.entries(file.mailboxes).map(([id, m]): MailboxConfig => {
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

/**
 * Who may sign in. Without a `users:` section that is the one OPERATOR_* login,
 * with every mailbox exactly as before. With one, each user gets the mailboxes
 * their entry names, and the OPERATOR_* login must be gone: leaving it set would
 * suggest an all-mailbox login that no longer exists.
 */
function usersFromFile(
  env: EnvConfig,
  file: MailboxFile,
  mailboxes: MailboxConfig[],
  path: string
): UserConfig[] {
  if (!file.users) {
    if (!env.OPERATOR_USERNAME || !env.OPERATOR_PASSWORD_HASH || env.OPERATOR_PASSWORD_HASH.length < 16) {
      throw new Error(
        `Invalid configuration:\n  OPERATOR_USERNAME and OPERATOR_PASSWORD_HASH must be set, unless ${path} defines users:`
      );
    }
    return [
      {
        id: env.OPERATOR_USERNAME,
        passwordHash: env.OPERATOR_PASSWORD_HASH,
        mailboxes: mailboxes.map((m) => ({ id: m.id, capabilities: m.capabilities }))
      }
    ];
  }

  const problems: string[] = [];
  if (env.OPERATOR_USERNAME || env.OPERATOR_PASSWORD_HASH) {
    problems.push(
      '  OPERATOR_USERNAME / OPERATOR_PASSWORD_HASH are set, but users: replaces them: describe the operator as a user and remove both from the environment'
    );
  }
  const byId = new Map(mailboxes.map((m) => [m.id, m]));
  const out = Object.entries(file.users).map(([id, u]): UserConfig => {
    const passwordHash = process.env[u.passwordHashEnv];
    if (!passwordHash) {
      problems.push(`  users.${id}: environment variable ${u.passwordHashEnv} is not set`);
    } else if (!passwordHash.startsWith('scrypt$') || passwordHash.length < 16) {
      problems.push(`  users.${id}: ${u.passwordHashEnv} is not a hash from hash-password`);
    }

    // The list form takes whatever the mailbox offers; the map form narrows it.
    const wanted: Array<[string, Capability[] | undefined]> = Array.isArray(u.mailboxes)
      ? [...new Set(u.mailboxes)].map((m) => [m, undefined])
      : Object.entries(u.mailboxes);
    const grants = wanted.flatMap(([mailboxId, caps]) => {
      const mailbox = byId.get(mailboxId);
      if (!mailbox) {
        problems.push(`  users.${id}: there is no mailbox "${mailboxId}"`);
        return [];
      }
      if (!caps) return [{ id: mailboxId, capabilities: mailbox.capabilities }];
      // Checked against the file, not the ENABLE_* switches: a switch turning a
      // capability off is deliberate, a user asking for one the mailbox never
      // had is a typo.
      const declared = new Set(['read', ...file.mailboxes[mailboxId]!.capabilities]);
      for (const c of caps) {
        if (!declared.has(c)) problems.push(`  users.${id}: mailbox "${mailboxId}" does not offer "${c}"`);
      }
      const set = new Set<Capability>(['read', ...caps]);
      return [{ id: mailboxId, capabilities: mailbox.capabilities.filter((c) => set.has(c)) }];
    });
    return { id, passwordHash: passwordHash ?? '', mailboxes: grants };
  });

  if (problems.length > 0) {
    throw new Error(`Invalid user configuration in ${path}:\n${problems.join('\n')}`);
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
  const file = parseMailboxFile(env.MAILBOXES_CONFIG);
  // The first mailbox is the default: tokens issued before scopes named a
  // mailbox ("mail:read") are read as applying to it.
  const mailboxes = mailboxesFromFile(env, file, env.MAILBOXES_CONFIG);
  cached = {
    ...env,
    mailboxes,
    users: usersFromFile(env, file, mailboxes, env.MAILBOXES_CONFIG),
    multiUser: file.users !== undefined,
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
