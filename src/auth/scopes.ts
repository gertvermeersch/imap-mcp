import { CAPABILITIES, type Capability, type Config } from '../config.js';

/**
 * Scopes name a capability and a mailbox: mail:read:personal, mail:send:agent. Each
 * one is granted, checked and narrowed on its own, so a token can read three
 * mailboxes, draft in two and send from none.
 */
export function scopeFor(capability: Capability, mailbox: string): string {
  return `mail:${capability}:${mailbox}`;
}

export function parseScope(scope: string): { capability: Capability; mailbox: string } | undefined {
  const m = /^mail:([a-z]+):([a-z0-9_-]+)$/.exec(scope);
  if (!m || !(CAPABILITIES as readonly string[]).includes(m[1]!)) return undefined;
  return { capability: m[1] as Capability, mailbox: m[2]! };
}

/**
 * Every scope this deployment offers: one per mailbox per capability it has.
 * A capability switched off globally, or not given to a mailbox, is neither
 * advertised nor grantable — asking for it is an invalid_scope error.
 */
export function supportedScopes(cfg: Config): string[] {
  return cfg.mailboxes.flatMap((m) => m.capabilities.map((c) => scopeFor(c, m.id)));
}

/** Matches the scopes from before mailboxes were named: mail:read, mail:draft, ... */
const LEGACY = /^mail:([a-z]+)$/;
const PRE_MAILBOX_CAPABILITIES = ['read', 'draft', 'mark', 'move'];

/**
 * What a client asks for at /authorize. A legacy unqualified scope, which a
 * client may have cached from an older metadata document, asks for that
 * capability on every mailbox that has it; the operator then picks per mailbox.
 * Returns the scopes on offer and the ones that match nothing.
 */
export function expandRequested(cfg: Config, requested: string[]): { scopes: string[]; unknown: string[] } {
  const supported = supportedScopes(cfg);
  const out = new Set<string>();
  const unknown: string[] = [];
  for (const s of requested) {
    const legacy = LEGACY.exec(s);
    const matches = legacy ? supported.filter((x) => parseScope(x)?.capability === legacy[1]) : supported.filter((x) => x === s);
    if (matches.length === 0) unknown.push(s);
    for (const x of matches) out.add(x);
  }
  // Keep the deployment's order (mailbox by mailbox) whatever order the client used.
  return { scopes: supported.filter((s) => out.has(s)), unknown };
}

/**
 * What a token carries, as the tools check it. Tokens and refresh tokens
 * issued before scopes named a mailbox say mail:read; those keep meaning the
 * mailbox they were granted on, which is the default (first) one.
 */
export function normalizeGranted(cfg: Config, scopes: string[]): string[] {
  const fallback = cfg.mailboxes[0]!.id;
  return [
    ...new Set(
      scopes.map((s) => {
        const legacy = LEGACY.exec(s);
        // Sending postdates mailbox-qualified scopes, so no legacy token ever
        // carried it; only the four original capabilities are translated.
        return legacy && PRE_MAILBOX_CAPABILITIES.includes(legacy[1]!)
          ? scopeFor(legacy[1] as Capability, fallback)
          : s;
      })
    )
  ];
}

/** True when the token can read at least one mailbox — the floor for /mcp. */
export function canReadAny(scopes: string[]): boolean {
  return scopes.some((s) => parseScope(s)?.capability === 'read');
}
