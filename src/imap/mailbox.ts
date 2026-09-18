import { simpleParser } from 'mailparser';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';
import type { Config } from '../config.js';
import type { ImapConnection } from './client.js';

export interface MessageSummary {
  uid: number;
  folder: string;
  messageId: string | undefined;
  date: string | undefined;
  from: string | undefined;
  to: string | undefined;
  subject: string | undefined;
  unseen: boolean;
  answered: boolean;
  flagged: boolean;
  hasAttachments: boolean;
  sizeBytes: number | undefined;
}

export interface MessageDetail extends MessageSummary {
  cc: string | undefined;
  replyTo: string | undefined;
  inReplyTo: string | undefined;
  references: string[];
  body: string;
  bodyTruncated: boolean;
  attachments: Array<{ filename: string | undefined; contentType: string; sizeBytes: number }>;
}

export class MailboxError extends Error {}

function addressText(a: unknown): string | undefined {
  if (!a) return undefined;
  const list = Array.isArray(a) ? a : [a];
  const parts = list
    .map((entry) => {
      const e = entry as { name?: string; address?: string };
      if (!e?.address) return undefined;
      return e.name ? `${e.name} <${e.address}>` : e.address;
    })
    .filter(Boolean);
  return parts.length > 0 ? parts.join(', ') : undefined;
}

export class Mailbox {
  constructor(
    private readonly cfg: Config,
    private readonly conn: ImapConnection
  ) {}

  /** Throws unless the folder is inside the configured allowlist. */
  private assertAllowed(folder: string): string {
    const allowed = this.cfg.ALLOWED_FOLDERS;
    if (allowed.length > 0 && !allowed.includes(folder)) {
      throw new MailboxError(
        `Folder "${folder}" is not in this server's allowlist (${allowed.join(', ')})`
      );
    }
    return folder;
  }

  async listFolders(): Promise<Array<{ path: string; name: string; specialUse?: string }>> {
    const list = await this.conn.withClient((c) => c.list());
    const allowed = this.cfg.ALLOWED_FOLDERS;
    return list
      .filter((m) => !m.flags?.has('\\Noselect'))
      .filter((m) => allowed.length === 0 || allowed.includes(m.path))
      .map((m) => ({
        path: m.path,
        name: m.name,
        ...(m.specialUse ? { specialUse: m.specialUse } : {})
      }));
  }

  async search(params: {
    folder: string;
    since?: string;
    before?: string;
    from?: string;
    to?: string;
    subject?: string;
    text?: string;
    unseenOnly?: boolean;
    limit?: number;
  }): Promise<MessageSummary[]> {
    const folder = this.assertAllowed(params.folder);
    const limit = Math.min(params.limit ?? 25, this.cfg.MAX_SEARCH_RESULTS);

    const query: Record<string, unknown> = {};
    const header: Record<string, string> = {};
    if (params.since) query.since = this.parseDate(params.since, 'since');
    if (params.before) query.before = this.parseDate(params.before, 'before');
    // HEADER <field> <value> is substring matching on every RFC 3501 server.
    // The bare FROM/TO keys are interpreted more loosely by some servers
    // (GreenMail, for one, matches whole addresses only), so prefer HEADER.
    if (params.from) header.from = params.from;
    if (params.to) header.to = params.to;
    if (Object.keys(header).length > 0) query.header = header;
    if (params.subject) query.subject = params.subject;
    if (params.text) query.body = params.text;
    if (params.unseenOnly) query.seen = false;
    if (Object.keys(query).length === 0) query.all = true;

    return this.conn.withFolder(folder, true, async (client) => {
      const uids = (await client.search(query, { uid: true })) || [];
      if (uids.length === 0) return [];
      // Newest first, then cap. Fetching only what we return keeps the
      // response small enough for a triage prompt.
      const wanted = [...uids].sort((a, b) => b - a).slice(0, limit);

      const out: MessageSummary[] = [];
      for await (const msg of client.fetch(
        wanted,
        { uid: true, envelope: true, flags: true, size: true, bodyStructure: true },
        { uid: true }
      )) {
        out.push(this.toSummary(folder, msg));
      }
      out.sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''));
      return out;
    });
  }

  async getMessage(folder0: string, uid: number): Promise<MessageDetail> {
    const folder = this.assertAllowed(folder0);
    return this.conn.withFolder(folder, true, async (client) => {
      const msg = await client.fetchOne(
        String(uid),
        { uid: true, envelope: true, flags: true, size: true, source: true, bodyStructure: true },
        { uid: true }
      );
      if (!msg || !msg.source) {
        throw new MailboxError(`No message with UID ${uid} in "${folder}"`);
      }
      const parsed = await simpleParser(msg.source);
      const text = parsed.text ?? this.stripHtml(parsed.html || '') ?? '';
      const truncated = text.length > this.cfg.MAX_BODY_CHARS;

      return {
        ...this.toSummary(folder, msg),
        cc: addressText(msg.envelope?.cc),
        replyTo: addressText(msg.envelope?.replyTo),
        inReplyTo: msg.envelope?.inReplyTo ?? undefined,
        references: this.normalizeReferences(parsed.references),
        body: truncated ? `${text.slice(0, this.cfg.MAX_BODY_CHARS)}\n\n[truncated]` : text,
        bodyTruncated: truncated,
        attachments: (parsed.attachments ?? []).map((a) => ({
          filename: a.filename,
          contentType: a.contentType,
          sizeBytes: a.size
        }))
      };
    });
  }

  /**
   * Collects the conversation around a message using Message-ID/References,
   * which is what mail clients thread on. Subject matching is deliberately not
   * used: it produces false joins on things like "Re: invoice".
   */
  async getThread(folder0: string, uid: number): Promise<MessageSummary[]> {
    const folder = this.assertAllowed(folder0);
    const seed = await this.getMessage(folder, uid);
    const root = seed.references[0] ?? seed.messageId;
    if (!root) return [seed];

    return this.conn.withFolder(folder, true, async (client) => {
      const uids = new Set<number>([uid]);
      const queries: Array<{ header: Record<string, string> }> = [
        { header: { 'message-id': root } },
        { header: { references: root } }
      ];
      for (const q of queries) {
        const found = (await client.search(q, { uid: true })) || [];
        for (const u of found) uids.add(u);
      }

      const wanted = [...uids].sort((a, b) => a - b).slice(0, this.cfg.MAX_SEARCH_RESULTS);
      const out: MessageSummary[] = [];
      for await (const msg of client.fetch(
        wanted,
        { uid: true, envelope: true, flags: true, size: true, bodyStructure: true },
        { uid: true }
      )) {
        out.push(this.toSummary(folder, msg));
      }
      out.sort((a, b) => (a.date ?? '').localeCompare(b.date ?? ''));
      return out;
    });
  }

  /**
   * Appends a message to the Drafts folder with the \Draft flag. There is no
   * SMTP client anywhere in this process, so this cannot send.
   */
  async createDraft(params: {
    to: string[];
    cc?: string[];
    subject: string;
    body: string;
    inReplyToUid?: number;
    inReplyToFolder?: string;
  }): Promise<{ folder: string; uid: number | undefined; subject: string }> {
    const drafts = this.assertAllowed(this.cfg.IMAP_DRAFTS_FOLDER);

    let inReplyTo: string | undefined;
    let references: string | undefined;
    if (params.inReplyToUid !== undefined) {
      const src = await this.getMessage(
        params.inReplyToFolder ?? 'INBOX',
        params.inReplyToUid
      );
      inReplyTo = src.messageId;
      references = [...src.references, src.messageId].filter(Boolean).join(' ');
    }

    const composer = new MailComposer({
      from: this.cfg.IMAP_USER,
      to: params.to,
      ...(params.cc?.length ? { cc: params.cc } : {}),
      subject: params.subject,
      text: params.body,
      ...(inReplyTo ? { inReplyTo } : {}),
      ...(references ? { references } : {})
    });

    const raw: Buffer = await new Promise((resolve, reject) => {
      composer.compile().build((err: Error | null, message: Buffer) => {
        if (err) reject(err);
        else resolve(message);
      });
    });

    const res = await this.conn.withClient(async (client) => {
      try {
        return await client.append(drafts, raw, ['\\Draft'], new Date());
      } catch (err) {
        // RFC 3501: a TRYCREATE response code means "that mailbox does not
        // exist, create it and retry". Mailcow ships a Drafts folder, but a
        // renamed or localised one would otherwise fail here for good.
        if (!this.isTryCreate(err)) throw err;
        await client.mailboxCreate(drafts);
        return client.append(drafts, raw, ['\\Draft'], new Date());
      }
    });
    if (res === false) {
      throw new MailboxError(`The server rejected the APPEND to "${drafts}"`);
    }

    return { folder: drafts, uid: res?.uid, subject: params.subject };
  }

  // --- helpers -------------------------------------------------------------

  private toSummary(folder: string, msg: any): MessageSummary {
    const flags: Set<string> = msg.flags ?? new Set();
    return {
      uid: msg.uid,
      folder,
      messageId: msg.envelope?.messageId ?? undefined,
      date: msg.envelope?.date ? new Date(msg.envelope.date).toISOString() : undefined,
      from: addressText(msg.envelope?.from),
      to: addressText(msg.envelope?.to),
      subject: msg.envelope?.subject ?? undefined,
      unseen: !flags.has('\\Seen'),
      answered: flags.has('\\Answered'),
      flagged: flags.has('\\Flagged'),
      hasAttachments: this.detectAttachments(msg.bodyStructure),
      sizeBytes: typeof msg.size === 'number' ? msg.size : undefined
    };
  }

  private isTryCreate(err: unknown): boolean {
    const e = err as { serverResponseCode?: string; responseText?: string } | undefined;
    const text = `${e?.serverResponseCode ?? ''} ${e?.responseText ?? ''} ${
      err instanceof Error ? err.message : ''
    }`;
    return /TRYCREATE|NONEXISTENT/i.test(text);
  }

  private detectAttachments(node: any): boolean {
    if (!node) return false;
    if (node.disposition === 'attachment') return true;
    if (Array.isArray(node.childNodes)) {
      return node.childNodes.some((c: unknown) => this.detectAttachments(c));
    }
    return false;
  }

  private normalizeReferences(refs: string | string[] | undefined): string[] {
    if (!refs) return [];
    return Array.isArray(refs) ? refs : [refs];
  }

  private stripHtml(html: string): string {
    return html
      .replace(/<style[\s\S]*?<\/style>/gi, '')
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/p>/gi, '\n\n')
      .replace(/<[^>]+>/g, '')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  }

  private parseDate(value: string, field: string): Date {
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) {
      throw new MailboxError(`Invalid date for "${field}": ${value}`);
    }
    return d;
  }
}
