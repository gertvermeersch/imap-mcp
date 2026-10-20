import type { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';
import type { Config, MailboxConfig } from '../config.js';
import type { ImapConnection } from './client.js';

export interface MessageSummary {
  mailbox: string;
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

/** A text part chosen out of BODYSTRUCTURE, addressed by its IMAP part number. */
interface TextPart {
  part: string;
  type: string;
}

/** A rendered message body, however it was obtained. */
interface RenderedBody {
  text: string;
  truncated: boolean;
  /** Set only by the full-parse fallback, which already holds them. */
  attachments?: MessageDetail['attachments'];
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
    readonly box: MailboxConfig,
    private readonly conn: ImapConnection
  ) {}

  get id(): string {
    return this.box.id;
  }

  /** Throws unless the folder is inside this mailbox's allowlist. */
  private assertAllowed(folder: string): string {
    const allowed = this.box.allowedFolders;
    if (allowed.length > 0 && !allowed.includes(folder)) {
      throw new MailboxError(
        `Folder "${folder}" is not in the allowlist for mailbox "${this.box.id}" (${allowed.join(', ')})`
      );
    }
    return folder;
  }

  async listFolders(): Promise<Array<{ path: string; name: string; specialUse?: string }>> {
    const list = await this.conn.withClient((c) => c.list());
    const allowed = this.box.allowedFolders;
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

  /**
   * Fetches one message without pulling its attachments over the wire: the
   * envelope, structure and threading headers first, then only the text part
   * the structure points at. A 25 MB message with a 3 kB body costs 3 kB.
   */
  async getMessage(folder0: string, uid: number): Promise<MessageDetail> {
    const folder = this.assertAllowed(folder0);
    return this.conn.withFolder(folder, true, async (client) => {
      const msg = await client.fetchOne(
        String(uid),
        {
          uid: true,
          envelope: true,
          flags: true,
          size: true,
          bodyStructure: true,
          // References is what getThread walks, and the envelope omits it.
          headers: ['references', 'in-reply-to']
        },
        { uid: true }
      );
      if (!msg) {
        throw new MailboxError(`No message with UID ${uid} in "${folder}"`);
      }

      const textPart = this.pickTextPart(msg.bodyStructure);
      const rendered = textPart
        ? await this.downloadTextPart(client, uid, textPart)
        : await this.parseWholeMessage(client, uid, folder);

      const overCap = rendered.text.length > this.cfg.MAX_BODY_CHARS;
      const bodyTruncated = overCap || rendered.truncated;
      const text = overCap ? rendered.text.slice(0, this.cfg.MAX_BODY_CHARS) : rendered.text;

      return {
        ...this.toSummary(folder, msg),
        cc: addressText(msg.envelope?.cc),
        replyTo: addressText(msg.envelope?.replyTo),
        inReplyTo: msg.envelope?.inReplyTo ?? undefined,
        references: this.parseReferences(msg.headers),
        body: bodyTruncated ? `${text}\n\n[truncated]` : text,
        bodyTruncated,
        attachments: rendered.attachments ?? this.collectAttachments(msg.bodyStructure)
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
   * Appends a message to the Drafts folder with the \Draft flag. Nothing here
   * sends; a draft only leaves the mailbox through send_draft, for mailboxes
   * granted that separately.
   */
  async createDraft(params: {
    to: string[];
    cc?: string[];
    subject: string;
    body: string;
    inReplyToUid?: number;
    inReplyToFolder?: string;
  }): Promise<{ folder: string; uid: number | undefined; subject: string }> {
    const drafts = this.assertAllowed(this.box.draftsFolder);

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
      from: this.fromHeader(),
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

    const uid = await this.appendCreating(drafts, raw, ['\\Draft']);
    return { folder: drafts, uid, subject: params.subject };
  }

  // --- the IMAP half of send_draft ------------------------------------------

  /**
   * Reads a draft's full source out of the Drafts folder, read-only. Anything
   * already flagged \Deleted has been sent (or thrown away) and is refused, so
   * a retried call cannot send the same draft twice.
   */
  async loadDraft(uid: number): Promise<{ folder: string; source: Buffer }> {
    const folder = this.assertAllowed(this.box.draftsFolder);
    return this.conn.withFolder(folder, true, async (client) => {
      const msg = await client.fetchOne(String(uid), { uid: true, flags: true, source: true }, { uid: true });
      if (!msg || !msg.source) {
        throw new MailboxError(`No draft with UID ${uid} in "${folder}" of mailbox "${this.box.id}"`);
      }
      if (msg.flags?.has('\\Deleted')) {
        throw new MailboxError(`Draft ${uid} in "${folder}" is marked deleted: it was already sent or discarded`);
      }
      return { folder, source: msg.source };
    });
  }

  /**
   * Every address on the messages with the given Message-IDs, searched across
   * the allowed folders. This is the evidence the reply-only policy checks
   * recipients against, so it skips anything the agent could have written
   * itself: the Drafts folder, any message still flagged \Draft (a draft moved
   * elsewhere keeps the flag), and Junk/Trash, where a spammer's message must not
   * count as a conversation.
   */
  async threadParticipants(messageIds: string[]): Promise<{ messages: number; addresses: Set<string> }> {
    const addresses = new Set<string>();
    let messages = 0;
    if (messageIds.length === 0) return { messages, addresses };

    const folders = (await this.listFolders()).filter(
      (f) =>
        f.path !== this.box.draftsFolder &&
        !['\\Drafts', '\\Junk', '\\Trash'].includes(f.specialUse ?? '')
    );
    const ids = messageIds.slice(0, 20);
    const query =
      ids.length === 1
        ? { header: { 'message-id': ids[0]! } }
        : { or: ids.map((id) => ({ header: { 'message-id': id } })) };

    for (const f of folders) {
      await this.conn.withFolder(f.path, true, async (client) => {
        const uids = (await client.search(query, { uid: true })) || [];
        if (uids.length === 0) return;
        for await (const msg of client.fetch(uids, { uid: true, flags: true, envelope: true }, { uid: true })) {
          if (msg.flags?.has('\\Draft')) continue;
          messages++;
          const env = msg.envelope;
          for (const list of [env?.from, env?.sender, env?.replyTo, env?.to, env?.cc]) {
            for (const a of list ?? []) {
              if (a.address) addresses.add(a.address.toLowerCase());
            }
          }
        }
      });
    }
    return { messages, addresses };
  }

  /** Files a sent message in the Sent folder, already marked read. */
  async fileSent(raw: Buffer): Promise<{ folder: string; uid: number | undefined }> {
    const folder = this.assertAllowed(this.box.sentFolder);
    return { folder, uid: await this.appendCreating(folder, raw, ['\\Seen']) };
  }

  /**
   * Takes a just-sent draft out of Drafts: the one place this server removes
   * a message, and only after its copy is in Sent. UID EXPUNGE touches nothing
   * but that UID; without UIDPLUS a plain EXPUNGE would also purge anything a
   * human had flagged \Deleted, so then the draft is only flagged, which is
   * still enough for loadDraft to refuse it.
   */
  async retireDraft(uid: number): Promise<'removed' | 'flagged'> {
    const folder = this.assertAllowed(this.box.draftsFolder);
    return this.conn.withFolder(folder, false, async (client) => {
      if (client.capabilities.has('UIDPLUS')) {
        if (await client.messageDelete(String(uid), { uid: true })) return 'removed';
      }
      await client.messageFlagsAdd(String(uid), ['\\Deleted'], { uid: true });
      return 'flagged';
    });
  }

  /**
   * Sets or clears \Seen and \Flagged on a batch of messages. Takes the folder
   * lock read-write — the only place besides move that does — and reports the
   * resulting state so the caller sees what the server actually holds.
   */
  async markMessages(params: {
    folder: string;
    uids: number[];
    seen?: boolean;
    flagged?: boolean;
  }): Promise<{ folder: string; updated: Array<{ uid: number; unseen: boolean; flagged: boolean }>; notFound: number[] }> {
    if (params.seen === undefined && params.flagged === undefined) {
      throw new MailboxError('Nothing to change: pass seen and/or flagged.');
    }
    const folder = this.assertAllowed(params.folder);
    const uids = this.checkUidBatch(params.uids);

    return this.conn.withFolder(folder, false, async (client) => {
      const { found, notFound } = await this.partitionExisting(client, uids);
      if (found.length === 0) return { folder, updated: [], notFound };

      const add: string[] = [];
      const remove: string[] = [];
      for (const [value, flag] of [
        [params.seen, '\\Seen'],
        [params.flagged, '\\Flagged']
      ] as const) {
        if (value === true) add.push(flag);
        else if (value === false) remove.push(flag);
      }
      if (add.length > 0 && !(await client.messageFlagsAdd(found, add, { uid: true }))) {
        throw new MailboxError(`The server rejected adding ${add.join(' ')} in "${folder}"`);
      }
      if (remove.length > 0 && !(await client.messageFlagsRemove(found, remove, { uid: true }))) {
        throw new MailboxError(`The server rejected removing ${remove.join(' ')} in "${folder}"`);
      }

      const updated: Array<{ uid: number; unseen: boolean; flagged: boolean }> = [];
      for await (const msg of client.fetch(found, { uid: true, flags: true }, { uid: true })) {
        const flags: Set<string> = msg.flags ?? new Set();
        updated.push({ uid: msg.uid, unseen: !flags.has('\\Seen'), flagged: flags.has('\\Flagged') });
      }
      updated.sort((a, b) => a.uid - b.uid);
      return { folder, updated, notFound };
    });
  }

  /**
   * Moves messages to another folder. Both ends must be inside the allowlist,
   * and the destination must already exist — unlike drafting, a typo here
   * should fail rather than quietly mint a folder.
   */
  async moveMessages(params: {
    folder: string;
    uids: number[];
    destination: string;
  }): Promise<{
    from: string;
    to: string;
    moved: Array<{ uid: number; newUid: number | undefined }>;
    notFound: number[];
  }> {
    const from = this.assertAllowed(params.folder);
    const to = this.assertAllowed(params.destination);
    if (from === to) {
      throw new MailboxError(`Messages are already in "${from}"`);
    }
    const uids = this.checkUidBatch(params.uids);

    return this.conn.withFolder(from, false, async (client) => {
      const { found, notFound } = await this.partitionExisting(client, uids);
      if (found.length === 0) return { from, to, moved: [], notFound };

      let res;
      try {
        res = await client.messageMove(found, to, { uid: true });
      } catch (err) {
        if (this.isTryCreate(err)) {
          throw new MailboxError(`Destination folder "${to}" does not exist`);
        }
        throw err;
      }
      if (res === false) {
        throw new MailboxError(`The server rejected the move from "${from}" to "${to}"`);
      }

      // uidMap needs UIDPLUS; without it the move still happened, we just
      // cannot say what the new UIDs are.
      const moved = found.map((uid) => ({ uid, newUid: res.uidMap?.get(uid) }));
      return { from, to, moved, notFound };
    });
  }

  // --- helpers -------------------------------------------------------------

  /** The From header this mailbox writes: its address, with the display name if one is set. */
  fromHeader(): string | { name: string; address: string } {
    return this.box.name ? { name: this.box.name, address: this.box.address } : this.box.address;
  }

  /** APPENDs a message, creating the folder first if the server says it is missing. */
  private async appendCreating(folder: string, raw: Buffer, flags: string[]): Promise<number | undefined> {
    const res = await this.conn.withClient(async (client) => {
      try {
        return await client.append(folder, raw, flags, new Date());
      } catch (err) {
        // RFC 3501: a TRYCREATE response code means "that mailbox does not
        // exist, create it and retry". Mailcow ships Drafts and Sent, but a
        // renamed or localised one would otherwise fail here for good.
        if (!this.isTryCreate(err)) throw err;
        await client.mailboxCreate(folder);
        return client.append(folder, raw, flags, new Date());
      }
    });
    if (res === false) {
      throw new MailboxError(`The server rejected the APPEND to "${folder}"`);
    }
    return res?.uid;
  }

  /** De-duplicates and bounds a caller-supplied UID list. */
  private checkUidBatch(uids: number[]): number[] {
    const unique = [...new Set(uids)];
    if (unique.length === 0) throw new MailboxError('No UIDs given.');
    if (unique.length > this.cfg.MAX_SEARCH_RESULTS) {
      throw new MailboxError(
        `Too many messages in one call (${unique.length}); the limit is ${this.cfg.MAX_SEARCH_RESULTS}.`
      );
    }
    return unique;
  }

  /** Splits UIDs into those present in the open folder and those that are not. */
  private async partitionExisting(
    client: ImapFlow,
    uids: number[]
  ): Promise<{ found: number[]; notFound: number[] }> {
    const present = new Set<number>();
    for await (const msg of client.fetch(uids, { uid: true }, { uid: true })) {
      present.add(msg.uid);
    }
    return {
      found: uids.filter((u) => present.has(u)),
      notFound: uids.filter((u) => !present.has(u))
    };
  }

  private toSummary(folder: string, msg: any): MessageSummary {
    const flags: Set<string> = msg.flags ?? new Set();
    return {
      mailbox: this.box.id,
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

  /**
   * Picks the part to render: the first inline text/plain, else the first
   * inline text/html. Parts marked as attachments are skipped — a .txt
   * attachment is not the body — and embedded messages are left alone so an
   * attached .eml cannot masquerade as the text of the mail carrying it.
   */
  private pickTextPart(node: any): TextPart | undefined {
    const candidates: TextPart[] = [];

    const walk = (n: any): void => {
      if (!n) return;
      const type = String(n.type ?? '').toLowerCase();
      if (n.disposition === 'attachment') return;
      if (type.startsWith('message/')) return;
      if (Array.isArray(n.childNodes) && n.childNodes.length > 0) {
        for (const child of n.childNodes) walk(child);
        return;
      }
      if (type === 'text/plain' || type === 'text/html') {
        // A non-multipart message carries no part number on its root node;
        // RFC 3501 addresses that body as part 1.
        candidates.push({ part: n.part ?? '1', type });
      }
    };

    walk(node);
    return candidates.find((c) => c.type === 'text/plain') ?? candidates[0];
  }

  /**
   * Streams a single body part. imapflow's maxBytes bounds the decoded output
   * and stops the fetch loop once it is reached, so the cap is honoured on the
   * wire rather than after the fact. Transfer encoding and non-UTF-8 charsets
   * are decoded on the way through. The enclosing lock is read-only, so this
   * still does not set \Seen.
   */
  private async downloadTextPart(
    client: ImapFlow,
    uid: number,
    part: TextPart
  ): Promise<RenderedBody> {
    // Four bytes per character is the UTF-8 worst case, so nothing inside the
    // character cap can be lost to the byte cap.
    const maxBytes = this.cfg.MAX_BODY_CHARS * 4;
    const { content } = await client.download(String(uid), part.part, { uid: true, maxBytes });

    const chunks: Buffer[] = [];
    let bytes = 0;
    for await (const chunk of content) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
      chunks.push(buf);
      bytes += buf.length;
    }

    const raw = Buffer.concat(chunks).toString('utf8');
    return {
      text: part.type === 'text/html' ? this.stripHtml(raw) : raw,
      truncated: bytes >= maxBytes
    };
  }

  /**
   * Fallback for messages whose structure offers no text part to download:
   * malformed MIME, or a body described in a way the walk above does not
   * recognise. Costs a full download, which is what this class otherwise
   * avoids, but mailparser is far more forgiving than a hand walk.
   */
  private async parseWholeMessage(
    client: ImapFlow,
    uid: number,
    folder: string
  ): Promise<RenderedBody> {
    const msg = await client.fetchOne(String(uid), { uid: true, source: true }, { uid: true });
    if (!msg || !msg.source) {
      throw new MailboxError(`No message with UID ${uid} in "${folder}"`);
    }
    const parsed = await simpleParser(msg.source);
    return {
      text: parsed.text ?? this.stripHtml(parsed.html || '') ?? '',
      truncated: false,
      attachments: (parsed.attachments ?? []).map((a) => ({
        filename: a.filename,
        contentType: a.contentType,
        sizeBytes: a.size
      }))
    };
  }

  /** Attachment metadata read off the structure — no attachment bytes fetched. */
  private collectAttachments(
    node: any,
    out: MessageDetail['attachments'] = []
  ): MessageDetail['attachments'] {
    if (!node) return out;
    if (node.disposition === 'attachment') {
      const size = typeof node.size === 'number' ? node.size : 0;
      const encoding = String(node.encoding ?? '').toLowerCase();
      out.push({
        filename: node.dispositionParameters?.filename ?? node.parameters?.name,
        contentType: String(node.type ?? 'application/octet-stream'),
        // BODYSTRUCTURE reports encoded octets. base64 inflates by 4/3, and the
        // decoded size is the one a human recognises as the file size.
        sizeBytes: encoding === 'base64' ? Math.floor((size * 3) / 4) : size
      });
    }
    for (const child of node.childNodes ?? []) this.collectAttachments(child, out);
    return out;
  }

  /**
   * Reads References out of a raw header block, unfolding continuation lines.
   * Produces the same angle-bracketed ids mailparser did, which is the form
   * getThread searches on and createDraft writes back into a References header.
   */
  private parseReferences(headers: Buffer | undefined): string[] {
    if (!headers) return [];
    const line = headers
      .toString('utf8')
      .replace(/\r?\n[ \t]+/g, ' ')
      .split(/\r?\n/)
      .find((l) => /^references:/i.test(l));
    if (!line) return [];
    return line
      .slice(line.indexOf(':') + 1)
      .split(/\s+/)
      .map((id) => id.trim())
      .filter(Boolean)
      .map((id) => (id.startsWith('<') ? id : `<${id}`))
      .map((id) => (id.endsWith('>') ? id : `${id}>`));
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
