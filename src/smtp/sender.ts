import { randomBytes } from 'node:crypto';
import nodemailer, { type Transporter } from 'nodemailer';
import { simpleParser, type AddressObject } from 'mailparser';
import type { RecipientPolicy } from '../config.js';
import { MailboxError, type Mailbox } from '../imap/mailbox.js';
import type { SendLog } from './send-log.js';

const DAY_MS = 24 * 60 * 60 * 1000;

export interface SendResult {
  mailbox: string;
  messageId: string;
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  accepted: string[];
  rejected: string[];
  sentFolder: string | undefined;
  sentUid: number | undefined;
  /** What happened to the draft: removed from Drafts, or only flagged \Deleted. */
  draft: 'removed' | 'flagged' | 'left in place';
  warnings?: string[];
}

/** Flattens a parsed To/Cc/Bcc header, groups included, into bare lowercase addresses. */
function addresses(field: AddressObject | AddressObject[] | undefined): string[] {
  const out: string[] = [];
  const walk = (entries: Array<{ address?: string; group?: unknown[] }>) => {
    for (const e of entries) {
      if (e.address) out.push(e.address.toLowerCase());
      if (Array.isArray(e.group)) walk(e.group as typeof entries);
    }
  };
  for (const obj of Array.isArray(field) ? field : field ? [field] : []) walk(obj.value);
  return out;
}

/** RFC 5322 date, with a numeric zone rather than the obsolete "GMT". */
function rfc5322Date(d: Date): string {
  return d.toUTCString().replace(/GMT$/, '+0000');
}

/**
 * Drops the named header fields (with their folded continuation lines) and
 * prepends replacements, leaving the body and every other header byte for byte
 * as the draft had them.
 */
function rewriteHeaders(raw: Buffer, drop: string[], add: Record<string, string>): Buffer {
  const text = raw.toString('binary');
  const split = /\r?\n\r?\n/.exec(text);
  if (!split) throw new MailboxError('The draft has no header/body separator and cannot be sent');
  const eol = split[0].startsWith('\r\n') ? '\r\n' : '\n';
  const head = text.slice(0, split.index);
  const rest = text.slice(split.index);

  const dropped = new Set(drop.map((h) => h.toLowerCase()));
  const kept: string[] = [];
  let skipping = false;
  for (const line of head.split(/\r?\n/)) {
    if (/^[ \t]/.test(line)) {
      if (!skipping) kept.push(line);
      continue;
    }
    const name = line.slice(0, line.indexOf(':')).trim().toLowerCase();
    skipping = dropped.has(name);
    if (!skipping) kept.push(line);
  }
  const added = Object.entries(add).map(([k, v]) => `${k}: ${v}`);
  return Buffer.from([...added, ...kept].join(eol) + rest, 'binary');
}

function matchesAllowlist(address: string, list: string[]): boolean {
  const domain = address.slice(address.lastIndexOf('@') + 1);
  return list.some((entry) => {
    const e = entry.toLowerCase().replace(/^\*@/, '@');
    return e.startsWith('@') ? domain === e.slice(1) : address === e;
  });
}

/**
 * Sends a message that already sits in a mailbox's Drafts folder — the only way
 * this server sends anything. The draft is sent exactly as stored (so a human
 * can edit it in between), after the checks in sendDraft, over SMTP submission
 * with that mailbox's own credentials.
 */
export class DraftSender {
  private readonly transports = new Map<string, Transporter>();
  /** Per-mailbox chain, so concurrent calls cannot both slip under the daily cap. */
  private readonly queues = new Map<string, Promise<unknown>>();

  constructor(private readonly log: SendLog) {}

  sendDraft(mailbox: Mailbox, uid: number): Promise<SendResult> {
    const prev = this.queues.get(mailbox.id) ?? Promise.resolve();
    const run = prev.catch(() => undefined).then(() => this.send(mailbox, uid));
    this.queues.set(mailbox.id, run);
    return run;
  }

  private async send(mailbox: Mailbox, uid: number): Promise<SendResult> {
    const box = mailbox.box;
    const policy = box.send;
    if (!policy) throw new MailboxError(`Mailbox "${box.id}" is not configured to send`);

    const sentToday = this.log.countSince(box.id, DAY_MS);
    if (sentToday >= policy.maxPerDay) {
      throw new MailboxError(
        `Mailbox "${box.id}" has sent ${sentToday} messages in the last 24 hours, its limit is ${policy.maxPerDay}. Nothing was sent.`
      );
    }

    const { source } = await mailbox.loadDraft(uid);
    const parsed = await simpleParser(source, { skipHtmlToText: true, skipTextToHtml: true, skipImageLinks: true });

    // The From must be this mailbox. Mailcow's sender ACL would refuse a
    // foreign address anyway, but a clear refusal here beats an SMTP error.
    const from = addresses(parsed.from);
    const self = box.address.toLowerCase();
    if (from.length !== 1 || from[0] !== self) {
      throw new MailboxError(
        `The draft's From (${from.join(', ') || 'missing'}) is not ${box.address}, the only address mailbox "${box.id}" may send as`
      );
    }

    const to = addresses(parsed.to);
    const cc = addresses(parsed.cc);
    const bcc = addresses(parsed.bcc);
    const recipients = [...new Set([...to, ...cc, ...bcc])];
    if (recipients.length === 0) throw new MailboxError('The draft has no recipients');
    if (recipients.length > policy.maxRecipients) {
      throw new MailboxError(
        `The draft has ${recipients.length} recipients; mailbox "${box.id}" allows at most ${policy.maxRecipients}`
      );
    }

    const messageId = parsed.messageId ?? `<${randomBytes(12).toString('hex')}@${self.split('@')[1]}>`;
    if (parsed.messageId && this.log.wasSent(box.id, messageId)) {
      throw new MailboxError(`A message with Message-ID ${messageId} was already sent from "${box.id}"`);
    }

    await this.checkRecipients(mailbox, policy.recipients, recipients, parsed);

    // The Date is the moment of sending, not of drafting.
    const now = new Date();
    const add: Record<string, string> = { Date: rfc5322Date(now) };
    const drop = ['date'];
    if (!parsed.messageId) {
      add['Message-ID'] = messageId;
      drop.push('message-id');
    }
    // What recipients get has no Bcc header; the copy filed in Sent keeps it,
    // like any mail client.
    const outgoing = rewriteHeaders(source, [...drop, 'bcc'], add);
    const sentCopy = rewriteHeaders(source, drop, add);

    const info = await this.transport(mailbox).sendMail({
      envelope: { from: box.address, to: recipients },
      raw: outgoing
    });
    const subject = parsed.subject ?? '';
    await this.log.record({ mailbox: box.id, at: now.getTime(), messageId, recipients, subject });
    console.log(
      `[send] mailbox=${box.id} draft=${uid} message-id=${messageId} to=${recipients.join(',')} subject=${JSON.stringify(subject)}`
    );

    // The message is out. Nothing below may throw, or a retry would look like
    // a failed send; problems are reported back as warnings instead.
    const warnings: string[] = [];
    let sentFolder: string | undefined;
    let sentUid: number | undefined;
    try {
      ({ folder: sentFolder, uid: sentUid } = await mailbox.fileSent(sentCopy));
    } catch (err) {
      warnings.push(`Sent, but filing a copy in "${box.sentFolder}" failed: ${(err as Error).message}`);
    }
    let draft: SendResult['draft'] = 'left in place';
    try {
      draft = await mailbox.retireDraft(uid);
    } catch (err) {
      warnings.push(`Sent, but the draft could not be taken out of Drafts: ${(err as Error).message}`);
    }

    const str = (a: unknown) => (typeof a === 'string' ? a : ((a as { address?: string })?.address ?? ''));
    return {
      mailbox: box.id,
      messageId,
      from: box.address,
      to,
      cc,
      bcc,
      subject,
      accepted: (info.accepted ?? []).map(str),
      rejected: (info.rejected ?? []).map(str),
      sentFolder,
      sentUid,
      draft,
      ...(warnings.length > 0 ? { warnings } : {})
    };
  }

  private async checkRecipients(
    mailbox: Mailbox,
    policy: RecipientPolicy,
    recipients: string[],
    parsed: { inReplyTo?: string; references?: string | string[] }
  ): Promise<void> {
    if (policy === 'any') return;

    if (Array.isArray(policy)) {
      const refused = recipients.filter((r) => !matchesAllowlist(r, policy));
      if (refused.length > 0) {
        throw new MailboxError(
          `Mailbox "${mailbox.id}" may only send to ${policy.join(', ')}; refused: ${refused.join(', ')}. Nothing was sent.`
        );
      }
      return;
    }

    // reply-only: the draft must answer a real message in this mailbox, and
    // every recipient must already be part of that conversation.
    const refs = [
      ...(parsed.inReplyTo ? [parsed.inReplyTo] : []),
      ...(Array.isArray(parsed.references) ? parsed.references : parsed.references ? [parsed.references] : [])
    ];
    const ids = [...new Set(refs.flatMap((r) => r.match(/<[^>]+>/g) ?? []))];
    if (ids.length === 0) {
      throw new MailboxError(
        `Mailbox "${mailbox.id}" may only send replies, and this draft does not reply to anything (no In-Reply-To or References). Create it with in_reply_to_uid.`
      );
    }
    const thread = await mailbox.threadParticipants(ids);
    if (thread.messages === 0) {
      throw new MailboxError(
        `Mailbox "${mailbox.id}" may only send replies, and the message this draft replies to was not found in its folders. Nothing was sent.`
      );
    }
    thread.addresses.add(mailbox.box.address.toLowerCase());
    const strangers = recipients.filter((r) => !thread.addresses.has(r));
    if (strangers.length > 0) {
      throw new MailboxError(
        `Mailbox "${mailbox.id}" may only reply to people already in the conversation; not in it: ${strangers.join(', ')}. Nothing was sent.`
      );
    }
  }

  private transport(mailbox: Mailbox): Transporter {
    let t = this.transports.get(mailbox.id);
    if (!t) {
      const smtp = mailbox.box.send!.smtp;
      t = nodemailer.createTransport({
        host: smtp.host,
        port: smtp.port,
        secure: smtp.secure,
        // Submission with the same app password the mailbox reads with; on
        // Mailcow that password needs SMTP enabled as well as IMAP.
        auth: { user: mailbox.box.imap.user, pass: mailbox.box.imap.password },
        tls: { rejectUnauthorized: smtp.tlsRejectUnauthorized }
      });
      this.transports.set(mailbox.id, t);
    }
    return t;
  }
}
