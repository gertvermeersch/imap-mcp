import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { Capability, Config } from '../config.js';
import { Mailbox, MailboxError } from '../imap/mailbox.js';
import { scopeFor } from '../auth/scopes.js';
import type { DraftSender } from '../smtp/sender.js';

function ok(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

function fail(err: unknown) {
  const message =
    err instanceof MailboxError
      ? err.message
      : err instanceof Error
        ? `Mailbox operation failed: ${err.message}`
        : 'Mailbox operation failed';
  return { content: [{ type: 'text' as const, text: message }], isError: true };
}

type Extra = { authInfo?: { scopes: string[] } };

const ACTIONS: Record<Capability, string> = {
  read: 'read',
  draft: 'save drafts',
  mark: 'change read or flag state',
  move: 'move messages',
  send: 'send mail'
};

export function buildMcpServer(
  cfg: Config,
  mailboxes: Map<string, Mailbox>,
  sender: DraftSender
): McpServer {
  const single = cfg.mailboxes.length === 1;
  const withCapability = (cap: Capability) =>
    cfg.mailboxes.filter((m) => m.capabilities.includes(cap)).map((m) => m.id);
  const anySend = withCapability('send').length > 0;

  /**
   * The mailbox argument. With one mailbox it may be left out; with several it
   * is required, so a UID from one mailbox can never be applied to another by
   * default. The enum lists only mailboxes this deployment gives `cap`.
   */
  const mailboxArg = (cap: Capability) => {
    const ids = withCapability(cap) as [string, ...string[]];
    const arg = z
      .enum(ids)
      .describe(single ? `Mailbox id (only "${ids[0]}").` : 'Mailbox id, from list_mailboxes.');
    return single ? arg.optional() : arg;
  };

  /**
   * The bearer middleware only requires read on some mailbox for the endpoint
   * as a whole, so every grant is checked here, where it is spent: read on the
   * named mailbox, and for a write also that write on the same mailbox. Returns
   * the mailbox, or a tool error when the token lacks a scope.
   */
  const open = (
    extra: Extra,
    id: string | undefined,
    cap: Capability
  ): { mailbox: Mailbox } | { denied: ReturnType<typeof fail> } => {
    const mailboxId = id ?? cfg.mailboxes[0]!.id;
    const mailbox = mailboxes.get(mailboxId);
    if (!mailbox) return { denied: fail(new MailboxError(`Unknown mailbox "${mailboxId}"`)) };
    for (const c of new Set<Capability>(['read', cap])) {
      const scope = scopeFor(c, mailboxId);
      if (!extra.authInfo?.scopes.includes(scope)) {
        return {
          denied: fail(
            new MailboxError(
              `This connection was not granted the ${scope} scope, so it cannot ${ACTIONS[c]} in mailbox "${mailboxId}". Re-authorize the connector to grant it.`
            )
          )
        };
      }
    }
    return { mailbox };
  };

  const described = cfg.mailboxes
    .map((m) => `${m.id} (${m.address}): ${m.capabilities.join(', ')}`)
    .join('; ');
  const server = new McpServer(
    { name: 'imap-mcp', version: '0.2.0' },
    {
      instructions: [
        single
          ? `Access to the IMAP mailbox ${described}.`
          : `Access to these IMAP mailboxes: ${described}. Every tool takes a mailbox id; list_mailboxes shows what this connection was actually granted.`,
        anySend
          ? 'Mail is only ever sent by send_draft, which sends a message already saved in that mailbox\'s Drafts folder: write it with create_draft, show it to the user, and send it only when they asked for it to be sent. Nothing is ever deleted, except a draft once it has been sent.'
          : 'This server cannot send or delete mail.',
        'Reading a message does',
        'not mark it as seen. Use search_messages to find candidates, then',
        'get_message for full text, and get_thread when the conversation matters.'
      ].join(' ')
    }
  );

  server.registerTool(
    'list_mailboxes',
    {
      title: 'List mailboxes',
      description:
        'List the mailboxes this server holds, with what this connection may do in each (read, draft, mark, move, send) and, where sending is granted, the recipient policy and daily limit.',
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false }
    },
    async (_args, extra) => {
      const granted = extra.authInfo?.scopes ?? [];
      return ok(
        cfg.mailboxes.map((m) => {
          const access = m.capabilities.filter((c) => granted.includes(scopeFor(c, m.id)));
          return {
            id: m.id,
            address: m.address,
            ...(m.name ? { name: m.name } : {}),
            access,
            notGranted: m.capabilities.filter((c) => !access.includes(c)),
            ...(m.send && access.includes('send')
              ? { send: { recipients: m.send.recipients, maxPerDay: m.send.maxPerDay, maxRecipients: m.send.maxRecipients } }
              : {})
          };
        })
      );
    }
  );

  server.registerTool(
    'list_folders',
    {
      title: 'List mail folders',
      description:
        'List the IMAP folders this server is allowed to read, with their special-use role (Inbox, Sent, Drafts, Archive, Junk) where the server reports one.',
      inputSchema: { mailbox: mailboxArg('read') },
      annotations: { readOnlyHint: true, openWorldHint: false }
    },
    async (args, extra) => {
      const o = open(extra, args.mailbox, 'read');
      if ('denied' in o) return o.denied;
      try {
        return ok(await o.mailbox.listFolders());
      } catch (err) {
        return fail(err);
      }
    }
  );

  server.registerTool(
    'search_messages',
    {
      title: 'Search messages',
      description:
        'Search a folder and return message summaries (uid, date, from, to, subject, flags, attachment presence) newest first. Combine filters to narrow; all filters are ANDed. Returns summaries only — use get_message for body text.',
      inputSchema: {
        mailbox: mailboxArg('read'),
        folder: z.string().default('INBOX').describe('Folder path, e.g. "INBOX".'),
        since: z
          .string()
          .optional()
          .describe('Only messages on or after this date (ISO 8601, e.g. 2026-09-15).'),
        before: z.string().optional().describe('Only messages before this date (ISO 8601).'),
        from: z.string().optional().describe('Substring match on the From header.'),
        to: z.string().optional().describe('Substring match on the To header.'),
        subject: z.string().optional().describe('Substring match on the Subject header.'),
        text: z.string().optional().describe('Substring match in the message body.'),
        unseen_only: z.boolean().optional().describe('Restrict to unread messages.'),
        limit: z
          .number()
          .int()
          .positive()
          .optional()
          .describe(`Maximum results (server cap: ${cfg.MAX_SEARCH_RESULTS}).`)
      },
      annotations: { readOnlyHint: true, openWorldHint: false }
    },
    async (args, extra) => {
      const o = open(extra, args.mailbox, 'read');
      if ('denied' in o) return o.denied;
      try {
        return ok(
          await o.mailbox.search({
            folder: args.folder ?? 'INBOX',
            since: args.since,
            before: args.before,
            from: args.from,
            to: args.to,
            subject: args.subject,
            text: args.text,
            unseenOnly: args.unseen_only,
            limit: args.limit
          })
        );
      } catch (err) {
        return fail(err);
      }
    }
  );

  server.registerTool(
    'get_message',
    {
      title: 'Get a message',
      description:
        'Fetch one message in full: headers, plain-text body (HTML is converted), and attachment metadata. Does not mark the message as read.',
      inputSchema: {
        mailbox: mailboxArg('read'),
        folder: z.string().default('INBOX').describe('Folder containing the message.'),
        uid: z.number().int().positive().describe('IMAP UID from search_messages.')
      },
      annotations: { readOnlyHint: true, openWorldHint: false }
    },
    async (args, extra) => {
      const o = open(extra, args.mailbox, 'read');
      if ('denied' in o) return o.denied;
      try {
        return ok(await o.mailbox.getMessage(args.folder ?? 'INBOX', args.uid));
      } catch (err) {
        return fail(err);
      }
    }
  );

  server.registerTool(
    'get_thread',
    {
      title: 'Get a conversation',
      description:
        'Return every message in the same conversation as the given message, oldest first, as summaries. Threading follows Message-ID and References headers, not subject lines.',
      inputSchema: {
        mailbox: mailboxArg('read'),
        folder: z.string().default('INBOX').describe('Folder containing the message.'),
        uid: z.number().int().positive().describe('IMAP UID of any message in the thread.')
      },
      annotations: { readOnlyHint: true, openWorldHint: false }
    },
    async (args, extra) => {
      const o = open(extra, args.mailbox, 'read');
      if ('denied' in o) return o.denied;
      try {
        return ok(await o.mailbox.getThread(args.folder ?? 'INBOX', args.uid));
      } catch (err) {
        return fail(err);
      }
    }
  );

  if (withCapability('draft').length > 0) {
    server.registerTool(
      'create_draft',
      {
        title: 'Save a draft',
        description: anySend
          ? 'Compose a message from the mailbox\'s own address and save it to its Drafts folder. Saving does not send it: a human can open it in their mail client, and only send_draft sends it. Pass in_reply_to_uid to thread the draft onto an existing message (required for mailboxes that may only send replies).'
          : 'Compose a message from the mailbox\'s own address and save it to its Drafts folder. It is never sent: a human opens their mail client and decides. Pass in_reply_to_uid to thread the draft onto an existing message.',
        inputSchema: {
          mailbox: mailboxArg('draft'),
          to: z.array(z.string()).min(1).describe('Recipient email addresses.'),
          cc: z.array(z.string()).optional().describe('Cc addresses.'),
          subject: z.string().min(1).describe('Subject line.'),
          body: z.string().min(1).describe('Plain-text body.'),
          in_reply_to_uid: z
            .number()
            .int()
            .positive()
            .optional()
            .describe('UID of the message being replied to, for correct threading.'),
          in_reply_to_folder: z
            .string()
            .optional()
            .describe('Folder of that message, in the same mailbox (default INBOX).')
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }
      },
      async (args, extra) => {
        const o = open(extra, args.mailbox, 'draft');
        if ('denied' in o) return o.denied;
        try {
          return ok(
            await o.mailbox.createDraft({
              to: args.to,
              cc: args.cc,
              subject: args.subject,
              body: args.body,
              inReplyToUid: args.in_reply_to_uid,
              inReplyToFolder: args.in_reply_to_folder
            })
          );
        } catch (err) {
          return fail(err);
        }
      }
    );
  }

  const uidList = (what: string) =>
    z
      .array(z.number().int().positive())
      .min(1)
      .max(cfg.MAX_SEARCH_RESULTS)
      .describe(`IMAP UIDs from search_messages ${what} (max ${cfg.MAX_SEARCH_RESULTS} per call).`);

  if (withCapability('mark').length > 0) {
    server.registerTool(
      'mark_messages',
      {
        title: 'Mark messages',
        description:
          'Mark messages in one folder as read or unread and/or flag or unflag them. Pass seen and/or flagged; anything omitted is left as it is. Reports the resulting state, and any UIDs that were not found.',
        inputSchema: {
          mailbox: mailboxArg('mark'),
          folder: z.string().default('INBOX').describe('Folder containing the messages.'),
          uids: uidList('in that folder'),
          seen: z.boolean().optional().describe('true marks as read, false marks as unread.'),
          flagged: z.boolean().optional().describe('true sets the flag (star), false clears it.')
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      async (args, extra) => {
        const o = open(extra, args.mailbox, 'mark');
        if ('denied' in o) return o.denied;
        try {
          return ok(
            await o.mailbox.markMessages({
              folder: args.folder ?? 'INBOX',
              uids: args.uids,
              seen: args.seen,
              flagged: args.flagged
            })
          );
        } catch (err) {
          return fail(err);
        }
      }
    );
  }

  if (withCapability('move').length > 0) {
    server.registerTool(
      'move_messages',
      {
        title: 'Move messages',
        description:
          'Move messages from one folder to another existing folder of the same mailbox (e.g. file into Archive). UIDs change on a move: the result maps each old UID to its new one where the server reports it. Both folders must be readable by this server; nothing is deleted or copied.',
        inputSchema: {
          mailbox: mailboxArg('move'),
          folder: z.string().default('INBOX').describe('Folder the messages are in now.'),
          uids: uidList('in that folder'),
          destination: z.string().min(1).describe('Folder path to move them to; it must already exist.')
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }
      },
      async (args, extra) => {
        const o = open(extra, args.mailbox, 'move');
        if ('denied' in o) return o.denied;
        try {
          return ok(
            await o.mailbox.moveMessages({
              folder: args.folder ?? 'INBOX',
              uids: args.uids,
              destination: args.destination
            })
          );
        } catch (err) {
          return fail(err);
        }
      }
    );
  }

  if (anySend) {
    server.registerTool(
      'send_draft',
      {
        title: 'Send a draft',
        description:
          'Send a message that is already in the mailbox\'s Drafts folder, exactly as it is saved there (a human may have edited it since create_draft). This sends real email and cannot be undone: only call it when the user asked for this message to be sent. The From must be the mailbox\'s own address; recipients are checked against the mailbox\'s sending policy (see list_mailboxes; "reply-only" means only people already in the conversation the draft replies to) and a daily limit. On success a copy is filed in Sent and the draft leaves Drafts, so the same UID cannot be sent twice.',
        inputSchema: {
          mailbox: mailboxArg('send'),
          uid: z.number().int().positive().describe('UID of the draft in that mailbox\'s Drafts folder, as returned by create_draft or search_messages.')
        },
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true }
      },
      async (args, extra) => {
        const o = open(extra, args.mailbox, 'send');
        if ('denied' in o) return o.denied;
        try {
          return ok(await sender.sendDraft(o.mailbox, args.uid));
        } catch (err) {
          return fail(err);
        }
      }
    );
  }

  return server;
}
