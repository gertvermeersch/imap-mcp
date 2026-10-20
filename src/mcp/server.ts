import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { Config } from '../config.js';
import { Mailbox, MailboxError } from '../imap/mailbox.js';

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

/**
 * The bearer middleware only requires mail:read for the endpoint as a whole, so
 * each write grant is checked here, where it is spent. Returns a tool error when
 * the token lacks the scope, undefined when the call may proceed.
 */
function missingScope(
  extra: { authInfo?: { scopes: string[] } },
  scope: string,
  action: string
): ReturnType<typeof fail> | undefined {
  if (extra.authInfo?.scopes.includes(scope)) return undefined;
  return fail(
    new MailboxError(
      `This connection was not granted the ${scope} scope, so it cannot ${action}. Re-authorize the connector to grant it.`
    )
  );
}

export function buildMcpServer(cfg: Config, mailbox: Mailbox): McpServer {
  const writes = [
    cfg.ENABLE_DRAFTS && 'save drafts (create_draft)',
    cfg.ENABLE_MARKING && 'mark messages read/unread or flagged (mark_messages)',
    cfg.ENABLE_MOVE && 'move messages between folders (move_messages)'
  ].filter(Boolean);
  const server = new McpServer(
    { name: 'imap-mcp', version: '0.1.0' },
    {
      instructions: [
        `Read access to the IMAP mailbox ${cfg.IMAP_USER}${
          writes.length > 0 ? `, plus: ${writes.join('; ')}` : ' (strictly read-only)'
        }.`,
        'This server cannot send or delete mail. Reading a message does',
        'not mark it as seen. Use search_messages to find candidates, then',
        'get_message for full text, and get_thread when the conversation matters.'
      ].join(' ')
    }
  );

  server.registerTool(
    'list_folders',
    {
      title: 'List mail folders',
      description:
        'List the IMAP folders this server is allowed to read, with their special-use role (Inbox, Sent, Drafts, Archive, Junk) where the server reports one.',
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false }
    },
    async () => {
      try {
        return ok(await mailbox.listFolders());
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
    async (args) => {
      try {
        return ok(
          await mailbox.search({
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
        folder: z.string().default('INBOX').describe('Folder containing the message.'),
        uid: z.number().int().positive().describe('IMAP UID from search_messages.')
      },
      annotations: { readOnlyHint: true, openWorldHint: false }
    },
    async (args) => {
      try {
        return ok(await mailbox.getMessage(args.folder ?? 'INBOX', args.uid));
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
        folder: z.string().default('INBOX').describe('Folder containing the message.'),
        uid: z.number().int().positive().describe('IMAP UID of any message in the thread.')
      },
      annotations: { readOnlyHint: true, openWorldHint: false }
    },
    async (args) => {
      try {
        return ok(await mailbox.getThread(args.folder ?? 'INBOX', args.uid));
      } catch (err) {
        return fail(err);
      }
    }
  );

  if (cfg.ENABLE_DRAFTS) {
    server.registerTool(
      'create_draft',
      {
        title: 'Save a draft',
        description:
          'Compose a message and save it to the Drafts folder. It is never sent — a human opens their mail client and decides. Pass in_reply_to_uid to thread the draft onto an existing message.',
        inputSchema: {
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
            .describe('Folder of that message (default INBOX).')
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }
      },
      async (args, extra) => {
        const denied = missingScope(extra, 'mail:draft', 'save drafts');
        if (denied) return denied;
        try {
          return ok(
            await mailbox.createDraft({
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

  if (cfg.ENABLE_MARKING) {
    server.registerTool(
      'mark_messages',
      {
        title: 'Mark messages',
        description:
          'Mark messages in one folder as read or unread and/or flag or unflag them. Pass seen and/or flagged; anything omitted is left as it is. Reports the resulting state, and any UIDs that were not found.',
        inputSchema: {
          folder: z.string().default('INBOX').describe('Folder containing the messages.'),
          uids: uidList('in that folder'),
          seen: z.boolean().optional().describe('true marks as read, false marks as unread.'),
          flagged: z.boolean().optional().describe('true sets the flag (star), false clears it.')
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
      },
      async (args, extra) => {
        const denied = missingScope(extra, 'mail:mark', 'change read or flag state');
        if (denied) return denied;
        try {
          return ok(
            await mailbox.markMessages({
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

  if (cfg.ENABLE_MOVE) {
    server.registerTool(
      'move_messages',
      {
        title: 'Move messages',
        description:
          'Move messages from one folder to another existing folder (e.g. file into Archive). UIDs change on a move: the result maps each old UID to its new one where the server reports it. Both folders must be readable by this server; nothing is deleted or copied.',
        inputSchema: {
          folder: z.string().default('INBOX').describe('Folder the messages are in now.'),
          uids: uidList('in that folder'),
          destination: z.string().min(1).describe('Folder path to move them to; it must already exist.')
        },
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }
      },
      async (args, extra) => {
        const denied = missingScope(extra, 'mail:move', 'move messages');
        if (denied) return denied;
        try {
          return ok(
            await mailbox.moveMessages({
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

  return server;
}
