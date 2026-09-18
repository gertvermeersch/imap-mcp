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

export function buildMcpServer(cfg: Config, mailbox: Mailbox): McpServer {
  const server = new McpServer(
    { name: 'imap-mcp', version: '0.1.0' },
    {
      instructions: [
        `Read-only access to the IMAP mailbox ${cfg.IMAP_USER}, plus draft creation.`,
        'This server cannot send, delete, move or flag mail. Reading a message does',
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
        // The bearer middleware only requires mail:read for the endpoint as a
        // whole, so the draft grant is checked here, where it is spent.
        if (!extra.authInfo?.scopes.includes('mail:draft')) {
          return fail(
            new MailboxError(
              'This connection was not granted the mail:draft scope, so it cannot save drafts. Re-authorize the connector to grant it.'
            )
          );
        }
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

  return server;
}
