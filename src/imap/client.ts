import { ImapFlow } from 'imapflow';
import type { Config } from '../config.js';

/**
 * One long-lived IMAP connection, reconnected on demand. imapflow serializes
 * mailbox access through getMailboxLock, so a single connection is both
 * sufficient and easier to reason about than a pool for a one-mailbox server.
 */
export class ImapConnection {
  private client: ImapFlow | undefined;
  private connecting: Promise<ImapFlow> | undefined;

  constructor(private readonly cfg: Config) {}

  private build(): ImapFlow {
    return new ImapFlow({
      host: this.cfg.IMAP_HOST,
      port: this.cfg.IMAP_PORT,
      secure: this.cfg.IMAP_SECURE,
      auth: { user: this.cfg.IMAP_USER, pass: this.cfg.IMAP_PASSWORD },
      tls: { rejectUnauthorized: this.cfg.IMAP_TLS_REJECT_UNAUTHORIZED },
      logger: false,
      // Keep the socket warm between the morning run and ad-hoc queries.
      maxIdleTime: 5 * 60 * 1000,
      emitLogs: false
    });
  }

  async get(): Promise<ImapFlow> {
    if (this.client?.usable) return this.client;
    if (this.connecting) return this.connecting;

    this.connecting = (async () => {
      const c = this.build();
      c.on('error', () => {
        // Drop the handle; the next call reconnects. Swallowing here keeps an
        // idle-socket reset from taking the process down.
        if (this.client === c) this.client = undefined;
      });
      c.on('close', () => {
        if (this.client === c) this.client = undefined;
      });
      await c.connect();
      this.client = c;
      return c;
    })();

    try {
      return await this.connecting;
    } finally {
      this.connecting = undefined;
    }
  }

  /**
   * Runs `fn` with an exclusive lock on `folder`. Read operations take the lock
   * read-only so that fetching a body never sets \Seen — triage must not change
   * what the mailbox looks like to a human.
   */
  async withFolder<T>(
    folder: string,
    readOnly: boolean,
    fn: (client: ImapFlow) => Promise<T>
  ): Promise<T> {
    const attempt = async (): Promise<T> => {
      const client = await this.get();
      const lock = await client.getMailboxLock(folder, { readOnly });
      try {
        return await fn(client);
      } finally {
        lock.release();
      }
    };

    try {
      return await attempt();
    } catch (err) {
      // One retry on a dead socket; a genuine IMAP error surfaces as-is.
      if (this.isConnectionError(err)) {
        this.client = undefined;
        return attempt();
      }
      throw err;
    }
  }

  async withClient<T>(fn: (client: ImapFlow) => Promise<T>): Promise<T> {
    try {
      return await fn(await this.get());
    } catch (err) {
      if (this.isConnectionError(err)) {
        this.client = undefined;
        return fn(await this.get());
      }
      throw err;
    }
  }

  private isConnectionError(err: unknown): boolean {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    const msg = err instanceof Error ? err.message : '';
    return (
      code === 'ECONNRESET' ||
      code === 'EPIPE' ||
      code === 'ETIMEDOUT' ||
      code === 'NoConnection' ||
      /not (usable|connected)|connection closed/i.test(msg)
    );
  }

  async close(): Promise<void> {
    const c = this.client;
    this.client = undefined;
    if (c?.usable) {
      try {
        await c.logout();
      } catch {
        /* shutting down anyway */
      }
    }
  }
}
