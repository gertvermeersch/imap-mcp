import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export interface SendRecord {
  mailbox: string;
  /** Epoch milliseconds. */
  at: number;
  messageId: string;
  recipients: string[];
  subject: string;
}

/** Long enough to answer "what did the agent send last week", short enough to stay small. */
const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Every message send_draft has handed to SMTP, persisted next to the OAuth
 * state. It is what the daily cap counts, what stops a Message-ID going out
 * twice, and the audit trail — so unlike the login throttle it must survive a
 * restart. Same atomic write-temp-then-rename as FileStore.
 */
export class SendLog {
  private records: SendRecord[] = [];
  private readonly path: string;
  private writeChain: Promise<void> = Promise.resolve();

  constructor(stateDir: string) {
    this.path = join(stateDir, 'send-log.json');
  }

  async init(): Promise<void> {
    await mkdir(join(this.path, '..'), { recursive: true });
    try {
      const parsed = JSON.parse(await readFile(this.path, 'utf8')) as { records?: SendRecord[] };
      this.records = parsed.records ?? [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    this.prune();
  }

  /** Messages sent from `mailbox` within the last `windowMs`. */
  countSince(mailbox: string, windowMs: number): number {
    const since = Date.now() - windowMs;
    return this.records.filter((r) => r.mailbox === mailbox && r.at >= since).length;
  }

  wasSent(mailbox: string, messageId: string): boolean {
    return this.records.some((r) => r.mailbox === mailbox && r.messageId === messageId);
  }

  async record(entry: SendRecord): Promise<void> {
    this.records.push(entry);
    this.prune();
    await this.flush();
  }

  private prune(): void {
    const cutoff = Date.now() - RETENTION_MS;
    this.records = this.records.filter((r) => r.at >= cutoff);
  }

  private flush(): Promise<void> {
    this.writeChain = this.writeChain.then(async () => {
      const tmp = `${this.path}.tmp`;
      await writeFile(tmp, JSON.stringify({ records: this.records }, null, 2), { mode: 0o600 });
      await rename(tmp, this.path);
    });
    return this.writeChain;
  }
}
