import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';

interface RefreshRecord {
  clientId: string;
  scopes: string[];
  resource?: string;
  expiresAt: number;
}

interface Persisted {
  clients: Record<string, OAuthClientInformationFull>;
  refreshTokens: Record<string, RefreshRecord>;
}

const EMPTY: Persisted = { clients: {}, refreshTokens: {} };

/**
 * Small JSON-file store. Single-instance by design: the whole point of this
 * server is one mailbox for one operator, so a file plus an in-process cache is
 * the right amount of machinery. Writes are atomic (write temp, rename).
 */
export class FileStore implements OAuthRegisteredClientsStore {
  private data: Persisted = structuredClone(EMPTY);
  private readonly path: string;
  private writeChain: Promise<void> = Promise.resolve();

  constructor(stateDir: string) {
    this.path = join(stateDir, 'oauth-state.json');
  }

  async init(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    try {
      const raw = await readFile(this.path, 'utf8');
      const parsed = JSON.parse(raw) as Partial<Persisted>;
      this.data = {
        clients: parsed.clients ?? {},
        refreshTokens: parsed.refreshTokens ?? {}
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      await this.flush();
    }
    this.pruneRefreshTokens();
  }

  private flush(): Promise<void> {
    // Serialize writes so concurrent registrations cannot interleave.
    this.writeChain = this.writeChain.then(async () => {
      const tmp = `${this.path}.tmp`;
      await writeFile(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
      await rename(tmp, this.path);
    });
    return this.writeChain;
  }

  // --- OAuthRegisteredClientsStore ----------------------------------------

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.data.clients[clientId];
  }

  async registerClient(
    client: OAuthClientInformationFull
  ): Promise<OAuthClientInformationFull> {
    this.data.clients[client.client_id] = client;
    await this.flush();
    return client;
  }

  // --- Refresh tokens ------------------------------------------------------

  async putRefreshToken(token: string, record: RefreshRecord): Promise<void> {
    this.data.refreshTokens[token] = record;
    await this.flush();
  }

  getRefreshToken(token: string): RefreshRecord | undefined {
    const rec = this.data.refreshTokens[token];
    if (!rec) return undefined;
    if (rec.expiresAt <= Date.now()) {
      void this.deleteRefreshToken(token);
      return undefined;
    }
    return rec;
  }

  async deleteRefreshToken(token: string): Promise<void> {
    if (!(token in this.data.refreshTokens)) return;
    delete this.data.refreshTokens[token];
    await this.flush();
  }

  private pruneRefreshTokens(): void {
    const now = Date.now();
    let changed = false;
    for (const [token, rec] of Object.entries(this.data.refreshTokens)) {
      if (rec.expiresAt <= now) {
        delete this.data.refreshTokens[token];
        changed = true;
      }
    }
    if (changed) void this.flush();
  }
}

export type { RefreshRecord };
