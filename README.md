# imap-mcp

A remote MCP server that gives Claude **read + draft** access to one IMAP mailbox, authenticated with OAuth 2.1.

Built to sit behind Traefik reverse proxy: TypeScript, Docker, Traefik. So IMAP itself is never exposed to the internet — only this server's HTTPS endpoint is.

```
claude.ai ──HTTPS/OAuth──▶ imap-mcp (VPS) ──IMAP/TLS, private subnet──▶ Mailcow (mail host)
```

## What it can and cannot do

| Tool | What it does |
|---|---|
| `list_folders` | Lists readable folders and their special-use roles |
| `search_messages` | Filters by date, sender, recipient, subject, body text, unread; returns summaries newest first |
| `get_message` | Full headers, plain-text body (HTML converted), attachment metadata |
| `get_thread` | The whole conversation, threaded on `Message-ID`/`References` |
| `create_draft` | Composes and saves to Drafts, optionally threaded onto a reply |

There is **no SMTP client anywhere in this process**, so it cannot send. It also cannot delete, move, or change flags. Reading a message takes a read-only mailbox lock, so triage never marks anything `\Seen` — the mailbox looks untouched to a human afterwards.

Two switches tighten it further:

- `ALLOWED_FOLDERS` — an allowlist; anything not listed is invisible to every tool.
- `ENABLE_DRAFTS=false` — drops `create_draft` entirely, making the server strictly read-only.

## Security model

- **OAuth 2.1**, authorization code + PKCE, per the MCP authorization spec. The server is both authorization server and resource server.
- **Audience binding (RFC 8707).** Access tokens are JWTs whose `aud` is this server's canonical URI. A token minted for any other resource is rejected — this is the check that stops a token from elsewhere being replayed here.
- **One operator.** A single username plus an scrypt password hash. Registering an OAuth client is automatic; *authorizing* one always requires that human login.
- **Refresh token rotation**, single-use authorization codes (60s), `iss` in the callback per RFC 9207.
- **Scopes are enforced, not just advertised.** `mail:read` gates the endpoint; `create_draft` additionally checks `mail:draft` on every call. A client that asks for read-only gets a token that cannot draft. With `ENABLE_DRAFTS=false` the scope is not advertised or grantable at all.
- **Sign-in throttling.** Five wrong passwords burn the authorization request, so further guesses cost a fresh `/authorize` round trip. Five failures from one address — or twenty across all addresses — lock the login form for 15 minutes with a `429` and a `Retry-After`. The counters are in memory and reset on restart.
- The mailbox password lives only in the container env. It is never returned by a tool, never rendered in the login page, and never leaves the server.

Give it a **dedicated Mailcow app password**, not your main one. If the mailbox supports it, a separate read-only IMAP user is better still.

## Deployment

**1. Create the mailbox credential.** In Mailcow, add an app password for the mailbox scoped to IMAP only. Note the private-subnet hostname you connect with — it must match the TLS certificate, or you will be tempted to set `IMAP_TLS_REJECT_UNAUTHORIZED=false`, which you should not do.

**2. Configure.**

```bash
git clone <this repo> /opt/imap-mcp && cd /opt/imap-mcp
cp .env.example .env
openssl rand -base64 48          # -> JWT_SECRET
$EDITOR .env
```

`MCP_RESOURCE_URL` must be **exactly** the URL you give claude.ai, including `/mcp`, with no trailing slash. It is the OAuth resource indicator and the JWT audience; a mismatch shows up as tokens being refused.

**3. Generate the operator password hash.**

```bash
docker compose build
docker compose run --rm imap-mcp node dist/tools/hash-password.js
# paste the scrypt$... output into OPERATOR_PASSWORD_HASH
```

**4. Add the Traefik TLS option.** Once, in Traefik's file provider:

```yaml
tls:
  options:
    http1only:
      alpnProtocols:
        - http/1.1
```

This is the same HTTP/2 multiplexing problem that bit the Dolibarr MCP. The compose labels already reference `http1only@file`.

**5. Bring it up.**

```bash
docker compose up -d
curl -s https://mail-mcp.example.be/healthz
curl -s https://mail-mcp.example.be/.well-known/oauth-protected-resource/mcp | jq
```

The second call should echo your `MCP_RESOURCE_URL` back as `resource`. If it doesn't, fix that before touching claude.ai.

**6. Register the connector.** In claude.ai, Settings → Connectors → Add custom connector, URL `https://mail-mcp.example.be/mcp`. Claude registers itself, then sends you to the login page. Sign in with `OPERATOR_USERNAME` and the password you hashed. Approve, and the tools appear.

**7. Wire it into the morning triage.** Once the connector is live, the 07:00 scheduled task's prompt needs one edit: tell it to check this mailbox alongside Gmail. Ask Claude to update the task — the schedule and run history survive a prompt change.

## Network notes

- The container needs a route to your Mailcow instance's IMAP. Attach it to whichever Docker network or host WireGuard interface provides that; the compose file assumes an external network named `mail`.
- Anthropic reaches the endpoint from published IP ranges. If you want a second layer, add a Traefik `IPAllowList` middleware for those ranges — but know that if they change, the 07:00 task fails silently until you notice. OAuth alone is the lower-maintenance choice.

## Development

```bash
npm install
npm run typecheck
npm run dev                       # tsx watch, reads .env from your shell
```

### Tests

`test/smoke.mjs` runs the whole thing end to end against a throwaway [GreenMail](https://greenmail-mail-test.github.io/greenmail/) IMAP server: OAuth discovery, dynamic client registration, PKCE, operator login, code exchange, refresh rotation, every tool, and the negative cases (no token, foreign audience, wrong verifier, replayed code, unknown folder).

```bash
curl -sfL -o /tmp/greenmail.jar \
  https://repo1.maven.org/maven2/com/icegreen/greenmail-standalone/2.1.13/greenmail-standalone-2.1.13.jar
npm run build
GREENMAIL_JAR=/tmp/greenmail.jar node test/smoke.mjs
```

39 checks; all should pass.

`test/auth.mjs` covers scope enforcement and login throttling. It needs neither Java nor an IMAP server — every path it asserts is refused before the mailbox is reached — so it is the quick one to run after touching `src/auth/`:

```bash
npm run build && npm run test:auth
```

22 checks; all should pass.

`test/body-parts.mjs` unit-tests the structure walks behind `get_message` — which body part to render, which nodes are attachments, and how `References` is parsed — against BODYSTRUCTURE fixtures. No server at all:

```bash
npm run build && npm run test:body
```

24 checks; all should pass. The `References` cases assert byte-for-byte agreement with what `mailparser` produced from the full source, because threading depends on that format not shifting.

Two behaviours the tests pinned down, worth knowing if you extend the search tool:

- Message search uses `HEADER from`/`HEADER to` rather than the bare `FROM`/`TO` keys. `HEADER` is substring matching on every RFC 3501 server; the bare keys are interpreted more loosely by some (GreenMail matches whole addresses only).
- `APPEND` to a missing Drafts folder returns `TRYCREATE`. The server creates the folder and retries once, so a renamed or localised Drafts doesn't break drafting.

`get_message` does not download the message. It fetches `BODYSTRUCTURE` plus the threading headers, picks the first inline `text/plain` (falling back to `text/html`), and streams only that part with a byte cap — so a 25 MB mail with a 3 kB body costs 3 kB, and attachment metadata is read off the structure without fetching a single attachment byte. Messages whose structure offers no renderable text part fall back to the old full-source parse, which is slower but copes with malformed MIME.

## Protocol version

Built against `@modelcontextprotocol/sdk` 1.30.0, which negotiates the protocol version with the client. The endpoint is **stateless** (no session IDs), matching where the spec moved in 2026-07-28 and letting Traefik restart the container without breaking a connector mid-conversation.

Note that the 2026-07-28 spec deprecates Dynamic Client Registration in favour of Client ID Metadata Documents. DCR still works and is what current clients use; if that changes, the swap is contained to `src/auth/`.
