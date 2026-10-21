# imap-mcp

A remote MCP server that gives Claude **read, draft, mark and move** access to one or more IMAP mailboxes, plus, for the mailboxes you choose, **sending a draft**. Authentication is OAuth 2.1. Each capability is its own scope per mailbox, so a single connector can read `personal@`, file mail in `info@` and send replies from `agent@` without any of those grants leaking into another mailbox.

Built to sit behind Traefik reverse proxy: TypeScript, Docker, Traefik. So IMAP itself is never exposed to the internet — only this server's HTTPS endpoint is.

```
claude.ai ──HTTPS/OAuth──▶ imap-mcp (VPS) ──IMAP/TLS, private subnet──▶ Mailcow (mail host)
```

## What it can and cannot do

Every tool except `list_mailboxes` takes a `mailbox` id. With one mailbox configured it may be left out; with several it is required, so a UID from one mailbox can never be applied to another by default.

| Tool | What it does |
|---|---|
| `list_mailboxes` | Lists the mailboxes, what this connection was granted in each, and each one's sending policy |
| `list_folders` | Lists readable folders and their special-use roles |
| `search_messages` | Filters by date, sender, recipient, subject, body text, unread; returns summaries newest first |
| `get_message` | Selected headers, plain-text body (HTML converted), attachment metadata |
| `get_thread` | Conversation summaries in the selected folder, capped at `MAX_SEARCH_RESULTS`, threaded on `Message-ID`/`References` |
| `create_draft` | Composes and saves to Drafts, optionally threaded onto a reply (`mail:draft`) |
| `mark_messages` | Marks messages read/unread and flags/unflags them; reports the resulting state (`mail:mark`) |
| `move_messages` | Moves messages to another existing folder; reports old → new UIDs (`mail:move`) |
| `send_draft` | Sends a message that is already in that mailbox's Drafts folder, then files it in Sent (`mail:send`) |

**Sending only ever happens through `send_draft`**, and only for mailboxes whose entry in `MAILBOXES_CONFIG` lists `send` (see [Sending](#sending)). There is no tool that composes and sends in one step. Claude writes the message with `create_draft`, and it sits in Drafts where a human can read, edit or delete it. `send_draft` then sends whatever is in Drafts at that moment. A single-mailbox deployment configured from env alone cannot send at all.

Nothing is permanently removed, with one exception. Once a draft has been sent, `send_draft` attempts to file it in Sent and remove it from Drafts (cleanup is attempted even if filing fails). It removes the draft with `UID EXPUNGE`, which touches only that UID. On a server without UIDPLUS it only flags the draft `\Deleted` and never expunges. No other tool issues `EXPUNGE` or a delete. Moving a message into a Trash folder is still a move, so keep Trash out of the folder allowlist if that is a concern. Reading a message takes a read-only mailbox lock, so triage never marks anything `\Seen`. `mark_messages` changes read/flag state; sending also sets flags when filing and retiring a draft. Only `mark_messages`, `move_messages` and `send_draft` take a read-write lock.

Both batch tools take at most `MAX_SEARCH_RESULTS` UIDs per call. UIDs that don't exist are returned in `notFound` instead of failing the batch. `move_messages` needs both folders to be allowed, and the destination must already exist — it will not create one. UIDs change on a move; the new UID is reported when the server supports UIDPLUS.

Switches that tighten it further:

- `ALLOWED_FOLDERS` (or `folders:` per mailbox): an allowlist. Anything not listed is invisible to every tool, including as a move destination.
- `capabilities:` per mailbox in `MAILBOXES_CONFIG`: which of `read`, `draft`, `mark`, `move`, `send` that mailbox offers at all.
- `ENABLE_DRAFTS=false`, `ENABLE_MARKING=false`, `ENABLE_MOVE=false`, `ENABLE_SEND=false`: global kill switches. Each one drops its tool and its scopes on every mailbox, whatever the config file says.
- All four false makes the server strictly read-only. With the current config validator, disabling send also requires removing any per-mailbox `send:` sections; otherwise startup fails.

## Security model

- **OAuth 2.1**, authorization code + PKCE, per the MCP authorization spec. The server is both authorization server and resource server.
- **Audience binding (RFC 8707).** Access tokens are JWTs whose `aud` is this server's canonical URI. A token minted for any other resource is rejected — this is the check that stops a token from elsewhere being replayed here.
- **One operator.** A single username plus an scrypt password hash. Registering an OAuth client is automatic; *authorizing* one always requires that human login.
- **Refresh token rotation**, single-use authorization codes (60s), `iss` in the callback per RFC 9207.
- **Scopes are per mailbox, and enforced, not just advertised.** A scope names a capability and a mailbox, e.g. `mail:read:personal`, `mail:move:info` or `mail:send:agent`. Every tool call checks read on the mailbox it names, and a write also checks that write on the same mailbox. The scopes are independent: a token that can mark cannot move, and a grant on `info` says nothing about `personal`. The endpoint itself only requires read on at least one mailbox.
- **The operator picks at sign-in.** The consent page groups a checkbox per requested scope under each mailbox. Everything starts ticked except send, which has to be ticked deliberately. The operator can narrow a grant, never widen it. A write on a mailbox is only granted together with read on that mailbox. Unticking every read is refused, and the request stays open so the operator can go back and tick one. The token response reports the narrower `scope`. A capability a mailbox doesn't have, or that an `ENABLE_*` switch turned off, is not advertised or grantable at all.
- **Upgrading keeps old connectors working.** Tokens and refresh tokens issued before scopes named a mailbox (`mail:read`, `mail:draft`, ...) are read as applying to the first mailbox, which is the one they were granted on. A client that still *requests* an unqualified `mail:read` is offered read on every mailbox. Re-authorize the connector to pick up other mailboxes or send.
- **Sign-in throttling.** Five wrong passwords burn the authorization request, so further guesses cost a fresh `/authorize` round trip. Five failures from one address — or twenty across all addresses — lock the login form for 15 minutes with a `429` and a `Retry-After`. The counters are in memory and reset on restart.
- Mailbox passwords live only in the container env. `mailboxes.yml` names the variable and never holds the password. They are never returned by a tool, never rendered in the login page, and never leave the server.

Give each mailbox a **dedicated Mailcow app password**, not its main one. Enable SMTP on that app password only for mailboxes that send.

## Several mailboxes

Set `MAILBOXES_CONFIG` to a YAML file listing the mailboxes, mounted read-only into the container. [mailboxes.example.yml](mailboxes.example.yml) is the annotated template:

```yaml
mailboxes:
  personal:                                   # id, used in tools and scopes
    address: personal@yourdomain.example      # also the IMAP/SMTP login unless `user:` says otherwise
    passwordEnv: IMAP_PASSWORD_PERSONAL       # the env var holding the app password
    folders: [INBOX, Sent, Drafts, Archive]
    capabilities: [read, draft, mark, move]
  agent:
    address: agent@yourdomain.example
    name: Your Company Assistant
    passwordEnv: IMAP_PASSWORD_AGENT
    capabilities: [read, draft, send]
    send:
      recipients: reply-only
      maxPerDay: 20
```

Each mailbox is a separate IMAP login with its own connection, folder allowlist, Drafts and Sent folders. Host, port and TLS come from the `IMAP_*` and `SMTP_*` env vars and can be overridden per mailbox. Startup fails if the file is invalid, if a password variable is unset, or if a sending mailbox has no SMTP host or hides Drafts or Sent from its own allowlist. The first mailbox is the default that pre-upgrade tokens map to. Without `MAILBOXES_CONFIG`, the server runs the single mailbox from `IMAP_USER`/`IMAP_PASSWORD` as before, with the local part of the address as its id (`personal@...` becomes `personal`).

## Sending

`send_draft(mailbox, uid)` sends the draft with that UID from the mailbox's Drafts folder. It is sent as stored, so edits a human made in their mail client go out, and a draft they deleted can't be sent. In order, it:

1. **Checks the daily cap.** Messages sent from this mailbox in the last 24 hours must be under `maxPerDay`. The count is kept in `STATE_DIR/send-log.json` and survives restarts.
2. **Checks the From.** It must be exactly the mailbox's address. Mailcow's sender ACL would refuse anything else too.
3. **Counts recipients.** To + Cc + Bcc must not exceed `maxRecipients`.
4. **Applies the recipient policy:**
   - `reply-only` (the default): the draft must reply (In-Reply-To/References) to a message found in the mailbox. Every recipient must appear on that conversation's From/Sender/Reply-To/To/Cc. The mailbox's Drafts, Junk and Trash don't count as evidence, and neither does any message still flagged `\Draft`. A draft moved into INBOX therefore can't pose as a conversation that lets an extra recipient in.
   - A list such as `[client@example.com, "@yourdomain.example"]`: only those addresses and domains.
   - `any`.
5. **Sends.** It submits over SMTP with the mailbox's own app password. The `Date` is set to the moment of sending and the `Bcc` header is stripped from what recipients get.
6. **Files and cleans up.** It files a copy (Bcc kept) in Sent, marked read, then takes the draft out of Drafts. A Message-ID in the retained send log is refused. The log retains 30 days of history; this is not an exactly-once delivery guarantee if SMTP succeeds before the log is persisted or the draft has no Message-ID.

Each send is logged as a `[send] mailbox=... message-id=... to=...` line. If filing in Sent or removing the draft fails after the message went out, the tool still reports success, with a warning, rather than an error a client might retry.

The tool carries `destructiveHint` and `openWorldHint` annotations; confirmation behavior depends on the client. Its description and the server instructions tell Claude to send only when the user asked for that message to be sent. The real safeguards are the scope, the policy and the cap, because an unattended scheduled task has nobody to ask. A sensible split is your own mailbox with draft only, and a separate `agent@` mailbox with `send` and `reply-only`.

## Deployment

**1. Create the mailbox credential.** In Mailcow, add an app password for the mailbox scoped to IMAP only (IMAP and SMTP for a mailbox that sends). With several mailboxes, create one per mailbox. Note the private-subnet hostname you connect with — it must match the TLS certificate, or you will be tempted to set `IMAP_TLS_REJECT_UNAUTHORIZED=false`, which you should not do.

**2. Configure.**

```bash
git clone <this repo> /opt/imap-mcp && cd /opt/imap-mcp
cp .env.example .env
cp docker-compose.example.yml docker-compose.yml
openssl rand -base64 48          # -> JWT_SECRET
$EDITOR .env
```

For several mailboxes, also `cp mailboxes.example.yml mailboxes.yml`, edit it, uncomment the `mailboxes.yml` volume in the compose file, and set `MAILBOXES_CONFIG=/config/mailboxes.yml` plus one `IMAP_PASSWORD_*` per mailbox in `.env`. Set `SMTP_HOST` if any mailbox sends.

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

This avoids HTTP/2 multiplexing issues with long-lived MCP streams. The compose labels already reference `http1only@file`.

**5. Bring it up.**

```bash
docker compose up -d
curl -s https://mail-mcp.example.com/healthz
curl -s https://mail-mcp.example.com/.well-known/oauth-protected-resource/mcp | jq
```

The second call should echo your `MCP_RESOURCE_URL` back as `resource`. If it doesn't, fix that before touching claude.ai.

**6. Register the connector.** In claude.ai, Settings → Connectors → Add custom connector, URL `https://mail-mcp.example.com/mcp`. Claude registers itself, then sends you to the login page. Sign in with `OPERATOR_USERNAME` and the password you hashed. Tick what to grant per mailbox (send is off unless you tick it), approve, and the tools appear. To add a mailbox or grant send later, edit `mailboxes.yml`, restart, and re-authorize the connector.

## Network notes

- The container needs a route to your Mailcow instance's IMAP. Attach it to whichever Docker network or host WireGuard interface provides that; the compose file assumes an external network named `mail`.
- Anthropic reaches the endpoint from published IP ranges. If you want a second layer, add a Traefik `IPAllowList` middleware for those ranges — but changes to those ranges can block connector access. OAuth alone is the lower-maintenance choice.

## Development

```bash
npm install
npm run typecheck
npm run dev                       # tsx watch; export configuration into your shell first
```

### Tests

`test/smoke.mjs` runs the whole thing end to end against a throwaway [GreenMail](https://greenmail-mail-test.github.io/greenmail/) IMAP and SMTP server: OAuth discovery, dynamic client registration, PKCE, operator login, code exchange, refresh rotation, every tool (including marking and moving), and the negative cases (no token, foreign audience, wrong verifier, replayed code, unknown folder, moving to a missing folder). A second instance runs two mailboxes from a `MAILBOXES_CONFIG` file and really sends with `send_draft`. It checks delivery, the stripped Bcc, the Sent copy and the removed draft, and every refusal: a stranger under reply-only, a draft that replies to nothing, a planted draft posing as a conversation, a double send, and the daily cap.

GreenMail runs in Docker by default, so the only requirement is a running Docker daemon:

```bash
npm run build
npm run test:smoke
```

The test pulls `greenmail/standalone` on first use, starts a container named `imap-mcp-smoke-greenmail` on ports 3143/3025, and removes it afterwards. Without Docker, point it at a standalone jar and it runs under a local Java instead:

```bash
curl -sfL -o /tmp/greenmail.jar \
  https://repo1.maven.org/maven2/com/icegreen/greenmail-standalone/2.1.13/greenmail-standalone-2.1.13.jar
npm run build
GREENMAIL_JAR=/tmp/greenmail.jar node test/smoke.mjs
```

71 checks; all should pass.

`test/auth.mjs` covers scope enforcement (including the mark and move scopes, per-mailbox scopes, legacy tokens and the operator's scope picker), `MAILBOXES_CONFIG` validation and login throttling. It needs neither Java nor an IMAP server — every path it asserts is refused before the mailbox is reached — so it is the quick one to run after touching `src/auth/`:

```bash
npm run build && npm run test:auth
```

61 checks; all should pass.

`test/body-parts.mjs` unit-tests the structure walks behind `get_message` — which body part to render, which nodes are attachments, and how `References` is parsed — against BODYSTRUCTURE fixtures. No server at all:

```bash
npm run build && npm run test:body
```

24 checks; all should pass. The `References` cases assert byte-for-byte agreement with what `mailparser` produced from the full source, because threading depends on that format not shifting.

Two behaviours the tests pinned down, worth knowing if you extend the search tool:

- Message search uses `HEADER from`/`HEADER to` rather than the bare `FROM`/`TO` keys. `HEADER` is substring matching on every RFC 3501 server; the bare keys are interpreted more loosely by some (GreenMail matches whole addresses only).
- `APPEND` to a missing Drafts or Sent folder returns `TRYCREATE`. The server creates the folder and retries once, so a renamed or localised one doesn't break drafting or sending.

`get_message` does not download the message. It fetches `BODYSTRUCTURE` plus the threading headers, picks the first inline `text/plain` (falling back to `text/html`), and streams only that part with a byte cap — so a 25 MB mail with a 3 kB body costs 3 kB, and attachment metadata is read off the structure without fetching a single attachment byte. Messages whose structure offers no renderable text part fall back to the old full-source parse, which is slower but copes with malformed MIME.

## Protocol version

Built against `@modelcontextprotocol/sdk` 1.30.0, which negotiates the protocol version with the client. The endpoint is **stateless** (no session IDs). Restarts still clear pending authorization requests, authorization codes and login-throttle counters.

The server supports Dynamic Client Registration (DCR) through the SDK OAuth router; the authorization implementation is in `src/auth/`.
