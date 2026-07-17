> **Important note:** All credits go to [reminia](https://github.com/reminia).  
> This project is a TypeScript port of [`reminia/zendesk-mcp-server`](https://github.com/reminia/zendesk-mcp-server), with some upgrades and new tools.

# Zendesk MCP Server (TypeScript)

A Model Context Protocol server for Zendesk, rewritten in TypeScript from [`reminia/zendesk-mcp-server`](https://github.com/reminia/zendesk-mcp-server).

## What's updated

- TypeScript + strict typing
- Native Zendesk REST integration via `fetch` (no Python/Zenpy dependency)
- Zod input validation for tools/prompts
- Consistent MCP tool error payloads (`isError` + message)
- Help Center resource caching (1-hour TTL)
- Per-user OAuth for Streamable HTTP while stdio keeps API-token authentication

## Requirements

- Node.js 20+
- For stdio: a Zendesk email and API token
- For Streamable HTTP: a Zendesk OAuth client, an HTTPS public origin reachable by each user's browser, and persistent encrypted SQLite storage

## Setup

Install and build once for either transport:

```bash
npm install
npm run build
```

### Stdio

Stdio keeps the original single-user Zendesk API-token flow. Copy the stdio-only template, fill in the three Zendesk values, and start the server:

```bash
cp .env.stdio.example .env
npm start
```

For local development, use `npm run dev`. The Claude MCP configuration example below is also stdio-only.

### Streamable HTTP

HTTP is OAuth-only and does not use the stdio email or API token. Copy the HTTP template and keep the populated file readable only by its owner:

```bash
cp .env.http.example .env
chmod 0600 .env
```

Set `PUBLIC_BASE_URL` to the origin only, for example `https://dev-server.tail22145b.ts.net`, and include that hostname in `MCP_ALLOWED_HOSTS`. Generate `OAUTH_ENCRYPTION_KEY` as a base64-encoded 32-byte key and place `OAUTH_DB_PATH` on persistent storage.

Create a Zendesk OAuth client with the exact registered callback `${PUBLIC_BASE_URL}/oauth/zendesk/callback`, then set its client ID and secret in the HTTP environment. The Zendesk client must request exactly the upstream scopes `read tickets:write`.

The public endpoints include `POST /mcp`, `GET /healthz`, OAuth metadata, registration, authorization, token, revocation, consent, and the Zendesk callback. `GET /mcp` and `DELETE /mcp` return authenticated `405` responses because the MCP transport is stateless.

### Docker Compose deployment

The Compose deployment publishes plain HTTP only on host loopback at `127.0.0.1:38184` and persists encrypted OAuth state in the `oauth-data` volume:

```bash
docker compose config
docker compose up -d --build --wait
docker compose ps
docker compose logs --tail=50 zendesk-mcp
```

Proxy the full local origin through Tailscale Serve, not only the `/mcp` path, so discovery metadata, browser consent, and callback routes all remain reachable:

```bash
sudo tailscale serve --bg http://127.0.0.1:38184
tailscale serve status
```

Do not bind the plain-HTTP listener to a public or tailnet interface. Tailscale Serve terminates HTTPS on port `443`; tailnet grants control which users can reach it. The browser completing login must be connected to the tailnet.

Verify readiness and OAuth discovery without a copied credential or Zendesk call:

```bash
MCP_URL=https://dev-server.tail22145b.ts.net/mcp npm run smoke:http
```

### Codex URL configuration and login

Configure only the URL:

```toml
[mcp_servers.zendesk]
url = "https://dev-server.tail22145b.ts.net/mcp"
```

Then begin the standards-based browser flow and complete both the local consent page and Zendesk authorization:

```bash
codex mcp login zendesk
```

Each user signs in with their own Zendesk account. Zendesk remains authoritative for role and object permissions, and HTTP requests run under the audit identity of the authorizing user.

## Environment variables

Use `.env.stdio.example` for stdio:

- `ZENDESK_SUBDOMAIN`
- `ZENDESK_EMAIL`
- `ZENDESK_API_KEY`

Use `.env.http.example` for HTTP:

- `PUBLIC_BASE_URL`
- `ZENDESK_SUBDOMAIN`
- `ZENDESK_OAUTH_CLIENT_ID`
- `ZENDESK_OAUTH_CLIENT_SECRET`
- `OAUTH_ENCRYPTION_KEY`
- `OAUTH_DB_PATH`
- `MCP_ALLOWED_HOSTS`, `HOST`, and `PORT`
- `MCP_ACCESS_TOKEN_TTL_SECONDS` and `ZENDESK_HTTP_TIMEOUT_MS`
- `MCP_BIND_ADDRESS` and `MCP_HOST_PORT`

Do not combine the templates. In particular, the HTTP deployment must not receive the stdio email or API token.

## OAuth session operations

`codex mcp logout zendesk` is client-local only: it deletes the current Codex token record but does not call server revocation. The already issued access token can therefore remain server-valid for at most its 15-minute lifetime, and a copied refresh token remains valid until server expiry or explicit revocation.

For server-side action, first list the non-secret sessions for the stable Zendesk user ID:

```bash
docker compose exec zendesk-mcp npm run oauth:sessions -- --zendesk-user-id <id>
```

Revoke exactly one MCP token family after confirming its opaque family ID:

```bash
docker compose exec zendesk-mcp npm run oauth:revoke-family -- --family-id <id> --confirm
```

This leaves the principal's Zendesk credential available to other active families. To invalidate all families for one principal and queue best-effort upstream Zendesk revocation, inspect the target first and then run:

```bash
docker compose exec zendesk-mcp npm run oauth:disconnect-user -- --zendesk-user-id <id> --confirm
```

Disconnect is the account-wide server operation. It increments the principal lifecycle epoch, revokes all of that principal's MCP families, prevents requests from using the credential, and retains failed upstream revocation in the durable retry outbox.

Acceptance criteria: the selected family or principal becomes unusable, sessions belonging to other principals remain usable, and no command output contains an email, token, encryption key, database contents, or ciphertext.

### Ordinary re-login tradeoff

An ordinary re-login immediately replaces the locally usable Zendesk credential and securely removes the superseded local ciphertext, but intentionally does not revoke the superseded upstream grant. This avoids an `A -> B -> A` race in which a delayed revoke could delete the new credential. The old grant can therefore remain orphaned until Zendesk expiry. Use short Zendesk token lifetimes and the Zendesk tenant-side token audit/revocation flow to recover from a suspected orphaned grant.

## Backup and restore

Create a new encrypted SQLite backup through the store's consistent backup API; the destination is create-only and must be a new absolute path below `/data/backups/`:

```bash
docker compose exec zendesk-mcp npm run oauth:backup -- --destination /data/backups/<new-name>.sqlite
```

Keep the OAuth encryption key in separate custody from both the live volume and its backups. A database backup without the matching key is intentionally unrecoverable; storing both together removes the protection against database theft.

Use this restore procedure:

1. Create a disposable Docker volume and copy only the completed consistent backup into it as `/data/oauth.sqlite`. If recovery uses a separately captured SQLite snapshot instead, checkpoint that snapshot before copying it; never copy the live `oauth.sqlite`, `-wal`, and `-shm` files independently.
2. Start the same application image against the disposable volume with a restore-only environment and the separately retrieved original encryption key. Do not route user traffic to the drill instance.
3. Confirm local readiness and run the non-secret session inventory. A missing or wrong key must fail closed.
4. For disaster recovery, keep the original volume untouched until the disposable-volume drill passes, then switch the deployment to a restored replacement volume during a maintenance window.

Acceptance criteria: the consistent-backup or checkpointed-snapshot restore opens only with the matching separately held key, reports the expected non-secret sessions, and does not modify the source backup or live volume.

## Maintenance-window cutover and rollback

Use one maintenance window for the OAuth-only HTTP cutover:

1. Inventory every URL-based Codex client plus the deployed image, HTTP environment, and client configuration. Capture only redacted configuration; never print credential values.
2. Secure a rollback copy, deploy the OAuth image and persistent volume, and replace the HTTP environment with `.env.http.example` values. Stdio remains on `.env.stdio.example` and is not part of this cutover.
3. For every client, retain only the URL. In a redacted configuration check, confirm `http_headers.Authorization`, `bearer_token_env_var`, and `env_http_headers.Authorization` are absent.
4. Run `codex mcp login zendesk` for every inventoried client, then complete the authenticated acceptance gates before declaring the cutover complete.

If a release gate fails, roll back the image, environment, and affected client config atomically to the secured pre-window set. Do not leave legacy shared authentication and OAuth active at the same time.

Retire old shared credentials and secured rollback copies only after every inventoried client passes, the maintenance window is closed, and a separate approval confirms the exact retirement scope. Delayed secret retirement preserves a controlled rollback without prematurely destroying recoverable material.

Acceptance criteria: every inventoried URL client has URL-only configuration and a distinct successful OAuth login; the redacted checks show all three static authorization fields absent; stdio behavior is unchanged; and rollback can restore image, environment, and client config as one unit until separately approved retirement.

## Claude MCP config example (stdio)

```json
{
  "mcpServers": {
    "zendesk": {
      "command": "node",
      "args": [
        "/absolute/path/to/zendesk-mcp-server/dist/index.js"
      ],
      "env": {
        "ZENDESK_SUBDOMAIN": "your-subdomain",
        "ZENDESK_EMAIL": "you@example.com",
        "ZENDESK_API_KEY": "your_zendesk_api_token"
      }
    }
  }
}
```

## Prompts

- `analyze-ticket`
- `draft-ticket-response`

## Tools

- `get_ticket`
- `get_tickets`
- `search_tickets`
- `search`
- `search_users`
- `search_organizations`
- `list_ticket_fields`
- `get_ticket_audits`
- `get_ticket_comments`
- `create_ticket_comment`
- `create_ticket`
- `update_ticket`

`get_ticket_comments` returns an `attachments` array on each comment. Each attachment includes its ID, filename, content type, size, download URL, inline/deleted flags, and malware scan result. File bytes are not embedded in MCP responses; consumers download relevant `content_url` values with a normal GET and inspect them locally.

## Resources

- `zendesk://knowledge-base`

## Contributing

Issues and pull requests are welcome at [github.com/eramba/zendesk-mcp-server](https://github.com/eramba/zendesk-mcp-server).

When submitting changes:

- Keep changes focused and small
- Include clear reproduction/validation steps
- Update documentation for any tool or behavior changes

## Support

For bug reports and feature requests, please use [GitHub Issues](https://github.com/eramba/zendesk-mcp-server/issues).
