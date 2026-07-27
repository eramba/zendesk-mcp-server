> **Important note:** All credits go to [reminia](https://github.com/reminia).
> This project is a TypeScript port of
> [`reminia/zendesk-mcp-server`](https://github.com/reminia/zendesk-mcp-server),
> with additional tools and internal Streamable HTTP deployment support.

# Zendesk MCP Server (TypeScript)

A Model Context Protocol server for Zendesk with stdio and stateless
Streamable HTTP transports.

## Authentication modes

- Streamable HTTP uses one random MCP bearer per internal colleague. The
  bearer selects that colleague's encrypted Zendesk OAuth grant; each POST
  constructs a request-scoped Zendesk client.
- Stdio retains the existing email/API-token configuration for compatibility.
  It does not use the HTTP user store.

Zendesk has announced that Support API tokens begin inactivity-based
deactivation on July 28, 2026 and are permanently deactivated on April 30,
2027. New HTTP deployments should use the OAuth flow documented here. See
[Zendesk's retirement announcement](https://support.zendesk.com/hc/en-us/articles/10840968198042-Announcing-the-removal-of-API-tokens-as-an-authentication-method-for-API-requests)
and [OAuth migration guide](https://developer.zendesk.com/documentation/api-basics/authentication/oauth-migration/).

## Requirements

- Node.js 20+
- one fixed Zendesk subdomain
- a confidential Zendesk OAuth client
- HTTPS for the public callback URL (loopback HTTP is accepted for development)
- a persistent path for the SQLite OAuth store

## Streamable HTTP setup

Create the Zendesk OAuth client for the fixed deployment subdomain and set its
callback URL exactly to:

```text
https://your-internal-mcp.example/oauth/callback
```

Copy the HTTP environment example and generate a 32-byte canonical base64url
encryption key:

```bash
cp .env.example .env
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\\n'
chmod 0600 .env
```

Set the generated value as `OAUTH_ENCRYPTION_KEY`, then configure:

- `PUBLIC_BASE_URL`: canonical public origin, with no path or query
- `ZENDESK_SUBDOMAIN`: one fixed Zendesk subdomain
- `ZENDESK_OAUTH_CLIENT_ID` and `ZENDESK_OAUTH_CLIENT_SECRET`
- `OAUTH_DB_PATH`: absolute SQLite path (`/data/oauth.sqlite` in Compose)
- `MCP_ALLOWED_HOSTS`, `HOST`, and `PORT` as needed
- `SELF_SERVICE_ENROLLMENT_ENABLED`: exact `true` or `false`; defaults to
  `false`

The server never derives its callback from `Host` or forwarded headers.
`GET /healthz` is public and never contacts Zendesk. `POST /mcp` is protected;
authenticated `GET /mcp` and `DELETE /mcp` return `405` because each POST uses
a fresh stateless transport.

Build and start locally:

```bash
npm install
npm run build
npm run start:http
```

### Optional self-service enrollment

Enable self-service only when the canonical HTTPS origin is restricted to the
intended colleagues through Tailscale access policy. Tailscale is the network
boundary; the application does not infer or verify Tailscale identity from
forwarded headers.

```dotenv
SELF_SERVICE_ENROLLMENT_ENABLED=true
```

After restarting the service, an internal colleague opens:

```text
https://your-internal-mcp.example/create-account
```

The page redirects through the same fixed Zendesk OAuth client. Only an
authoritative Zendesk `agent` or `admin` identity can complete enrollment; an
end user receives no MCP account or bearer. After OAuth succeeds, the browser
shows the personal bearer and a Codex configuration fragment once. The bearer
is not recoverable from the database or a second page load, so it must be
copied immediately to the colleague's protected Codex configuration.

One Zendesk identity can have only one internal account. A duplicate,
previously revoked, lost-bearer, or reauthorization case must be handled with
the administrator commands below. Disable new self-service enrollment at any
time by setting the flag to `false` and restarting; existing linked bearers
continue to work.

### Create and link a user

```bash
npm run admin -- create --label "Martin"
```

The command prints a user ID, one MCP bearer, and one short-lived link. The
bearer is shown once and cannot be retrieved later. Transfer the link and
bearer separately through approved secure channels:

1. The colleague opens the link and authorizes the fixed Zendesk OAuth client.
2. The callback exchanges the code and establishes identity through
   `users/me`.
3. After linking succeeds, give that colleague their unique MCP bearer.

List non-secret metadata:

```bash
npm run admin -- list
```

When a refresh grant becomes terminal, the mapping changes to
`reauthorization_required` and MCP access fails closed. Generate a fresh
one-time link without changing or reprinting the bearer:

```bash
npm run admin -- reauthorize --user <uuid>
```

Revoke local access immediately:

```bash
npm run admin -- revoke --user <uuid>
```

Optionally attempt one bounded upstream Zendesk revocation after the local
commit:

```bash
npm run admin -- revoke --user <uuid> --upstream
```

The command reports `succeeded`, `failed`, or `unavailable`; there is no
background retry or outbox.

### Codex MCP configuration

```toml
[mcp_servers.zendesk]
url = "https://your-internal-mcp.example/mcp"
bearer_token_env_var = "ZENDESK_MCP_BEARER_TOKEN"
```

Set only that user's bearer on the client:

```bash
export ZENDESK_MCP_BEARER_TOKEN='the-user-specific-bearer'
```

For a Codex desktop configuration that must survive a computer restart without
depending on a launch environment variable, use the one-time fragment shown by
the enrollment page:

```toml
[mcp_servers.zendesk]
url = "https://your-internal-mcp.example/mcp"

[mcp_servers.zendesk.http_headers]
Authorization = "Bearer zmcp_the-user-specific-bearer"
```

This stores the bearer as plaintext in the user's protected Codex config, so
the file must not be shared or committed.

Do not copy the Zendesk OAuth client secret, encryption key, database, access
token, or refresh token to MCP clients.

Verify MCP initialization without calling Zendesk:

```bash
MCP_URL=https://your-internal-mcp.example/mcp \
MCP_BEARER_TOKEN="$ZENDESK_MCP_BEARER_TOKEN" \
npm run smoke:http
```

`npm run smoke:http` calls Zendesk only when the explicit `--zendesk` option is
added. The self-contained `npm run smoke:http:local` uses fake encrypted
credentials and asserts that zero Zendesk requests occur.

## Docker Compose

Compose publishes plain HTTP on host loopback by default. Terminate HTTPS in
the existing trusted reverse proxy and do not expose the plain HTTP port
directly. Before enabling self-service, verify that the HTTPS origin is not
reachable outside the approved Tailscale users.

```bash
docker compose config
docker compose up -d --build --wait
docker compose ps
docker compose logs --tail=50 zendesk-mcp
```

The runtime runs as the unprivileged `node` user with a read-only root
filesystem, `no-new-privileges`, writable tmpfs at `/tmp`, and one named volume
mounted at `/data`. Restarting the service preserves `/data/oauth.sqlite`.

Run administration commands inside the running service so they use the same
environment and `/data` volume as the server:

```bash
docker compose exec -T zendesk-mcp npm run admin -- create --label "Martin"
docker compose exec -T zendesk-mcp npm run admin -- list
docker compose exec -T zendesk-mcp npm run admin -- reauthorize --user <uuid>
docker compose exec -T zendesk-mcp npm run admin -- revoke --user <uuid>
```

### Backup

Keep the encryption key separately; a database backup without its matching key
cannot be opened. Use the SQLite online backup command rather than copying a
live database and its WAL files:

```bash
backup_name="oauth-backup-$(date -u +%Y%m%d-%H%M%S).sqlite"
docker compose exec -T zendesk-mcp npm run admin -- \
  backup --output "/data/backups/$backup_name"
docker compose cp "zendesk-mcp:/data/backups/$backup_name" "./$backup_name"
chmod 0600 "./$backup_name"
```

The backup is created mode `0600`. Protect, rotate, and test-restores of both
the copied database backup and encryption key using normal infrastructure
controls. The command leaves the original backup under `/data/backups`; remove
that exact in-volume copy after verifying the protected host copy.

## Migration from the shared HTTP identity

1. Back up the current deployment configuration.
2. Configure the Zendesk OAuth client, fixed callback, encryption key, and
   persistent store.
3. Deploy the new image without retiring the old credentials.
4. Create and complete one link per colleague.
5. Update each MCP client to its unique bearer and verify initialization.
6. Verify a non-destructive Zendesk read under each expected identity.
7. Revoke the old shared MCP bearer and retire legacy Zendesk credentials only
   after the separate live cutover is approved.

No migration automatically imports the shared API-token identity.

### Rollback

Preserve the OAuth database and encryption key, stop the new container, and
restore the previously pinned image and configuration. Restore the previous
shared HTTP bearer/API-token settings only while Zendesk still permits them
and only under the organization's normal approval process. A rollback does not
delete the new OAuth store or revoke upstream grants; perform either action
separately if required.

## Stdio compatibility

Copy `.env.stdio.example`, set `ZENDESK_SUBDOMAIN`, `ZENDESK_EMAIL`, and
`ZENDESK_API_KEY`, then run:

```bash
npm run build
npm start
```

The equivalent MCP client command remains `node /absolute/path/dist/index.js`.
Stdio API-token compatibility is temporary because of Zendesk's published
retirement schedule.

## MCP surface

Prompts:

- `analyze-ticket`
- `draft-ticket-response`

Tools:

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

Resources:

- `zendesk://knowledge-base`

`get_ticket_comments` includes normalized attachment metadata. File bytes are
not embedded in MCP responses.

## Support

Use [GitHub Issues](https://github.com/eramba/zendesk-mcp-server/issues) for
bugs and feature requests.
