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

## Requirements

- Node.js 20+
- Zendesk API token

## Setup

```bash
npm install
cp .env.example .env
# edit .env with your credentials
npm run build
```

Run over stdio:

```bash
npm start
```

For local development:

```bash
npm run dev
```

### Streamable HTTP

Build and start the HTTP transport locally:

```bash
npm run build
MCP_BEARER_TOKEN="$(openssl rand -hex 32)" \
MCP_ALLOWED_HOSTS="localhost,127.0.0.1" \
npm run start:http
```

The endpoints are `POST /mcp` and `GET /healthz`. `GET /mcp` and `DELETE /mcp` return `405` because the server is stateless.

### Docker Compose deployment

The default deployment publishes plain HTTP only on the host loopback address, `127.0.0.1:38184`. Tailscale Serve provides the tailnet-only HTTPS endpoint:

```text
https://dev-server.tail22145b.ts.net/mcp
```

Create `.env` from `.env.example`, keep it mode `0600`, set the three `ZENDESK_*` values, and generate the server token with `openssl rand -hex 32`. Then run:

```bash
docker compose config
docker compose up -d --build --wait
docker compose ps
docker compose logs --tail=50 zendesk-mcp
sudo tailscale serve --bg http://127.0.0.1:38184
tailscale serve status
```

Update an existing checkout with:

```bash
git pull --ff-only origin master
docker compose up -d --build --wait
```

Do not bind the plain-HTTP service to a public or tailnet interface. Tailscale Serve terminates HTTPS on port `443` and proxies to the loopback-only service; tailnet grants control which clients can connect.

### Codex URL configuration

```toml
[mcp_servers.zendesk]
url = "https://dev-server.tail22145b.ts.net/mcp"
bearer_token_env_var = "ZENDESK_MCP_BEARER_TOKEN"
```

Set `ZENDESK_MCP_BEARER_TOKEN` to the shared MCP token on each trusted client. Do not copy `ZENDESK_SUBDOMAIN`, `ZENDESK_EMAIL`, or `ZENDESK_API_KEY` to clients.

For a shell-launched Codex process on macOS or Linux:

```bash
export ZENDESK_MCP_BEARER_TOKEN='the-shared-mcp-token'
```

For the macOS Codex app in the current login session:

```bash
launchctl setenv ZENDESK_MCP_BEARER_TOKEN 'the-shared-mcp-token'
```

Fully quit and reopen the Codex app after changing its environment. Linux services must receive the same variable through their service manager and be restarted.

Verify a configured endpoint without returning ticket data:

```bash
MCP_URL=https://dev-server.tail22145b.ts.net/mcp npm run smoke:http
```

## Environment variables

- `ZENDESK_SUBDOMAIN`
- `ZENDESK_EMAIL`
- `ZENDESK_API_KEY`

## Claude MCP config example

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
