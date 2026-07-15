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
