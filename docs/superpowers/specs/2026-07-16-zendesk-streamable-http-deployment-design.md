# Zendesk Streamable HTTP Deployment Design

**Date:** 2026-07-16  
**Status:** Approved in conversation; pending written-spec review

## Problem

The project currently exposes Zendesk MCP only through stdio. That works when each Codex host has a local checkout, Node.js runtime, and its own copy of the Zendesk credentials, but it cannot be configured as one shared URL-type MCP server.

Current lifecycle:

`src/index.ts -> read environment -> ZendeskClient -> buildZendeskServer -> StdioServerTransport`

The target is one Docker Compose deployment on `dev-server`, backed by one set of Zendesk credentials and usable from this computer and other Tailscale-connected Codex hosts through a Streamable HTTP URL.

## Goals

- Add MCP Streamable HTTP without breaking the existing stdio entrypoint.
- Reuse the existing Zendesk client, MCP tools, prompts, resource, and server instructions.
- Deploy with a repository-owned `Dockerfile` and `docker-compose.yml`.
- Build the image from the checkout on `dev-server`; do not require an image registry or CI pipeline.
- Publish the service on the currently free host port `38184` by default.
- Restrict network exposure to the `dev-server` Tailscale address and require bearer-token authentication.
- Store one set of Zendesk credentials only on the MCP server.
- Provide deterministic health, authentication, MCP protocol, and live Zendesk verification.

## Non-goals

- Removing or changing stdio MCP support.
- Adding OAuth, a public Internet endpoint, a new DNS name, TLS termination, or an Apache reverse proxy.
- Adding a registry-based release pipeline or automatic deployment.
- Adding server-side MCP sessions, resumability, or server-initiated notifications.
- Giving each client separate Zendesk credentials or a separate bearer token.
- Changing the behavior or schemas of existing Zendesk tools.

## Assumptions

- Client hosts can resolve `dev-server` through Tailscale and reach `100.83.206.45`.
- Tailscale provides the encrypted network path. Plain HTTP must not be reused on a public interface; public exposure would require a separate HTTPS and access-control design.
- One shared MCP bearer token is acceptable for the current trusted client set. Rotating it requires updating the server and all configured clients.
- The current local `.env` is the intended source for the initial server-side `ZENDESK_SUBDOMAIN`, `ZENDESK_EMAIL`, and `ZENDESK_API_KEY` values.

## Architecture

The existing `buildZendeskServer(client)` factory is the earliest extension point that already owns every tool, prompt, resource, capability, and server instruction. The HTTP transport will compose around that factory instead of duplicating MCP registration.

### Entrypoints and shared configuration

- `src/index.ts` remains the stdio entrypoint used by `npm start`.
- A small shared environment module parses the three required `ZENDESK_*` values for both transports.
- `src/http.ts` is the HTTP process entrypoint used by a new `npm run start:http` script. It parses HTTP-only configuration, constructs one shared `ZendeskClient`, starts the listener, and owns graceful shutdown.
- A focused HTTP application module creates the routes and accepts its configuration and `ZendeskClient` as dependencies so protocol and authentication behavior can be tested without live Zendesk access.

The HTTP lifecycle is:

`src/http.ts -> validated environment -> shared ZendeskClient -> authenticated POST /mcp -> fresh buildZendeskServer(client) + stateless StreamableHTTPServerTransport -> Zendesk API`

### Stateless Streamable HTTP

The implementation will follow the stateless Streamable HTTP pattern shipped with the installed `@modelcontextprotocol/sdk` version:

1. Accept an authenticated `POST /mcp` request.
2. Create a fresh `McpServer` through `buildZendeskServer(client)`.
3. Create a `StreamableHTTPServerTransport` with no session ID generator.
4. Connect the server and transport before handling the request.
5. Close both after the response closes.

Stateless mode fits the current request/response tools and avoids an in-memory session map, session cleanup, and cross-request transport state. A future feature that genuinely needs notifications or resumability must receive a separate stateful-transport design.

### HTTP surface

- `POST /mcp` handles Streamable HTTP MCP requests.
- `GET /mcp` and `DELETE /mcp` return protocol-shaped `405 Method Not Allowed` responses because stateless mode does not expose persistent SSE streams or session termination.
- `GET /healthz` returns a minimal process-health response without contacting Zendesk or disclosing configuration.
- `HOST` defaults to `0.0.0.0` inside the container.
- `PORT` defaults to `3000` inside the container and must be a valid TCP port.

## Authentication and network boundary

`POST /mcp`, `GET /mcp`, and `DELETE /mcp` require `Authorization: Bearer <token>`. `/healthz` remains unauthenticated so Docker can evaluate process health.

The server requires `MCP_BEARER_TOKEN` at startup. Initial deployment generates a cryptographically secure 256-bit token. Token comparison must account for different lengths and use a timing-safe comparison. Authentication failures return `401` with `WWW-Authenticate: Bearer`; logs must not contain the supplied or expected token.

The HTTP application will use the MCP SDK's hostname validation. Allowed hostnames are configurable and the deployment permits only the names needed for the Tailscale URL and local health check: `dev-server`, `dev-server.tail22145b.ts.net`, `100.83.206.45`, `localhost`, and `127.0.0.1`.

Docker publishes only the Tailscale host address by default:

`100.83.206.45:38184 -> container:3000`

The bind address and host port are overridable for future deployments, but changing the bind address to a public interface is not safe without HTTPS and a new exposure review.

## Configuration contract

The uncommitted server-side `.env` contains:

- `ZENDESK_SUBDOMAIN`
- `ZENDESK_EMAIL`
- `ZENDESK_API_KEY`
- `MCP_BEARER_TOKEN`
- optional host-port, bind-address, and allowed-host overrides

It is created with mode `0600`. The initial three Zendesk values are transferred from the existing local `.env` without printing them or committing them. `.env.example` contains placeholders only.

Each Codex client uses:

```toml
[mcp_servers.zendesk]
url = "http://dev-server:38184/mcp"
bearer_token_env_var = "ZENDESK_MCP_BEARER_TOKEN"
```

The corresponding client environment variable contains the shared MCP bearer token. URL-type MCP configuration does not forward `[mcp_servers.<name>.env]` values to the remote process, so Zendesk credentials stay exclusively in the server-side `.env`.

The deployment handoff provides the generated bearer token once for installation on trusted clients without displaying or copying any Zendesk credential. README documents how to make the client token available to Codex on macOS and Linux and notes that a running Codex app or service must be restarted after its environment changes.

## Container and Compose design

The repository will add:

- A multi-stage `Dockerfile` based on a supported Node.js 22 image. The build stage installs locked dependencies and compiles TypeScript; the runtime stage contains production dependencies and compiled output only.
- A `.dockerignore` excluding `.git`, local environment files, dependencies, build output, IDE files, and other development-only content.
- A root `docker-compose.yml` that builds the checkout, runs the HTTP entrypoint as a non-root user, enables `init`, uses `restart: unless-stopped`, mounts no source code, and loads the uncommitted `.env`.
- A healthcheck that calls `GET /healthz` inside the container.
- A read-only runtime filesystem with a temporary `/tmp` mount, provided the implementation and container smoke test prove the MCP SDK needs no other writable path.

The live checkout is `/data/zendesk-mcp-server`. Initial deployment checks out the exact implementation commit that passed local verification. After that implementation is merged, the live checkout tracks `origin/master`. The manual update contract is:

1. Fast-forward the `master` checkout from `origin/master`.
2. Reconfirm that the configured Tailscale bind address and host port are available.
3. Run `docker compose up -d --build`.
4. Confirm Compose health and inspect bounded startup logs.
5. Re-run authenticated MCP smoke verification.

## Error handling and lifecycle

- Missing Zendesk credentials, a missing bearer token, an invalid port, or an empty allowed-host set fails startup with a configuration error that names keys but never values.
- Missing or invalid bearer authorization returns `401` without constructing an MCP server or calling Zendesk.
- Disallowed or missing Host headers return `403` through the SDK's hostname protection.
- Unsupported HTTP methods return `405` in JSON-RPC error form.
- Unexpected request-handler failures return `500` in JSON-RPC error form if headers have not been sent and are logged without credentials.
- Every request owns and closes its MCP server and transport. Closing one request cannot affect another client.
- `SIGINT` and `SIGTERM` stop accepting new connections, close the HTTP listener, and then exit. In-flight requests receive a bounded grace period before forced process termination.
- `/healthz` proves only that the HTTP process is ready; live Zendesk reachability is verified separately so a Zendesk outage does not cause a container restart loop.

## Testing

Implementation will use the optimized TDD loop. For each behavioral slice, save only the test change, run the narrow test to prove a valid RED, then apply the stated production change and rerun that same test for GREEN.

Focused automated coverage will prove:

- Shared environment parsing preserves stdio behavior and rejects missing Zendesk variables.
- HTTP configuration rejects missing authentication, invalid ports, and invalid allowed-host configuration.
- `/healthz` succeeds without authorization and does not call Zendesk.
- Missing, malformed, and incorrect bearer tokens return `401` and do not construct an MCP request handler.
- Disallowed Host headers return `403`.
- Authenticated `GET /mcp` and `DELETE /mcp` return `405`.
- An authenticated official SDK Streamable HTTP client can initialize and list the existing tools.
- Multiple HTTP requests use isolated MCP server/transport instances while sharing only the stateless Zendesk client.
- Existing in-memory MCP and Zendesk-client tests remain unchanged and green.

Repository verification:

- `npm run check`
- `npm test`
- `git diff --check`
- `docker compose config`
- Build the Compose image.
- Start a local container and prove health, unauthorized rejection, authenticated MCP initialization, and clean shutdown.

Live `dev-server` verification:

- Immediately before starting Compose, port `38184` is still unused on `100.83.206.45`.
- `docker compose ps` reports the service healthy.
- The listener is present only on `100.83.206.45:38184`, not on every host interface.
- An unauthenticated MCP request returns `401`.
- An authenticated SDK client completes initialization and `tools/list` through `http://dev-server:38184/mcp`.
- One authenticated read-only Zendesk call succeeds. Deployment verification must not create or modify a ticket.
- Existing services on ports `38181`, `38182`, and `38183` remain running and unchanged.

Automated tests must not require live Zendesk credentials, the shared bearer token, Tailscale, Docker, or `dev-server` access.

## Execution mode

Use inline single-agent implementation. The work crosses one shared configuration boundary, one HTTP composition path, packaging, documentation, and focused tests. These files form one compact lifecycle and parallel implementation would introduce avoidable overlap.

The integrated result is proven by focused RED/GREEN tests, the complete local verification suite, a real container smoke test, and live read-only MCP verification after deployment.

## Compatibility and trade-offs

- Existing `npm start` and stdio clients retain their behavior.
- Stateless HTTP avoids session lifecycle complexity but cannot provide resumable streams or unsolicited server notifications. The current Zendesk server does not need either capability.
- A single bearer token is operationally simple but has one shared blast radius. Token rotation is the remedy if a client host is lost or the token is exposed.
- Binding only the Tailscale address keeps the service off public interfaces but makes Tailscale connectivity a client prerequisite.
- Building on `dev-server` is the smallest deployment contract, at the cost of slower updates and less immutable provenance than a registry image.
- `/healthz` cannot prove Zendesk availability by design; protocol and read-only Zendesk smoke checks provide that evidence without destabilizing container health.

## Acceptance criteria

- The project supports both stdio and stateless Streamable HTTP MCP transports without duplicated tool registration.
- `http://dev-server:38184/mcp` is reachable from a Tailscale-connected Codex client and rejected without the shared bearer token.
- The Docker port is bound only to `100.83.206.45` by default.
- Zendesk credentials exist only in the uncommitted server environment and are never returned to clients or logs.
- One bearer token can be installed on this computer and other trusted Codex hosts without copying Zendesk credentials.
- The Compose service builds from `/data/zendesk-mcp-server`, starts automatically, becomes healthy, and shuts down cleanly.
- Existing stdio behavior and tests remain green.
- Type checking, automated tests, Compose validation, container smoke verification, and live authenticated read-only MCP verification all pass.
