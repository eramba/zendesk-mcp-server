# Zendesk Streamable HTTP Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an authenticated stateless Streamable HTTP transport, package it with Docker Compose, and deploy one shared Zendesk MCP service to `dev-server` at `http://dev-server:38184/mcp` without breaking stdio.

**Architecture:** Preserve `src/index.ts` as the stdio composition root and extract only shared environment parsing. Add a separate HTTP composition root that creates a fresh `McpServer` and stateless `StreamableHTTPServerTransport` for every authenticated POST while sharing the immutable `ZendeskClient`. Build that process into a non-root, read-only container published only on the `dev-server` Tailscale address.

**Tech Stack:** TypeScript 5.9, Node.js 22, `@modelcontextprotocol/sdk` 1.26, Express supplied through the SDK server helper, Node test runner, Docker, Docker Compose, Tailscale.

## Global Constraints

- Keep `npm start` and the existing stdio MCP contract backward-compatible.
- Use stateless Streamable HTTP; do not add session storage, resumability, OAuth, TLS termination, Apache, or a registry pipeline.
- Require one shared `MCP_BEARER_TOKEN` for every `/mcp` method and never log credentials or token values.
- Keep Zendesk credentials only in the uncommitted server `.env` with mode `0600`.
- Default container listener: `0.0.0.0:3000`.
- Default host publication: `100.83.206.45:38184`, never `0.0.0.0:38184`.
- Allowed deployment Host values: `dev-server`, `dev-server.tail22145b.ts.net`, `100.83.206.45`, `localhost`, and `127.0.0.1`.
- `/healthz` is process health only and must not call Zendesk.
- Live verification may initialize MCP, list tools, and call one read-only Zendesk tool; it must not create or modify a ticket.
- Use the optimized TDD loop: state the production change, save only the test, prove RED, implement, and prove GREEN.
- Execute inline single-agent because the files form one compact lifecycle with overlapping configuration and verification boundaries.

## File Structure

- Create `src/config.ts`: shared Zendesk environment parsing plus HTTP-only configuration validation.
- Modify `src/index.ts`: consume `readZendeskConfig()` while preserving stdio startup.
- Create `src/http-app.ts`: authenticated health and stateless MCP routes; no process or deployment concerns.
- Create `src/http.ts`: HTTP composition root, listener startup, and bounded signal shutdown.
- Create `test/config.test.mjs`: configuration defaults and validation.
- Create `test/http.test.mjs`: health, host protection, bearer auth, method handling, and official SDK round trip.
- Modify `package.json`: HTTP development/start scripts and the reusable smoke command.
- Create `Dockerfile`: multi-stage Node 22 build and non-root runtime.
- Create `.dockerignore`: secret and development-artifact exclusions.
- Create `docker-compose.yml`: Tailscale-only port publication, health, restart, read-only filesystem, and env loading.
- Modify `.env.example`: HTTP server and Compose settings with non-secret example values.
- Create `scripts/smoke-http.mjs`: authenticated initialize/list-tools check with an optional read-only Zendesk call.
- Modify `README.md`: stdio/HTTP usage, Compose operations, Codex configuration, token installation, and security boundary.

---

### Task 1: Shared Configuration Without Stdio Regression

**Files:**
- Create: `test/config.test.mjs`
- Create: `src/config.ts`
- Modify: `src/index.ts`

**Interfaces:**
- Consumes: `process.env` or an injected `Readonly<Record<string, string | undefined>>`.
- Produces: `readZendeskConfig(env?): ZendeskConfig` and `readHttpConfig(env?): HttpConfig`.
- `ZendeskConfig`: `{ subdomain: string; email: string; apiKey: string }`.
- `HttpConfig`: `{ host: string; port: number; bearerToken: string; allowedHosts: string[] }`.

- [ ] **Step 1: State the production change without editing production files**

Record in the task workpad: "Extract environment parsing into `src/config.ts`; keep stdio behavior unchanged and add strict HTTP defaults and validation for the later entrypoint."

- [ ] **Step 2: Add the failing configuration tests only**

Create `test/config.test.mjs`:

```js
import assert from 'node:assert/strict'
import test from 'node:test'

import { readHttpConfig, readZendeskConfig } from '../dist/config.js'

const ZENDESK_ENV = {
  ZENDESK_SUBDOMAIN: 'example',
  ZENDESK_EMAIL: 'agent@example.test',
  ZENDESK_API_KEY: 'zendesk-token',
}

test('readZendeskConfig returns the required values', () => {
  assert.deepEqual(readZendeskConfig(ZENDESK_ENV), {
    subdomain: 'example',
    email: 'agent@example.test',
    apiKey: 'zendesk-token',
  })
})

test('readZendeskConfig reports every missing key without values', () => {
  assert.throws(
    () => readZendeskConfig({ ZENDESK_SUBDOMAIN: 'example' }),
    /Missing required environment variables: ZENDESK_EMAIL, ZENDESK_API_KEY/,
  )
})

test('readHttpConfig applies safe local defaults', () => {
  assert.deepEqual(readHttpConfig({ MCP_BEARER_TOKEN: 'server-secret' }), {
    host: '0.0.0.0',
    port: 3000,
    bearerToken: 'server-secret',
    allowedHosts: ['localhost', '127.0.0.1'],
  })
})

test('readHttpConfig parses explicit deployment values', () => {
  assert.deepEqual(
    readHttpConfig({
      HOST: '127.0.0.1',
      PORT: '38184',
      MCP_BEARER_TOKEN: 'server-secret',
      MCP_ALLOWED_HOSTS: 'dev-server, 100.83.206.45,dev-server',
    }),
    {
      host: '127.0.0.1',
      port: 38184,
      bearerToken: 'server-secret',
      allowedHosts: ['dev-server', '100.83.206.45'],
    },
  )
})

test('readHttpConfig rejects a missing bearer token', () => {
  assert.throws(
    () => readHttpConfig({}),
    /Missing required environment variable: MCP_BEARER_TOKEN/,
  )
})

test('readHttpConfig rejects invalid TCP ports', () => {
  for (const port of ['', '0', '65536', '3.5', 'not-a-port']) {
    assert.throws(
      () => readHttpConfig({ MCP_BEARER_TOKEN: 'server-secret', PORT: port }),
      /PORT must be an integer between 1 and 65535/,
    )
  }
})

test('readHttpConfig rejects an explicitly empty allowed-host set', () => {
  assert.throws(
    () =>
      readHttpConfig({
        MCP_BEARER_TOKEN: 'server-secret',
        MCP_ALLOWED_HOSTS: ' , ',
      }),
    /MCP_ALLOWED_HOSTS must contain at least one hostname/,
  )
})
```

- [ ] **Step 3: Run the narrow test and prove RED**

Run:

```bash
npm run build && node --test test/config.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `dist/config.js`.

- [ ] **Step 4: Add the minimal shared configuration module**

Create `src/config.ts`:

```ts
export type Environment = Readonly<Record<string, string | undefined>>;

export type ZendeskConfig = {
  subdomain: string;
  email: string;
  apiKey: string;
};

export type HttpConfig = {
  host: string;
  port: number;
  bearerToken: string;
  allowedHosts: string[];
};

const ZENDESK_KEYS = [
  "ZENDESK_SUBDOMAIN",
  "ZENDESK_EMAIL",
  "ZENDESK_API_KEY",
] as const;

function isBlank(value: string | undefined): boolean {
  return value === undefined || value.trim() === "";
}

export function readZendeskConfig(
  env: Environment = process.env,
): ZendeskConfig {
  const missing = ZENDESK_KEYS.filter((key) => isBlank(env[key]));
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }

  return {
    subdomain: env.ZENDESK_SUBDOMAIN as string,
    email: env.ZENDESK_EMAIL as string,
    apiKey: env.ZENDESK_API_KEY as string,
  };
}

export function readHttpConfig(env: Environment = process.env): HttpConfig {
  if (isBlank(env.MCP_BEARER_TOKEN)) {
    throw new Error("Missing required environment variable: MCP_BEARER_TOKEN");
  }

  const rawPort = env.PORT ?? "3000";
  if (!/^\d+$/.test(rawPort)) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }

  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }

  const rawAllowedHosts = env.MCP_ALLOWED_HOSTS ?? "localhost,127.0.0.1";
  const allowedHosts = [
    ...new Set(
      rawAllowedHosts
        .split(",")
        .map((host) => host.trim())
        .filter(Boolean),
    ),
  ];

  if (allowedHosts.length === 0) {
    throw new Error("MCP_ALLOWED_HOSTS must contain at least one hostname");
  }

  return {
    host: env.HOST?.trim() || "0.0.0.0",
    port,
    bearerToken: env.MCP_BEARER_TOKEN as string,
    allowedHosts,
  };
}
```

- [ ] **Step 5: Rewire stdio to the shared parser**

Replace the local `Env` type and `readEnv()` function in `src/index.ts`; the complete file becomes:

```ts
#!/usr/bin/env node
import "dotenv/config";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readZendeskConfig } from "./config.js";
import { buildZendeskServer } from "./server.js";
import { ZendeskClient } from "./zendesk-client.js";

async function main() {
  const config = readZendeskConfig();
  const client = new ZendeskClient(
    config.subdomain,
    config.email,
    config.apiKey,
  );
  const server = buildZendeskServer(client);

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("Zendesk MCP server (TypeScript) running on stdio");
}

main().catch((error) => {
  console.error("Fatal server error:", error);
  process.exit(1);
});
```

- [ ] **Step 6: Re-run the narrow and existing stdio tests for GREEN**

Run:

```bash
npm run build && node --test test/config.test.mjs test/server-instructions.test.mjs
```

Expected: all configuration tests and the existing in-memory MCP initialization test PASS.

- [ ] **Step 7: Commit the configuration slice**

```bash
git add src/config.ts src/index.ts test/config.test.mjs
git commit -m "refactor: share MCP environment parsing"
```

---

### Task 2: Authenticated Stateless Streamable HTTP

**Files:**
- Create: `test/http.test.mjs`
- Create: `src/http-app.ts`
- Create: `src/http.ts`
- Modify: `package.json`

**Interfaces:**
- Consumes: `HttpConfig`, one `ZendeskClient`, and the existing `buildZendeskServer(client)` factory.
- Produces: `createHttpApp(options): Express`, `npm run dev:http`, and `npm run start:http`.
- `HttpAppOptions`: `{ host: string; allowedHosts: string[]; bearerToken: string; client: ZendeskClient; serverFactory?: typeof buildZendeskServer }`.

- [ ] **Step 1: State the production change without editing production files**

Record: "Add an authenticated HTTP app that creates one stateless MCP server/transport per POST and a process entrypoint that shuts down on SIGINT or SIGTERM."

- [ ] **Step 2: Add the failing HTTP tests only**

Create `test/http.test.mjs`:

```js
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request } from 'node:http'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { createHttpApp } from '../dist/http-app.js'
import { buildZendeskServer } from '../dist/server.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

const BEARER_TOKEN = 'test-bearer-token'

function makeApp(overrides = {}) {
  return createHttpApp({
    host: '127.0.0.1',
    allowedHosts: ['127.0.0.1', 'localhost'],
    bearerToken: BEARER_TOKEN,
    client: new ZendeskClient('example', 'agent@example.test', 'zendesk-token'),
    ...overrides,
  })
}

async function listen(t, app) {
  const listener = app.listen(0, '127.0.0.1')
  await once(listener, 'listening')

  t.after(async () => {
    if (!listener.listening) return
    await new Promise((resolve, reject) => {
      listener.close((error) => (error ? reject(error) : resolve()))
    })
  })

  const address = listener.address()
  assert.ok(address && typeof address === 'object')
  return `http://127.0.0.1:${address.port}`
}

function rawRequest(url, { method = 'GET', headers = {} } = {}) {
  const target = new URL(url)
  return new Promise((resolve, reject) => {
    const req = request(
      {
        hostname: target.hostname,
        port: target.port,
        path: target.pathname,
        method,
        headers,
      },
      (res) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => {
          body += chunk
        })
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }))
      },
    )
    req.on('error', reject)
    req.end()
  })
}

test('healthz is public and does not require Zendesk access', async (t) => {
  const baseUrl = await listen(t, makeApp())
  const response = await fetch(`${baseUrl}/healthz`)

  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { ok: true })
})

test('mcp rejects missing and incorrect bearer tokens before building a server', async (t) => {
  let serversBuilt = 0
  const baseUrl = await listen(
    t,
    makeApp({
      serverFactory: (client) => {
        serversBuilt += 1
        return buildZendeskServer(client)
      },
    }),
  )

  for (const authorization of [undefined, 'Bearer wrong-token', 'Basic abc']) {
    const headers = { 'Content-Type': 'application/json' }
    if (authorization) headers.Authorization = authorization
    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers,
      body: '{}',
    })
    assert.equal(response.status, 401)
    assert.equal(response.headers.get('www-authenticate'), 'Bearer')
  }

  assert.equal(serversBuilt, 0)
})

test('host validation rejects an unapproved hostname', async (t) => {
  const baseUrl = await listen(t, makeApp())
  const response = await rawRequest(`${baseUrl}/healthz`, {
    headers: { Host: 'evil.example' },
  })

  assert.equal(response.status, 403)
})

test('authenticated GET and DELETE mcp requests return 405', async (t) => {
  const baseUrl = await listen(t, makeApp())

  for (const method of ['GET', 'DELETE']) {
    const response = await fetch(`${baseUrl}/mcp`, {
      method,
      headers: { Authorization: `Bearer ${BEARER_TOKEN}` },
    })
    assert.equal(response.status, 405)
    assert.equal(response.headers.get('allow'), 'POST')
  }
})

test('unexpected request setup failures return a protocol-shaped 500', async (t) => {
  const baseUrl = await listen(
    t,
    makeApp({
      serverFactory: () => {
        throw new Error('test setup failure')
      },
    }),
  )
  const response = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${BEARER_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: '{}',
  })

  assert.equal(response.status, 500)
  assert.deepEqual(await response.json(), {
    jsonrpc: '2.0',
    error: { code: -32603, message: 'Internal server error' },
    id: null,
  })
})

test('official SDK client initializes and every POST gets a fresh MCP server', async (t) => {
  let serversBuilt = 0
  let postsSent = 0
  const baseUrl = await listen(
    t,
    makeApp({
      serverFactory: (client) => {
        serversBuilt += 1
        return buildZendeskServer(client)
      },
    }),
  )

  const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
    requestInit: {
      headers: { Authorization: `Bearer ${BEARER_TOKEN}` },
    },
    fetch: async (input, init) => {
      if (init?.method === 'POST') postsSent += 1
      return fetch(input, init)
    },
  })
  const client = new Client({ name: 'http-test-client', version: '1.0.0' })

  await client.connect(transport)
  try {
    const result = await client.listTools()
    const names = result.tools.map((tool) => tool.name)
    assert.ok(names.includes('get_ticket'))
    assert.ok(names.includes('create_ticket_comment'))
    assert.ok(postsSent >= 2)
    assert.equal(serversBuilt, postsSent)
  } finally {
    await client.close()
  }
})
```

- [ ] **Step 3: Run the narrow test and prove RED**

Run:

```bash
npm run build && node --test test/http.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `dist/http-app.js`.

- [ ] **Step 4: Implement the HTTP application**

Create `src/http-app.ts`:

```ts
import { timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { buildZendeskServer } from "./server.js";
import { ZendeskClient } from "./zendesk-client.js";

export type HttpAppOptions = {
  host: string;
  allowedHosts: string[];
  bearerToken: string;
  client: ZendeskClient;
  serverFactory?: typeof buildZendeskServer;
};

function bearerMatches(header: string | undefined, expected: string): boolean {
  if (!header) return false;
  const match = /^Bearer ([^\s]+)$/i.exec(header);
  if (!match) return false;

  const actualBuffer = Buffer.from(match[1], "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  return (
    actualBuffer.length === expectedBuffer.length &&
    timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

export function createHttpApp({
  host,
  allowedHosts,
  bearerToken,
  client,
  serverFactory = buildZendeskServer,
}: HttpAppOptions) {
  const app = createMcpExpressApp({ host, allowedHosts });

  app.get("/healthz", (_req, res) => {
    res.status(200).json({ ok: true });
  });

  app.use("/mcp", (req, res, next) => {
    if (!bearerMatches(req.headers.authorization, bearerToken)) {
      res.setHeader("WWW-Authenticate", "Bearer");
      res.status(401).json({
        jsonrpc: "2.0",
        error: { code: -32001, message: "Unauthorized" },
        id: null,
      });
      return;
    }
    next();
  });

  app.get("/mcp", (_req, res) => {
    res.setHeader("Allow", "POST");
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed" },
      id: null,
    });
  });

  app.delete("/mcp", (_req, res) => {
    res.setHeader("Allow", "POST");
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed" },
      id: null,
    });
  });

  app.post("/mcp", async (req, res) => {
    let server: ReturnType<typeof buildZendeskServer> | undefined;
    let transport: StreamableHTTPServerTransport | undefined;
    let closed = false;

    const closeResources = async () => {
      if (closed) return;
      closed = true;
      if (transport) await transport.close().catch(() => undefined);
      if (server) await server.close().catch(() => undefined);
    };

    res.once("close", () => {
      void closeResources();
    });

    try {
      server = serverFactory(client);
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      await closeResources();
      const message = error instanceof Error ? error.message : "Unknown error";
      console.error("Error handling MCP request:", message);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  return app;
}
```

- [ ] **Step 5: Implement the HTTP composition root and bounded shutdown**

Create `src/http.ts`:

```ts
#!/usr/bin/env node
import "dotenv/config";
import { readHttpConfig, readZendeskConfig } from "./config.js";
import { createHttpApp } from "./http-app.js";
import { ZendeskClient } from "./zendesk-client.js";

function main() {
  const zendeskConfig = readZendeskConfig();
  const httpConfig = readHttpConfig();
  const client = new ZendeskClient(
    zendeskConfig.subdomain,
    zendeskConfig.email,
    zendeskConfig.apiKey,
  );
  const app = createHttpApp({
    host: httpConfig.host,
    allowedHosts: httpConfig.allowedHosts,
    bearerToken: httpConfig.bearerToken,
    client,
  });

  const listener = app.listen(httpConfig.port, httpConfig.host, () => {
    console.error(
      `Zendesk MCP Streamable HTTP server listening on ${httpConfig.host}:${httpConfig.port}`,
    );
  });

  listener.on("error", (error) => {
    console.error("HTTP listener error:", error.message);
    process.exitCode = 1;
  });

  let shuttingDown = false;
  const shutdown = (signal: NodeJS.Signals) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.error(`Received ${signal}; stopping HTTP listener`);

    const timer = setTimeout(() => {
      console.error("HTTP shutdown grace period expired");
      listener.closeAllConnections();
      process.exitCode = 1;
    }, 10_000);
    timer.unref();

    listener.close((error) => {
      clearTimeout(timer);
      if (error) {
        console.error("HTTP shutdown error:", error.message);
        process.exitCode = 1;
      }
    });
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown error";
  console.error("Fatal HTTP server error:", message);
  process.exit(1);
}
```

- [ ] **Step 6: Add HTTP scripts without changing stdio scripts**

Add these entries to the existing `scripts` object in `package.json`:

```json
"dev:http": "tsx src/http.ts",
"start:http": "node dist/http.js"
```

Keep `dev`, `start`, `test`, and `check` unchanged.

- [ ] **Step 7: Run the HTTP test and complete suite for GREEN**

Run:

```bash
npm run build && node --test test/http.test.mjs
npm run check
npm test
```

Expected: HTTP tests PASS, type checking PASS, and all existing tests PASS.

- [ ] **Step 8: Commit the HTTP transport slice**

```bash
git add src/http-app.ts src/http.ts test/http.test.mjs package.json package-lock.json
git commit -m "feat: add authenticated HTTP MCP transport"
```

`package-lock.json` is staged only if the package script edit causes npm to rewrite it; no dependency addition is expected.

---

### Task 3: Docker Image and Compose Contract

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `docker-compose.yml`
- Modify: `.env.example`

**Interfaces:**
- Consumes: `npm run build`, `npm run start:http`, and server `.env`.
- Produces: service `zendesk-mcp`, image target `runtime`, container port `3000`, and host defaults `100.83.206.45:38184`.

- [ ] **Step 1: Prove the deployment contract is absent**

Run:

```bash
docker compose config
```

Expected: FAIL because no Compose configuration file exists.

- [ ] **Step 2: Add the multi-stage image**

Create `Dockerfile`:

```dockerfile
FROM node:22-alpine AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine AS runtime

ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build --chown=node:node /app/dist ./dist

USER node
EXPOSE 3000
CMD ["node", "dist/http.js"]
```

- [ ] **Step 3: Exclude secrets and development-only content from the image context**

Create `.dockerignore`:

```text
.git
.gitignore
.env
.env.*
node_modules
dist
coverage
.idea
.DS_Store
docs
test
```

- [ ] **Step 4: Add the Compose service**

Create `docker-compose.yml`:

```yaml
services:
  zendesk-mcp:
    build:
      context: .
      target: runtime
    init: true
    restart: unless-stopped
    env_file:
      - ${MCP_ENV_FILE:-.env}
    environment:
      HOST: 0.0.0.0
      PORT: 3000
    ports:
      - "${MCP_BIND_ADDRESS:-100.83.206.45}:${MCP_HOST_PORT:-38184}:3000"
    healthcheck:
      test:
        - CMD
        - node
        - -e
        - "fetch('http://127.0.0.1:3000/healthz').then((response) => { if (!response.ok) process.exit(1) }).catch(() => process.exit(1))"
      interval: 10s
      timeout: 3s
      retries: 5
      start_period: 5s
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    stop_grace_period: 15s
```

- [ ] **Step 5: Extend the environment example**

Append to `.env.example`:

```dotenv
MCP_BEARER_TOKEN=replace-with-64-random-hex-characters
MCP_ALLOWED_HOSTS=dev-server,dev-server.tail22145b.ts.net,100.83.206.45,localhost,127.0.0.1
MCP_BIND_ADDRESS=100.83.206.45
MCP_HOST_PORT=38184
```

- [ ] **Step 6: Validate and build the deployment artifacts**

Run:

```bash
MCP_ENV_FILE=.env.example MCP_BIND_ADDRESS=127.0.0.1 docker compose config
docker build --target runtime -t zendesk-mcp-server:local .
```

Expected: Compose renders one `zendesk-mcp` service with `127.0.0.1:38184:3000`; Docker builds the runtime image successfully and the final image runs as user `node`.

- [ ] **Step 7: Commit the packaging slice**

```bash
git add Dockerfile .dockerignore docker-compose.yml .env.example
git commit -m "build: add Docker Compose deployment"
```

---

### Task 4: Reusable Smoke Client and Operator Documentation

**Files:**
- Create: `scripts/smoke-http.mjs`
- Modify: `package.json`
- Modify: `README.md`

**Interfaces:**
- Consumes: `MCP_URL`, client-side `MCP_BEARER_TOKEN`, and optional CLI flag `--zendesk`.
- Produces: `npm run smoke:http` with JSON summary `{ ok, toolCount, zendeskRead }` and no ticket content or token output.

- [ ] **Step 1: Prove the smoke command and URL deployment documentation are absent**

Run:

```bash
npm run smoke:http
rg -n "bearer_token_env_var|docker compose up -d --build|38184" README.md
```

Expected: the npm command is missing and `rg` finds no complete URL deployment instructions.

- [ ] **Step 2: Add the smoke client**

Create `scripts/smoke-http.mjs`:

```js
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

function requiredEnv(name) {
  const value = process.env[name]
  if (!value?.trim()) throw new Error(`Missing required environment variable: ${name}`)
  return value
}

const url = new URL(requiredEnv('MCP_URL'))
const bearerToken = requiredEnv('MCP_BEARER_TOKEN')
const verifyZendesk = process.argv.includes('--zendesk')
const transport = new StreamableHTTPClientTransport(url, {
  requestInit: {
    headers: { Authorization: `Bearer ${bearerToken}` },
  },
})
const client = new Client({ name: 'zendesk-mcp-smoke', version: '1.0.0' })
let connected = false

try {
  await client.connect(transport)
  connected = true
  const tools = await client.listTools()

  if (verifyZendesk) {
    const result = await client.callTool({
      name: 'get_tickets',
      arguments: {
        page: 1,
        per_page: 1,
        sort_by: 'updated_at',
        sort_order: 'desc',
      },
    })
    if (result.isError) throw new Error('Read-only Zendesk smoke call failed')
  }

  console.log(
    JSON.stringify({
      ok: true,
      toolCount: tools.tools.length,
      zendeskRead: verifyZendesk,
    }),
  )
} finally {
  if (connected) await client.close()
}
```

- [ ] **Step 3: Register the smoke command**

Add to `package.json` scripts:

```json
"smoke:http": "node scripts/smoke-http.mjs"
```

- [ ] **Step 4: Document both transports and the deployment contract**

Add these sections to `README.md` after the existing local-development run instructions:

````markdown
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

The default deployment publishes the container only on the `dev-server` Tailscale address:

```text
http://dev-server:38184/mcp
```

Create `.env` from `.env.example`, keep it mode `0600`, set the three `ZENDESK_*` values, and generate the server token with `openssl rand -hex 32`. Then run:

```bash
docker compose config
docker compose up -d --build --wait
docker compose ps
docker compose logs --tail=50 zendesk-mcp
```

Update an existing checkout with:

```bash
git pull --ff-only origin master
docker compose up -d --build --wait
```

Do not bind the plain-HTTP service to a public interface. Tailscale supplies the encrypted network path; public exposure requires HTTPS and a separate access-control review.

### Codex URL configuration

```toml
[mcp_servers.zendesk]
url = "http://dev-server:38184/mcp"
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
MCP_URL=http://dev-server:38184/mcp npm run smoke:http
```
````

- [ ] **Step 5: Verify the smoke command validation and documentation**

Run:

```bash
node scripts/smoke-http.mjs
rg -n "bearer_token_env_var|docker compose up -d --build|100.83.206.45|38184|launchctl setenv" README.md
npm run check
```

Expected: the smoke client fails only with `Missing required environment variable: MCP_URL`; every required operational topic is found; type checking passes.

- [ ] **Step 6: Commit the operations slice**

```bash
git add scripts/smoke-http.mjs package.json package-lock.json README.md
git commit -m "docs: add HTTP MCP operations guide"
```

---

### Task 5: Integrated Local Verification

**Files:**
- Verify only; no source changes expected.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: evidence that stdio, HTTP, container security, authentication, health, MCP initialization, and shutdown work together.

- [ ] **Step 1: Run repository verification**

```bash
npm run check
npm test
git diff --check
git status --short
```

Expected: type checking and all tests PASS, diff validation is clean, and only intentional committed state remains.

- [ ] **Step 2: Revalidate Compose and rebuild from scratch**

```bash
MCP_ENV_FILE=.env.example MCP_BIND_ADDRESS=127.0.0.1 docker compose config
docker build --no-cache --target runtime -t zendesk-mcp-server:verification .
```

Expected: Compose renders the localhost override and the clean image build succeeds.

- [ ] **Step 3: Start the local smoke stack and wait for health**

```bash
MCP_ENV_FILE=.env.example \
MCP_BIND_ADDRESS=127.0.0.1 \
MCP_HOST_PORT=38184 \
docker compose -p zendesk-mcp-smoke up -d --build --wait --wait-timeout 120
```

Expected: `zendesk-mcp-smoke-zendesk-mcp-1` becomes healthy.

- [ ] **Step 4: Prove health, bearer rejection, and authenticated MCP initialization**

```bash
curl -fsS http://127.0.0.1:38184/healthz
test "$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:38184/mcp)" = "401"
MCP_URL=http://127.0.0.1:38184/mcp \
MCP_BEARER_TOKEN=replace-with-64-random-hex-characters \
npm run smoke:http
```

Expected: health returns `{"ok":true}`, unauthenticated POST is `401`, and smoke output is JSON with `ok:true`, a nonzero `toolCount`, and `zendeskRead:false`.

- [ ] **Step 5: Prove non-root, read-only runtime and graceful stop**

```bash
docker compose -p zendesk-mcp-smoke exec zendesk-mcp id
docker compose -p zendesk-mcp-smoke exec zendesk-mcp sh -c 'test ! -w /app && test -w /tmp'
docker compose -p zendesk-mcp-smoke stop -t 15 zendesk-mcp
docker compose -p zendesk-mcp-smoke ps -a
```

Expected: `id` reports the `node` user, `/app` is not writable, `/tmp` is writable, and the service stops without exceeding 15 seconds.

- [ ] **Step 6: Remove the local smoke stack**

```bash
MCP_ENV_FILE=.env.example \
MCP_BIND_ADDRESS=127.0.0.1 \
MCP_HOST_PORT=38184 \
docker compose -p zendesk-mcp-smoke down --remove-orphans
```

Expected: the smoke container and network are removed; no source or `.env` file is changed.

---

### Task 6: Publish the Verified Commit and Deploy to dev-server

**Files:**
- Local source: no new source changes.
- Remote create: `/data/zendesk-mcp-server/`
- Remote secret create: `/data/zendesk-mcp-server/.env` with mode `0600`.

**Interfaces:**
- Consumes: the fully verified branch commit, existing local `.env`, Docker on `dev-server`, and public GitHub repository `https://github.com/eramba/zendesk-mcp-server`.
- Produces: healthy service at `http://dev-server:38184/mcp` and a generated shared bearer token retrievable by the user.

- [ ] **Step 1: Recheck live prerequisites read-only**

```bash
ssh martin.horvath@dev-server "ss -ltnH"
ssh root@dev-server "docker ps --format '{{.Names}}\t{{.Ports}}'"
ssh root@dev-server "test ! -e /data/zendesk-mcp-server"
```

Expected: no listener or Docker publication uses port `38184`, services on `38181` through `38183` remain present, and the target directory does not exist. Stop for user direction if the directory already exists or `38184` is no longer free.

- [ ] **Step 2: Push the exact verified branch**

```bash
git status --short --branch
git push -u origin codex/zendesk-http-deployment
```

Expected: worktree is clean and the verified branch push succeeds.

- [ ] **Step 3: Clone and pin the verified commit on dev-server**

```bash
IMPLEMENTATION_SHA="$(git rev-parse HEAD)"
ssh root@dev-server "git clone https://github.com/eramba/zendesk-mcp-server.git /data/zendesk-mcp-server"
ssh root@dev-server "cd /data/zendesk-mcp-server && git fetch origin codex/zendesk-http-deployment && git checkout '$IMPLEMENTATION_SHA'"
```

Expected: `/data/zendesk-mcp-server` is a Git checkout detached at the exact verified implementation commit. Do not switch it to `master` until the implementation is merged.

- [ ] **Step 4: Confirm the local credential file contains only expected keys**

Run without printing values:

```bash
awk -F= 'NF && $1 !~ /^#/ { print $1 }' .env
```

Expected keys: `ZENDESK_SUBDOMAIN`, `ZENDESK_EMAIL`, and `ZENDESK_API_KEY`. Stop if other active keys are present and inspect them before copying.

- [ ] **Step 5: Transfer credentials and generate the server token without printing secrets**

```bash
scp .env root@dev-server:/data/zendesk-mcp-server/.env
ssh root@dev-server 'set -euo pipefail
cd /data/zendesk-mcp-server
chmod 600 .env
token="$(openssl rand -hex 32)"
printf "\nMCP_BEARER_TOKEN=%s\n" "$token" >> .env
printf "MCP_ALLOWED_HOSTS=dev-server,dev-server.tail22145b.ts.net,100.83.206.45,localhost,127.0.0.1\n" >> .env
printf "MCP_BIND_ADDRESS=100.83.206.45\n" >> .env
printf "MCP_HOST_PORT=38184\n" >> .env
test "$(stat -c %a .env)" = "600"'
```

Expected: `.env` contains the required server settings, remains mode `0600`, and no value appears in command output.

- [ ] **Step 6: Validate configuration and start the live service**

```bash
ssh root@dev-server 'set -euo pipefail
cd /data/zendesk-mcp-server
docker compose config >/dev/null
docker compose up -d --build --wait --wait-timeout 180
docker compose ps
docker compose logs --tail=50 zendesk-mcp'
```

Expected: image builds, service becomes healthy, and bounded logs contain no credential or bearer-token values.

- [ ] **Step 7: Prove the listener is Tailscale-only**

```bash
ssh root@dev-server "ss -ltnH | awk '\$4 ~ /:38184\$/'"
```

Expected: exactly one listener line with `100.83.206.45:38184`; there must be no `0.0.0.0:38184` or `[::]:38184` line.

- [ ] **Step 8: Prove remote authentication and one read-only Zendesk call**

```bash
test "$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://dev-server:38184/mcp)" = "401"
MCP_BEARER_TOKEN="$(ssh root@dev-server "sed -n 's/^MCP_BEARER_TOKEN=//p' /data/zendesk-mcp-server/.env")"
MCP_URL=http://dev-server:38184/mcp \
MCP_BEARER_TOKEN="$MCP_BEARER_TOKEN" \
npm run smoke:http -- --zendesk
unset MCP_BEARER_TOKEN
```

Expected: unauthenticated POST is `401`; authenticated smoke output has `ok:true`, a nonzero `toolCount`, and `zendeskRead:true`. The smoke client does not print ticket data or the token.

- [ ] **Step 9: Confirm neighboring services were not changed**

```bash
ssh root@dev-server "docker ps --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'"
```

Expected: the pre-existing services on ports `38181`, `38182`, and `38183` remain running with their original publications, alongside the new `38184` service.

- [ ] **Step 10: Hand off the client configuration and token retrieval command**

Give the user this config:

```toml
[mcp_servers.zendesk]
url = "http://dev-server:38184/mcp"
bearer_token_env_var = "ZENDESK_MCP_BEARER_TOKEN"
```

Give the user this command to retrieve the generated token directly into their own terminal when configuring this computer or another trusted host:

```bash
ssh root@dev-server "sed -n 's/^MCP_BEARER_TOKEN=//p' /data/zendesk-mcp-server/.env"
```

Remind them to restart the Codex app or service after setting `ZENDESK_MCP_BEARER_TOKEN`. Do not paste Zendesk credentials into the handoff.

---

## Final Verification Gate

Before declaring the implementation complete, re-run and capture the final outputs of:

```bash
npm run check
npm test
git diff --check
git status --short --branch
MCP_ENV_FILE=.env.example MCP_BIND_ADDRESS=127.0.0.1 docker compose config
curl -fsS http://dev-server:38184/healthz
ssh root@dev-server "cd /data/zendesk-mcp-server && docker compose ps"
ssh root@dev-server "ss -ltnH | awk '\$4 ~ /:38184\$/'"
```

Completion requires: clean committed local state, all automated checks green, valid Compose rendering, healthy remote service, exactly one Tailscale-only `38184` listener, authenticated SDK smoke success, read-only Zendesk smoke success, and unchanged neighboring services.
