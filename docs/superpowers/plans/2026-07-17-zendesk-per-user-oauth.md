# Zendesk Per-User OAuth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Streamable HTTP transport's shared bearer and shared Zendesk API-token identity with browser-based per-user OAuth while preserving stateless MCP requests, all existing tools/resources, and stdio API-token compatibility.

**Architecture:** The process is an MCP OAuth authorization/resource server for Codex and a confidential OAuth client of one fixed Zendesk subdomain. SQLite stores encrypted Zendesk grants and hashed, rotating MCP credentials; authenticated `/mcp` requests resolve a principal and construct a request-scoped OAuth `ZendeskClient`. MCP credentials never cross into Zendesk, and Zendesk credentials never leave the server.

**Tech Stack:** TypeScript 5.9, Node.js 20/22, `@modelcontextprotocol/sdk` 1.26, Express 5.2.1, `express-rate-limit` 8.2.1, `better-sqlite3` 12.11.1, AES-256-GCM, Node test runner, Docker Compose, Tailscale Serve, Zendesk OAuth authorization-code flow.

**Approved design:** `docs/superpowers/specs/2026-07-17-zendesk-per-user-oauth-design.md`

## Global Constraints

- One fixed Zendesk subdomain and one Docker Compose replica; no request-supplied subdomain or horizontally shared store.
- Keep `npm start` stdio authentication on `ZENDESK_EMAIL` plus `ZENDESK_API_KEY`; remove those values and `MCP_BEARER_TOKEN` from the final HTTP deployment.
- The final HTTP runtime has one authentication path only: OAuth discovery plus MCP access tokens. Never run shared bearer and OAuth side by side.
- Keep stateless Streamable HTTP: one fresh `McpServer` and `StreamableHTTPServerTransport` per POST; no resumability or server notifications.
- Keep all twelve current tools, both prompts, and `zendesk://knowledge-base` unchanged.
- Require exactly `zendesk:read zendesk:write` on MCP authorization and exactly `read tickets:write` upstream. Global `read` is required by Zendesk ticket audits and is the approved exception to resource-specific read scopes.
- Login transactions and MCP authorization codes expire after 10 minutes; MCP access tokens default to 900 seconds; MCP refresh generations expire after 30 days; identical refresh retries are cached for 60 seconds.
- `MCP_ACCESS_TOKEN_TTL_SECONDS` accepts only `60..3600`; `ZENDESK_HTTP_TIMEOUT_MS` defaults to `15000` and accepts only `1000..60000`.
- `PUBLIC_BASE_URL` is an origin-only HTTPS URL and is never inferred from request headers; the exact resource is `${PUBLIC_BASE_URL}/mcp` and the fixed callback is `${PUBLIC_BASE_URL}/oauth/zendesk/callback`.
- Dynamic registration accepts only public authorization-code clients using PKCE S256 and exact explicit-port HTTP loopback redirects on `127.0.0.1` or `localhost`.
- Persist only hashes of MCP bearer values, codes, state, CSRF values, and browser nonces. Encrypt Zendesk grants, login payloads, disconnect tombstones, and refresh retry responses with record-specific AES-GCM AAD.
- Never log or return authorization headers, OAuth values, email addresses, upstream response bodies, ticket content, or decrypted credentials. Public errors use a stable category/status plus a correlation ID.
- Do not blindly retry authorization-code exchange or token refresh. Retry only disconnect outbox work classified as transient.
- Use the optimized TDD loop for every behavior change: state the intended production change, save only the focused test, prove RED, implement, and prove GREEN.
- The two live mutations—one private test-ticket comment and one disposable-principal disconnect—require a named target and separate explicit approval immediately before execution.

## File Structure

- Modify `package.json` and `package-lock.json`: pin runtime dependencies and add operator scripts.
- Modify `src/config.ts`: preserve stdio parsing and add strict HTTP OAuth configuration.
- Create `src/oauth/constants.ts`: canonical scopes, lifetimes, endpoint paths, and normalized-scope helpers.
- Create `src/oauth/errors.ts`: sanitized typed upstream and reauthorization errors.
- Create `src/oauth/token-cipher.ts`: opaque-value generation, hashing, AES-GCM envelopes, and record-specific AAD.
- Create `src/oauth/store.ts`: stable storage contract, domain inputs/results, and `OAuthRegisteredClientsStore` surface.
- Create `src/oauth/sqlite-schema.ts`: transactional forward-only SQLite migration SQL only.
- Create `src/oauth/sqlite-store.ts`: `better-sqlite3` implementation of login/principal/credential transactions, MCP token lifecycle, admin queries, backup, and disconnect-outbox persistence.
- Create `src/oauth/zendesk-oauth-client.ts`: fixed-host Zendesk authorize/exchange/refresh/identity/revoke protocol.
- Create `src/oauth/zendesk-broker-provider.ts`: MCP SDK `OAuthServerProvider` implementation.
- Create `src/oauth/consent.ts`: browser-bound consent rendering and POST orchestration.
- Create `src/oauth/zendesk-callback.ts`: upstream callback, staging, identity, and atomic login finalization.
- Create `src/oauth/oauth-router.ts`: SDK handlers, corrected public-client metadata, consent/callback routes, and rate limits.
- Create `src/oauth/zendesk-client-resolver.ts`: principal lookup, single-flight refresh, CAS installation, and guarded reauthorization.
- Create `src/oauth/revocation-worker.ts`: disconnect-only leased outbox worker.
- Create `src/oauth/admin.ts`: non-model-visible sessions, family revocation, disconnect, and backup operations.
- Modify `src/zendesk-client.ts`: discriminated Basic/Bearer auth, timeout, one guarded 401 retry, and sanitized errors.
- Modify `src/http-app.ts`: OAuth routes, `requireBearerAuth`, and request-scoped client resolution.
- Create `src/http-runtime.ts`: testable OAuth dependency composition, readiness, and ordered shutdown.
- Modify `src/http.ts`: OAuth composition root, readiness, worker lifecycle, and bounded shutdown.
- Keep `src/index.ts` and `src/server.ts` behaviorally unchanged except for the new explicit Basic-auth constructor call.
- Create `test/helpers/fake-zendesk.mjs`: deterministic local upstream OAuth/API server.
- Create `test/helpers/oauth-fixture.mjs`: temporary SQLite/cipher/provider/app fixture with a fake clock.
- Create focused tests under `test/oauth-*.test.mjs`, `test/zendesk-oauth-client.test.mjs`, `test/zendesk-client-auth.test.mjs`, and `test/zendesk-client-resolver.test.mjs`; modify current config/HTTP/deployment regression tests.
- Replace `.env.example` with `.env.stdio.example` and `.env.http.example`.
- Modify `Dockerfile`, `docker-compose.yml`, `scripts/smoke-http.mjs`, and `README.md`; create `scripts/oauth-admin.mjs`.

---

### Task 0: Record a Clean Baseline Before OAuth Work

**Files:**
- No source changes.

**Interfaces:**
- Establishes the green baseline that every later TDD task preserves: current stdio behavior, 12 tools, two prompts, one resource, HTTP statelessness, and Compose syntax.

- [ ] **Step 1: Run the current non-mutating verification suite**

```bash
npm run check
npm test
git diff --check
docker compose config
```

Expected: all commands exit `0`. If any command fails, stop and create a separate diagnosis/fix task before starting OAuth work; do not attribute a pre-existing failure to this feature.

- [ ] **Step 2: Record the baseline MCP surface**

Run:

```bash
npm run build && node --test test/server-instructions.test.mjs test/http.test.mjs
```

Expected: existing initialization and HTTP tests confirm the current 12 tools, two prompts, `zendesk://knowledge-base`, fresh server-per-POST lifecycle, and public `/healthz` behavior. Record only counts and test names in the task workpad; do not record credentials or request headers.

---

### Task 1: Pin Dependencies and Parse HTTP OAuth Configuration

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Modify: `src/config.ts`
- Modify: `test/config.test.mjs`

**Interfaces:**
- Consumes: `Environment = Readonly<Record<string, string | undefined>>`.
- Produces: `readHttpOAuthConfig(env?): HttpOAuthConfig`.
- `HttpOAuthConfig` contains `host`, `port`, `allowedHosts`, `publicBaseUrl`, `issuerUrl`, `mcpResourceUrl`, `zendeskCallbackUrl`, `zendeskSubdomain`, `zendeskOAuthClientId`, `zendeskOAuthClientSecret`, `oauthEncryptionKey`, `oauthDbPath`, `mcpAccessTokenTtlSeconds`, and `zendeskHttpTimeoutMs`.
- Preserve `readZendeskConfig(env?): ZendeskConfig` and the existing `readHttpConfig()` temporarily so every intermediate commit remains green; Task 20 removes the legacy HTTP reader and its bearer path atomically.

- [ ] **Step 1: State the production change before editing production files**

Record in the task workpad:

```text
Add an independent, strictly validated HTTP OAuth configuration without changing stdio. Keep the legacy HTTP reader only until the OAuth app integration task so no intermediate commit mixes incomplete auth paths.
```

- [ ] **Step 2: Replace the HTTP configuration tests only**

Keep the two existing `readZendeskConfig` tests, keep the existing legacy `readHttpConfig` tests until Task 20, and append this complete table-driven coverage to `test/config.test.mjs`:

```js
import { readHttpConfig, readHttpOAuthConfig, readZendeskConfig } from '../dist/config.js'

const HTTP_OAUTH_ENV = {
  HOST: '127.0.0.1',
  PORT: '38184',
  MCP_ALLOWED_HOSTS: 'dev-server.tail22145b.ts.net,localhost,127.0.0.1',
  PUBLIC_BASE_URL: 'https://dev-server.tail22145b.ts.net',
  ZENDESK_SUBDOMAIN: 'example',
  ZENDESK_OAUTH_CLIENT_ID: 'oauth-client-id',
  ZENDESK_OAUTH_CLIENT_SECRET: 'oauth-client-secret',
  OAUTH_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64'),
  OAUTH_DB_PATH: '/data/oauth.sqlite',
}

test('readHttpOAuthConfig returns canonical URLs and defaults', () => {
  const config = readHttpOAuthConfig(HTTP_OAUTH_ENV)
  assert.equal(config.host, '127.0.0.1')
  assert.equal(config.port, 38184)
  assert.deepEqual(config.allowedHosts, [
    'dev-server.tail22145b.ts.net',
    'localhost',
    '127.0.0.1',
  ])
  assert.equal(config.publicBaseUrl.href, 'https://dev-server.tail22145b.ts.net/')
  assert.equal(config.issuerUrl.href, 'https://dev-server.tail22145b.ts.net/')
  assert.equal(config.mcpResourceUrl.href, 'https://dev-server.tail22145b.ts.net/mcp')
  assert.equal(
    config.zendeskCallbackUrl.href,
    'https://dev-server.tail22145b.ts.net/oauth/zendesk/callback',
  )
  assert.equal(config.zendeskSubdomain, 'example')
  assert.equal(config.oauthEncryptionKey.length, 32)
  assert.equal(config.oauthDbPath, '/data/oauth.sqlite')
  assert.equal(config.mcpAccessTokenTtlSeconds, 900)
  assert.equal(config.zendeskHttpTimeoutMs, 15000)
})

test('readHttpOAuthConfig reports every missing key without values', () => {
  assert.throws(
    () => readHttpOAuthConfig({}),
    /PUBLIC_BASE_URL, ZENDESK_SUBDOMAIN, ZENDESK_OAUTH_CLIENT_ID, ZENDESK_OAUTH_CLIENT_SECRET, OAUTH_ENCRYPTION_KEY, OAUTH_DB_PATH/,
  )
})

test('readHttpOAuthConfig rejects unsafe origins, subdomains, keys, and ranges', () => {
  const cases = [
    ['PUBLIC_BASE_URL', 'http://dev-server.tail22145b.ts.net', /HTTPS origin/],
    ['PUBLIC_BASE_URL', 'https://user:pass@dev-server.tail22145b.ts.net', /HTTPS origin/],
    ['PUBLIC_BASE_URL', 'https://dev-server.tail22145b.ts.net/path', /HTTPS origin/],
    ['PUBLIC_BASE_URL', 'https://dev-server.tail22145b.ts.net/?query=1', /HTTPS origin/],
    ['PUBLIC_BASE_URL', 'https://dev-server.tail22145b.ts.net/#fragment', /HTTPS origin/],
    ['PUBLIC_BASE_URL', 'https://other.example.test', /MCP_ALLOWED_HOSTS/],
    ['ZENDESK_SUBDOMAIN', 'two.labels', /DNS label/],
    ['ZENDESK_SUBDOMAIN', '-invalid', /DNS label/],
    ['OAUTH_ENCRYPTION_KEY', Buffer.alloc(31).toString('base64'), /32 decoded bytes/],
    ['OAUTH_DB_PATH', 'relative.sqlite', /absolute path/],
    ['MCP_ACCESS_TOKEN_TTL_SECONDS', '59', /60 and 3600/],
    ['MCP_ACCESS_TOKEN_TTL_SECONDS', '3601', /60 and 3600/],
    ['ZENDESK_HTTP_TIMEOUT_MS', '999', /1000 and 60000/],
    ['ZENDESK_HTTP_TIMEOUT_MS', '60001', /1000 and 60000/],
  ]

  for (const [key, value, expected] of cases) {
    assert.throws(
      () => readHttpOAuthConfig({ ...HTTP_OAUTH_ENV, [key]: value }),
      expected,
      String(key),
    )
  }
})
```

- [ ] **Step 3: Run the narrow test and prove RED**

Run:

```bash
npm run build && node --test test/config.test.mjs
```

Expected: FAIL because `readHttpOAuthConfig` is not exported.

- [ ] **Step 4: Install the pinned direct dependencies**

Run:

```bash
npm install --save-exact better-sqlite3@12.11.1 express@5.2.1 express-rate-limit@8.2.1
npm install --save-dev --save-exact @types/better-sqlite3@7.6.13
```

Expected: `package.json` lists exact versions, `express` is direct rather than transitive, and `package-lock.json` changes without audit fix rewrites.

- [ ] **Step 5: Add the HTTP OAuth types and parser**

Add `import { isAbsolute } from "node:path";` at the top of `src/config.ts`. Extract the listener parsing first so neither reader needs a fake bearer value, then make the legacy `readHttpConfig()` return `{ ...readListenerConfig(env), bearerToken }` as it does today. Add this exact helper before the public OAuth contract:

```ts
type ListenerConfig = {
  host: string;
  port: number;
  allowedHosts: string[];
};

function readListenerConfig(env: Environment): ListenerConfig {
  const rawPort = env.PORT ?? "3000";
  if (!/^\d+$/.test(rawPort)) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }
  const port = Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error("PORT must be an integer between 1 and 65535");
  }
  const allowedHosts = [
    ...new Set(
      (env.MCP_ALLOWED_HOSTS ?? "localhost,127.0.0.1")
        .split(",")
        .map((host) => host.trim())
        .filter(Boolean),
    ),
  ];
  if (allowedHosts.length === 0) {
    throw new Error("MCP_ALLOWED_HOSTS must contain at least one hostname");
  }
  return { host: env.HOST?.trim() || "0.0.0.0", port, allowedHosts };
}
```

Then append the following public OAuth contract:

```ts
export type HttpOAuthConfig = {
  host: string;
  port: number;
  allowedHosts: string[];
  publicBaseUrl: URL;
  issuerUrl: URL;
  mcpResourceUrl: URL;
  zendeskCallbackUrl: URL;
  zendeskSubdomain: string;
  zendeskOAuthClientId: string;
  zendeskOAuthClientSecret: string;
  oauthEncryptionKey: Buffer;
  oauthDbPath: string;
  mcpAccessTokenTtlSeconds: number;
  zendeskHttpTimeoutMs: number;
};

const HTTP_OAUTH_REQUIRED_KEYS = [
  "PUBLIC_BASE_URL",
  "ZENDESK_SUBDOMAIN",
  "ZENDESK_OAUTH_CLIENT_ID",
  "ZENDESK_OAUTH_CLIENT_SECRET",
  "OAUTH_ENCRYPTION_KEY",
  "OAUTH_DB_PATH",
] as const;

function boundedInteger(
  name: string,
  raw: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const value = raw ?? String(fallback);
  if (!/^\d+$/.test(value)) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return parsed;
}

export function readHttpOAuthConfig(
  env: Environment = process.env,
): HttpOAuthConfig {
  const missing = HTTP_OAUTH_REQUIRED_KEYS.filter((key) => isBlank(env[key]));
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }

  const publicBaseUrl = new URL(env.PUBLIC_BASE_URL as string);
  const originOnly =
    publicBaseUrl.protocol === "https:" &&
    publicBaseUrl.username === "" &&
    publicBaseUrl.password === "" &&
    publicBaseUrl.pathname === "/" &&
    publicBaseUrl.search === "" &&
    publicBaseUrl.hash === "";
  if (!originOnly) throw new Error("PUBLIC_BASE_URL must be an origin-only HTTPS origin");

  const listener = readListenerConfig(env);
  if (!listener.allowedHosts.includes(publicBaseUrl.hostname)) {
    throw new Error("PUBLIC_BASE_URL hostname must appear in MCP_ALLOWED_HOSTS");
  }

  const zendeskSubdomain = env.ZENDESK_SUBDOMAIN as string;
  if (!/^(?!-)[a-z0-9-]{1,63}(?<!-)$/i.test(zendeskSubdomain)) {
    throw new Error("ZENDESK_SUBDOMAIN must be one DNS label");
  }

  const encryptionKey = Buffer.from(env.OAUTH_ENCRYPTION_KEY as string, "base64");
  if (encryptionKey.length !== 32) {
    throw new Error("OAUTH_ENCRYPTION_KEY must decode to exactly 32 decoded bytes");
  }

  const databasePath = env.OAUTH_DB_PATH as string;
  if (!isAbsolute(databasePath)) {
    throw new Error("OAUTH_DB_PATH must be an absolute path");
  }

  return {
    host: listener.host,
    port: listener.port,
    allowedHosts: listener.allowedHosts,
    publicBaseUrl: new URL(publicBaseUrl.origin),
    issuerUrl: new URL(publicBaseUrl.origin),
    mcpResourceUrl: new URL("/mcp", publicBaseUrl),
    zendeskCallbackUrl: new URL("/oauth/zendesk/callback", publicBaseUrl),
    zendeskSubdomain: zendeskSubdomain.toLowerCase(),
    zendeskOAuthClientId: env.ZENDESK_OAUTH_CLIENT_ID as string,
    zendeskOAuthClientSecret: env.ZENDESK_OAUTH_CLIENT_SECRET as string,
    oauthEncryptionKey: encryptionKey,
    oauthDbPath: databasePath,
    mcpAccessTokenTtlSeconds: boundedInteger(
      "MCP_ACCESS_TOKEN_TTL_SECONDS",
      env.MCP_ACCESS_TOKEN_TTL_SECONDS,
      900,
      60,
      3600,
    ),
    zendeskHttpTimeoutMs: boundedInteger(
      "ZENDESK_HTTP_TIMEOUT_MS",
      env.ZENDESK_HTTP_TIMEOUT_MS,
      15000,
      1000,
      60000,
    ),
  };
}
```

- [ ] **Step 6: Prove configuration GREEN and preserve the current suite**

Run:

```bash
npm run check
npm run build && node --test test/config.test.mjs test/http.test.mjs
```

Expected: TypeScript passes and all configuration/current HTTP tests PASS.

- [ ] **Step 7: Commit the configuration foundation**

```bash
git add package.json package-lock.json src/config.ts test/config.test.mjs
git commit -m "feat: add HTTP OAuth configuration"
```

---

### Task 2: Add Canonical OAuth Constants, Sanitized Errors, and Token Encryption

**Files:**
- Create: `src/oauth/constants.ts`
- Create: `src/oauth/errors.ts`
- Create: `src/oauth/token-cipher.ts`
- Create: `test/oauth-crypto.test.mjs`

**Interfaces:**
- Produces: `MCP_SCOPES`, `MCP_SCOPE`, `ZENDESK_SCOPES`, lifecycle constants, `normalizeMcpScopes(scopes)`.
- Produces: `randomOpaque(bytes?)`, `hashOpaque(value)`, `digestBinding(value)`, and `TokenCipher`.
- `TokenCipher.encrypt(plaintext, context): EncryptedValue` and `TokenCipher.decrypt(envelope, context): string` use the same discriminated `CipherContext`.
- Produces: `ZendeskUpstreamError` and `ReauthorizationRequiredError`; their messages never contain upstream bodies.

- [ ] **Step 1: State the production change before editing production files**

```text
Create the shared security vocabulary first: exact scopes and lifetimes, opaque-value/hash helpers, record-bound AES-GCM encryption, and public-safe upstream errors.
```

- [ ] **Step 2: Add the failing crypto tests only**

Create `test/oauth-crypto.test.mjs`:

```js
import assert from 'node:assert/strict'
import test from 'node:test'

import {
  TokenCipher,
  digestBinding,
  hashOpaque,
  randomOpaque,
} from '../dist/oauth/token-cipher.js'

const key = Buffer.alloc(32, 9)
const credentialContext = {
  kind: 'zendesk_credential',
  rowId: 'credential-1',
  expiresAt: 1_800_000_000,
  subdomain: 'example',
  principalId: 'principal-1',
  credentialVersion: 4,
  principalEpoch: 2,
}

test('TokenCipher round-trips only with the exact record context', () => {
  const cipher = new TokenCipher(key)
  const encrypted = cipher.encrypt('access-secret refresh-secret', credentialContext)

  assert.equal(cipher.decrypt(encrypted, credentialContext), 'access-secret refresh-secret')
  assert.doesNotMatch(JSON.stringify(encrypted), /access-secret|refresh-secret/)

  for (const changed of [
    { ...credentialContext, rowId: 'credential-2' },
    { ...credentialContext, principalId: 'principal-2' },
    { ...credentialContext, credentialVersion: 5 },
    { ...credentialContext, principalEpoch: 3 },
    { ...credentialContext, expiresAt: 1_800_000_001 },
  ]) {
    assert.throws(() => cipher.decrypt(encrypted, changed))
  }
})

test('TokenCipher rejects wrong keys and tampering', () => {
  const cipher = new TokenCipher(key)
  const encrypted = cipher.encrypt('secret', credentialContext)
  const flip = (value) => `${value.slice(0, -1)}${value.endsWith('A') ? 'B' : 'A'}`

  assert.throws(() => new TokenCipher(Buffer.alloc(32, 8)).decrypt(encrypted, credentialContext))
  assert.throws(() => cipher.decrypt({ ...encrypted, nonce: flip(encrypted.nonce) }, credentialContext))
  assert.throws(() =>
    cipher.decrypt({ ...encrypted, ciphertext: flip(encrypted.ciphertext) }, credentialContext),
  )
  assert.throws(() => cipher.decrypt({ ...encrypted, tag: flip(encrypted.tag) }, credentialContext))
})

test('TokenCipher rejects moving every record kind across its bound dimensions', () => {
  const cipher = new TokenCipher(key)
  const contexts = [
    {
      kind: 'login', rowId: 'login-1', expiresAt: 1_800_000_000, subdomain: 'example',
      clientId: 'client-1', browserNonceHash: 'nonce-1', redirectDigest: 'redirect-1', resourceDigest: 'resource-1',
    },
    {
      kind: 'staged_grant', rowId: 'stage-1', expiresAt: 1_800_000_000, purpose: 'refresh', subdomain: 'example',
      expectedPrincipalId: 'principal-1', expectedPrincipalEpoch: 2, expectedCredentialVersion: 4,
    },
    {
      kind: 'disconnect_outbox', rowId: 'outbox-1', expiresAt: 1_800_000_000, subdomain: 'example',
      principalId: 'principal-1', credentialVersion: 4, principalEpoch: 2,
    },
    {
      kind: 'mcp_refresh_retry', rowId: 'refresh-1', expiresAt: 1_800_000_000, familyId: 'family-1',
      clientId: 'client-1', resource: 'https://example.test/mcp', scopes: 'zendesk:read zendesk:write', generation: 2,
    },
  ]
  for (const context of contexts) {
    const encrypted = cipher.encrypt('secret', context)
    assert.throws(() => cipher.decrypt(encrypted, { ...context, rowId: `${context.rowId}-moved` }))
    assert.throws(() => cipher.decrypt(encrypted, { ...context, expiresAt: context.expiresAt + 1 }))
  }
})

test('opaque values have at least 256 bits and hashes are deterministic lookup values', () => {
  const first = randomOpaque()
  const second = randomOpaque()
  assert.notEqual(first, second)
  assert.ok(Buffer.from(first, 'base64url').length >= 32)
  assert.equal(hashOpaque(first), hashOpaque(first))
  assert.notEqual(hashOpaque(first), first)
  assert.equal(digestBinding('https://localhost:1234/callback'), digestBinding('https://localhost:1234/callback'))
})

test('constructor requires exactly one 256-bit key', () => {
  assert.throws(() => new TokenCipher(Buffer.alloc(31)), /32 bytes/)
  assert.throws(() => new TokenCipher(Buffer.alloc(33)), /32 bytes/)
})
```

- [ ] **Step 3: Run the narrow test and prove RED**

Run:

```bash
npm run build && node --test test/oauth-crypto.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `dist/oauth/token-cipher.js`.

- [ ] **Step 4: Add the exact constants and scope canonicalizer**

Create `src/oauth/constants.ts`:

```ts
export const MCP_SCOPES = ["zendesk:read", "zendesk:write"] as const;
export const MCP_SCOPE = MCP_SCOPES.join(" ");
export const ZENDESK_SCOPES = [
  "read",
  "tickets:write",
] as const;

export const LOGIN_TTL_SECONDS = 10 * 60;
export const AUTHORIZATION_CODE_TTL_SECONDS = 10 * 60;
export const MCP_REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
export const MCP_REFRESH_RETRY_SECONDS = 60;
export const REFRESH_SKEW_SECONDS = 60;

export const OAUTH_PATHS = {
  authorize: "/authorize",
  token: "/token",
  register: "/register",
  revoke: "/revoke",
  consent: "/oauth/consent",
  zendeskCallback: "/oauth/zendesk/callback",
  protectedResourceMetadata: "/.well-known/oauth-protected-resource/mcp",
  authorizationServerMetadata: "/.well-known/oauth-authorization-server",
} as const;

export function normalizeMcpScopes(scopes: readonly string[]): string[] {
  const unique = [...new Set(scopes)];
  if (
    unique.length !== MCP_SCOPES.length ||
    !MCP_SCOPES.every((scope) => unique.includes(scope))
  ) {
    throw new Error(`scope must be exactly ${MCP_SCOPE}`);
  }
  return [...MCP_SCOPES];
}
```

- [ ] **Step 5: Implement record-bound AES-GCM and opaque lookup helpers**

Create `src/oauth/token-cipher.ts`:

```ts
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";

export type EncryptedValue = {
  version: 1;
  nonce: string;
  ciphertext: string;
  tag: string;
};

type BaseCipherContext = {
  rowId: string;
  expiresAt: number;
};

export type CipherContext =
  | (BaseCipherContext & {
      kind: "key_check";
    })
  | (BaseCipherContext & {
      kind: "login";
      subdomain: string;
      clientId: string;
      browserNonceHash: string;
      redirectDigest: string;
      resourceDigest: string;
    })
  | (BaseCipherContext & {
      kind: "zendesk_credential" | "disconnect_outbox";
      subdomain: string;
      principalId: string;
      credentialVersion: number;
      principalEpoch: number;
    })
  | (BaseCipherContext & {
      kind: "staged_grant";
      purpose: "login" | "refresh";
      subdomain: string;
      expectedPrincipalId: string | null;
      expectedCredentialVersion: number | null;
      expectedPrincipalEpoch: number | null;
    })
  | (BaseCipherContext & {
      kind: "mcp_refresh_retry";
      familyId: string;
      clientId: string;
      resource: string;
      scopes: string;
      generation: number;
    });

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonical(item)]),
    );
  }
  return value;
}

function aad(context: CipherContext): Buffer {
  return Buffer.from(JSON.stringify(canonical(context)), "utf8");
}

export function randomOpaque(bytes = 32): string {
  if (!Number.isSafeInteger(bytes) || bytes < 32) {
    throw new Error("opaque values require at least 32 random bytes");
  }
  return randomBytes(bytes).toString("base64url");
}

export function hashOpaque(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

export function digestBinding(value: string): string {
  return hashOpaque(value);
}

export class TokenCipher {
  readonly #key: Buffer;

  constructor(key: Buffer) {
    if (key.length !== 32) throw new Error("TokenCipher key must be exactly 32 bytes");
    this.#key = Buffer.from(key);
  }

  encrypt(plaintext: string, context: CipherContext): EncryptedValue {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.#key, nonce);
    cipher.setAAD(aad(context));
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    return {
      version: 1,
      nonce: nonce.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
    };
  }

  decrypt(envelope: EncryptedValue, context: CipherContext): string {
    if (envelope.version !== 1) throw new Error("Unsupported encrypted value version");
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.#key,
      Buffer.from(envelope.nonce, "base64url"),
    );
    decipher.setAAD(aad(context));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  }
}
```

- [ ] **Step 6: Add stable sanitized error types**

Create `src/oauth/errors.ts`:

```ts
export type ZendeskErrorCategory =
  | "unauthorized"
  | "forbidden"
  | "rate_limited"
  | "invalid_request"
  | "temporarily_unavailable"
  | "invalid_grant";

export class ZendeskUpstreamError extends Error {
  constructor(
    readonly category: ZendeskErrorCategory,
    readonly status: number | undefined,
    readonly retryable: boolean,
    readonly correlationId: string,
  ) {
    super(`Zendesk request failed (${category}; correlation ${correlationId})`);
    this.name = "ZendeskUpstreamError";
  }
}

export class ReauthorizationRequiredError extends Error {
  constructor(readonly correlationId: string) {
    super(`Zendesk authorization must be renewed with codex mcp login zendesk (correlation ${correlationId})`);
    this.name = "ReauthorizationRequiredError";
  }
}
```

- [ ] **Step 7: Prove crypto GREEN**

Run:

```bash
npm run check
npm run build && node --test test/oauth-crypto.test.mjs
```

Expected: TypeScript passes and all five crypto tests PASS.

- [ ] **Step 8: Commit the security primitives**

```bash
git add src/oauth/constants.ts src/oauth/errors.ts src/oauth/token-cipher.ts test/oauth-crypto.test.mjs
git commit -m "feat: add OAuth security primitives"
```

---

### Task 3: Create the Durable SQLite Schema and Store Lifecycle

**Files:**
- Create: `src/oauth/store.ts`
- Create: `src/oauth/sqlite-schema.ts`
- Create: `src/oauth/sqlite-store.ts`
- Create: `test/oauth-store-schema.test.mjs`

**Interfaces:**
- Produces: `OAuthStore`, `SqliteOAuthStoreOptions`, and `openSqliteOAuthStore(options): OAuthStore`.
- This opening declaration exposes `isReady()`, `assertReady()`, `recover(now)`, `backup(destination)`, and `close()`; Tasks 4–9 add their domain members in the exact code blocks that introduce their first consumer.
- All store methods are synchronous except SQLite's consistent backup API. No transaction may span an upstream `fetch` or another `await`.

- [ ] **Step 1: State the production change before editing production files**

```text
Create the complete forward-only schema and a fail-closed SQLite lifecycle with foreign keys, WAL, FULL synchronous writes, bounded busy timeout, key verification, recovery, backup, checkpoint, and filesystem permissions.
```

- [ ] **Step 2: Add the failing schema tests only**

Create `test/oauth-store-schema.test.mjs` with a temporary directory per test. The tests must use these exact assertions:

```js
import assert from 'node:assert/strict'
import { mkdtemp, readFile, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher } from '../dist/oauth/token-cipher.js'

async function fixture(t, key = Buffer.alloc(32, 4)) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-store-'))
  const path = join(directory, 'oauth.sqlite')
  const store = openSqliteOAuthStore({ path, cipher: new TokenCipher(key), now: () => 1_700_000_000 })
  t.after(() => store.close())
  return { directory, path, store }
}

test('new store migrates once with durable SQLite pragmas and restrictive modes', async (t) => {
  const { directory, path, store } = await fixture(t)
  assert.equal(store.isReady(), true)
  assert.deepEqual(store.inspectForTest().pragmas, {
    foreignKeys: 1,
    journalMode: 'wal',
    synchronous: 2,
    trustedSchema: 0,
    secureDelete: 1,
  })
  assert.equal(store.inspectForTest().schemaVersion, 1)
  assert.equal((await stat(directory)).mode & 0o777, 0o700)
  assert.equal((await stat(path)).mode & 0o777, 0o600)
})

test('migration and key check are idempotent across restart', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-reopen-'))
  const path = join(directory, 'oauth.sqlite')
  const key = Buffer.alloc(32, 5)
  openSqliteOAuthStore({ path, cipher: new TokenCipher(key) }).close()
  const reopened = openSqliteOAuthStore({ path, cipher: new TokenCipher(key) })
  t.after(() => reopened.close())
  assert.equal(reopened.inspectForTest().schemaVersion, 1)
  assert.equal(reopened.inspectForTest().migrationCount, 1)
})

test('wrong restore key and unknown newer schema fail closed', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-key-'))
  const path = join(directory, 'oauth.sqlite')
  const first = openSqliteOAuthStore({ path, cipher: new TokenCipher(Buffer.alloc(32, 6)) })
  first.close()
  assert.throws(
    () => openSqliteOAuthStore({ path, cipher: new TokenCipher(Buffer.alloc(32, 7)) }),
    /encryption key/i,
  )

  const Database = (await import('better-sqlite3')).default
  const db = new Database(path)
  db.prepare('UPDATE schema_migrations SET version = 999').run()
  db.close()
  assert.throws(
    () => openSqliteOAuthStore({ path, cipher: new TokenCipher(Buffer.alloc(32, 6)) }),
    /newer schema version/i,
  )
})

test('backup is consistent and still requires the separate encryption key', async (t) => {
  const { directory, store } = await fixture(t, Buffer.alloc(32, 8))
  const backup = join(directory, 'backup.sqlite')
  await store.backup(backup)
  const bytes = await readFile(backup)
  assert.doesNotMatch(bytes.toString('utf8'), /oauth-key-check-sentinel/)

  const restored = openSqliteOAuthStore({
    path: backup,
    cipher: new TokenCipher(Buffer.alloc(32, 8)),
  })
  restored.close()
  assert.throws(
    () => openSqliteOAuthStore({ path: backup, cipher: new TokenCipher(Buffer.alloc(32, 9)) }),
    /encryption key/i,
  )
})
```

`inspectForTest()` is an explicitly test-only, non-secret diagnostic returning numeric pragma/schema metadata; it must not return rows or ciphertext.

- [ ] **Step 3: Run the narrow test and prove RED**

Run:

```bash
npm run build && node --test test/oauth-store-schema.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `dist/oauth/sqlite-store.js`.

- [ ] **Step 4: Define the initial stable store contract**

Create `src/oauth/store.ts`:

```ts
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";

export type RecoverySummary = {
  expiredLogins: number;
  discardedStages: number;
  reclaimedClaims: number;
};

export type StoreInspection = {
  schemaVersion: number;
  migrationCount: number;
  pragmas: {
    foreignKeys: number;
    journalMode: string;
    synchronous: number;
    trustedSchema: number;
    secureDelete: number;
  };
};

export interface OAuthStore extends OAuthRegisteredClientsStore {
  isReady(): boolean;
  assertReady(): void;
  recover(now: number): RecoverySummary;
  backup(destination: string): Promise<void>;
  inspectForTest(): StoreInspection;
  close(): void;
}
```

- [ ] **Step 5: Add schema version 1 as one forward-only migration**

Create `src/oauth/sqlite-schema.ts` and define `SCHEMA_VERSION = 1`. Migration 1 must create the following exact tables and constraints in one transaction:

```sql
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

CREATE TABLE store_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_id_issued_at INTEGER NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL CHECK (token_endpoint_auth_method = 'none'),
  grant_types_json TEXT NOT NULL,
  response_types_json TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope = 'zendesk:read zendesk:write'),
  client_name TEXT,
  metadata_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE oauth_client_redirect_uris (
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE login_transactions (
  id TEXT PRIMARY KEY,
  transaction_hash TEXT NOT NULL UNIQUE,
  upstream_state_hash TEXT UNIQUE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  browser_nonce_hash TEXT NOT NULL,
  consent_csrf_hash TEXT NOT NULL,
  encrypted_payload_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('consent_pending','upstream_pending','callback_claimed','complete','failed','denied')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consented_at INTEGER,
  completed_at INTEGER
);

CREATE TABLE principals (
  id TEXT PRIMARY KEY,
  subdomain TEXT NOT NULL,
  zendesk_user_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','disconnected','reauthorization_required')),
  lifecycle_epoch INTEGER NOT NULL CHECK (lifecycle_epoch >= 1),
  disconnected_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (subdomain, zendesk_user_id)
);

CREATE TABLE zendesk_credentials (
  principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
  credential_version INTEGER NOT NULL CHECK (credential_version >= 1),
  principal_epoch INTEGER NOT NULL,
  encrypted_grant_json TEXT NOT NULL,
  access_expires_at INTEGER NOT NULL,
  refresh_expires_at INTEGER NOT NULL,
  scopes TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE staged_grants (
  id TEXT PRIMARY KEY,
  login_transaction_id TEXT REFERENCES login_transactions(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('login','refresh')),
  subdomain TEXT NOT NULL,
  expected_principal_id TEXT,
  expected_principal_epoch INTEGER,
  expected_credential_version INTEGER,
  encrypted_grant_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('staged','discard_only')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE authorization_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scopes TEXT NOT NULL,
  resource TEXT NOT NULL,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  principal_epoch INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE TABLE token_families (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  principal_id TEXT NOT NULL REFERENCES principals(id),
  principal_epoch INTEGER NOT NULL,
  scopes TEXT NOT NULL,
  resource TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  revoked_at INTEGER,
  revoke_reason TEXT
);

CREATE TABLE access_tokens (
  token_hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE refresh_token_generations (
  token_hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('current','consumed')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  successor_generation INTEGER,
  encrypted_retry_response_json TEXT,
  retry_response_expires_at INTEGER,
  UNIQUE (family_id, generation)
);

CREATE TABLE revocation_outbox (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  captured_principal_epoch INTEGER NOT NULL,
  credential_version INTEGER NOT NULL,
  encrypted_grant_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','claimed')),
  attempt_count INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  claim_owner TEXT,
  claim_expires_at INTEGER,
  retention_expires_at INTEGER NOT NULL,
  last_error_category TEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);

CREATE INDEX authorization_codes_expiry_idx ON authorization_codes(expires_at);
CREATE INDEX access_tokens_family_idx ON access_tokens(family_id);
CREATE INDEX refresh_generations_family_idx ON refresh_token_generations(family_id, generation);
CREATE INDEX revocation_outbox_due_idx ON revocation_outbox(status, next_attempt_at, claim_expires_at);
CREATE INDEX token_families_principal_idx ON token_families(principal_id, revoked_at);
CREATE INDEX staged_grants_recovery_idx ON staged_grants(status, expires_at);
```

- [ ] **Step 6: Implement open, migration, key check, recovery, backup, and close**

Create `src/oauth/sqlite-store.ts` with this exported boundary:

```ts
export type SqliteOAuthStoreOptions = {
  path: string;
  cipher: TokenCipher;
  now?: () => number;
  randomId?: () => string;
  randomToken?: (bytes?: number) => string;
  busyTimeoutMs?: number;
};

export function openSqliteOAuthStore(
  options: SqliteOAuthStoreOptions,
): OAuthStore;
```

The implementation sequence is exact:

1. Require an absolute DB path; recursively create its parent and attempt mode `0700`.
2. Open `better-sqlite3` with `timeout: busyTimeoutMs ?? 5000`.
3. Set `foreign_keys=ON`, `journal_mode=WAL`, `synchronous=FULL`, `busy_timeout`, `trusted_schema=OFF`, and `secure_delete=ON`.
4. Read the maximum schema version; reject anything greater than `SCHEMA_VERSION`; execute each missing migration and its `schema_migrations` insert inside one `db.transaction()`.
5. Attempt DB mode `0600`.
6. On first open, encrypt the literal key-check sentinel under `{ kind: "key_check", rowId: "store-key-check", expiresAt: 253402300799 }` and store only its envelope JSON. On later opens, decrypt and constant-compare the literal; any failure throws `OAuth store encryption key is invalid` before readiness becomes true.
7. Run `recover(now())`, then set readiness true.
8. `backup(destination)` calls `db.backup(destination)`; `close()` checkpoints WAL with `TRUNCATE`, marks readiness false, then closes.
9. If any startup step fails, close the DB and rethrow a value-free error.

- [ ] **Step 7: Prove schema GREEN**

Run:

```bash
npm run check
npm run build && node --test test/oauth-store-schema.test.mjs
```

Expected: all schema, restart, key, permission, and backup tests PASS.

- [ ] **Step 8: Commit the durable store foundation**

```bash
git add src/oauth/store.ts src/oauth/sqlite-schema.ts src/oauth/sqlite-store.ts test/oauth-store-schema.test.mjs
git commit -m "feat: add persistent OAuth store schema"
```

---

### Task 4: Persist Only the Supported Public MCP Client Profile

**Files:**
- Modify: `src/oauth/store.ts`
- Modify: `src/oauth/sqlite-store.ts`
- Create: `test/oauth-client-registration.test.mjs`

**Interfaces:**
- `OAuthStore.getClient(clientId): OAuthClientInformationFull | undefined`.
- `OAuthStore.registerClient(client): OAuthClientInformationFull` generates the opaque client ID and issued-at timestamp.
- The router must later configure `clientRegistrationHandler({ clientIdGeneration: false })`; the store owns ID generation.

- [ ] **Step 1: State the production change before editing production files**

```text
Implement the SDK client store but accept only a secretless Codex-style authorization-code client with exact scopes and explicit-port loopback redirects.
```

- [ ] **Step 2: Add failing registration tests only**

Create `test/oauth-client-registration.test.mjs`. Build one valid metadata object and mutate one dimension at a time:

```js
const VALID_CLIENT = {
  redirect_uris: ['http://127.0.0.1:43123/callback'],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'Codex Desktop',
  scope: 'zendesk:read zendesk:write',
}

test('registerClient generates and persists the canonical public profile', async (t) => {
  const store = await openStoreFixture(t)
  const registered = store.registerClient(VALID_CLIENT)
  assert.match(registered.client_id, /^[A-Za-z0-9_-]{43,}$/)
  assert.equal(registered.client_secret, undefined)
  assert.equal(registered.token_endpoint_auth_method, 'none')
  assert.deepEqual(registered.grant_types, ['authorization_code', 'refresh_token'])
  assert.deepEqual(registered.response_types, ['code'])
  assert.equal(registered.scope, 'zendesk:read zendesk:write')
  assert.deepEqual(store.getClient(registered.client_id), registered)
})

test('registerClient permits exact explicit-port localhost callbacks and defaults scope', async (t) => {
  const store = await openStoreFixture(t)
  const registered = store.registerClient({
    ...VALID_CLIENT,
    redirect_uris: ['http://localhost:53123/a/path'],
    scope: undefined,
  })
  assert.equal(registered.scope, 'zendesk:read zendesk:write')
})

test('registerClient rejects every unsupported profile without persisting it', async (t) => {
  const store = await openStoreFixture(t)
  const invalid = [
    { ...VALID_CLIENT, token_endpoint_auth_method: 'client_secret_post' },
    { ...VALID_CLIENT, grant_types: ['authorization_code'] },
    { ...VALID_CLIENT, response_types: ['code', 'token'] },
    { ...VALID_CLIENT, scope: 'zendesk:read' },
    { ...VALID_CLIENT, redirect_uris: ['https://example.test/callback'] },
    { ...VALID_CLIENT, redirect_uris: ['http://127.0.0.1/callback'] },
    { ...VALID_CLIENT, redirect_uris: ['http://127.0.0.1:43123/callback?x=1'] },
    { ...VALID_CLIENT, redirect_uris: ['http://user@localhost:43123/callback'] },
    { ...VALID_CLIENT, jwks: { keys: [] } },
    { ...VALID_CLIENT, software_statement: 'statement' },
    { ...VALID_CLIENT, client_name: 'x'.repeat(201) },
    { ...VALID_CLIENT, client_name: 'unsafe\nname' },
  ]

  for (const candidate of invalid) {
    assert.throws(() => store.registerClient(candidate), /invalid_client_metadata/i)
  }
  assert.equal(store.inspectForTest().clientCount, 0)
})
```

Add `clientCount` to the non-secret `StoreInspection` type and test helper. The helper must be shared from `test/helpers/oauth-fixture.mjs` once Task 22 creates that file; until then keep a local temporary-store helper in this test.

- [ ] **Step 3: Run the narrow test and prove RED**

Run:

```bash
npm run build && node --test test/oauth-client-registration.test.mjs
```

Expected: FAIL because `registerClient` is not implemented.

- [ ] **Step 4: Implement exact client validation and atomic persistence**

In `src/oauth/sqlite-store.ts`, use SDK `InvalidClientMetadataError` for every rejected profile so the later registration handler returns OAuth `400`, not generic `500`. Apply these exact rules before opening a transaction:

```ts
const UNSUPPORTED_CLIENT_FIELDS = [
  "client_uri",
  "logo_uri",
  "contacts",
  "tos_uri",
  "policy_uri",
  "jwks_uri",
  "jwks",
  "software_id",
  "software_version",
  "software_statement",
] as const;

function sameSet(actual: readonly string[] | undefined, expected: readonly string[]): boolean {
  return Boolean(
    actual &&
      actual.length === expected.length &&
      expected.every((value) => actual.includes(value)),
  );
}

function normalizeRedirectUri(value: string): string {
  const url = new URL(value);
  const valid =
    url.protocol === "http:" &&
    (url.hostname === "127.0.0.1" || url.hostname === "localhost") &&
    url.port !== "" &&
    Number(url.port) > 0 &&
    url.username === "" &&
    url.password === "" &&
    url.search === "" &&
    url.hash === "";
  if (!valid) throw new InvalidClientMetadataError("invalid_client_metadata");
  return url.href;
}
```

Require `token_endpoint_auth_method === "none"`, exact grant/response sets, canonical/default MCP scope, at least one unique redirect, printable ASCII client names of `1..200` characters, and every unsupported field to be `undefined`. Generate `client_id` with `randomToken(32)`, set `client_id_issued_at` to integer epoch seconds, return no secret, and insert the client plus normalized redirect rows inside one transaction.

- [ ] **Step 5: Prove registration GREEN**

Run:

```bash
npm run check
npm run build && node --test test/oauth-client-registration.test.mjs test/oauth-store-schema.test.mjs
```

Expected: all registration and schema tests PASS.

- [ ] **Step 6: Commit public-client persistence**

```bash
git add src/oauth/store.ts src/oauth/sqlite-store.ts test/oauth-client-registration.test.mjs
git commit -m "feat: persist public MCP clients"
```

---

### Task 5: Persist One-Time Login and Consent Transactions

**Files:**
- Modify: `src/oauth/store.ts`
- Modify: `src/oauth/sqlite-store.ts`
- Create: `test/oauth-login-transactions.test.mjs`

**Interfaces:**

Add these exact domain operations to `OAuthStore`:

```ts
export type BeginLoginInput = {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource: string;
  originalState: string | undefined;
  subdomain: string;
  now: number;
};

export type LoginStart = {
  transactionToken: string;
  consentCsrf: string;
  browserNonce: string;
  expiresAt: number;
};

export type ConsentDecisionInput = {
  transactionToken: string;
  consentCsrf: string;
  browserNonce: string;
  decision: "confirm" | "deny";
  now: number;
};

export type OAuthRedirectContext = {
  redirectUri: string;
  originalState: string | undefined;
};

export type ConsentDecisionResult =
  | { kind: "confirmed"; upstreamState: string }
  | ({ kind: "denied" } & OAuthRedirectContext)
  | { kind: "invalid" };

export type ZendeskCallbackContext = OAuthRedirectContext & {
  transactionId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource: string;
  createdAt: number;
};

beginLogin(input: BeginLoginInput): LoginStart;
decideConsent(input: ConsentDecisionInput): ConsentDecisionResult;
claimZendeskCallback(upstreamState: string, now: number): ZendeskCallbackContext | undefined;
failLogin(transactionId: string, now: number): OAuthRedirectContext | undefined;
```

- [ ] **Step 1: State the production change before editing production files**

```text
Persist a ten-minute browser-bound login transaction whose externally presented values are hashed, whose original MCP state/redirect are encrypted, and whose consent and upstream state can each be consumed exactly once.
```

- [ ] **Step 2: Add RED tests for one-time state and plaintext absence**

In `test/oauth-login-transactions.test.mjs`, cover this exact sequence:

1. Register `VALID_CLIENT`, call `beginLogin`, and assert each returned opaque value decodes to at least 32 bytes.
2. Read the DB bytes plus captured logs and assert they contain none of the raw transaction token, CSRF, browser nonce, original MCP state, redirect URI, or code challenge.
3. Confirm with the exact three values; assert one upstream state is returned and a replay returns `{ kind: "invalid" }`.
4. Claim the callback with upstream state once; assert byte-for-byte original state and exact bindings; a second claim is `undefined`.
5. Prove wrong CSRF, wrong browser nonce, expired transaction, and mixing values from two transactions all fail without advancing either row.
6. Prove deny consumes the transaction once and returns only the trusted stored redirect plus original state.

- [ ] **Step 3: Run the narrow test and prove RED**

```bash
npm run build && node --test test/oauth-login-transactions.test.mjs
```

Expected: FAIL because `beginLogin` and `decideConsent` do not exist.

- [ ] **Step 4: Implement the login transaction state machine**

Implement `beginLogin` as one transaction that validates the stored client/redirect and exact scopes/resource, generates independent 32-byte values, hashes all lookup values, encrypts this payload, and inserts `consent_pending` with `expires_at = now + 600`:

```ts
type EncryptedLoginPayload = {
  originalState: string | undefined;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource: string;
};
```

Use the login AAD dimensions defined in Task 2. `decideConsent` must compare all three hashes and expiry in one transaction, consume the CSRF by changing status, and either return the decrypted trusted redirect or generate/store a separate upstream-state hash while changing to `upstream_pending`. `claimZendeskCallback` atomically changes only a matching, unexpired `upstream_pending` row to `callback_claimed`. `failLogin` changes only `callback_claimed` to `failed` and returns its decrypted trusted context.

- [ ] **Step 5: Prove login transaction GREEN**

```bash
npm run check
npm run build && node --test test/oauth-login-transactions.test.mjs
```

Expected: one-time, expiry, transplant, encryption, and denial tests PASS.

- [ ] **Step 6: Commit the login-state slice**

```bash
git add src/oauth/store.ts src/oauth/sqlite-store.ts test/oauth-login-transactions.test.mjs
git commit -m "feat: persist OAuth login transactions"
```

---

### Task 6: Add Principals, Encrypted Grant Staging, and Atomic Login Commit

**Files:**
- Modify: `src/oauth/store.ts`
- Modify: `src/oauth/sqlite-store.ts`
- Create: `test/oauth-principal-credentials.test.mjs`

**Interfaces:**

```ts
export type ZendeskGrant = {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
  scopes: string[];
};

export type StageLoginGrantInput = {
  transactionId: string;
  subdomain: string;
  grant: ZendeskGrant;
  now: number;
};

export type CommitLoginInput = {
  transactionId: string;
  stageId: string;
  zendeskUserId: string;
  now: number;
};

export type LoginCommitResult = OAuthRedirectContext & {
  principalId: string;
  principalEpoch: number;
  authorizationCode: string;
};

stageLoginGrant(input: StageLoginGrantInput): { stageId: string };
commitLogin(input: CommitLoginInput): LoginCommitResult;
discardStagedGrant(stageId: string, now: number): boolean;
```

- [ ] **Step 1: State the production change before editing production files**

```text
Stage every returned Zendesk grant before identity work, then atomically install the credential, create the epoch-bound MCP code, and complete the login only after users/me establishes the stable Zendesk user ID.
```

- [ ] **Step 2: Add failing principal lifecycle tests only**

`test/oauth-principal-credentials.test.mjs` must prove:

- the staged grant is encrypted, unavailable to credential lookup, and removable as discard-only;
- the first callback creates `(subdomain, zendeskUserId)`, epoch `1`, credential version `1`, one code, and completes the login in one transaction;
- an injected failure before any of those three writes commits none of them;
- re-login for the same active user increments only credential version, keeps epoch and existing active families, and never clears a family revocation marker;
- concurrent logins serialize so only the last committed credential is current and the loser is local-discard only with zero upstream cleanup calls;
- a callback started before `disconnected_at` cannot reactivate; one begun later can cancel only an unclaimed outbox row, increment epoch, and install a new credential;
- a claimed disconnect row blocks reactivation until the claim is released or completed;
- no plaintext grant, state, code, or email sentinel appears in DB bytes or logs.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/oauth-principal-credentials.test.mjs
```

Expected: FAIL because grant staging and `commitLogin` are missing.

- [ ] **Step 4: Implement staging and the atomic callback transaction**

`stageLoginGrant` inserts one encrypted `purpose='login'` row tied to the claimed transaction and a bounded expiry. `commitLogin` must execute this exact order inside one synchronous SQLite transaction:

1. Re-read the unexpired `callback_claimed` transaction and staged grant.
2. Resolve or create the stable principal by `(subdomain, zendeskUserId)`.
3. Enforce the disconnected timing/claim fence.
4. Allocate the next credential version and active lifecycle epoch.
5. Re-encrypt the staged grant under the final credential AAD and upsert `zendesk_credentials`.
6. Generate a separate 32-byte MCP authorization code and insert only its hash with all transaction bindings plus the active epoch and ten-minute expiry.
7. Mark the login complete and delete the staging ciphertext.
8. Return the raw code plus the decrypted trusted redirect/original state only after commit.

Use an injected transaction-failure hook only in tests; it must not be exported from the package entrypoint.

- [ ] **Step 5: Prove principal lifecycle GREEN**

```bash
npm run check
npm run build && node --test test/oauth-principal-credentials.test.mjs test/oauth-login-transactions.test.mjs
```

Expected: atomicity, re-login, disconnected timing, and secret-sentinel tests PASS.

- [ ] **Step 6: Commit the principal slice**

```bash
git add src/oauth/store.ts src/oauth/sqlite-store.ts test/oauth-principal-credentials.test.mjs
git commit -m "feat: add principal credential lifecycle"
```

---

### Task 7: Issue Epoch- and Audience-Bound MCP Authorization Codes and Access Tokens

**Files:**
- Modify: `src/oauth/store.ts`
- Modify: `src/oauth/sqlite-store.ts`
- Create: `test/oauth-access-tokens.test.mjs`

**Interfaces:**

```ts
export type IssuedTokens = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
};

export type CodeExchangeInput = {
  clientId: string;
  authorizationCode: string;
  redirectUri: string;
  resource: string;
  now: number;
  accessTokenTtlSeconds: number;
};

export type StoredAuthInfo = {
  clientId: string;
  principalId: string;
  scopes: string[];
  resource: string;
  expiresAt: number;
};

challengeForAuthorizationCode(clientId: string, code: string, now: number): string | undefined;
consumeCodeAndIssueFamily(input: CodeExchangeInput): IssuedTokens;
lookupAccessToken(token: string, now: number): StoredAuthInfo | undefined;
```

- [ ] **Step 1: State the production change before editing production files**

```text
Exchange a one-time code for a new MCP token family only while its bound principal remains active at the exact lifecycle epoch, then verify access tokens by hash, expiry, family, scope, client, and canonical resource.
```

- [ ] **Step 2: Add failing code/access tests only**

Cover successful issue/verify plus wrong client, omitted/wrong redirect, omitted/wrong resource, expired code, reused code, revoked family, expired access, altered scope, and stale/disconnected/reauthorization epoch. Assert access/refresh plaintext never occurs in DB bytes and `expiresAt` is integer epoch seconds.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/oauth-access-tokens.test.mjs
```

Expected: FAIL because the code exchange methods are absent.

- [ ] **Step 4: Implement atomic family issuance and access lookup**

`challengeForAuthorizationCode` is read-only and does not consume the code. `consumeCodeAndIssueFamily` must atomically require an unconsumed/unexpired exact binding and an active principal at `principal_epoch`, mark the code consumed, create one family, create generation `1`, hash/store both random tokens, and return the raw values exactly once. Set access expiry to `now + accessTokenTtlSeconds`, refresh expiry to `now + 2_592_000`, and family scope to canonical `zendesk:read zendesk:write`. `lookupAccessToken` joins family/principal and returns `undefined` unless every binding and current principal epoch/status remains valid.

- [ ] **Step 5: Prove access-token GREEN**

```bash
npm run check
npm run build && node --test test/oauth-access-tokens.test.mjs
```

Expected: all binding, epoch, reuse, expiry, and plaintext tests PASS.

- [ ] **Step 6: Commit audience-bound tokens**

```bash
git add src/oauth/store.ts src/oauth/sqlite-store.ts test/oauth-access-tokens.test.mjs
git commit -m "feat: issue audience-bound MCP tokens"
```

---

### Task 8: Rotate MCP Refresh Tokens and Revoke Only Their Family

**Files:**
- Modify: `src/oauth/store.ts`
- Modify: `src/oauth/sqlite-store.ts`
- Create: `test/oauth-refresh-revocation.test.mjs`

**Interfaces:**

```ts
export type RefreshExchangeInput = {
  clientId: string;
  refreshToken: string;
  scopes: string[] | undefined;
  resource: string | undefined;
  canonicalResource: string;
  now: number;
  accessTokenTtlSeconds: number;
};

export type RefreshExchangeResult =
  | { kind: "issued"; tokens: IssuedTokens }
  | { kind: "idempotent"; tokens: IssuedTokens }
  | { kind: "invalid_grant"; reason: "expired" | "replay" | "revoked" | "binding_mismatch" };

rotateRefreshToken(input: RefreshExchangeInput): RefreshExchangeResult;
revokeFamilyByPresentedToken(clientId: string, token: string, now: number): void;
```

- [ ] **Step 1: State the production change before editing production files**

```text
Rotate each refresh generation atomically, tolerate only one exact 60-second lost-response retry, retain replay markers until their own expiry, and confine revocation to the presenting client's family.
```

- [ ] **Step 2: Add RED tests for rotation and replay**

Test `R1 -> R2 -> R3`, concurrent `R1` calls, exact `R1` retry inside 60 seconds, retry after 60 seconds, retry after R2 has advanced, wrong client/scope/resource, omitted current-rmcp resource inheritance, wrong supplied resource, family revocation during the retry window, expired R1 after its 30-day expiry, process reopen, and isolation between two families on one principal.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/oauth-refresh-revocation.test.mjs
```

Expected: FAIL because `rotateRefreshToken` is absent.

- [ ] **Step 4: Implement exact refresh-generation transitions**

For a current generation, one transaction must validate its active family/principal bindings, consume it, create the next raw access/refresh pair, store their hashes, encrypt the exact response under `mcp_refresh_retry` AAD on the consumed row, and commit before returning. An identical retry may decrypt that response only while all are true: within 60 seconds, family active, client/scopes/resource identical, and the cached successor remains the current unconsumed generation. Store recovery and every refresh lookup clear only `encrypted_retry_response_json` after its 60-second expiry while retaining the consumed token hash until that generation's own 30-day expiry. A consumed-token replay outside those conditions revokes the family; a token already past its own expiry returns `expired` without revoking a healthy family. Omitted refresh `resource` inherits only the family's immutable resource; any supplied mismatch returns `binding_mismatch`.

`revokeFamilyByPresentedToken` must find either token hash, require stored client ownership, and set only that family's `revoked_at`; unknown, already-revoked, or cross-client values are no-ops.

- [ ] **Step 5: Prove refresh GREEN**

```bash
npm run check
npm run build && node --test test/oauth-refresh-revocation.test.mjs
```

Expected: rotation, retry, replay, restart, and family-isolation tests PASS.

- [ ] **Step 6: Commit refresh rotation**

```bash
git add src/oauth/store.ts src/oauth/sqlite-store.ts test/oauth-refresh-revocation.test.mjs
git commit -m "feat: rotate MCP refresh tokens"
```

---

### Task 9: Add Atomic Disconnect and the Leased Revocation Outbox

**Files:**
- Modify: `src/oauth/store.ts`
- Modify: `src/oauth/sqlite-store.ts`
- Create: `test/oauth-disconnect-store.test.mjs`

**Interfaces:**

```ts
export type DisconnectResult =
  | { kind: "disconnected"; principalId: string; revokedFamilies: number; outboxId: string }
  | { kind: "not_found" }
  | { kind: "already_disconnected"; principalId: string };

export type RevocationClaim = {
  outboxId: string;
  principalId: string;
  capturedPrincipalEpoch: number;
  credentialVersion: number;
  grant: ZendeskGrant;
  attemptCount: number;
  retentionExpiresAt: number;
};

disconnectUser(subdomain: string, zendeskUserId: string, now: number): DisconnectResult;
claimDueRevocation(owner: string, now: number, leaseExpiresAt: number): RevocationClaim | undefined;
renewRevocationClaim(outboxId: string, owner: string, leaseExpiresAt: number): boolean;
rescheduleRevocation(outboxId: string, owner: string, category: string, nextAttemptAt: number): boolean;
completeRevocation(outboxId: string, owner: string, now: number): boolean;
releaseClaims(owner: string, now: number): number;
```

- [ ] **Step 1: State the production change before editing production files**

```text
Disconnect one principal in a single fail-closed transaction and move only that explicit disconnect credential to a leased revocation outbox; re-login, CAS losers, and failed staging never enter this outbox.
```

- [ ] **Step 2: Add failing disconnect/outbox tests only**

Prove atomic status/epoch increment, pending-code invalidation, all-family revocation, immediate credential unavailability, encrypted tombstone, idempotent repeated disconnect, due-claim ownership, lease renewal, expired-lease reclaim after reopen, release on abort, captured-epoch eligibility, reactivation cancellation of unclaimed work, blocking during active claim, and isolation from another principal. Assert re-login/staging-discard paths produce zero outbox rows.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/oauth-disconnect-store.test.mjs
```

Expected: FAIL because disconnect/outbox methods are absent.

- [ ] **Step 4: Implement the disconnect and lease transitions**

`disconnectUser` must atomically increment lifecycle epoch, set `disconnected_at`, revoke all active families, invalidate unconsumed codes, delete the resolvable credential, and re-encrypt that exact grant into one `pending` outbox row. Set retention to `refreshExpiresAt + 604_800` seconds. Claims use a caller-provided unique owner and lease deadline; before claim and every renew, atomically require the principal still be disconnected at the captured epoch with no active credential. Recovery requeues expired claims. Use exponential retry `min(900, 5 * 2 ** max(0, attemptCount - 1))` seconds. Never promise forensic deletion from SQLite pages or backups; remove the ciphertext logically and rely on encrypted-at-rest storage plus documented backup retention.

- [ ] **Step 5: Run the complete store milestone**

```bash
npm run check
npm run build && node --test \
  test/oauth-store-schema.test.mjs \
  test/oauth-client-registration.test.mjs \
  test/oauth-login-transactions.test.mjs \
  test/oauth-principal-credentials.test.mjs \
  test/oauth-access-tokens.test.mjs \
  test/oauth-refresh-revocation.test.mjs \
  test/oauth-disconnect-store.test.mjs
```

Expected: every persistent lifecycle test PASS.

- [ ] **Step 6: Commit disconnect persistence**

```bash
git add src/oauth/store.ts src/oauth/sqlite-store.ts test/oauth-disconnect-store.test.mjs
git commit -m "feat: add disconnect revocation outbox"
```

---

### Task 10: Implement the MCP SDK OAuth Provider Contract

**Files:**
- Create: `src/oauth/zendesk-broker-provider.ts`
- Create: `test/oauth-provider.test.mjs`

**Interfaces:**

```ts
export type AuthorizationStarter = (
  client: OAuthClientInformationFull,
  params: AuthorizationParams,
  res: Response,
) => Promise<void>;

export type ZendeskBrokerOAuthProviderOptions = {
  store: OAuthStore;
  resourceUrl: URL;
  accessTokenTtlSeconds: number;
  startAuthorization: AuthorizationStarter;
  now?: () => number;
};

export class ZendeskBrokerOAuthProvider implements OAuthServerProvider {
  constructor(options: ZendeskBrokerOAuthProviderOptions);
  get clientsStore(): OAuthRegisteredClientsStore;
  readonly skipLocalPkceValidation: false;
  authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void>;
  challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string>;
  exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string, codeVerifier?: string, redirectUri?: string, resource?: URL): Promise<OAuthTokens>;
  exchangeRefreshToken(client: OAuthClientInformationFull, token: string, scopes?: string[], resource?: URL): Promise<OAuthTokens>;
  verifyAccessToken(token: string): Promise<AuthInfo>;
  revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void>;
}
```

- [ ] **Step 1: State the production change before editing production files**

```text
Adapt the frozen store transactions to the SDK provider contract while preserving exact client, redirect, scope, resource, PKCE, epoch, ownership, and integer-second AuthInfo semantics.
```

- [ ] **Step 2: Add the failing provider contract tests only**

`test/oauth-provider.test.mjs` must exercise each public method with a real temporary store. Assert:

- `clientsStore` is the same store and `skipLocalPkceValidation` is `false`;
- authorize rejects missing/wrong resource, wrong scope, or unregistered redirect before calling the injected starter;
- challenge lookup does not consume the code;
- code exchange requires exact redirect/resource and maps store tokens to SDK `OAuthTokens`;
- the SDK-owned PKCE path calls exchange with `codeVerifier === undefined`; a regression test pins this installed 1.26 behavior;
- refresh accepts omitted resource only by family inheritance, rejects a supplied mismatch, and maps every invalid store result to `InvalidGrantError` or `InvalidTargetError`;
- `verifyAccessToken` rejects invalid tokens with `InvalidTokenError`, independently rechecks exact canonical resource, and returns `{ token, clientId, scopes, expiresAt, resource: new URL(resource), extra: { principalId } }` with no other `extra` fields;
- revoke is a no-op for unknown/cross-client tokens and affects only the owned family.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/oauth-provider.test.mjs
```

Expected: FAIL with missing provider module.

- [ ] **Step 4: Implement exact SDK error mapping**

Import SDK errors from `@modelcontextprotocol/sdk/server/auth/errors.js` and use this mapping:

```ts
const providerErrors = {
  missingRedirect: InvalidRequestError,
  wrongOrReusedCode: InvalidGrantError,
  badScope: InvalidScopeError,
  missingOrWrongResource: InvalidTargetError,
  invalidBearer: InvalidTokenError,
} as const;
```

Normalize authorization scopes before calling `startAuthorization`. Keep local PKCE validation enabled: `challengeForAuthorizationCode` only reads the challenge and `exchangeAuthorizationCode` consumes later. Never accept a request-derived resource fallback. During refresh, pass `undefined` through to the store so only the stored family can supply the approved rmcp compatibility value.

- [ ] **Step 5: Prove provider GREEN and freeze its contract**

```bash
npm run check
npm run build && node --test test/oauth-provider.test.mjs test/oauth-refresh-revocation.test.mjs
```

Expected: all provider and backing lifecycle tests PASS.

- [ ] **Step 6: Commit the provider**

```bash
git add src/oauth/zendesk-broker-provider.ts test/oauth-provider.test.mjs
git commit -m "feat: implement MCP OAuth provider"
```

---

### Task 11: Implement the Fixed-Host Zendesk OAuth Gateway

**Files:**
- Create: `src/oauth/zendesk-oauth-client.ts`
- Create: `test/helpers/fake-zendesk.mjs`
- Create: `test/zendesk-oauth-client.test.mjs`
- Modify: `src/oauth/errors.ts`

**Interfaces:**

```ts
export interface ZendeskOAuthGateway {
  createAuthorizationUrl(state: string): URL;
  exchangeAuthorizationCode(code: string, signal?: AbortSignal): Promise<ZendeskGrant>;
  refreshCredential(refreshToken: string, signal?: AbortSignal): Promise<ZendeskGrant>;
  getCurrentUser(accessToken: string, signal?: AbortSignal): Promise<{ zendeskUserId: string }>;
  revokeCurrentToken(accessToken: string, signal?: AbortSignal): Promise<void>;
}

export type ZendeskOAuthClientOptions = {
  subdomain: string;
  clientId: string;
  clientSecret: string;
  callbackUrl: URL;
  scopes: readonly string[];
  timeoutMs: number;
  shutdownSignal?: AbortSignal;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
};
```

- [ ] **Step 1: State the production change before editing production files**

```text
Own the upstream Zendesk protocol in one fixed-host gateway, explicitly request expiring/refreshable grants even for legacy local clients, abort every fetch on timeout/shutdown, and expose only sanitized typed failures.
```

- [ ] **Step 2: Add a deterministic fake Zendesk server and RED tests**

`test/helpers/fake-zendesk.mjs` must record method, pathname, parsed JSON/form fields, and authorization scheme while allowing tests to queue responses and hung requests. `test/zendesk-oauth-client.test.mjs` must assert these exact endpoints:

```text
GET    https://{subdomain}.zendesk.com/oauth/authorizations/new
POST   https://{subdomain}.zendesk.com/oauth/tokens
GET    https://{subdomain}.zendesk.com/api/v2/users/me.json
DELETE https://{subdomain}.zendesk.com/api/v2/oauth/tokens/current.json
```

For both authorization-code exchange and refresh, assert `scope = "read tickets:write"`, `expires_in = 1800`, and `refresh_token_expires_in = 2592000`. Assert rotated token parsing, integer expiries, missing refresh-token rejection, mismatched/invalid response rejection, one fetch only on exchange/refresh failure, timeout/shutdown abort, and that body/header/token sentinels never appear in thrown messages or captured logs.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/zendesk-oauth-client.test.mjs
```

Expected: FAIL with missing gateway module.

- [ ] **Step 4: Implement fixed endpoints and explicit expiration policy**

`createAuthorizationUrl` must construct the fixed origin internally and set only:

```ts
{
  response_type: "code",
  client_id: clientId,
  redirect_uri: callbackUrl.href,
  scope: "read tickets:write",
  state,
  expires_in: "1800",
  refresh_token_expires_in: "2592000",
}
```

Authorization-code exchange sends JSON `{ grant_type: "authorization_code", code, client_id, client_secret, redirect_uri, scope, expires_in: 1800, refresh_token_expires_in: 2592000 }`. Refresh sends JSON `{ grant_type: "refresh_token", refresh_token, client_id, client_secret, scope, expires_in: 1800, refresh_token_expires_in: 2592000 }`. Require access token, refresh token, both expiry values, bearer token type, and exact approved scopes before returning a `ZendeskGrant` with integer epoch seconds. Never derive a hostname from a response or request.

Combine per-call and shutdown abort signals without logging abort reasons. Parse an error body only to classify `invalid_grant`, `401`, `403`, `429`, retryable `5xx`, invalid response, or abort; discard its content and throw `ZendeskUpstreamError` with a random correlation ID.

- [ ] **Step 5: Prove Zendesk gateway GREEN**

```bash
npm run check
npm run build && node --test test/zendesk-oauth-client.test.mjs
```

Expected: endpoint, expiry, rotation, timeout, no-retry, and sanitization tests PASS.

- [ ] **Step 6: Commit the upstream gateway**

```bash
git add src/oauth/errors.ts src/oauth/zendesk-oauth-client.ts test/helpers/fake-zendesk.mjs test/zendesk-oauth-client.test.mjs
git commit -m "feat: add Zendesk OAuth protocol client"
```

---

### Task 12: Compose SDK-Owned OAuth Handlers with Correct Public Metadata

**Files:**
- Create: `src/oauth/oauth-router.ts`
- Create: `test/oauth-router.test.mjs`
- Create: `test/oauth-sdk-compat.test.mjs`

**Interfaces:**

```ts
export type ZendeskOAuthRouterOptions = {
  provider: ZendeskBrokerOAuthProvider;
  issuerUrl: URL;
  resourceUrl: URL;
  consentHandler: RequestHandler;
  callbackHandler: RequestHandler;
};

export function createZendeskOAuthRouter(options: ZendeskOAuthRouterOptions): Router;
```

- [ ] **Step 1: State the production change before editing production files**

```text
Use SDK parsing, PKCE, token, registration, revoke, and metadata building blocks, but locally correct both public-client authentication metadata fields and mount rate-limited consent/callback routes.
```

- [ ] **Step 2: Add RED metadata and SDK-compatibility tests**

Use a stub provider and a real Express listener. Assert protected-resource metadata is exactly path-specific for `/mcp`; authorization metadata has same-origin `/authorize`, `/token`, `/register`, `/revoke`; both `token_endpoint_auth_methods_supported` and `revocation_endpoint_auth_methods_supported` equal `['none']`; scopes and S256 are exact. POST a current Codex-shaped registration including `application_type`, prove the installed SDK strips that unsupported field, produces no secret, and calls the store because `clientIdGeneration` is false. Prove token/revoke accept public `client_id` without a secret.

- [ ] **Step 3: Prove RED against the SDK default**

```bash
npm run build && node --test test/oauth-router.test.mjs test/oauth-sdk-compat.test.mjs
```

Expected: FAIL because the local router is absent; a control assertion should document that SDK 1.26's stock revocation metadata advertises `client_secret_post`.

- [ ] **Step 4: Implement the thin router composition**

Import and mount the SDK's `authorizationHandler`, `tokenHandler`, `clientRegistrationHandler`, `revocationHandler`, `createOAuthMetadata`, `mcpAuthMetadataRouter`, and `metadataHandler` exports. Build metadata through `createOAuthMetadata`, replace both authentication-method arrays with `['none']`, and pass the corrected object to `mcpAuthMetadataRouter`. Configure `clientRegistrationHandler` with `clientIdGeneration: false`.

Use explicit limiter policies: register `20/hour`; authorize `60/15 minutes`; token and revoke `120/15 minutes`; consent and callback `60/15 minutes`; standard headers on, legacy headers off. Mount consent URL-encoded parsing with `limit: '4kb'`, `parameterLimit: 4`, and no extended objects. Do not mount `mcpAuthRouter` itself.

- [ ] **Step 5: Prove router GREEN**

```bash
npm run check
npm run build && node --test test/oauth-router.test.mjs test/oauth-sdk-compat.test.mjs
```

Expected: exact metadata, public DCR, rate-limit, and installed-SDK behavior tests PASS.

- [ ] **Step 6: Commit the custom composition**

```bash
git add src/oauth/oauth-router.ts test/oauth-router.test.mjs test/oauth-sdk-compat.test.mjs
git commit -m "feat: compose public-client OAuth routes"
```

---

### Task 13: Add Browser-Bound Local Consent

**Files:**
- Create: `src/oauth/consent.ts`
- Create: `test/oauth-consent.test.mjs`

**Interfaces:**

```ts
export type ConsentControllerOptions = {
  store: OAuthStore;
  zendesk: ZendeskOAuthGateway;
  publicBaseUrl: URL;
  subdomain: string;
  now?: () => number;
};

export class ConsentController {
  constructor(options: ConsentControllerOptions);
  begin: AuthorizationStarter;
  handlePost(req: Request, res: Response): Promise<void>;
}
```

- [ ] **Step 1: State the production change before editing production files**

```text
Require explicit local consent for each dynamically registered client and bind the one-time form to the same browser with a strict cookie, CSRF value, transaction token, exact Origin, and atomic store decision.
```

- [ ] **Step 2: Add failing browser-security tests only**

Assert the page escapes the untrusted client name, displays exact callback host/port, resource and both MCP scopes, warns that localhost can be impersonated, contains no third-party asset, and includes only transaction/CSRF hidden values. Assert these headers: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, CSP with `default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`, and `X-Frame-Options: DENY`.

For POST, prove confirm/deny success plus missing/wrong cookie, missing/wrong Origin, wrong CSRF, mixed transactions, oversized body, prefetch transplant, and replay all fail closed before Zendesk redirect. Prove deny redirects to the exact trusted loopback callback with `error=access_denied` and byte-for-byte original state.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/oauth-consent.test.mjs
```

Expected: FAIL with missing consent controller.

- [ ] **Step 4: Implement the consent controller**

`begin` validates through provider/store, calls `beginLogin`, sets exactly `HttpOnly; Secure; SameSite=Strict; Path=/oauth/consent; Max-Age=600`, and returns a small escaped HTML form. `handlePost` requires `Content-Type: application/x-www-form-urlencoded`, exact `Origin === publicBaseUrl.origin`, the named cookie, scalar transaction/CSRF/decision fields, and `decision` equal to `confirm` or `deny`. Always clear the cookie. Deny appends only `error` and original `state` to the trusted redirect. Confirm calls `zendesk.createAuthorizationUrl(upstreamState)` only after the store atomically consumes consent.

- [ ] **Step 5: Prove consent GREEN**

```bash
npm run check
npm run build && node --test test/oauth-consent.test.mjs
```

Expected: content, headers, binding, replay, and redirect tests PASS.

- [ ] **Step 6: Commit browser consent**

```bash
git add src/oauth/consent.ts test/oauth-consent.test.mjs
git commit -m "feat: add browser-bound OAuth consent"
```

---

### Task 14: Finalize Zendesk Callback Through Encrypted Staging

**Files:**
- Create: `src/oauth/zendesk-callback.ts`
- Create: `test/oauth-callback.test.mjs`

**Interfaces:**

```ts
export type ZendeskCallbackControllerOptions = {
  store: OAuthStore;
  zendesk: ZendeskOAuthGateway;
  subdomain: string;
  now?: () => number;
};

export class ZendeskCallbackController {
  constructor(options: ZendeskCallbackControllerOptions);
  handle(req: Request, res: Response): Promise<void>;
}
```

- [ ] **Step 1: State the production change before editing production files**

```text
Consume Zendesk state once, exchange and stage the returned grant before identity work, then atomically install the stable user credential and MCP code before redirecting Codex.
```

- [ ] **Step 2: Add failing callback transaction tests only**

Test success, Zendesk `access_denied`, missing code, unknown/expired/replayed state, exchange failure, crash immediately after exchange, stage failure, users/me failure, commit failure, concurrent re-login, and callback begun before/after disconnect. Assert success calls `exchange -> stage -> users/me -> commit -> redirect` in that order; no MCP code is visible before commit; trusted failures redirect with stable `access_denied`, `server_error`, or `temporarily_unavailable` plus original state; untrusted state returns only a generic correlated HTML error. Assert every failed staged grant is discard-only and produces zero upstream cleanup calls.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/oauth-callback.test.mjs
```

Expected: FAIL with missing callback controller.

- [ ] **Step 4: Implement the callback orchestration**

Read scalar query fields only. Claim state before examining success/error details. For a Zendesk denial, fail the trusted transaction and redirect Codex. For success, exchange once, immediately stage encrypted grant, call `getCurrentUser`, then call `commitLogin`; only its returned raw MCP code may be appended to the trusted callback. On any post-exchange failure, mark the stage discard-only, fail the transaction, and redirect with a sanitized stable error. Never retry exchange or users/me automatically and never call upstream cleanup for failed/superseded staging.

- [ ] **Step 5: Run the browser-flow milestone**

```bash
npm run check
npm run build && node --test \
  test/oauth-provider.test.mjs \
  test/oauth-router.test.mjs \
  test/oauth-sdk-compat.test.mjs \
  test/oauth-consent.test.mjs \
  test/oauth-callback.test.mjs \
  test/zendesk-oauth-client.test.mjs
```

Expected: complete local OAuth browser/protocol suite PASS.

- [ ] **Step 6: Commit callback finalization**

```bash
git add src/oauth/zendesk-callback.ts test/oauth-callback.test.mjs
git commit -m "feat: complete brokered Zendesk login"
```

---

### Task 15: Make `ZendeskClient` Explicitly Basic or OAuth-Bearer Authenticated

**Files:**
- Modify: `src/zendesk-client.ts`
- Modify: `src/index.ts`
- Modify: `test/zendesk-comments-attachments.test.mjs`
- Create: `test/zendesk-client-auth.test.mjs`

**Interfaces:**

```ts
export type BasicZendeskAuth = {
  kind: "api_token";
  email: string;
  apiToken: string;
};

export type OAuthZendeskAuth = {
  kind: "oauth";
  accessToken: string;
  principalEpoch: number;
  credentialVersion: number;
  onUnauthorized: (input: {
    principalEpoch: number;
    credentialVersion: number;
    terminal: boolean;
    signal: AbortSignal;
  }) => Promise<
    | { kind: "retry"; accessToken: string; principalEpoch: number; credentialVersion: number }
    | { kind: "reauthorization_required"; correlationId: string }
    | { kind: "stale_failure"; correlationId: string }
  >;
};

export type ZendeskClientOptions = {
  subdomain: string;
  auth: BasicZendeskAuth | OAuthZendeskAuth;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
};

export class ZendeskClient {
  constructor(options: ZendeskClientOptions);
}
```

- [ ] **Step 1: State the production change before editing production files**

```text
Replace the implicit Basic-only client constructor with an explicit discriminated auth contract, preserve stdio Basic behavior, add request deadlines, retry an OAuth 401 exactly once through the resolver, and remove upstream response bodies from all public errors.
```

- [ ] **Step 2: Add failing auth/error tests only**

Create `test/zendesk-client-auth.test.mjs` with fake `fetch` assertions for:

- stdio sends `Authorization: Basic` from `api_token` and preserves existing pagination/normalization;
- OAuth sends `Authorization: Bearer oauth-access-1`, receives `401`, obtains exactly one retry credential, then retries only the original request as `Bearer oauth-access-2`;
- a second `401` calls the terminal unauthorized callback and returns a `ReauthorizationRequiredError` or sanitized stale failure without a third HTTP request;
- `403`, `429`, `5xx`, malformed JSON, network error, and timeout map to `ZendeskUpstreamError` with category/status/retryable/correlation ID but no response body, ticket body, header, email, or token sentinel;
- cancelling an outer signal aborts the fetch; and
- all existing attachment tests change only constructor setup, not expected behavior.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/zendesk-client-auth.test.mjs test/zendesk-comments-attachments.test.mjs
```

Expected: FAIL because the new options constructor and OAuth branch do not exist.

- [ ] **Step 4: Implement the discriminated request path**

Change the constructor to accept only `ZendeskClientOptions`. Build Basic authorization only from `{ kind: "api_token" }`; build Bearer authorization only from `{ kind: "oauth" }`. Use a fresh `AbortController` per request, abort after `timeoutMs ?? 15000`, and always clear the timer. For the OAuth branch, invoke `onUnauthorized(...terminal:false)` after the first `401`, retry once only if it returns `retry`, then invoke `onUnauthorized(...terminal:true)` after a second `401` and throw either `ReauthorizationRequiredError` or a new sanitized `ZendeskUpstreamError`.

For every non-OK response, consume at most a bounded body for internal category classification, never interpolate it into errors/logs, and include only the generated correlation ID in the thrown message. Update `src/index.ts` to instantiate:

```ts
new ZendeskClient({
  subdomain: config.subdomain,
  auth: { kind: "api_token", email: config.email, apiToken: config.apiKey },
});
```

- [ ] **Step 5: Prove Basic and OAuth client GREEN**

```bash
npm run check
npm run build && node --test test/zendesk-client-auth.test.mjs test/zendesk-comments-attachments.test.mjs test/server-instructions.test.mjs
```

Expected: Basic regression, OAuth retry, deadline, and sanitizer tests PASS.

- [ ] **Step 6: Commit the shared client boundary**

```bash
git add src/zendesk-client.ts src/index.ts test/zendesk-client-auth.test.mjs test/zendesk-comments-attachments.test.mjs
git commit -m "refactor: support request-scoped Zendesk OAuth"
```

---

### Task 16: Resolve Per-Principal Zendesk Clients with Single-Flight Refresh

**Files:**
- Create: `src/oauth/zendesk-client-resolver.ts`
- Modify: `src/oauth/store.ts`
- Modify: `src/oauth/sqlite-store.ts`
- Create: `test/zendesk-client-resolver.test.mjs`

**Interfaces:**

```ts
export type CredentialSnapshot = {
  principalId: string;
  zendeskUserId: string;
  principalEpoch: number;
  credentialVersion: number;
  status: "active" | "disconnected" | "reauthorization_required";
  grant: ZendeskGrant;
};

export type StageRefreshInput = {
  principalId: string;
  expectedPrincipalEpoch: number;
  expectedCredentialVersion: number;
  grant: ZendeskGrant;
  now: number;
};

export type InstallRefreshResult =
  | { kind: "installed"; snapshot: CredentialSnapshot }
  | { kind: "winner"; snapshot: CredentialSnapshot }
  | { kind: "disconnected" };

loadCredential(principalId: string): CredentialSnapshot | undefined;
stageRefreshGrant(input: StageRefreshInput): { stageId: string };
installStagedRefresh(stageId: string, now: number): InstallRefreshResult;
markReauthorizationRequiredIfCurrent(input: {
  principalId: string;
  expectedPrincipalEpoch: number;
  expectedCredentialVersion: number;
  now: number;
}): boolean;

export interface ZendeskClientResolverLike {
  resolve(principalId: string): Promise<ZendeskClient>;
}
```

- [ ] **Step 1: State the production change before editing production files**

```text
Load one active principal credential per request, refresh it at most once concurrently per principal, stage before identity validation, atomically install only a matching epoch/version winner, and construct a new OAuth ZendeskClient for that request.
```

- [ ] **Step 2: Add failing resolver tests only**

Create `test/zendesk-client-resolver.test.mjs` and prove:

- a currently valid credential produces a request-scoped Bearer client without upstream refresh;
- ten simultaneous resolve calls for one expiring principal result in one upstream refresh/users-me sequence;
- simultaneous calls for principal A and B use independent locks and never cross Authorization headers or errors;
- refresh stages first, requires the same `users/me` ID, persists a rotated refresh token, and survives reopening the store;
- if a concurrent login wins the CAS, the resolver discards local staging and adopts the winner without upstream cleanup;
- disconnected or reauthorization-required principal never falls back to Basic/default credentials;
- a hung upstream operation releases its single-flight entry after abort.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/zendesk-client-resolver.test.mjs
```

Expected: FAIL with missing resolver module/store methods.

- [ ] **Step 4: Implement snapshot/stage/CAS persistence and resolver**

`loadCredential` decrypts only a current active credential. `stageRefreshGrant` persists the returned grant immediately under `staged_grant` AAD with the expected epoch/version. `installStagedRefresh` performs a short transaction: if the expected active snapshot still matches, increment version and install; if a newer active snapshot exists, return it as `winner`; otherwise return `disconnected`. It never invokes Zendesk.

`ZendeskClientResolver` keeps `Map<string, Promise<CredentialSnapshot>>` only for in-process refreshes. It checks refresh skew, starts one refresh for the snapshot, calls `refreshCredential`, stages it, calls `getCurrentUser`, requires the original ID, installs/adopts via CAS, and removes the map entry in `finally`. It creates `ZendeskClient` with OAuth auth plus the typed `onUnauthorized` bridge in Task 17.

- [ ] **Step 5: Prove resolver GREEN**

```bash
npm run check
npm run build && node --test test/zendesk-client-resolver.test.mjs
```

Expected: proactive refresh, user isolation, CAS winner, restart, and single-flight tests PASS.

- [ ] **Step 6: Commit per-user resolution**

```bash
git add src/oauth/store.ts src/oauth/sqlite-store.ts src/oauth/zendesk-client-resolver.ts test/zendesk-client-resolver.test.mjs
git commit -m "feat: resolve per-user Zendesk clients"
```

---

### Task 17: Guard 401 and `invalid_grant` Races Before Reauthorization

**Files:**
- Modify: `src/oauth/zendesk-client-resolver.ts`
- Modify: `src/oauth/sqlite-store.ts`
- Create: `test/zendesk-client-resolver-races.test.mjs`

**Interfaces:**

The `onUnauthorized` callback defined in Task 15 is now fulfilled by the resolver. The terminal path calls the existing `markReauthorizationRequiredIfCurrent` store method and returns one of its three declared result kinds.

- [ ] **Step 1: State the production change before editing production files**

```text
Make every terminal 401 or invalid_grant transition conditional on the request's original epoch and credential version so an old in-flight request can never invalidate a newer login or refresh winner.
```

- [ ] **Step 2: Add the complete RED race matrix**

`test/zendesk-client-resolver-races.test.mjs` must independently control promises and cover:

- old access token 401 after a successful proactive refresh adopts the newer snapshot;
- current snapshot 401 refreshes and retries exactly once;
- second 401 on the still-current snapshot transitions only that principal to `reauthorization_required`, increments epoch, invalidates codes, and revokes its families;
- `invalid_grant` racing a newer login loses its CAS and does not revoke the winner/families;
- refresh-versus-login and concurrent login preserve the winning credential and use zero upstream cleanup calls;
- disconnect-versus-refresh prevents installation and cannot resurrect credentials;
- stale terminal failure returns `stale_failure`, not `reauthorization_required`;
- neither A's failure nor cache state affects B.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/zendesk-client-resolver-races.test.mjs
```

Expected: FAIL because terminal guard behavior is absent or incorrect.

- [ ] **Step 4: Implement the guarded unauthorized bridge**

On first 401, re-read the snapshot: return a newer access token immediately or run the same single-flight refresh for the observed snapshot. On terminal 401 or `invalid_grant`, call `markReauthorizationRequiredIfCurrent` in one transaction. Only a `true` result may increment epoch, invalidate pending codes, revoke that principal's families, and return `reauthorization_required`; a `false` result reloads the winner and returns `stale_failure`. A failed/cas-losing stage is deleted locally without refresh/delete/revoke to Zendesk.

- [ ] **Step 5: Prove race GREEN**

```bash
npm run check
npm run build && node --test test/zendesk-client-resolver.test.mjs test/zendesk-client-resolver-races.test.mjs
```

Expected: all winner, reauthorization, isolation, and zero-upstream-cleanup race tests PASS.

- [ ] **Step 6: Commit guarded invalidation**

```bash
git add src/oauth/sqlite-store.ts src/oauth/zendesk-client-resolver.ts test/zendesk-client-resolver-races.test.mjs
git commit -m "fix: guard Zendesk credential invalidation"
```

---

### Task 18: Process Explicit Disconnects with a Single Leased Revocation Worker

**Files:**
- Create: `src/oauth/revocation-worker.ts`
- Create: `test/zendesk-revocation-worker.test.mjs`

**Interfaces:**

```ts
export type ZendeskRevocationWorkerOptions = {
  store: OAuthStore;
  zendesk: ZendeskOAuthGateway;
  timeoutMs: number;
  now?: () => number;
  randomOwner?: () => string;
  pollIntervalMs?: number;
};

export class ZendeskRevocationWorker {
  constructor(options: ZendeskRevocationWorkerOptions);
  start(): void;
  stop(signal?: AbortSignal): Promise<void>;
  drain(signal?: AbortSignal): Promise<void>;
}
```

- [ ] **Step 1: State the production change before editing production files**

```text
Run only disconnect-originated cleanup with concurrency one, a unique expiring claim lease, bounded retry, and an epoch check immediately before each upstream operation so old cleanup cannot revoke a reactivated credential.
```

- [ ] **Step 2: Add failing worker tests only**

Prove one claim at a time, lease duration `timeoutMs + 5000`, renewal before a refresh-plus-delete sequence, `DELETE /current` success, 401 then refresh solely to delete, `invalid_grant`/known expiry/already-revoked terminal completion, 5xx/network exponential backoff, process-crash lease reclamation, stop abort/reschedule, and no claim/revoke after fresh reactivation. Scan all worker log output for access/refresh/email sentinels.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/zendesk-revocation-worker.test.mjs
```

Expected: FAIL with missing worker module.

- [ ] **Step 4: Implement the worker loop**

Use one process-unique opaque owner and a single in-flight promise. Before every attempt and before every renewal, claim through the store's captured-epoch predicate. Call `revokeCurrentToken`; for unauthorized responses only, refresh the tombstoned grant, renew the claim, and immediately revoke the refreshed access token. Classify retryable failures only through `ZendeskUpstreamError.retryable`; reschedule with Task 9 backoff. Do not run this worker for ordinary re-login, CAS loser, or failed staging rows.

- [ ] **Step 5: Prove worker GREEN**

```bash
npm run check
npm run build && node --test test/zendesk-revocation-worker.test.mjs test/oauth-disconnect-store.test.mjs
```

Expected: lease, retry, abort, terminal, reactivation, and secret-free logging tests PASS.

- [ ] **Step 6: Commit disconnect processing**

```bash
git add src/oauth/revocation-worker.ts test/zendesk-revocation-worker.test.mjs
git commit -m "feat: process disconnect revocations"
```

---

### Task 19: Bind Stateless HTTP Requests to OAuth Principals

**Files:**
- Modify: `src/http-app.ts`
- Modify: `test/http.test.mjs`

**Interfaces:**

```ts
export type HttpAppOptions = {
  host: string;
  allowedHosts: string[];
  provider: ZendeskBrokerOAuthProvider;
  resolver: ZendeskClientResolverLike;
  oauthRouter: Router;
  resourceMetadataUrl: string;
  isReady: () => boolean;
  serverFactory?: typeof buildZendeskServer;
};

export function createHttpApp(options: HttpAppOptions): Express;
```

- [ ] **Step 1: State the production change before editing production files**

```text
Remove the shared bearer and process-global ZendeskClient from the HTTP app, mount OAuth before protected MCP routes, verify both MCP scopes, and resolve exactly one non-secret principal ID immediately before creating each fresh MCP server.
```

- [ ] **Step 2: Replace HTTP tests with OAuth RED cases**

Modify `test/http.test.mjs` to prove:

- `/healthz` reports local readiness and never invokes resolver/Zendesk;
- unauthenticated `/mcp` returns 401 with the exact protected-resource metadata URL and required scopes;
- valid bearer lacking either scope returns 403 before resolver/server; invalid bearer does the same;
- valid bearer with `{ principalId }` resolves only that principal and builds a fresh server for each POST;
- GET/DELETE require bearer then return protocol 405 without resolving credentials;
- concurrent A/B POSTs receive distinct fake Bearer credentials with no cross result/error;
- OAuth metadata/registration/consent/callback routes are reachable before `/mcp`; and
- startup/setup failure still returns a protocol-shaped 500 without error details.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/http.test.mjs
```

Expected: FAIL because existing app expects `bearerToken` and global `client`.

- [ ] **Step 4: Implement the final mount order**

Use `createMcpExpressApp({ host, allowedHosts })`. Mount in this order: public `/healthz`; `oauthRouter`; `requireBearerAuth({ verifier: provider, requiredScopes: ["zendesk:read", "zendesk:write"], resourceMetadataUrl })` for `/mcp`; authenticated GET/DELETE 405; POST resolution/transport. For POST, require `typeof req.auth?.extra?.principalId === "string"`, call `resolver.resolve`, and pass the result to `serverFactory`. Never read `req.auth.token`, raw headers, or Zendesk values in logs.

- [ ] **Step 5: Prove HTTP integration GREEN**

```bash
npm run check
npm run build && node --test test/http.test.mjs test/oauth-router.test.mjs
```

Expected: OAuth challenge, scope, isolation, statelessness, and health/405 tests PASS.

- [ ] **Step 6: Commit the OAuth-bound HTTP app**

```bash
git add src/http-app.ts test/http.test.mjs
git commit -m "feat: bind HTTP requests to OAuth principals"
```

---

### Task 20: Compose the OAuth Runtime and Ordered Shutdown

**Files:**
- Create: `src/http-runtime.ts`
- Modify: `src/http.ts`
- Modify: `src/config.ts`
- Create: `test/http-runtime.test.mjs`
- Modify: `test/config.test.mjs`

**Interfaces:**

```ts
export type HttpRuntime = {
  app: Express;
  startWorker(): void;
  shutdown(signal: NodeJS.Signals): Promise<void>;
};

export function createHttpRuntime(config: HttpOAuthConfig): HttpRuntime;
```

- [ ] **Step 1: State the production change before editing production files**

```text
Make the HTTP entrypoint construct OAuth-only dependencies after successful store migration, expose readiness from local persistence only, start the disconnect worker after initialization, and stop work in a safe bounded order.
```

- [ ] **Step 2: Add failing runtime/config tests only**

`test/http-runtime.test.mjs` must assert construction order `cipher -> store/migrate -> Zendesk gateway -> consent/callback -> provider/router -> resolver -> worker -> app`, failure-closed store/cipher startup, no global credential-bound `ZendeskClient`, worker starts only after readiness, and shutdown order `stop claims -> abort/drain worker -> listener close -> release claims -> store close`. Add config tests proving the final `readHttpOAuthConfig` neither requires nor returns `MCP_BEARER_TOKEN`, `ZENDESK_EMAIL`, or `ZENDESK_API_KEY`; keep `readZendeskConfig` unchanged for stdio.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/http-runtime.test.mjs test/config.test.mjs
```

Expected: FAIL because the existing HTTP composition reads shared bearer/Basic configuration.

- [ ] **Step 4: Implement composition and remove legacy HTTP configuration atomically**

Create the runtime using only `readHttpOAuthConfig`; pass `oauthEncryptionKey`, `oauthDbPath`, `zendeskSubdomain`, fixed client credentials, canonical URLs, TTL, and timeout to dependencies. In this same task, retain the private `readListenerConfig(env)` introduced in Task 1, delete `HttpConfig`, `readHttpConfig`, and every HTTP shared-bearer field, and update the configuration tests. Keep `readZendeskConfig` solely for `src/index.ts`.

`src/http.ts` must listen only after `createHttpRuntime` succeeds, use the existing ten-second listener grace timer, and call runtime shutdown from SIGINT/SIGTERM exactly once. `/healthz` must return readiness even while Zendesk is unavailable; it is not an upstream health probe.

- [ ] **Step 5: Prove runtime GREEN**

```bash
npm run check
npm run build && node --test test/http-runtime.test.mjs test/config.test.mjs test/http.test.mjs
```

Expected: OAuth-only startup/shutdown, stdio preservation, and HTTP tests PASS.

- [ ] **Step 6: Commit runtime composition**

```bash
git add src/config.ts src/http-runtime.ts src/http.ts test/http-runtime.test.mjs test/config.test.mjs
git commit -m "feat: compose OAuth HTTP runtime"
```

---

### Task 21: Add Non-Model-Visible OAuth Session Administration

**Files:**
- Create: `src/oauth/admin.ts`
- Create: `scripts/oauth-admin.mjs`
- Modify: `src/config.ts`
- Modify: `package.json`
- Create: `test/oauth-admin.test.mjs`

**Interfaces:**

```ts
export type OAuthAdminConfig = {
  zendeskSubdomain: string;
  oauthEncryptionKey: Buffer;
  oauthDbPath: string;
};

export function readOAuthAdminConfig(env?: Environment): OAuthAdminConfig;

export type AdminIo = {
  stdout(message: string): void;
  stderr(message: string): void;
};

export type SessionSummary = {
  familyId: string;
  clientName: string | null;
  redirectUri: string;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
  status: "active" | "revoked" | "expired";
};

export type RevokeFamilyResult =
  | { kind: "revoked"; familyId: string }
  | { kind: "not_found" }
  | { kind: "already_revoked"; familyId: string };

export interface OAuthStore {
  listSessions(subdomain: string, zendeskUserId: string, now: number): SessionSummary[];
  revokeFamilyById(familyId: string, now: number): RevokeFamilyResult;
}

export async function runOAuthAdmin(
  argv: string[],
  env?: Environment,
  io?: AdminIo,
): Promise<number>;
```

- [ ] **Step 1: State the production change before editing production files**

```text
Expose operator-run session listing, family revoke, principal disconnect, and a new-file-only consistent backup through a non-model-visible CLI that opens the same encrypted store, requires explicit confirmation for mutation, and never prints secrets or email addresses.
```

- [ ] **Step 2: Add failing CLI tests only**

Create `test/oauth-admin.test.mjs` and assert:

- `sessions --zendesk-user-id 123` returns opaque family ID, escaped client name, loopback redirect, created/last-use/expiry/status only;
- `revoke-family --family-id family-1` and `disconnect-user --zendesk-user-id 123` exit `2` and mutate nothing without literal `--confirm`;
- confirmed revoke changes only that family; confirmed disconnect affects only that principal and enqueues outbox work;
- `backup --destination /data/backups/snapshot.sqlite` refuses an existing path, creates a readable SQLite backup with the correct key, and never exposes the key or ciphertext;
- malformed/missing arguments exit `2`; store/cipher errors exit `1`; success exits `0`;
- stored control characters in client names cannot control the terminal; and
- output contains no raw token, refresh token, grant, email, ciphertext, or database path sentinel.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/oauth-admin.test.mjs
```

Expected: FAIL with missing `runOAuthAdmin`.

- [ ] **Step 4: Implement the parser and thin executable**

`readOAuthAdminConfig` must require only fixed subdomain, 32-byte encryption key, and absolute DB path; it must not require listener URL, bearer, Zendesk API token, or OAuth client secret. Implement exactly these scripts:

```json
{
  "oauth:sessions": "node scripts/oauth-admin.mjs sessions",
  "oauth:revoke-family": "node scripts/oauth-admin.mjs revoke-family",
  "oauth:disconnect-user": "node scripts/oauth-admin.mjs disconnect-user",
  "oauth:backup": "node scripts/oauth-admin.mjs backup"
}
```

Implement `OAuthStore.listSessions` as a subdomain/user join that returns only `SessionSummary`, and `revokeFamilyById` as one family-only update that never touches the principal credential or another family. For `backup`, create `/data/backups` mode `0700` if missing, reject any existing destination or path outside that directory, then call `store.backup(destination)`. `scripts/oauth-admin.mjs` imports `runOAuthAdmin`, passes `process.argv.slice(2)`, and assigns `process.exitCode`; it does not invoke `process.exit()` or start a revocation worker. Enforce decimal Zendesk IDs, opaque family IDs matching `[A-Za-z0-9_-]{16,}`, literal `--confirm` for mutation, and a new absolute backup destination under `/data/backups/`. Always close the opened store in `finally`. Escape output by replacing ASCII controls with `?`.

- [ ] **Step 5: Prove admin GREEN**

```bash
npm run check
npm run build && node --test test/oauth-admin.test.mjs
```

Expected: argument, confirmation, isolation, output-safety, and exit-code tests PASS.

- [ ] **Step 6: Commit session administration**

```bash
git add src/oauth/admin.ts src/oauth/store.ts src/oauth/sqlite-store.ts scripts/oauth-admin.mjs src/config.ts package.json test/oauth-admin.test.mjs
git commit -m "feat: add OAuth session administration"
```

---

### Task 22: Exercise the Complete Local Broker with Fake Zendesk

**Files:**
- Create: `test/helpers/oauth-fixture.mjs`
- Create: `test/oauth-e2e.test.mjs`
- Modify: `test/http.test.mjs`
- Modify: `test/server-instructions.test.mjs`

**Interfaces:**

`createOAuthFixture(t, options?)` creates an isolated temporary SQLite DB, fixed clock, `TokenCipher`, fake Zendesk server, registered Codex client, provider, consent controller, callback controller, OAuth router, resolver, and HTTP app. It returns these test helpers:

```js
await fixture.registerClient()
await fixture.beginBrowserLogin()
await fixture.confirmConsent()
await fixture.completeZendeskCallback({ zendeskUserId: '101' })
await fixture.exchangeMcpCode()
await fixture.callMcp(accessToken, request)
```

- [ ] **Step 1: State the production change before editing production files**

```text
Prove the integrated SDK handler chain and every local success criterion with two fake Zendesk principals, without a live tenant, copied bearer, Tailscale, or test-ticket mutation.
```

- [ ] **Step 2: Add one end-to-end happy-path test and prove RED**

Create the first test in `test/oauth-e2e.test.mjs` that performs discovery, dynamic registration, authorization, local consent, fake Zendesk callback, MCP code exchange, authenticated initialize/list-tools, a ticket read, and a resource read. Assert all twelve tools, both prompts, and `zendesk://knowledge-base` are still registered.

Run:

```bash
npm run build && node --test test/oauth-e2e.test.mjs
```

Expected: FAIL until all prior wiring is present.

- [ ] **Step 3: Add the remaining exact integration cases**

Add separate tests for:

- two principals issuing distinct Bearer headers concurrently without cache/result/error crossover;
- all metadata/resource/redirect/PKCE/code/refresh/revoke bindings;
- one access-token refresh, `R1 -> R2 -> R3`, restart persistence, and current-rmcp omitted-resource compatibility;
- local logout semantics: deleting a local client credential is not asserted as server revocation; RFC 7009 family revoke is;
- principal disconnect immediate local invalidation and outbox eligibility with fake upstream;
- secret sentinels absent from all fixture logs, database bytes, HTTP errors, MCP tool output, and metadata;
- malformed consent/callback/token inputs return only stable errors; and
- failure of A never causes fallback to B or a default account.

- [ ] **Step 4: Implement only fixture wiring required by those tests**

The fixture may inject clock/random/fetch functions but must use the production router, provider, store, resolver, `ZendeskClient`, `buildZendeskServer`, and Streamable HTTP transport. Do not duplicate production authorization logic inside test helpers. Attach one scoped log collector and restore global `fetch`/console state in `t.after`.

- [ ] **Step 5: Prove end-to-end GREEN**

```bash
npm run check
npm test
```

Expected: current regression tests plus all OAuth integration tests PASS.

- [ ] **Step 6: Commit integration coverage**

```bash
git add test/helpers/oauth-fixture.mjs test/oauth-e2e.test.mjs test/http.test.mjs test/server-instructions.test.mjs
git commit -m "test: cover OAuth broker end to end"
```

---

### Task 23: Package a Persistent, Non-Root OAuth HTTP Deployment

**Files:**
- Modify: `Dockerfile`
- Modify: `docker-compose.yml`
- Delete: `.env.example`
- Create: `.env.stdio.example`
- Create: `.env.http.example`
- Modify: `test/deployment.test.mjs`

**Interfaces:**

The Compose service remains `zendesk-mcp`; its only persistent writable path is named volume `oauth-data:/data`. The final runtime has no compiler, no `npm ci`, no shared HTTP bearer, no Zendesk email/API token, and retains loopback port publication, `read_only`, tmpfs `/tmp`, non-root user, `no-new-privileges`, and 15-second stop grace.

- [ ] **Step 1: State the production change before editing production files**

```text
Build the native SQLite dependency once in the Alpine build stage, copy the pruned production result into a non-root read-only runtime, and mount an encrypted OAuth database volume at /data.
```

- [ ] **Step 2: Add failing deployment/static tests only**

Extend `test/deployment.test.mjs` to assert all of:

- `${MCP_BIND_ADDRESS:-127.0.0.1}:${MCP_HOST_PORT:-38184}:3000` remains the only port publication;
- `oauth-data:/data` exists and `/data` is created/chowned before `USER node`;
- runtime stage copies pruned `node_modules` and never runs `npm ci`, `npm install`, or compiler-toolchain setup;
- root filesystem remains read-only with `/tmp` tmpfs and `no-new-privileges`;
- HTTP template includes only public URL, subdomain, OAuth client ID/secret placeholders, encryption-key placeholder, DB path, listener/host/port/TTL/timeout; no shared bearer, email, or API token;
- stdio template includes only subdomain, email, and API token; and
- real `.env` remains ignored and the former combined template is deleted.

- [ ] **Step 3: Prove RED**

```bash
npm run build && node --test test/deployment.test.mjs
```

Expected: FAIL against the current runtime `npm ci`, absent volume, and shared-bearer template.

- [ ] **Step 4: Implement the multi-stage image and Compose volume**

Use this final Dockerfile shape:

```dockerfile
FROM node:22-alpine AS build
WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node scripts/oauth-admin.mjs ./scripts/oauth-admin.mjs
RUN mkdir /data && chown node:node /data && chmod 0700 /data
USER node
EXPOSE 3000
CMD ["node", "dist/http.js"]
```

In Compose, add `oauth-data:/data` beneath the service and define top-level `oauth-data:`. Keep all existing security properties and health endpoint. Create templates with placeholders only; `.env.http.example` must set `OAUTH_DB_PATH=/data/oauth.sqlite` and state that `OAUTH_ENCRYPTION_KEY` is a separately generated base64 32-byte key.

- [ ] **Step 5: Prove packaging GREEN**

```bash
npm run check
npm run build && node --test test/deployment.test.mjs
docker compose config
docker compose build zendesk-mcp
```

Expected: static tests, Compose validation, and Alpine image build PASS.

- [ ] **Step 6: Commit deployment packaging**

```bash
git add Dockerfile docker-compose.yml .env.stdio.example .env.http.example test/deployment.test.mjs
git rm .env.example
git commit -m "build: package persistent OAuth deployment"
```

---

### Task 24: Replace Shared-Bearer Smoke and Document OAuth Operations

**Files:**
- Modify: `scripts/smoke-http.mjs`
- Modify: `README.md`
- Create: `test/smoke-http.test.mjs`
- Create: `test/documentation.test.mjs`

**Interfaces:**

`npm run smoke:http` accepts only `MCP_URL`. It uses unauthenticated HTTP requests and exits nonzero unless health, 401 challenge, protected-resource metadata, and authorization-server metadata match the configured canonical OAuth contract. It never reads bearer/Zendesk credential environment values, initializes an MCP client, lists tools, or calls Zendesk.

- [ ] **Step 1: State the production change before editing production files**

```text
Make the operational smoke prove discovery without copied secrets, and make documentation distinguish stdio API-token use from OAuth HTTP use, login, revocation, backup, rollback, and client cutover.
```

- [ ] **Step 2: Add failing smoke/documentation tests only**

`test/smoke-http.test.mjs` starts the production HTTP app fixture and asserts the script requires `MCP_URL`, succeeds without any credential environment variable, checks `/healthz`, reads the 401 challenge, follows the metadata URL, and validates exact `/mcp` resource, issuer, endpoints, S256, scopes, and public-client `none` methods. `test/documentation.test.mjs` asserts README contains URL-only Codex config and `codex mcp login zendesk`, explains local-only `codex mcp logout`, and has no shared-bearer guidance in the HTTP/Compose section.

- [ ] **Step 3: Prove RED**

```bash
node --test test/smoke-http.test.mjs test/documentation.test.mjs
```

Expected: FAIL because current smoke requires `MCP_BEARER_TOKEN` and README tells clients to copy it.

- [ ] **Step 4: Implement no-secret smoke and exact operations guidance**

`scripts/smoke-http.mjs` must use `fetch` only, parse `WWW-Authenticate` without printing values, and output a compact JSON success record containing only `ok`, `issuer`, and `resource`. README must include:

- separate stdio and HTTP environment templates;
- registering the exact Zendesk callback `${PUBLIC_BASE_URL}/oauth/zendesk/callback` and requesting `read tickets:write`;
- full-origin Tailscale Serve so metadata and OAuth routes are reachable;
- URL-only Codex configuration followed by `codex mcp login zendesk`;
- exact distinction between client-local `codex mcp logout` and server family revocation/disconnect commands;
- encrypted SQLite backup via `npm run oauth:backup -- --destination /data/backups/<new-name>.sqlite`, checkpointed restore into a disposable volume, and separate encryption-key custody;
- maintenance-window inventory, redacted check that `http_headers.Authorization`, `bearer_token_env_var`, and `env_http_headers.Authorization` are absent, atomic rollback of image/environment/client config, and delayed secret retirement; and
- the intentional ordinary-relogin orphan-grant tradeoff and Zendesk tenant-audit recovery.

- [ ] **Step 5: Prove smoke/docs GREEN**

```bash
npm run build && node --test test/smoke-http.test.mjs test/documentation.test.mjs
MCP_URL=http://127.0.0.1:38184/mcp npm run smoke:http
```

Expected: local fixture tests PASS; the manual command succeeds only against a running OAuth-enabled local container and requires no secret.

- [ ] **Step 6: Commit operations documentation**

```bash
git add scripts/smoke-http.mjs README.md test/smoke-http.test.mjs test/documentation.test.mjs
git commit -m "docs: document per-user OAuth operations"
```

---

### Task 25: Run the Local Release Gate, Then Separate Staging and Cutover Gates

**Files:**
- Modify only if a gate exposes a defect; each defect gets its own focused RED/GREEN fix commit.

**Interfaces:**
- No new production interface. This task proves the previously committed ones together.

- [ ] **Step 1: Run the local release gate without external mutation**

Before this step, create an untracked `.env.http.local` from `.env.http.example` with a locally generated base64 32-byte encryption key and non-production placeholder Zendesk OAuth client values. The health/metadata gate must not contact Zendesk.

```bash
npm run check
npm test
git diff --check
MCP_ENV_FILE=.env.http.local docker compose config
docker compose build zendesk-mcp
MCP_ENV_FILE=.env.http.local docker compose up -d --wait
curl --fail http://127.0.0.1:38184/healthz
MCP_ENV_FILE=.env.http.local docker compose down
```

Expected: all commands exit `0`; no Zendesk login, ticket mutation, or disconnect is performed.

- [ ] **Step 2: Verify container security and persistence locally**

```bash
MCP_ENV_FILE=.env.http.local docker compose up -d --wait
MCP_ENV_FILE=.env.http.local docker compose exec -T zendesk-mcp id -u
MCP_ENV_FILE=.env.http.local docker compose exec -T zendesk-mcp sh -c 'test -w /data && test -w /tmp && ! test -w /'
MCP_ENV_FILE=.env.http.local docker compose restart zendesk-mcp
MCP_ENV_FILE=.env.http.local docker compose ps
MCP_ENV_FILE=.env.http.local docker compose down
```

Expected: UID is not `0`, `/data` and `/tmp` are writable, root is not writable, health returns after restart, and the named volume persists.

Still in the disposable local environment, run `npm run oauth:backup -- --destination /data/backups/local-release.sqlite` inside the container, restore that file into a separate disposable volume, and prove the same separately retained key opens the store while a different key fails closed. This is a local backup test only; it must not call Zendesk or disconnect a principal.

- [ ] **Step 3: Run the staging browser and refresh compatibility gate**

Before this step, obtain separate authorization for staging deployment and register exactly `https://dev-server.tail22145b.ts.net/oauth/zendesk/callback` in Zendesk. Set staging `MCP_ACCESS_TOKEN_TTL_SECONDS=60`, connect the browser to Tailscale, run `codex mcp login zendesk`, complete local and Zendesk consent, then keep two Codex Desktop tasks open. Alternate MCP calls across at least three access-token expiry/refresh generations; repeat with the current CLI. Restore TTL `900` only after success.

Expected: both clients recover without restart, re-login, stale token, or `invalid_grant`. Any failure is a release blocker because the known Codex refresh compatibility issue cannot be solved by silently extending lifetime or disabling rotation.

- [ ] **Step 4: Run live scope, attribution, and isolation checks**

With normal TTL restored, perform ticket/field/audit/comment reads, user identity/search, organization search, general search, and Help Center resource access. Log in as a second Zendesk user from another client and prove concurrent reads remain isolated. The `read` scope must be demonstrated specifically through `get_ticket_audits` because it is why global read was approved.

Expected: each call reflects its user's Zendesk permissions; no response/error crosses principals.

- [ ] **Step 5: Request explicit approval before either live mutation**

Do not proceed until the user separately names:

1. a test ticket and approves exactly one private comment to prove `tickets:write` and audit attribution; and
2. a disposable Zendesk principal and approves exactly one `oauth:disconnect-user --confirm` operation.

After approval, verify comment audit `author_id` equals the OAuth `users/me` ID. For disconnect, prove immediate family invalidation, a controlled transient outbox retry, eventual upstream rejection while captured epoch remains disconnected, and no impact on the other principal.

- [ ] **Step 6: Complete client cutover only with maintenance-window approval**

Inventory all URL clients without exposing secrets. Deploy OAuth image/volume, remove `MCP_BEARER_TOKEN`, `ZENDESK_EMAIL`, and `ZENDESK_API_KEY` only from the HTTP deployment, remove every client `http_headers.Authorization`, `bearer_token_env_var`, and `env_http_headers.Authorization`, retain URL-only config, and run `codex mcp login zendesk` per client. Roll back image, HTTP environment, and affected client entries together on a release-gate failure; never leave dual shared/OAuth auth active. Destroy old bearer material and secured rollback copies only after a separately confirmed retirement scope.

Expected: every inventory client fails closed until it completes OAuth; stdio remains unchanged; no shared bearer survives the cutover.

## Specification Coverage Review

| Approved requirement | Planned tasks |
| --- | --- |
| Preserve stdio API-token use, all 12 tools, prompts, and resource | T0, T1, T15, T19, T22, T25 |
| Separate MCP and Zendesk credential domains | T2, T5–T8, T10–T11, T15–T20 |
| Public dynamic registration, S256 PKCE, exact loopback redirect | T4, T10, T12–T13 |
| Fixed subdomain, encrypted SQLite, and fail-closed startup | T1–T3, T20, T23 |
| One-time browser consent, callback state, and atomic staged login | T5–T6, T13–T14 |
| Audience-bound codes, access tokens, refresh rotation, and family revocation | T7–T10, T22 |
| Global Zendesk `read` plus `tickets:write` and per-user role enforcement | T11, T15–T17, T22, T25 |
| Request-scoped client isolation and fresh stateless MCP server per POST | T15–T20, T22 |
| Disconnect fencing and durable upstream-revocation outbox | T9, T18, T21–T22 |
| Sanitized errors, secret-free logs, headers, and rate limits | T2, T11–T15, T18–T22 |
| Non-root persistent deployment, backup/restore, and OAuth-only HTTP cutover | T3, T21, T23–T25 |
| Codex refresh compatibility and real Zendesk acceptance | T25 staging and cutover gates |

## Deliberate External Gates

- The plan proves protocol behavior locally with fake Zendesk. A real Codex Desktop/CLI multi-refresh run, tailnet browser callback, and endpoint-family scope probe remain mandatory staging evidence in Task 25.
- The controlled ticket comment and disposable-principal disconnect are intentionally outside ordinary implementation authority. Task 25 requires a separately named target and explicit approval immediately before each mutation.
- Secret retirement and deletion of old shared-bearer rollback material happen only after the completed cutover gate and a separate confirmation of the exact retirement scope.
