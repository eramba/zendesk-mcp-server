# Zendesk Internal User Bearers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the shared HTTP MCP/Zendesk identity with hash-only per-user MCP bearers that resolve encrypted, refreshable Zendesk OAuth grants, while preserving stateless HTTP and stdio API-token behavior.

**Architecture:** A focused SQLite store owns internal user mappings, one-time invitations, and AES-256-GCM OAuth grants. A fixed Zendesk OAuth gateway links identities through `users/me`; a per-user single-flight resolver supplies an explicit request-scoped `ZendeskClient` to the existing `buildZendeskServer(client)` extension point.

**Tech Stack:** Node.js 20+, TypeScript 5.9, Express through `@modelcontextprotocol/sdk` 1.26, `better-sqlite3` 12.11.1, Node crypto AES-256-GCM/SHA-256, Node test runner, Docker Compose.

## Global Constraints

- Execute sequentially in `/Users/shrkz1/Typescript-JS/zendesk-mcp-server` on `codex/zendesk-internal-user-bearers`; do not create another worktree.
- Follow strict focused RED/GREEN. Before each test edit, record the current path and intended production change in `.superpowers/sdd/progress.md`; save only the test, run it, and observe the expected missing-behavior failure before production changes.
- Preserve 12 tools, 2 prompts, 1 `zendesk://knowledge-base` resource, fresh stateless HTTP transports, host validation, public `/healthz`, and stdio API-token behavior.
- HTTP has no shared Zendesk credential, shared bearer fallback, global mutable user, credential tool input, inbound MCP OAuth server, token family, durable worker, outbox, distributed lock, or web admin UI.
- Use one fixed Zendesk subdomain, OAuth client ID, callback URL, and scope `read tickets:write`.
- Store MCP bearers, invitation tokens, and OAuth states only as SHA-256 hashes; encrypt access and refresh tokens with AES-256-GCM and a separately configured 32-byte base64url key.
- Network operations have 10-second bounded timeouts, reject redirects, respect ownership-aware cancellation, and expose no secrets in errors or logs.
- Same-user refreshes are single-flight and use conditional versioned persistence; different users refresh independently.
- Locally revoke first. Optional upstream revocation is one bounded synchronous attempt with an exact reported outcome and no retry machinery.
- No live Zendesk login, request, mutation, revocation, deployment, cutover, or credential retirement is authorized.

---

### Task 1: Split and validate HTTP OAuth configuration

**Files:**

- Modify: `src/config.ts`
- Modify: `test/config.test.mjs`

**Interfaces:**

- Preserve: `readZendeskConfig(env): ZendeskConfig` for stdio.
- Produce:

```ts
export type HttpOAuthConfig = {
  host: string;
  port: number;
  allowedHosts: string[];
  publicBaseUrl: URL;
  zendeskSubdomain: string;
  zendeskOAuthClientId: string;
  zendeskOAuthClientSecret: string;
  oauthEncryptionKey: Buffer;
  oauthDbPath: string;
  zendeskCallbackUrl: URL;
};

export function readHttpOAuthConfig(
  env?: Environment,
): HttpOAuthConfig;
```

- `PUBLIC_BASE_URL` must be an origin-only HTTPS URL, except that
  `http://localhost` and loopback IP hosts are allowed for local tests.
- `ZENDESK_SUBDOMAIN` must be one DNS label.
- `OAUTH_ENCRYPTION_KEY` must decode from canonical base64url to exactly
  32 bytes.
- `OAUTH_DB_PATH` must be absolute.

- [ ] **Step 1: Record the current configuration flow and intended change**

Use `apply_patch` to record that HTTP currently calls `readZendeskConfig()` plus
`readHttpConfig()` and that the production change will create a distinct HTTP
OAuth reader without changing the stdio reader.

- [ ] **Step 2: Replace HTTP configuration tests with the desired contract**

Add literal fixtures and assertions equivalent to:

```js
const HTTP_ENV = {
  PUBLIC_BASE_URL: 'https://mcp.example.test',
  ZENDESK_SUBDOMAIN: 'acme',
  ZENDESK_OAUTH_CLIENT_ID: 'internal-mcp',
  ZENDESK_OAUTH_CLIENT_SECRET: 'client-secret-sentinel',
  OAUTH_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64url'),
  OAUTH_DB_PATH: '/var/lib/zendesk-mcp/oauth.sqlite',
}

const config = readHttpOAuthConfig(HTTP_ENV)
assert.equal(config.publicBaseUrl.href, 'https://mcp.example.test/')
assert.equal(
  config.zendeskCallbackUrl.href,
  'https://mcp.example.test/oauth/callback',
)
assert.deepEqual(config.oauthEncryptionKey, Buffer.alloc(32, 7))
assert.equal('zendeskOAuthClientSecret' in JSON.parse(JSON.stringify({
  host: config.host,
})), false)
```

Cover every required key, origin-only URL rules, loopback HTTP allowance,
unsafe schemes/credentials/query/fragment/path, invalid subdomains, noncanonical
or wrong-length keys, relative database paths, ports, and allowed-host parsing.
Assertions must check variable names but never secret values.

- [ ] **Step 3: Run the focused test and confirm RED**

Run:

```bash
npm run build && node --test test/config.test.mjs
```

Expected RED: `readHttpOAuthConfig` is not exported or the old shared
`MCP_BEARER_TOKEN` contract produces different results.

- [ ] **Step 4: Implement the minimal configuration reader**

Use `URL`, `isAbsolute` from `node:path`, `isIP` from `node:net`, and canonical
base64url round-trip validation. Return copied key bytes. Do not retain
`bearerToken` in the HTTP configuration.

- [ ] **Step 5: Run the same test and confirm GREEN**

Run:

```bash
npm run build && node --test test/config.test.mjs
```

Expected: all configuration tests pass with no printed secret values.

- [ ] **Step 6: Commit**

```bash
git add src/config.ts test/config.test.mjs
git commit -m "feat: add per-user HTTP OAuth config"
```

### Task 2: Add cryptography, focused SQLite schema, and hash-only bearer mapping

**Files:**

- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `src/internal-auth/crypto.ts`
- Create: `src/internal-auth/store.ts`
- Create: `test/internal-auth-store.test.mjs`

**Interfaces:**

```ts
export type OAuthGrant = {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
  scopes: string[];
};

export type UserStatus =
  | "pending"
  | "active"
  | "revoked"
  | "reauthorization_required";

export type CredentialSnapshot = {
  userId: string;
  zendeskUserId: string;
  version: number;
  grant: OAuthGrant;
};

export class SecretCipher {
  constructor(key: Buffer);
  encrypt(plaintext: string, associatedData: string): string;
  decrypt(envelopeJson: string, associatedData: string): string;
}

export function randomOpaque(prefix?: string): string;
export function hashOpaque(value: string): string;

export class InternalAuthStore {
  static open(options: {
    path: string;
    cipher: SecretCipher;
    subdomain: string;
    clientId: string;
    now?: () => number;
  }): InternalAuthStore;

  createPendingUser(label: string): {
    userId: string;
    bearer: string;
    invitation: string;
    expiresAt: number;
  };

  authenticateBearer(bearer: string): { userId: string } | undefined;
  loadCredential(userId: string): CredentialSnapshot | undefined;
  inspectUsers(): Array<{
    id: string;
    label: string;
    status: UserStatus;
    zendeskUserId: string | null;
    zendeskName: string | null;
    zendeskEmail: string | null;
    createdAt: number;
    updatedAt: number;
    revokedAt: number | null;
    invitationStatus: "none" | "pending" | "started" | "consumed" | "expired";
    invitationExpiresAt: number | null;
  }>;
  close(): void;
}
```

The schema has only `store_metadata`, `internal_users`,
`oauth_invitations`, and `oauth_grants`, with the columns and protections in
the design specification.

- [ ] **Step 1: Record the current persistence absence and intended change**

State that the repository has no durable auth store and production will add one
versioned schema, a key check, mode-`0600` database, random bearer generation,
and hash-only active lookup.

- [ ] **Step 2: Write store and crypto tests first**

Use a real temporary SQLite file. Add behavior tests equivalent to:

```js
const created = store.createPendingUser('Martin')
assert.match(created.bearer, /^zmcp_[A-Za-z0-9_-]{43}$/)
assert.match(created.invitation, /^[A-Za-z0-9_-]{43}$/)
assert.equal(store.authenticateBearer(created.bearer), undefined)

const bytes = await readFile(dbPath)
assert.equal(bytes.includes(Buffer.from(created.bearer)), false)
assert.equal(bytes.includes(Buffer.from(created.invitation)), false)
assert.equal(bytes.includes(Buffer.from('Martin')), true)
```

Also prove:

- 100 generated bearers/invitations are unique;
- only four expected tables exist;
- schema and partial unique indexes exist;
- the database file mode is `0600`;
- reopening with the same key succeeds;
- reopening with another key fails with a safe key-check error;
- malformed key-check envelopes fail closed without ciphertext text;
- unknown and malformed bearers return no mapping;
- a pending bearer cannot authenticate.

Use direct readonly SQLite inspection only to assert persistence outcomes, not
private JavaScript call counts.

- [ ] **Step 3: Run the focused test and confirm RED**

Run:

```bash
npm run build && node --test test/internal-auth-store.test.mjs
```

Expected RED: the new modules or `InternalAuthStore` behavior does not exist.

- [ ] **Step 4: Add the required SQLite dependency and minimal implementation**

Install exact versions:

```bash
npm install better-sqlite3@12.11.1
npm install --save-dev @types/better-sqlite3@7.6.13
```

Implement:

- SHA-256 exact lookup;
- AES-256-GCM canonical JSON envelopes with 12-byte nonce and 16-byte tag;
- schema creation in one transaction;
- WAL, foreign keys, full synchronous durability, secure delete,
  untrusted schema, and 5-second busy timeout;
- encrypted key-check creation/verification;
- unique bearer hash and non-null Zendesk identity indexes;
- generated `zmcp_` bearer and independent invitation;
- pending-user insert plus invitation insert in one transaction;
- safe decryption errors with no envelope or key content.

- [ ] **Step 5: Run the same test and confirm GREEN**

Run:

```bash
npm run build && node --test test/internal-auth-store.test.mjs
```

Expected: store/crypto tests pass.

- [ ] **Step 6: Run existing tests for regression**

Run:

```bash
npm test
```

Expected: existing 18 tests plus the new focused tests pass.

- [ ] **Step 7: Commit**

```bash
git add package.json package-lock.json src/internal-auth/crypto.ts src/internal-auth/store.ts test/internal-auth-store.test.mjs
git commit -m "feat: persist internal user credentials"
```

### Task 3: Complete invitation, grant, revocation, and backup transactions

**Files:**

- Modify: `src/internal-auth/store.ts`
- Modify: `test/internal-auth-store.test.mjs`

**Interfaces:**

Add:

```ts
startInvitation(invitation: string, state: string): {
  invitationId: string;
  userId: string;
  expiresAt: number;
} | undefined;

claimCallback(state: string): {
  invitationId: string;
  userId: string;
} | undefined;

completeLink(input: {
  invitationId: string;
  userId: string;
  identity: {
    id: string;
    name: string | null;
    email: string | null;
  };
  grant: OAuthGrant;
}): CredentialSnapshot;

createReauthorization(userId: string): {
  invitation: string;
  expiresAt: number;
};

installRefreshedGrant(input: {
  userId: string;
  expectedVersion: number;
  grant: OAuthGrant;
}):
  | { kind: "installed"; snapshot: CredentialSnapshot }
  | { kind: "newer"; snapshot: CredentialSnapshot }
  | { kind: "inactive" };

markReauthorizationRequired(
  userId: string,
  expectedVersion: number,
): boolean;

revokeUser(userId: string): {
  kind: "revoked" | "already_revoked" | "not_found";
  capturedGrant?: OAuthGrant;
};

backup(destination: string): Promise<void>;
```

- [ ] **Step 1: Record the transaction lifecycle and intended change**

Write the current store flow and the exact state transitions:

```text
pending invitation
  -> atomically started with state hash
  -> atomically callback-claimed
  -> atomically active with encrypted version-1 grant
active version N
  -> conditional active version N+1
active
  -> revoked or reauthorization_required with grant deletion
```

- [ ] **Step 2: Add transaction behavior tests**

Prove with literal clocks and real concurrent calls:

- invitation and state plaintext never appear in SQLite;
- invitation expiry is 30 minutes;
- start is one-time and rejects expired/reused tokens;
- state is independent from invitation and callback claim is one-time;
- wrong/missing/mismatched state cannot claim;
- only the intended user activates;
- duplicate Zendesk identity cannot activate a second mapping;
- failed/mismatched completion leaves the mapping non-active;
- grant activation and user status update are atomic;
- access and refresh plaintext never appear in the file, WAL, or SHM;
- conditional refresh installs version `N + 1`, a stale writer adopts the
  winner, and inactive users cannot be updated;
- terminal reauthorization and revocation remove the credential in the same
  transaction;
- pending, revoked, and reauthorization-required bearers cannot authenticate,
  while only an active mapping with a valid grant can authenticate;
- reauthorization creates a fresh link but never a bearer;
- expired and old consumed invitations are cleaned opportunistically without a
  background worker;
- backup reopens with the same key, rejects a different key, and has mode
  `0600`.

- [ ] **Step 3: Run the focused tests and confirm RED**

Run:

```bash
npm run build && node --test --test-name-pattern="invitation|callback|grant|refresh|revok|backup" test/internal-auth-store.test.mjs
```

Expected RED: lifecycle methods are absent.

- [ ] **Step 4: Implement minimal transactional methods**

Use `better-sqlite3` transactions and guarded updates:

```sql
UPDATE oauth_invitations
SET state_hash = ?, started_at = ?
WHERE invitation_hash = ?
  AND started_at IS NULL
  AND consumed_at IS NULL
  AND expires_at > ?;
```

```sql
UPDATE oauth_grants
SET version = ?, encrypted_grant = ?, access_expires_at = ?,
    refresh_expires_at = ?, updated_at = ?
WHERE user_id = ? AND version = ?
  AND EXISTS (
    SELECT 1 FROM internal_users
    WHERE id = ? AND status = 'active'
  );
```

Clean expired/consumed invitations opportunistically. Encrypt the new version
before conditional install, then load the winner when the update loses.

- [ ] **Step 5: Run the same tests and confirm GREEN**

Run:

```bash
npm run build && node --test test/internal-auth-store.test.mjs
```

Expected: all store lifecycle tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/internal-auth/store.ts test/internal-auth-store.test.mjs
git commit -m "feat: add one-time user linking state"
```

### Task 4: Implement the fixed Zendesk OAuth gateway and linking handlers

**Files:**

- Create: `src/internal-auth/errors.ts`
- Create: `src/internal-auth/zendesk-oauth.ts`
- Create: `src/internal-auth/link-handlers.ts`
- Create: `test/zendesk-oauth.test.mjs`
- Create: `test/oauth-linking.test.mjs`

**Interfaces:**

```ts
export class SafeAuthError extends Error {
  readonly category:
    | "invalid_grant"
    | "unauthorized"
    | "forbidden"
    | "rate_limited"
    | "temporarily_unavailable"
    | "invalid_response"
    | "aborted"
    | "reauthorization_required";
  readonly correlationId: string;
  readonly retryable: boolean;
}

export interface ZendeskOAuthGateway {
  authorizationUrl(state: string): URL;
  exchangeCode(code: string, signal?: AbortSignal): Promise<OAuthGrant>;
  refresh(refreshToken: string, signal?: AbortSignal): Promise<OAuthGrant>;
  currentUser(accessToken: string, signal?: AbortSignal): Promise<{
    id: string;
    name: string | null;
    email: string | null;
  }>;
  revokeCurrent(accessToken: string, signal?: AbortSignal): Promise<void>;
}

export type ZendeskOAuthOptions = {
  subdomain: string;
  clientId: string;
  clientSecret: string;
  callbackUrl: URL;
  timeoutMs: number;
  signal?: AbortSignal;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
};

export class ZendeskOAuthClient implements ZendeskOAuthGateway {
  constructor(options: ZendeskOAuthOptions);
}

export function createLinkHandlers(options: {
  store: InternalAuthStore;
  oauth: ZendeskOAuthGateway;
  now?: () => number;
}): {
  link: RequestHandler;
  callback: RequestHandler;
};
```

- [ ] **Step 1: Record fixed-host protocol and intended change**

Record the four fixed upstream endpoints, fixed callback binding, approved
scope, explicit TTLs, safe errors, no cookies, and state claim before code
exchange.

- [ ] **Step 2: Write OAuth gateway tests**

With a fake fetch, assert exact URLs, methods, redirects, authorization scheme,
and payloads:

```js
assert.deepEqual(Object.fromEntries(oauth.authorizationUrl('state').searchParams), {
  response_type: 'code',
  client_id: 'client-id',
  redirect_uri: 'https://mcp.example.test/oauth/callback',
  scope: 'read tickets:write',
  state: 'state',
  expires_in: '1800',
  refresh_token_expires_in: '2592000',
})
```

Prove strict token response parsing, set-equivalent approved scopes, integer
expiries, rotated refresh token capture, `users/me` identity parsing,
current-token `DELETE`, redirect rejection, timeout/call/shutdown abort, and
safe classification. Put body, header, token, code, state, client-secret, and
transport sentinels in fake failures and assert none appear in errors/logs.

- [ ] **Step 3: Run OAuth tests and confirm RED**

Run:

```bash
npm run build && node --test test/zendesk-oauth.test.mjs
```

Expected RED: gateway and safe error types do not exist.

- [ ] **Step 4: Implement the fixed gateway**

Use JSON requests to `/oauth/tokens`, `redirect: "error"`, combined abort
signals, and strict response validation. Consume error bodies only for bounded
classification and never embed them in errors.

- [ ] **Step 5: Run OAuth tests and confirm GREEN**

Run:

```bash
npm run build && node --test test/zendesk-oauth.test.mjs
```

- [ ] **Step 6: Write link/callback tests**

Mount the handlers on a local MCP Express app. Prove:

- missing, duplicate, expired, reused, and unknown invitation values return a
  fixed safe `400` or `410`;
- success sets `Cache-Control: no-store` and
  `Referrer-Policy: no-referrer`, then redirects only to the fixed Zendesk
  origin;
- no cookie or bearer appears;
- independently generated OAuth states match the 32-byte base64url shape and
  remain unique across repeated invitation starts;
- callback claims state before gateway exchange;
- missing, mismatched, expired, and replayed state never calls exchange;
- successful callback calls `exchangeCode`, then `currentUser`, then activates
  exactly the claimed mapping;
- identity comes from fake `users/me`, not the admin label;
- an exchange/identity/duplicate-identity failure does not activate and makes
  one best-effort bounded revocation only if an access token exists;
- browser responses and captured logs contain no invitation, state, code,
  access token, refresh token, client secret, or encryption key sentinel.

- [ ] **Step 7: Run linking tests and confirm RED**

Run:

```bash
npm run build && node --test test/oauth-linking.test.mjs
```

Expected RED: handlers do not exist.

- [ ] **Step 8: Implement linking handlers and confirm GREEN**

Run:

```bash
npm run build && node --test test/oauth-linking.test.mjs
```

- [ ] **Step 9: Commit**

```bash
git add src/internal-auth/errors.ts src/internal-auth/zendesk-oauth.ts src/internal-auth/link-handlers.ts test/zendesk-oauth.test.mjs test/oauth-linking.test.mjs
git commit -m "feat: link internal users with Zendesk OAuth"
```

### Task 5: Add explicit Zendesk authentication and safe request retries

**Files:**

- Modify: `src/zendesk-client.ts`
- Modify: `src/index.ts`
- Create: `test/zendesk-client-auth.test.mjs`
- Modify: `test/zendesk-comments-attachments.test.mjs`

**Interfaces:**

```ts
export type ZendeskAuthentication =
  | { kind: "api-token"; email: string; token: string }
  | {
      kind: "oauth";
      accessToken: string;
      onUnauthorized(input: {
        terminal: boolean;
        signal: AbortSignal;
      }): Promise<
        | { kind: "retry"; accessToken: string }
        | { kind: "reauthorization_required"; correlationId: string }
        | { kind: "stale_failure"; correlationId: string }
      >;
    };

export type ZendeskClientOptions = {
  subdomain: string;
  auth: ZendeskAuthentication;
  timeoutMs?: number;
  signal?: AbortSignal;
  fetch?: typeof globalThis.fetch;
};

export class ZendeskClient {
  constructor(options: ZendeskClientOptions);
}
```

- [ ] **Step 1: Record current Basic-only request flow and intended change**

State that all API methods already converge on `request()`. The production
change is confined to constructor/auth header selection, bounded fetch, one
OAuth invalid-token retry, and safe errors; API methods remain unchanged.

- [ ] **Step 2: Write focused authentication tests**

Prove:

- API-token options emit the exact existing Basic header;
- OAuth options emit Bearer and never include email/API token;
- timeout and outer abort cancel a hung fetch;
- only OAuth `401` with `error=invalid_token` invokes the handler;
- handler retry uses the returned token exactly once;
- second invalid-token response invokes `terminal: true` and does not retry;
- API-token 401 never attempts OAuth refresh;
- error bodies, tokens, URLs containing secrets, and transport messages never
  appear in thrown errors or logs;
- pagination still rejects off-origin next links or normalizes only the fixed
  Zendesk API origin.

- [ ] **Step 3: Run focused tests and confirm RED**

Run:

```bash
npm run build && node --test test/zendesk-client-auth.test.mjs
```

Expected RED: object-form authentication and OAuth retry do not exist.

- [ ] **Step 4: Implement the minimal auth union and retry**

Keep every public Zendesk method intact. Buffer at most a small bounded error
body for `invalid_token` classification. Retry the same method/body once with
the resolver-provided token.

Update stdio construction:

```ts
new ZendeskClient({
  subdomain: config.subdomain,
  auth: {
    kind: "api-token",
    email: config.email,
    token: config.apiKey,
  },
});
```

- [ ] **Step 5: Run focused and existing Zendesk tests and confirm GREEN**

Run:

```bash
npm run build && node --test test/zendesk-client-auth.test.mjs test/zendesk-comments-attachments.test.mjs
```

- [ ] **Step 6: Commit**

```bash
git add src/zendesk-client.ts src/index.ts test/zendesk-client-auth.test.mjs test/zendesk-comments-attachments.test.mjs
git commit -m "refactor: support request-scoped Zendesk OAuth"
```

### Task 6: Implement per-user single-flight credential resolution

**Files:**

- Create: `src/internal-auth/client-resolver.ts`
- Create: `test/user-client-resolver.test.mjs`

**Interfaces:**

```ts
export interface UserClientResolverLike {
  resolve(userId: string, signal?: AbortSignal): Promise<ZendeskClient>;
}

export class UserClientResolver implements UserClientResolverLike {
  constructor(options: {
    store: InternalAuthStore;
    oauth: ZendeskOAuthGateway;
    subdomain: string;
    now?: () => number;
    refreshSkewSeconds?: number;
    timeoutMs?: number;
    signal?: AbortSignal;
    fetch?: typeof globalThis.fetch;
  });
  resolve(userId: string, signal?: AbortSignal): Promise<ZendeskClient>;
}
```

- [ ] **Step 1: Record the credential lifecycle and intended change**

Record:

```text
load current user's encrypted snapshot
  -> proactive refresh if expiry <= now + 60
  -> users/me identity check on rotated token
  -> conditional encrypted install
  -> construct request-scoped client
  -> on current 401: same keyed refresh and one retry
  -> on invalid_grant or second 401: disable only current version
```

- [ ] **Step 2: Write resolver concurrency and isolation tests**

Use real SQLite and deferred fake OAuth calls. Prove:

- two active bearer-derived user IDs produce clients with distinct access
  tokens and distinct `users/me` identities;
- interleaved concurrent tool calls never exchange authorizations;
- no absent/invalid user can resolve and no shared credential exists;
- fresh grants do not call refresh or `users/me`;
- expiring same-user calls join exactly one refresh promise;
- aborting one same-user caller stops only its wait while another caller and a
  later joiner retain the same refresh promise;
- two users enter two independent refresh promises before either is released;
- rotated credentials are visible in a separately reopened store before
  resolver callers continue;
- rotated `users/me` must equal stored authoritative user ID;
- stale conditional writers adopt the installed winner;
- a 401 on an old client adopts a newer stored snapshot;
- `invalid_grant` marks only that current user
  `reauthorization_required`, deletes its grant, and never returns another
  user's token;
- a second invalid-token response is terminal;
- one user's transient failure does not change another user's status;
- all resolver errors and logs exclude token and identity sentinels.

- [ ] **Step 3: Run the focused test and confirm RED**

Run:

```bash
npm run build && node --test test/user-client-resolver.test.mjs
```

Expected RED: resolver does not exist.

- [ ] **Step 4: Implement version-keyed single-flight**

The map value contains `{ version, pending }`. On refresh entry, reload the
snapshot and adopt a newer version. Bind the shared promise to shutdown and
timeout rather than one caller; each caller waits with its own cancellation.
Remove only the same map entry when the shared promise settles. Persist before
returning. Convert `invalid_grant` to conditional reauthorization, while
transient failures leave the mapping active.

- [ ] **Step 5: Run the focused test and confirm GREEN**

Run:

```bash
npm run build && node --test test/user-client-resolver.test.mjs
```

- [ ] **Step 6: Commit**

```bash
git add src/internal-auth/client-resolver.ts test/user-client-resolver.test.mjs
git commit -m "feat: resolve per-user Zendesk clients"
```

### Task 7: Bind protected HTTP requests to active internal users

**Files:**

- Modify: `src/http-app.ts`
- Create: `src/http-runtime.ts`
- Modify: `src/http.ts`
- Modify: `test/http.test.mjs`
- Create: `test/http-runtime.test.mjs`

**Interfaces:**

```ts
export type HttpAppOptions = {
  host: string;
  allowedHosts: string[];
  authenticateBearer(token: string): { userId: string } | undefined;
  resolver: UserClientResolverLike;
  linkHandlers: {
    link: RequestHandler;
    callback: RequestHandler;
  };
  serverFactory?: typeof buildZendeskServer;
};

export type HttpRuntime = {
  app: Express;
  close(): void;
  shutdownSignal: AbortSignal;
};

export type HttpRuntimeDependencies = {
  now?: () => number;
  openStore?: typeof InternalAuthStore.open;
  createOAuth?: (options: ZendeskOAuthOptions) => ZendeskOAuthGateway;
  createResolver?: (
    options: ConstructorParameters<typeof UserClientResolver>[0],
  ) => UserClientResolverLike;
  createHandlers?: typeof createLinkHandlers;
  createApp?: typeof createHttpApp;
};

export function createHttpRuntime(
  config: HttpOAuthConfig,
  dependencies?: HttpRuntimeDependencies,
): HttpRuntime;
```

- [ ] **Step 1: Record current middleware/data flow and intended change**

State that the shared bearer middleware currently closes over one token/client.
The production change parses a bearer, performs status-only lookup, delays
decryption/resolution until POST, and passes the resulting client to the same
server factory.

- [ ] **Step 2: Replace HTTP authentication tests first**

Update the fixture to seed real users or use explicit fake boundaries. Prove
all of these separately:

- missing authorization;
- empty/multiple/malformed Bearer values;
- wrong scheme;
- unknown bearer;
- pending bearer;
- revoked bearer;
- reauthorization-required bearer;
- active bearer.

For every rejection assert `401`, `WWW-Authenticate: Bearer`, zero resolver
calls, zero serverFactory calls, zero credential loads/decryptions, and zero
Zendesk fetches. Do not assert only on mock invocation; also assert the HTTP
response and unchanged store state.

Prove valid authenticated GET and DELETE remain `405` without resolver calls.
Prove two bearers initialize through two distinct clients. Preserve host
validation and official MCP SDK initialization/fresh-server counts.

- [ ] **Step 3: Run HTTP tests and confirm RED**

Run:

```bash
npm run build && node --test test/http.test.mjs
```

Expected RED: `createHttpApp` still expects a shared bearer and client.

- [ ] **Step 4: Implement status-only auth and request-scoped POST**

Use a strict parser:

```ts
const match = /^Bearer ([^\s]+)$/i.exec(header ?? "");
```

Store only `userId` in `res.locals`. Create a request abort controller and
abort it when the response closes. Resolve before `serverFactory`, then retain
the existing stateless transport setup and cleanup.

Map terminal reauthorization to `401`, transient safe auth setup errors to
`503`, and unexpected setup errors to `500`; log only safe category/correlation
ID.

- [ ] **Step 5: Run HTTP tests and confirm GREEN**

Run:

```bash
npm run build && node --test test/http.test.mjs
```

- [ ] **Step 6: Write runtime wiring tests**

Prove startup:

- opens/verifies the store before app creation;
- uses fixed callback/subdomain/client ID;
- wires store, OAuth gateway, handlers, and resolver once;
- does not read stdio email/API key or legacy shared bearer;
- fails before listen on wrong key, malformed store, or invalid config;
- `/healthz` never invokes store credential methods or OAuth/Zendesk fetch;
- shutdown aborts network work, waits for listener closure, and then closes the
  store without adding a worker.

- [ ] **Step 7: Run runtime tests and confirm RED**

Run:

```bash
npm run build && node --test test/http-runtime.test.mjs
```

Expected RED: runtime module does not exist and `src/http.ts` still builds a
global API-token client.

- [ ] **Step 8: Implement runtime wiring and confirm GREEN**

Run:

```bash
npm run build && node --test test/http-runtime.test.mjs
```

- [ ] **Step 9: Run the MCP surface regression tests**

Run:

```bash
npm run build && node --test test/server-instructions.test.mjs test/http.test.mjs test/zendesk-comments-attachments.test.mjs
```

- [ ] **Step 10: Commit**

```bash
git add src/http-app.ts src/http-runtime.ts src/http.ts test/http.test.mjs test/http-runtime.test.mjs
git commit -m "feat: bind HTTP MCP requests to internal users"
```

### Task 8: Add the administration CLI

**Files:**

- Create: `src/admin.ts`
- Modify: `package.json`
- Create: `test/admin.test.mjs`

**Interfaces:**

```text
npm run admin -- create --label <label>
npm run admin -- reauthorize --user <uuid>
npm run admin -- list
npm run admin -- revoke --user <uuid> [--upstream]
npm run admin -- backup --output <absolute-path>
```

```ts
export async function runAdmin(
  argv: string[],
  dependencies?: {
    openStore?: typeof InternalAuthStore.open;
    createOAuth?: (config: HttpOAuthConfig) => ZendeskOAuthGateway;
    stdout?: (line: string) => void;
    stderr?: (line: string) => void;
  },
): Promise<number>;
```

- [ ] **Step 1: Record the operational boundary and intended change**

State that commands may print only a newly created bearer/invitation once,
never retrieve existing secrets, and always commit local revoke before the
optional upstream call.

- [ ] **Step 2: Write CLI tests**

Spawn the compiled CLI with a temporary environment/database and assert:

- `create` outputs one user ID, one bearer, one link, expiry, and a shown-once
  warning;
- the exact bearer/link token cannot be found by `list` or a second command;
- `reauthorize` outputs only a new link and never a bearer;
- `list` contains allowed metadata but no hashes, ciphertext, token expiries,
  key, client secret, or bearer;
- `revoke` immediately blocks authentication and reports
  `upstream: not_attempted`;
- direct `runAdmin` tests inject a deferred fake gateway and prove
  `revoke --upstream` blocks locally before it resolves, reporting only
  `succeeded`, `failed`, or `unavailable`;
- no outbox/worker row or file appears;
- invalid commands/IDs/paths return nonzero with concise sanitized usage;
- `backup` produces a mode-`0600` consistent database.

- [ ] **Step 3: Run CLI tests and confirm RED**

Run:

```bash
npm run build && node --test test/admin.test.mjs
```

Expected RED: CLI and package script do not exist.

- [ ] **Step 4: Implement a small argument parser and command handlers**

Add:

```json
"admin": "node dist/admin.js"
```

Use only exact command/flag names. Print JSON for `list` and stable labeled
lines for one-time secret output. Catch errors at the CLI boundary and print
safe messages without raw exception text from crypto, SQLite, or fetch.

- [ ] **Step 5: Run CLI tests and confirm GREEN**

Run:

```bash
npm run build && node --test test/admin.test.mjs
```

- [ ] **Step 6: Commit**

```bash
git add src/admin.ts package.json package-lock.json test/admin.test.mjs
git commit -m "feat: administer internal Zendesk users"
```

### Task 9: Update deployment, fake-only smoke, and operator documentation

**Files:**

- Modify: `.env.example`
- Create: `.env.stdio.example`
- Modify: `.dockerignore`
- Modify: `Dockerfile`
- Modify: `docker-compose.yml`
- Modify: `scripts/smoke-http.mjs`
- Create: `scripts/smoke-http-local.mjs`
- Modify: `package.json`
- Modify: `test/deployment.test.mjs`
- Create: `test/smoke-http.test.mjs`
- Modify: `README.md`

**Interfaces:**

- `npm run smoke:http` remains a client against an explicitly configured URL
  and bearer and makes no Zendesk call unless its existing explicit
  `--zendesk` option is supplied.
- `npm run smoke:http:local` creates a temporary fake linked user, injects
  fetch functions that throw if called, starts a loopback app, checks health,
  unauthenticated rejection, and MCP initialization, then reports
  `zendeskRequests: 0`.

- [ ] **Step 1: Record current container and documentation flow**

State that the container is already non-root/read-only with `/tmp` writable,
but has no persistent `/data`; production will add only the named `/data`
volume and OAuth environment.

- [ ] **Step 2: Write deployment and smoke tests first**

Behavior tests must parse or execute artifacts, not merely search source text:

- build the image;
- inspect configured user as non-root;
- start with a temporary fake env and named volume;
- inspect root filesystem as read-only;
- verify a write succeeds in `/data` and `/tmp` but fails in `/app`;
- restart the container and prove the store/user metadata survives;
- capture logs and assert fake bearer, invitation, state, access token, refresh
  token, client secret, and encryption key sentinels are absent;
- execute `smoke:http:local` and assert health `200`, unauthenticated `401`,
  MCP initialize/listTools success, and zero Zendesk requests.

Keep Docker build/start tests bounded and clean up only their unique
test-prefixed container, volume, image, and network names.

- [ ] **Step 3: Run deployment/smoke tests and confirm RED**

Run:

```bash
npm run build && node --test test/deployment.test.mjs test/smoke-http.test.mjs
```

Expected RED: `/data`, persistent OAuth configuration, and local fake-only
smoke do not exist.

- [ ] **Step 4: Implement deployment and smoke changes**

Docker/Compose must retain:

```yaml
read_only: true
tmpfs:
  - /tmp
security_opt:
  - no-new-privileges:true
volumes:
  - zendesk_mcp_data:/data
```

Create `/data` owned by `node`, remain `USER node`, and set the example
`OAUTH_DB_PATH=/data/oauth.sqlite`.

- [ ] **Step 5: Update README proportionally**

Document:

- HTTP OAuth environment and canonical callback;
- base64url encryption-key generation with Node crypto;
- persistent SQLite path;
- Zendesk confidential client setup and `read tickets:write`;
- create, one-time handoff, link, list, reauthorize, revoke, optional upstream
  outcome, and backup commands;
- Compose-aware administration through the compiled runtime CLI and the shared
  `/data` volume;
- Codex Streamable HTTP URL plus bearer environment variable;
- migration from the shared HTTP identity;
- stdio compatibility and Zendesk API-token retirement dates;
- safe backup/restore and file permissions;
- rollback that preserves the volume/key;
- live validation and cutover steps still not performed.

Do not include any real private URL or credential.

- [ ] **Step 6: Run focused deployment/smoke tests and confirm GREEN**

Run:

```bash
npm run build && node --test test/deployment.test.mjs test/smoke-http.test.mjs
```

- [ ] **Step 7: Run the fake-only smoke directly**

Run:

```bash
npm run smoke:http:local
```

Expected JSON includes:

```json
{
  "health": 200,
  "unauthenticatedMcp": 401,
  "mcpInitialized": true,
  "zendeskRequests": 0
}
```

- [ ] **Step 8: Commit**

```bash
git add .env.example .env.stdio.example .dockerignore Dockerfile docker-compose.yml scripts/smoke-http.mjs scripts/smoke-http-local.mjs package.json package-lock.json test/deployment.test.mjs test/smoke-http.test.mjs README.md
git commit -m "docs: package per-user OAuth deployment"
```

### Task 10: Full verification, audit, final fixes, and ready PR

**Files:**

- Modify only files required by a failing focused regression.
- Create a separate final-fix commit only when verification exposes a real
  defect.

- [ ] **Step 1: Review plan/spec coverage**

Map every required evidence item in the design specification to a passing test
name. Confirm the final source contains no inbound MCP OAuth route, dynamic
client registration, MCP token table, family, replay record, worker, outbox,
distributed coordination, global mutable user, or shared HTTP credential.

- [ ] **Step 2: Run fresh code verification**

Run from the final branch state:

```bash
npm run check
npm test
git diff --check master...HEAD
```

Read the complete output and record exact test totals.

- [ ] **Step 3: Run Compose validation with fake configuration**

Create a mode-`0600` temporary env file outside the repository with only fake
values, then run:

```bash
MCP_ENV_FILE=<absolute-temporary-fake-env> docker compose config
```

Inspect the result without printing the env file or copying values into the
report.

- [ ] **Step 4: Build and inspect the final Docker image**

Run:

```bash
docker build --target runtime -t zendesk-mcp-internal-bearers:verify .
```

Then execute bounded checks proving:

- non-root UID/GID;
- read-only root;
- writable `/data` and `/tmp`;
- unwritable `/app`;
- restart retains the named-volume store;
- no secret sentinel appears in logs.

- [ ] **Step 5: Run final fake-only local HTTP smoke**

Run:

```bash
npm run smoke:http:local
```

Require health `200`, unauthenticated `/mcp` `401`, fake linked bearer MCP
initialization, and zero Zendesk requests.

- [ ] **Step 6: Audit tracked content and diff**

Run:

```bash
git status --short
git diff --stat master...HEAD
git diff --numstat master...HEAD
git log --oneline --decorate master..HEAD
git diff --check master...HEAD
rg -n -i $'\x54\x4f\x44\x4f|\x54\x42\x44|\x70\x6c\x61\x63\x65\x68\x6f\x6c\x64\x65\x72|commented-out experiment' src test scripts README.md Dockerfile docker-compose.yml .env.example .env.stdio.example docs/superpowers/specs/2026-07-27-zendesk-internal-user-bearers-design.md docs/superpowers/plans/2026-07-27-zendesk-internal-user-bearers.md
```

Inspect the complete diff for unrelated changes and test/demo strings that look
like real secrets. Confirm production and test additions are materially smaller
and easier to audit than PR #4's 22,288 added lines.

- [ ] **Step 7: Fix any discovered defect through focused RED/GREEN**

For each defect, add the focused failing test, observe RED, apply the minimal
fix, observe GREEN, rerun affected suites, and commit:

```bash
git add <exact-affected-files>
git commit -m "fix: harden internal user authentication"
```

If no defect is found, do not create an empty commit.

- [ ] **Step 8: Re-run all final gates after the last commit**

Repeat Steps 2 through 6 if any tracked file changed after their first run.

- [ ] **Step 9: Inspect publication state**

Run:

```bash
gh auth status
git merge-base --is-ancestor origin/master HEAD
git status --short --branch
git log --oneline master..HEAD
```

Require authenticated `gh`, a clean worktree, and ancestry from current
`origin/master`.

- [ ] **Step 10: Push the exact branch**

```bash
git push -u origin codex/zendesk-internal-user-bearers
```

- [ ] **Step 11: Create a ready-for-review PR against master**

Use a temporary body file and:

```bash
gh pr create \
  --repo eramba/zendesk-mcp-server \
  --base master \
  --head codex/zendesk-internal-user-bearers \
  --title "Add internal per-user Zendesk bearers" \
  --body-file <absolute-temporary-pr-body>
```

The body must contain the objective, current/target lifecycle, selected
architecture, security boundaries, intentional static inbound bearer decision,
comparison to PR #4, exact verification evidence, live checks not performed,
migration, rollback, and remaining live validation. Do not modify PR #4.

- [ ] **Step 12: Verify the PR is ready**

Run:

```bash
gh pr view --repo eramba/zendesk-mcp-server --json url,isDraft,state,baseRefName,headRefName,title
```

Require `isDraft: false`, state `OPEN`, base `master`, and the exact head branch.
