# Internal Per-User Zendesk Bearers Design

**Date:** 2026-07-27

**Status:** Approved for implementation by the unattended execution prompt

## Objective

Replace the shared HTTP MCP bearer and shared Zendesk API-token identity with a
small internal per-user authentication layer:

```text
POST /mcp
  -> validate an opaque internal bearer
  -> hash it and resolve one active internal user
  -> load and decrypt that user's Zendesk OAuth grant
  -> refresh that grant safely when necessary
  -> construct a request-scoped ZendeskClient
  -> buildZendeskServer(client)
  -> create a fresh stateless Streamable HTTP transport
  -> call Zendesk as that user
```

The stdio entrypoint keeps its existing email/API-token configuration. The HTTP
entrypoint no longer accepts a shared Zendesk identity or a shared
`MCP_BEARER_TOKEN`.

## Current System

The current HTTP lifecycle is:

```text
src/http.ts
  -> read process-level ZENDESK_SUBDOMAIN, ZENDESK_EMAIL, ZENDESK_API_KEY
  -> construct one process-global ZendeskClient
  -> read one MCP_BEARER_TOKEN
  -> authenticate /mcp
  -> build a fresh McpServer and stateless transport for each POST
  -> reuse the process-global ZendeskClient
```

`src/http-app.ts` already creates a fresh MCP server and transport for every
POST. `buildZendeskServer(client)` is therefore the earliest existing typed
extension point. The design changes how `client` is resolved without changing
the MCP server's tools, prompts, resources, schemas, or stateless transport
lifecycle.

The baseline is 12 tools, 2 prompts, and 1
`zendesk://knowledge-base` resource. The baseline verification on 2026-07-27
passed `npm run check`, `npm test` with 18 tests, and `docker compose config`.

## Verified Zendesk Protocol Constraints

The design uses current Zendesk documentation rather than treating PR #4 as a
protocol authority:

- Zendesk's confidential authorization-code flow is appropriate for a
  server-side app acting for a specific user. The authorization endpoint is
  `/oauth/authorizations/new`, the token endpoint is `/oauth/tokens`, the
  redirect URI must match exactly, and `state` must be checked.
  [Zendesk OAuth migration guide](https://developer.zendesk.com/documentation/api-basics/authentication/oauth-migration/)
- Access and refresh tokens rotate together. The old token pair becomes invalid
  immediately, so the new pair must be persisted before ordinary use resumes.
  A refresh token is single-use.
  [Zendesk refresh-token guide](https://developer.zendesk.com/documentation/api-basics/authentication/refresh-token/)
- Explicit `expires_in` and `refresh_token_expires_in` values are required to
  guarantee refresh-token issuance for OAuth clients created before
  2026-04-30. This service requests a 30-minute access token and a 30-day
  refresh token.
  [Zendesk grant-token reference](https://developer.zendesk.com/api-reference/ticketing/oauth/grant_type_tokens/)
- `GET /api/v2/users/me` returns the authenticated Zendesk user and is the
  authoritative identity check.
  [Zendesk Users API](https://developer.zendesk.com/api-reference/ticketing/users/users/)
- `DELETE /api/v2/oauth/tokens/current.json` revokes the presented OAuth access
  token and returns `204` on success.
  [Zendesk token revocation guide](https://developer.zendesk.com/documentation/api-basics/authentication/revoking-oauth-token/)
- Zendesk is retiring Support API tokens. Inactive-token deactivation and new
  account restrictions begin on 2026-07-28, new token creation is blocked on
  2026-10-27, and all remaining Support API tokens stop working on 2027-04-30.
  [Zendesk API-token retirement announcement](https://support.zendesk.com/hc/en-us/articles/10840968198042-Announcing-the-removal-of-API-tokens-as-an-authentication-method-for-API-requests)

The OAuth client requests `read tickets:write`. `read` covers the existing GET
operations across tickets, users, organizations, and Help Center resources;
`tickets:write` covers the existing ticket creation, update, and comment tools.
The design does not request impersonation.

## Approaches Considered

### 1. Focused SQLite store and explicit request-scoped resolver

Store one hash-only inbound bearer mapping, short-lived invitation state, and
one encrypted Zendesk grant per user. Resolve the client explicitly before
`buildZendeskServer(client)`. Coordinate refreshes with an in-memory
single-flight map keyed by internal user ID and persist rotations with an
optimistic version check.

**Security:** Strong isolation, encrypted server-side credentials, immediate
local revocation, and no shared fallback.

**Complexity:** Four small tables and a small number of focused modules.

**Operational cost:** One persistent SQLite file and one encryption key.

**Testability:** Store, OAuth gateway, resolver, HTTP boundary, and CLI can be
tested independently with real SQLite and fake fetch implementations.

**Decision:** Selected.

### 2. Encrypted configuration file or in-memory user mapping

Load per-user bearers and OAuth grants from environment variables or an
encrypted JSON file.

**Security:** It can encrypt grants, but safe atomic refresh rotation,
one-time invitations, immediate revocation, and concurrent administration
become bespoke file-locking problems.

**Complexity:** Initially smaller, but operational edge cases recreate a
database poorly.

**Operational cost:** Manual secret-file replacement and restart-driven
changes.

**Testability:** Concurrency and crash behavior are harder to prove.

**Decision:** Rejected because it does not meet the durable refresh and
administration requirements safely.

### 3. Reduce PR #4's OAuth broker

Start from PR #4 and remove dynamic registration, MCP authorization codes,
MCP access and refresh tokens, token families, replay records, revocation
outbox, worker leases, and lifecycle fencing.

**Security:** PR #4 contains useful Zendesk protocol and race test ideas, but
its security model begins at an inbound MCP OAuth authorization server rather
than a static internal bearer.

**Complexity:** The pull request adds 22,288 lines across 64 files, including a
2,967-line SQLite store and multiple durable lifecycle subsystems. Deleting
features from that graph would still leave coupled abstractions and a difficult
audit.

**Operational cost:** More routes, state machines, worker behavior, and
shutdown coordination than a single-instance internal service needs.

**Testability:** Extensive, but dominated by out-of-scope behavior.

**Decision:** Rejected. Only verified endpoint shapes, refresh-race lessons,
sanitized error patterns, and useful negative test cases are retained.

## Architecture

### Configuration

The HTTP entrypoint reads:

- `PUBLIC_BASE_URL`: canonical origin of this service. It must contain a scheme
  and authority only, with no credentials, query, fragment, or non-root path.
  HTTPS is required except for loopback local development.
- `ZENDESK_SUBDOMAIN`: one DNS label and the only permitted upstream Zendesk
  host selector.
- `ZENDESK_OAUTH_CLIENT_ID`: fixed confidential OAuth client identifier.
- `ZENDESK_OAUTH_CLIENT_SECRET`: fixed confidential OAuth client secret.
- `OAUTH_ENCRYPTION_KEY`: canonical base64url encoding of exactly 32 random
  bytes.
- `OAUTH_DB_PATH`: absolute path to the SQLite database.
- Existing `HOST`, `PORT`, and `MCP_ALLOWED_HOSTS`.

The callback is always
`PUBLIC_BASE_URL + /oauth/callback`. It is never inferred from `Host`,
`Forwarded`, or `X-Forwarded-*` headers.

The stdio entrypoint continues to read `ZENDESK_SUBDOMAIN`,
`ZENDESK_EMAIL`, and `ZENDESK_API_KEY`. HTTP startup does not read the email,
API key, or legacy shared MCP bearer.

Configuration errors name only the invalid variable. Values are never included
in messages.

### Cryptographic primitives

- MCP bearers use 32 random bytes encoded as base64url and prefixed with
  `zmcp_`. The prefix identifies the credential type but contains no identity.
- Invitation tokens and OAuth states each use an independent 32 random bytes
  encoded as base64url.
- Exact bearer, invitation, and state lookup uses SHA-256 hashes encoded as
  base64url.
- OAuth grants use AES-256-GCM with a fresh 96-bit nonce for every write.
- The encrypted envelope contains only version, nonce, ciphertext, and
  authentication tag.
- Grant associated data binds ciphertext to the internal user ID, grant
  version, fixed Zendesk subdomain, and fixed OAuth client ID.
- A database key-check record uses a separate associated-data context. Opening
  an existing database with the wrong key or malformed ciphertext fails before
  the HTTP listener starts.

Hashes are not encryption and are used only for high-entropy exact lookup.
OAuth access and refresh tokens are never hashed as their plaintext is required
for upstream requests; the whole grant is encrypted instead.

### Persistence

The implementation uses `better-sqlite3` in WAL mode with foreign keys,
`trusted_schema=OFF`, `secure_delete=ON`, a bounded busy timeout, and full
synchronous durability. The database file is mode `0600`.

#### `store_metadata`

| Column | Purpose | Protection |
| --- | --- | --- |
| `key` | Schema and key-check record name | Non-secret |
| `value` | Schema version or encrypted key-check envelope | Key-check is encrypted |

There are exactly two logical records: schema version and key check. The key
check proves the configured encryption key can decrypt this store without
needing a user grant to exist.

#### `internal_users`

| Column | Purpose | Protection |
| --- | --- | --- |
| `id` | Random UUID internal stable identifier | Non-secret identifier |
| `label` | Administrator-supplied display label | Identifying metadata |
| `bearer_hash` | Exact MCP bearer lookup | SHA-256; plaintext never stored |
| `status` | `pending`, `active`, `revoked`, or `reauthorization_required` | Non-secret state |
| `zendesk_user_id` | Authoritative ID returned by `users/me` | Identifying metadata |
| `zendesk_name` | Name returned by `users/me` | Identifying metadata |
| `zendesk_email` | Email returned by `users/me`, when present | Identifying metadata |
| `created_at` | Creation epoch seconds | Non-secret |
| `updated_at` | Last state-change epoch seconds | Non-secret |
| `revoked_at` | Local revocation epoch seconds | Non-secret |

`bearer_hash` is unique. Generation retries on the theoretical hash collision.
A partial unique index on non-null `zendesk_user_id` prevents one Zendesk
identity from being activated behind two internal bearers. The administrator's
label is never an authentication boundary.

#### `oauth_invitations`

| Column | Purpose | Protection |
| --- | --- | --- |
| `id` | Random UUID invitation identifier | Non-secret identifier |
| `user_id` | Intended internal user | Foreign key |
| `invitation_hash` | One-time link lookup | SHA-256; plaintext never stored |
| `state_hash` | OAuth callback binding after link start | SHA-256; plaintext never stored |
| `created_at` | Invitation creation time | Non-secret |
| `expires_at` | Hard expiry | Non-secret |
| `started_at` | When the one-time link was consumed | Non-secret |
| `consumed_at` | When callback state was claimed | Non-secret |

Creating or reissuing an invitation invalidates unconsumed invitations for that
user. The link handler generates a fresh independent OAuth state and atomically
changes a non-expired, unstarted invitation to `started_at` with its state
hash. A second link request cannot start it again.

The callback hashes its `state` and atomically changes a non-expired,
started, unconsumed row to `consumed_at`. Network exchange begins only after
that claim. A replay, missing state, mismatch, or expiry cannot claim the row.
If exchange or identity lookup later fails, the row remains consumed and the
mapping remains non-active; an administrator issues a new link.

Expired and old consumed invitations are deleted opportunistically on store
open and invitation operations. No worker is required.

#### `oauth_grants`

| Column | Purpose | Protection |
| --- | --- | --- |
| `user_id` | One grant per internal user | Foreign key and primary key |
| `version` | Optimistic refresh generation | Non-secret integer |
| `encrypted_grant` | Access token, refresh token, expiries, and canonical scopes | AES-256-GCM |
| `access_expires_at` | Refresh scheduling without decryption scans | Sensitive timing metadata, not a credential |
| `refresh_expires_at` | Reauthorization scheduling/status | Sensitive timing metadata, not a credential |
| `updated_at` | Last successful install | Non-secret |

Activation inserts version 1 and changes the intended mapping to `active` in
one transaction. A refresh encrypts version `N + 1`, then atomically replaces
version `N` only if the user remains active. The newly rotated grant is
persisted before the resolver returns it.

Revocation or terminal reauthorization changes the user status and deletes the
grant in one transaction. Future authentication then fails on status before
any decryption.

### Administration CLI

The compiled CLI is exposed as:

```text
npm run admin -- create --label "Martin"
npm run admin -- reauthorize --user <internal-user-id>
npm run admin -- list
npm run admin -- revoke --user <internal-user-id>
npm run admin -- revoke --user <internal-user-id> --upstream
npm run admin -- backup --output /absolute/secure/path/oauth.sqlite
```

`create` prints the internal user ID, one MCP bearer, one link URL, and the
expiry. The bearer and invitation token exist in plaintext only in command
memory and output. The output explicitly says both are shown once and must be
handed off through a secure channel.

`reauthorize` creates a new one-time link for a `pending` or
`reauthorization_required` mapping. It never prints or rotates the existing MCP
bearer.

`list` prints only internal user ID, label, status, authoritative Zendesk
identity metadata, timestamps, and current invitation status/expiry. It never
prints bearer hashes, invitation/state hashes, encrypted grants, token expiry
details, or configuration secrets.

`revoke` commits local revocation first, so the bearer is blocked immediately.
Without `--upstream`, it reports `upstream: not_attempted`. With `--upstream`,
the CLI captures the decrypted current access token in memory, commits local
revocation and credential deletion, performs one bounded
`DELETE /api/v2/oauth/tokens/current.json`, and reports `succeeded`, `failed`,
or `unavailable`. There is no retry queue or outbox.

`backup` uses SQLite's online backup API and sets the destination to mode
`0600`. A backup remains sensitive because it contains identity metadata,
bearer hashes, and encrypted grants.

There is deliberately no command to retrieve or print an existing bearer,
invitation token, OAuth token, encrypted grant, client secret, or encryption
key.

### Browser OAuth linking

The fixed OAuth app is a confidential server-side client: its client secret is
available only to this service, and its callback is fixed. Zendesk requires
PKCE for public authorization-code clients but documents the client-secret
exchange for confidential authorization-code clients. This narrow design uses
the confidential exchange plus one-time invitation and independent state; it
does not add an upstream PKCE verifier lifecycle, and it does not add any
inbound MCP OAuth or PKCE flow.

1. The administrator creates a pending user. The store persists only the
   bearer hash and invitation hash.
2. The colleague opens
   `GET /oauth/link?invitation=<one-time-token>`.
3. The handler validates the single query value, generates an independent
   OAuth state, and atomically starts the intended non-expired invitation.
4. The handler returns a redirect to the fixed
   `https://<subdomain>.zendesk.com/oauth/authorizations/new` endpoint with
   fixed client ID, fixed callback, `read tickets:write`, state, and explicit
   token lifetimes.
5. Zendesk redirects to the fixed callback with `code` and `state`.
6. The callback atomically claims the state before using the authorization
   code.
7. The OAuth gateway exchanges the code at the fixed `/oauth/tokens` endpoint.
8. The gateway calls fixed `/api/v2/users/me.json` with the access token.
9. The store enforces unique authoritative Zendesk identity, encrypts the
   complete grant, and activates only the claimed internal mapping in one
   transaction.
10. The browser receives a fixed success page containing no credentials.

Both browser routes set `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`. They do not use cookies. The inbound MCP bearer
never enters the browser flow. There is no request-selected redirect, upstream
host, subdomain, client ID, or scope.

The authorization code is held only in request memory and is never logged or
persisted. If a token exchange succeeds but identity validation or activation
fails, the implementation makes one bounded best-effort current-token
revocation and discards the plaintext grant.

### OAuth gateway and errors

All Zendesk OAuth requests:

- use the fixed Zendesk origin;
- reject redirects;
- have a 10-second timeout;
- combine timeout, request, and shutdown cancellation;
- validate status and response shape;
- never include upstream bodies, headers, codes, states, tokens, or transport
  error text in application errors or logs.

The gateway distinguishes `invalid_grant` from transient upstream failure.
Errors carry a random correlation ID and a safe category only.

### Request-scoped Zendesk client

`ZendeskClient` accepts an explicit authentication union:

```text
{ kind: "api-token", email, token }
{ kind: "oauth", accessToken, onUnauthorized }
```

The API-token branch preserves stdio behavior. The OAuth branch sends
`Authorization: Bearer <accessToken>`. Credentials never enter tool schemas or
arguments.

The client has a bounded request timeout. On an OAuth `401` with
`error=invalid_token`, it calls the request-scoped unauthorized handler, adopts
the resolver's refreshed access token, and retries the Zendesk request exactly
once. A second invalid-token response marks the still-current mapping as
requiring reauthorization and fails without another retry.

### Refresh coordination

The resolver:

1. Loads and decrypts the active user's credential snapshot.
2. Refreshes proactively when access expiry is within 60 seconds.
3. Creates the request-scoped client only after a usable snapshot exists.
4. Handles a current-token `401` by refreshing and returning a retry token.

An in-memory map is keyed by internal user ID. Each entry is one refresh promise
for a specific stored version:

- same user and version join one promise;
- different users use independent promises;
- a caller that sees a newer stored version adopts it without refreshing;
- successful rotation is encrypted and conditionally persisted before callers
  continue;
- `users/me` on the rotated access token must match the stored authoritative
  Zendesk user ID;
- `invalid_grant`, expired refresh credentials, identity change, or a second
  invalid-token response atomically changes the still-current mapping to
  `reauthorization_required` and removes its grant;
- stale failures cannot invalidate a newer version;
- no path loads another user's credential or a shared fallback.

The fixed single-instance deployment makes process-local single-flight plus
SQLite atomicity sufficient. There is no distributed lock, lease, fencing
epoch, durable refresh worker, or background queue.

### HTTP boundary

`GET /healthz` remains public and always returns non-secret local readiness. It
does not resolve a bearer, decrypt a grant, refresh a token, or contact Zendesk.
Host validation remains provided by the MCP SDK Express app.

For every `/mcp` method, the authentication middleware accepts exactly one
case-insensitive `Bearer` scheme and one non-whitespace token. Missing,
malformed, wrong-scheme, unknown, pending, revoked, and
reauthorization-required credentials return protocol-shaped `401` with
`WWW-Authenticate: Bearer`.

Status lookup happens before grant loading. Rejected requests do not call the
resolver, decrypt credentials, access Zendesk, or invoke `serverFactory`.

After a valid active bearer:

- `GET /mcp` and `DELETE /mcp` preserve the existing `405` and `Allow: POST`
  behavior without decrypting the grant.
- `POST /mcp` resolves a request-scoped client, calls
  `buildZendeskServer(client)`, and creates a fresh transport with
  `sessionIdGenerator: undefined`.

Refresh terminal failures return safe `401`; transient upstream setup failures
return a sanitized protocol-shaped `503`; unexpected setup failures return a
sanitized protocol-shaped `500`. No error response or log contains secrets.

### Shutdown

HTTP startup validates configuration, opens and verifies the store, constructs
the fixed OAuth gateway, resolver, and app, and only then starts listening.

Shutdown aborts new/upstream work, stops accepting connections, waits for the
listener's existing requests within the existing 10-second grace period, then
closes SQLite. The design does not introduce a worker lifecycle.

## Deployment

The runtime image remains non-root and read-only. It adds:

- a `/data` directory owned by the existing `node` user;
- a named Compose volume mounted only at `/data`;
- `OAUTH_DB_PATH=/data/oauth.sqlite`;
- `/tmp` as the existing tmpfs.

Only `/data` and `/tmp` are writable. `no-new-privileges` remains enabled.
Container restart reopens the same named-volume database and verifies the
configured encryption key.

## Migration

1. Build and verify the new image with fake data.
2. Create the fixed confidential Zendesk OAuth client with callback
   `PUBLIC_BASE_URL/oauth/callback`.
3. Configure the HTTP OAuth environment and persistent volume.
4. Start the new service and verify public health plus unauthenticated
   rejection.
5. Create and link internal users one at a time.
6. Give each user the one-time bearer through a secure channel.
7. Update each Codex MCP client to use the same service URL and its unique
   bearer.
8. Verify two-user read attribution and isolation in staging.
9. Retire the old shared HTTP bearer and HTTP API-token environment only after
   cutover approval.

Stdio can continue using the legacy API token during migration, subject to
Zendesk's retirement schedule.

## Rollback

1. Stop the new HTTP container without deleting its named volume.
2. Restore the previous image and previous shared HTTP environment.
3. Verify `/healthz` and shared-bearer initialization.
4. Preserve the OAuth database and encryption key for a later retry.

Rollback depends on the old Support API token still being active and is
therefore time-limited by Zendesk's retirement schedule. No database downgrade
is necessary because the old release does not open the new store.

## Verification Strategy

Focused RED/GREEN tests will prove:

- configuration rejects unsafe URLs, subdomains, database paths, and keys
  without exposing values;
- bearer/invitation/state values are random and only hashes reach SQLite;
- grants are encrypted, key checks fail closed, and malformed ciphertext fails
  closed;
- invitation start and callback claim are expiry-bound, atomic, one-time, and
  replay-resistant;
- callback activation is bound to the claimed mapping and authoritative
  `users/me` identity;
- two active bearers resolve distinct clients and access tokens under
  concurrency;
- proactive and `401` refresh persist rotated credentials before retry;
- same-user refresh is single-flight and different-user refresh is independent;
- terminal refresh failure and a second invalid token disable only the intended
  mapping with no fallback;
- revocation immediately blocks authentication and optional upstream outcome is
  reported exactly;
- all rejected bearer states fail before resolver, decryption, server factory,
  or Zendesk network work;
- health, host validation, authenticated GET/DELETE `405`, stateless POST,
  official SDK initialization, tools, prompts, resources, and stdio remain
  covered;
- Docker remains non-root, read-only outside `/data` and `/tmp`, and persistent
  across restart;
- a local fake-grant smoke initializes MCP without any Zendesk request.

Final verification is:

```text
npm run check
npm test
git diff --check
docker compose config (with a fake temporary environment file)
docker image build
npm run smoke:http:local
```

The final audit also scans tracked changes and runtime logs for plaintext test
secrets, real credentials, unfinished markers, unrelated changes, and accidental
copies of PR #4's inbound OAuth/token-family/revocation-worker architecture.

## Explicit Non-Goals

This design does not add an inbound MCP OAuth server, dynamic client
registration, MCP authorization codes, MCP access or refresh tokens, token
families, replay records, inbound consent, an external identity provider, a web
admin UI, multiple Zendesk subdomains, multiple replicas, distributed locking,
durable refresh/revocation workers, an outbox, generalized lifecycle fencing,
or speculative backup infrastructure.

Tailscale, HTTPS termination, live deployment, live Zendesk authorization,
live Zendesk API calls, user cutover, and legacy credential retirement remain
external validation and deployment steps.
