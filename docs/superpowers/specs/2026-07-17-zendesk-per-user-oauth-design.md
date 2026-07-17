# Zendesk Per-User OAuth Design

**Date:** 2026-07-17
**Status:** Approved by user on 2026-07-17
**Scope:** Per-user Zendesk identity for the existing stateless Streamable HTTP transport

## Summary

Replace the HTTP deployment's shared Zendesk email/API-token identity and shared MCP bearer with a standards-based OAuth broker. Each Codex user completes one browser login. The server stores that user's Zendesk OAuth credentials securely and issues separate, short-lived MCP credentials to Codex. Every authenticated MCP POST receives a request-scoped `ZendeskClient`, so reads and writes run with the permissions and audit identity of the user who authorized Zendesk.

The existing stdio transport remains compatible with `ZENDESK_EMAIL` and `ZENDESK_API_KEY`. The existing tool and resource registrations remain shared between transports.

This design deliberately targets one Zendesk subdomain, one Docker Compose instance, and all current read/write tools. It does not introduce a public admin UI, external identity provider, multiple Zendesk tenants, or horizontally scaled storage.

## Motivation

The current HTTP lifecycle is:

`src/http.ts -> process-level ZENDESK_* config -> one ZendeskClient -> shared MCP bearer -> authenticated POST /mcp -> fresh McpServer and stateless transport -> shared ZendeskClient -> Zendesk API`

This isolates MCP server and transport objects per POST, but all users still act as the same Zendesk identity. The shared MCP bearer also has one revocation and compromise boundary for every client.

Passing a Zendesk email and API token in custom headers could create a request-scoped client, but it is not the durable solution:

- The long-lived upstream secret would cross the HTTP boundary on every MCP request.
- Client, proxy, request-context, and logging mistakes would have more opportunities to expose it.
- A client-supplied email is not a trusted identity boundary for Zendesk API-token authentication.
- Zendesk has announced progressive API-token retirement beginning on 2026-07-28 and final deactivation on 2027-04-30.

Zendesk recommends authorization-code OAuth when an integration acts for a specific user. The MCP authorization specification likewise defines OAuth 2.1 for HTTP transports and forbids passing an MCP access token through to a downstream API. The two token domains therefore remain separate.

## Goals

- Give every HTTP user one browser-based onboarding flow initiated by `codex mcp login zendesk`.
- Run every Zendesk API call as the Zendesk user who authorized the integration.
- Keep MCP credentials and Zendesk credentials separate and audience-bound.
- Preserve stateless Streamable HTTP and its fresh server/transport-per-POST lifecycle.
- Reuse `buildZendeskServer(client)` without adding credentials to tool inputs or rewriting all tool handlers.
- Preserve the stdio transport and its existing environment-based authentication.
- Support all twelve current tools and the knowledge-base resource.
- Provide individual login, refresh, accurate client-local logout, explicit server-side revocation, and reauthorization behavior.
- Keep secrets out of MCP payloads, model context, errors, logs, and persistent plaintext storage.

## Non-goals

- Multiple Zendesk subdomains or global Zendesk OAuth distribution.
- External corporate SSO or a separate hosted authorization product.
- Multiple HTTP replicas or shared network storage.
- Stateful MCP sessions, resumability, or server-initiated notifications.
- Per-tool step-up authorization or a read-only first release.
- A credential-configuration MCP tool, custom tool arguments, or MCP `_meta` credentials.
- Client-supplied Zendesk email, API token, OAuth access token, or subdomain headers.
- An admin web portal for users, sessions, or token management.
- Changing the behavior or schemas of existing Zendesk tools.

## Decisions

### One OAuth login, two independent token domains

The server acts as both:

1. an MCP OAuth authorization/resource server for Codex; and
2. a confidential OAuth client of the fixed Zendesk subdomain.

Codex receives only MCP authorization codes, access tokens, and refresh tokens issued for the public MCP resource URL. Zendesk access and refresh tokens remain server-side and are used only for the Zendesk API.

The inbound MCP token is never forwarded to Zendesk. The Zendesk token is never returned to Codex.

### SDK handlers with a custom broker provider

Use the installed MCP SDK's authorization, token, registration, revocation, protected-resource metadata, PKCE validation, and `requireBearerAuth` building blocks. Compose them in a thin local `createZendeskOAuthRouter` instead of mounting `mcpAuthRouter` unchanged.

The local composition exists for one bounded compatibility reason: SDK 1.26 accepts a registered public client at the token and revocation endpoints, but its generated metadata advertises revocation only with `client_secret_post`. Codex's current `rmcp` client dynamically registers with `token_endpoint_auth_method=none`. The local metadata therefore advertises only `none` for token and revocation client authentication, while all request parsing, PKCE validation, and handler behavior remain SDK-owned. A protocol regression test pins this assumption before any SDK upgrade.

Implement a focused `ZendeskBrokerOAuthProvider` for the SDK's `OAuthServerProvider` contract. Do not use `ProxyOAuthServerProvider`: that generic provider forwards the MCP client's `client_id`, redirect URI, PKCE data, scopes, and resource to the upstream authorization server. Zendesk instead requires this service's fixed Zendesk OAuth client ID, client secret, and registered server callback. The broker must preserve the original MCP transaction while it completes a separate upstream flow.

### Request-scoped Zendesk client

The earliest existing extension point is the authenticated POST route immediately before `serverFactory(client)`.

The target runtime lifecycle is:

`POST /mcp -> validate MCP access token -> obtain principalId -> resolve or refresh that principal's Zendesk credential -> construct request-scoped ZendeskClient -> buildZendeskServer(client) -> stateless transport -> Zendesk API`

`src/server.ts` continues closing over the client passed to `buildZendeskServer`. No global mutable current-user state, `AsyncLocalStorage`, credentials in tool arguments, or repeated edits to every tool callback are needed.

### Single subdomain and deployment

The Zendesk subdomain is server configuration and cannot be supplied by a client. One Docker Compose instance owns one local persistent OAuth store. The store is exposed through an interface so a later multi-replica design can replace its implementation without changing the broker or resolver contracts.

### Public MCP clients only

Dynamic registration accepts only public authorization-code clients using PKCE S256. This matches the current Codex CLI and avoids creating MCP client secrets that a desktop public client cannot protect.

`OAuthStore` implements the SDK's `OAuthRegisteredClientsStore`: `getClient` performs lookup and `registerClient` validates and stores registrations. `ZendeskBrokerOAuthProvider` exposes that store through its `clientsStore` getter; registration is not a provider method.

`registerClient` rejects all metadata except the following profile:

- `token_endpoint_auth_method` is exactly `none`;
- `grant_types` contains exactly `authorization_code` and `refresh_token`;
- `response_types` contains exactly `code`;
- optional `scope`, when present, canonicalizes to exactly `zendesk:read zendesk:write`; when omitted the store records that same default;
- every redirect URI is exact-match loopback HTTP on `127.0.0.1` or `localhost`, with an explicit non-zero port, no userinfo, query, or fragment, and any path allowed for Codex's ephemeral callback;
- `client_name`, when present, is a bounded printable string; and
- no client JWK, software statement, or other client-authentication mechanism is accepted.

The server generates an opaque client ID and returns no client secret. SDK 1.26 strips unsupported registration fields such as Codex's `application_type` before `registerClient`; the Codex compatibility test pins that behavior so an SDK parser change fails visibly.

## Component Design

### `package.json`

Add pinned `better-sqlite3@12.11.1`, `express@5.2.1`, and `express-rate-limit@8.2.1` as direct runtime dependencies, with `@types/better-sqlite3` remaining development-only, and update the lockfile. The local OAuth router imports Express and its callback limiter directly and must not rely on MCP SDK transitive dependencies.

### `src/config.ts`

Keep `readZendeskConfig()` for stdio. Add a separate HTTP OAuth configuration reader so the HTTP process no longer requires a Zendesk email, API token, or shared MCP bearer.

Required HTTP OAuth values:

- `PUBLIC_BASE_URL=https://dev-server.tail22145b.ts.net`
- `ZENDESK_SUBDOMAIN=<fixed-subdomain>`
- `ZENDESK_OAUTH_CLIENT_ID=<local-oauth-client-id>`
- `ZENDESK_OAUTH_CLIENT_SECRET=<local-oauth-client-secret>`
- `OAUTH_ENCRYPTION_KEY=<base64-encoded-32-byte-key>`
- `OAUTH_DB_PATH=/data/oauth.sqlite`

Optional `MCP_ACCESS_TOKEN_TTL_SECONDS` defaults to `900` and accepts only `60..3600`. Production uses the 15-minute default; staging temporarily uses the minimum for the Codex refresh compatibility gate.

Optional `ZENDESK_HTTP_TIMEOUT_MS` defaults to `15000` and accepts only `1000..60000`. It applies to existing Zendesk API calls and every new OAuth, identity, token-metadata, refresh, and revocation request.

Existing listener, port, and allowed-host configuration remains. `PUBLIC_BASE_URL` is canonical and must not be inferred from `Host` or forwarded headers. Startup accepts only an origin-only HTTPS URL: no username/password, non-root path, query, or fragment. It normalizes to `URL.origin` and requires that hostname to appear in `MCP_ALLOWED_HOSTS`, so generated issuer/resource/callback URLs and the Express host guard cannot diverge. Validate the fixed Zendesk subdomain as one DNS label before deriving upstream endpoints.

Configuration validation names missing or invalid keys without printing values. The HTTP process fails startup if the public URL is not HTTPS, the encryption key is not exactly 32 decoded bytes, the OAuth callback cannot be derived, or the store cannot be opened and migrated.

### `src/http.ts`

Construct these process-level dependencies:

- `OAuthStore`
- `TokenCipher`
- `ZendeskOAuthClient`
- `ZendeskBrokerOAuthProvider`
- `ZendeskClientResolver`
- `ZendeskRevocationWorker`
- the HTTP application

Do not construct a process-global credential-bound `ZendeskClient` for HTTP. Start the revocation worker only after migrations succeed; it claims due outbox rows atomically with a bounded concurrency of one. Claims use a process-unique `claim_owner` and bounded `claim_expires_at` lease longer than one configured network timeout plus margin, and renew before a second refresh/delete call. Startup and each poll reclaim expired leases, while graceful abort cancels the fetch and clears or reschedules the owned claim. Graceful listener shutdown stops new worker claims, drains the listener and in-flight cleanup within the existing grace period, then closes the store.

### `src/http-app.ts`

Mount, in order:

1. public `/healthz`;
2. locally composed SDK OAuth metadata, registration, authorization, token, and revocation routes;
3. the broker's consent POST and fixed Zendesk callback routes;
4. `requireBearerAuth` on all `/mcp` methods; and
5. existing stateless GET/DELETE behavior plus POST handling.

The bearer middleware receives the provider as verifier, requires `zendesk:read` and `zendesk:write`, and advertises the path-specific protected-resource metadata URL in `WWW-Authenticate`.

For POST, read only the validated non-secret `principalId` from `req.auth.extra`, resolve a request-scoped Zendesk client, and pass it to the existing server factory. The raw SDK `AuthInfo.token` and `requestInfo.headers` are never logged.

GET and DELETE continue returning authenticated protocol-shaped `405` responses and never load Zendesk credentials. `/healthz` never calls Zendesk.

### `src/oauth/store.ts`

Define the storage contract and its single-instance SQLite implementation using pinned `better-sqlite3@12.11.1` plus development-only types. This keeps the package's Node 20-compatible contract and avoids relying on the still-experimental `node:sqlite` API in the current Node 22 image. The schema owns:

- dynamically registered public MCP clients and their exact redirect URIs;
- short-lived upstream login transactions;
- one-time MCP authorization codes;
- principals keyed by fixed subdomain plus stable Zendesk user ID, with active/disconnected status and a monotonically increasing lifecycle epoch;
- encrypted, monotonically versioned Zendesk credential records and expirations;
- encrypted login and refresh staging records that are either atomically installed or locally discarded;
- MCP token families;
- hashed MCP access tokens;
- hashed, rotating MCP refresh-token generations retained until each generation's own expiry plus a short encrypted idempotent-retry response; and
- disconnect-only revocation outbox records with captured principal epoch, retry schedule, expiring claim lease, and reauthorization state.

Schema migrations run transactionally at startup. There are no destructive automatic migrations. All consume, rotate, replace, and revoke operations are atomic. Consumed refresh-token hashes remain as replay markers until that generation's original 30-day expiry; only the encrypted successor response is deleted after its 60-second grace. Replay after the generation's expiry is simply rejected as expired rather than revoking an otherwise healthy family. Enable foreign keys, WAL mode, a bounded busy timeout, and durable synchronous writes. Apply `0700` permissions to the data directory and `0600` to the database where the mounted filesystem supports Unix modes.

The database lives at `/data/oauth.sqlite` on a named Docker volume writable only by the container's existing non-root user. The rest of the container remains read-only, with `/tmp` remaining tmpfs-backed. The Docker build installs or compiles the native dependency once in the build stage, prunes development packages, and copies the resulting production `node_modules` into the runtime image; the runtime stage does not compile native code. Backups use SQLite's consistent backup API or a checkpointed snapshot, never an uncoordinated raw copy of live WAL files.

### `src/oauth/token-cipher.ts`

Encrypt Zendesk access and refresh tokens, the 60-second MCP refresh retry response, and the login transaction payload containing the original MCP state and trusted redirect URI with AES-256-GCM. Every encrypted value stores a format version, random 96-bit nonce, ciphertext, and authentication tag. The master key is supplied separately from the database and is never written to the volume. Public clients using `token_endpoint_auth_method=none` have no client secret to store.

Authenticated additional data is record-specific because a login transaction has no principal yet:

- every record binds format version, record kind, stable row ID, and expiry;
- login transactions additionally bind the fixed subdomain, MCP client ID, browser-binding nonce hash, and digests of the exact redirect URI and resource;
- Zendesk credentials and disconnect outbox records bind fixed subdomain, principal ID, credential kind, credential version, and captured lifecycle epoch; and
- MCP refresh retry responses bind token-family ID, client ID, resource, normalized scopes, and consumed generation.

Moving a ciphertext to another row, principal, kind, version, expiry, client, resource, scope set, or generation therefore fails authentication instead of decrypting under the wrong context.

MCP bearer values, authorization codes, upstream Zendesk state, consent CSRF values, browser-binding nonces, and refresh tokens are generated from at least 32 random bytes and encoded base64url. Persistent lookup stores SHA-256 hashes rather than plaintext lookup values. The original MCP state must be returned unchanged, so it is retained only inside the encrypted login transaction rather than reduced to a lookup hash.

### `src/oauth/zendesk-oauth-client.ts`

Own only the upstream Zendesk protocol:

- construct the authorization URL for the fixed subdomain and OAuth client;
- exchange a Zendesk authorization code at the token endpoint;
- refresh the Zendesk credential;
- revoke upstream credentials when explicitly disconnecting a principal; and
- call `users/me` to establish and revalidate the stable Zendesk user ID.

It sends the fixed server callback, client ID, and client secret. It never accepts an arbitrary host or subdomain from a request.

Every network operation has the configured abort timeout and participates in shutdown cancellation. Authorization-code exchange and token refresh are never blindly retried because codes are one-time and refresh tokens may rotate; the caller handles correlated failure, staging, and reauthorization. The outbox worker alone retries explicitly classified transient revocation work with persisted backoff.

Successful upstream authorization and every refresh require a successful `users/me` response matching the expected principal. Zendesk remains the authority for the user's role and endpoint permissions; the MCP server does not elevate them.

### `src/oauth/zendesk-broker-provider.ts`

Implement the SDK `OAuthServerProvider` methods:

- expose the `OAuthRegisteredClientsStore` through `clientsStore`;
- begin authorization;
- retrieve the PKCE challenge for an MCP authorization code;
- exchange an MCP authorization code;
- exchange and rotate an MCP refresh token;
- validate an MCP access token into `AuthInfo`; and
- revoke an MCP token family when either one of its access or refresh tokens is presented.

`AuthInfo.expiresAt` is always integer epoch seconds, never milliseconds. `AuthInfo.resource` is a `URL` equal to the canonical `${PUBLIC_BASE_URL}/mcp` resource. Its `extra` field contains only `principalId`.

The provider rejects a missing or non-canonical `resource` during authorization and authorization-code exchange. Authorization-code exchange also rejects an omitted or non-exact `redirect_uri`. Every code is bound to the original client, redirect URI, PKCE challenge, scopes, resource, principal, and the principal's active lifecycle epoch; every token family remains bound to client, scopes, principal, epoch, and resource.

Code consumption and token-family creation are one SQLite transaction that requires the principal to remain active at the code's epoch. A disconnect or transition to `reauthorization_required` increments the epoch and invalidates every pending code from the prior epoch, so a pre-invalidation code cannot mint a usable family later.

There is one explicit current-Codex compatibility exception: `rmcp` 1.8 omits `resource` on refresh even though the MCP specification requires it on token requests. If refresh omits the value, the provider inherits the immutable canonical resource already stored on that refresh-token family; if refresh supplies a value, it must match exactly. This never permits a new audience or token passthrough, and a regression test is tied to the installed client behavior. Remove the exception once the supported Codex client sends `resource` consistently.

The revocation endpoint authenticates a public client by its registered `client_id`; possession of the token is the revocation authority. It revokes a token only when its stored owner matches that client. Unknown, already revoked, or cross-client tokens return the RFC-required success response without changing another family or revealing whether a token exists.

### `src/oauth/zendesk-client-resolver.ts`

Given a validated `principalId`:

1. load and decrypt the principal's Zendesk credential;
2. reject a missing, revoked, or `reauthorization_required` record without fallback;
3. return the current access token if it remains valid beyond the refresh skew;
4. otherwise perform one single-flight refresh for that principal;
5. immediately persist the returned grant in an encrypted refresh-staging row tied to the expected active epoch and credential version;
6. call `users/me` and require the same Zendesk user ID;
7. atomically compare-and-swap the expected active principal epoch and credential version while moving the staged access/refresh token and new expiry into the credential; and
8. construct a request-scoped OAuth-authenticated `ZendeskClient` carrying that epoch/version and a principal-bound unauthorized callback.

Concurrent requests for different principals never share a lock. Concurrent requests for one expiring principal await the same refresh operation.

The unauthorized callback handles a Zendesk `401` without invalidating healthy credentials from another request:

1. compare the request's principal epoch and credential version with the current stored values;
2. if the store is newer, return that access token immediately;
3. otherwise run the same single-flight, compare-and-swap refresh for the expected version;
4. let the client retry the original Zendesk request exactly once with the returned token; and
5. transition to `reauthorization_required`, increment the lifecycle epoch, invalidate pending codes, and revoke that principal's MCP token families only when `(invalid_grant || the one retry still returns 401)` and an atomic guard proves the principal is still active at the expected epoch and credential version.

If the terminal guard loses because a concurrent login or refresh advanced either value, the stale failure is ignored and the request adopts the healthy winner. This applies equally to proactive refresh and refresh triggered by a `401`, preventing an old in-flight request from revoking a newly installed credential.

If a Zendesk refresh succeeds but its compare-and-swap loses to a concurrent login or disconnect, the resolver never installs the losing staged grant. It marks the row discard-only, securely deletes its ciphertext during the same recovery cycle, and makes no upstream refresh or delete that could race with the winning credential. The request then adopts the current active credential or fails closed if the principal was disconnected.

### `src/zendesk-client.ts`

Replace the implicit email/token-only constructor contract with a discriminated authentication type:

- API-token Basic authentication for stdio; or
- OAuth Bearer authentication for HTTP.

All endpoint, pagination, normalization, tool, and resource behavior remains unchanged. Every fetch uses the configured abort timeout and no blind retry. The HTTP resolver injects an `onUnauthorized(principalEpoch, credentialVersion)` callback into its request-scoped client. On the first Zendesk `401`, the client obtains a replacement token through that callback and retries the same request once. A second `401` becomes a sanitized typed reauthorization error after the resolver performs the version guard described above. Stdio clients omit the callback and preserve current behavior.

Replace raw upstream-body error messages with a typed sanitized error containing stable category, HTTP status, retryability, and correlation ID. Neither the thrown message, MCP tool result, nor normal logs include the upstream body, ticket content, headers, or token-shaped values.

### `src/server.ts`

No tool or resource schema changes. `buildZendeskServer(client)` remains the shared typed boundary for stdio and HTTP.

The current knowledge-base cache remains inside each fresh MCP server, so it cannot cross principals. Any future cache moved outside the request server must be keyed by subdomain and principal ID unless the cached endpoint is proven identity-independent.

### Documentation and operational files

The authentication change also owns every current shared-bearer surface:

- split the ambiguous combined environment sample into `.env.stdio.example` for API-token stdio and `.env.http.example` for Compose OAuth; never put a real secret or generated encryption key in either template;
- update `README.md` requirements, local/Compose startup, full-origin Tailscale Serve, URL-only Codex configuration, browser login, backup/restore, cutover/rollback, local-only Codex logout, and operator revocation procedures;
- change `scripts/smoke-http.mjs` from a shared-bearer client into a non-secret discovery/readiness smoke for health, unauthenticated challenge, and OAuth metadata; authenticated live acceptance runs through a logged-in Codex client rather than copied token material;
- implement the three confirmed session/operator commands plus a create-only consistent-backup command through one non-model-visible `scripts/oauth-admin.mjs` entrypoint; and
- replace the shared-bearer assumptions in configuration, HTTP, deployment, and smoke tests with the fake OAuth provider and persistent-store contract.

## Authorization Flow

### Discovery and MCP authorization start

1. An unauthenticated `/mcp` request returns `401` with a `WWW-Authenticate` challenge containing the path-specific protected-resource metadata URL and required scopes.
2. Codex discovers the same-origin authorization server metadata.
3. Codex dynamically registers its loopback callback and begins an authorization-code flow with PKCE, requested scopes, and the canonical `/mcp` resource.
4. The broker validates the client, exact redirect URI, scopes, PKCE challenge, and resource.
5. The broker stores a short-lived one-time login transaction, including the original Codex state, a separate one-time consent CSRF value, and the hash of a random browser-binding nonce.
6. It sets that nonce only in a short-lived `HttpOnly; Secure; SameSite=Strict` cookie scoped to the consent route, then renders a local consent page showing the escaped, explicitly unverified client name, exact loopback redirect host and port, requested MCP scopes, and resource. The page warns that a localhost callback can be impersonated.
7. Deny atomically consumes the transaction and redirects to the validated Codex callback with `error=access_denied` and the original state.
8. Confirm atomically consumes the CSRF value, advances the transaction to `upstream_pending`, and only then redirects the browser to Zendesk with a separate random upstream state.

The consent page is required for every dynamically registered client before the broker forwards to its static Zendesk client. This satisfies the MCP confused-deputy requirement; the upstream Zendesk consent page identifies the broker, not the downstream Codex registration. The page uses no third-party assets and sends `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, a restrictive Content Security Policy with `frame-ancestors 'none'` and `form-action 'self'`, and an anti-clickjacking header.

The form accepts only a small URL-encoded POST with the one-time transaction and CSRF values. Confirm and deny both require the matching browser cookie plus an exact same-origin `Origin` header, atomically consume the CSRF value, and clear the cookie. A public MCP client that prefetched its own consent HTML therefore cannot transplant the hidden fields into another logged-in browser and submit consent on that user's behalf.

### Zendesk callback and MCP code issuance

1. Zendesk redirects the browser to `https://dev-server.tail22145b.ts.net/oauth/zendesk/callback`.
2. The broker hashes and atomically consumes the upstream state record.
3. It exchanges the Zendesk code server-to-server and immediately stages the returned token response encrypted on that matched transaction before another upstream call.
4. It calls `users/me` with the staged Zendesk access token to establish the stable Zendesk user ID.
5. In one SQLite transaction, it upserts the principal using the fixed subdomain and returned Zendesk user ID, moves/re-encrypts the staged grant into a versioned principal credential, inserts a separate one-time MCP authorization code bound to the new active epoch plus the original MCP client/redirect/PKCE/scopes/resource, and marks the login transaction complete.
6. Only after that transaction commits does it redirect the browser to the original Codex callback with the MCP code and original Codex state.

The Zendesk callback is browser-mediated. It may remain tailnet-only as long as the user's browser is connected to the tailnet and Zendesk accepts the registered HTTPS callback URI.

Repeated or concurrent browser logins for the same Zendesk user are serialized by credential-version compare-and-swap. The last committed credential becomes current and clears the principal's `reauthorization_required` state. Only already-active MCP token families remain bound to the principal and automatically use the new credential, so logging in on a second Codex client does not log out the first. No login or credential replacement clears a family's `revoked_at`; families revoked by replay, RFC 7009, `invalid_grant`, or disconnect stay revoked, and the successful login receives a new family.

Each login transaction records its creation time. If `users/me` resolves a disconnected principal, a callback may reactivate it only when that login began after `disconnected_at`; an older in-flight callback is rejected and cannot undo an operator disconnect. Reactivation increments the principal lifecycle epoch and issues only the newly authorized MCP family; previously revoked families stay revoked.

Ordinary re-login never performs automatic upstream revocation. The transaction makes the superseded credential unavailable immediately and securely deletes its local ciphertext, while its independent Zendesk grant expires under Zendesk's configured lifetime. This deliberately avoids an `A -> B -> A` race in which a delayed delete of grant A could revoke a newly current credential. Tenant-side token audit/revocation remains the recovery path for an orphaned or suspected superseded grant.

If Zendesk denies authorization, the broker redirects to the already validated original Codex callback with `error=access_denied` and the original MCP state. If code exchange or `users/me` fails, it redirects with `error=server_error` and the original MCP state. A local browser error page is used only when no trusted, unconsumed login transaction exists, because Codex otherwise waits indefinitely for its loopback callback.

If any step after token exchange fails or the process crashes, the staged encrypted grant is unavailable to requests and becomes discard-only. Recovery securely removes its local ciphertext without an upstream call that could race with a healthy credential. The sanitized OAuth error redirect is never delayed or populated with cleanup detail; the upstream grant remains subject to Zendesk expiry and tenant-side audit.

### MCP token exchange and request use

1. Codex exchanges the MCP code with its PKCE verifier.
2. The provider atomically consumes the code and issues a new opaque MCP access/refresh token family.
3. Codex sends the MCP access token in `Authorization: Bearer` on every HTTP request.
4. The verifier checks its hash, expiry, revocation state, client, scopes, and exact resource audience before returning `AuthInfo`.
5. The POST route resolves the principal's independent Zendesk credential and builds a request-scoped client.

## Token and Scope Policy

### MCP tokens

- Login transactions and authorization codes expire after 10 minutes.
- MCP access tokens expire after 15 minutes.
- Each MCP refresh-token generation expires 30 days after issuance; successful rotation starts a new 30-day inactivity window.
- Every successful refresh rotates the MCP refresh token.
- The first refresh atomically consumes the presented token and caches the exact encrypted token response for 60 seconds. An identical retry with the same normalized scopes, client, and resource during that window receives the same response only while the family is active and that cached successor is still its current unconsumed generation; this handles a lost response or concurrent Codex refresh without resurrecting revoked or already-advanced state.
- Reuse after that 60-second window, or reuse with different scopes, client, or resource, revokes the entire token family.
- A successful RFC 7009 revocation request invalidates only the selected MCP client token family.
- A principal may have multiple active MCP client token families.

### Zendesk tokens

- Store and honor the upstream `expires_in` and refresh-token expiration semantics returned by Zendesk.
- Request `expires_in=1800` and `refresh_token_expires_in=2592000` explicitly on initial authorization-code exchange and refresh. This guarantees a renewable grant for legacy local Zendesk OAuth clients created before 2026-04-30, which otherwise may issue a non-expiring access token without a refresh token.
- Refresh before expiry using a bounded clock skew.
- If Zendesk rotates the refresh token, replace the stored value immediately.
- A current-epoch/version upstream `invalid_grant`, explicit revocation, or unrecoverable `401` marks the principal `reauthorization_required`; stale failures cannot.
- MCP token revocation does not automatically revoke the shared per-principal Zendesk credential because another Codex client may still use it.

### Disconnect semantics

Client revocation accepts either token type and revokes only that MCP token family. The encrypted Zendesk credential remains available to other token families for the same principal. The current Codex CLI's `codex mcp logout zendesk` only deletes its local token record and does not call the server's revocation endpoint; its access token therefore remains server-valid for at most 15 minutes, and any copied refresh token remains valid until server expiry or explicit revocation.

There is no admin web UI or model-visible disconnect tool. Guaranteed server-side session and principal invalidation use operator commands inside the container:

```bash
npm run oauth:sessions -- --zendesk-user-id <id>
npm run oauth:revoke-family -- --family-id <id> --confirm
npm run oauth:disconnect-user -- --zendesk-user-id <id> --confirm
npm run oauth:backup -- --destination /data/backups/<new-name>.sqlite
```

The read-only sessions command prints only opaque family ID, escaped registered client name, loopback redirect, creation/last-use/expiry timestamps, and status. Each mutating command first prints its non-secret target and refuses to continue without `--confirm`. The backup command accepts only a new absolute path under `/data/backups/`, uses SQLite's consistent backup API, and never prints the encryption key or database contents.

Family revocation atomically revokes that family only. Principal disconnect atomically increments the lifecycle epoch, marks the principal disconnected with `disconnected_at`, invalidates pending codes, revokes all its MCP families, and moves the encrypted Zendesk credential into a fail-closed `revocation_pending` outbox record. Refresh compare-and-swap requires the old epoch and active status, so no in-flight refresh can resurrect credentials after that commit. Requests can never resolve a tombstoned credential.

The outbox is disconnect-only. Before every network attempt the worker atomically verifies that the principal remains disconnected at the captured epoch with no active credential, then takes the expiring claim lease. A post-disconnect reactivation transaction refuses while cleanup is actively claimed; otherwise it atomically cancels the pending outbox row, securely discards the old ciphertext without an upstream call, and only then installs the new credential. This prevents an old cleanup attempt from revoking a reactivated principal.

For an eligible disconnect row, the worker best-effort calls Zendesk's `DELETE /api/v2/oauth/tokens/current.json` with the tombstoned credential. A `401` is not assumed terminal: while its refresh token remains eligible, the worker refreshes only to obtain a current access token and immediately revokes it. `invalid_grant`, a confirmed already-revoked response, or known refresh-token expiry completes cleanup; transport errors and `5xx` retain the encrypted tombstone with bounded backoff. A documented terminal retention deadline after upstream refresh-token expiry removes an unrecoverable tombstone. Commands and worker logs never print a token or email address.

### Scopes

Advertise and issue both MCP scopes for this release:

- `zendesk:read`
- `zendesk:write`

Authorization requests must select exactly both scopes. This all-tools release does not issue read-only MCP tokens because `/mcp` requires both scopes and a read-only token would be valid-looking but unusable. Per-tool scope enforcement can be introduced later together with a deliberate read-only product mode.

Request only the narrowest upstream Zendesk scope set proven to support every current behavior:

- `read`
- `tickets:write`

The global `read` scope is required because Zendesk's ticket-audit endpoints explicitly do not accept the resource-specific `tickets:read` scope. It subsumes the resource-specific read scopes for the current ticket, user, organization, and Help Center calls. This broadens the upstream token's potential GET surface, but Zendesk continues enforcing each user's role and object-level permissions, and the MCP server exposes only its existing tools and resource. `tickets:write` remains resource-specific for the current ticket and comment mutations.

| Current behavior | Zendesk endpoints represented | Required upstream scope |
| --- | --- | --- |
| `get_ticket`, `get_tickets`, `search_tickets`, `list_ticket_fields`, `get_ticket_audits`, `get_ticket_comments` | ticket, field, audit, and comment GETs | `read` |
| `create_ticket`, `update_ticket`, `create_ticket_comment` | ticket POST/PUT and comment write | `tickets:write` |
| `search_users` and the `users/me` identity check | user GET/search | `read` |
| `search_organizations` | organization GET/search | `read` |
| general `search` | ticket, user, and organization search results | `read` |
| knowledge-base resource | Help Center article GETs | `read` |

Because Zendesk returns a token even for an invalid scope string and only fails later with `403`, fake-server tests are not sufficient. Pre-cutover live probes must exercise each read scope family, and the controlled test-ticket acceptance must exercise `tickets:write`.

## Security Requirements

- Production issuer, resource, callback, and authorization endpoints use HTTPS.
- The public base URL is configuration, not request-derived data.
- The Zendesk subdomain and OAuth endpoints are fixed server-side.
- MCP access tokens are audience-bound to the exact canonical `/mcp` resource.
- PKCE S256 is mandatory for MCP authorization codes.
- Explicit local consent is mandatory before a dynamically registered client is forwarded to the static Zendesk OAuth client.
- OAuth client redirect URIs are exact-match validated and limited to the explicit-port `127.0.0.1` and `localhost` HTTP profile used by Codex; arbitrary HTTPS callbacks are not registered in this deployment.
- Login state, authorization codes, and rotating refresh tokens are one-time values.
- Consent uses a separately generated one-time CSRF value, browser-binding `HttpOnly; Secure; SameSite=Strict` cookie, and exact-origin POST check; it cannot be framed or submitted to a non-local action.
- Dynamic registration, authorize, token, revoke, and callback routes are rate-limited.
- No Zendesk credential appears in MCP tool arguments, `_meta`, resources, prompts, model-visible output, URLs, or custom client headers.
- No Authorization header, OAuth code, state, token response, email address, complete request headers, or decrypted credential is logged.
- Errors use correlation IDs and stable public codes rather than upstream bodies.
- There is no fallback to the legacy shared HTTP identity.
- The encryption key and database backups are stored separately.
- The process fails closed when the token store, cipher, principal, scope, resource, or upstream credential cannot be validated.

## Error Handling

- Missing, malformed, unknown, revoked, or expired MCP bearer: `401` with protected-resource metadata.
- Valid bearer with missing required scope: `403` with the required scope challenge.
- Invalid registration, redirect URI, resource, PKCE, state, code, or refresh replay: standard OAuth `400` response without sensitive detail.
- Zendesk authorization denial: consume the login transaction and redirect to the validated Codex callback with `error=access_denied` plus the original MCP state.
- Zendesk token exchange, `users/me`, validation, or principal-commit failure: do not issue an MCP code; mark any staged grant discard-only, then redirect to the validated Codex callback with `error=server_error` or `temporarily_unavailable`, the original state, and no upstream detail.
- Unknown, expired, or already consumed Zendesk state: no trusted redirect exists, so return a small generic correlated browser error page.
- Store or cipher failure: fail closed with `500`, log only the correlation ID and internal error class, and mark readiness unhealthy if persistence is unavailable.
- Refresh `invalid_grant`: only an expected-epoch/version compare-and-swap may mark that principal for reauthorization, increment its epoch, invalidate pending codes, and revoke its MCP token families. A stale loser adopts the newer credential instead.
- Unexpected Zendesk `401` during a tool call: compare the principal epoch and credential version, refresh or adopt a newer token, and retry exactly once. Only an epoch/version-guarded `invalid_grant` or second `401` marks the principal for reauthorization and returns a sanitized MCP tool error instructing the user to run `codex mcp login zendesk`; the next request receives `401`.
- Zendesk `403`, validation errors, rate limits, and outages retain their current tool-error shape after removing sensitive upstream content.

`/healthz` reports process and local-store readiness only. It never calls Zendesk, so an upstream outage does not create a container restart loop.

## Deployment

### Zendesk setup

Create one local confidential OAuth client for the fixed Zendesk subdomain and register exactly:

`https://dev-server.tail22145b.ts.net/oauth/zendesk/callback`

Store its client ID and client secret only in server-side deployment configuration.

### Docker Compose

- Keep loopback-only publication and Tailscale Serve HTTPS termination.
- Proxy the entire origin, not only `/mcp`, so metadata and OAuth routes are reachable.
- Add a named volume mounted at `/data` and writable by the existing non-root user.
- Install/compile `better-sqlite3` in the Alpine build stage, prune there, copy production `node_modules` into runtime, and create/chown `/data` before `USER node`; the runtime stage has no compiler toolchain.
- Keep the root filesystem read-only, `/tmp` as tmpfs, and `no-new-privileges`.
- Add the public base URL, Zendesk OAuth client credentials, database path, and base64 encryption key to the protected environment file or Docker secret mechanism.
- Back up the encrypted database with the SQLite backup API or a checkpointed snapshot, and back up the encryption key separately.

### Maintenance-window cutover

This is an intentional break-before-login cutover, not a dual-auth migration. Before the window, inventory every URL client and preserve a secured rollback copy of the old image, HTTP deployment environment, and client configuration. Do not expose or print existing bearer values during inventory.

During the window:

1. deploy the OAuth-enabled server and persistent volume;
2. remove `MCP_BEARER_TOKEN`, `ZENDESK_EMAIL`, and `ZENDESK_API_KEY` from the HTTP deployment environment while retaining the fixed subdomain and new OAuth values;
3. for every Codex client, remove all static credential sources: the current `http_headers.Authorization`, any `bearer_token_env_var`, and any `env_http_headers.Authorization`;
4. leave a URL-only client entry—OAuth discovery is the current Codex default:

```toml
[mcp_servers.zendesk]
url = "https://dev-server.tail22145b.ts.net/mcp"
```

5. inspect the effective entry in a redacted form and prove none of those three credential sources remains; and
6. run for each client:

```bash
codex mcp login zendesk
```

Existing URL clients fail closed from deployment until their OAuth login succeeds. After every inventoried client passes acceptance, destroy the working rollback copies of shared bearer material according to the normal secret-retirement procedure. If a release gate fails, roll back the image, HTTP environment, and affected client entries together; do not leave legacy shared auth and OAuth enabled concurrently.

These removals apply only to the Docker HTTP deployment. Stdio users retain their own existing `ZENDESK_EMAIL` and `ZENDESK_API_KEY` environment configuration.

## Recommended Implementation Mode

Use a hybrid execution mode. Build the shared auth types, configuration, cipher, schema, store transactions, and provider contract sequentially with the optimized TDD loop because their invariants and migrations are tightly coupled. Once those contracts are green and frozen, run bounded parallel workstreams for request-scoped Zendesk authentication, HTTP/OAuth routing and consent, and Docker/documentation/operational tooling. Rejoin before protocol integration tests, image smoke, and the live Codex/Zendesk gates. The integrated proof is the complete automated suite plus the staged multi-user, multi-task refresh, attribution, isolation, revocation, restart, and backup acceptance defined below.

## Testing Strategy

Implementation follows the optimized TDD loop: inspect the narrow production path, save only the test change, prove a focused RED, apply the stated production change, and rerun the same test for GREEN.

Automated tests use a fake Zendesk OAuth/API server and never require live Zendesk credentials, Tailscale, or `dev-server`.

### Configuration and crypto

- HTTP OAuth config accepts the complete valid environment and rejects each missing or malformed value without exposing values.
- Public base URL rejects credentials, path/query/fragment, insecure scheme, and allowed-host mismatch; fixed subdomain rejects non-label input.
- Stdio config retains the current API-token contract.
- AES-GCM encrypt/decrypt round-trips.
- Wrong key, changed nonce, ciphertext, or tag fails authentication.
- Moving encrypted login transactions, Zendesk credentials, disconnect outbox rows, or MCP retry responses across any of their kind-specific AAD dimensions fails authentication.
- Persisted database and captured logs do not contain plaintext secret sentinels.
- Fake Zendesk `4xx`/`5xx` bodies containing token, ticket, and arbitrary secret sentinels never appear in MCP tool output or logs; only stable category/status/correlation data remains.

### Store and token lifecycle

- Schema migration creates the expected version on an empty volume and reopens idempotently.
- Login state and authorization codes are one-time and expire after 10 minutes.
- MCP access tokens expire after 15 minutes and are bound to client, scopes, principal, and resource.
- `AuthInfo.expiresAt` uses integer epoch seconds and the exact canonical `/mcp` `URL`; millisecond timestamps and resource mismatches fail.
- MCP refresh rotates; same-scope/client/resource retry within 60 seconds is idempotent, while later or mismatched replay revokes its family.
- Consumed refresh-token hashes remain detectable until their generation expiry while the encrypted replay response disappears after 60 seconds.
- Revocation during the grace window prevents cached response return; after `R1 -> R2 -> R3`, retrying `R1` is replay rather than an idempotent response.
- Revoking one client family leaves another family and the principal's Zendesk credential intact.
- Authorization-code exchange requires the principal's still-active epoch; disconnect and reauthorization invalidate older pending codes atomically.
- Operator commands require confirmation, target only the selected family/principal, and emit no secret or email; disconnect makes the credential immediately unusable and retains ciphertext only in the revocation outbox.
- Store operations remain correct after process restart.

### OAuth protocol

- Protected-resource and authorization-server metadata advertise the exact issuer, resource, endpoints, PKCE method, and scopes.
- Dynamic registration accepts valid Codex loopback callbacks and rejects unsafe or mismatched redirects.
- Dynamic registration accepts Codex's public-client metadata with exactly the all-tools scope set, rejects confidential methods and every other scope set, and remains compatible with the installed client's stripped `application_type` field.
- Authorization preserves the original MCP state while using a distinct Zendesk state.
- Authorization displays escaped client identity, the exact localhost callback hostname, scopes, and resource; no Zendesk redirect occurs before a valid one-time consent confirmation.
- Consent denial redirects to Codex with `access_denied`; missing/mismatched browser cookie, wrong/missing Origin, CSRF mismatch, prefetch transplant, replay, framing, and oversized form bodies fail closed.
- Wrong, expired, or replayed state fails before Zendesk tokens are stored.
- Missing resource fails at authorization and code exchange; current-rmcp-shaped refresh may omit it and inherits the family's stored canonical value, while a wrong supplied refresh resource fails. Missing redirect URI fails code exchange; wrong redirect URI, client, scope, PKCE verifier, or reused MCP code also fails.
- Zendesk denial, missing code, exchange failure, `users/me`, or local commit failure never issues an MCP code and returns the correct sanitized OAuth error plus byte-for-byte original state to the Codex callback.
- The original MCP state and transaction payload are absent as plaintext from the database and logs.
- A successful exchange is encrypted on the login transaction before identity calls; successful callback atomically moves it to the stable Zendesk user, while callback failure, expiry, or simulated crash leaves only a fail-closed discard-only staging row for local deletion.
- Credential replacement, MCP code insertion, and login-transaction completion commit or roll back together.
- Successful callback stores the stable Zendesk user ID and encrypted tokens, then returns a distinct MCP code.
- Token and revocation metadata advertise public-client method `none`; token and revoke handlers accept no client secret and enforce client ownership.
- Refresh concurrently retries the same consumed token idempotently for 60 seconds; later or cross-scope/client/resource replay revokes the family.

### Request isolation and Zendesk refresh

- Invalid MCP auth fails before credential lookup or MCP server construction.
- Principal A and principal B produce different request-scoped Zendesk Bearer headers.
- Concurrent A/B requests cannot cross credentials, results, errors, or cache state.
- Ten simultaneous requests for one expiring principal cause one Zendesk refresh.
- A stale request receiving `401` adopts a newer epoch/version instead of revoking it; a current version refreshes and retries once; only a guarded terminal failure affects that principal.
- A rotated upstream refresh token is persisted and used after restart.
- Every upstream refresh stages before identity validation and revalidates the same Zendesk user ID before installation.
- Refresh-versus-login, old-token `401` after refresh, and concurrent-login races preserve the winning credential, discard losing local ciphertext, and make zero upstream cleanup calls.
- `invalid_grant` versus a successful concurrent login loses its epoch/version guard and cannot revoke the winner or its active families.
- Concurrent logins atomically version credentials, preserve existing active MCP families, discard superseded local ciphertext, and make no upstream cleanup call.
- Re-login preserves only active families and never clears a family-level revocation marker.
- Disconnect-versus-refresh increments the principal epoch and prevents stale compare-and-swap; a callback begun before disconnect cannot reactivate the principal, while a fresh post-disconnect login can.
- Tombstone cleanup refreshes an expired access token only for immediate revocation, retries transient failure, and treats `invalid_grant` or known refresh expiry as terminal.
- Re-login, CAS-loser, and failed-staging tests assert local discard and zero upstream cleanup calls. Disconnect, retry, and disconnect-then-reactivate tests assert that only a still-disconnected captured epoch can enter the revocation worker.
- A simulated process death after outbox claim leaves an expired lease that a reopened worker reclaims; graceful abort reschedules rather than strands work.
- Upstream `invalid_grant` affects only its principal and never invokes a default account.
- Hung OAuth/API/metadata/revocation requests abort within the configured bound, release single-flight/worker claims safely, and do not retry one-time exchange or refresh blindly.
- GET, DELETE, and health requests do not decrypt Zendesk credentials.

### Regression and packaging

- All twelve existing tools and both prompts remain registered.
- The knowledge-base resource remains available.
- Existing Zendesk normalization, pagination, attachment, server-instruction, and stdio tests remain green.
- `npm run check`
- `npm test`
- `git diff --check`
- `docker compose config`
- Docker image build
- Compose health, unauthenticated challenge, OAuth metadata, and clean shutdown smoke
- Non-root user, read-only root filesystem, writable `/data`, writable tmpfs `/tmp`, and `no-new-privileges` checks
- README and split environment examples contain the correct transport-specific variables and no HTTP shared-bearer instructions.
- `smoke:http` requires no bearer or Zendesk credential and validates discovery metadata without returning ticket data.
- Operator npm scripts map to the non-model-visible admin entrypoint and refuse mutation without `--confirm`.

## Live Acceptance

1. Before the maintenance window, register the exact Zendesk callback and deploy a staging instance with a deliberately short MCP access-token lifetime.
2. Run `codex mcp login zendesk`, complete both the local broker consent and Zendesk browser flow, and confirm `users/me` resolves the expected Zendesk user ID.
3. Keep two Codex Desktop tasks open against the same registered client. Alternate MCP calls from both tasks across at least three access-token expirations/refresh generations and prove both recover without restart or login. Repeat once with the current CLI.
4. Treat any stale-token or `invalid_grant` failure as a release blocker. The open Codex refresh issue means the 15-minute production lifetime is not accepted on assumption; a longer access lifetime or non-rotating refresh policy would require a separate explicit security tradeoff and design revision.
5. With the normal lifetime restored, probe every read scope family live: ticket/field/audit/comment reads, user search/identity, organization search, general search, and the Help Center resource.
6. Log in as a second Zendesk user from another client and prove concurrent read requests remain isolated.
7. With explicit approval, add one private comment to a designated test ticket to exercise `tickets:write`.
8. Read the ticket audit and prove its `author_id` equals the OAuth user's stable Zendesk user ID.
9. Run `oauth:revoke-family --confirm` for one session, prove that session receives `401`, and confirm the other user/client remains functional. Do not use `codex mcp logout` as proof of server revocation because the current CLI only deletes local credentials.
10. Restart the container and confirm stored, encrypted credentials continue working without another login.
11. With a disposable Zendesk principal and separate explicit approval, run `oauth:disconnect-user --confirm`. Prove immediate local invalidation of every family, transient outbox retry followed by eventual upstream token rejection while the captured epoch remains disconnected, and no effect on the other active principal.
12. Verify the SQLite backup/restore procedure on a disposable copy and confirm the encryption key is required and stored separately.

The controlled private comment and disposable-principal token revocation are the two live mutations in acceptance. Each requires a named target and separate explicit approval immediately before execution.

## Success Criteria

- Each supported current Codex runtime passes the multi-task refresh gate and can complete one standards-based browser login without copying Zendesk or MCP secrets manually.
- Zendesk writes are attributed to the Zendesk user who authorized that client.
- Two concurrent users cannot cross credentials or data through shared mutable state.
- MCP and Zendesk token audiences, storage, refresh, and revocation remain independent.
- No plaintext credential appears in the client configuration, MCP messages, logs, errors, or database.
- The URL, stateless Streamable HTTP transport, existing tools, resources, prompts, and stdio behavior remain available.
- Loss or revocation of one user's credentials fails closed for that principal and does not fall back to a service account.

## Risks and Mitigations

- **OAuth broker complexity:** Use SDK handlers and middleware behind a thin metadata composition layer; custom protocol code is limited to the Zendesk bridge, persistent provider, consent, and resolver.
- **Codex Desktop stale refresh state:** Require the multi-task, multi-generation live gate on the installed version and stop cutover on failure; do not silently weaken rotation or extend token lifetime.
- **Current Codex omits refresh `resource`:** Accept omission only by inheriting the immutable audience bound at code exchange, reject every supplied mismatch, pin the compatibility test, and remove the exception when the supported client is compliant.
- **Refresh-token race:** Serialize refresh per principal, compare-and-swap lifecycle and credential versions, persist rotated credentials immediately, and provide only a bounded idempotent retry window.
- **Crash between upstream exchange/rotation and persistence:** Stage every returned grant in encrypted storage before further work; winners install atomically, losers/failures are discarded locally, and only an explicit disconnect enters the upstream revocation outbox.
- **Irreducible exchange crash window:** Zendesk token issuance and the local SQLite commit cannot be one transaction. Keep the code-exchange-to-staging path synchronous and minimal, but document that a process death after Zendesk sends a token and before local staging can leave an unknown upstream grant until Zendesk expiry or tenant-side audit/revocation.
- **Superseded upstream grant:** Ordinary re-login discards the old secret locally but intentionally does not race an upstream delete against the new credential. Use short Zendesk token lifetimes and tenant-side token audit; a requirement for zero orphaned grants would force a material redesign such as one upstream connection per client or a blocking per-principal revocation fence.
- **Database theft:** Encrypt upstream credentials, hash bearer values, and keep the encryption key separate.
- **Encryption-key loss:** Document and separately back up the key; fail closed because encrypted tokens are intentionally unrecoverable without it.
- **Unsafe redirects or token confusion:** Exact redirect matching, PKCE, one-time state/codes, and resource/audience validation are mandatory.
- **Tailnet-only callback:** The browser performing login must be connected to Tailscale; deployment smoke verifies the complete redirect path before cutover.
- **Zendesk permission differences:** Zendesk remains authoritative; the MCP server reports a sanitized permission error and never elevates a user.
- **Global upstream read scope:** Ticket audits force the broad `read` scope rather than resource-specific read scopes. Keep writes restricted to `tickets:write`, expose no new MCP read tools in this release, and retain the live endpoint-family probes plus per-user Zendesk role enforcement.
- **Native SQLite dependency:** Pin and smoke-test `better-sqlite3` in the Node 22 Alpine image, compile only in the build stage when no matching prebuild is available, and verify backup/restore.
- **Local-only Codex logout:** Document it accurately and use RFC 7009 or confirmed operator commands when server-side invalidation is required.

## References

- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Codex Streamable HTTP MCP configuration](https://learn.chatgpt.com/docs/extend/mcp#streamable-http-servers)
- [Open Codex MCP refresh issue #17265](https://github.com/openai/codex/issues/17265)
- [Zendesk authorization-code OAuth guide](https://developer.zendesk.com/documentation/api-basics/authentication/api-tokens-to-oauth/)
- [Zendesk OAuth token scopes](https://developer.zendesk.com/api-reference/ticketing/oauth/oauth_tokens/)
- [Zendesk Ticket Audits scope requirement](https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_audits/)
- [Zendesk API-token retirement timeline](https://developer.zendesk.com/documentation/api-basics/authentication/oauth-migration/)
- [Node SQLite runtime status](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html)
- [better-sqlite3 documentation](https://github.com/WiseLibs/better-sqlite3)
