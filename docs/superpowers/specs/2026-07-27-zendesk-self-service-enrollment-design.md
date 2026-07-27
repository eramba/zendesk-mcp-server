# Zendesk Self-Service Enrollment Design

**Date:** 2026-07-27

**Status:** Approved for implementation

## Objective

Allow an internal colleague to create and link one personal MCP bearer without
an administrator running `npm run admin -- create`. The enrollment page is
available only through the company's Tailscale deployment, and a bearer is
created only after Zendesk proves that the colleague is an agent or admin in
the configured Zendesk account.

The intended lifecycle is:

```text
GET /create-account
  -> show a no-store enrollment page
POST /create-account
  -> create one short-lived hash-only OAuth state
  -> redirect to the fixed Zendesk OAuth client
GET /oauth/callback
  -> claim the state before any upstream call
  -> exchange the authorization code
  -> load users/me and require role agent or admin
  -> atomically create the active internal user, encrypted grant, and bearer hash
  -> show the plaintext MCP bearer once
POST /mcp with that bearer
  -> resolve the linked Zendesk identity through the existing runtime
```

The existing administrator invitation, reauthorization, listing, revocation,
backup, request-scoped MCP transport, and stdio flows remain available.

## Current Lifecycle and Extension Point

The current administrator path is:

```text
admin create
  -> InternalAuthStore.createPendingUser(label)
  -> print one bearer and one invitation URL
GET /oauth/link?invitation=...
  -> consume the invitation and attach a random OAuth state
GET /oauth/callback
  -> exchange the code
  -> establish the authoritative identity with users/me
  -> activate the pending user and its bearer
```

`createLinkHandlers`, `ZendeskOAuthGateway.currentUser`, and
`InternalAuthStore` are the earliest existing typed extension points. The
self-service flow extends those contracts and the existing callback rather
than adding another OAuth client, callback, credential store, or MCP
authentication path.

## Approaches Considered

### OAuth-first self-service

Create only an expiring OAuth state before authorization. Generate the user
and bearer after a successful role check.

**Decision:** Selected. It proves Zendesk eligibility before creating any MCP
credential, gives the bearer a one-time handoff, and needs only a focused store
extension and HTTP handlers.

### Bearer-first self-service

Expose the existing `createPendingUser` operation as an internal POST and show
the bearer before OAuth completes.

**Decision:** Rejected. It is less code, but any tailnet member could allocate
unbounded pending users and secrets before proving a Zendesk identity.

### Administrator-approved browser invitation

Keep an administrator provisioning step but move bearer handoff to the OAuth
success page.

**Decision:** Rejected for this feature because it does not provide the
requested self-service workflow. The existing CLI remains the controlled
fallback.

## Eligibility and Identity

The fixed Zendesk OAuth client and configured subdomain remain the upstream
trust boundary. `GET /api/v2/users/me` is extended to parse an authoritative
`role` in addition to ID, name, and email. Accepted roles are exactly `agent`
and `admin`; `end-user`, missing, or unknown roles fail closed.

Zendesk custom agent roles are represented by the top-level `agent` role and
are therefore eligible. The internal display label is derived from the
authoritative Zendesk name, then email, then a deterministic user-ID fallback.
No path or form label is trusted as identity.

The existing unique index on `internal_users.zendesk_user_id` continues to
enforce one internal account and bearer per Zendesk identity. Self-service does
not rotate, recover, or add a second bearer. An existing, revoked, or
reauthorization-required identity is directed to the administrator.

Role eligibility is checked at initial enrollment and whenever a refreshed
grant is verified with `users/me`. If a refreshed identity is no longer an
agent or admin, or no longer matches the stored Zendesk user ID, the resolver
marks the internal account as requiring reauthorization and fails closed.

## HTTP Routes and Browser Flow

### `GET /create-account`

Returns a small server-rendered HTML page with a form and a single
"Connect Zendesk" action. It creates no database state and accepts no label.
When self-service is disabled, the route is not mounted and returns `404`.

### `POST /create-account`

Requires an `Origin` that exactly matches `PUBLIC_BASE_URL`. It creates a
random 32-byte base64url OAuth state, persists only its SHA-256 hash with a
short expiry, and redirects to the authorization URL produced by the existing
fixed `ZendeskOAuthGateway`.

The POST has no secret request fields. A failed state allocation returns a
generic unavailable page without attempting Zendesk OAuth.

### `GET /oauth/callback`

The callback keeps one canonical redirect URI for both existing administrator
invitations and self-service enrollment. A store claim returns a discriminated
flow result:

- an administrator invitation identifies its pre-created internal user; or
- a self-service enrollment identifies its consumed enrollment record.

The callback claims exactly one matching state before exchanging a code. An
impossible collision that matches both flow stores fails closed. Existing
administrator invitation behavior remains unchanged.

For self-service, the callback exchanges the code, loads and validates
`users/me`, checks eligibility, and calls one store transaction that:

1. allocates the internal user ID and `zmcp_` bearer;
2. encrypts the complete Zendesk grant with the new user ID as associated data;
3. inserts an active `internal_users` row with the bearer hash and authoritative
   Zendesk identity; and
4. inserts the encrypted grant.

The transaction returns the plaintext bearer but never persists it. Unique
identity conflicts return an `already_registered` result; unrelated storage
failures remain generic.

### Success page

The one-time success response shows:

- internal `user_id`;
- the personal `mcp_bearer`;
- the canonical MCP URL (`PUBLIC_BASE_URL + /mcp`);
- a ready-to-copy Codex `http_headers.Authorization` configuration fragment;
- a warning that the bearer cannot be displayed or recovered again.

The bearer is present only in the HTTPS response body. It is not placed in a
URL, redirect, cookie, template log, or external asset. Reloading the callback
cannot retrieve it because the state was already consumed.

## Persistence

A new lifecycle table stores pending self-service states:

### `oauth_self_enrollments`

| Column | Purpose |
| --- | --- |
| `id` | Random internal enrollment UUID |
| `state_hash` | Unique SHA-256 lookup hash; plaintext is never stored |
| `created_at` | Creation epoch seconds |
| `expires_at` | Strict callback deadline |
| `consumed_at` | One-time claim marker |

Expired enrollment rows are removed during store open and enrollment
operations, matching invitation cleanup. Creation and claim use immediate
SQLite transactions so concurrent callbacks cannot both win.

No schema change is required for `internal_users` or `oauth_grants`. Store
metadata and encryption-key compatibility remain unchanged.

## Configuration and Deployment Boundary

`SELF_SERVICE_ENROLLMENT_ENABLED` is an optional strict boolean and defaults to
disabled. The Docker environment and documentation expose it explicitly. The
production deployment enables it only after the MCP origin is restricted to
the intended Tailscale users and served over Tailscale HTTPS.

The application does not trust `Host`, `Forwarded`, or `X-Forwarded-*` to build
URLs or infer that a request came through Tailscale. Canonical links and Origin
checks use only `PUBLIC_BASE_URL`; existing allowed-host middleware remains in
force.

Loopback HTTP remains allowed for local development and automated tests.

## Response Security and Secret Handling

Every enrollment and callback HTML response sets:

- `Cache-Control: no-store`;
- `Pragma: no-cache`;
- `Referrer-Policy: no-referrer`;
- `X-Content-Type-Options: nosniff`;
- `X-Frame-Options: DENY`;
- a restrictive `Content-Security-Policy` with no external resources; and
- a restrictive `Permissions-Policy`.

No handler logs OAuth codes, states, bearer values, grants, identity payloads,
or rendered response bodies. Safe operational logs contain only a category and
correlation ID where the existing error model provides one.

If an access token has been issued but eligibility, identity uniqueness, or
activation fails, the handler makes one bounded best-effort call to revoke the
new current grant before returning a response. Revocation failure never
activates an account and never exposes a credential.

## Error Behavior

- Disabled self-service: `404` because the routes are not mounted.
- Missing or cross-origin POST: `403`, no state allocation, no Zendesk call.
- Invalid, expired, consumed, duplicated, or ambiguous state: generic `400` or
  `410`, no exchange when the claim cannot succeed.
- OAuth denial or malformed callback: generic callback failure, no account.
- Ineligible Zendesk role: generic `403`, best-effort upstream revocation.
- Existing Zendesk identity: safe already-registered page, best-effort
  revocation of the newly issued grant, no bearer rotation.
- Upstream or store failure: generic `502` or `503` page, no active partial
  account.

All error pages omit user-supplied values and secrets.

## Testing

Implementation follows sequential test-driven development with focused RED and
GREEN cycles.

### Store tests

- states are unique, hash-only, expiring, and one-time;
- concurrent claims have exactly one winner;
- self-enrollment creates an active user and encrypted grant atomically;
- the returned bearer authenticates but is absent from SQLite bytes;
- duplicate Zendesk identity returns the expected safe result and creates no
  second user or grant;
- failed transactions leave no partial active user;
- cleanup removes expired self-enrollment state.

### OAuth and resolver tests

- `currentUser` accepts only documented identity fields and the three known
  Zendesk roles;
- missing or malformed roles are invalid responses;
- refresh preserves access for the same eligible identity;
- refresh fails closed when the identity is demoted to `end-user`.

### Handler and HTTP tests

- disabled routes return `404`;
- GET is side-effect free and contains no external resources;
- same-origin POST redirects only to the fixed Zendesk authorization origin;
- cross-origin POST performs no store or OAuth operation;
- successful agent and admin callbacks show one bearer and activate MCP access;
- end-user, duplicate, denial, replay, expiry, collision, exchange failure,
  identity failure, activation failure, and revocation failure all fail closed;
- response headers prevent caching, referrer leakage, framing, and permissive
  content loading;
- rendered bodies and captured logs contain none of the state, code, access
  token, refresh token, client secret, or encryption key fixtures.

### Integrated verification

- `npm run check`;
- full `npm test`;
- Docker production image build and `docker compose config`;
- local fake-only HTTP smoke covering the enrollment page, OAuth redirect,
  callback, one-time bearer, authenticated MCP initialization, replay failure,
  and clean shutdown;
- source and bounded-log scans for sentinel secrets and placeholders.

Live Zendesk mutation is not required for automated verification. Existing
manual smoke commands remain available for an operator-controlled read test.

## Non-Goals

- Public-internet signup or replacement for the Tailscale access policy.
- Company SSO, email-domain allowlists, or per-email administrator approval.
- More than one bearer per Zendesk identity.
- Self-service bearer recovery, rotation, revocation, or reauthorization.
- Changes to MCP tools, Zendesk scopes, stdio authentication, or the fixed OAuth
  client.
- Persisting plaintext bearer values for later display.

## Acceptance Criteria

The feature is complete when an eligible Zendesk agent or admin, connected
through the approved Tailscale HTTPS origin, can open `/create-account`, finish
the fixed OAuth flow, receive exactly one personal bearer, configure Codex, and
successfully initialize MCP as that Zendesk identity without an administrator
CLI command. End users, duplicate identities, callback replays, and all partial
failure paths must produce no usable new bearer or active account.
