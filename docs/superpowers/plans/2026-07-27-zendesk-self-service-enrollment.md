# Zendesk Self-Service Enrollment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an eligible Zendesk agent or admin create one personal MCP bearer from a Tailscale-only browser flow without an administrator CLI command.

**Architecture:** Extend the fixed OAuth callback with a second hash-only state flow. The callback validates the authoritative Zendesk role and then atomically creates an active internal user, encrypted grant, and hash-only bearer; the plaintext bearer is returned in one no-store HTML response. Existing invitation, admin, stdio, and request-scoped MCP behavior remains intact.

**Tech Stack:** TypeScript, Node.js 24, Express, `better-sqlite3`, Zendesk OAuth, Node test runner, Docker Compose.

## Global Constraints

- Work in the current dedicated `codex/zendesk-internal-user-bearers` checkout; do not create another worktree.
- Follow sequential TDD: save only the focused test, prove a meaningful RED, apply the stated production change, and prove GREEN.
- `SELF_SERVICE_ENROLLMENT_ENABLED` is an optional strict boolean and defaults to `false`.
- Self-service accepts exactly Zendesk roles `agent` and `admin`; every other or malformed role fails closed.
- Generate the MCP bearer only after eligibility succeeds. Persist only its SHA-256 hash and display plaintext once.
- Keep the fixed OAuth client, canonical `/oauth/callback`, existing admin invitation flow, one-Zendesk-user uniqueness, and existing Zendesk scopes.
- Never put bearer, state, OAuth code, access token, refresh token, client secret, or encryption key in URLs, cookies, logs, or persisted plaintext.
- Do not add a dependency or public-internet authentication system.

## File Structure

- `src/internal-auth/store.ts`: define the authoritative identity type, self-enrollment state lifecycle, unified callback claim, and atomic active-user creation.
- `src/internal-auth/zendesk-oauth.ts`: parse and validate Zendesk `role` from `users/me`.
- `src/internal-auth/client-resolver.ts`: fail refresh closed when role is no longer eligible.
- `src/internal-auth/link-handlers.ts`: own both browser enrollment routes and the shared OAuth callback while preserving admin invitations.
- `src/http-app.ts`: conditionally mount the two `/create-account` methods and existing OAuth routes.
- `src/http-runtime.ts`: pass canonical origin and feature flag into handlers/app.
- `src/config.ts`: parse the strict self-service feature flag.
- `test/internal-auth-store.test.mjs`: store lifecycle, atomicity, uniqueness, hash-only secret, and concurrency coverage.
- `test/zendesk-oauth.test.mjs`: role response parsing coverage.
- `test/user-client-resolver.test.mjs`: eligible and demoted refresh behavior.
- `test/oauth-linking.test.mjs`: browser flow, headers, role gate, replay, duplicate, revocation, and secret-leak coverage.
- `test/http.test.mjs`, `test/http-runtime.test.mjs`, `test/config.test.mjs`: route mounting and typed wiring.
- `scripts/smoke-http-local.mjs`, `test/smoke-http.test.mjs`: fake-only end-to-end enrollment and MCP initialization.
- `.env.example`, `README.md`, `test/deployment.test.mjs`: explicit deployment configuration and operator documentation.

---

### Task 1: Authoritative Zendesk role and refresh eligibility

**Files:**
- Modify: `src/internal-auth/store.ts`
- Modify: `src/internal-auth/zendesk-oauth.ts`
- Modify: `src/internal-auth/client-resolver.ts`
- Test: `test/zendesk-oauth.test.mjs`
- Test: `test/user-client-resolver.test.mjs`
- Update fixtures: `test/internal-auth-store.test.mjs`, `test/oauth-linking.test.mjs`, `test/admin.test.mjs`, `scripts/smoke-http-local.mjs`

**Interfaces:**
- Produces: `ZendeskIdentity = { id: string; name: string | null; email: string | null; role: "end-user" | "agent" | "admin" }` from `store.ts`.
- Produces: `isEligibleZendeskIdentity(identity: ZendeskIdentity): boolean` from `zendesk-oauth.ts`.
- Changes: `ZendeskOAuthGateway.currentUser(...): Promise<ZendeskIdentity>`.

- [ ] **Step 1: Write failing role parsing and demotion tests**

Add response cases to `test/zendesk-oauth.test.mjs` that assert `currentUser()` returns `role: 'agent'` and rejects missing, unknown, and non-string roles with `SafeAuthError('invalid_response')`. Add a resolver test whose refreshed `currentUser()` returns the same ID with `role: 'end-user'` and assert the store becomes `reauthorization_required`.

Every existing identity fixture passed to `completeLink` or returned by `currentUser` must explicitly include `role: 'agent'`; do not change production yet.

- [ ] **Step 2: Run the narrow tests and prove RED**

Run:

```bash
npm run build
node --test --test-name-pattern='users/me|demoted' test/zendesk-oauth.test.mjs test/user-client-resolver.test.mjs
```

Expected: FAIL because the production identity omits `role` and the resolver accepts a same-ID end user.

- [ ] **Step 3: Implement the typed role contract**

In `store.ts`, export:

```ts
export type ZendeskIdentity = {
  id: string;
  name: string | null;
  email: string | null;
  role: "end-user" | "agent" | "admin";
};
```

Make `validateIdentity` and `completeLink` consume `ZendeskIdentity`. In `zendesk-oauth.ts`, validate the exact three documented roles and return one in `currentUser`. Export:

```ts
export function isEligibleZendeskIdentity(
  identity: ZendeskIdentity,
): boolean {
  return identity.role === "agent" || identity.role === "admin";
}
```

In `UserClientResolver.#performRefresh`, require both matching ID and `isEligibleZendeskIdentity(identity)` before installing the refreshed grant; otherwise call `#disable(snapshot)`.

- [ ] **Step 4: Run the narrow tests and prove GREEN**

Run:

```bash
npm run build
node --test --test-name-pattern='users/me|demoted' test/zendesk-oauth.test.mjs test/user-client-resolver.test.mjs
```

Expected: PASS.

- [ ] **Step 5: Commit the role boundary**

```bash
git add src/internal-auth/store.ts src/internal-auth/zendesk-oauth.ts src/internal-auth/client-resolver.ts test/zendesk-oauth.test.mjs test/user-client-resolver.test.mjs test/internal-auth-store.test.mjs test/oauth-linking.test.mjs test/admin.test.mjs scripts/smoke-http-local.mjs
git commit -m "feat: enforce Zendesk agent enrollment roles"
```

### Task 2: Hash-only enrollment state and atomic bearer creation

**Files:**
- Modify: `src/internal-auth/store.ts`
- Test: `test/internal-auth-store.test.mjs`

**Interfaces:**
- Produces: `createSelfEnrollment(): { state: string; expiresAt: number }`.
- Produces: `claimAuthorization(state: string): { kind: "invitation"; invitationId: string; userId: string } | { kind: "self_enrollment"; enrollmentId: string } | undefined`.
- Produces: `completeSelfEnrollment(input): { kind: "created"; userId: string; bearer: string } | { kind: "already_registered" }`.

- [ ] **Step 1: Write failing store lifecycle tests**

Add tests that create 100 self-enrollment states, assert their plaintext never occurs in SQLite bytes, and prove expiry plus one-time claim. Add a concurrent/synchronous double-claim assertion with exactly one winner. Replace direct callback claims in existing fixtures with `claimAuthorization` and assert invitation results use `kind: 'invitation'`.

Add an atomic activation test:

```js
const enrollment = store.createSelfEnrollment()
const claimed = store.claimAuthorization(enrollment.state)
const created = store.completeSelfEnrollment({
  enrollmentId: claimed.enrollmentId,
  identity: {
    id: '4242',
    name: 'Authoritative Agent',
    email: 'agent@example.test',
    role: 'agent',
  },
  grant: grant('self-service'),
})
assert.equal(created.kind, 'created')
assert.deepEqual(store.authenticateBearer(created.bearer), {
  userId: created.userId,
})
```

Then assert a second enrollment for identity `4242` returns
`{ kind: 'already_registered' }`, creates no second user, and exposes neither
bearer in SQLite bytes. Inject a failure inside the transaction through an
invalid/expired grant and assert no active partial user remains.

- [ ] **Step 2: Run the focused store tests and prove RED**

Run:

```bash
npm run build
node --test --test-name-pattern='self-enrollment|authorization state|atomic' test/internal-auth-store.test.mjs
```

Expected: FAIL because the new table and methods do not exist.

- [ ] **Step 3: Implement store persistence and transactions**

Add `oauth_self_enrollments(id, state_hash UNIQUE, created_at, expires_at, consumed_at)` to `SCHEMA` and a TTL constant. Extend startup cleanup to remove expired rows.

`createSelfEnrollment` must allocate a random state with bounded collision retries and persist only `hashOpaque(state)`. `claimAuthorization` must use one immediate transaction to query both invitation and self-enrollment hashes, require exactly one match, and atomically set the winner's consumed timestamp. Replace the invitation-only callback claim method and update existing callers.

`completeSelfEnrollment` must verify the consumed, unexpired enrollment row; validate an eligible identity and canonical grant; generate UUID/bearer; encrypt with user/version associated data; insert the active user and grant in one transaction; and return plaintext only from the successful call. Catch only the Zendesk identity unique constraint as `already_registered`; sanitize all other failures.

- [ ] **Step 4: Run the focused store tests and prove GREEN**

Run:

```bash
npm run build
node --test --test-name-pattern='self-enrollment|authorization state|atomic' test/internal-auth-store.test.mjs
```

Expected: PASS.

- [ ] **Step 5: Run all store tests and commit**

```bash
node --test test/internal-auth-store.test.mjs
git add src/internal-auth/store.ts test/internal-auth-store.test.mjs test/oauth-linking.test.mjs test/admin.test.mjs scripts/smoke-http-local.mjs
git commit -m "feat: persist one-time self-enrollment states"
```

### Task 3: Browser enrollment and shared callback

**Files:**
- Modify: `src/internal-auth/link-handlers.ts`
- Test: `test/oauth-linking.test.mjs`

**Interfaces:**
- Changes `createLinkHandlers(options)` options to include `publicBaseUrl: URL` and `selfServiceEnabled: boolean`.
- Changes its return type to `{ link; createAccount; startEnrollment; callback }`, where each property is an Express `RequestHandler`.

- [ ] **Step 1: Write failing browser-flow tests**

Extend the OAuth linking fixture to mount:

```js
app.get('/create-account', handlers.createAccount)
app.post('/create-account', handlers.startEnrollment)
```

Prove:

- disabled handlers return `404` and allocate no state;
- GET is side-effect free and shows one local POST form;
- a POST with `Origin` unequal to `publicBaseUrl.origin` returns `403` with no OAuth call;
- a same-origin POST returns `302` only to `https://acme.zendesk.com/oauth/authorizations/new`;
- an eligible callback returns `user_id`, one `zmcp_` bearer, `/mcp`, and a Codex Authorization snippet;
- the returned bearer authenticates and callback replay fails;
- `end-user` and duplicate identities display no bearer and trigger exactly one best-effort revocation;
- exchange, identity, store, and revocation failures expose no state, code, token, client secret, or encryption key sentinel.

Assert every HTML response includes `no-store`, `no-referrer`, `nosniff`,
`DENY`, restrictive CSP, and Permissions Policy.

- [ ] **Step 2: Run the enrollment handler tests and prove RED**

Run:

```bash
npm run build
node --test --test-name-pattern='self-service|create-account|eligible|end-user|duplicate' test/oauth-linking.test.mjs
```

Expected: FAIL because the routes and enrollment callback branch do not exist.

- [ ] **Step 3: Implement the minimal browser flow**

Add static escaped HTML renderers and one shared browser-header function. Build all links and the displayed MCP URL from `publicBaseUrl`, never request headers. The POST must compare `request.get('origin')` with `publicBaseUrl.origin` before calling `store.createSelfEnrollment()`.

Update callback claim handling to dispatch the discriminated store result. Preserve the invitation branch exactly. In the self-enrollment branch, exchange the code, retrieve identity, require `isEligibleZendeskIdentity`, call `completeSelfEnrollment`, and render the bearer only for `kind: 'created'`. For ineligible, duplicate, or post-exchange failure, make one bounded `revokeCurrent` attempt and render a fixed safe page. Claim state before exchange and never retry a consumed callback.

Use HTML escaping for the canonical MCP URL and generated identifiers even though their formats are constrained. No external stylesheet, script, image, or font is allowed.

- [ ] **Step 4: Run the enrollment handler tests and prove GREEN**

Run:

```bash
npm run build
node --test --test-name-pattern='self-service|create-account|eligible|end-user|duplicate' test/oauth-linking.test.mjs
```

Expected: PASS.

- [ ] **Step 5: Run all OAuth linking tests and commit**

```bash
node --test test/oauth-linking.test.mjs
git add src/internal-auth/link-handlers.ts test/oauth-linking.test.mjs
git commit -m "feat: add browser self-service enrollment"
```

### Task 4: Configuration, route mounting, and runtime wiring

**Files:**
- Modify: `src/config.ts`
- Modify: `src/http-app.ts`
- Modify: `src/http-runtime.ts`
- Test: `test/config.test.mjs`
- Test: `test/http.test.mjs`
- Test: `test/http-runtime.test.mjs`
- Update fixture: `scripts/smoke-http-local.mjs`

**Interfaces:**
- Adds `selfServiceEnrollmentEnabled: boolean` to `HttpOAuthConfig`.
- Adds `selfServiceEnrollmentEnabled: boolean` and the two enrollment handlers to `HttpAppOptions`.

- [ ] **Step 1: Write failing config and mounting tests**

Assert absent `SELF_SERVICE_ENROLLMENT_ENABLED` parses as `false`, exact `true` parses as `true`, exact `false` parses as `false`, and values such as `1`, `yes`, `TRUE`, whitespace-only, or secret sentinels throw an error naming only the variable.

In HTTP tests, supply all four handlers and assert `/create-account` GET/POST are `404` when disabled and delegate when enabled. In runtime tests, assert canonical `publicBaseUrl` and the flag reach both handler and app factories.

- [ ] **Step 2: Run focused wiring tests and prove RED**

Run:

```bash
npm run build
node --test --test-name-pattern='self-service|create-account|runtime wires' test/config.test.mjs test/http.test.mjs test/http-runtime.test.mjs
```

Expected: FAIL because the config property and route contracts do not exist.

- [ ] **Step 3: Implement strict configuration and conditional routes**

Add a parser that accepts only undefined/`false`/`true` and returns false by default. Pass `publicBaseUrl` and the flag to `createLinkHandlers`; pass the flag and returned handlers to `createHttpApp`. Mount both `/create-account` methods only when true. Keep `/oauth/link` and `/oauth/callback` mounted regardless so administrator linking remains available.

- [ ] **Step 4: Run focused wiring tests and prove GREEN**

Run:

```bash
npm run build
node --test --test-name-pattern='self-service|create-account|runtime wires' test/config.test.mjs test/http.test.mjs test/http-runtime.test.mjs
```

Expected: PASS.

- [ ] **Step 5: Run the affected files and commit**

```bash
node --test test/config.test.mjs test/http.test.mjs test/http-runtime.test.mjs
git add src/config.ts src/http-app.ts src/http-runtime.ts test/config.test.mjs test/http.test.mjs test/http-runtime.test.mjs scripts/smoke-http-local.mjs
git commit -m "feat: wire optional self-service enrollment"
```

### Task 5: Fake-only end-to-end smoke and deployment documentation

**Files:**
- Modify: `scripts/smoke-http-local.mjs`
- Modify: `test/smoke-http.test.mjs`
- Modify: `.env.example`
- Modify: `README.md`
- Modify: `test/deployment.test.mjs`

**Interfaces:**
- The smoke script remains network-independent and emits one JSON object without secrets.
- Deployment enables self-service with `SELF_SERVICE_ENROLLMENT_ENABLED=true` only behind approved Tailscale HTTPS access.

- [ ] **Step 1: Write failing smoke/deployment assertions**

Update `test/smoke-http.test.mjs` to require the JSON fields:

```js
{
  enrollmentPage: true,
  oauthRedirect: true,
  enrollmentCompleted: true,
  replayRejected: true,
  initialized: true,
  toolsListed: true,
  zendeskRequests: 0,
}
```

Extend `test/deployment.test.mjs` to require the feature flag in `.env.example`, the `/create-account` workflow and Tailscale-only warning in README, and the existing one-OAuth-client/admin recovery commands.

- [ ] **Step 2: Run smoke and deployment tests and prove RED**

Run:

```bash
npm run build
node --test test/smoke-http.test.mjs test/deployment.test.mjs
```

Expected: FAIL because the script and docs do not cover browser enrollment.

- [ ] **Step 3: Extend the fake-only smoke and documentation**

Make the local script enable the routes, use a fake OAuth gateway, GET the page, POST with the exact local Origin, capture the upstream state, simulate callback exchange/current-user role, parse the one returned bearer from the success HTML, reject replay, and use the bearer for SDK initialization. Assert no real Zendesk fetch occurs and print only booleans/counts.

Document the exact production URL, explicit feature flag, agent/admin requirement, one-time bearer handoff, duplicate/recovery behavior, static Codex header example, Tailscale network prerequisite, and safe rollback by disabling the flag without affecting existing users.

- [ ] **Step 4: Run smoke and deployment tests and prove GREEN**

Run:

```bash
npm run build
node --test test/smoke-http.test.mjs test/deployment.test.mjs
```

Expected: PASS and no output contains fake bearer/grant fixtures.

- [ ] **Step 5: Commit operations support**

```bash
git add scripts/smoke-http-local.mjs test/smoke-http.test.mjs .env.example README.md test/deployment.test.mjs
git commit -m "docs: package self-service enrollment"
```

### Task 6: Full verification and publication

**Files:**
- Verify all modified files

**Interfaces:**
- Consumes the complete implementation.
- Produces a pushed branch with no uncommitted changes and fresh verification evidence.

- [ ] **Step 1: Run static and complete automated checks**

```bash
npm run check
npm test
npm audit --omit=dev
docker compose config
docker build --target runtime -t zendesk-mcp-self-service:verify .
```

Expected: every command exits `0`; audit reports zero production vulnerabilities.

- [ ] **Step 2: Run the local integrated smoke**

```bash
npm run smoke:http:local
```

Expected: one secret-free JSON object with every enrollment/MCP boolean true and `zendeskRequests: 0`.

- [ ] **Step 3: Scan for placeholders, leaked sentinel values, and diff errors**

```bash
rg -n -i 'TODO|TBD|commented-out experiment' src test scripts README.md .env.example docs/superpowers/specs/2026-07-27-zendesk-self-service-enrollment-design.md docs/superpowers/plans/2026-07-27-zendesk-self-service-enrollment.md
git diff --check
git status --short --branch
```

Expected: no implementation placeholders, no whitespace errors, and only intentional plan checkbox edits if tracked.

- [ ] **Step 4: Commit any verification-only corrections**

If verification required a scoped correction, repeat its failing command, apply only that correction, rerun the same command, then commit the exact files with a descriptive message. Otherwise create no empty commit.

- [ ] **Step 5: Push the dedicated branch**

```bash
git push origin codex/zendesk-internal-user-bearers
```

Expected: the remote branch advances to the verified local HEAD. Do not create a new pull request because the branch already has PR #5.
