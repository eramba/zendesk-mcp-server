# Internal User Bearers Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the administration workflow usable from the production Compose deployment and prevent one disconnected request from cancelling another request's shared OAuth refresh.

**Architecture:** Keep the compiled administration CLI as the sole store-management entrypoint and invoke it inside the Compose service so it shares `/data`. Keep one resolver-owned refresh promise per user/version; request cancellation stops only that caller's wait, while the OAuth gateway's existing timeout and shutdown signal bound the shared upstream operation.

**Tech Stack:** Node.js 20+, TypeScript 5.9, Node test runner, Docker Compose, `better-sqlite3`.

## Global Constraints

- Keep the current checkout on `codex/zendesk-internal-user-bearers`; do not create a worktree.
- Preserve the existing SQLite schema, bearer values, grants, and stdio behavior.
- Add no dependency, background worker, distributed coordination, or web admin UI.
- Use a failing regression test before each production change.
- Keep secrets and identity values out of errors and logs.

---

### Task 1: Make the compiled admin CLI usable in Compose

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `test/deployment.test.mjs`

**Interfaces:**
- Consumes: compiled `dist/admin.js` and the Compose service's existing environment and `/data` volume.
- Produces: `npm run admin -- <command>` that runs without TypeScript development dependencies, plus Compose-specific create/list/reauthorize/revoke and backup commands.

- [ ] **Step 1: Write the failing runtime-image regression test**

Extend the deployment test to build the runtime image and execute `npm run admin -- list` with valid non-secret configuration. Assert that the process reaches the administration CLI instead of failing with `tsc: not found`.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm run build && node --test --test-name-pattern="production image runs the compiled admin CLI" test/deployment.test.mjs`

Expected: FAIL because the production image omits `tsc` but the `admin` script invokes `npm run build`.

- [ ] **Step 3: Apply the minimal runtime and documentation change**

Set the package script to `node dist/admin.js`. Document `docker compose exec zendesk-mcp npm run admin -- ...` for live administration. Document backup through `docker compose run --rm --no-deps` with a host bind mount at `/backup`, so the online backup leaves the named database volume and lands in an operator-controlled directory.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run: `npm run build && node --test --test-name-pattern="production image runs the compiled admin CLI" test/deployment.test.mjs`

Expected: PASS and no `tsc: not found` output.

---

### Task 2: Isolate request cancellation from single-flight refresh

**Files:**
- Modify: `src/internal-auth/client-resolver.ts`
- Modify: `test/user-client-resolver.test.mjs`

**Interfaces:**
- Consumes: `resolve(userId, signal?)`, the resolver shutdown signal, and `PendingRefresh.pending`.
- Produces: one shared refresh per user/version that survives an individual caller abort, while each caller can fail promptly with safe category `aborted`.

- [ ] **Step 1: Write the failing concurrent cancellation test**

Start two resolves for the same expiring credential, passing an abort signal only to the first. Abort the first after the single refresh starts, verify the first rejects with safe category `aborted`, release the fake OAuth refresh, and assert the second resolves with the rotated access token, the grant is persisted at version 2, and refresh was called once.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm run build && node --test --test-name-pattern="caller abort does not cancel a shared refresh" test/user-client-resolver.test.mjs`

Expected: FAIL because the first caller's signal currently owns and cancels the shared refresh operation.

- [ ] **Step 3: Apply the minimal resolver change**

Create shared refresh work with the resolver shutdown signal only. Add a private wait helper that rejects one caller with `SafeAuthError("aborted", { retryable: true })` when its combined request/shutdown signal aborts, removes its listener after settlement, and never aborts or suppresses the shared promise.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run: `npm run build && node --test --test-name-pattern="caller abort does not cancel a shared refresh" test/user-client-resolver.test.mjs`

Expected: PASS with one refresh, one aborted caller, one successful caller, and stored version 2.

---

### Task 3: Integrated verification and publication

**Files:**
- Verify all modified files above.

**Interfaces:**
- Consumes: the two independently green fixes.
- Produces: a clean, verified update to the existing pull-request branch.

- [ ] **Step 1: Run the complete repository gate**

Run: `npm run check && npm test && npm run smoke:http:local && git diff --check`

Expected: TypeScript exits 0, all tests pass, smoke returns `"ok":true`, and diff check is empty.

- [ ] **Step 2: Verify deployment artifacts**

Run: `MCP_ENV_FILE=.env.example docker compose config --quiet && docker build -t zendesk-mcp-server:review-fixes .`

Expected: Compose validation and Docker build both exit 0.

- [ ] **Step 3: Review and publish the scoped change**

Inspect `git diff --stat`, `git diff`, and `git status`. Commit only the two fixes, their regression tests, documentation, and this plan; then push `codex/zendesk-internal-user-bearers` to update the existing pull request.
