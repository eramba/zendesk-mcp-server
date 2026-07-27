# Zendesk Support Capabilities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the authenticated Zendesk MCP server from 13 to 24 typed support tools, enrich ticket and directory context, protect ticket writes with optimistic concurrency, and support bounded inline comment attachments.

**Architecture:** Extend the existing request-scoped `ZendeskClient` and its one OAuth-aware transport. Keep curated public types in `src/types.ts`, split MCP registrations into focused tool modules, and make all new list endpoints cursor-based while preserving existing offset contracts.

**Tech Stack:** TypeScript 5.9, Node.js 22, MCP SDK 1.26, Zod 4, Node test runner, Docker Compose.

## Global Constraints

- Work on `codex/zendesk-support-capabilities`, based on merged `master` at `4f08385`.
- Keep OAuth scopes exactly `read tickets:write`; no reauthorization or new OAuth client.
- Preserve request-scoped bearer-to-Zendesk-user isolation and existing refresh behavior.
- Use explicit typed tools; do not add a generic Zendesk request proxy.
- New list tools use `page_size`, optional `after`, `has_more`, and `next_cursor`.
- `update_ticket` and `create_ticket_comment` require `expected_updated_at` and use Zendesk safe updates.
- Inline comment attachments allow at most 3 files and 5 MiB decoded aggregate per call.
- Never expose or log OAuth tokens, Zendesk upload tokens, base64 content, upstream bodies, or transport messages.
- Do not reset or replace the existing Docker database.
- Do not perform automated live Zendesk mutations.

---

## File Structure

- `src/types.ts`: curated public entity, pagination, ticket-write, and attachment types.
- `src/zendesk-client.ts`: upstream payload normalization, shared OAuth-aware transport, endpoint methods, safe writes, and attachment upload lifecycle.
- `src/tools/shared.ts`: shared Zod schemas plus JSON and fixed-error MCP rendering.
- `src/tools/tickets.ts`: ticket get/list/search/audit/comment/create/update registrations.
- `src/tools/directory.ts`: generic search, current user, user, organization, and history registrations.
- `src/tools/workflows.ts`: view and assignable-group registrations.
- `src/tools/metadata.ts`: ticket fields, metrics, forms, and custom-status registrations.
- `src/tools/index.ts`: one `registerZendeskTools(server, client)` composition entrypoint.
- `src/server.ts`: MCP metadata, prompts, tool composition call, and knowledge-base resource.
- `test/zendesk-rich-tickets.test.mjs`: rich entity normalization and ticket writes.
- `test/zendesk-workflows.test.mjs`: views, groups, memberships, and cursor behavior.
- `test/zendesk-directory.test.mjs`: exact user/organization records and ticket histories.
- `test/zendesk-metadata.test.mjs`: metrics, forms, and custom statuses.
- `test/zendesk-attachments.test.mjs`: attachment validation, upload chaining, cleanup, and secret safety.
- `test/server-tool-surface.test.mjs`: exact MCP tool discovery and stable prompts/resources.
- `README.md`: 24-tool public surface and attachment limits.

---

### Task 1: Rich ticket and directory representations

**Files:**
- Modify: `src/types.ts`
- Modify: `src/zendesk-client.ts`
- Create: `test/zendesk-rich-tickets.test.mjs`

**Interfaces:**
- Produces: expanded `ZendeskTicket`, `ZendeskUser`, and `ZendeskOrganization`.
- Produces: normalized tickets from every existing ticket-returning client method.
- Consumes: the existing `ZendeskClient.request<T>()` path unchanged.

- [ ] **Step 1: Write failing normalization tests**

Create fixtures containing every approved ticket, user, and organization field. Assert that `getTicket()`, `getCurrentUser()`, and organization search retain known fields, normalize absent arrays to `[]`, absent scalar values to `null`, and omit an `upstream_secret` fixture property.

```js
assert.deepEqual(ticket.custom_fields, [{ id: 9001, value: ['gold', 'priority'] }])
assert.equal(ticket.group_id, 73)
assert.equal(ticket.via.channel, 'email')
assert.equal('upstream_secret' in ticket, false)
assert.deepEqual(user.user_fields, { support_tier: 'enterprise' })
assert.deepEqual(organization.domain_names, ['example.test'])
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `npm run build && node --test test/zendesk-rich-tickets.test.mjs`

Expected: FAIL because the approved fields are absent from normalized results.

- [ ] **Step 3: Expand public and upstream payload types**

Add exact nullable/array properties from the design. Use these core shapes:

```ts
export type ZendeskCustomFieldValue = { id: number; value: unknown };
export type ZendeskVia = { channel: string | null };
export type ZendeskSatisfactionRating = {
  id: number | null;
  score: string | null;
  comment: string | null;
};
```

Expand `TicketPayload`, `UserPayload`, and `OrganizationPayload`, then update `normalizeTicket`, `normalizeUser`, and `normalizeOrganization`. Do not copy unknown keys.

- [ ] **Step 4: Run focused and existing normalization tests**

Run: `npm run build && node --test test/zendesk-rich-tickets.test.mjs test/current-user.test.mjs test/zendesk-comments-attachments.test.mjs`

Expected: PASS.

- [ ] **Step 5: Commit the rich read contract**

```bash
git add src/types.ts src/zendesk-client.ts test/zendesk-rich-tickets.test.mjs
git commit -m "feat: enrich Zendesk support records"
```

### Task 2: Safe and complete ticket writes

**Files:**
- Modify: `src/types.ts`
- Modify: `src/zendesk-client.ts`
- Modify: `src/server.ts`
- Modify: `src/internal-auth/errors.ts`
- Modify: `test/zendesk-rich-tickets.test.mjs`

**Interfaces:**
- Produces: `ZendeskTicketWriteFields`, `ZendeskFollowerChange`, and `ZendeskEmailCcChange`.
- Produces: `updateTicket(ticketId, fields, expectedUpdatedAt)`.
- Produces: comment input requiring `expected_updated_at`; attachments are added in Task 7.

- [ ] **Step 1: Add failing direct-client and MCP schema tests**

Assert an update body with the approved fields and concurrency envelope:

```js
assert.deepEqual(JSON.parse(request.body).ticket, {
  group_id: 73,
  custom_status_id: 88,
  collaborator_ids: [10, 11],
  followers: [{ user_id: 12, action: 'put' }],
  email_ccs: [{ user_email: 'cc@example.test', action: 'put' }],
  safe_update: true,
  updated_stamp: '2026-07-27T10:00:00Z',
})
```

Also assert that MCP rejects missing `expected_updated_at`, and that an upstream 409 becomes category `conflict` without exposing the response body.

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `npm run build && node --test test/zendesk-rich-tickets.test.mjs`

Expected: FAIL because the write fields, required timestamp, and conflict category do not exist.

- [ ] **Step 3: Implement typed write inputs and safe updates**

Add discriminated Zod items requiring exactly one identifier:

```ts
const followerChangeSchema = z.union([
  z.object({ user_id: z.number().int().positive(), action: actionSchema.default("put") }),
  z.object({ user_email: z.string().email(), action: actionSchema.default("put") }),
]);
```

Create the parallel email-CC schema with optional `user_name`. Add the remaining approved create/update fields. Strip `expected_updated_at` from public fields and send it only as:

```ts
ticket: { ...fields, safe_update: true, updated_stamp: expectedUpdatedAt }
```

Add `conflict` to the safe category union and classify HTTP 409 without parsing or surfacing its body.

- [ ] **Step 4: Make comment writes safe before attachments**

Change the client signature to an object:

```ts
createTicketComment(input: {
  ticketId: number;
  comment: string;
  public: boolean;
  expectedUpdatedAt: string;
}): Promise<ZendeskTicket>
```

Return the normalized updated ticket rather than echoing comment text.

- [ ] **Step 5: Run focused tests**

Run: `npm run build && node --test test/zendesk-rich-tickets.test.mjs test/zendesk-client-auth.test.mjs`

Expected: PASS.

- [ ] **Step 6: Commit safe writes**

```bash
git add src/types.ts src/zendesk-client.ts src/server.ts src/internal-auth/errors.ts test/zendesk-rich-tickets.test.mjs
git commit -m "feat: protect Zendesk ticket writes"
```

### Task 3: Modularize MCP tool registration without behavior changes

**Files:**
- Create: `src/tools/shared.ts`
- Create: `src/tools/tickets.ts`
- Create: `src/tools/directory.ts`
- Create: `src/tools/workflows.ts`
- Create: `src/tools/metadata.ts`
- Create: `src/tools/index.ts`
- Modify: `src/server.ts`
- Create: `test/server-tool-surface.test.mjs`

**Interfaces:**
- Produces: `registerZendeskTools(server: McpServer, client: ZendeskClient): void`.
- Produces: focused registration functions called only by `src/tools/index.ts`.
- Preserves: all 13 current tool names and schemas after Tasks 1-2 changes.

- [ ] **Step 1: Add a characterization test**

Connect through `InMemoryTransport`, list tools, and assert the sorted exact 13-name baseline:

```js
assert.deepEqual(names.sort(), [
  'create_ticket', 'create_ticket_comment', 'get_current_user', 'get_ticket',
  'get_ticket_audits', 'get_ticket_comments', 'get_tickets', 'list_ticket_fields',
  'search', 'search_organizations', 'search_tickets', 'search_users', 'update_ticket',
])
```

Also assert two prompt names and the `zendesk://knowledge-base` resource.

- [ ] **Step 2: Run the characterization test GREEN before refactor**

Run: `npm run build && node --test test/server-tool-surface.test.mjs`

Expected: PASS.

- [ ] **Step 3: Move registrations into focused modules**

Move only tool registration code and its Zod schemas. Keep prompts and the knowledge-base resource in `server.ts`. `src/tools/shared.ts` exports:

```ts
export const cursorInputSchema = {
  page_size: z.number().int().min(1).max(100).default(25),
  after: z.string().min(1).max(2048).optional(),
};
export function jsonText(value: unknown): CallToolResult;
export function toolError(error: unknown): CallToolResult;
```

`buildZendeskServer` calls `registerZendeskTools(server, client)` once.

- [ ] **Step 4: Run characterization and full existing server tests**

Run: `npm run build && node --test test/server-tool-surface.test.mjs test/http.test.mjs test/server-instructions.test.mjs test/current-user.test.mjs`

Expected: PASS with the same 13 tools.

- [ ] **Step 5: Commit the structural refactor**

```bash
git add src/server.ts src/tools test/server-tool-surface.test.mjs
git commit -m "refactor: split Zendesk tool registrations"
```

### Task 4: Views and assignable groups

**Files:**
- Modify: `src/types.ts`
- Modify: `src/zendesk-client.ts`
- Modify: `src/tools/workflows.ts`
- Create: `test/zendesk-workflows.test.mjs`
- Modify: `test/server-tool-surface.test.mjs`

**Interfaces:**
- Produces: `CursorInput`, `CursorPage<T>`, `ZendeskView`, `ZendeskGroup`, and `ZendeskGroupMembership`.
- Produces: `listViews`, `listViewTickets`, `listAssignableGroups`, and `listGroupMembers`.

- [ ] **Step 1: Write failing endpoint and MCP tests**

Cover these exact paths and query values:

```text
/views.json?active=true&page[size]=25
/views/44/tickets.json?page[size]=25&page[after]=view-cursor
/groups/assignable.json?page[size]=25
/groups/73/memberships.json?include=users&page[size]=25
```

Fixtures must include `links.next` with a cursor and `meta.has_more`. Assert that the output contains only `next_cursor`, not the upstream URL. Assert off-origin next links fail closed.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `npm run build && node --test test/zendesk-workflows.test.mjs`

Expected: FAIL because types, methods, and tools do not exist.

- [ ] **Step 3: Implement shared cursor helpers and workflow methods**

Use:

```ts
export type CursorInput = { pageSize: number; after?: string };
export type CursorPage<T> = {
  items: T[];
  page_size: number;
  has_more: boolean;
  next_cursor: string | null;
};
```

Build query parameters with `URLSearchParams`. Extract `page[after]` only after validating the next URL through the existing same-origin `nextPath` boundary.

- [ ] **Step 4: Register the four MCP tools**

Map `items` to `views`, `tickets`, `groups`, or `memberships` in public JSON. `list_group_members` includes normalized sideloaded `users` so the caller can resolve membership ids without another search.

- [ ] **Step 5: Run workflow and tool-surface tests**

Run: `npm run build && node --test test/zendesk-workflows.test.mjs test/server-tool-surface.test.mjs`

Expected: PASS with 17 tools.

- [ ] **Step 6: Commit workflow tools**

```bash
git add src/types.ts src/zendesk-client.ts src/tools/workflows.ts test/zendesk-workflows.test.mjs test/server-tool-surface.test.mjs
git commit -m "feat: add Zendesk queue and assignment tools"
```

### Task 5: Exact directory records and ticket history

**Files:**
- Modify: `src/zendesk-client.ts`
- Modify: `src/tools/directory.ts`
- Create: `test/zendesk-directory.test.mjs`
- Modify: `test/server-tool-surface.test.mjs`

**Interfaces:**
- Produces: `getUser`, `getOrganization`, `listUserTickets`, and `listOrganizationTickets`.
- Consumes: rich normalized user, organization, ticket, and cursor types from Tasks 1 and 4.

- [ ] **Step 1: Write failing exact-path and relationship tests**

Assert:

```text
/users/101.json
/organizations/202.json
/users/101/tickets/requested.json?page[size]=25
/users/101/tickets/assigned.json?page[size]=25
/users/101/tickets/ccd.json?page[size]=25
/users/101/tickets/followed.json?page[size]=25
/organizations/202/tickets.json?page[size]=25
```

Verify default MCP relationship `requested`, enum validation, normalized rich entities, and cursor output.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `npm run build && node --test test/zendesk-directory.test.mjs`

Expected: FAIL because directory methods and tools do not exist.

- [ ] **Step 3: Implement methods and four tools**

Validate numeric ids in Zod before the client call. Encode only the fixed relationship enum into the path; never interpolate arbitrary path input.

- [ ] **Step 4: Run directory and tool-surface tests**

Run: `npm run build && node --test test/zendesk-directory.test.mjs test/server-tool-surface.test.mjs`

Expected: PASS with 21 tools.

- [ ] **Step 5: Commit directory tools**

```bash
git add src/zendesk-client.ts src/tools/directory.ts test/zendesk-directory.test.mjs test/server-tool-surface.test.mjs
git commit -m "feat: add Zendesk customer context tools"
```

### Task 6: Metrics, forms, and custom statuses

**Files:**
- Modify: `src/types.ts`
- Modify: `src/zendesk-client.ts`
- Modify: `src/tools/metadata.ts`
- Create: `test/zendesk-metadata.test.mjs`
- Modify: `test/server-tool-surface.test.mjs`

**Interfaces:**
- Produces: `ZendeskTicketMetrics`, `ZendeskTicketForm`, and `ZendeskCustomStatus`.
- Produces: `getTicketMetrics`, `listTicketForms`, and `listCustomStatuses`.

- [ ] **Step 1: Write failing normalization and MCP tests**

Use representative metric durations with `calendar` and `business`, form field ids and conditions, and custom-status agent/end-user labels. Assert exact paths:

```text
/tickets/36870/metrics.json
/ticket_forms.json?active=true&page[size]=25
/custom_statuses.json?active=true
```

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `npm run build && node --test test/zendesk-metadata.test.mjs`

Expected: FAIL because metadata types, methods, and tools do not exist.

- [ ] **Step 3: Implement curated metadata types and normalizers**

Metrics include assignment/status timestamps, replies, reopens, and calendar/business duration objects. Forms include ids, active/default flags, names, and ordered `ticket_field_ids`. Custom statuses include ids, active/default flags, labels, descriptions, and `status_category`.

- [ ] **Step 4: Implement and register the three tools**

`list_ticket_forms` uses cursor pagination. `list_custom_statuses` returns the unpaginated active collection and count.

- [ ] **Step 5: Run metadata and tool-surface tests**

Run: `npm run build && node --test test/zendesk-metadata.test.mjs test/server-tool-surface.test.mjs`

Expected: PASS with 24 tools.

- [ ] **Step 6: Commit metadata tools**

```bash
git add src/types.ts src/zendesk-client.ts src/tools/metadata.ts test/zendesk-metadata.test.mjs test/server-tool-surface.test.mjs
git commit -m "feat: add Zendesk workflow metadata tools"
```

### Task 7: Bounded inline ticket attachments

**Files:**
- Modify: `src/types.ts`
- Modify: `src/zendesk-client.ts`
- Modify: `src/tools/shared.ts`
- Modify: `src/tools/tickets.ts`
- Create: `test/zendesk-attachments.test.mjs`

**Interfaces:**
- Produces: `ZendeskInlineAttachmentInput`.
- Extends: `createTicketComment` with an optional attachment array.
- Preserves: one common OAuth-aware request transport and sanitized failure behavior.

- [ ] **Step 1: Write failing local-validation tests**

Cover empty filename, path separators, control characters, invalid MIME, malformed or noncanonical base64, more than 3 files, and decoded aggregate over 5 MiB. For every invalid case assert zero fetch calls.

- [ ] **Step 2: Write failing upload lifecycle tests**

For two files assert:

1. first `POST /uploads.json?filename=first.png` uses binary body and image MIME,
2. second upload includes the first returned token and uses the second filename,
3. final ticket `PUT` has `comment.uploads: [token]`, `safe_update: true`, and the expected stamp,
4. no result or error contains the token or base64 fixture.

Also assert one best-effort `DELETE /uploads/{token}.json` after a later upload or comment failure, while the original sanitized category is retained.

- [ ] **Step 3: Run focused tests and confirm RED**

Run: `npm run build && node --test test/zendesk-attachments.test.mjs`

Expected: FAIL because attachment schema and binary upload transport do not exist.

- [ ] **Step 4: Refactor the request path at the shared response boundary**

Keep authorization, refresh, timeout, cancellation, redirects, and classification in one function returning a successful `Response`. Build JSON and upload parsers above it. For binary uploads, preserve the caller-provided MIME `Content-Type`; do not overwrite it with JSON.

- [ ] **Step 5: Implement canonical validation and upload chaining**

Decode only after validating canonical base64. Enforce decoded aggregate with `Buffer.byteLength`. Upload sequentially, pass the active token to subsequent upload requests, and return the token only inside the client method's local scope.

- [ ] **Step 6: Attach and clean up**

Send the final token in `ticket.comment.uploads`. On subsequent failure, perform one bounded best-effort delete using the same authenticated transport and then rethrow the original error. Successful comments return only the normalized updated ticket.

- [ ] **Step 7: Run attachment, auth, and comment tests**

Run: `npm run build && node --test test/zendesk-attachments.test.mjs test/zendesk-client-auth.test.mjs test/zendesk-comments-attachments.test.mjs test/zendesk-rich-tickets.test.mjs`

Expected: PASS.

- [ ] **Step 8: Commit attachments**

```bash
git add src/types.ts src/zendesk-client.ts src/tools/shared.ts src/tools/tickets.ts test/zendesk-attachments.test.mjs
git commit -m "feat: attach bounded files to Zendesk comments"
```

### Task 8: Documentation and integrated verification

**Files:**
- Modify: `README.md`
- Modify: `test/server-tool-surface.test.mjs`
- Modify: `test/http.test.mjs` only if the exact public surface assertion belongs there
- Modify: `scripts/smoke-http-local.mjs` only if its assertions require the exact count

**Interfaces:**
- Produces: documented 24-tool surface, strict-write guidance, pagination contract, and attachment limits.

- [ ] **Step 1: Update README**

List all 24 tools. Document `expected_updated_at`, conflict retry behavior, cursor pagination, three-file/5-MiB limits, and that no upload token is exposed.

- [ ] **Step 2: Run formatting and static checks**

Run: `git diff --check`

Run: `npm run check`

Expected: both exit 0.

- [ ] **Step 3: Run the complete test suite**

Run: `npm test`

Expected: all tests pass with zero failures.

- [ ] **Step 4: Run dependency and HTTP verification**

Run: `npm audit --audit-level=high`

Run: `npm run smoke:http:local`

Expected: zero high-or-greater vulnerabilities and smoke JSON with `ok:true`, authentication rejection, completed enrollment, MCP initialization, tool listing, and zero Zendesk requests.

- [ ] **Step 5: Review the final diff and commit docs**

Run: `git status --short --branch`

Run: `git diff --check`

Run: `git diff master...HEAD --stat`

```bash
git add README.md test/server-tool-surface.test.mjs test/http.test.mjs scripts/smoke-http-local.mjs
git commit -m "docs: describe Zendesk support capabilities"
```

Stage only files that actually changed; omit unchanged paths from `git add`.

- [ ] **Step 6: Rebuild local Docker without resetting data**

Run: `docker compose up -d --build --force-recreate --wait`

Run: `docker compose ps`

Run: `curl --fail --silent --show-error http://127.0.0.1:38184/healthz`

Expected: the service is healthy on `127.0.0.1:38184` and health returns `{"ok":true}`.

- [ ] **Step 7: Push and create a new PR**

Push `codex/zendesk-support-capabilities`, create a ready PR against `master`, and include the exact verification evidence. Do not alter or delete the persisted Docker database.
