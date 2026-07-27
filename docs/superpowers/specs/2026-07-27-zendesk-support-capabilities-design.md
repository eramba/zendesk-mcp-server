# Zendesk Support Capabilities Design

**Date:** 2026-07-27  
**Branch:** `codex/zendesk-support-capabilities`  
**Base:** merged `master` at `4f08385`

## Context

The server currently exposes 13 MCP tools around tickets, search, comments,
ticket fields, audits, and the current authenticated user. Every Streamable
HTTP request is already resolved to a user-specific `ZendeskClient`, so new
support capabilities must extend that client rather than introduce another
authentication or request path.

The current ticket model is too narrow for day-to-day support work. It omits
assignment, form, custom-status, custom-field, collaborator, follower, and
workflow context that Zendesk already returns. The server also cannot expose
the authenticated agent's queues, resolve exact requester or organization
records, inspect ticket history by requester or organization, inspect ticket
metrics, or attach a local file to a new comment.

## Goals

1. Expand the existing ticket read and write contract for normal support work.
2. Add typed tools for views, assignment groups, exact user and organization
   context, requester and organization ticket history, metrics, forms, and
   custom statuses.
3. Add bounded inline attachments to `create_ticket_comment` without exposing
   Zendesk upload tokens or adding an upload database.
4. Protect ticket updates and comments with Zendesk optimistic concurrency.
5. Preserve the current request-scoped user isolation, OAuth refresh behavior,
   sanitized failures, stdio compatibility, and `read tickets:write` scopes.

## Non-goals

- User or organization mutations
- Macros
- Ticket deletion, merging, spam marking, comment redaction, or other
  destructive operations
- A generic Zendesk API proxy tool
- Large-file or resumable uploads
- New OAuth scopes, clients, enrollment steps, or database schema
- Live Zendesk write tests in the automated suite

## Approved Public MCP Contract

### Expanded ticket representation

All tools that return tickets use one curated `ZendeskTicket` type. In addition
to the existing fields, it includes these optional or nullable properties:

- `submitter_id`
- `group_id`
- `brand_id`
- `ticket_form_id`
- `custom_status_id`
- `custom_fields: Array<{ id: number; value: unknown }>`
- `collaborator_ids`
- `email_cc_ids`
- `follower_ids`
- `problem_id`
- `due_at`
- `external_id`
- `recipient`
- `has_incidents`
- `allow_attachments`
- `satisfaction_rating` with `id`, `score`, and `comment`
- `via` with at least the normalized `channel`

Unknown upstream fields remain excluded. Missing known properties normalize to
`null`, `false`, or an empty array according to their semantic type.

### Expanded directory representations

`ZendeskUser` keeps its current fields and adds support-relevant context:
`alias`, `phone`, `verified`, `role_type`, `custom_role_id`,
`default_group_id`, `locale`, `locale_id`, `time_zone`, `external_id`, `tags`,
`user_fields`, and `last_login_at`.

`ZendeskOrganization` keeps its current fields and adds `domain_names`,
`external_id`, `group_id`, `organization_fields`, `shared_comments`, and
`tags`. Unknown user and organization properties remain excluded.

### Expanded ticket writes

`create_ticket` accepts the existing fields plus the applicable writable
properties:

- `organization_id`
- `group_id`
- `brand_id`
- `ticket_form_id`
- `custom_status_id`
- `problem_id`
- `due_at`
- `collaborator_ids`
- `additional_collaborators`, where each value is a user id, email, or a
  `{ name, email }` object
- `followers`, where every item has exactly one of `user_id` or `user_email`
  and an optional `action` of `put` or `delete`
- `email_ccs`, with the same identifiers, optional `user_name`, and optional
  `put` or `delete` action

`update_ticket` accepts the same applicable writable properties. It requires
`expected_updated_at`, maps it to Zendesk `updated_stamp`, and always sends
`safe_update: true`. A Zendesk 409 is returned to MCP as a fixed conflict error
that tells the caller to fetch the ticket again; it is never silently retried.

`create_ticket_comment` also requires `expected_updated_at` and uses the same
safe-update behavior. This intentionally requires a fresh ticket read before a
public reply or internal note.

### Inline comment attachments

`create_ticket_comment` accepts an optional `attachments` array with at most
three items:

```text
{
  filename: string,
  content_type: string,
  content_base64: string
}
```

The decoded aggregate is limited to 5 MiB per tool call. Filenames must be
single basenames without control characters, path separators, or empty values.
Content types must be syntactically valid MIME types. Base64 must be canonical
and valid before any upstream request.

The server uploads files sequentially to one Zendesk upload session, posts the
comment with the resulting token, and best-effort deletes the upload if any
later upload or the ticket update fails. No file is written to local disk, and
no base64 data or Zendesk upload token is returned or logged.

### New tools

The public surface grows from 13 to 24 tools:

1. `list_views`
   - Lists active views visible to the authenticated agent.
2. `list_view_tickets`
   - Lists full normalized tickets in one visible view.
3. `list_assignable_groups`
   - Lists groups to which the authenticated agent can assign tickets.
4. `list_group_members`
   - Lists memberships and normalized users for one group.
5. `get_user`
   - Retrieves one exact user by numeric id.
6. `get_organization`
   - Retrieves one exact organization by numeric id.
7. `list_user_tickets`
   - Lists tickets related to one user. `relationship` is one of `requested`,
     `assigned`, `ccd`, or `followed` and defaults to `requested`.
8. `list_organization_tickets`
   - Lists tickets belonging to one organization.
9. `get_ticket_metrics`
   - Retrieves metrics for one ticket.
10. `list_ticket_forms`
    - Lists active ticket forms visible to the authenticated user.
11. `list_custom_statuses`
    - Lists active custom ticket statuses.

`search_users` and `search_organizations` remain unchanged. Exact lookup and
history tools complement rather than replace them.

### Pagination

New list tools use cursor pagination:

- input: `page_size` from 1 through 100, default 25; optional opaque `after`
- output: entity collection, `has_more`, and `next_cursor`

The client reads Zendesk `meta.has_more` and `links.next`, extracts only the
same-origin `page[after]` value, and never returns or follows an arbitrary URL.
Endpoints that return an unpaginated collection, such as custom statuses, omit
cursor fields. Existing offset-based tools retain their current contract.

## Architecture

### Existing lifecycle

```text
MCP bearer
  -> UserClientResolver
  -> request-scoped ZendeskClient with that user's OAuth grant
  -> buildZendeskServer(client)
  -> typed tool handler
  -> Zendesk Support API
  -> normalized MCP response
```

Every new capability stays inside this lifecycle.

### Client transport

`ZendeskClient` remains the single public client. Its current request function
already owns authorization, token refresh, retry-once behavior, timeout,
cancellation, redirect rejection, status classification, and sanitized errors.

That function is refactored at its earliest extension point into a common
response transport with two focused parsers:

- JSON request/response for all existing and new resource methods
- binary request with JSON response for Zendesk uploads

Both parsers share the exact same origin, authorization, refresh, timeout,
redirect, and error path. Upload handling must not create a parallel `fetch`
implementation.

### Tool registration modules

`buildZendeskServer` continues to create the MCP server, prompts, and resource,
but delegates tool registration to focused modules:

- ticket tools
- directory tools for users and organizations
- workflow tools for views and groups
- metadata tools for metrics, forms, and custom statuses

Shared response rendering, error rendering, pagination schemas, and reusable
ticket-write schemas live in one internal tools module. The split is limited to
the surface touched by this work; unrelated prompts and the knowledge-base
resource are not redesigned.

### Endpoint mapping

- views: `GET /api/v2/views`, `GET /api/v2/views/{id}/tickets`
- groups: `GET /api/v2/groups/assignable`,
  `GET /api/v2/groups/{id}/memberships?include=users`
- users: `GET /api/v2/users/{id}` and the requested, assigned, ccd, or followed
  user-ticket endpoints
- organizations: `GET /api/v2/organizations/{id}` and
  `GET /api/v2/organizations/{id}/tickets`
- metrics: `GET /api/v2/tickets/{id}/metrics`
- forms: `GET /api/v2/ticket_forms`
- statuses: `GET /api/v2/custom_statuses`
- uploads: `POST /api/v2/uploads?filename=...`, with the returned token passed
  to subsequent upload requests and the final ticket comment

`.json` suffixes may be used consistently with the existing client.

## Error Handling and Safety

- Keep the existing fixed, secret-free upstream error categories.
- Add a specific 409 conflict category and fixed caller guidance.
- Reject malformed attachment input before any Zendesk request.
- Enforce attachment count and decoded aggregate size before upload.
- Do not include response bodies, request URLs, OAuth credentials, upload
  tokens, base64 content, or transport exception messages in surfaced errors.
- Keep timeout and outer cancellation active through multi-file upload and the
  final ticket update.
- On partial attachment failure, best-effort delete the upload once and retain
  the original sanitized failure.
- Do not automatically retry a ticket write after a conflict.
- Preserve all per-user isolation and refresh semantics already covered by the
  HTTP resolver tests.

## Testing Strategy

Implementation uses sequential focused RED -> GREEN TDD because the slices
share types, client transport, tool schemas, and server registration.

Focused tests cover:

1. Rich ticket normalization across get, list, search, create, and update.
2. Exact safe-update request bodies and 409 conflict behavior.
3. Each new endpoint path, authorization, cursor input, cursor output, and
   normalized response.
4. MCP discovery and tool-call output for every new tool family.
5. Attachment validation with zero upstream calls on invalid input.
6. Multi-file upload ordering, token chaining, comment attachment, total-size
   limits, cleanup, cancellation, refresh, and secret-free failures.
7. Two bearer-selected users continue to receive isolated clients.
8. The public tool count becomes 24 while prompts and resources remain stable.

Final verification requires:

- focused tests for every slice
- `npm run check`
- `npm test`
- `npm audit --audit-level=high`
- `npm run smoke:http:local`
- Docker rebuild with health verification, without resetting the user database
- final diff and worktree review

No automated test performs a live Zendesk mutation. A live authenticated read
smoke is optional only if the already configured local bearer can be used
without exposing it.

## Execution and Delivery

Use inline single-agent, sequential TDD on
`codex/zendesk-support-capabilities`. The shared client and public types make
parallel implementation more conflict-prone than useful. Keep commits atomic
by capability boundary, push the completed branch, and create a new PR against
`master` after integrated verification.

The existing local Docker database and enrolled users are preserved throughout
the work.
