# Zendesk Comment Attachments Design

**Date:** 2026-07-15
**Status:** Design approved; awaiting written spec review

## Problem

Zendesk returns ticket attachments inside each comment's `attachments` array, but `ZendeskClient.getTicketComments()` currently normalizes only comment text and metadata. The MCP `get_ticket_comments` tool therefore drops attachment data before the agent can see it.

This was reproduced read-only against ticket `36870`:

- Zendesk returned three comments.
- Two comments contained attachments: `logs_2026-07-14 (2).zip` and `~WRD0000.jpg`.
- The ZIP was downloadable with a normal unauthenticated GET and had a valid ZIP signature.
- The normalized client and MCP tool output contained no `attachments` field.

Current flow:

`Zendesk comments API -> raw comment with attachments -> getTicketComments normalization drops attachments -> MCP returns text-only comments`

## Goals

- Make regular files and inline images visible in `get_ticket_comments`.
- Preserve the relationship between each attachment and its source comment.
- Give agents enough metadata and instructions to download and inspect relevant attachments locally.
- Return all ticket comments rather than silently omitting attachments after the first API page.
- Keep binary data out of the MCP JSON response.
- Treat customer-provided files and archives as untrusted input.

## Non-goals

- Adding a separate attachment-listing or attachment-download MCP tool.
- Returning attachment bytes or base64 data through MCP.
- Writing downloaded files from the MCP server process.
- Uploading, modifying, or redacting Zendesk attachments.
- Implementing archive parsing or diagnostics analysis inside this server.

## Assumption

The consuming agent can make ordinary HTTP GET requests and save files in its own workspace. If a future consumer lacks either capability, it will need a separately designed download bridge; that is outside this change.

## Architecture

The existing comment contract is the earliest lifecycle boundary that already carries the relevant data. It will be extended instead of introducing a parallel attachment workflow.

### Typed contract

Add a `ZendeskAttachment` type with these fields:

- `id: number`
- `file_name: string | null`
- `content_type: string | null`
- `size: number | null`
- `content_url: string | null`
- `inline: boolean`
- `deleted: boolean`
- `malware_scan_result: string | null`

Add `attachments: ZendeskAttachment[]` to `ZendeskComment`. A comment without attachments returns an empty array. Missing optional Zendesk values normalize to `null`; missing boolean flags normalize to `false`.

The contract intentionally excludes attachment bytes, API-record URLs, mapped URLs, thumbnails, dimensions, and malware override controls because they are not required for the download-and-inspect workflow.

### Zendesk client

`ZendeskClient.getTicketComments()` will:

1. Request ticket comments with `include_inline_images=true` and a page size of 100.
2. Follow Zendesk's returned `links.next` or `next_page` value using the existing `nextPath()` boundary.
3. Accumulate normalized comments in API order.
4. Normalize each comment's attachment array into the typed contract.
5. Fail the whole request if any page fails, avoiding a silently incomplete result.

The client continues to authenticate only calls to the configured Zendesk API base URL. It does not fetch attachment `content_url` values.

### MCP tool and agent behavior

`get_ticket_comments` remains the only relevant MCP tool. Its input and top-level JSON shape remain unchanged; each returned comment gains an `attachments` array.

MCP server instructions will generalize the current inline-image guidance:

- Inspect each comment's attachment metadata when it may be relevant to the task.
- Download relevant `content_url` values with a normal GET that follows redirects; do not use HEAD as an availability check.
- Do not send Zendesk API credentials to attachment URLs or redirected third-party hosts.
- Save the file locally before inspecting it.
- Do not open an attachment marked deleted or explicitly identified as malicious.
- Treat archives as untrusted: list their contents first, extract into a dedicated directory, and never execute their contents merely to inspect them.
- Report download, extraction, or inspection failures explicitly instead of claiming the attachment was analyzed.

Attachment URLs should be treated as sensitive access links and should not be copied into unrelated logs or external messages.

Resulting flow:

`Zendesk comments API -> typed comments with attachments -> MCP JSON -> agent downloads relevant content_url -> local inspection`

## Error handling

- A missing or non-array `attachments` property becomes `[]`.
- Missing optional attachment fields do not discard the comment or attachment.
- A Zendesk API error on any comments page propagates through the existing MCP `isError` response.
- The server does not retry attachment downloads because downloading happens in the agent environment, outside this MCP server.
- An agent that cannot download or safely inspect a file must identify the affected attachment and the concrete failure.

## Testing

Implementation will use the optimized TDD loop.

Preparation before RED:

1. Re-read the focused production and test files.
2. State the intended production change in one sentence without applying it.
3. Apply only the test change.

Focused automated coverage:

- A client test stubs Zendesk comment responses and proves the request includes `include_inline_images=true`.
- A multi-page fixture proves all pages are followed in order.
- Attachment fixtures prove the selected fields are normalized without binary data.
- Comments without attachments produce `attachments: []`.
- Missing optional values produce the specified null or false defaults.
- An in-memory MCP test proves `get_ticket_comments` returns attachments with their source comments.
- The server-instructions test covers GET with redirects, no HEAD availability check, credential isolation, local inspection, and safe archive handling.

After a valid focused RED, apply the stated production change and re-run the same test for GREEN. Then run:

- `npm run check`
- `npm test`
- `git diff --check`

Manual read-only verification uses ticket `36870` only as a smoke test:

- MCP output includes the ZIP and JPG attachment metadata.
- The ZIP `content_url` downloads with GET.
- The downloaded bytes begin with the ZIP `PK` signature.

Automated tests must not depend on live Zendesk credentials or ticket state.

## Execution mode

Use inline single-agent implementation. The change is one compact lifecycle crossing shared types, one client method, server instructions, and focused tests. Parallel implementation would create overlapping edits and unnecessary integration overhead.

The integrated result is proven by focused RED/GREEN evidence, the complete local test suite, type checking, diff validation, and the live read-only smoke test.

## Compatibility and trade-offs

- Existing consumers keep the same tool name, input, and top-level array response. Adding `attachments` is backward-compatible for JSON consumers that ignore unknown fields.
- Fetching every comments page makes the tool description "Retrieve all comments" accurate and prevents later attachments from remaining invisible.
- Very large tickets can produce larger MCP responses. This is accepted for the current contract; if real usage shows context-size pressure, pagination or a narrow attachment-summary tool should be designed separately rather than silently truncating results.

## Acceptance criteria

- Ticket `36870` exposes both known attachments through `get_ticket_comments`.
- Regular attachments and inline images use the same typed comment contract.
- Relevant files can be downloaded by the agent without Zendesk credentials being forwarded to attachment hosts.
- Empty, malformed, deleted, malicious, and multi-page cases follow the documented behavior.
- Focused tests, `npm run check`, the full test suite, and the live read-only smoke test pass.
