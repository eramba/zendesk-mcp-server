# Zendesk Comment Attachments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (recommended for this plan's approved inline mode) or superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve regular and inline Zendesk comment attachments in `get_ticket_comments` so agents can safely download and inspect relevant files.

**Architecture:** Extend the existing typed comment contract with normalized attachment metadata, then make `ZendeskClient.getTicketComments()` follow all Zendesk comment pages with inline images included. Keep the existing MCP tool and JSON transport, and guide the consuming agent to download relevant `content_url` values without forwarding Zendesk credentials or embedding binary data in MCP.

**Tech Stack:** Node.js 20+, TypeScript 5.9, native `fetch`, MCP TypeScript SDK, Zod, Node test runner.

## Global Constraints

- Use Node.js 20 or newer.
- Add no runtime or development dependencies.
- Keep `get_ticket_comments` as the only attachment-related MCP tool.
- Keep the tool's input and top-level array response unchanged.
- Return metadata only; never return attachment bytes or base64 through MCP.
- Include regular attachments and inline images.
- Follow every Zendesk comments page and preserve API order.
- Treat cursor `meta.has_more` as authoritative and normalize full next URLs without duplicating `/api/v2`.
- Never send Zendesk API credentials to attachment URLs or redirected third-party hosts.
- Never write downloaded files from the MCP server process.
- Treat customer files and archives as untrusted input.
- Automated tests must not use live Zendesk credentials or ticket state.
- Use the explicit preparation -> test-only RED -> production GREEN sequence for each production behavior change.

---

## File Structure

- Create `test/zendesk-comments-attachments.test.mjs`: focused client pagination, normalization, and in-memory MCP contract tests.
- Modify `src/types.ts`: define `ZendeskAttachment` and add it to `ZendeskComment`.
- Modify `src/zendesk-client.ts`: model raw comment attachments, normalize them, request inline images, and follow all comments pages.
- Modify `test/server-instructions.test.mjs`: specify safe download and archive-handling instructions.
- Modify `src/server.ts`: publish the attachment workflow through MCP initialization instructions.
- Modify `README.md`: document the metadata-only attachment behavior of `get_ticket_comments`.

### Task 1: Preserve Attachments Through the Comment Contract

**Files:**
- Create: `test/zendesk-comments-attachments.test.mjs`
- Modify: `src/types.ts:1-23`
- Modify: `src/zendesk-client.ts:1-15,17-31,98-113,236-256`

**Interfaces:**
- Consumes: `new ZendeskClient(subdomain: string, email: string, token: string)` and `buildZendeskServer(client: ZendeskClient)`.
- Produces: `ZendeskAttachment`, `ZendeskComment.attachments: ZendeskAttachment[]`, and `ZendeskClient.getTicketComments(ticketId: number): Promise<ZendeskComment[]>` with full-page traversal.

- [ ] **Step 1: Prepare the TDD change without editing production code**

Read `src/types.ts`, `src/zendesk-client.ts`, `src/server.ts`, and `test/server-instructions.test.mjs`.

State this sentence before editing:

> I will extend the existing comment contract to normalize attachment metadata and make `getTicketComments()` follow every page with inline images included.

- [ ] **Step 2: Add the failing client and MCP contract tests**

Create `test/zendesk-comments-attachments.test.mjs` with exactly this content and do not edit `src/` yet:

```js
import assert from 'node:assert/strict'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { buildZendeskServer } from '../dist/server.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function installFetch(t, implementation) {
  const originalFetch = globalThis.fetch
  globalThis.fetch = implementation
  t.after(() => {
    globalThis.fetch = originalFetch
  })
}

test('getTicketComments includes inline images, follows pagination, and normalizes attachments', async (t) => {
  const calls = []

  installFetch(t, async (input, init = {}) => {
    const url = String(input)
    calls.push({ url, headers: new Headers(init.headers) })

    if (calls.length === 1) {
      return jsonResponse({
        comments: [
          {
            id: 101,
            author_id: 201,
            body: 'Diagnostics attached',
            html_body: '<p>Diagnostics attached</p>',
            public: true,
            created_at: '2026-07-14T20:14:10Z',
            attachments: [
              {
                id: 301,
                file_name: 'logs.zip',
                content_type: 'application/zip',
                size: 420049,
                content_url: 'https://example.zendesk.com/attachments/token/example/logs.zip',
                inline: false,
                deleted: false,
                malware_scan_result: 'malware_not_found',
                thumbnails: [{ id: 999 }],
              },
            ],
          },
        ],
        links: {
          next: 'https://example.zendesk.com/api/v2/tickets/36870/comments.json?include_inline_images=true&page%5Bsize%5D=100&page%5Bafter%5D=cursor',
        },
        meta: { has_more: true },
      })
    }

    return jsonResponse({
      comments: [
        {
          id: 102,
          attachments: [],
        },
      ],
      links: { next: null },
      meta: { has_more: false },
    })
  })

  const client = new ZendeskClient('example', 'agent@example.test', 'test-token')
  const comments = await client.getTicketComments(36870)

  assert.equal(calls.length, 2)
  const firstUrl = new URL(calls[0].url)
  assert.equal(firstUrl.pathname, '/api/v2/tickets/36870/comments.json')
  assert.equal(firstUrl.searchParams.get('include_inline_images'), 'true')
  assert.equal(firstUrl.searchParams.get('page[size]'), '100')
  assert.match(calls[0].headers.get('authorization') ?? '', /^Basic /)
  assert.equal(new URL(calls[1].url).pathname, '/api/v2/tickets/36870/comments.json')
  assert.match(calls[1].headers.get('authorization') ?? '', /^Basic /)

  assert.deepEqual(comments, [
    {
      id: 101,
      author_id: 201,
      body: 'Diagnostics attached',
      html_body: '<p>Diagnostics attached</p>',
      public: true,
      created_at: '2026-07-14T20:14:10Z',
      attachments: [
        {
          id: 301,
          file_name: 'logs.zip',
          content_type: 'application/zip',
          size: 420049,
          content_url: 'https://example.zendesk.com/attachments/token/example/logs.zip',
          inline: false,
          deleted: false,
          malware_scan_result: 'malware_not_found',
        },
      ],
    },
    {
      id: 102,
      author_id: null,
      body: null,
      html_body: null,
      public: false,
      created_at: null,
      attachments: [],
    },
  ])
})

test('getTicketComments stops when cursor metadata reports no more pages', async (t) => {
  let calls = 0

  installFetch(t, async () => {
    calls += 1

    if (calls === 1) {
      return jsonResponse({
        comments: [{ id: 104, attachments: [] }],
        links: {
          next: 'https://example.zendesk.com/api/v2/tickets/36870/comments.json?include_inline_images=true&page%5Bsize%5D=100&page%5Bafter%5D=terminal-cursor',
        },
        meta: { has_more: false },
      })
    }

    return jsonResponse({
      comments: [],
      links: { next: null },
      meta: { has_more: false },
    })
  })

  const client = new ZendeskClient('example', 'agent@example.test', 'test-token')
  const comments = await client.getTicketComments(36870)

  assert.equal(calls, 1)
  assert.equal(comments.length, 1)
})

test('get_ticket_comments exposes attachment defaults through MCP', async (t) => {
  installFetch(t, async () =>
    jsonResponse({
      comments: [
        {
          id: 103,
          attachments: [{ id: 302 }],
        },
      ],
      links: { next: null },
      meta: { has_more: false },
    }),
  )

  const zendesk = new ZendeskClient('example', 'agent@example.test', 'test-token')
  const server = buildZendeskServer(zendesk)
  const client = new Client({ name: 'attachment-test-client', version: '1.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()

  await server.connect(serverTransport)
  await client.connect(clientTransport)

  try {
    const result = await client.callTool({
      name: 'get_ticket_comments',
      arguments: { ticket_id: 36870 },
    })

    assert.equal(result.isError, undefined)
    assert.equal(result.content[0].type, 'text')
    const comments = JSON.parse(result.content[0].text)

    assert.deepEqual(comments[0].attachments, [
      {
        id: 302,
        file_name: null,
        content_type: null,
        size: null,
        content_url: null,
        inline: false,
        deleted: false,
        malware_scan_result: null,
      },
    ])
  } finally {
    await client.close()
    await server.close()
  }
})
```

- [ ] **Step 3: Run the focused tests and confirm valid RED**

Run:

```bash
npm run build && node --test test/zendesk-comments-attachments.test.mjs
```

Expected: FAIL. The first test reports one API call instead of two and/or the MCP assertion reports that `attachments` is missing. Confirm the failure is an assertion about the new contract, not a syntax, import, credential, or network error.

- [ ] **Step 4: Add the typed attachment contract**

In `src/types.ts`, add `ZendeskAttachment` before `ZendeskComment`, then add the `attachments` field:

```ts
export type ZendeskAttachment = {
  id: number;
  file_name: string | null;
  content_type: string | null;
  size: number | null;
  content_url: string | null;
  inline: boolean;
  deleted: boolean;
  malware_scan_result: string | null;
};

export type ZendeskComment = {
  id: number;
  author_id: number | null;
  body: string | null;
  html_body: string | null;
  public: boolean;
  created_at: string | null;
  attachments: ZendeskAttachment[];
};
```

- [ ] **Step 5: Model and normalize Zendesk comment payloads**

Add `ZendeskAttachment` to the type import in `src/zendesk-client.ts`:

```ts
import type {
  TicketAuditListResult,
  TicketFieldListResult,
  TicketListResult,
  TicketSearchResult,
  ZendeskAttachment,
  ZendeskComment,
  ZendeskKnowledgeBase,
  ZendeskOrganization,
  ZendeskSearchResult,
  ZendeskTicket,
  ZendeskTicketAudit,
  ZendeskTicketAuditEvent,
  ZendeskTicketField,
  ZendeskUser,
} from "./types.js";
```

Add these payload types after `TicketPayload`:

```ts
type AttachmentPayload = {
  id?: number;
  file_name?: string;
  content_type?: string;
  size?: number;
  content_url?: string;
  inline?: boolean;
  deleted?: boolean;
  malware_scan_result?: string;
};

type CommentPayload = {
  id?: number;
  author_id?: number;
  body?: string;
  html_body?: string;
  public?: boolean;
  created_at?: string;
  attachments?: AttachmentPayload[];
};
```

Add these normalizers after `normalizeTicket()`:

```ts
function normalizeAttachment(attachment: AttachmentPayload): ZendeskAttachment {
  return {
    id: Number(attachment.id),
    file_name: attachment.file_name ?? null,
    content_type: attachment.content_type ?? null,
    size: attachment.size ?? null,
    content_url: attachment.content_url ?? null,
    inline: Boolean(attachment.inline),
    deleted: Boolean(attachment.deleted),
    malware_scan_result: attachment.malware_scan_result ?? null,
  };
}

function normalizeComment(comment: CommentPayload): ZendeskComment {
  return {
    id: Number(comment.id),
    author_id: comment.author_id ?? null,
    body: comment.body ?? null,
    html_body: comment.html_body ?? null,
    public: Boolean(comment.public),
    created_at: comment.created_at ?? null,
    attachments: Array.isArray(comment.attachments)
      ? comment.attachments.map(normalizeAttachment)
      : [],
  };
}
```

- [ ] **Step 6: Replace the one-page comment fetch with full cursor traversal**

Replace `ZendeskClient.getTicketComments()` with:

```ts
async getTicketComments(ticketId: number): Promise<ZendeskComment[]> {
  const comments: ZendeskComment[] = [];
  let nextCommentsPath: string | null =
    `/tickets/${ticketId}/comments.json?include_inline_images=true&page[size]=100`;

  while (nextCommentsPath) {
    const data = await this.request<{
      comments: CommentPayload[];
      links?: { next?: string | null };
      meta?: { has_more: boolean };
      next_page?: string | null;
    }>(nextCommentsPath);

    comments.push(...data.comments.map(normalizeComment));
    const nextUrl = data.meta
      ? data.meta.has_more
        ? (data.links?.next ?? null)
        : null
      : (data.next_page ?? data.links?.next ?? null);
    nextCommentsPath = this.nextPath(nextUrl);
  }

  return comments;
}
```

- [ ] **Step 7: Normalize full Zendesk cursor URLs against the API base path**

Replace `nextPath()` with:

```ts
private nextPath(nextUrl: string | null): string | null {
  if (!nextUrl) {
    return null;
  }

  if (nextUrl.startsWith("http://") || nextUrl.startsWith("https://")) {
    const parsed = new URL(nextUrl);
    const apiPrefix = "/api/v2";
    const pathname = parsed.pathname.startsWith(`${apiPrefix}/`)
      ? parsed.pathname.slice(apiPrefix.length)
      : parsed.pathname;
    return `${pathname}${parsed.search}`;
  }

  return nextUrl;
}
```

- [ ] **Step 8: Re-run the same focused tests and confirm GREEN**

Run:

```bash
npm run build && node --test test/zendesk-comments-attachments.test.mjs
```

Expected: PASS with `3` tests passed and `0` failed.

- [ ] **Step 9: Run the existing suite and type checker**

Run:

```bash
npm run check
npm test
git diff --check
```

Expected: all commands exit `0`; the complete suite reports `4` tests passed and `0` failed.

- [ ] **Step 10: Commit the comment contract**

```bash
git add src/types.ts src/zendesk-client.ts test/zendesk-comments-attachments.test.mjs
git commit -m "feat: expose Zendesk comment attachments"
```

### Task 2: Publish Safe Attachment Handling Instructions

**Files:**
- Modify: `test/server-instructions.test.mjs:10-24`
- Modify: `src/server.ts:29-33`

**Interfaces:**
- Consumes: `ZendeskComment.attachments` and each attachment's `content_url`, `deleted`, and `malware_scan_result` fields from Task 1.
- Produces: MCP initialization instructions that tell the consuming agent how to download and inspect attachments without exposing Zendesk credentials.

- [ ] **Step 1: Prepare the instruction change without editing production code**

Read `src/server.ts:29-33` and `test/server-instructions.test.mjs`.

State this sentence before editing:

> I will generalize the MCP initialization instructions from inline images to all comment attachments, including credential isolation and safe archive inspection.

- [ ] **Step 2: Replace the instruction test with the failing attachment specification**

In `test/server-instructions.test.mjs`, keep the imports and MCP setup unchanged, rename the test, and replace its assertions with:

```js
test('publishes safe Zendesk attachment retrieval instructions during MCP initialization', async () => {
  const zendesk = new ZendeskClient('example', 'agent@example.test', 'test-token')
  const server = buildZendeskServer(zendesk)
  const client = new Client({ name: 'test-client', version: '1.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()

  await server.connect(serverTransport)
  await client.connect(clientTransport)

  try {
    const instructions = client.getInstructions() ?? ''

    assert.match(instructions, /comments may contain an attachments array/i)
    assert.match(instructions, /normal HTTP GET/i)
    assert.match(instructions, /follows redirects/i)
    assert.match(instructions, /do not use HEAD/i)
    assert.match(instructions, /do not send Zendesk API credentials/i)
    assert.match(instructions, /sensitive access links/i)
    assert.match(instructions, /marked deleted/i)
    assert.match(instructions, /malicious/i)
    assert.match(instructions, /list their contents first/i)
    assert.match(instructions, /dedicated directory/i)
    assert.match(instructions, /never execute/i)
    assert.match(instructions, /report download, extraction, or inspection failures/i)
  } finally {
    await client.close()
    await server.close()
  }
})
```

- [ ] **Step 3: Run the instruction test and confirm valid RED**

Run:

```bash
npm run build && node --test test/server-instructions.test.mjs
```

Expected: FAIL on `/comments may contain an attachments array/i`. Confirm MCP initialization itself succeeds.

- [ ] **Step 4: Replace `SERVER_INSTRUCTIONS` with the approved attachment workflow**

In `src/server.ts`, replace the existing constant with:

```ts
const SERVER_INSTRUCTIONS = [
  "Zendesk ticket and comment body or html_body fields may contain inline image URLs, and comments may contain an attachments array.",
  "When an image or attachment is relevant, retrieve its URL (the content_url for attachments) with a normal HTTP GET that follows redirects; do not use HEAD to decide whether content is available because Zendesk content may reject HEAD while allowing GET.",
  "Do not send Zendesk API credentials to attachment URLs or redirected third-party hosts.",
  "Treat attachment content URLs as sensitive access links and do not copy them into unrelated logs or external messages.",
  "Save a downloaded file locally before inspecting it.",
  "Do not open an attachment marked deleted or explicitly identified as malicious.",
  "Treat archives as untrusted: list their contents first, extract them into a dedicated directory, and never execute their contents merely to inspect them.",
  "Report download, extraction, or inspection failures explicitly; do not claim an attachment was analyzed when inspection failed.",
].join(" ");
```

- [ ] **Step 5: Re-run the same instruction test and confirm GREEN**

Run:

```bash
npm run build && node --test test/server-instructions.test.mjs
```

Expected: PASS with `1` test passed and `0` failed.

- [ ] **Step 6: Run the complete local verification**

Run:

```bash
npm run check
npm test
git diff --check
```

Expected: all commands exit `0`; the complete suite reports `4` tests passed and `0` failed.

- [ ] **Step 7: Commit the server instructions**

```bash
git add src/server.ts test/server-instructions.test.mjs
git commit -m "feat: guide agents through Zendesk attachments"
```

### Task 3: Document and Verify the Integrated Live Flow

**Files:**
- Modify: `README.md:73-87`

**Interfaces:**
- Consumes: the completed `get_ticket_comments` attachment contract and MCP initialization instructions.
- Produces: user-facing behavior documentation and read-only live evidence for ticket `36870`.

- [ ] **Step 1: Document the metadata-only attachment contract**

Immediately after the Tools list in `README.md`, add:

```markdown
`get_ticket_comments` returns an `attachments` array on each comment. Each attachment includes its ID, filename, content type, size, download URL, inline/deleted flags, and malware scan result. File bytes are not embedded in MCP responses; consumers download relevant `content_url` values with a normal GET and inspect them locally.
```

- [ ] **Step 2: Run the full automated verification**

Run:

```bash
npm run check
npm test
git diff --check
```

Expected: all commands exit `0`; the complete suite reports `4` tests passed and `0` failed.

- [ ] **Step 3: Run the sanitized read-only smoke test against ticket 36870**

Run from the repository root. The script prints attachment names but never prints credentials or attachment URLs:

```bash
node --input-type=module <<'NODE'
import assert from 'node:assert/strict'
import 'dotenv/config'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { buildZendeskServer } from './dist/server.js'
import { ZendeskClient } from './dist/zendesk-client.js'

const required = ['ZENDESK_SUBDOMAIN', 'ZENDESK_EMAIL', 'ZENDESK_API_KEY']
const missing = required.filter((key) => !process.env[key])
assert.deepEqual(missing, [], `Missing Zendesk environment variables: ${missing.join(', ')}`)

const zendesk = new ZendeskClient(
  process.env.ZENDESK_SUBDOMAIN,
  process.env.ZENDESK_EMAIL,
  process.env.ZENDESK_API_KEY,
)
const server = buildZendeskServer(zendesk)
const client = new Client({ name: 'live-attachment-smoke', version: '1.0.0' })
const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()

await server.connect(serverTransport)
await client.connect(clientTransport)

try {
  const result = await client.callTool({
    name: 'get_ticket_comments',
    arguments: { ticket_id: 36870 },
  })
  assert.equal(result.isError, undefined)
  assert.equal(result.content[0].type, 'text')

  const comments = JSON.parse(result.content[0].text)
  const attachments = comments.flatMap((comment) => comment.attachments)
  const zip = attachments.find((attachment) => attachment.file_name === 'logs_2026-07-14 (2).zip')
  const image = attachments.find((attachment) => attachment.file_name === '~WRD0000.jpg')

  assert.ok(zip, 'Expected ZIP attachment was not returned by MCP')
  assert.ok(image, 'Expected JPG attachment was not returned by MCP')
  assert.equal(typeof zip.content_url, 'string')

  const response = await fetch(zip.content_url, { redirect: 'follow' })
  assert.equal(response.status, 200)
  const bytes = new Uint8Array(await response.arrayBuffer())
  assert.deepEqual(Array.from(bytes.slice(0, 2)), [0x50, 0x4b])

  console.log(JSON.stringify({
    ticket_id: 36870,
    comment_count: comments.length,
    attachment_names: attachments.map((attachment) => attachment.file_name),
    zip_bytes: bytes.length,
    zip_magic: 'PK',
  }, null, 2))
} finally {
  await client.close()
  await server.close()
}
NODE
```

Expected: exit `0`, attachment names include `logs_2026-07-14 (2).zip`, inline `image001.png`, and `~WRD0000.jpg`; `zip_bytes` is greater than `0`, and `zip_magic` is `PK`.

- [ ] **Step 4: Review the final diff and scope**

Run:

```bash
git diff --check
git status --short
git diff -- README.md
```

Expected: no whitespace errors; only the intended README and approved design/plan documentation updates remain uncommitted because the production changes were already committed.

- [ ] **Step 5: Commit the documentation**

```bash
git add README.md docs/superpowers/specs/2026-07-15-zendesk-comment-attachments-design.md docs/superpowers/plans/2026-07-15-zendesk-comment-attachments.md
git commit -m "docs: document Zendesk comment attachments"
```

- [ ] **Step 6: Confirm the implementation branch is clean**

Run:

```bash
git status --short --branch
git log -4 --oneline
```

Expected: the working tree is clean and the latest four commits are the attachment contract, attachment instructions, cursor pagination correction, and documentation commits.
