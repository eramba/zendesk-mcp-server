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
