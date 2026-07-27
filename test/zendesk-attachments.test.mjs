import assert from 'node:assert/strict'
import test from 'node:test'

import { ZendeskClient } from '../dist/zendesk-client.js'

function apiResponse(body, status = 200) {
  return new Response(body === undefined ? undefined : JSON.stringify(body), {
    status,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
  })
}

function attachmentClient(responses) {
  const requests = []
  return {
    requests,
    client: new ZendeskClient({
      subdomain: 'acme',
      auth: {
        kind: 'oauth',
        accessToken: 'access-token-sentinel',
        onUnauthorized: async () => assert.fail('fresh token must not refresh'),
      },
      fetch: async (input, init = {}) => {
        requests.push({
          url: String(input),
          method: init.method ?? 'GET',
          contentType: new Headers(init.headers).get('content-type'),
          body: init.body,
        })
        const next = responses.shift()
        assert.notEqual(next, undefined, 'unexpected Zendesk request')
        return next
      },
    }),
  }
}

const baseComment = {
  ticketId: 36870,
  comment: 'Logs attached',
  public: false,
  expectedUpdatedAt: '2026-07-27T10:00:00Z',
}

test('invalid inline attachments fail before any Zendesk request', async () => {
  const oversized = Buffer.alloc(5 * 1024 * 1024 + 1).toString('base64')
  const invalidCases = [
    [{ filename: '../secret.txt', content_type: 'text/plain', content_base64: 'YQ==' }],
    [{ filename: 'bad\u0000name.txt', content_type: 'text/plain', content_base64: 'YQ==' }],
    [{ filename: 'file.txt', content_type: 'not a mime', content_base64: 'YQ==' }],
    [{ filename: 'file.txt', content_type: 'text/plain', content_base64: 'not-base64' }],
    [{ filename: 'file.txt', content_type: 'text/plain', content_base64: 'YR==' }],
    Array.from({ length: 4 }, (_, index) => ({
      filename: `${index}.txt`,
      content_type: 'text/plain',
      content_base64: 'YQ==',
    })),
    [{ filename: 'large.bin', content_type: 'application/octet-stream', content_base64: oversized }],
  ]

  for (const attachments of invalidCases) {
    const { client, requests } = attachmentClient([])
    const error = await client.createTicketComment({
      ...baseComment,
      attachments,
    }).catch((caught) => caught)

    assert.ok(error instanceof Error)
    assert.equal(requests.length, 0)
    assert.equal(String(error).includes('not-base64'), false)
  }
})

test('comment attachments chain one Zendesk upload token and never expose it', async () => {
  const uploadToken = 'upload-token-secret-sentinel'
  const { client, requests } = attachmentClient([
    apiResponse({ upload: { token: uploadToken } }, 201),
    apiResponse({ upload: { token: uploadToken } }, 201),
    apiResponse({ ticket: { id: 36870, updated_at: '2026-07-27T10:01:00Z' } }),
  ])

  const ticket = await client.createTicketComment({
    ...baseComment,
    attachments: [
      { filename: 'first.png', content_type: 'image/png', content_base64: 'Zmlyc3Q=' },
      { filename: 'second.txt', content_type: 'text/plain', content_base64: 'c2Vjb25k' },
    ],
  })

  assert.equal(requests[0].url, 'https://acme.zendesk.com/api/v2/uploads.json?filename=first.png')
  assert.equal(requests[0].method, 'POST')
  assert.equal(requests[0].contentType, 'image/png')
  assert.equal(Buffer.from(requests[0].body).toString(), 'first')
  assert.equal(requests[1].url, `https://acme.zendesk.com/api/v2/uploads.json?filename=second.txt&token=${uploadToken}`)
  assert.equal(requests[1].contentType, 'text/plain')
  assert.equal(Buffer.from(requests[1].body).toString(), 'second')
  assert.deepEqual(JSON.parse(requests[2].body), {
    ticket: {
      comment: {
        body: 'Logs attached',
        public: false,
        uploads: [uploadToken],
      },
      safe_update: true,
      updated_stamp: '2026-07-27T10:00:00Z',
    },
  })
  assert.equal(ticket.id, 36870)
  assert.equal(JSON.stringify(ticket).includes(uploadToken), false)
})

test('failed comments best-effort delete the upload and preserve the original safe error', async () => {
  const uploadToken = 'upload-token-secret-sentinel'
  const { client, requests } = attachmentClient([
    apiResponse({ upload: { token: uploadToken } }, 201),
    apiResponse({ error: 'UpdateConflict', description: 'body-secret' }, 409),
    apiResponse(undefined, 204),
  ])

  const error = await client.createTicketComment({
    ...baseComment,
    attachments: [
      { filename: 'log.txt', content_type: 'text/plain', content_base64: 'bG9n' },
    ],
  }).catch((caught) => caught)

  assert.equal(error.category, 'conflict')
  assert.equal(requests[2].url, `https://acme.zendesk.com/api/v2/uploads/${uploadToken}.json`)
  assert.equal(requests[2].method, 'DELETE')
  assert.equal(String(error).includes(uploadToken), false)
  assert.equal(String(error).includes('body-secret'), false)
})
