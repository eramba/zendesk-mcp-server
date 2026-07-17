import assert from 'node:assert/strict'
import test from 'node:test'

import {
  ReauthorizationRequiredError,
  ZendeskUpstreamError,
} from '../dist/oauth/errors.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

const UUID_PATTERN = /^[0-9a-f-]{36}$/i

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

function basicClient(fetch, overrides = {}) {
  return new ZendeskClient({
    subdomain: 'example',
    auth: {
      kind: 'api_token',
      email: 'agent@example.test',
      apiToken: 'api-token-sentinel',
    },
    fetch,
    ...overrides,
  })
}

function oauthClient(fetch, onUnauthorized, overrides = {}) {
  return new ZendeskClient({
    subdomain: 'example',
    auth: {
      kind: 'oauth',
      accessToken: 'oauth-access-1',
      principalEpoch: 7,
      credentialVersion: 3,
      onUnauthorized,
    },
    fetch,
    ...overrides,
  })
}

test('api-token auth sends Basic credentials and preserves pagination normalization', async () => {
  const calls = []
  const responses = [
    jsonResponse({
      comments: [{ id: 11, body: 'first', attachments: [{ id: 31 }] }],
      links: { next: 'https://example.zendesk.com/api/v2/tickets/42/comments.json?page%5Bafter%5D=next' },
      meta: { has_more: true },
    }),
    jsonResponse({
      comments: [{ id: 12, public: true, attachments: [] }],
      links: { next: null },
      meta: { has_more: false },
    }),
  ]
  const client = basicClient(async (input, init) => {
    calls.push({ url: String(input), headers: new Headers(init?.headers) })
    return responses.shift()
  })

  const comments = await client.getTicketComments(42)

  assert.equal(calls.length, 2)
  const expected = `Basic ${Buffer.from('agent@example.test/token:api-token-sentinel').toString('base64')}`
  assert.deepEqual(calls.map((call) => call.headers.get('authorization')), [expected, expected])
  assert.equal(new URL(calls[1].url).pathname, '/api/v2/tickets/42/comments.json')
  assert.deepEqual(comments, [
    {
      id: 11,
      author_id: null,
      body: 'first',
      html_body: null,
      public: false,
      created_at: null,
      attachments: [{
        id: 31,
        file_name: null,
        content_type: null,
        size: null,
        content_url: null,
        inline: false,
        deleted: false,
        malware_scan_result: null,
      }],
    },
    {
      id: 12,
      author_id: null,
      body: null,
      html_body: null,
      public: true,
      created_at: null,
      attachments: [],
    },
  ])
})

test('OAuth retries the original request once with the resolver credential', async () => {
  const requests = []
  const callbacks = []
  const client = oauthClient(
    async (input, init) => {
      requests.push({ url: String(input), authorization: new Headers(init?.headers).get('authorization') })
      return requests.length === 1
        ? jsonResponse({ error: 'expired-access-sentinel' }, 401)
        : jsonResponse({ ticket: { id: 42, subject: 'retried' } })
    },
    async (input) => {
      callbacks.push(input)
      return {
        kind: 'retry',
        accessToken: 'oauth-access-2',
        principalEpoch: 8,
        credentialVersion: 4,
      }
    },
  )

  const ticket = await client.getTicket(42)

  assert.equal(ticket.id, 42)
  assert.equal(ticket.subject, 'retried')
  assert.deepEqual(requests.map(({ url, authorization }) => ({ url, authorization })), [
    { url: 'https://example.zendesk.com/api/v2/tickets/42.json', authorization: 'Bearer oauth-access-1' },
    { url: 'https://example.zendesk.com/api/v2/tickets/42.json', authorization: 'Bearer oauth-access-2' },
  ])
  assert.equal(callbacks.length, 1)
  assert.equal(callbacks[0].principalEpoch, 7)
  assert.equal(callbacks[0].credentialVersion, 3)
  assert.equal(callbacks[0].terminal, false)
  assert.ok(callbacks[0].signal instanceof AbortSignal)
})

test('a second OAuth 401 is terminal reauthorization with no third fetch', async () => {
  const authorizations = []
  const callbacks = []
  const correlationId = '11111111-1111-4111-8111-111111111111'
  const client = oauthClient(
    async (_input, init) => {
      authorizations.push(new Headers(init?.headers).get('authorization'))
      return jsonResponse({ error: 'upstream-body-sentinel' }, 401)
    },
    async (input) => {
      callbacks.push(input)
      if (!input.terminal) {
        return {
          kind: 'retry',
          accessToken: 'oauth-access-2',
          principalEpoch: 8,
          credentialVersion: 4,
        }
      }
      return { kind: 'reauthorization_required', correlationId }
    },
  )

  await assert.rejects(client.getTicket(42), (error) => {
    assert.ok(error instanceof ReauthorizationRequiredError)
    assert.equal(error.correlationId, correlationId)
    assert.equal(error.message.includes('upstream-body-sentinel'), false)
    return true
  })
  assert.deepEqual(authorizations, ['Bearer oauth-access-1', 'Bearer oauth-access-2'])
  assert.deepEqual(callbacks.map(({ principalEpoch, credentialVersion, terminal }) => ({
    principalEpoch,
    credentialVersion,
    terminal,
  })), [
    { principalEpoch: 7, credentialVersion: 3, terminal: false },
    { principalEpoch: 8, credentialVersion: 4, terminal: true },
  ])
})

test('a stale terminal OAuth 401 is sanitized and never triggers a third fetch', async () => {
  let fetches = 0
  const correlationId = '22222222-2222-4222-8222-222222222222'
  const client = oauthClient(
    async () => {
      fetches += 1
      return jsonResponse({ error: 'stale-body-sentinel' }, 401)
    },
    async ({ terminal }) => terminal
      ? { kind: 'stale_failure', correlationId }
      : {
          kind: 'retry',
          accessToken: 'oauth-access-2',
          principalEpoch: 8,
          credentialVersion: 4,
        },
  )

  await assert.rejects(client.getTicket(42), (error) => {
    assert.ok(error instanceof ZendeskUpstreamError)
    assert.equal(error.category, 'unauthorized')
    assert.equal(error.status, 401)
    assert.equal(error.retryable, false)
    assert.equal(error.correlationId, correlationId)
    assert.equal(error.message.includes('stale-body-sentinel'), false)
    return true
  })
  assert.equal(fetches, 2)
})

test('classifies and sanitizes HTTP, JSON, and network failures', async () => {
  const bodySentinel = 'upstream-body-secret-sentinel'
  const ticketSentinel = 'ticket-body-secret-sentinel'
  const headerSentinel = 'upstream-header-secret-sentinel'
  const emailSentinel = 'agent@example.test'
  const tokenSentinel = 'api-token-sentinel'
  const sentinels = [bodySentinel, ticketSentinel, headerSentinel, emailSentinel, tokenSentinel]
  const cases = [
    [403, 'forbidden', false],
    [429, 'rate_limited', true],
    [503, 'temporarily_unavailable', true],
  ]

  for (const [status, category, retryable] of cases) {
    const client = basicClient(async () => jsonResponse(
      { error: bodySentinel },
      status,
      { 'x-secret': headerSentinel },
    ))
    await assert.rejects(
      client.createTicket({ subject: ticketSentinel, description: ticketSentinel }),
      (error) => {
        assert.ok(error instanceof ZendeskUpstreamError)
        assert.equal(error.category, category)
        assert.equal(error.status, status)
        assert.equal(error.retryable, retryable)
        assert.match(error.correlationId, UUID_PATTERN)
        for (const sentinel of sentinels) assert.equal(error.message.includes(sentinel), false)
        return true
      },
    )
  }

  const malformed = basicClient(async () => new Response(`not-json-${bodySentinel}`, { status: 200 }))
  await assert.rejects(malformed.getTicket(42), (error) => {
    assert.ok(error instanceof ZendeskUpstreamError)
    assert.equal(error.category, 'invalid_response')
    assert.equal(error.status, 200)
    assert.equal(error.retryable, false)
    for (const sentinel of sentinels) assert.equal(error.message.includes(sentinel), false)
    return true
  })

  const network = basicClient(async () => {
    throw new Error(`network-${bodySentinel}`)
  })
  await assert.rejects(network.getTicket(42), (error) => {
    assert.ok(error instanceof ZendeskUpstreamError)
    assert.equal(error.category, 'temporarily_unavailable')
    assert.equal(error.status, undefined)
    assert.equal(error.retryable, true)
    for (const sentinel of sentinels) assert.equal(error.message.includes(sentinel), false)
    return true
  })
})

test('bounds discarded upstream failure bodies', async () => {
  let pulls = 0
  let cancelled = false
  const stream = new ReadableStream({
    pull(controller) {
      pulls += 1
      controller.enqueue(new Uint8Array(1024).fill(65))
      if (pulls === 100) controller.close()
    },
    cancel() {
      cancelled = true
    },
  })
  const client = basicClient(async () => new Response(stream, { status: 503 }))

  await assert.rejects(
    client.getTicket(42),
    (error) => error instanceof ZendeskUpstreamError && error.category === 'temporarily_unavailable',
  )

  assert.equal(cancelled, true)
  assert.ok(pulls < 100)
})

test('a hung bounded-body cancellation cannot outlive the request deadline', async () => {
  const stream = new ReadableStream({
    pull(controller) {
      controller.enqueue(new Uint8Array(9 * 1024).fill(65))
    },
    cancel() {
      return new Promise(() => {})
    },
  })
  const client = basicClient(async () => new Response(stream, { status: 503 }), { timeoutMs: 5 })

  const outcome = await Promise.race([
    client.getTicket(42).catch((error) => error),
    new Promise((resolve) => setTimeout(() => resolve('still-pending'), 30)),
  ])

  assert.notEqual(outcome, 'still-pending')
  assert.ok(outcome instanceof ZendeskUpstreamError)
  assert.equal(outcome.category, 'aborted')
})

function hungFetch(onSignal) {
  return async (_input, init) => new Promise((resolve, reject) => {
    const signal = init?.signal
    onSignal(signal)
    const abort = () => reject(signal?.reason ?? new DOMException('Aborted', 'AbortError'))
    if (signal?.aborted) abort()
    else signal?.addEventListener('abort', abort, { once: true })
  })
}

test('request timeout aborts the fetch with a sanitized typed error', async () => {
  let observedSignal
  const client = basicClient(hungFetch((signal) => { observedSignal = signal }), { timeoutMs: 5 })

  await assert.rejects(client.getTicket(42), (error) => {
    assert.ok(error instanceof ZendeskUpstreamError)
    assert.equal(error.category, 'aborted')
    assert.equal(error.status, undefined)
    assert.equal(error.retryable, false)
    assert.match(error.correlationId, UUID_PATTERN)
    return true
  })
  assert.equal(observedSignal.aborted, true)
})

test('an outer abort signal cancels the in-flight fetch', async () => {
  let observedSignal
  const controller = new AbortController()
  const client = basicClient(hungFetch((signal) => { observedSignal = signal }), { timeoutMs: 5_000 })

  const pending = client.getTicket(42, controller.signal)
  controller.abort(new Error('outer-abort-secret-sentinel'))

  await assert.rejects(pending, (error) => {
    assert.ok(error instanceof ZendeskUpstreamError)
    assert.equal(error.category, 'aborted')
    assert.equal(error.message.includes('outer-abort-secret-sentinel'), false)
    return true
  })
  assert.equal(observedSignal.aborted, true)
})
