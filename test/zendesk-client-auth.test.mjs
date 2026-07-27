import assert from 'node:assert/strict'
import test from 'node:test'

import { SafeAuthError } from '../dist/internal-auth/errors.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

function response(body, status = 200) {
  return new Response(
    body === undefined ? undefined : JSON.stringify(body),
    {
      status,
      headers: body === undefined
        ? {}
        : { 'content-type': 'application/json' },
    },
  )
}

function fakeFetch() {
  const requests = []
  const queued = []
  return {
    requests,
    queue(value) {
      queued.push(value)
    },
    fetch(input, init = {}) {
      requests.push({
        url: String(input),
        method: init.method ?? 'GET',
        authorization: new Headers(init.headers).get('authorization'),
        signal: init.signal,
      })
      const next = queued.shift()
      assert.notEqual(next, undefined, 'unexpected Zendesk API request')
      if (typeof next === 'function') return next(init.signal)
      return Promise.resolve(next)
    },
  }
}

function apiTokenClient(fake, overrides = {}) {
  return new ZendeskClient({
    subdomain: 'acme',
    auth: {
      kind: 'api-token',
      email: 'agent@example.test',
      token: 'api-token-sentinel',
    },
    timeoutMs: 50,
    fetch: fake.fetch,
    ...overrides,
  })
}

function oauthClient(fake, onUnauthorized, overrides = {}) {
  return new ZendeskClient({
    subdomain: 'acme',
    auth: {
      kind: 'oauth',
      accessToken: 'access-initial-sentinel',
      onUnauthorized,
    },
    timeoutMs: 50,
    fetch: fake.fetch,
    ...overrides,
  })
}

test('uses explicit API-token and OAuth authorization without changing API behavior', async () => {
  const basic = fakeFetch()
  basic.queue(response({ ticket: { id: 41, subject: 'Basic' } }))
  const basicTicket = await apiTokenClient(basic).getTicket(41)
  assert.equal(basicTicket.id, 41)
  assert.equal(
    basic.requests[0].authorization,
    `Basic ${Buffer.from('agent@example.test/token:api-token-sentinel').toString('base64')}`,
  )

  const oauth = fakeFetch()
  oauth.queue(response({ ticket: { id: 42, subject: 'OAuth' } }))
  const oauthTicket = await oauthClient(
    oauth,
    async () => assert.fail('fresh OAuth request must not refresh'),
  ).getTicket(42)
  assert.equal(oauthTicket.id, 42)
  assert.equal(oauth.requests[0].authorization, 'Bearer access-initial-sentinel')
})

test('OAuth invalid_token refreshes once and retries with only the returned token', async () => {
  const fake = fakeFetch()
  fake.queue(response({
    error: 'invalid_token',
    error_description: 'expired-secret-sentinel',
  }, 401))
  fake.queue(response({ ticket: { id: 42, subject: 'Retried' } }))
  const calls = []
  const client = oauthClient(fake, async (input) => {
    calls.push(input.terminal)
    assert.ok(input.signal instanceof AbortSignal)
    return { kind: 'retry', accessToken: 'access-rotated-sentinel' }
  })

  assert.equal((await client.getTicket(42)).subject, 'Retried')
  assert.deepEqual(calls, [false])
  assert.deepEqual(
    fake.requests.map(({ authorization }) => authorization),
    ['Bearer access-initial-sentinel', 'Bearer access-rotated-sentinel'],
  )
})

test('a second OAuth invalid_token is terminal and never makes a third request', async () => {
  const fake = fakeFetch()
  fake.queue(response({ error: 'invalid_token' }, 401))
  fake.queue(response({ error: 'invalid_token' }, 401))
  const calls = []
  const client = oauthClient(fake, async ({ terminal }) => {
    calls.push(terminal)
    return terminal
      ? {
          kind: 'reauthorization_required',
          correlationId: '00000000-0000-4000-8000-000000000002',
        }
      : { kind: 'retry', accessToken: 'access-rotated-sentinel' }
  })

  await assert.rejects(
    client.getTicket(42),
    (error) =>
      error instanceof SafeAuthError &&
      error.category === 'reauthorization_required',
  )
  assert.deepEqual(calls, [false, true])
  assert.equal(fake.requests.length, 2)
})

test('Basic auth and non-invalid-token 401 responses never invoke OAuth refresh', async () => {
  const basic = fakeFetch()
  basic.queue(response({ error: 'invalid_token' }, 401))
  await assert.rejects(
    apiTokenClient(basic).getTicket(42),
    (error) => error instanceof SafeAuthError && error.category === 'unauthorized',
  )
  assert.equal(basic.requests.length, 1)

  const oauth = fakeFetch()
  oauth.queue(response({ error: 'Unauthorized' }, 401))
  let refreshCalls = 0
  await assert.rejects(
    oauthClient(oauth, async () => {
      refreshCalls += 1
      return { kind: 'retry', accessToken: 'should-not-be-used' }
    }).getTicket(42),
    (error) => error instanceof SafeAuthError && error.category === 'unauthorized',
  )
  assert.equal(refreshCalls, 0)
  assert.equal(oauth.requests.length, 1)
})

test('bounded API requests respect timeout and outer cancellation', async () => {
  for (const mode of ['timeout', 'outer']) {
    const fake = fakeFetch()
    let aborted = false
    fake.queue((signal) => new Promise((_resolve, reject) => {
      const onAbort = () => {
        aborted = true
        reject(new DOMException('transport-secret-sentinel', 'AbortError'))
      }
      signal.addEventListener('abort', onAbort, { once: true })
      if (signal.aborted) onAbort()
    }))
    const outer = new AbortController()
    const client = apiTokenClient(fake, {
      timeoutMs: mode === 'timeout' ? 5 : 5_000,
      signal: outer.signal,
    })
    const pending = client.getTicket(42)
    if (mode === 'outer') outer.abort(new Error('outer-secret-sentinel'))

    await assert.rejects(
      pending,
      (error) => error instanceof SafeAuthError && error.category === 'aborted',
    )
    assert.equal(aborted, true)
    assert.equal(fake.requests.length, 1)
  }
})

test('API failures expose no body, token, URL, or transport secrets', async () => {
  const secrets = [
    'body-secret-sentinel',
    'api-token-sentinel',
    'access-initial-sentinel',
    'transport-secret-sentinel',
    'off-origin-secret.example.test',
  ]

  const upstream = fakeFetch()
  upstream.queue(response({
    error: 'body-secret-sentinel',
    details: { token: 'access-initial-sentinel' },
  }, 503))
  const failures = [
    await apiTokenClient(upstream).getTicket(42).catch((error) => error),
  ]

  const transport = fakeFetch()
  transport.queue(() => Promise.reject(new Error('transport-secret-sentinel')))
  failures.push(
    await oauthClient(transport, async () => assert.fail('no refresh'))
      .getTicket(42)
      .catch((error) => error),
  )

  const pagination = fakeFetch()
  pagination.queue(response({
    comments: [],
    next_page: 'https://off-origin-secret.example.test/api/v2/comments?page=2',
  }))
  failures.push(
    await apiTokenClient(pagination)
      .getTicketComments(42)
      .catch((error) => error),
  )

  for (const error of failures) {
    assert.ok(error instanceof SafeAuthError)
    const rendered = `${error.name} ${error.message} ${error.stack}`
    for (const secret of secrets) assert.equal(rendered.includes(secret), false)
  }
  assert.equal(pagination.requests.length, 1)
})
