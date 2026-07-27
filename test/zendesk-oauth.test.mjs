import assert from 'node:assert/strict'
import test from 'node:test'

import { randomOpaque } from '../dist/internal-auth/crypto.js'
import { SafeAuthError } from '../dist/internal-auth/errors.js'
import { ZendeskOAuthClient } from '../dist/internal-auth/zendesk-oauth.js'

const NOW = 1_700_000_000
const CALLBACK = new URL('https://mcp.example.test/oauth/callback')

function response(body, status = 200, headers = {}) {
  return new Response(
    body === undefined ? undefined : JSON.stringify(body),
    {
      status,
      headers: {
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        ...headers,
      },
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
      const url = input instanceof URL ? input : new URL(String(input))
      requests.push({
        url: url.href,
        method: init.method ?? 'GET',
        redirect: init.redirect,
        authorization: new Headers(init.headers).get('authorization'),
        contentType: new Headers(init.headers).get('content-type'),
        body: typeof init.body === 'string' ? JSON.parse(init.body) : undefined,
      })
      const next = queued.shift()
      assert.notEqual(next, undefined, 'unexpected Zendesk fetch')
      if (typeof next === 'function') return next(init.signal)
      return Promise.resolve(next)
    },
  }
}

function tokenBody(overrides = {}) {
  return {
    access_token: 'access-rotated-sentinel',
    refresh_token: 'refresh-rotated-sentinel',
    token_type: 'bearer',
    scope: 'read tickets:write',
    expires_in: 1_800,
    refresh_token_expires_in: 2_592_000,
    ...overrides,
  }
}

function fixture(overrides = {}) {
  const fake = fakeFetch()
  const client = new ZendeskOAuthClient({
    subdomain: 'acme',
    clientId: 'client-id-sentinel',
    clientSecret: 'client-secret-sentinel',
    callbackUrl: CALLBACK,
    timeoutMs: 50,
    fetch: fake.fetch,
    now: () => NOW,
    ...overrides,
  })
  return { client, fake }
}

test('builds only the fixed authorization URL with renewable least privilege', () => {
  const { client } = fixture()
  const state = randomOpaque()
  const url = client.authorizationUrl(state)

  assert.equal(url.origin, 'https://acme.zendesk.com')
  assert.equal(url.pathname, '/oauth/authorizations/new')
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    response_type: 'code',
    client_id: 'client-id-sentinel',
    redirect_uri: CALLBACK.href,
    scope: 'read tickets:write',
    state,
    expires_in: '1800',
    refresh_token_expires_in: '2592000',
  })
  assert.equal([...url.searchParams].length, 7)
})

test('exchanges and refreshes rotating token pairs at the fixed endpoint', async () => {
  const { client, fake } = fixture()
  fake.queue(response(tokenBody({ scope: 'tickets:write read' })))
  fake.queue(response(tokenBody({
    access_token: 'access-second-sentinel',
    refresh_token: 'refresh-second-sentinel',
  })))

  assert.deepEqual(await client.exchangeCode('code-sentinel'), {
    accessToken: 'access-rotated-sentinel',
    refreshToken: 'refresh-rotated-sentinel',
    accessExpiresAt: NOW + 1_800,
    refreshExpiresAt: NOW + 2_592_000,
    scopes: ['read', 'tickets:write'],
  })
  assert.deepEqual(await client.refresh('refresh-old-sentinel'), {
    accessToken: 'access-second-sentinel',
    refreshToken: 'refresh-second-sentinel',
    accessExpiresAt: NOW + 1_800,
    refreshExpiresAt: NOW + 2_592_000,
    scopes: ['read', 'tickets:write'],
  })

  assert.deepEqual(fake.requests, [
    {
      url: 'https://acme.zendesk.com/oauth/tokens',
      method: 'POST',
      redirect: 'error',
      authorization: null,
      contentType: 'application/json',
      body: {
        grant_type: 'authorization_code',
        code: 'code-sentinel',
        client_id: 'client-id-sentinel',
        client_secret: 'client-secret-sentinel',
        redirect_uri: CALLBACK.href,
        scope: 'read tickets:write',
        expires_in: 1_800,
        refresh_token_expires_in: 2_592_000,
      },
    },
    {
      url: 'https://acme.zendesk.com/oauth/tokens',
      method: 'POST',
      redirect: 'error',
      authorization: null,
      contentType: 'application/json',
      body: {
        grant_type: 'refresh_token',
        refresh_token: 'refresh-old-sentinel',
        client_id: 'client-id-sentinel',
        client_secret: 'client-secret-sentinel',
        scope: 'read tickets:write',
        expires_in: 1_800,
        refresh_token_expires_in: 2_592_000,
      },
    },
  ])
})

test('uses users/me as identity and the current-token revocation endpoint', async () => {
  const { client, fake } = fixture()
  fake.queue(response({
    user: {
      id: 424242,
      name: 'Martin Agent',
      email: 'martin@example.test',
      role: 'agent',
    },
  }))
  fake.queue(response(undefined, 204))

  assert.deepEqual(await client.currentUser('identity-token-sentinel'), {
    id: '424242',
    name: 'Martin Agent',
    email: 'martin@example.test',
    role: 'agent',
  })
  await client.revokeCurrent('revoke-token-sentinel')

  assert.deepEqual(fake.requests, [
    {
      url: 'https://acme.zendesk.com/api/v2/users/me.json',
      method: 'GET',
      redirect: 'error',
      authorization: 'Bearer identity-token-sentinel',
      contentType: null,
      body: undefined,
    },
    {
      url: 'https://acme.zendesk.com/api/v2/oauth/tokens/current.json',
      method: 'DELETE',
      redirect: 'error',
      authorization: 'Bearer revoke-token-sentinel',
      contentType: null,
      body: undefined,
    },
  ])
})

test('rejects malformed token and users/me identity responses', async () => {
  const invalidTokens = [
    tokenBody({ access_token: '' }),
    tokenBody({ refresh_token: undefined }),
    tokenBody({ token_type: 'mac' }),
    tokenBody({ scope: 'read write' }),
    tokenBody({ expires_in: 1_800.5 }),
    tokenBody({ refresh_token_expires_in: '2592000' }),
    tokenBody({ refresh_token_expires_in: 1_800 }),
    {},
    'not-an-object',
  ]

  for (const body of invalidTokens) {
    const { client, fake } = fixture()
    fake.queue(response(body))
    await assert.rejects(
      client.exchangeCode('code'),
      (error) => error instanceof SafeAuthError && error.category === 'invalid_response',
    )
  }

  for (const body of [
    {},
    { user: null },
    { user: { id: 0 } },
    { user: { id: 1.5 } },
    { user: { id: '42' } },
    { user: { id: 42 } },
    { user: { id: 42, role: 'owner' } },
    { user: { id: 42, role: 7 } },
    { user: { id: 42, name: 7 } },
    { user: { id: 42, email: [] } },
  ]) {
    const { client, fake } = fixture()
    fake.queue(response(body))
    await assert.rejects(
      client.currentUser('access'),
      (error) => error instanceof SafeAuthError && error.category === 'invalid_response',
    )
  }
})

test('classifies upstream failures without exposing their contents', async () => {
  const cases = [
    [400, { error: 'invalid_grant', description: 'body-secret-sentinel' }, 'invalid_grant', false],
    [401, { error: 'header-secret-sentinel' }, 'unauthorized', false],
    [403, { error: 'forbidden-secret-sentinel' }, 'forbidden', false],
    [429, { error: 'rate-secret-sentinel' }, 'rate_limited', true],
    [503, { error: 'upstream-secret-sentinel' }, 'temporarily_unavailable', true],
  ]

  for (const [status, body, category, retryable] of cases) {
    const { client, fake } = fixture()
    fake.queue(response(body, status))
    await assert.rejects(client.refresh('refresh-secret-sentinel'), (error) => {
      assert.ok(error instanceof SafeAuthError)
      assert.equal(error.category, category)
      assert.equal(error.retryable, retryable)
      assert.match(error.correlationId, /^[0-9a-f-]{36}$/)
      const rendered = `${error.name} ${error.message} ${error.stack}`
      for (const secret of [
        'body-secret-sentinel',
        'header-secret-sentinel',
        'forbidden-secret-sentinel',
        'rate-secret-sentinel',
        'upstream-secret-sentinel',
        'refresh-secret-sentinel',
      ]) {
        assert.equal(rendered.includes(secret), false)
      }
      return true
    })
  }
})

test('rejects redirects and aborts timeout, call, and shutdown work', async () => {
  const redirected = fixture()
  redirected.fake.queue(response(undefined, 302, {
    location: 'https://off-origin.example.test/stolen',
  }))
  await assert.rejects(
    redirected.client.exchangeCode('redirect-code-sentinel'),
    (error) => error instanceof SafeAuthError && error.category === 'temporarily_unavailable',
  )
  assert.equal(redirected.fake.requests.length, 1)

  for (const mode of ['timeout', 'call', 'shutdown']) {
    const shutdown = new AbortController()
    const { client, fake } = fixture({
      timeoutMs: mode === 'timeout' ? 5 : 5_000,
      signal: shutdown.signal,
    })
    let aborted = false
    fake.queue((signal) => new Promise((_resolve, reject) => {
      const onAbort = () => {
        aborted = true
        reject(new DOMException('transport-secret-sentinel', 'AbortError'))
      }
      signal.addEventListener('abort', onAbort, { once: true })
      if (signal.aborted) onAbort()
    }))

    const call = new AbortController()
    const pending = client.currentUser(
      'access-token-sentinel',
      mode === 'call' ? call.signal : undefined,
    )
    if (mode === 'call') call.abort(new Error('call-secret-sentinel'))
    if (mode === 'shutdown') shutdown.abort(new Error('shutdown-secret-sentinel'))

    await assert.rejects(pending, (error) => {
      assert.ok(error instanceof SafeAuthError)
      assert.equal(error.category, 'aborted')
      for (const secret of [
        'transport-secret-sentinel',
        'call-secret-sentinel',
        'shutdown-secret-sentinel',
        'access-token-sentinel',
      ]) {
        assert.equal(error.message.includes(secret), false)
      }
      return true
    })
    assert.equal(aborted, true)
    assert.equal(fake.requests.length, 1)
  }
})
