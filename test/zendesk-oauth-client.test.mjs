import assert from 'node:assert/strict'
import test from 'node:test'

import { ZendeskUpstreamError } from '../dist/oauth/errors.js'
import { ZendeskOAuthClient } from '../dist/oauth/zendesk-oauth-client.js'
import { createFakeZendesk } from './helpers/fake-zendesk.mjs'

const NOW = 1_700_000_000
const ORIGIN = 'https://acme.zendesk.com'
const CALLBACK_URL = new URL('https://broker.example.test/oauth/zendesk/callback')
const APPROVED_SCOPES = ['read', 'tickets:write']
const ACCESS_TTL = 1_800
const REFRESH_TTL = 2_592_000

function fixture(overrides = {}) {
  const fake = createFakeZendesk()
  const client = new ZendeskOAuthClient({
    subdomain: 'acme',
    clientId: 'client-id-sentinel',
    clientSecret: 'client-secret-sentinel',
    callbackUrl: CALLBACK_URL,
    scopes: APPROVED_SCOPES,
    timeoutMs: 50,
    fetch: fake.fetch,
    now: () => NOW,
    ...overrides,
  })
  return { client, fake }
}

function tokenResponse(overrides = {}) {
  return {
    access_token: 'access-token-rotated',
    refresh_token: 'refresh-token-rotated',
    token_type: 'bearer',
    scope: 'read tickets:write',
    expires_in: ACCESS_TTL,
    refresh_token_expires_in: REFRESH_TTL,
    ...overrides,
  }
}

async function captureConsole(run) {
  const output = []
  const originals = {}
  for (const name of ['log', 'info', 'warn', 'error']) {
    originals[name] = console[name]
    console[name] = (...values) => output.push(values.map(String).join(' '))
  }
  try {
    return { result: await run(), output }
  } finally {
    for (const [name, original] of Object.entries(originals)) console[name] = original
  }
}

test('builds only the fixed-host authorization endpoint and explicit renewable policy', () => {
  const { client } = fixture()
  const url = client.createAuthorizationUrl('state-sentinel')

  assert.equal(url.origin, ORIGIN)
  assert.equal(url.pathname, '/oauth/authorizations/new')
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    response_type: 'code',
    client_id: 'client-id-sentinel',
    redirect_uri: CALLBACK_URL.href,
    scope: 'read tickets:write',
    state: 'state-sentinel',
    expires_in: '1800',
    refresh_token_expires_in: '2592000',
  })
  assert.equal([...url.searchParams].length, 7)
})

test('exchanges a code once at the fixed token endpoint and returns integer epoch expiries', async () => {
  const { client, fake } = fixture()
  fake.queueResponse({ body: tokenResponse() })

  const grant = await client.exchangeAuthorizationCode('authorization-code-sentinel')

  assert.deepEqual(fake.requests, [{
    method: 'POST',
    url: `${ORIGIN}/oauth/tokens`,
    pathname: '/oauth/tokens',
    json: {
      grant_type: 'authorization_code',
      code: 'authorization-code-sentinel',
      client_id: 'client-id-sentinel',
      client_secret: 'client-secret-sentinel',
      redirect_uri: CALLBACK_URL.href,
      scope: 'read tickets:write',
      expires_in: ACCESS_TTL,
      refresh_token_expires_in: REFRESH_TTL,
    },
    form: undefined,
    authorizationScheme: undefined,
    redirect: 'error',
  }])
  assert.deepEqual(grant, {
    accessToken: 'access-token-rotated',
    refreshToken: 'refresh-token-rotated',
    accessExpiresAt: NOW + ACCESS_TTL,
    refreshExpiresAt: NOW + REFRESH_TTL,
    scopes: APPROVED_SCOPES,
  })
  assert.equal(Number.isInteger(grant.accessExpiresAt), true)
  assert.equal(Number.isInteger(grant.refreshExpiresAt), true)
  assert.equal(Number.isSafeInteger(grant.accessExpiresAt), true)
  assert.equal(Number.isSafeInteger(grant.refreshExpiresAt), true)
  fake.assertDrained()
})

test('refreshes once with the renewable policy and parses both rotated tokens', async () => {
  const { client, fake } = fixture()
  fake.queueResponse({ body: tokenResponse({
    access_token: 'new-access-token',
    refresh_token: 'new-refresh-token',
  }) })

  const grant = await client.refreshCredential('old-refresh-token-sentinel')

  assert.equal(fake.requests.length, 1)
  assert.deepEqual(fake.requests[0], {
    method: 'POST',
    url: `${ORIGIN}/oauth/tokens`,
    pathname: '/oauth/tokens',
    json: {
      grant_type: 'refresh_token',
      refresh_token: 'old-refresh-token-sentinel',
      client_id: 'client-id-sentinel',
      client_secret: 'client-secret-sentinel',
      scope: 'read tickets:write',
      expires_in: ACCESS_TTL,
      refresh_token_expires_in: REFRESH_TTL,
    },
    form: undefined,
    authorizationScheme: undefined,
    redirect: 'error',
  })
  assert.equal(grant.accessToken, 'new-access-token')
  assert.equal(grant.refreshToken, 'new-refresh-token')
})

test('rejects missing refresh token, wrong type/scopes, fractional expiries, and malformed bodies', async () => {
  const invalidBodies = [
    tokenResponse({ refresh_token: undefined }),
    tokenResponse({ token_type: 'mac' }),
    tokenResponse({ scope: 'tickets:write read' }),
    tokenResponse({ expires_in: 1800.5 }),
    tokenResponse({ refresh_token_expires_in: '2592000' }),
    { user: { id: 42 } },
    'not-json',
  ]

  for (const body of invalidBodies) {
    const { client, fake } = fixture()
    fake.queueResponse({ body })
    await assert.rejects(
      client.exchangeAuthorizationCode('code'),
      (error) => error instanceof ZendeskUpstreamError && error.category === 'invalid_response',
    )
    assert.equal(fake.requests.length, 1)
  }
})

test('rejects unsafe clocks, TTLs, epoch overflow, and refresh expiry not after access expiry', async () => {
  const cases = [
    { now: NOW, body: tokenResponse({ expires_in: Number.MAX_SAFE_INTEGER + 1 }) },
    { now: NOW, body: tokenResponse({ refresh_token_expires_in: Number.MAX_SAFE_INTEGER + 1 }) },
    { now: Number.NaN, body: tokenResponse() },
    { now: NOW + 0.5, body: tokenResponse() },
    { now: Number.MAX_SAFE_INTEGER - 1_000, body: tokenResponse() },
    { now: NOW, body: tokenResponse({ refresh_token_expires_in: ACCESS_TTL }) },
    { now: NOW, body: tokenResponse({ refresh_token_expires_in: ACCESS_TTL - 1 }) },
  ]

  for (const { now, body } of cases) {
    const { client, fake } = fixture({ now: () => now })
    fake.queueResponse({ body })
    await assert.rejects(
      client.exchangeAuthorizationCode('code-sentinel'),
      (error) => {
        assert.ok(error instanceof ZendeskUpstreamError)
        assert.equal(error.category, 'invalid_response')
        assert.equal(error.status, 200)
        assert.equal(error.retryable, false)
        return true
      },
    )
    assert.equal(fake.requests.length, 1)
  }
})

test('classifies upstream failures without retrying exchange or refresh', async () => {
  const cases = [
    [400, { error: 'invalid_grant' }, 'invalid_grant', false],
    [401, { error: 'body-sentinel' }, 'unauthorized', false],
    [403, { error: 'body-sentinel' }, 'forbidden', false],
    [429, { error: 'body-sentinel' }, 'rate_limited', true],
    [503, { error: 'body-sentinel' }, 'temporarily_unavailable', true],
  ]

  for (const [status, body, category, retryable] of cases) {
    for (const operation of ['exchange', 'refresh']) {
      const { client, fake } = fixture()
      fake.queueResponse({ status, body })
      const call = operation === 'exchange'
        ? client.exchangeAuthorizationCode('code-sentinel')
        : client.refreshCredential('refresh-sentinel')
      await assert.rejects(call, (error) => {
        assert.ok(error instanceof ZendeskUpstreamError)
        assert.equal(error.category, category)
        assert.equal(error.status, status)
        assert.equal(error.retryable, retryable)
        assert.match(error.correlationId, /^[0-9a-f-]{36}$/i)
        return true
      })
      assert.equal(fake.requests.length, 1)
    }
  }
})

test('uses fixed users/me and current-token revoke endpoints with Bearer authorization', async () => {
  const { client, fake } = fixture()
  fake.queueResponse({ body: { user: { id: 424242 } } })
  fake.queueResponse({ status: 204 })

  assert.deepEqual(await client.getCurrentUser('identity-token-sentinel'), { zendeskUserId: '424242' })
  await client.revokeCurrentToken('revoke-token-sentinel')

  assert.deepEqual(fake.requests.map(({ method, url, pathname, authorizationScheme, redirect }) => ({
    method,
    url,
    pathname,
    authorizationScheme,
    redirect,
  })), [
    {
      method: 'GET',
      url: `${ORIGIN}/api/v2/users/me.json`,
      pathname: '/api/v2/users/me.json',
      authorizationScheme: 'Bearer',
      redirect: 'error',
    },
    {
      method: 'DELETE',
      url: `${ORIGIN}/api/v2/oauth/tokens/current.json`,
      pathname: '/api/v2/oauth/tokens/current.json',
      authorizationScheme: 'Bearer',
      redirect: 'error',
    },
  ])
})

test('rejects invalid or unsafe current-user IDs as sanitized invalid responses', async () => {
  for (const body of [
    {},
    { user: null },
    { user: { id: 1.5 } },
    { user: { id: '' } },
    { user: { id: Number.MAX_SAFE_INTEGER + 1 } },
  ]) {
    const { client, fake } = fixture()
    fake.queueResponse({ body })
    await assert.rejects(
      client.getCurrentUser('access-token-sentinel'),
      (error) => error instanceof ZendeskUpstreamError && error.category === 'invalid_response',
    )
  }
})

test('does not follow redirect responses or make an off-origin fetch', async () => {
  const { client, fake } = fixture()
  fake.queueResponse({
    status: 302,
    headers: { location: 'https://off-origin.example.test/stolen' },
  })

  await assert.rejects(
    client.exchangeAuthorizationCode('redirect-code-sentinel'),
    (error) => error instanceof ZendeskUpstreamError && error.category === 'invalid_request',
  )
  assert.equal(fake.requests.length, 1)
  assert.deepEqual({
    method: fake.requests[0].method,
    url: fake.requests[0].url,
    redirect: fake.requests[0].redirect,
  }, {
    method: 'POST',
    url: `${ORIGIN}/oauth/tokens`,
    redirect: 'error',
  })
})

test('aborts hung requests on timeout, per-call abort, and shutdown without retrying', async () => {
  const timeoutFixture = fixture({ timeoutMs: 5 })
  const timeoutHung = timeoutFixture.fake.queueHung()
  await assert.rejects(
    timeoutFixture.client.exchangeAuthorizationCode('timeout-code-sentinel'),
    (error) => error instanceof ZendeskUpstreamError && error.category === 'aborted',
  )
  assert.equal(timeoutHung.aborted, true)
  assert.equal(timeoutFixture.fake.requests.length, 1)

  const perCallFixture = fixture({ timeoutMs: 5_000 })
  const perCallHung = perCallFixture.fake.queueHung()
  const perCall = new AbortController()
  const pendingRefresh = perCallFixture.client.refreshCredential('refresh-token-sentinel', perCall.signal)
  perCall.abort(new Error('abort-reason-sentinel'))
  await assert.rejects(
    pendingRefresh,
    (error) => error instanceof ZendeskUpstreamError && error.category === 'aborted',
  )
  assert.equal(perCallHung.aborted, true)
  assert.equal(perCallFixture.fake.requests.length, 1)

  const shutdown = new AbortController()
  const shutdownFixture = fixture({ timeoutMs: 5_000, shutdownSignal: shutdown.signal })
  const shutdownHung = shutdownFixture.fake.queueHung()
  const pendingIdentity = shutdownFixture.client.getCurrentUser('access-token-sentinel')
  shutdown.abort(new Error('shutdown-reason-sentinel'))
  await assert.rejects(
    pendingIdentity,
    (error) => error instanceof ZendeskUpstreamError && error.category === 'aborted',
  )
  assert.equal(shutdownHung.aborted, true)
  assert.equal(shutdownFixture.fake.requests.length, 1)
})

test('keeps timeout cancellation active while consuming a hung response body', async () => {
  const { client, fake } = fixture({ timeoutMs: 5 })
  const hungBody = fake.queueHungBody()

  const outcome = await Promise.race([
    client.exchangeAuthorizationCode('body-timeout-code').catch((error) => error),
    new Promise((resolve) => setTimeout(() => resolve('still-pending'), 30)),
  ])

  assert.notEqual(outcome, 'still-pending')
  assert.ok(outcome instanceof ZendeskUpstreamError)
  assert.equal(outcome.category, 'aborted')
  assert.equal(hungBody.aborted, true)
  assert.equal(fake.requests.length, 1)
})

test('never exposes upstream body, header, token, abort, or transport sentinels in errors or logs', async () => {
  const sentinels = [
    'body-secret-sentinel',
    'header-secret-sentinel',
    'access-token-sentinel',
    'abort-reason-sentinel',
    'transport-secret-sentinel',
  ]
  const failures = []

  const { output } = await captureConsole(async () => {
    const upstream = fixture()
    upstream.fake.queueResponse({
      status: 503,
      body: { error: sentinels[0] },
      headers: { 'x-secret': sentinels[1] },
    })
    failures.push(await upstream.client.getCurrentUser(sentinels[2]).catch((error) => error))

    const aborted = fixture({ timeoutMs: 5_000 })
    aborted.fake.queueHung()
    const controller = new AbortController()
    const pending = aborted.client.revokeCurrentToken(sentinels[2], controller.signal)
    controller.abort(new Error(sentinels[3]))
    failures.push(await pending.catch((error) => error))

    const transport = fixture()
    transport.fake.queueError(new Error(sentinels[4]))
    failures.push(await transport.client.refreshCredential('refresh-token-sentinel').catch((error) => error))
  })

  assert.equal(failures.length, 3)
  for (const error of failures) {
    assert.ok(error instanceof ZendeskUpstreamError)
    for (const sentinel of sentinels) assert.equal(error.message.includes(sentinel), false)
  }
  const logs = output.join('\n')
  for (const sentinel of sentinels) assert.equal(logs.includes(sentinel), false)
})
