import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import Database from 'better-sqlite3'

import { ZendeskCallbackController } from '../dist/oauth/zendesk-callback.js'
import { ZendeskUpstreamError } from '../dist/oauth/errors.js'
import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher, randomOpaque } from '../dist/oauth/token-cipher.js'

const NOW = 1_700_000_000
const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const RESOURCE = 'https://broker.example.test/mcp'
const CODE_CHALLENGE = 'C'.repeat(43)
const SCOPES = ['zendesk:read', 'zendesk:write']
const VALID_CLIENT = {
  redirect_uris: [REDIRECT_URI],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'Codex Desktop',
  scope: SCOPES.join(' '),
}

function grant(label, now = NOW) {
  return {
    accessToken: `access-${label}`,
    refreshToken: `refresh-${label}`,
    accessExpiresAt: now + 1_800,
    refreshExpiresAt: now + 2_592_000,
    scopes: ['read', 'tickets:write'],
  }
}

function rows(path, sql, parameters = []) {
  const db = new Database(path, { readonly: true })
  try {
    return db.prepare(sql).all(...parameters)
  } finally {
    db.close()
  }
}

function wrapStore(store, overrides = {}) {
  return new Proxy(store, {
    get(target, property) {
      if (Object.hasOwn(overrides, property)) return overrides[property]
      const value = Reflect.get(target, property)
      return typeof value === 'function' ? value.bind(target) : value
    },
  })
}

function response(events = [], options = {}) {
  return {
    body: undefined,
    headers: new Map(),
    location: undefined,
    statusCode: 200,
    setHeader(name, value) {
      this.headers.set(name.toLowerCase(), String(value))
      return this
    },
    status(value) {
      this.statusCode = value
      return this
    },
    type(value) {
      this.headers.set('content-type', value === 'html' ? 'text/html' : value)
      return this
    },
    send(value) {
      this.body = String(value)
      return this
    },
    redirect(status, location) {
      events.push('redirect')
      if (options.redirectFailure) throw options.redirectFailure
      this.statusCode = status
      this.location = String(location)
      return this
    },
  }
}

function callbackRequest(query) {
  return { query }
}

async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-callback-'))
  const path = join(directory, 'oauth.sqlite')
  const currentTime = options.currentTime ?? { value: NOW }
  const events = []
  const cleanupCalls = []
  const discardCalls = []
  const exchangeCalls = []
  const failLoginCalls = []
  const identityCalls = []
  let activeResponse
  let lastResponse

  const store = openSqliteOAuthStore({
    path,
    cipher: new TokenCipher(Buffer.alloc(32, options.keyByte ?? 83)),
    mcpResourceUrl: new URL(RESOURCE),
    now: () => currentTime.value,
    testHooks: options.beforeLoginCommit
      ? { beforeLoginCommit: () => options.beforeLoginCommit({ activeResponse, path }) }
      : undefined,
  })
  t.after(() => store.close())
  const client = store.registerClient(VALID_CLIENT)

  const gateway = {
    createAuthorizationUrl: () => assert.fail('unexpected authorization URL creation'),
    async exchangeAuthorizationCode(code) {
      events.push('exchange')
      exchangeCalls.push(code)
      if (options.exchange) return options.exchange(code, currentTime.value)
      return grant(code, currentTime.value)
    },
    async refreshCredential() {
      assert.fail('unexpected Zendesk refresh')
    },
    async getCurrentUser(accessToken) {
      events.push('users/me')
      identityCalls.push(accessToken)
      if (options.identity) return options.identity(accessToken)
      return { zendeskUserId: options.zendeskUserId ?? '101' }
    },
    async revokeCurrentToken(accessToken) {
      cleanupCalls.push(accessToken)
      assert.fail('callback must not perform upstream cleanup')
    },
  }

  const overrides = { ...options.storeOverrides }
  const originalStage = overrides.stageLoginGrant
  overrides.stageLoginGrant = (input) => {
    events.push('stage')
    return originalStage ? originalStage(store, input) : store.stageLoginGrant(input)
  }
  const originalCommit = overrides.commitLogin
  overrides.commitLogin = (input) => {
    events.push('commit')
    return originalCommit ? originalCommit(store, input) : store.commitLogin(input)
  }
  const originalDiscard = overrides.discardStagedGrant
  overrides.discardStagedGrant = (stageId, now) => {
    discardCalls.push(stageId)
    return originalDiscard
      ? originalDiscard(store, stageId, now)
      : store.discardStagedGrant(stageId, now)
  }
  const originalFailLogin = overrides.failLogin
  overrides.failLogin = (transactionId, now) => {
    failLoginCalls.push(transactionId)
    return originalFailLogin
      ? originalFailLogin(store, transactionId, now)
      : store.failLogin(transactionId, now)
  }
  const controller = new ZendeskCallbackController({
    store: wrapStore(store, overrides),
    zendesk: gateway,
    subdomain: options.subdomain ?? 'example',
    now: () => currentTime.value,
  })

  async function invoke(query, responseOptions = {}) {
    const res = response(events, responseOptions)
    lastResponse = res
    activeResponse = res
    await controller.handle(callbackRequest(query), res)
    activeResponse = undefined
    return res
  }

  return {
    cleanupCalls,
    client,
    controller,
    currentTime,
    discardCalls,
    events,
    exchangeCalls,
    failLoginCalls,
    gateway,
    identityCalls,
    invoke,
    get lastResponse() { return lastResponse },
    path,
    store,
  }
}

function beginCallback(f, originalState = 'mcp-original-state', now = f.currentTime.value) {
  const started = f.store.beginLogin({
    clientId: f.client.client_id,
    redirectUri: REDIRECT_URI,
    codeChallenge: CODE_CHALLENGE,
    scopes: [...SCOPES],
    resource: RESOURCE,
    originalState,
    subdomain: 'example',
    now,
  })
  const confirmed = f.store.decideConsent({
    transactionToken: started.transactionToken,
    consentCsrf: started.consentCsrf,
    browserNonce: started.browserNonce,
    decision: 'confirm',
    now,
  })
  assert.equal(confirmed.kind, 'confirmed')
  return confirmed.upstreamState
}

function assertTrustedRedirect(res, error, state) {
  assert.equal(res.statusCode, 302)
  assert.ok(res.location)
  const redirect = new URL(res.location)
  assert.equal(redirect.origin + redirect.pathname, REDIRECT_URI)
  assert.deepEqual([...redirect.searchParams.keys()], ['error', 'state'])
  assert.equal(redirect.searchParams.get('error'), error)
  assert.equal(redirect.searchParams.get('state'), state)
  assert.equal(redirect.searchParams.has('code'), false)
}

function assertGenericUntrustedError(res, sentinels = []) {
  assert.equal(res.statusCode, 400)
  assert.equal(res.location, undefined)
  assert.equal(res.headers.get('cache-control'), 'no-store')
  assert.match(res.headers.get('content-type'), /^text\/html/)
  assert.match(res.body, /correlation [0-9a-f-]{36}/i)
  assert.doesNotMatch(res.body, /Zendesk|OAuth|state|code|token/i)
  for (const sentinel of sentinels) assert.equal(res.body.includes(sentinel), false)
}

test('success orders exchange, encrypted stage, users/me, atomic commit, and redirect', async (t) => {
  let responseDuringCommit
  let committedCode
  const f = await fixture(t, {
    beforeLoginCommit: ({ activeResponse, path }) => {
      responseDuringCommit = activeResponse
      assert.equal(activeResponse.location, undefined, 'redirect must wait for commit')
      assert.equal(
        rows(path, 'SELECT code_hash FROM authorization_codes').length,
        0,
        'the MCP code must not be visible outside the uncommitted transaction',
      )
    },
    storeOverrides: {
      commitLogin(store, input) {
        const result = store.commitLogin(input)
        committedCode = result.authorizationCode
        return result
      },
    },
  })
  const originalState = 'byte-for-byte-%2F-✓-&-state'
  const upstreamState = beginCallback(f, originalState)

  const res = await f.invoke({ state: upstreamState, code: 'zendesk-code-sentinel' })

  assert.equal(responseDuringCommit.location, res.location)
  assert.deepEqual(f.events, ['exchange', 'stage', 'users/me', 'commit', 'redirect'])
  assert.deepEqual(f.exchangeCalls, ['zendesk-code-sentinel'])
  assert.deepEqual(f.identityCalls, ['access-zendesk-code-sentinel'])
  assert.deepEqual(f.cleanupCalls, [])
  assert.deepEqual(f.discardCalls, [])
  assert.deepEqual(f.failLoginCalls, [])
  assert.equal(res.statusCode, 302)
  const redirect = new URL(res.location)
  assert.equal(redirect.origin + redirect.pathname, REDIRECT_URI)
  assert.deepEqual([...redirect.searchParams.keys()], ['code', 'state'])
  assert.equal(redirect.searchParams.get('code'), committedCode)
  assert.equal(redirect.searchParams.get('state'), originalState)
  assert.notEqual(committedCode, 'zendesk-code-sentinel')
  assert.equal(f.store.challengeForAuthorizationCode(f.client.client_id, committedCode, NOW), CODE_CHALLENGE)
  assert.equal(rows(f.path, 'SELECT * FROM staged_grants').length, 0)
  assert.deepEqual(rows(
    f.path,
    'SELECT zendesk_user_id, status, lifecycle_epoch FROM principals',
  ), [{ zendesk_user_id: '101', status: 'active', lifecycle_epoch: 1 }])
})

test('a response disconnect after commit does not reclassify the completed login as failed', async (t) => {
  const f = await fixture(t)
  const upstreamState = beginCallback(f, 'disconnect-after-commit-state')
  const responseFailure = new Error('browser-disconnected-after-commit')

  await assert.rejects(
    f.invoke(
      { state: upstreamState, code: 'disconnect-after-commit-code' },
      { redirectFailure: responseFailure },
    ),
    responseFailure,
  )

  assert.deepEqual(f.events, ['exchange', 'stage', 'users/me', 'commit', 'redirect'])
  assert.deepEqual(f.discardCalls, [])
  assert.deepEqual(f.failLoginCalls, [])
  assert.equal(rows(f.path, 'SELECT * FROM authorization_codes').length, 1)
  assert.equal(rows(f.path, 'SELECT status FROM login_transactions WHERE status = ?', ['complete']).length, 1)
  assert.equal(rows(f.path, 'SELECT * FROM staged_grants').length, 0)
  assert.deepEqual(f.cleanupCalls, [])
})

test('claims state before handling denial or missing and non-scalar callback fields', async (t) => {
  const f = await fixture(t)

  const deniedState = beginCallback(f, 'denied-original-state')
  const denied = await f.invoke({
    state: deniedState,
    error: 'access_denied',
    error_description: 'upstream-secret-sentinel',
    code: 'must-not-be-exchanged',
  })
  assertTrustedRedirect(denied, 'access_denied', 'denied-original-state')
  assert.deepEqual(f.exchangeCalls, [])

  const missingState = beginCallback(f, 'missing-code-state')
  const missing = await f.invoke({ state: missingState })
  assertTrustedRedirect(missing, 'server_error', 'missing-code-state')

  const repeatedCodeState = beginCallback(f, 'repeated-code-state')
  const repeatedCode = await f.invoke({
    state: repeatedCodeState,
    code: ['one', 'two'],
  })
  assertTrustedRedirect(repeatedCode, 'server_error', 'repeated-code-state')

  const repeatedErrorState = beginCallback(f, 'repeated-error-state')
  const repeatedError = await f.invoke({
    state: repeatedErrorState,
    error: ['access_denied', 'server_error'],
    code: 'must-not-be-exchanged',
  })
  assertTrustedRedirect(repeatedError, 'server_error', 'repeated-error-state')

  assert.deepEqual(f.exchangeCalls, [])
  assert.deepEqual(f.identityCalls, [])
  assert.deepEqual(f.cleanupCalls, [])
})

test('unknown, expired, replayed, missing, and non-scalar state return only generic correlated HTML', async (t) => {
  const f = await fixture(t)
  const replayedState = beginCallback(f, 'replayed-original-secret')
  const first = await f.invoke({ state: replayedState, error: 'access_denied' })
  assertTrustedRedirect(first, 'access_denied', 'replayed-original-secret')

  const expiredState = beginCallback(f, 'expired-original-secret')
  f.currentTime.value = NOW + 600
  const cases = [
    [{ state: 'unknown-state-sentinel', code: 'code-secret-sentinel' }, ['unknown-state-sentinel', 'code-secret-sentinel']],
    [{ state: replayedState, error: 'access_denied' }, [replayedState, 'replayed-original-secret']],
    [{ state: expiredState, code: 'expired-code-secret' }, [expiredState, 'expired-code-secret', 'expired-original-secret']],
    [{ code: 'missing-state-code-secret' }, ['missing-state-code-secret']],
    [{ state: ['duplicate-state-one', 'duplicate-state-two'], code: 'code-secret' }, ['duplicate-state-one', 'duplicate-state-two', 'code-secret']],
    [{ state: { nested: 'object-state-secret' }, code: 'code-secret' }, ['object-state-secret', 'code-secret']],
  ]
  for (const [query, sentinels] of cases) {
    const res = await f.invoke(query)
    assertGenericUntrustedError(res, sentinels)
  }
  assert.deepEqual(f.exchangeCalls, [])
  assert.deepEqual(f.cleanupCalls, [])
})

test('a thrown state-claim infrastructure failure propagates without writing a response', async (t) => {
  const infrastructureFailure = new Error('sqlite-readiness-cipher-failure-sentinel')
  const f = await fixture(t, {
    storeOverrides: {
      claimZendeskCallback: () => { throw infrastructureFailure },
    },
  })

  await assert.rejects(
    f.invoke({ state: 'opaque-state-sentinel', code: 'code-must-not-be-read' }),
    (error) => error === infrastructureFailure,
  )

  assert.equal(f.lastResponse.statusCode, 200)
  assert.equal(f.lastResponse.body, undefined)
  assert.equal(f.lastResponse.location, undefined)
  assert.equal(f.lastResponse.headers.size, 0)
  assert.deepEqual(f.events, [])
  assert.deepEqual(f.exchangeCalls, [])
  assert.deepEqual(f.identityCalls, [])
  assert.deepEqual(f.cleanupCalls, [])
})

test('exchange failures redirect stably without staging or cleanup', async (t) => {
  const cases = [
    ['invalid exchange', new ZendeskUpstreamError('invalid_response', 200, false, randomOpaque()), 'server_error'],
    ['outage exchange', new ZendeskUpstreamError('temporarily_unavailable', 503, true, randomOpaque()), 'temporarily_unavailable'],
  ]

  for (const [label, failure, expectedError] of cases) {
    const f = await fixture(t, { exchange: async () => { throw failure } })
    const state = beginCallback(f, `${label}-state`)
    const res = await f.invoke({ state, code: `${label}-code` })

    assertTrustedRedirect(res, expectedError, `${label}-state`)
    assert.deepEqual(f.events, ['exchange', 'redirect'])
    assert.equal(rows(f.path, 'SELECT * FROM staged_grants').length, 0)
    assert.deepEqual(f.cleanupCalls, [])
  }
})

test('a pre-stage exception after successful exchange issues no code and performs no cleanup', async (t) => {
  let issuedGrant
  const f = await fixture(t, {
    exchange: async (code, now) => {
      issuedGrant = grant(code, now)
      return issuedGrant
    },
    storeOverrides: {
      stageLoginGrant(_store, input) {
        assert.equal(input.grant, issuedGrant, 'the issued grant reached the staging boundary')
        throw new Error('simulated-process-crash-before-stage-persist')
      },
    },
  })
  const state = beginCallback(f, 'crash-window-original-state')

  const res = await f.invoke({ state, code: 'crash-window-code' })

  assertTrustedRedirect(res, 'server_error', 'crash-window-original-state')
  assert.deepEqual(f.events, ['exchange', 'stage', 'redirect'])
  assert.ok(issuedGrant)
  assert.equal(rows(f.path, 'SELECT * FROM staged_grants').length, 0)
  assert.equal(rows(f.path, 'SELECT * FROM authorization_codes').length, 0)
  assert.equal(rows(f.path, 'SELECT * FROM zendesk_credentials').length, 0)
  assert.deepEqual(f.discardCalls, [])
  assert.equal(f.failLoginCalls.length, 1)
  assert.deepEqual(f.cleanupCalls, [])
})

test('stage, users/me, and commit failures never issue a code and discard every known stage locally', async (t) => {
  const cases = [
    {
      label: 'stage',
      options: {
        subdomain: 'not/a/subdomain',
      },
      expectedEvents: ['exchange', 'stage', 'redirect'],
      expectedStages: [],
    },
    {
      label: 'identity',
      options: {
        identity: async () => {
          throw new ZendeskUpstreamError('invalid_response', 200, false, randomOpaque())
        },
      },
      expectedEvents: ['exchange', 'stage', 'users/me', 'redirect'],
      expectedStages: ['discard_only'],
    },
    {
      label: 'identity outage',
      options: {
        identity: async () => {
          throw new ZendeskUpstreamError('temporarily_unavailable', 503, true, randomOpaque())
        },
      },
      expectedError: 'temporarily_unavailable',
      expectedEvents: ['exchange', 'stage', 'users/me', 'redirect'],
      expectedStages: ['discard_only'],
    },
    {
      label: 'commit',
      options: {
        storeOverrides: {
          commitLogin: () => { throw new Error('commit-secret-sentinel') },
        },
      },
      expectedEvents: ['exchange', 'stage', 'users/me', 'commit', 'redirect'],
      expectedStages: ['discard_only'],
    },
  ]

  for (const { label, options, expectedError = 'server_error', expectedEvents, expectedStages } of cases) {
    const f = await fixture(t, options)
    const state = beginCallback(f, `${label}-original-state`)
    const res = await f.invoke({ state, code: `${label}-code` })

    assertTrustedRedirect(res, expectedError, `${label}-original-state`)
    assert.deepEqual(f.events, expectedEvents)
    assert.deepEqual(
      rows(f.path, 'SELECT status FROM staged_grants ORDER BY id').map(({ status }) => status),
      expectedStages,
    )
    assert.equal(rows(f.path, 'SELECT * FROM authorization_codes').length, 0)
    assert.equal(rows(f.path, 'SELECT * FROM zendesk_credentials').length, 0)
    assert.deepEqual(f.cleanupCalls, [])
  }
})

test('concurrent re-login commits distinct MCP codes and last-writer credential version without cleanup', async (t) => {
  const waiting = []
  let releases
  const bothExchanged = new Promise((resolve) => { releases = resolve })
  const f = await fixture(t, {
    exchange: async (code, now) => {
      waiting.push(code)
      if (waiting.length === 2) releases()
      await bothExchanged
      return grant(code, now)
    },
    identity: async () => ({ zendeskUserId: '202' }),
  })
  const stateA = beginCallback(f, 'state-a')
  const stateB = beginCallback(f, 'state-b')

  const [a, b] = await Promise.all([
    f.invoke({ state: stateA, code: 'code-a' }),
    f.invoke({ state: stateB, code: 'code-b' }),
  ])

  const codeA = new URL(a.location).searchParams.get('code')
  const codeB = new URL(b.location).searchParams.get('code')
  assert.equal(a.statusCode, 302)
  assert.equal(b.statusCode, 302)
  assert.notEqual(codeA, codeB)
  assert.equal(rows(f.path, 'SELECT * FROM principals').length, 1)
  assert.deepEqual(
    rows(f.path, 'SELECT credential_version FROM zendesk_credentials'),
    [{ credential_version: 2 }],
  )
  assert.equal(rows(f.path, 'SELECT * FROM authorization_codes').length, 2)
  assert.equal(rows(f.path, 'SELECT * FROM staged_grants').length, 0)
  assert.deepEqual(f.cleanupCalls, [])
})

test('disconnect rejects an older in-flight login while a login begun afterward reactivates safely', async (t) => {
  const f = await fixture(t, { zendeskUserId: '303' })

  const initialState = beginCallback(f, 'initial-state')
  const initial = await f.invoke({ state: initialState, code: 'initial-code' })
  assert.equal(initial.statusCode, 302)

  const oldState = beginCallback(f, 'old-in-flight-state')
  f.currentTime.value = NOW + 1
  const disconnected = f.store.disconnectUser('example', '303', f.currentTime.value)
  assert.equal(disconnected.kind, 'disconnected')

  f.currentTime.value = NOW + 2
  f.events.length = 0
  const old = await f.invoke({ state: oldState, code: 'old-code' })
  assertTrustedRedirect(old, 'server_error', 'old-in-flight-state')
  assert.deepEqual(f.events, ['exchange', 'stage', 'users/me', 'commit', 'redirect'])
  assert.deepEqual(
    rows(f.path, 'SELECT status FROM staged_grants'),
    [{ status: 'discard_only' }],
  )

  const freshState = beginCallback(f, 'fresh-post-disconnect-state')
  f.events.length = 0
  const fresh = await f.invoke({ state: freshState, code: 'fresh-code' })
  assert.equal(fresh.statusCode, 302)
  assert.deepEqual(f.events, ['exchange', 'stage', 'users/me', 'commit', 'redirect'])
  assert.deepEqual(rows(
    f.path,
    'SELECT status, lifecycle_epoch, disconnected_at FROM principals WHERE zendesk_user_id = ?',
    ['303'],
  ), [{ status: 'active', lifecycle_epoch: 3, disconnected_at: null }])
  assert.equal(rows(f.path, 'SELECT * FROM revocation_outbox WHERE completed_at IS NULL').length, 0)
  assert.equal(rows(f.path, 'SELECT * FROM authorization_codes').length, 2)
  assert.deepEqual(f.cleanupCalls, [])
})
