import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import Database from 'better-sqlite3'

import { REFRESH_SKEW_SECONDS } from '../dist/oauth/constants.js'
import { ReauthorizationRequiredError, ZendeskUpstreamError } from '../dist/oauth/errors.js'
import { ZendeskClientResolver } from '../dist/oauth/zendesk-client-resolver.js'
import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher } from '../dist/oauth/token-cipher.js'

const NOW = 1_700_000_000
const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const RESOURCE = 'https://broker.example.test/mcp'
const MCP_SCOPES = ['zendesk:read', 'zendesk:write']
const ZENDESK_SCOPES = ['read', 'tickets:write']
const VALID_CLIENT = {
  redirect_uris: [REDIRECT_URI],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'Codex Desktop',
  scope: MCP_SCOPES.join(' '),
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, reject, resolve }
}

function grant(label, accessExpiresAt = NOW + 3_600) {
  return {
    accessToken: `access-${label}-SENTINEL`,
    refreshToken: `refresh-${label}-SENTINEL`,
    accessExpiresAt,
    refreshExpiresAt: NOW + 86_400,
    scopes: [...ZENDESK_SCOPES],
  }
}

function unauthorizedResponse() {
  return new Response(JSON.stringify({ error: 'unauthorized' }), {
    status: 401,
    headers: { 'content-type': 'application/json' },
  })
}

function ticketResponse(id = 42) {
  return new Response(JSON.stringify({ ticket: { id, subject: `ticket-${id}` } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-client-resolver-races-'))
  const path = join(directory, 'oauth.sqlite')
  const clock = { value: NOW }
  const store = openSqliteOAuthStore({
    path,
    cipher: new TokenCipher(Buffer.alloc(32, 83)),
    mcpResourceUrl: new URL(RESOURCE),
    now: () => clock.value,
  })
  t.after(() => store.close())
  const client = store.registerClient(VALID_CLIENT)
  return { client, clock, path, store }
}

function beginCallback(store, clientId, label, now = NOW) {
  const started = store.beginLogin({
    clientId,
    redirectUri: REDIRECT_URI,
    codeChallenge: 'C'.repeat(43),
    scopes: [...MCP_SCOPES],
    resource: RESOURCE,
    originalState: `state-${label}`,
    subdomain: 'example',
    now,
  })
  const decision = store.decideConsent({
    transactionToken: started.transactionToken,
    consentCsrf: started.consentCsrf,
    browserNonce: started.browserNonce,
    decision: 'confirm',
    now,
  })
  assert.equal(decision.kind, 'confirmed')
  const callback = store.claimZendeskCallback(decision.upstreamState, now)
  assert.ok(callback)
  return callback
}

function prepareLogin(store, clientId, zendeskUserId, installedGrant, label, now = NOW) {
  const callback = beginCallback(store, clientId, label, now)
  const staged = store.stageLoginGrant({
    transactionId: callback.transactionId,
    subdomain: 'example',
    grant: installedGrant,
    now,
  })
  return {
    commit() {
      return store.commitLogin({
        transactionId: callback.transactionId,
        stageId: staged.stageId,
        zendeskUserId,
        now,
      })
    },
  }
}

function installPrincipal(store, clientId, zendeskUserId, installedGrant, label, now = NOW) {
  return prepareLogin(store, clientId, zendeskUserId, installedGrant, label, now).commit()
}

function issueFamily(store, clientId, authorizationCode, now = NOW) {
  return store.consumeCodeAndIssueFamily({
    clientId,
    authorizationCode,
    redirectUri: REDIRECT_URI,
    resource: RESOURCE,
    now,
    accessTokenTtlSeconds: 300,
  })
}

function gateway(overrides = {}) {
  return {
    createAuthorizationUrl() {
      assert.fail('resolver must not create an authorization URL')
    },
    async exchangeAuthorizationCode() {
      assert.fail('resolver must not exchange an authorization code')
    },
    async refreshCredential() {
      assert.fail('unexpected credential refresh')
    },
    async getCurrentUser() {
      assert.fail('unexpected users/me request')
    },
    async revokeCurrentToken() {
      assert.fail('resolver must never perform upstream cleanup')
    },
    ...overrides,
  }
}

function resolver(options) {
  return new ZendeskClientResolver({
    subdomain: 'example',
    refreshSkewSeconds: REFRESH_SKEW_SECONDS,
    timeoutMs: 1_000,
    ...options,
  })
}

function rows(path, sql, ...params) {
  const db = new Database(path, { readonly: true })
  try {
    return db.prepare(sql).all(...params)
  } finally {
    db.close()
  }
}

function authorization(init) {
  return new Headers(init?.headers).get('authorization')
}

test('an old 401 after proactive refresh adopts the newer snapshot without another refresh', async (t) => {
  const f = await fixture(t)
  const initial = grant('proactive-old', NOW + REFRESH_SKEW_SECONDS + 10)
  const rotated = grant('proactive-new')
  const principal = installPrincipal(f.store, f.client.client_id, '101', initial, 'proactive')
  const entered = deferred()
  const release = deferred()
  const authorizations = []
  let refreshCalls = 0
  const clientResolver = resolver({
    store: f.store,
    now: () => f.clock.value,
    zendesk: gateway({
      async refreshCredential(refreshToken) {
        refreshCalls += 1
        assert.equal(refreshToken, initial.refreshToken)
        entered.resolve()
        await release.promise
        return rotated
      },
      async getCurrentUser(accessToken) {
        assert.equal(accessToken, rotated.accessToken)
        return { zendeskUserId: '101' }
      },
    }),
    fetch: async (_input, init) => {
      const header = authorization(init)
      authorizations.push(header)
      return header === `Bearer ${initial.accessToken}` ? unauthorizedResponse() : ticketResponse()
    },
  })

  const oldClient = await clientResolver.resolve(principal.principalId)
  f.clock.value = NOW + 11
  const proactive = clientResolver.resolve(principal.principalId)
  await entered.promise
  assert.equal(refreshCalls, 1)
  release.resolve()
  await proactive

  assert.equal((await oldClient.getTicket(42)).id, 42)
  assert.equal(refreshCalls, 1)
  assert.deepEqual(authorizations, [
    `Bearer ${initial.accessToken}`,
    `Bearer ${rotated.accessToken}`,
  ])
})

test('a current 401 refreshes through one controlled flight and retries the request exactly once', async (t) => {
  const f = await fixture(t)
  const initial = grant('current-old')
  const rotated = grant('current-new')
  const principal = installPrincipal(f.store, f.client.client_id, '202', initial, 'current')
  const entered = deferred()
  const release = deferred()
  const authorizations = []
  let refreshCalls = 0
  const clientResolver = resolver({
    store: f.store,
    now: () => f.clock.value,
    zendesk: gateway({
      async refreshCredential(refreshToken) {
        refreshCalls += 1
        assert.equal(refreshToken, initial.refreshToken)
        entered.resolve()
        await release.promise
        return rotated
      },
      async getCurrentUser(accessToken) {
        assert.equal(accessToken, rotated.accessToken)
        return { zendeskUserId: '202' }
      },
    }),
    fetch: async (_input, init) => {
      authorizations.push(authorization(init))
      return authorizations.length === 1 ? unauthorizedResponse() : ticketResponse()
    },
  })

  const client = await clientResolver.resolve(principal.principalId)
  const pending = client.getTicket(42)
  await entered.promise
  assert.deepEqual(authorizations, [`Bearer ${initial.accessToken}`])
  release.resolve()

  assert.equal((await pending).id, 42)
  assert.equal(refreshCalls, 1)
  assert.deepEqual(authorizations, [
    `Bearer ${initial.accessToken}`,
    `Bearer ${rotated.accessToken}`,
  ])
  assert.deepEqual(f.store.loadCredential(principal.principalId).grant, rotated)
})

test('a second current 401 increments only that epoch, invalidates codes, and revokes its families', async (t) => {
  const f = await fixture(t)
  const first = installPrincipal(f.store, f.client.client_id, '303', grant('terminal-first'), 'terminal-first')
  issueFamily(f.store, f.client.client_id, first.authorizationCode)
  const active = grant('terminal-active')
  const pendingCode = installPrincipal(
    f.store,
    f.client.client_id,
    '303',
    active,
    'terminal-pending-code',
    NOW + 1,
  )
  const rotated = grant('terminal-refreshed')
  f.clock.value = NOW + 2
  let fetchCalls = 0
  const clientResolver = resolver({
    store: f.store,
    now: () => f.clock.value,
    zendesk: gateway({
      async refreshCredential(refreshToken) {
        assert.equal(refreshToken, active.refreshToken)
        return rotated
      },
      async getCurrentUser() {
        return { zendeskUserId: '303' }
      },
    }),
    fetch: async () => {
      fetchCalls += 1
      return unauthorizedResponse()
    },
  })

  const client = await clientResolver.resolve(pendingCode.principalId)
  await assert.rejects(
    client.getTicket(42),
    (error) => error instanceof ReauthorizationRequiredError,
  )

  assert.equal(fetchCalls, 2)
  assert.deepEqual(rows(
    f.path,
    'SELECT status, lifecycle_epoch FROM principals WHERE id = ?',
    pendingCode.principalId,
  ), [{ status: 'reauthorization_required', lifecycle_epoch: 2 }])
  assert.deepEqual(rows(
    f.path,
    'SELECT credential_version, principal_epoch FROM zendesk_credentials WHERE principal_id = ?',
    pendingCode.principalId,
  ), [{ credential_version: 3, principal_epoch: 1 }])
  assert.equal(rows(
    f.path,
    'SELECT COUNT(*) AS count FROM authorization_codes WHERE principal_id = ? AND consumed_at IS NULL',
    pendingCode.principalId,
  )[0].count, 0)
  assert.deepEqual(rows(
    f.path,
    'SELECT revoked_at, revoke_reason FROM token_families WHERE principal_id = ?',
    pendingCode.principalId,
  ), [{ revoked_at: f.clock.value, revoke_reason: 'principal_reauthorization_required' }])
  assert.deepEqual(rows(f.path, 'SELECT * FROM staged_grants'), [])
})

test('invalid_grant racing a newer login loses the guard without revoking the winner or families', async (t) => {
  const f = await fixture(t)
  const initial = grant('invalid-grant-old')
  const first = installPrincipal(f.store, f.client.client_id, '404', initial, 'invalid-grant-old')
  issueFamily(f.store, f.client.client_id, first.authorizationCode)
  const entered = deferred()
  const release = deferred()
  const winner = grant('invalid-grant-winner')
  let fetchCalls = 0
  const clientResolver = resolver({
    store: f.store,
    now: () => f.clock.value,
    zendesk: gateway({
      async refreshCredential(refreshToken) {
        assert.equal(refreshToken, initial.refreshToken)
        entered.resolve()
        await release.promise
        throw new ZendeskUpstreamError('invalid_grant', 400, false, 'invalid-grant-race')
      },
    }),
    fetch: async () => {
      fetchCalls += 1
      return unauthorizedResponse()
    },
  })

  const client = await clientResolver.resolve(first.principalId)
  const pending = client.getTicket(42)
  await entered.promise
  installPrincipal(f.store, f.client.client_id, '404', winner, 'invalid-grant-winner', NOW + 1)
  release.resolve()

  await assert.rejects(pending, (error) => {
    assert.ok(error instanceof ZendeskUpstreamError)
    assert.equal(error.category, 'unauthorized')
    return true
  })
  assert.equal(fetchCalls, 1)
  assert.deepEqual(f.store.loadCredential(first.principalId).grant, winner)
  assert.deepEqual(rows(
    f.path,
    'SELECT status, lifecycle_epoch FROM principals WHERE id = ?',
    first.principalId,
  ), [{ status: 'active', lifecycle_epoch: 1 }])
  assert.deepEqual(rows(
    f.path,
    'SELECT revoked_at, revoke_reason FROM token_families WHERE principal_id = ?',
    first.principalId,
  ), [{ revoked_at: null, revoke_reason: null }])
})

test('refresh versus two concurrent logins adopts the last winner with zero upstream cleanup', async (t) => {
  const f = await fixture(t)
  const initial = grant('login-race-old')
  const refreshLoser = grant('login-race-refresh-loser')
  const loginOne = grant('login-race-one')
  const loginWinner = grant('login-race-winner')
  const first = installPrincipal(f.store, f.client.client_id, '505', initial, 'login-race-old')
  const entered = deferred()
  const release = deferred()
  const cleanupCalls = []
  const authorizations = []
  const clientResolver = resolver({
    store: f.store,
    now: () => f.clock.value,
    zendesk: gateway({
      async refreshCredential() {
        entered.resolve()
        await release.promise
        return refreshLoser
      },
      async getCurrentUser() {
        return { zendeskUserId: '505' }
      },
      async revokeCurrentToken(accessToken) {
        cleanupCalls.push(accessToken)
      },
    }),
    fetch: async (_input, init) => {
      const header = authorization(init)
      authorizations.push(header)
      return header === `Bearer ${initial.accessToken}` ? unauthorizedResponse() : ticketResponse()
    },
  })

  const client = await clientResolver.resolve(first.principalId)
  const pendingRequest = client.getTicket(42)
  await entered.promise
  const preparedOne = prepareLogin(
    f.store,
    f.client.client_id,
    '505',
    loginOne,
    'login-race-one',
    NOW + 1,
  )
  const preparedWinner = prepareLogin(
    f.store,
    f.client.client_id,
    '505',
    loginWinner,
    'login-race-winner',
    NOW + 2,
  )
  await Promise.all([
    Promise.resolve().then(() => preparedOne.commit()),
    Promise.resolve().then(() => preparedWinner.commit()),
  ])
  release.resolve()

  assert.equal((await pendingRequest).id, 42)
  assert.deepEqual(f.store.loadCredential(first.principalId).grant, loginWinner)
  assert.deepEqual(authorizations, [
    `Bearer ${initial.accessToken}`,
    `Bearer ${loginWinner.accessToken}`,
  ])
  assert.deepEqual(cleanupCalls, [])
  assert.deepEqual(rows(f.path, 'SELECT * FROM staged_grants'), [])
})

test('disconnect winning against refresh prevents installation and cannot resurrect credentials', async (t) => {
  const f = await fixture(t)
  const initial = grant('disconnect-old')
  const refreshLoser = grant('disconnect-refresh-loser')
  const first = installPrincipal(f.store, f.client.client_id, '606', initial, 'disconnect-old')
  const entered = deferred()
  const release = deferred()
  const cleanupCalls = []
  const clientResolver = resolver({
    store: f.store,
    now: () => f.clock.value,
    zendesk: gateway({
      async refreshCredential() {
        entered.resolve()
        await release.promise
        return refreshLoser
      },
      async getCurrentUser() {
        return { zendeskUserId: '606' }
      },
      async revokeCurrentToken(accessToken) {
        cleanupCalls.push(accessToken)
      },
    }),
    fetch: async () => unauthorizedResponse(),
  })

  const client = await clientResolver.resolve(first.principalId)
  const pending = client.getTicket(42)
  await entered.promise
  assert.equal(f.store.disconnectUser('example', '606', NOW + 1).kind, 'disconnected')
  release.resolve()

  await assert.rejects(pending, (error) => {
    assert.ok(error instanceof ZendeskUpstreamError)
    assert.equal(error.category, 'unauthorized')
    return true
  })
  assert.equal(f.store.loadCredential(first.principalId), undefined)
  assert.deepEqual(rows(
    f.path,
    'SELECT status, lifecycle_epoch FROM principals WHERE id = ?',
    first.principalId,
  ), [{ status: 'disconnected', lifecycle_epoch: 2 }])
  assert.deepEqual(rows(f.path, 'SELECT * FROM zendesk_credentials'), [])
  assert.deepEqual(rows(f.path, 'SELECT * FROM staged_grants'), [])
  assert.deepEqual(cleanupCalls, [])
})

test('a newer login before terminal handling makes the second 401 a stale_failure', async (t) => {
  const f = await fixture(t)
  const initial = grant('stale-terminal-old')
  const first = installPrincipal(f.store, f.client.client_id, '707', initial, 'stale-terminal-old')
  issueFamily(f.store, f.client.client_id, first.authorizationCode)
  const refreshed = grant('stale-terminal-refreshed')
  const winner = grant('stale-terminal-winner')
  const secondFetchEntered = deferred()
  const secondFetchRelease = deferred()
  let fetchCalls = 0
  const clientResolver = resolver({
    store: f.store,
    now: () => f.clock.value,
    zendesk: gateway({
      async refreshCredential() {
        return refreshed
      },
      async getCurrentUser() {
        return { zendeskUserId: '707' }
      },
    }),
    fetch: async () => {
      fetchCalls += 1
      if (fetchCalls === 2) {
        secondFetchEntered.resolve()
        await secondFetchRelease.promise
      }
      return unauthorizedResponse()
    },
  })

  const client = await clientResolver.resolve(first.principalId)
  const pending = client.getTicket(42)
  await secondFetchEntered.promise
  installPrincipal(f.store, f.client.client_id, '707', winner, 'stale-terminal-winner', NOW + 1)
  secondFetchRelease.resolve()

  await assert.rejects(pending, (error) => {
    assert.ok(error instanceof ZendeskUpstreamError)
    assert.equal(error.category, 'unauthorized')
    assert.equal(error instanceof ReauthorizationRequiredError, false)
    return true
  })
  assert.equal(fetchCalls, 2)
  assert.deepEqual(f.store.loadCredential(first.principalId).grant, winner)
  assert.deepEqual(rows(
    f.path,
    'SELECT status, lifecycle_epoch FROM principals WHERE id = ?',
    first.principalId,
  ), [{ status: 'active', lifecycle_epoch: 1 }])
  assert.deepEqual(rows(
    f.path,
    'SELECT revoked_at, revoke_reason FROM token_families WHERE principal_id = ?',
    first.principalId,
  ), [{ revoked_at: null, revoke_reason: null }])
})

test('A invalid_grant and its blocked refresh cache do not delay or mutate B', async (t) => {
  const f = await fixture(t)
  const oldA = grant('isolation-a-old')
  const oldB = grant('isolation-b-old')
  const newB = grant('isolation-b-new')
  const principalA = installPrincipal(f.store, f.client.client_id, '808', oldA, 'isolation-a')
  const principalB = installPrincipal(f.store, f.client.client_id, '809', oldB, 'isolation-b')
  const enteredA = deferred()
  const releaseA = deferred()
  const authorizations = []
  const cleanupCalls = []
  const clientResolver = resolver({
    store: f.store,
    now: () => f.clock.value,
    zendesk: gateway({
      async refreshCredential(refreshToken) {
        if (refreshToken === oldA.refreshToken) {
          enteredA.resolve()
          await releaseA.promise
          throw new ZendeskUpstreamError('invalid_grant', 400, false, 'principal-a-invalid')
        }
        assert.equal(refreshToken, oldB.refreshToken)
        return newB
      },
      async getCurrentUser(accessToken) {
        assert.equal(accessToken, newB.accessToken)
        return { zendeskUserId: '809' }
      },
      async revokeCurrentToken(accessToken) {
        cleanupCalls.push(accessToken)
      },
    }),
    fetch: async (_input, init) => {
      const header = authorization(init)
      authorizations.push(header)
      if (header === `Bearer ${newB.accessToken}`) return ticketResponse(809)
      return unauthorizedResponse()
    },
  })

  const clientA = await clientResolver.resolve(principalA.principalId)
  const clientB = await clientResolver.resolve(principalB.principalId)
  const pendingA = clientA.getTicket(42)
  const pendingB = clientB.getTicket(42)
  await enteredA.promise

  assert.equal((await pendingB).id, 809)
  assert.equal(f.store.loadCredential(principalA.principalId).credentialVersion, 1)
  assert.equal(f.store.loadCredential(principalB.principalId).credentialVersion, 2)
  releaseA.resolve()
  await assert.rejects(pendingA, (error) => error instanceof ReauthorizationRequiredError)

  assert.equal(f.store.loadCredential(principalA.principalId), undefined)
  assert.deepEqual(f.store.loadCredential(principalB.principalId).grant, newB)
  assert.deepEqual(rows(
    f.path,
    'SELECT zendesk_user_id, status, lifecycle_epoch FROM principals ORDER BY zendesk_user_id',
  ), [
    { zendesk_user_id: '808', status: 'reauthorization_required', lifecycle_epoch: 2 },
    { zendesk_user_id: '809', status: 'active', lifecycle_epoch: 1 },
  ])
  assert.deepEqual(cleanupCalls, [])
  assert.deepEqual(new Set(authorizations), new Set([
    `Bearer ${oldA.accessToken}`,
    `Bearer ${oldB.accessToken}`,
    `Bearer ${newB.accessToken}`,
  ]))
})
