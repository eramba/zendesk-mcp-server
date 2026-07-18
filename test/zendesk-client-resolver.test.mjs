import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import Database from 'better-sqlite3'

import { REFRESH_SKEW_SECONDS } from '../dist/oauth/constants.js'
import { ZendeskClientResolver } from '../dist/oauth/zendesk-client-resolver.js'
import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher } from '../dist/oauth/token-cipher.js'
import { ZendeskOAuthClient } from '../dist/oauth/zendesk-oauth-client.js'

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

function ticketResponse(id = 42) {
  return new Response(JSON.stringify({ ticket: { id, subject: `ticket-${id}` } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-client-resolver-'))
  const path = join(directory, 'oauth.sqlite')
  const cipher = new TokenCipher(Buffer.alloc(32, options.keyByte ?? 71))
  const clock = options.clock ?? { value: NOW }
  const store = openSqliteOAuthStore({
    path,
    cipher,
    mcpResourceUrl: new URL(RESOURCE),
    now: () => clock.value,
  })
  t.after(() => store.close())
  const client = store.registerClient(VALID_CLIENT)
  return { cipher, client, clock, directory, path, store }
}

function beginCallback(store, clientId, label, now = NOW, subdomain = 'example') {
  const started = store.beginLogin({
    clientId,
    redirectUri: REDIRECT_URI,
    codeChallenge: 'C'.repeat(43),
    scopes: [...MCP_SCOPES],
    resource: RESOURCE,
    originalState: `state-${label}`,
    subdomain,
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

function installPrincipal(store, clientId, zendeskUserId, installedGrant, label, now = NOW) {
  const callback = beginCallback(store, clientId, label, now)
  const staged = store.stageLoginGrant({
    transactionId: callback.transactionId,
    subdomain: 'example',
    grant: installedGrant,
    now,
  })
  return store.commitLogin({
    transactionId: callback.transactionId,
    stageId: staged.stageId,
    zendeskUserId,
    now,
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
      assert.fail('resolver must not perform upstream cleanup')
    },
    ...overrides,
  }
}

function resolver(options) {
  return new ZendeskClientResolver({
    subdomain: 'example',
    now: () => NOW,
    refreshSkewSeconds: REFRESH_SKEW_SECONDS,
    timeoutMs: 1_000,
    ...options,
  })
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

function rows(path, sql) {
  const db = new Database(path, { readonly: true })
  try {
    return db.prepare(sql).all()
  } finally {
    db.close()
  }
}

test('a valid credential creates a fresh Bearer client without refreshing upstream', async (t) => {
  const f = await fixture(t)
  const installed = grant('valid')
  const principal = installPrincipal(f.store, f.client.client_id, '101', installed, 'valid')
  const authorizations = []
  const clientResolver = resolver({
    store: f.store,
    zendesk: gateway(),
    fetch: async (_input, init) => {
      authorizations.push(new Headers(init?.headers).get('authorization'))
      return ticketResponse()
    },
  })

  const first = await clientResolver.resolve(principal.principalId)
  const second = await clientResolver.resolve(principal.principalId)
  assert.notEqual(first, second)
  assert.equal((await first.getTicket(42)).id, 42)
  assert.equal((await second.getTicket(42)).id, 42)
  assert.deepEqual(authorizations, [
    `Bearer ${installed.accessToken}`,
    `Bearer ${installed.accessToken}`,
  ])
})

test('ten simultaneous resolves share one refresh and users/me sequence', async (t) => {
  const f = await fixture(t)
  const initial = grant('single-flight-old', NOW + REFRESH_SKEW_SECONDS)
  const rotated = grant('single-flight-new')
  const principal = installPrincipal(f.store, f.client.client_id, '202', initial, 'single-flight')
  const release = deferred()
  let refreshCalls = 0
  let identityCalls = 0
  const authorizations = []
  const clientResolver = resolver({
    store: f.store,
    zendesk: gateway({
      async refreshCredential(refreshToken) {
        refreshCalls += 1
        assert.equal(refreshToken, initial.refreshToken)
        await release.promise
        return rotated
      },
      async getCurrentUser(accessToken) {
        identityCalls += 1
        assert.equal(accessToken, rotated.accessToken)
        return { zendeskUserId: '202' }
      },
    }),
    fetch: async (_input, init) => {
      authorizations.push(new Headers(init?.headers).get('authorization'))
      return ticketResponse()
    },
  })

  const pending = Array.from({ length: 10 }, () => clientResolver.resolve(principal.principalId))
  await new Promise((resolvePromise) => setImmediate(resolvePromise))
  assert.equal(refreshCalls, 1)
  release.resolve()
  const clients = await Promise.all(pending)
  await Promise.all(clients.map((client) => client.getTicket(42)))

  assert.equal(refreshCalls, 1)
  assert.equal(identityCalls, 1)
  assert.deepEqual(authorizations, Array(10).fill(`Bearer ${rotated.accessToken}`))
  assert.equal(f.store.loadCredential(principal.principalId).credentialVersion, 2)
})

test('principals A and B refresh independently without crossing errors or Authorization', async (t) => {
  const f = await fixture(t)
  const oldA = grant('a-old', NOW + 1)
  const oldB = grant('b-old', NOW + 1)
  const newB = grant('b-new')
  const principalA = installPrincipal(f.store, f.client.client_id, '301', oldA, 'principal-a')
  const principalB = installPrincipal(f.store, f.client.client_id, '302', oldB, 'principal-b')
  const entered = deferred()
  const release = deferred()
  const refreshTokens = []
  const authorizations = []
  let enteredCount = 0
  const clientResolver = resolver({
    store: f.store,
    zendesk: gateway({
      async refreshCredential(refreshToken) {
        refreshTokens.push(refreshToken)
        enteredCount += 1
        if (enteredCount === 2) entered.resolve()
        await release.promise
        if (refreshToken === oldA.refreshToken) throw new Error('principal-a-refresh-failure')
        assert.equal(refreshToken, oldB.refreshToken)
        return newB
      },
      async getCurrentUser(accessToken) {
        assert.equal(accessToken, newB.accessToken)
        return { zendeskUserId: '302' }
      },
    }),
    fetch: async (_input, init) => {
      authorizations.push(new Headers(init?.headers).get('authorization'))
      return ticketResponse()
    },
  })

  const pendingA = clientResolver.resolve(principalA.principalId)
  const pendingB = clientResolver.resolve(principalB.principalId)
  await entered.promise
  release.resolve()
  const [resultA, resultB] = await Promise.allSettled([pendingA, pendingB])

  assert.equal(resultA.status, 'rejected')
  assert.match(resultA.reason.message, /principal-a-refresh-failure/)
  assert.equal(resultB.status, 'fulfilled')
  await resultB.value.getTicket(42)
  assert.deepEqual(new Set(refreshTokens), new Set([oldA.refreshToken, oldB.refreshToken]))
  assert.deepEqual(authorizations, [`Bearer ${newB.accessToken}`])
})

test('refresh stages before users/me, requires the exact user, and persists rotation across reopen', async (t) => {
  const f = await fixture(t)
  const initial = grant('persist-old', NOW + 1)
  const rotated = grant('persist-rotated')
  const principal = installPrincipal(f.store, f.client.client_id, '401', initial, 'persist')
  const events = []
  const trackedStore = wrapStore(f.store, {
    stageRefreshGrant(input) {
      events.push('stage')
      return f.store.stageRefreshGrant(input)
    },
    installStagedRefresh(stageId, now) {
      events.push('install')
      return f.store.installStagedRefresh(stageId, now)
    },
  })
  const clientResolver = resolver({
    store: trackedStore,
    zendesk: gateway({
      async refreshCredential() {
        events.push('refresh')
        return rotated
      },
      async getCurrentUser() {
        events.push('users/me')
        return { zendeskUserId: '401' }
      },
    }),
    fetch: async () => ticketResponse(),
  })

  await clientResolver.resolve(principal.principalId)
  assert.deepEqual(events, ['refresh', 'stage', 'users/me', 'install'])
  assert.deepEqual(f.store.loadCredential(principal.principalId).grant, rotated)

  f.store.close()
  const reopened = openSqliteOAuthStore({
    path: f.path,
    cipher: f.cipher,
    mcpResourceUrl: new URL(RESOURCE),
    now: () => NOW,
  })
  t.after(() => reopened.close())
  assert.deepEqual(reopened.loadCredential(principal.principalId).grant, rotated)
})

test('recovery securely deletes an identity-mismatched refresh stage across reopen', async (t) => {
  const f = await fixture(t)
  const initial = grant('identity-old', NOW + 1)
  const rotated = grant('identity-wrong')
  const principal = installPrincipal(f.store, f.client.client_id, '402', initial, 'identity')
  const clientResolver = resolver({
    store: f.store,
    zendesk: gateway({
      async refreshCredential() {
        return rotated
      },
      async getCurrentUser() {
        return { zendeskUserId: 'not-402' }
      },
    }),
    fetch: async () => ticketResponse(),
  })

  await assert.rejects(clientResolver.resolve(principal.principalId), /identity/i)
  assert.deepEqual(f.store.loadCredential(principal.principalId).grant, initial)
  const discarded = rows(
    f.path,
    'SELECT purpose, status, encrypted_grant_json FROM staged_grants',
  )
  assert.equal(discarded.length, 1)
  assert.equal(discarded[0].purpose, 'refresh')
  assert.equal(discarded[0].status, 'discard_only')
  const encryptedStage = discarded[0].encrypted_grant_json

  f.store.recover(NOW)
  assert.deepEqual(rows(f.path, 'SELECT * FROM staged_grants'), [])
  const backup = join(f.directory, 'recovered.sqlite')
  await f.store.backup(backup)
  assert.equal((await readFile(backup)).includes(Buffer.from(encryptedStage, 'utf8')), false)

  f.store.close()
  const reopened = openSqliteOAuthStore({
    path: f.path,
    cipher: f.cipher,
    mcpResourceUrl: new URL(RESOURCE),
    now: () => NOW,
  })
  t.after(() => reopened.close())
  assert.deepEqual(rows(f.path, 'SELECT * FROM staged_grants'), [])
  assert.deepEqual(reopened.loadCredential(principal.principalId).grant, initial)
})

test('a concurrent login CAS winner is adopted and the losing stage is removed locally', async (t) => {
  const f = await fixture(t)
  const initial = grant('cas-old', NOW + 1)
  const losingRefresh = grant('cas-loser')
  const loginWinner = grant('cas-winner')
  const principal = installPrincipal(f.store, f.client.client_id, '501', initial, 'cas-initial')
  const cleanupCalls = []
  const authorizations = []
  const clientResolver = resolver({
    store: f.store,
    zendesk: gateway({
      async refreshCredential() {
        return losingRefresh
      },
      async getCurrentUser() {
        installPrincipal(f.store, f.client.client_id, '501', loginWinner, 'cas-login-winner', NOW + 1)
        return { zendeskUserId: '501' }
      },
      async revokeCurrentToken(accessToken) {
        cleanupCalls.push(accessToken)
      },
    }),
    fetch: async (_input, init) => {
      authorizations.push(new Headers(init?.headers).get('authorization'))
      return ticketResponse()
    },
  })

  const client = await clientResolver.resolve(principal.principalId)
  await client.getTicket(42)

  assert.deepEqual(authorizations, [`Bearer ${loginWinner.accessToken}`])
  assert.deepEqual(f.store.loadCredential(principal.principalId).grant, loginWinner)
  assert.deepEqual(rows(f.path, 'SELECT * FROM staged_grants'), [])
  assert.deepEqual(cleanupCalls, [])
})

test('disconnected and reauthorization-required principals fail closed without Basic fallback', async (t) => {
  const f = await fixture(t)
  const disconnectedGrant = grant('disconnected')
  const reauthorizationGrant = grant('reauthorization')
  const disconnected = installPrincipal(
    f.store,
    f.client.client_id,
    '601',
    disconnectedGrant,
    'disconnected',
  )
  const reauthorization = installPrincipal(
    f.store,
    f.client.client_id,
    '602',
    reauthorizationGrant,
    'reauthorization',
  )
  assert.equal(f.store.disconnectUser('example', '601', NOW + 1).kind, 'disconnected')
  const current = f.store.loadCredential(reauthorization.principalId)
  assert.equal(f.store.markReauthorizationRequiredIfCurrent({
    principalId: reauthorization.principalId,
    expectedPrincipalEpoch: current.principalEpoch,
    expectedCredentialVersion: current.credentialVersion,
    now: NOW + 1,
  }), true)
  const authorizations = []
  const clientResolver = resolver({
    store: f.store,
    zendesk: gateway(),
    fetch: async (_input, init) => {
      authorizations.push(new Headers(init?.headers).get('authorization'))
      return ticketResponse()
    },
  })

  await assert.rejects(clientResolver.resolve(disconnected.principalId), /reauthorization|credential/i)
  await assert.rejects(clientResolver.resolve(reauthorization.principalId), /reauthorization|credential/i)
  assert.deepEqual(authorizations, [])
  assert.equal(authorizations.some((value) => value?.startsWith('Basic ')), false)
})

test('an aborted hung refresh releases the per-principal single-flight entry', async (t) => {
  const f = await fixture(t)
  const initial = grant('hung-old', NOW + 1)
  const rotated = grant('hung-new')
  const principal = installPrincipal(f.store, f.client.client_id, '701', initial, 'hung')
  let refreshAttempts = 0
  const oauthGateway = new ZendeskOAuthClient({
    subdomain: 'example',
    clientId: 'fixed-client-id',
    clientSecret: 'fixed-client-secret',
    callbackUrl: new URL('https://broker.example.test/oauth/zendesk/callback'),
    scopes: [...ZENDESK_SCOPES],
    timeoutMs: 20,
    now: () => NOW,
    fetch: async (input, init) => {
      const url = new URL(String(input))
      if (url.pathname === '/oauth/tokens') {
        refreshAttempts += 1
        if (refreshAttempts === 1) {
          return await new Promise((_resolve, reject) => {
            init.signal.addEventListener(
              'abort',
              () => reject(new DOMException('Aborted', 'AbortError')),
              { once: true },
            )
          })
        }
        return new Response(JSON.stringify({
          access_token: rotated.accessToken,
          refresh_token: rotated.refreshToken,
          token_type: 'Bearer',
          scope: ZENDESK_SCOPES.join(' '),
          expires_in: rotated.accessExpiresAt - NOW,
          refresh_token_expires_in: rotated.refreshExpiresAt - NOW,
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      if (url.pathname === '/api/v2/users/me.json') {
        return new Response(JSON.stringify({ user: { id: 701 } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      assert.fail(`unexpected fake Zendesk URL ${url.href}`)
    },
  })
  const clientResolver = resolver({
    store: f.store,
    zendesk: oauthGateway,
    fetch: async () => ticketResponse(),
  })

  await assert.rejects(
    clientResolver.resolve(principal.principalId),
    (error) => error?.category === 'aborted',
  )
  const client = await clientResolver.resolve(principal.principalId)
  assert.equal((await client.getTicket(42)).id, 42)
  assert.equal(refreshAttempts, 2)
  assert.deepEqual(f.store.loadCredential(principal.principalId).grant, rotated)
})
