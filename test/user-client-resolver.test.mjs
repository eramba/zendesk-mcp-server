import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { SecretCipher, randomOpaque } from '../dist/internal-auth/crypto.js'
import { SafeAuthError } from '../dist/internal-auth/errors.js'
import { UserClientResolver } from '../dist/internal-auth/client-resolver.js'
import { InternalAuthStore } from '../dist/internal-auth/store.js'

const NOW = 1_700_000_000
const KEY = Buffer.alloc(32, 19)

function grant(label, accessExpiresAt = NOW + 1_800) {
  return {
    accessToken: `access-${label}-sentinel`,
    refreshToken: `refresh-${label}-sentinel`,
    accessExpiresAt,
    refreshExpiresAt: NOW + 30 * 24 * 60 * 60,
    scopes: ['read', 'tickets:write'],
  }
}

function activate(store, label, identityId, userGrant = grant(label)) {
  const created = store.createPendingUser(label)
  const state = randomOpaque()
  const started = store.startInvitation(created.invitation, state)
  assert.ok(started)
  const claimed = store.claimCallback(state)
  assert.ok(claimed)
  store.completeLink({
    ...claimed,
    identity: {
      id: identityId,
      name: label,
      email: `${label.toLowerCase()}@example.test`,
    },
    grant: userGrant,
  })
  return created
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-resolver-'))
  const path = join(directory, 'oauth.sqlite')
  const clock = { value: NOW }
  const store = InternalAuthStore.open({
    path,
    cipher: new SecretCipher(KEY),
    subdomain: 'acme',
    clientId: 'internal-mcp',
    now: () => clock.value,
  })
  t.after(() => store.close())
  return { clock, path, store }
}

function deferred() {
  let resolve
  let reject
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function ticketFetch(authorizations) {
  return async (_input, init) => {
    authorizations.push(new Headers(init.headers).get('authorization'))
    return new Response(JSON.stringify({ ticket: { id: 1 } }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }
}

test('bearer-selected users receive isolated clients and no shared fallback', async (t) => {
  const { store } = await fixture(t)
  const martin = activate(store, 'Martin', '101')
  const adrian = activate(store, 'Adrian', '202')
  const authorizations = []
  const oauth = {
    refresh: async () => assert.fail('fresh grants must not refresh'),
    currentUser: async () => assert.fail('fresh grants must not call users/me'),
  }
  const resolver = new UserClientResolver({
    store,
    oauth,
    subdomain: 'acme',
    now: () => NOW,
    fetch: ticketFetch(authorizations),
  })

  const [martinClient, adrianClient] = await Promise.all([
    resolver.resolve(store.authenticateBearer(martin.bearer).userId),
    resolver.resolve(store.authenticateBearer(adrian.bearer).userId),
  ])
  await Promise.all([martinClient.getTicket(1), adrianClient.getTicket(1)])

  assert.deepEqual(new Set(authorizations), new Set([
    'Bearer access-Martin-sentinel',
    'Bearer access-Adrian-sentinel',
  ]))
  await assert.rejects(
    resolver.resolve('00000000-0000-4000-8000-000000000000'),
    (error) => error instanceof SafeAuthError && error.category === 'unauthorized',
  )
  assert.equal(authorizations.length, 2)
})

test('same-user expiring credentials refresh once and persist before callers continue', async (t) => {
  const { path, store } = await fixture(t)
  const created = activate(store, 'Martin', '101', grant('old', NOW + 30))
  const release = deferred()
  let refreshCalls = 0
  const oauth = {
    refresh: async (token) => {
      refreshCalls += 1
      assert.equal(token, 'refresh-old-sentinel')
      return release.promise
    },
    currentUser: async (token) => {
      assert.equal(token, 'access-rotated-sentinel')
      return { id: '101', name: 'Martin', email: 'martin@example.test' }
    },
  }
  const authorizations = []
  const resolver = new UserClientResolver({
    store,
    oauth,
    subdomain: 'acme',
    now: () => NOW,
    fetch: ticketFetch(authorizations),
  })
  const userId = store.authenticateBearer(created.bearer).userId
  const first = resolver.resolve(userId)
  const second = resolver.resolve(userId)
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(refreshCalls, 1)

  release.resolve(grant('rotated'))
  const clients = await Promise.all([first, second])
  const observer = InternalAuthStore.open({
    path,
    cipher: new SecretCipher(KEY),
    subdomain: 'acme',
    clientId: 'internal-mcp',
    now: () => NOW,
  })
  t.after(() => observer.close())
  assert.equal(observer.loadCredential(userId).grant.accessToken, 'access-rotated-sentinel')
  assert.equal(observer.loadCredential(userId).version, 2)

  await Promise.all(clients.map((client) => client.getTicket(1)))
  assert.deepEqual(authorizations, [
    'Bearer access-rotated-sentinel',
    'Bearer access-rotated-sentinel',
  ])
})

test('caller abort does not cancel a shared refresh for another caller', async (t) => {
  const { store } = await fixture(t)
  const created = activate(store, 'Martin', '101', grant('old', NOW + 30))
  const release = deferred()
  let refreshCalls = 0
  const oauth = {
    refresh: (token, signal) => {
      refreshCalls += 1
      assert.equal(token, 'refresh-old-sentinel')
      return new Promise((resolve, reject) => {
        const abort = () => reject(new SafeAuthError('aborted', { retryable: true }))
        signal?.addEventListener('abort', abort, { once: true })
        release.promise.then(resolve, reject).finally(() => {
          signal?.removeEventListener('abort', abort)
        })
      })
    },
    currentUser: async (token) => {
      assert.equal(token, 'access-rotated-sentinel')
      return { id: '101', name: 'Martin', email: 'martin@example.test' }
    },
  }
  const authorizations = []
  const resolver = new UserClientResolver({
    store,
    oauth,
    subdomain: 'acme',
    now: () => NOW,
    fetch: ticketFetch(authorizations),
  })
  const firstController = new AbortController()
  const first = resolver
    .resolve(created.userId, firstController.signal)
    .then((client) => ({ client }), (error) => ({ error }))
  const second = resolver
    .resolve(created.userId)
    .then((client) => ({ client }), (error) => ({ error }))

  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(refreshCalls, 1)
  firstController.abort()

  const firstResult = await first
  assert.ok(firstResult.error instanceof SafeAuthError)
  assert.equal(firstResult.error.category, 'aborted')

  const third = resolver
    .resolve(created.userId)
    .then((client) => ({ client }), (error) => ({ error }))
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(refreshCalls, 1)

  release.resolve(grant('rotated'))
  const [secondResult, thirdResult] = await Promise.all([second, third])
  assert.ok(secondResult.client)
  assert.ok(thirdResult.client)
  assert.equal(store.loadCredential(created.userId).version, 2)
  assert.equal(
    store.loadCredential(created.userId).grant.accessToken,
    'access-rotated-sentinel',
  )
  await Promise.all([
    secondResult.client.getTicket(1),
    thirdResult.client.getTicket(1),
  ])
  assert.deepEqual(authorizations, [
    'Bearer access-rotated-sentinel',
    'Bearer access-rotated-sentinel',
  ])
})

test('different users refresh independently and preserve their identity boundary', async (t) => {
  const { store } = await fixture(t)
  const first = activate(store, 'First', '301', grant('first-old', NOW + 30))
  const second = activate(store, 'Second', '302', grant('second-old', NOW + 30))
  const releases = new Map([
    ['refresh-first-old-sentinel', deferred()],
    ['refresh-second-old-sentinel', deferred()],
  ])
  const entered = []
  const oauth = {
    refresh: async (token) => {
      entered.push(token)
      return releases.get(token).promise
    },
    currentUser: async (token) => ({
      id: token.includes('first') ? '301' : '302',
      name: null,
      email: null,
    }),
  }
  const resolver = new UserClientResolver({
    store,
    oauth,
    subdomain: 'acme',
    now: () => NOW,
    fetch: ticketFetch([]),
  })

  const firstPending = resolver.resolve(store.authenticateBearer(first.bearer).userId)
  const secondPending = resolver.resolve(store.authenticateBearer(second.bearer).userId)
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(new Set(entered), new Set(releases.keys()))

  releases.get('refresh-second-old-sentinel').resolve(grant('second-new'))
  releases.get('refresh-first-old-sentinel').resolve(grant('first-new'))
  await Promise.all([firstPending, secondPending])
  assert.equal(store.loadCredential(first.userId).grant.accessToken, 'access-first-new-sentinel')
  assert.equal(store.loadCredential(second.userId).grant.accessToken, 'access-second-new-sentinel')
})

test('invalid_grant and refreshed identity mismatch disable only the affected mapping', async (t) => {
  const { store } = await fixture(t)
  const invalid = activate(store, 'Invalid', '401', grant('invalid', NOW + 30))
  const healthy = activate(store, 'Healthy', '402')
  const mismatch = activate(store, 'Mismatch', '403', grant('mismatch', NOW + 30))
  const oauth = {
    refresh: async (token) => {
      if (token === 'refresh-invalid-sentinel') {
        throw new SafeAuthError('invalid_grant')
      }
      return grant('mismatch-new')
    },
    currentUser: async () => ({ id: '999', name: null, email: null }),
  }
  const resolver = new UserClientResolver({
    store,
    oauth,
    subdomain: 'acme',
    now: () => NOW,
    fetch: ticketFetch([]),
  })

  for (const user of [invalid, mismatch]) {
    await assert.rejects(
      resolver.resolve(user.userId),
      (error) =>
        error instanceof SafeAuthError &&
        error.category === 'reauthorization_required',
    )
    assert.equal(store.loadCredential(user.userId), undefined)
  }
  assert.equal(
    store.inspectUsers().find(({ id }) => id === healthy.userId).status,
    'active',
  )
  assert.equal(store.loadCredential(healthy.userId).grant.accessToken, 'access-Healthy-sentinel')
})

test('an old client adopts a newer credential on 401 and a second invalid token is terminal', async (t) => {
  const { store } = await fixture(t)
  const created = activate(store, 'Martin', '501')
  const requests = []
  const fetch = async (_input, init) => {
    requests.push(new Headers(init.headers).get('authorization'))
    return new Response(JSON.stringify({ error: 'invalid_token' }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    })
  }
  const oauth = {
    refresh: async () => assert.fail('newer stored grant must be adopted'),
    currentUser: async () => assert.fail('newer stored grant must be adopted'),
  }
  const resolver = new UserClientResolver({
    store,
    oauth,
    subdomain: 'acme',
    now: () => NOW,
    fetch,
  })
  const client = await resolver.resolve(created.userId)
  store.installRefreshedGrant({
    userId: created.userId,
    expectedVersion: 1,
    grant: grant('winner'),
  })
  await assert.rejects(
    client.getTicket(1),
    (error) =>
      error instanceof SafeAuthError &&
      error.category === 'reauthorization_required',
  )
  assert.deepEqual(requests, [
    'Bearer access-Martin-sentinel',
    'Bearer access-winner-sentinel',
  ])
  assert.equal(store.loadCredential(created.userId), undefined)
})

test('transient refresh failures are sanitized and do not disable any mapping', async (t) => {
  const { store } = await fixture(t)
  const created = activate(store, 'Secret Identity Sentinel', '601', grant('secret', NOW + 30))
  const oauth = {
    refresh: async () => {
      throw new Error('refresh-secret-sentinel transport-secret-sentinel')
    },
    currentUser: async () => assert.fail('failed refresh has no identity call'),
  }
  const resolver = new UserClientResolver({
    store,
    oauth,
    subdomain: 'acme',
    now: () => NOW,
    fetch: ticketFetch([]),
  })

  const error = await resolver.resolve(created.userId).catch((value) => value)
  assert.ok(error instanceof SafeAuthError)
  assert.equal(error.category, 'temporarily_unavailable')
  const rendered = `${error.name} ${error.message} ${error.stack}`
  for (const secret of [
    'refresh-secret-sentinel',
    'transport-secret-sentinel',
    'Secret Identity Sentinel',
    '601',
  ]) {
    assert.equal(rendered.includes(secret), false)
  }
  assert.equal(store.inspectUsers().find(({ id }) => id === created.userId).status, 'active')
})
