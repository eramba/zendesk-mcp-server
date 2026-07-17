import assert from 'node:assert/strict'
import test from 'node:test'

import { ZendeskUpstreamError } from '../dist/oauth/errors.js'
import { ZendeskRevocationWorker } from '../dist/oauth/revocation-worker.js'
import { ZendeskOAuthClient } from '../dist/oauth/zendesk-oauth-client.js'

const NOW = 1_700_000_000
const TIMEOUT_MS = 15_000
const LEASE_SECONDS = Math.ceil((TIMEOUT_MS + 5_000) / 1_000)
const ACCESS_SENTINEL = 'access-secret-SENTINEL'
const REFRESH_SENTINEL = 'refresh-secret-SENTINEL'
const EMAIL_SENTINEL = 'worker-user@example.test'

function grant(overrides = {}) {
  return {
    accessToken: ACCESS_SENTINEL,
    refreshToken: REFRESH_SENTINEL,
    accessExpiresAt: NOW + 60,
    refreshExpiresAt: NOW + 3_600,
    scopes: ['read', 'tickets:write'],
    ...overrides,
  }
}

function claim(overrides = {}) {
  return {
    outboxId: 'outbox-1',
    principalId: 'principal-1',
    capturedPrincipalEpoch: 2,
    credentialVersion: 1,
    grant: grant(),
    attemptCount: 1,
    retentionExpiresAt: NOW + 86_400,
    ...overrides,
  }
}

function upstream(category, retryable, status) {
  return new ZendeskUpstreamError(category, status, retryable, `correlation-${category}`)
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

async function waitFor(predicate, message = 'condition') {
  const deadline = Date.now() + 2_000
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${message}`)
    await new Promise((resolve) => setImmediate(resolve))
  }
}

function fakeStore({ nextClaim = claim(), renew = true } = {}) {
  let available = nextClaim
  const calls = []
  return {
    calls,
    claimDueRevocation(owner, now, leaseExpiresAt) {
      calls.push(['claim', owner, now, leaseExpiresAt])
      const result = available
      available = undefined
      return result
    },
    renewRevocationClaim(outboxId, owner, leaseExpiresAt) {
      calls.push(['renew', outboxId, owner, leaseExpiresAt])
      return typeof renew === 'function' ? renew() : renew
    },
    rescheduleRevocation(outboxId, owner, category, nextAttemptAt) {
      calls.push(['reschedule', outboxId, owner, category, nextAttemptAt])
      return true
    },
    completeRevocation(outboxId, owner, now) {
      calls.push(['complete', outboxId, owner, now])
      return true
    },
    releaseClaims(owner, now) {
      calls.push(['release', owner, now])
      return 1
    },
  }
}

function worker(options = {}) {
  return new ZendeskRevocationWorker({
    timeoutMs: TIMEOUT_MS,
    now: () => NOW,
    randomOwner: () => 'worker-owner-a',
    pollIntervalMs: 1,
    ...options,
  })
}

async function captureConsole(run) {
  const output = []
  const originals = {}
  for (const name of ['log', 'info', 'warn', 'error']) {
    originals[name] = console[name]
    console[name] = (...values) => output.push(values.map(String).join(' '))
  }
  try {
    await run()
    return output
  } finally {
    for (const [name, original] of Object.entries(originals)) console[name] = original
  }
}

test('uses one unique owner, timeout plus margin lease, and concurrency one', async () => {
  const firstStore = fakeStore()
  const secondStore = fakeStore()
  const firstRevoke = deferred()
  const firstGateway = {
    revokeCurrentToken: () => firstRevoke.promise,
    refreshCredential: () => assert.fail('direct revoke must not refresh'),
  }
  const secondGateway = {
    revokeCurrentToken: async () => {},
    refreshCredential: () => assert.fail('direct revoke must not refresh'),
  }
  const first = worker({ store: firstStore, zendesk: firstGateway })
  const second = worker({
    store: secondStore,
    zendesk: secondGateway,
    randomOwner: () => 'worker-owner-b',
  })

  first.start()
  second.start()
  await waitFor(
    () => firstStore.calls.some(([name]) => name === 'claim')
      && secondStore.calls.some(([name]) => name === 'complete'),
    'both workers to claim',
  )
  await new Promise((resolve) => setTimeout(resolve, 10))

  assert.deepEqual(firstStore.calls.filter(([name]) => name === 'claim'), [
    ['claim', 'worker-owner-a', NOW, NOW + LEASE_SECONDS],
  ])
  assert.deepEqual(secondStore.calls[0], ['claim', 'worker-owner-b', NOW, NOW + LEASE_SECONDS])
  assert.notEqual(firstStore.calls[0][1], secondStore.calls[0][1])
  assert.equal(firstStore.calls.some(([name]) => name === 'complete'), false)

  let drained = false
  const draining = first.drain().then(() => { drained = true })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(drained, false)
  firstRevoke.resolve()
  await draining
  await waitFor(() => firstStore.calls.some(([name]) => name === 'complete'), 'first completion')
  await Promise.all([first.stop(), second.stop()])
})

test('revokes current token directly, and 401 refreshes solely for renewed immediate deletion', async () => {
  const directStore = fakeStore()
  const directCalls = []
  const direct = worker({
    store: directStore,
    zendesk: {
      async revokeCurrentToken(token) { directCalls.push(['revoke', token]) },
      refreshCredential: () => assert.fail('successful DELETE /current must not refresh'),
    },
  })
  direct.start()
  await waitFor(() => directStore.calls.some(([name]) => name === 'complete'), 'direct completion')
  await direct.stop()
  assert.deepEqual(directCalls, [['revoke', ACCESS_SENTINEL]])
  assert.equal(directStore.calls.some(([name]) => name === 'renew'), false)

  const refreshed = grant({
    accessToken: 'rotated-access-SENTINEL',
    refreshToken: 'rotated-refresh-SENTINEL',
    accessExpiresAt: NOW + 1_800,
    refreshExpiresAt: NOW + 7_200,
  })
  const refreshStore = fakeStore()
  const refreshCalls = []
  const refreshWorker = worker({
    store: refreshStore,
    zendesk: {
      async revokeCurrentToken(token) {
        refreshCalls.push(['revoke', token])
        if (token === ACCESS_SENTINEL) throw upstream('unauthorized', false, 401)
      },
      async refreshCredential(token) {
        refreshCalls.push(['refresh', token])
        return refreshed
      },
    },
  })

  refreshWorker.start()
  await waitFor(() => refreshStore.calls.some(([name]) => name === 'complete'), 'refresh completion')
  await refreshWorker.stop()

  assert.deepEqual(refreshCalls, [
    ['revoke', ACCESS_SENTINEL],
    ['refresh', REFRESH_SENTINEL],
    ['revoke', refreshed.accessToken],
  ])
  const renewals = refreshStore.calls.filter(([name]) => name === 'renew')
  assert.equal(renewals.length, 2)
  assert.equal(renewals[0][3] > NOW + LEASE_SECONDS, true)
  assert.equal(renewals[1][3] > renewals[0][3], true)
  assert.equal(refreshStore.calls.findIndex(([name]) => name === 'renew') < refreshStore.calls.findIndex(([name]) => name === 'complete'), true)
})

test('invalid grant, known refresh expiry, and already-revoked outcomes complete terminally', async () => {
  const cases = [
    {
      name: 'known refresh expiry',
      row: claim({ grant: grant({ refreshExpiresAt: NOW }) }),
      gateway: {
        revokeCurrentToken: () => assert.fail('expired tombstone must not call Zendesk'),
        refreshCredential: () => assert.fail('expired tombstone must not refresh'),
      },
    },
    {
      name: 'invalid grant',
      row: claim(),
      gateway: {
        revokeCurrentToken: async () => { throw upstream('unauthorized', false, 401) },
        refreshCredential: async () => { throw upstream('invalid_grant', false, 400) },
      },
    },
    {
      name: 'already revoked after refresh',
      row: claim(),
      gateway: {
        revokeCurrentToken: async () => { throw upstream('unauthorized', false, 401) },
        refreshCredential: async () => grant({ accessToken: 'already-revoked-access' }),
      },
    },
  ]

  for (const item of cases) {
    const store = fakeStore({ nextClaim: item.row })
    const instance = worker({ store, zendesk: item.gateway })
    instance.start()
    await waitFor(() => store.calls.some(([name]) => name === 'complete'), item.name)
    await instance.stop()
    assert.equal(store.calls.some(([name]) => name === 'reschedule'), false, item.name)
  }
})

test('only retryable gateway failures use exact exponential backoff', async () => {
  for (const [attemptCount, delay] of [[1, 5], [2, 10], [9, 900]]) {
    const store = fakeStore({ nextClaim: claim({ attemptCount, outboxId: `outbox-${attemptCount}` }) })
    const instance = worker({
      store,
      zendesk: {
        revokeCurrentToken: async () => { throw upstream('temporarily_unavailable', true, 503) },
        refreshCredential: () => assert.fail('5xx must not enter the 401 refresh path'),
      },
    })
    instance.start()
    await waitFor(() => store.calls.some(([name]) => name === 'reschedule'), `attempt ${attemptCount}`)
    await instance.stop()
    assert.deepEqual(store.calls.find(([name]) => name === 'reschedule'), [
      'reschedule',
      `outbox-${attemptCount}`,
      'worker-owner-a',
      'temporarily_unavailable',
      NOW + delay,
    ])
  }

  const terminalStore = fakeStore()
  const terminal = worker({
    store: terminalStore,
    zendesk: {
      revokeCurrentToken: async () => { throw upstream('forbidden', false, 403) },
      refreshCredential: () => assert.fail('403 must not refresh'),
    },
  })
  terminal.start()
  await waitFor(() => terminalStore.calls.some(([name]) => name === 'complete'), 'terminal completion')
  await terminal.stop()
  assert.equal(terminalStore.calls.some(([name]) => name === 'reschedule'), false)
})

test('startup reclaims a process-crash lease only after expiry', async () => {
  let clock = NOW + 9
  const calls = []
  let completed = false
  const store = {
    claimDueRevocation(owner, now, leaseExpiresAt) {
      calls.push(['claim', owner, now, leaseExpiresAt])
      if (now < NOW + 10 || completed) return undefined
      completed = true
      return claim({ attemptCount: 2 })
    },
    renewRevocationClaim: () => true,
    rescheduleRevocation: () => true,
    completeRevocation(outboxId, owner, now) {
      calls.push(['complete', outboxId, owner, now])
      return true
    },
    releaseClaims: () => 0,
  }
  const gateway = {
    revokeCurrentToken: async () => {},
    refreshCredential: () => assert.fail('reclaimed direct revoke must not refresh'),
  }
  const beforeExpiry = worker({ store, zendesk: gateway, now: () => clock })
  beforeExpiry.start()
  await waitFor(() => calls.some(([name]) => name === 'claim'), 'pre-expiry poll')
  await beforeExpiry.stop()
  assert.equal(calls.some(([name]) => name === 'complete'), false)

  clock = NOW + 10
  const replacement = worker({
    store,
    zendesk: gateway,
    now: () => clock,
    randomOwner: () => 'replacement-owner',
  })
  replacement.start()
  await waitFor(() => calls.some(([name]) => name === 'complete'), 'crash reclaim')
  await replacement.stop()
  assert.equal(calls.some((entry) => entry[0] === 'claim' && entry[1] === 'replacement-owner'), true)
})

test('stop aborts in-flight cleanup and immediately releases it for rescheduling', async () => {
  const store = fakeStore()
  let observedSignal
  const instance = worker({
    store,
    zendesk: {
      revokeCurrentToken(_token, signal) {
        observedSignal = signal
        return new Promise((resolve, reject) => {
          signal.addEventListener('abort', () => reject(upstream('aborted', false)), { once: true })
        })
      },
      refreshCredential: () => assert.fail('aborted direct revoke must not refresh'),
    },
  })

  instance.start()
  await waitFor(() => observedSignal instanceof AbortSignal, 'in-flight signal')
  await instance.stop()

  assert.equal(observedSignal.aborted, true)
  assert.deepEqual(store.calls.filter(([name]) => name === 'release'), [
    ['release', 'worker-owner-a', NOW],
  ])
  assert.equal(store.calls.some(([name]) => name === 'complete' || name === 'reschedule'), false)
})

test('gateway request timeout preserves the tombstone and releases the claim safely', async () => {
  const store = fakeStore()
  const gateway = new ZendeskOAuthClient({
    subdomain: 'acme',
    clientId: 'client-id',
    clientSecret: 'client-secret',
    callbackUrl: new URL('https://broker.example.test/oauth/zendesk/callback'),
    scopes: ['read', 'tickets:write'],
    timeoutMs: 5,
    fetch: async (_url, init) => new Promise((_resolve, reject) => {
      const rejectAbort = () => reject(new DOMException('Aborted', 'AbortError'))
      if (init.signal.aborted) rejectAbort()
      else init.signal.addEventListener('abort', rejectAbort, { once: true })
    }),
    now: () => NOW,
  })
  const instance = worker({ store, zendesk: gateway })

  instance.start()
  await waitFor(
    () => store.calls.some(([name]) => name === 'release' || name === 'complete'),
    'gateway timeout outcome',
  )
  await instance.stop()

  assert.deepEqual(store.calls.filter(([name]) => name === 'release'), [
    ['release', 'worker-owner-a', NOW],
  ])
  assert.equal(store.calls.some(([name]) => name === 'complete' || name === 'reschedule'), false)
})

test('captured-epoch fences prevent claims after reactivation and refresh after a lost renewal', async () => {
  const reactivatedStore = fakeStore({ nextClaim: null })
  const calls = []
  const noClaimWorker = worker({
    store: reactivatedStore,
    zendesk: {
      revokeCurrentToken: async () => calls.push('revoke'),
      refreshCredential: async () => calls.push('refresh'),
    },
  })
  noClaimWorker.start()
  await waitFor(() => reactivatedStore.calls.some(([name]) => name === 'claim'), 'reactivated poll')
  await noClaimWorker.stop()
  assert.deepEqual(calls, [])

  const lostLeaseStore = fakeStore({ renew: false })
  const lostLeaseCalls = []
  const lostLeaseWorker = worker({
    store: lostLeaseStore,
    zendesk: {
      async revokeCurrentToken(token) {
        lostLeaseCalls.push(['revoke', token])
        throw upstream('unauthorized', false, 401)
      },
      async refreshCredential(token) { lostLeaseCalls.push(['refresh', token]) },
    },
  })
  lostLeaseWorker.start()
  await waitFor(() => lostLeaseStore.calls.some(([name]) => name === 'renew'), 'lost renewal')
  await lostLeaseWorker.drain()
  await lostLeaseWorker.stop()
  assert.deepEqual(lostLeaseCalls, [['revoke', ACCESS_SENTINEL]])
  assert.equal(lostLeaseStore.calls.some(([name]) => name === 'complete' || name === 'reschedule'), false)
})

test('worker logs never expose tombstone tokens or user identifiers', async () => {
  const store = fakeStore({ nextClaim: claim({ principalId: EMAIL_SENTINEL }) })
  const output = await captureConsole(async () => {
    const instance = worker({
      store,
      zendesk: {
        revokeCurrentToken: async () => { throw upstream('temporarily_unavailable', true, 503) },
        refreshCredential: () => assert.fail('retryable revoke must not refresh'),
      },
    })
    instance.start()
    await waitFor(() => store.calls.some(([name]) => name === 'reschedule'), 'secret-safe retry')
    await instance.stop()
  })

  const logs = output.join('\n')
  assert.equal(logs.includes(ACCESS_SENTINEL), false)
  assert.equal(logs.includes(REFRESH_SENTINEL), false)
  assert.equal(logs.includes(EMAIL_SENTINEL), false)
})
