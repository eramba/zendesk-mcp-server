import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js'

import { SecretCipher } from '../dist/internal-auth/crypto.js'
import { SafeAuthError } from '../dist/internal-auth/errors.js'
import { createLinkHandlers } from '../dist/internal-auth/link-handlers.js'
import { InternalAuthStore } from '../dist/internal-auth/store.js'

const NOW = 1_700_000_000

function grant(label) {
  return {
    accessToken: `access-${label}-sentinel`,
    refreshToken: `refresh-${label}-sentinel`,
    accessExpiresAt: NOW + 1_800,
    refreshExpiresAt: NOW + 2_592_000,
    scopes: ['read', 'tickets:write'],
  }
}

async function fixture(t, oauthOverrides = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-linking-'))
  const clock = { value: NOW }
  const store = InternalAuthStore.open({
    path: join(directory, 'oauth.sqlite'),
    cipher: new SecretCipher(Buffer.alloc(32, 12)),
    subdomain: 'acme',
    clientId: 'internal-mcp',
    now: () => clock.value,
  })
  t.after(() => store.close())

  const calls = {
    authorizationStates: [],
    exchanges: [],
    identities: [],
    revocations: [],
  }
  const oauth = {
    authorizationUrl(state) {
      calls.authorizationStates.push(state)
      const url = new URL('https://acme.zendesk.com/oauth/authorizations/new')
      url.searchParams.set('state', state)
      return url
    },
    async exchangeCode(code) {
      calls.exchanges.push(code)
      return grant('linked')
    },
    async currentUser(accessToken) {
      calls.identities.push(accessToken)
      return {
        id: '4242',
        name: 'Authoritative Agent',
        email: 'authoritative@example.test',
        role: 'agent',
      }
    },
    async revokeCurrent(accessToken) {
      calls.revocations.push(accessToken)
    },
    async refresh() {
      assert.fail('link handlers must not refresh')
    },
    ...oauthOverrides,
  }
  const handlers = createLinkHandlers({
    store,
    oauth,
    now: () => clock.value,
  })
  const app = createMcpExpressApp({
    host: '127.0.0.1',
    allowedHosts: ['127.0.0.1', 'localhost'],
  })
  app.get('/oauth/link', handlers.link)
  app.get('/oauth/callback', handlers.callback)
  const listener = app.listen(0, '127.0.0.1')
  await once(listener, 'listening')
  t.after(async () => {
    if (!listener.listening) return
    await new Promise((resolve, reject) => {
      listener.close((error) => (error ? reject(error) : resolve()))
    })
  })
  const address = listener.address()
  assert.ok(address && typeof address === 'object')
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    calls,
    clock,
    store,
  }
}

async function beginLink(f, label = 'Martin') {
  const created = f.store.createPendingUser(label)
  const response = await fetch(
    `${f.baseUrl}/oauth/link?invitation=${encodeURIComponent(created.invitation)}`,
    { redirect: 'manual' },
  )
  assert.equal(response.status, 302)
  return {
    created,
    state: new URL(response.headers.get('location')).searchParams.get('state'),
  }
}

test('link rejects missing, duplicate, unknown, expired, and reused invitations safely', async (t) => {
  const f = await fixture(t)
  const created = f.store.createPendingUser('Martin')

  for (const path of [
    '/oauth/link',
    '/oauth/link?invitation=',
    '/oauth/link?invitation=one&invitation=two',
    '/oauth/link?invitation=unknown',
  ]) {
    const response = await fetch(`${f.baseUrl}${path}`, { redirect: 'manual' })
    assert.ok([400, 410].includes(response.status))
    assert.equal(response.headers.get('cache-control'), 'no-store')
    assert.equal(response.headers.get('referrer-policy'), 'no-referrer')
    assert.equal((await response.text()).includes('unknown'), false)
  }
  assert.equal(f.calls.authorizationStates.length, 0)

  const first = await fetch(
    `${f.baseUrl}/oauth/link?invitation=${created.invitation}`,
    { redirect: 'manual' },
  )
  assert.equal(first.status, 302)
  const reused = await fetch(
    `${f.baseUrl}/oauth/link?invitation=${created.invitation}`,
    { redirect: 'manual' },
  )
  assert.equal(reused.status, 410)

  const expired = f.store.createPendingUser('Expired')
  f.clock.value = expired.expiresAt
  const expiredResponse = await fetch(
    `${f.baseUrl}/oauth/link?invitation=${expired.invitation}`,
    { redirect: 'manual' },
  )
  assert.equal(expiredResponse.status, 410)
})

test('link generates independent state and redirects only to fixed Zendesk without cookies', async (t) => {
  const f = await fixture(t)
  const states = new Set()

  for (let index = 0; index < 25; index += 1) {
    const { created, state } = await beginLink(f, `User ${index}`)
    assert.match(state, /^[A-Za-z0-9_-]{43}$/)
    assert.notEqual(state, created.invitation)
    states.add(state)
  }

  assert.equal(states.size, 25)
  assert.equal(f.calls.authorizationStates.length, 25)
  const created = f.store.createPendingUser('Header check')
  const response = await fetch(
    `${f.baseUrl}/oauth/link?invitation=${created.invitation}`,
    { redirect: 'manual' },
  )
  const location = new URL(response.headers.get('location'))
  assert.equal(location.origin, 'https://acme.zendesk.com')
  assert.equal(location.pathname, '/oauth/authorizations/new')
  assert.equal(response.headers.get('cache-control'), 'no-store')
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer')
  assert.equal(response.headers.get('set-cookie'), null)
  assert.equal(location.href.includes(created.invitation), false)
})

test('callback claims state before exchange and activates the intended users/me identity', async (t) => {
  const f = await fixture(t)
  const { created, state } = await beginLink(f, 'Untrusted admin label')
  const response = await fetch(
    `${f.baseUrl}/oauth/callback?code=code-sentinel&state=${state}`,
  )

  assert.equal(response.status, 200)
  assert.equal(response.headers.get('cache-control'), 'no-store')
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer')
  assert.equal(response.headers.get('set-cookie'), null)
  assert.equal((await response.text()).includes('linked'), true)
  assert.deepEqual(f.calls.exchanges, ['code-sentinel'])
  assert.deepEqual(f.calls.identities, ['access-linked-sentinel'])
  assert.deepEqual(f.calls.revocations, [])
  assert.deepEqual(f.store.authenticateBearer(created.bearer), {
    userId: created.userId,
  })

  const metadata = f.store.inspectUsers().find(({ id }) => id === created.userId)
  assert.equal(metadata.label, 'Untrusted admin label')
  assert.equal(metadata.zendeskUserId, '4242')
  assert.equal(metadata.zendeskName, 'Authoritative Agent')
  assert.equal(metadata.zendeskEmail, 'authoritative@example.test')

  const replay = await fetch(
    `${f.baseUrl}/oauth/callback?code=replay-code&state=${state}`,
  )
  assert.equal(replay.status, 400)
  assert.deepEqual(f.calls.exchanges, ['code-sentinel'])
})

test('missing, duplicate, mismatched, and denied callbacks never activate', async (t) => {
  const f = await fixture(t)
  const { created, state } = await beginLink(f)

  for (const path of [
    '/oauth/callback',
    '/oauth/callback?code=code-only',
    '/oauth/callback?code=code&state=wrong',
    `/oauth/callback?code=one&code=two&state=${state}`,
  ]) {
    const response = await fetch(`${f.baseUrl}${path}`)
    assert.equal(response.status, 400)
  }
  assert.deepEqual(f.calls.exchanges, [])
  assert.equal(f.store.authenticateBearer(created.bearer), undefined)

  const denied = await fetch(
    `${f.baseUrl}/oauth/callback?error=access_denied&state=${state}`,
  )
  assert.equal(denied.status, 400)
  const replay = await fetch(
    `${f.baseUrl}/oauth/callback?code=after-denial&state=${state}`,
  )
  assert.equal(replay.status, 400)
  assert.deepEqual(f.calls.exchanges, [])
})

test('post-exchange failure never activates and makes one best-effort revocation', async (t) => {
  const errors = []
  const original = console.error
  console.error = (...values) => errors.push(values.map(String).join(' '))
  t.after(() => {
    console.error = original
  })
  const f = await fixture(t, {
    async currentUser() {
      throw new SafeAuthError('invalid_response')
    },
    async revokeCurrent(accessToken) {
      f.calls.revocations.push(accessToken)
      throw new SafeAuthError('temporarily_unavailable', { retryable: true })
    },
  })
  const { created, state } = await beginLink(f)
  const response = await fetch(
    `${f.baseUrl}/oauth/callback?code=code-secret-sentinel&state=${state}`,
  )

  assert.equal(response.status, 502)
  const body = await response.text()
  for (const secret of [
    created.bearer,
    created.invitation,
    state,
    'code-secret-sentinel',
    'access-linked-sentinel',
    'refresh-linked-sentinel',
  ]) {
    assert.equal(body.includes(secret), false)
  }
  assert.equal(f.store.authenticateBearer(created.bearer), undefined)
  assert.deepEqual(f.calls.revocations, ['access-linked-sentinel'])
  assert.equal(errors.length, 1)
})

test('exchange failure does not activate or attempt revocation and logs no secrets', async (t) => {
  const errors = []
  const original = console.error
  console.error = (...values) => errors.push(values.map(String).join(' '))
  t.after(() => {
    console.error = original
  })

  const f = await fixture(t, {
    async exchangeCode() {
      throw new SafeAuthError('invalid_grant')
    },
  })
  const { created, state } = await beginLink(f)
  const code = 'authorization-code-secret-sentinel'
  const response = await fetch(
    `${f.baseUrl}/oauth/callback?code=${code}&state=${state}`,
  )

  assert.equal(response.status, 502)
  assert.equal(f.store.authenticateBearer(created.bearer), undefined)
  assert.deepEqual(f.calls.revocations, [])
  const rendered = `${await response.text()}\n${errors.join('\n')}`
  for (const secret of [
    created.bearer,
    created.invitation,
    state,
    code,
    'client-secret-sentinel',
  ]) {
    assert.equal(rendered.includes(secret), false)
  }
})
