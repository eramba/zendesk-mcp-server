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
const PUBLIC_BASE_URL = new URL('https://mcp.example.test/')

function grant(label) {
  return {
    accessToken: `access-${label}-sentinel`,
    refreshToken: `refresh-${label}-sentinel`,
    accessExpiresAt: NOW + 1_800,
    refreshExpiresAt: NOW + 2_592_000,
    scopes: ['read', 'tickets:write'],
  }
}

async function fixture(t, oauthOverrides = {}, handlerOverrides = {}) {
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
    publicBaseUrl: PUBLIC_BASE_URL,
    selfServiceEnabled: true,
    now: () => clock.value,
    ...handlerOverrides,
  })
  const app = createMcpExpressApp({
    host: '127.0.0.1',
    allowedHosts: ['127.0.0.1', 'localhost'],
  })
  app.get('/oauth/link', handlers.link)
  app.get('/oauth/callback', handlers.callback)
  if (handlers.createAccount) {
    app.get('/create-account', handlers.createAccount)
  }
  if (handlers.startEnrollment) {
    app.post('/create-account', handlers.startEnrollment)
  }
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

function assertBrowserSecurity(response) {
  assert.equal(response.headers.get('cache-control'), 'no-store')
  assert.equal(response.headers.get('pragma'), 'no-cache')
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer')
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff')
  assert.equal(response.headers.get('x-frame-options'), 'DENY')
  assert.match(response.headers.get('content-security-policy'), /default-src 'none'/)
  assert.match(response.headers.get('content-security-policy'), /frame-ancestors 'none'/)
  assert.match(response.headers.get('permissions-policy'), /camera=\(\)/)
}

async function beginSelfEnrollment(f, origin = PUBLIC_BASE_URL.origin) {
  const response = await fetch(`${f.baseUrl}/create-account`, {
    method: 'POST',
    headers: { Origin: origin },
    redirect: 'manual',
  })
  return {
    response,
    state: response.headers.get('location')
      ? new URL(response.headers.get('location')).searchParams.get('state')
      : null,
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

test('self-service enrollment page is explicit, side-effect free, and same-origin only', async (t) => {
  const disabled = await fixture(t, {}, { selfServiceEnabled: false })
  assert.equal((await fetch(`${disabled.baseUrl}/create-account`)).status, 404)

  const f = await fixture(t)
  const page = await fetch(`${f.baseUrl}/create-account`)
  assert.equal(page.status, 200)
  assertBrowserSecurity(page)
  const pageBody = await page.text()
  assert.match(pageBody, /<form[^>]+method="post"[^>]+action="\/create-account"/i)
  assert.match(pageBody, /Connect Zendesk/i)
  assert.equal(pageBody.includes('<script'), false)
  assert.equal(f.calls.authorizationStates.length, 0)
  assert.deepEqual(f.store.inspectUsers(), [])

  const crossOrigin = await beginSelfEnrollment(f, 'https://evil.example.test')
  assert.equal(crossOrigin.response.status, 403)
  assertBrowserSecurity(crossOrigin.response)
  assert.equal(crossOrigin.state, null)
  assert.equal(f.calls.authorizationStates.length, 0)

  const started = await beginSelfEnrollment(f)
  assert.equal(started.response.status, 302)
  assertBrowserSecurity(started.response)
  assert.match(started.state, /^[A-Za-z0-9_-]{43}$/)
  const location = new URL(started.response.headers.get('location'))
  assert.equal(location.origin, 'https://acme.zendesk.com')
  assert.equal(location.pathname, '/oauth/authorizations/new')
  assert.deepEqual(f.calls.authorizationStates, [started.state])
  assert.deepEqual(f.store.inspectUsers(), [])
})

for (const eligibleRole of ['agent', 'admin']) {
  test(`self-service ${eligibleRole} receives one bearer only after authoritative OAuth identity`, async (t) => {
    const f = await fixture(t, {
      async currentUser(accessToken) {
        f.calls.identities.push(accessToken)
        return {
          id: eligibleRole === 'agent' ? '5101' : '5102',
          name: eligibleRole === 'agent' ? 'Eligible Agent' : 'Eligible Admin',
          email: `${eligibleRole}@example.test`,
          role: eligibleRole,
        }
      },
    })
    const started = await beginSelfEnrollment(f)
    assert.equal(started.response.status, 302)

    const callback = await fetch(
      `${f.baseUrl}/oauth/callback?code=self-code-sentinel&state=${started.state}`,
    )
    assert.equal(callback.status, 200)
    assertBrowserSecurity(callback)
    const body = await callback.text()
    const bearer = body.match(/zmcp_[A-Za-z0-9_-]{43}/)?.[0]
    const userId = body.match(/[0-9a-f]{8}-[0-9a-f-]{27}/i)?.[0]
    assert.match(bearer, /^zmcp_[A-Za-z0-9_-]{43}$/)
    assert.match(userId, /^[0-9a-f-]{36}$/)
    assert.match(body, /https:\/\/mcp\.example\.test\/mcp/)
    assert.match(body, /Authorization = &quot;Bearer zmcp_/)
    assert.match(body, /shown once|displayed once|cannot be recovered/i)
    assert.deepEqual(f.store.authenticateBearer(bearer), { userId })
    assert.deepEqual(f.calls.exchanges, ['self-code-sentinel'])
    assert.deepEqual(f.calls.identities, ['access-linked-sentinel'])
    assert.deepEqual(f.calls.revocations, [])

    const replay = await fetch(
      `${f.baseUrl}/oauth/callback?code=replay-code&state=${started.state}`,
    )
    assert.equal(replay.status, 400)
    assert.equal((await replay.text()).includes(bearer), false)
    assert.deepEqual(f.calls.exchanges, ['self-code-sentinel'])
  })
}

test('self-service rejects end users and duplicate identities without displaying a bearer', async (t) => {
  const endUser = await fixture(t, {
    async currentUser(accessToken) {
      endUser.calls.identities.push(accessToken)
      return {
        id: '5201',
        name: 'Zendesk Customer',
        email: 'customer@example.test',
        role: 'end-user',
      }
    },
  })
  const endUserStart = await beginSelfEnrollment(endUser)
  const forbidden = await fetch(
    `${endUser.baseUrl}/oauth/callback?code=end-user-code&state=${endUserStart.state}`,
  )
  assert.equal(forbidden.status, 403)
  assertBrowserSecurity(forbidden)
  assert.equal((await forbidden.text()).includes('zmcp_'), false)
  assert.deepEqual(endUser.calls.revocations, ['access-linked-sentinel'])
  assert.deepEqual(endUser.store.inspectUsers(), [])

  const duplicate = await fixture(t, {
    async currentUser(accessToken) {
      duplicate.calls.identities.push(accessToken)
      return {
        id: '5202',
        name: 'Duplicate Agent',
        email: 'duplicate@example.test',
        role: 'agent',
      }
    },
  })
  const firstStart = await beginSelfEnrollment(duplicate)
  const first = await fetch(
    `${duplicate.baseUrl}/oauth/callback?code=first-code&state=${firstStart.state}`,
  )
  assert.equal(first.status, 200)
  const firstBearer = (await first.text()).match(/zmcp_[A-Za-z0-9_-]{43}/)?.[0]
  assert.ok(firstBearer)

  const secondStart = await beginSelfEnrollment(duplicate)
  const second = await fetch(
    `${duplicate.baseUrl}/oauth/callback?code=second-code&state=${secondStart.state}`,
  )
  assert.equal(second.status, 409)
  const secondBody = await second.text()
  assert.equal(secondBody.includes('zmcp_'), false)
  assert.match(secondBody, /already registered|contact.*administrator/i)
  assert.deepEqual(duplicate.calls.revocations, ['access-linked-sentinel'])
  assert.equal(duplicate.store.inspectUsers().length, 1)
  assert.ok(duplicate.store.authenticateBearer(firstBearer))
})

test('self-service post-exchange failure is secret-free and revokes best effort', async (t) => {
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
  const started = await beginSelfEnrollment(f)
  const code = 'self-service-code-secret-sentinel'
  const response = await fetch(
    `${f.baseUrl}/oauth/callback?code=${code}&state=${started.state}`,
  )

  assert.equal(response.status, 502)
  assertBrowserSecurity(response)
  const rendered = `${await response.text()}\n${errors.join('\n')}`
  for (const secret of [
    started.state,
    code,
    'access-linked-sentinel',
    'refresh-linked-sentinel',
    'client-secret-sentinel',
  ]) {
    assert.equal(rendered.includes(secret), false)
  }
  assert.deepEqual(f.calls.revocations, ['access-linked-sentinel'])
  assert.deepEqual(f.store.inspectUsers(), [])
})

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
