import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import express from 'express'

import { ConsentController } from '../dist/oauth/consent.js'
import { createZendeskOAuthRouter } from '../dist/oauth/oauth-router.js'
import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher } from '../dist/oauth/token-cipher.js'
import { ZendeskBrokerOAuthProvider } from '../dist/oauth/zendesk-broker-provider.js'

const NOW = 1_700_000_000
const PUBLIC_BASE_URL = new URL('https://broker.example.test')
const RESOURCE = new URL('/mcp', PUBLIC_BASE_URL).href
const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const SCOPES = ['zendesk:read', 'zendesk:write']
const VERIFIER = 'v'.repeat(43)
const CODE_CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url')
const CLIENT_NAME = '<img src=x onerror="alert(1)"> & Codex'
const COOKIE_NAME = '__Secure-zendesk_oauth_consent'
const COOKIE_ATTRIBUTES = 'HttpOnly; Secure; SameSite=Strict; Path=/oauth/consent; Max-Age=600'
const CLEAR_COOKIE = `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/oauth/consent; Max-Age=0`

async function startFixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-consent-'))
  const store = openSqliteOAuthStore({
    path: join(directory, 'oauth.sqlite'),
    cipher: new TokenCipher(Buffer.alloc(32, 73)),
    mcpResourceUrl: new URL(RESOURCE),
    now: () => NOW,
  })
  t.after(() => store.close())
  const client = store.registerClient({
    redirect_uris: [REDIRECT_URI],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    client_name: CLIENT_NAME,
    scope: SCOPES.join(' '),
  })

  const authorizationStates = []
  const gateway = {
    onCreateAuthorizationUrl: undefined,
    createAuthorizationUrl(state) {
      this.onCreateAuthorizationUrl?.(state)
      authorizationStates.push(state)
      const url = new URL('https://example.zendesk.com/oauth/authorizations/new')
      url.searchParams.set('state', state)
      return url
    },
    exchangeAuthorizationCode: async () => assert.fail('unexpected Zendesk exchange'),
    refreshCredential: async () => assert.fail('unexpected Zendesk refresh'),
    getCurrentUser: async () => assert.fail('unexpected Zendesk identity lookup'),
    revokeCurrentToken: async () => assert.fail('unexpected Zendesk revocation'),
  }
  const controller = new ConsentController({
    store,
    zendesk: gateway,
    publicBaseUrl: PUBLIC_BASE_URL,
    subdomain: 'example',
    now: () => NOW,
  })
  const provider = new ZendeskBrokerOAuthProvider({
    store,
    resourceUrl: new URL(RESOURCE),
    accessTokenTtlSeconds: 900,
    startAuthorization: controller.begin,
    now: () => NOW,
  })
  const app = express()
  app.use(createZendeskOAuthRouter({
    provider,
    issuerUrl: PUBLIC_BASE_URL,
    resourceUrl: new URL(RESOURCE),
    consentHandler: controller.handlePost,
    callbackHandler: (_req, res) => res.status(204).end(),
  }))
  app.use((error, _req, res, _next) => {
    res.status(error.status ?? 500).json({ error: 'request_rejected' })
  })
  const server = app.listen(0, '127.0.0.1')
  t.after(() => new Promise((resolve) => server.close(resolve)))
  await new Promise((resolve, reject) => {
    server.once('listening', resolve)
    server.once('error', reject)
  })
  const address = server.address()
  assert.ok(address && typeof address !== 'string')
  return {
    authorizationStates,
    baseUrl: `http://127.0.0.1:${address.port}`,
    client,
    gateway,
    store,
  }
}

function authorizeUrl(baseUrl, clientId, state) {
  const url = new URL('/authorize', baseUrl)
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    code_challenge: CODE_CHALLENGE,
    code_challenge_method: 'S256',
    scope: SCOPES.join(' '),
    state,
    resource: RESOURCE,
  }).toString()
  return url
}

function hiddenFields(html) {
  return Object.fromEntries(
    [...html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)]
      .map((match) => [match[1], match[2]]),
  )
}

async function beginConsent(fixture, state = 'mcp-state') {
  const response = await fetch(
    authorizeUrl(fixture.baseUrl, fixture.client.client_id, state),
    { redirect: 'manual' },
  )
  assert.equal(response.status, 200)
  const html = await response.text()
  const fields = hiddenFields(html)
  assert.deepEqual(Object.keys(fields).sort(), ['csrf', 'transaction'])
  const setCookie = response.headers.get('set-cookie')
  assert.ok(setCookie)
  const cookie = setCookie.split(';', 1)[0]
  const browserNonce = cookie.slice(`${COOKIE_NAME}=`.length)
  assert.match(browserNonce, /^[A-Za-z0-9_-]+$/)
  return { browserNonce, cookie, fields, html, response, setCookie }
}

function consentRequest(baseUrl, consent, overrides = {}) {
  const body = overrides.body ?? new URLSearchParams({
    transaction: consent.fields.transaction,
    csrf: consent.fields.csrf,
    decision: overrides.decision ?? 'confirm',
  })
  const headers = {
    'content-type': 'application/x-www-form-urlencoded',
    origin: PUBLIC_BASE_URL.origin,
    cookie: consent.cookie,
    ...overrides.headers,
  }
  for (const name of overrides.omitHeaders ?? []) delete headers[name]
  return fetch(`${baseUrl}/oauth/consent`, {
    method: 'POST',
    redirect: 'manual',
    headers,
    body,
  })
}

function assertCookieCleared(response) {
  assert.equal(response.headers.get('set-cookie'), CLEAR_COOKIE)
}

function assertConsentResponseHardened(response) {
  assert.deepEqual({
    cacheControl: response.headers.get('cache-control'),
    setCookie: response.headers.get('set-cookie'),
  }, {
    cacheControl: 'no-store',
    setCookie: CLEAR_COOKIE,
  })
}

test('renders escaped browser consent with exact security headers and strict cookie', async (t) => {
  const fixture = await startFixture(t)
  const consent = await beginConsent(fixture)

  assert.equal(consent.response.headers.get('cache-control'), 'no-store')
  assert.equal(consent.response.headers.get('referrer-policy'), 'no-referrer')
  assert.equal(
    consent.response.headers.get('content-security-policy'),
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
  )
  assert.equal(consent.response.headers.get('x-frame-options'), 'DENY')
  assert.equal(
    consent.setCookie,
    `${COOKIE_NAME}=${consent.browserNonce}; ${COOKIE_ATTRIBUTES}`,
  )

  assert.equal(consent.html.includes(CLIENT_NAME), false)
  assert.match(consent.html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt; &amp; Codex/)
  assert.match(consent.html, /unverified client name/i)
  assert.match(consent.html, /127\.0\.0\.1:43123/)
  assert.match(consent.html, new RegExp(RESOURCE.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.match(consent.html, /zendesk:read/)
  assert.match(consent.html, /zendesk:write/)
  assert.match(consent.html, /localhost callback can be impersonated/i)
  assert.equal(consent.html.includes(consent.browserNonce), false)
  assert.equal((consent.html.match(/type="hidden"/g) ?? []).length, 2)
  assert.doesNotMatch(consent.html, /<(?:script|link|img|iframe)\b/i)
  assert.doesNotMatch(consent.html, /<[a-z][^>]*\s(?:src|href)\s*=/i)
  assert.equal(fixture.authorizationStates.length, 0)
})

test('confirms only after atomic consent, redirects to Zendesk, clears cookie, and rejects replay', async (t) => {
  const fixture = await startFixture(t)
  const consent = await beginConsent(fixture, 'confirm-state')
  fixture.gateway.onCreateAuthorizationUrl = () => {
    assert.deepEqual(fixture.store.decideConsent({
      transactionToken: consent.fields.transaction,
      consentCsrf: consent.fields.csrf,
      browserNonce: consent.browserNonce,
      decision: 'confirm',
      now: NOW,
    }), { kind: 'invalid' }, 'store consent must already be consumed before Zendesk redirect creation')
  }

  const confirmed = await consentRequest(fixture.baseUrl, consent)
  assert.equal(confirmed.status, 302)
  assertCookieCleared(confirmed)
  assert.equal(fixture.authorizationStates.length, 1)
  assert.equal(
    confirmed.headers.get('location'),
    `https://example.zendesk.com/oauth/authorizations/new?state=${fixture.authorizationStates[0]}`,
  )

  const replay = await consentRequest(fixture.baseUrl, consent)
  assert.equal(replay.status, 400)
  assertCookieCleared(replay)
  assert.equal(fixture.authorizationStates.length, 1)
})

test('denies to the exact trusted loopback redirect with only access_denied and original state', async (t) => {
  const fixture = await startFixture(t)
  const originalState = 'byte-for-byte-%2F-✓-&-state'
  const consent = await beginConsent(fixture, originalState)

  const denied = await consentRequest(fixture.baseUrl, consent, { decision: 'deny' })
  assert.equal(denied.status, 302)
  assertCookieCleared(denied)
  assert.equal(fixture.authorizationStates.length, 0)

  const location = denied.headers.get('location')
  assert.ok(location)
  const redirect = new URL(location)
  assert.equal(redirect.origin + redirect.pathname, REDIRECT_URI)
  assert.deepEqual([...redirect.searchParams.keys()], ['error', 'state'])
  assert.equal(redirect.searchParams.get('error'), 'access_denied')
  assert.equal(redirect.searchParams.get('state'), originalState)
})

test('fails closed on malformed, unbound, mixed, transplanted, and oversized consent posts', async (t) => {
  const fixture = await startFixture(t)
  const first = await beginConsent(fixture, 'first-state')
  const second = await beginConsent(fixture, 'second-state')

  const invalidRequests = [
    ['missing cookie', { omitHeaders: ['cookie'] }],
    ['wrong cookie', { headers: { cookie: `${COOKIE_NAME}=wrong` } }],
    ['duplicate named cookie', { headers: { cookie: `${first.cookie}; ${first.cookie}` } }],
    ['missing Origin', { omitHeaders: ['origin'] }],
    ['wrong Origin', { headers: { origin: 'https://attacker.example' } }],
    ['wrong CSRF', { body: new URLSearchParams({
      transaction: first.fields.transaction,
      csrf: 'wrong',
      decision: 'confirm',
    }) }],
    ['mixed transactions', { body: new URLSearchParams({
      transaction: first.fields.transaction,
      csrf: second.fields.csrf,
      decision: 'confirm',
    }) }],
    ['prefetch transplant', { headers: { cookie: second.cookie } }],
    ['wrong content type', {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        transaction: first.fields.transaction,
        csrf: first.fields.csrf,
        decision: 'confirm',
      }),
    }],
    ['invalid decision', { decision: 'approve' }],
  ]

  for (const [label, overrides] of invalidRequests) {
    const response = await consentRequest(fixture.baseUrl, first, overrides)
    assert.equal(response.status, 400, label)
    assertCookieCleared(response)
    assert.equal(fixture.authorizationStates.length, 0, label)
  }

  for (const field of ['transaction', 'csrf', 'decision']) {
    const body = new URLSearchParams({
      transaction: first.fields.transaction,
      csrf: first.fields.csrf,
      decision: 'confirm',
    })
    body.append(field, field === 'decision' ? 'deny' : body.get(field))
    const response = await consentRequest(fixture.baseUrl, first, { body })
    assert.equal(response.status, 400, `${field} must be scalar`)
    assertCookieCleared(response)
    assert.equal(fixture.authorizationStates.length, 0)
  }

  const oversized = await consentRequest(fixture.baseUrl, first, {
    body: new URLSearchParams({ transaction: 'x'.repeat(4_097) }),
  })
  assert.equal(oversized.status, 413)
  assertConsentResponseHardened(oversized)
  assert.equal(fixture.authorizationStates.length, 0)

  const validAfterFailures = await consentRequest(fixture.baseUrl, first)
  assert.equal(validAfterFailures.status, 302)
  assert.equal(fixture.authorizationStates.length, 1)
})
