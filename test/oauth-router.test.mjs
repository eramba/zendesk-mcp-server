import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'

import express from 'express'

import { createZendeskOAuthRouter } from '../dist/oauth/oauth-router.js'

const ISSUER = 'https://oauth.example.test/'
const RESOURCE = 'https://oauth.example.test/mcp'
const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const SCOPES = ['zendesk:read', 'zendesk:write']
const VERIFIER = 'v'.repeat(43)
const CHALLENGE = createHash('sha256').update(VERIFIER).digest('base64url')
const CLEAR_CONSENT_COOKIE = '__Secure-zendesk_oauth_consent=; HttpOnly; Secure; SameSite=Strict; Path=/oauth/consent; Max-Age=0'

const PUBLIC_CLIENT = {
  client_id: 'public-client',
  client_id_issued_at: 1_700_000_000,
  redirect_uris: [REDIRECT_URI],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'Codex Desktop',
  scope: SCOPES.join(' '),
}

async function startFixture(t) {
  const calls = {
    authorize: [],
    callback: [],
    consent: [],
    exchangeAuthorizationCode: [],
    exchangeRefreshToken: [],
    registerClient: [],
    revokeToken: [],
  }
  let nextClientId = 1
  const clients = new Map([[PUBLIC_CLIENT.client_id, PUBLIC_CLIENT]])
  const clientsStore = {
    getClient: (clientId) => clients.get(clientId),
    registerClient: (metadata) => {
      calls.registerClient.push(metadata)
      const client = {
        ...metadata,
        client_id: `registered-${nextClientId++}`,
        client_id_issued_at: 1_700_000_000,
      }
      clients.set(client.client_id, client)
      return client
    },
  }
  const provider = {
    clientsStore,
    skipLocalPkceValidation: false,
    authorize: async (client, params, res) => {
      calls.authorize.push({ client, params })
      res.status(204).end()
    },
    challengeForAuthorizationCode: async () => CHALLENGE,
    exchangeAuthorizationCode: async (...args) => {
      calls.exchangeAuthorizationCode.push(args)
      return {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        token_type: 'Bearer',
        expires_in: 900,
        scope: SCOPES.join(' '),
      }
    },
    exchangeRefreshToken: async (...args) => {
      calls.exchangeRefreshToken.push(args)
      return {
        access_token: 'refreshed-access-token',
        refresh_token: 'refreshed-refresh-token',
        token_type: 'Bearer',
        expires_in: 900,
        scope: SCOPES.join(' '),
      }
    },
    verifyAccessToken: async () => {
      throw new Error('not used')
    },
    revokeToken: async (...args) => {
      calls.revokeToken.push(args)
    },
  }

  const consentHandler = (req, res) => {
    calls.consent.push(req.body)
    res.status(204).end()
  }
  const callbackHandler = (req, res) => {
    calls.callback.push(req.query)
    res.status(204).end()
  }
  const app = express()
  app.use(createZendeskOAuthRouter({
    provider,
    issuerUrl: new URL(ISSUER),
    resourceUrl: new URL(RESOURCE),
    consentHandler,
    callbackHandler,
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
  return { baseUrl: `http://127.0.0.1:${address.port}`, calls }
}

function formRequest(body) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body),
  }
}

function assertConsentResponseHardened(response) {
  assert.deepEqual({
    cacheControl: response.headers.get('cache-control'),
    setCookie: response.headers.get('set-cookie'),
  }, {
    cacheControl: 'no-store',
    setCookie: CLEAR_CONSENT_COOKIE,
  })
}

async function assertLimiter(baseUrl, path, expectedLimit, expectedWindow, request) {
  let response
  for (let count = 1; count <= expectedLimit; count += 1) {
    response = await fetch(`${baseUrl}${path}`, request(count))
    assert.notEqual(response.status, 429, `${path} request ${count}`)
  }
  assert.equal(response.headers.get('ratelimit-policy'), `${expectedLimit};w=${expectedWindow}`)
  assert.equal(response.headers.get('ratelimit-limit'), String(expectedLimit))
  assert.equal(response.headers.get('x-ratelimit-limit'), null)

  response = await fetch(`${baseUrl}${path}`, request(expectedLimit + 1))
  assert.equal(response.status, 429, `${path} must reject request ${expectedLimit + 1}`)
  return response
}

test('serves exact path-specific resource and corrected public-client authorization metadata', async (t) => {
  const { baseUrl } = await startFixture(t)

  const protectedResponse = await fetch(
    `${baseUrl}/.well-known/oauth-protected-resource/mcp`,
  )
  assert.equal(protectedResponse.status, 200)
  assert.deepEqual(await protectedResponse.json(), {
    resource: RESOURCE,
    authorization_servers: [ISSUER],
    scopes_supported: SCOPES,
  })
  assert.equal(
    (await fetch(`${baseUrl}/.well-known/oauth-protected-resource`)).status,
    404,
  )

  const authorizationResponse = await fetch(
    `${baseUrl}/.well-known/oauth-authorization-server`,
  )
  assert.equal(authorizationResponse.status, 200)
  assert.deepEqual(await authorizationResponse.json(), {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}authorize`,
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint: `${ISSUER}token`,
    token_endpoint_auth_methods_supported: ['none'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    scopes_supported: SCOPES,
    revocation_endpoint: `${ISSUER}revoke`,
    revocation_endpoint_auth_methods_supported: ['none'],
    registration_endpoint: `${ISSUER}register`,
  })
})

test('uses SDK registration parsing, store-owned IDs, PKCE, and public token/revoke auth', async (t) => {
  const { baseUrl, calls } = await startFixture(t)
  const registration = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      application_type: 'native',
      redirect_uris: [REDIRECT_URI],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: 'Codex Desktop',
      scope: SCOPES.join(' '),
    }),
  })
  assert.equal(registration.status, 201)
  const registered = await registration.json()
  assert.equal(registered.client_id, 'registered-1')
  assert.equal(registered.client_secret, undefined)
  assert.equal(calls.registerClient.length, 1)
  assert.equal(calls.registerClient[0].application_type, undefined)
  assert.equal(calls.registerClient[0].client_id, undefined)
  assert.equal(calls.registerClient[0].client_id_issued_at, undefined)
  assert.equal(calls.registerClient[0].client_secret, undefined)

  const token = await fetch(`${baseUrl}/token`, formRequest({
    grant_type: 'authorization_code',
    client_id: PUBLIC_CLIENT.client_id,
    code: 'authorization-code',
    code_verifier: VERIFIER,
    redirect_uri: REDIRECT_URI,
    resource: RESOURCE,
  }))
  assert.equal(token.status, 200)
  assert.equal(calls.exchangeAuthorizationCode.length, 1)
  assert.equal(calls.exchangeAuthorizationCode[0][0].client_id, PUBLIC_CLIENT.client_id)
  assert.equal(calls.exchangeAuthorizationCode[0][2], undefined)
  assert.equal(calls.exchangeAuthorizationCode[0][3], REDIRECT_URI)
  assert.equal(calls.exchangeAuthorizationCode[0][4].href, RESOURCE)

  const revoke = await fetch(`${baseUrl}/revoke`, formRequest({
    client_id: PUBLIC_CLIENT.client_id,
    token: 'refresh-token',
    token_type_hint: 'refresh_token',
  }))
  assert.equal(revoke.status, 200)
  assert.deepEqual(await revoke.json(), {})
  assert.equal(calls.revokeToken.length, 1)
  assert.equal(calls.revokeToken[0][0].client_id, PUBLIC_CLIENT.client_id)
  assert.deepEqual(calls.revokeToken[0][1], {
    token: 'refresh-token',
    token_type_hint: 'refresh_token',
  })
})

test('applies the exact standard-only limiter policies to all OAuth and browser routes', async (t) => {
  const { baseUrl } = await startFixture(t)

  await assertLimiter(baseUrl, '/register', 20, 3600, (count) => ({
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      redirect_uris: [`http://127.0.0.1:${43000 + count}/callback`],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: 'Codex Desktop',
      scope: SCOPES.join(' '),
    }),
  }))
  await assertLimiter(baseUrl, '/authorize', 60, 900, (count) => ({
    method: 'GET',
    redirect: 'manual',
    headers: { accept: 'application/json' },
  }))
  await assertLimiter(baseUrl, '/token', 120, 900, () => formRequest({
    grant_type: 'refresh_token',
    client_id: PUBLIC_CLIENT.client_id,
    refresh_token: 'refresh-token',
  }))
  await assertLimiter(baseUrl, '/revoke', 120, 900, () => formRequest({
    client_id: PUBLIC_CLIENT.client_id,
    token: 'access-token',
  }))
  const limitedConsent = await assertLimiter(baseUrl, '/oauth/consent', 60, 900, () => formRequest({
    transaction: 'transaction',
    csrf: 'csrf',
    decision: 'confirm',
  }))
  assertConsentResponseHardened(limitedConsent)
  await assertLimiter(baseUrl, '/oauth/zendesk/callback', 60, 900, () => ({
    method: 'GET',
  }))
})

test('consent accepts only small flat URL-encoded forms', async (t) => {
  const { baseUrl, calls } = await startFixture(t)

  const accepted = await fetch(`${baseUrl}/oauth/consent`, formRequest({
    transaction: 'transaction',
    csrf: 'csrf',
    decision: 'confirm',
    note: 'flat',
  }))
  assert.equal(accepted.status, 204)
  assert.deepEqual(calls.consent[0], {
    transaction: 'transaction',
    csrf: 'csrf',
    decision: 'confirm',
    note: 'flat',
  })

  const tooManyParameters = await fetch(`${baseUrl}/oauth/consent`, formRequest({
    one: '1',
    two: '2',
    three: '3',
    four: '4',
    five: '5',
  }))
  assert.equal(tooManyParameters.status, 413)
  assertConsentResponseHardened(tooManyParameters)

  const tooLarge = await fetch(`${baseUrl}/oauth/consent`, formRequest({
    transaction: 'x'.repeat(4_097),
  }))
  assert.equal(tooLarge.status, 413)
  assertConsentResponseHardened(tooLarge)
  assert.equal(calls.consent.length, 1)
})
