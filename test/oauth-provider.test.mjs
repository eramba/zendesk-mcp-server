import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import express from 'express'
import {
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
  InvalidTokenError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { tokenHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/token.js'

import { ZendeskBrokerOAuthProvider } from '../dist/oauth/zendesk-broker-provider.js'
import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher, randomOpaque } from '../dist/oauth/token-cipher.js'

const NOW = 1_700_000_000
const ACCESS_TTL = 3_600
const REFRESH_TTL = 2_592_000
const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const OTHER_REDIRECT_URI = 'http://127.0.0.1:43124/callback'
const RESOURCE = 'https://dev-server.tail22145b.ts.net/mcp'
const OTHER_RESOURCE = 'https://other.example.test/mcp'
const CODE_CHALLENGE = 'C'.repeat(43)
const MCP_SCOPES = ['zendesk:read', 'zendesk:write']
const VALID_CLIENT = {
  redirect_uris: [REDIRECT_URI],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'Codex Desktop',
  scope: MCP_SCOPES.join(' '),
}

async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-provider-'))
  const path = join(directory, 'oauth.sqlite')
  const store = openSqliteOAuthStore({
    path,
    cipher: new TokenCipher(Buffer.alloc(32, options.keyByte ?? 61)),
    mcpResourceUrl: new URL(RESOURCE),
    now: () => options.currentTime?.value ?? NOW,
  })
  t.after(() => store.close())
  const client = store.registerClient(VALID_CLIENT)
  const starterCalls = []
  const provider = new ZendeskBrokerOAuthProvider({
    store,
    resourceUrl: new URL(RESOURCE),
    accessTokenTtlSeconds: ACCESS_TTL,
    startAuthorization: async (...args) => {
      starterCalls.push(args)
    },
    now: () => options.currentTime?.value ?? NOW,
  })
  return { store, client, provider, starterCalls }
}

function commitAuthorizationCode(store, clientId, label, now = NOW) {
  const started = store.beginLogin({
    clientId,
    redirectUri: REDIRECT_URI,
    codeChallenge: CODE_CHALLENGE,
    scopes: [...MCP_SCOPES].reverse(),
    resource: RESOURCE,
    originalState: `state-${label}`,
    subdomain: 'example',
    now,
  })
  const consent = store.decideConsent({
    transactionToken: started.transactionToken,
    consentCsrf: started.consentCsrf,
    browserNonce: started.browserNonce,
    decision: 'confirm',
    now,
  })
  assert.equal(consent.kind, 'confirmed')
  const callback = store.claimZendeskCallback(consent.upstreamState, now)
  assert.ok(callback)
  const staged = store.stageLoginGrant({
    transactionId: callback.transactionId,
    subdomain: 'example',
    grant: {
      accessToken: `zendesk-access-${label}`,
      refreshToken: `zendesk-refresh-${label}`,
      accessExpiresAt: now + 3_600,
      refreshExpiresAt: now + 86_400,
      scopes: ['tickets:write', 'read'],
    },
    now,
  })
  return store.commitLogin({
    transactionId: callback.transactionId,
    stageId: staged.stageId,
    zendeskUserId: '424242',
    now,
  })
}

async function issueFamily(store, provider, client, label, now = NOW) {
  const committed = commitAuthorizationCode(store, client.client_id, label, now)
  const tokens = await provider.exchangeAuthorizationCode(
    client,
    committed.authorizationCode,
    undefined,
    REDIRECT_URI,
    new URL(RESOURCE),
  )
  return { committed, tokens }
}

test('exposes the registered client store and keeps SDK-local PKCE validation enabled', async (t) => {
  const { store, provider } = await fixture(t)
  assert.equal(provider.clientsStore, store)
  assert.equal(provider.skipLocalPkceValidation, false)
})

test('authorize validates redirect, exact scopes, and canonical resource before calling the starter', async (t) => {
  const { client, provider, starterCalls } = await fixture(t)
  const response = {}
  const valid = {
    state: 'state',
    scopes: [...MCP_SCOPES].reverse(),
    codeChallenge: CODE_CHALLENGE,
    redirectUri: REDIRECT_URI,
    resource: new URL(RESOURCE),
  }

  await assert.rejects(provider.authorize(client, { ...valid, resource: undefined }, response), InvalidTargetError)
  await assert.rejects(provider.authorize(client, { ...valid, resource: new URL(OTHER_RESOURCE) }, response), InvalidTargetError)
  await assert.rejects(provider.authorize(client, { ...valid, scopes: ['zendesk:read'] }, response), InvalidScopeError)
  await assert.rejects(provider.authorize(client, { ...valid, redirectUri: OTHER_REDIRECT_URI }, response), InvalidRequestError)
  assert.equal(starterCalls.length, 0)

  await provider.authorize(client, valid, response)
  assert.equal(starterCalls.length, 1)
  assert.equal(starterCalls[0][0], client)
  assert.deepEqual(starterCalls[0][1], { ...valid, scopes: MCP_SCOPES })
  assert.equal(starterCalls[0][2], response)
})

test('challenge lookup is read-only and failed lookups map to invalid_grant', async (t) => {
  const { store, client, provider } = await fixture(t)
  const committed = commitAuthorizationCode(store, client.client_id, 'challenge')

  assert.equal(await provider.challengeForAuthorizationCode(client, committed.authorizationCode), CODE_CHALLENGE)
  assert.equal(await provider.challengeForAuthorizationCode(client, committed.authorizationCode), CODE_CHALLENGE)
  await assert.rejects(
    provider.challengeForAuthorizationCode(client, randomOpaque()),
    InvalidGrantError,
  )

  const tokens = await provider.exchangeAuthorizationCode(
    client,
    committed.authorizationCode,
    undefined,
    REDIRECT_URI,
    new URL(RESOURCE),
  )
  assert.equal(tokens.token_type, 'Bearer')
})

test('authorization-code exchange requires exact redirect and resource and maps store tokens', async (t) => {
  const { store, client, provider } = await fixture(t)

  for (const [label, redirectUri, resource, ErrorType] of [
    ['missing-redirect', undefined, new URL(RESOURCE), InvalidRequestError],
    ['wrong-redirect', OTHER_REDIRECT_URI, new URL(RESOURCE), InvalidGrantError],
    ['missing-resource', REDIRECT_URI, undefined, InvalidTargetError],
    ['wrong-resource', REDIRECT_URI, new URL(OTHER_RESOURCE), InvalidTargetError],
  ]) {
    const committed = commitAuthorizationCode(store, client.client_id, label)
    await assert.rejects(
      provider.exchangeAuthorizationCode(
        client,
        committed.authorizationCode,
        undefined,
        redirectUri,
        resource,
      ),
      ErrorType,
    )
  }

  const committed = commitAuthorizationCode(store, client.client_id, 'exchange')
  const tokens = await provider.exchangeAuthorizationCode(
    client,
    committed.authorizationCode,
    undefined,
    REDIRECT_URI,
    new URL(RESOURCE),
  )
  assert.deepEqual(Object.keys(tokens).sort(), [
    'access_token',
    'expires_in',
    'refresh_token',
    'scope',
    'token_type',
  ])
  assert.equal(tokens.token_type, 'Bearer')
  assert.equal(tokens.expires_in, ACCESS_TTL)
  assert.equal(tokens.scope, MCP_SCOPES.join(' '))
  await assert.rejects(
    provider.exchangeAuthorizationCode(
      client,
      committed.authorizationCode,
      undefined,
      REDIRECT_URI,
      new URL(RESOURCE),
    ),
    InvalidGrantError,
  )
})

test('installed SDK 1.26 performs PKCE locally and passes undefined codeVerifier to the provider', async (t) => {
  const { store, client } = await fixture(t)
  const verifier = 'v'.repeat(43)
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  let receivedVerifier = 'not-called'
  const sdkProvider = {
    clientsStore: store,
    skipLocalPkceValidation: false,
    challengeForAuthorizationCode: async () => challenge,
    exchangeAuthorizationCode: async (_client, _code, codeVerifier) => {
      receivedVerifier = codeVerifier
      return { access_token: 'access', token_type: 'Bearer' }
    },
  }
  const app = express()
  app.use('/token', tokenHandler({ provider: sdkProvider, rateLimit: false }))
  const server = app.listen(0, '127.0.0.1')
  t.after(() => new Promise((resolve) => server.close(resolve)))
  await new Promise((resolve, reject) => {
    server.once('listening', resolve)
    server.once('error', reject)
  })
  const address = server.address()
  assert.ok(address && typeof address !== 'string')

  const response = await fetch(`http://127.0.0.1:${address.port}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: client.client_id,
      code: 'authorization-code',
      code_verifier: verifier,
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
    }),
  })
  assert.equal(response.status, 200)
  assert.equal(receivedVerifier, undefined)
})

test('refresh inherits an omitted resource, rejects a supplied mismatch, and maps issued tokens', async (t) => {
  const { store, client, provider } = await fixture(t)
  const original = await issueFamily(store, provider, client, 'refresh-success')

  const refreshed = await provider.exchangeRefreshToken(
    client,
    original.tokens.refresh_token,
    undefined,
    undefined,
  )
  assert.equal(refreshed.token_type, 'Bearer')
  assert.equal(refreshed.expires_in, ACCESS_TTL)
  assert.equal(refreshed.scope, MCP_SCOPES.join(' '))

  await assert.rejects(
    provider.exchangeRefreshToken(
      client,
      refreshed.refresh_token,
      undefined,
      new URL(OTHER_RESOURCE),
    ),
    InvalidTargetError,
  )
})

test('every invalid refresh-store outcome maps to invalid_grant', async (t) => {
  await t.test('unknown or replayed token', async (t) => {
    const { client, provider } = await fixture(t, { keyByte: 62 })
    await assert.rejects(
      provider.exchangeRefreshToken(client, randomOpaque()),
      InvalidGrantError,
    )
  })

  await t.test('expired token', async (t) => {
    const currentTime = { value: NOW }
    const { store, client, provider } = await fixture(t, { currentTime, keyByte: 63 })
    const issued = await issueFamily(store, provider, client, 'expired-refresh')
    currentTime.value = NOW + REFRESH_TTL
    await assert.rejects(
      provider.exchangeRefreshToken(client, issued.tokens.refresh_token),
      InvalidGrantError,
    )
  })

  await t.test('revoked token', async (t) => {
    const { store, client, provider } = await fixture(t, { keyByte: 64 })
    const issued = await issueFamily(store, provider, client, 'revoked-refresh')
    await provider.revokeToken(client, { token: issued.tokens.access_token })
    await assert.rejects(
      provider.exchangeRefreshToken(client, issued.tokens.refresh_token),
      InvalidGrantError,
    )
  })

  await t.test('binding mismatch', async (t) => {
    const { store, client, provider } = await fixture(t, { keyByte: 65 })
    const issued = await issueFamily(store, provider, client, 'binding-refresh')
    await assert.rejects(
      provider.exchangeRefreshToken(client, issued.tokens.refresh_token, ['zendesk:read']),
      InvalidGrantError,
    )
  })
})

test('verifyAccessToken returns only canonical SDK AuthInfo and rejects invalid or wrong-resource records', async (t) => {
  const { store, client, provider } = await fixture(t)
  const issued = await issueFamily(store, provider, client, 'verify')

  assert.deepEqual(await provider.verifyAccessToken(issued.tokens.access_token), {
    token: issued.tokens.access_token,
    clientId: client.client_id,
    scopes: MCP_SCOPES,
    expiresAt: NOW + ACCESS_TTL,
    resource: new URL(RESOURCE),
    extra: { principalId: issued.committed.principalId },
  })
  assert.equal(Number.isSafeInteger((await provider.verifyAccessToken(issued.tokens.access_token)).expiresAt), true)
  await assert.rejects(provider.verifyAccessToken(randomOpaque()), InvalidTokenError)

  const wrongResourceStore = new Proxy(store, {
    get(target, property, receiver) {
      if (property === 'lookupAccessToken') {
        return () => ({
          clientId: client.client_id,
          principalId: issued.committed.principalId,
          scopes: MCP_SCOPES,
          resource: OTHER_RESOURCE,
          expiresAt: NOW + ACCESS_TTL,
        })
      }
      const value = Reflect.get(target, property, receiver)
      return typeof value === 'function' ? value.bind(target) : value
    },
  })
  const strictProvider = new ZendeskBrokerOAuthProvider({
    store: wrongResourceStore,
    resourceUrl: new URL(RESOURCE),
    accessTokenTtlSeconds: ACCESS_TTL,
    startAuthorization: async () => {},
    now: () => NOW,
  })
  await assert.rejects(
    strictProvider.verifyAccessToken(issued.tokens.access_token),
    InvalidTokenError,
  )
})

test('revoke ignores unknown and cross-client tokens and affects only the owned family', async (t) => {
  const { store, client, provider } = await fixture(t)
  const otherClient = store.registerClient({ ...VALID_CLIENT, client_name: 'Other client' })
  const owned = await issueFamily(store, provider, client, 'owned-family')
  const untouched = await issueFamily(store, provider, client, 'untouched-family', NOW + 1)

  await provider.revokeToken(otherClient, { token: owned.tokens.access_token, token_type_hint: 'access_token' })
  await provider.revokeToken(client, { token: randomOpaque(), token_type_hint: 'refresh_token' })
  assert.equal((await provider.verifyAccessToken(owned.tokens.access_token)).clientId, client.client_id)

  await provider.revokeToken(client, { token: owned.tokens.refresh_token, token_type_hint: 'refresh_token' })
  await assert.rejects(provider.verifyAccessToken(owned.tokens.access_token), InvalidTokenError)
  assert.equal((await provider.verifyAccessToken(untouched.tokens.access_token)).clientId, client.client_id)
})
