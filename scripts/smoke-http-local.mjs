import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { createHttpApp } from '../dist/http-app.js'
import { UserClientResolver } from '../dist/internal-auth/client-resolver.js'
import { SecretCipher } from '../dist/internal-auth/crypto.js'
import { createLinkHandlers } from '../dist/internal-auth/link-handlers.js'
import { InternalAuthStore } from '../dist/internal-auth/store.js'

const directory = await mkdtemp(join(tmpdir(), 'zendesk-mcp-local-smoke-'))
const store = InternalAuthStore.open({
  path: join(directory, 'oauth.sqlite'),
  cipher: new SecretCipher(Buffer.alloc(32, 37)),
  subdomain: 'fake',
  clientId: 'fake-client',
})
const publicBaseUrl = new URL('http://127.0.0.1:38184/')
let listener
let client
let zendeskRequests = 0

try {
  const now = Math.floor(Date.now() / 1_000)
  const oauthCalls = {
    authorizationStates: [],
    exchanges: [],
    identities: [],
  }
  const oauth = {
    authorizationUrl(state) {
      oauthCalls.authorizationStates.push(state)
      const url = new URL('https://fake.zendesk.com/oauth/authorizations/new')
      url.searchParams.set('state', state)
      return url
    },
    async exchangeCode(code) {
      oauthCalls.exchanges.push(code)
      return {
        accessToken: 'fake-access-token',
        refreshToken: 'fake-refresh-token',
        accessExpiresAt: now + 1_800,
        refreshExpiresAt: now + 2_592_000,
        scopes: ['read', 'tickets:write'],
      }
    },
    async currentUser(accessToken) {
      oauthCalls.identities.push(accessToken)
      return {
        id: '999001',
        name: 'Fake smoke agent',
        email: 'fake-smoke@example.test',
        role: 'agent',
      }
    },
    async revokeCurrent() {
      assert.fail('successful smoke enrollment must not revoke')
    },
    async refresh() {
      assert.fail('fresh smoke credentials must not refresh')
    },
  }

  const neverZendesk = async () => {
    zendeskRequests += 1
    throw new Error('Fake-only smoke attempted a Zendesk request')
  }
  const resolver = new UserClientResolver({
    store,
    oauth,
    subdomain: 'fake',
    fetch: neverZendesk,
  })
  const linkHandlers = createLinkHandlers({
    store,
    oauth,
    publicBaseUrl,
    zendeskAuthorizationOrigin: new URL('https://fake.zendesk.com/'),
    selfServiceEnabled: true,
  })
  const app = createHttpApp({
    host: '127.0.0.1',
    allowedHosts: ['127.0.0.1'],
    authenticateBearer: (bearer) => store.authenticateBearer(bearer),
    resolver,
    selfServiceEnrollmentEnabled: true,
    linkHandlers,
  })
  listener = app.listen(0, '127.0.0.1')
  await once(listener, 'listening')
  const address = listener.address()
  assert.ok(address && typeof address === 'object')
  const baseUrl = `http://127.0.0.1:${address.port}`

  const health = await fetch(`${baseUrl}/healthz`)
  const unauthenticated = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  })
  const enrollmentPageResponse = await fetch(`${baseUrl}/create-account`)
  const enrollmentPageBody = await enrollmentPageResponse.text()
  const enrollmentStart = await fetch(`${baseUrl}/create-account`, {
    method: 'POST',
    headers: { Origin: publicBaseUrl.origin },
    redirect: 'manual',
  })
  const authorizationLocation = new URL(
    enrollmentStart.headers.get('location'),
  )
  const state = authorizationLocation.searchParams.get('state')
  const callback = await fetch(
    `${baseUrl}/oauth/callback?code=fake-smoke-code&state=${state}`,
  )
  const callbackBody = await callback.text()
  const bearer = callbackBody.match(/zmcp_[A-Za-z0-9_-]{43}/)?.[0]
  assert.ok(bearer)
  const replay = await fetch(
    `${baseUrl}/oauth/callback?code=fake-replay-code&state=${state}`,
  )

  const transport = new StreamableHTTPClientTransport(
    new URL(`${baseUrl}/mcp`),
    {
      requestInit: {
        headers: { authorization: `Bearer ${bearer}` },
      },
    },
  )
  client = new Client({ name: 'fake-local-smoke', version: '1.0.0' })
  await client.connect(transport)
  const tools = await client.listTools()

  assert.equal(health.status, 200)
  assert.equal(unauthenticated.status, 401)
  assert.equal(enrollmentPageResponse.status, 200)
  assert.match(enrollmentPageBody, /Connect Zendesk/)
  assert.equal(enrollmentStart.status, 302)
  assert.equal(authorizationLocation.origin, 'https://fake.zendesk.com')
  assert.match(state, /^[A-Za-z0-9_-]{43}$/)
  assert.equal(callback.status, 200)
  assert.ok(store.authenticateBearer(bearer))
  assert.equal(replay.status, 400)
  assert.deepEqual(oauthCalls.authorizationStates, [state])
  assert.deepEqual(oauthCalls.exchanges, ['fake-smoke-code'])
  assert.deepEqual(oauthCalls.identities, ['fake-access-token'])
  assert.ok(tools.tools.some(({ name }) => name === 'get_ticket'))
  assert.equal(zendeskRequests, 0)
  console.log(JSON.stringify({
    ok: true,
    healthStatus: health.status,
    unauthenticatedStatus: unauthenticated.status,
    enrollmentPage: true,
    oauthRedirect: true,
    enrollmentCompleted: true,
    replayRejected: true,
    initialized: true,
    toolsListed: true,
    zendeskRequests,
  }))
} finally {
  await client?.close().catch(() => undefined)
  if (listener?.listening) {
    await new Promise((resolve) => listener.close(resolve))
  }
  store.close()
  await rm(directory, { recursive: true, force: true })
}
