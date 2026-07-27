import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { createHttpApp } from '../dist/http-app.js'
import { UserClientResolver } from '../dist/internal-auth/client-resolver.js'
import { SecretCipher, randomOpaque } from '../dist/internal-auth/crypto.js'
import { InternalAuthStore } from '../dist/internal-auth/store.js'

const directory = await mkdtemp(join(tmpdir(), 'zendesk-mcp-local-smoke-'))
const store = InternalAuthStore.open({
  path: join(directory, 'oauth.sqlite'),
  cipher: new SecretCipher(Buffer.alloc(32, 37)),
  subdomain: 'fake',
  clientId: 'fake-client',
})
let listener
let client
let zendeskRequests = 0

try {
  const created = store.createPendingUser('Fake smoke user')
  const state = randomOpaque()
  const started = store.startInvitation(created.invitation, state)
  assert.ok(started)
  const claimed = store.claimCallback(state)
  assert.ok(claimed)
  const now = Math.floor(Date.now() / 1_000)
  store.completeLink({
    ...claimed,
    identity: {
      id: '999001',
      name: 'Fake smoke user',
      email: 'fake-smoke@example.test',
    },
    grant: {
      accessToken: 'fake-access-token',
      refreshToken: 'fake-refresh-token',
      accessExpiresAt: now + 1_800,
      refreshExpiresAt: now + 2_592_000,
      scopes: ['read', 'tickets:write'],
    },
  })

  const neverZendesk = async () => {
    zendeskRequests += 1
    throw new Error('Fake-only smoke attempted a Zendesk request')
  }
  const resolver = new UserClientResolver({
    store,
    oauth: {
      authorizationUrl: () => {
        throw new Error('not used')
      },
      exchangeCode: neverZendesk,
      refresh: neverZendesk,
      currentUser: neverZendesk,
      revokeCurrent: neverZendesk,
    },
    subdomain: 'fake',
    fetch: neverZendesk,
  })
  const app = createHttpApp({
    host: '127.0.0.1',
    allowedHosts: ['127.0.0.1'],
    authenticateBearer: (bearer) => store.authenticateBearer(bearer),
    resolver,
    linkHandlers: {
      link: (_request, response) => response.status(404).end(),
      callback: (_request, response) => response.status(404).end(),
    },
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

  const transport = new StreamableHTTPClientTransport(
    new URL(`${baseUrl}/mcp`),
    {
      requestInit: {
        headers: { authorization: `Bearer ${created.bearer}` },
      },
    },
  )
  client = new Client({ name: 'fake-local-smoke', version: '1.0.0' })
  await client.connect(transport)
  const tools = await client.listTools()

  assert.equal(health.status, 200)
  assert.equal(unauthenticated.status, 401)
  assert.ok(tools.tools.some(({ name }) => name === 'get_ticket'))
  assert.equal(zendeskRequests, 0)
  console.log(JSON.stringify({
    ok: true,
    healthStatus: health.status,
    unauthenticatedStatus: unauthenticated.status,
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
