import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request } from 'node:http'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { createHttpApp } from '../dist/http-app.js'
import { SafeAuthError } from '../dist/internal-auth/errors.js'
import { buildZendeskServer } from '../dist/server.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

const BEARER_TOKEN = 'test-bearer-token'
const USER_ID = '00000000-0000-4000-8000-000000000001'

function apiClient(label = 'default') {
  return new ZendeskClient({
    subdomain: 'example',
    auth: {
      kind: 'api-token',
      email: `${label}@example.test`,
      token: `${label}-zendesk-token`,
    },
  })
}

function makeApp(overrides = {}) {
  return createHttpApp({
    host: '127.0.0.1',
    allowedHosts: ['127.0.0.1', 'localhost'],
    authenticateBearer: (token) =>
      token === BEARER_TOKEN ? { userId: USER_ID } : undefined,
    resolver: { resolve: async () => apiClient() },
    linkHandlers: {
      link: (_req, res) => res.status(204).end(),
      callback: (_req, res) => res.status(204).end(),
    },
    ...overrides,
  })
}

async function listen(t, app) {
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
  return `http://127.0.0.1:${address.port}`
}

function rawRequest(url, { method = 'GET', headers = {} } = {}) {
  const target = new URL(url)
  return new Promise((resolve, reject) => {
    const req = request(
      {
        hostname: target.hostname,
        port: target.port,
        path: target.pathname,
        method,
        headers,
      },
      (res) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => {
          body += chunk
        })
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }))
      },
    )
    req.on('error', reject)
    req.end()
  })
}

test('healthz is public and does not require Zendesk access', async (t) => {
  const baseUrl = await listen(t, makeApp())
  const response = await fetch(`${baseUrl}/healthz`)

  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { ok: true })
})

test('mcp rejects every invalid or inactive bearer shape before credential use or server creation', async (t) => {
  let serversBuilt = 0
  let resolverCalls = 0
  let credentialUses = 0
  const baseUrl = await listen(
    t,
    makeApp({
      authenticateBearer: (token) => {
        if (token === 'would-use-credentials') credentialUses += 1
        return undefined
      },
      resolver: {
        resolve: async () => {
          resolverCalls += 1
          throw new Error('resolver must not run')
        },
      },
      serverFactory: (client) => {
        serversBuilt += 1
        return buildZendeskServer(client)
      },
    }),
  )

  for (const authorization of [
    undefined,
    '',
    'Bearer',
    'Bearer ',
    'Bearer unknown',
    'Bearer pending',
    'Bearer revoked',
    'Bearer reauthorization-required',
    'Bearer token extra',
    'Basic abc',
    'Digest abc',
  ]) {
    const headers = { 'Content-Type': 'application/json' }
    if (authorization !== undefined) headers.Authorization = authorization
    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers,
      body: '{}',
    })
    assert.equal(response.status, 401)
    assert.equal(response.headers.get('www-authenticate'), 'Bearer')
  }

  assert.equal(serversBuilt, 0)
  assert.equal(resolverCalls, 0)
  assert.equal(credentialUses, 0)
})

test('host validation rejects an unapproved hostname', async (t) => {
  const baseUrl = await listen(t, makeApp())
  const response = await rawRequest(`${baseUrl}/healthz`, {
    headers: { Host: 'evil.example' },
  })

  assert.equal(response.status, 403)
})

test('authenticated GET and DELETE mcp requests return 405 without credential resolution', async (t) => {
  let resolverCalls = 0
  let serversBuilt = 0
  const baseUrl = await listen(t, makeApp({
    resolver: {
      resolve: async () => {
        resolverCalls += 1
        return apiClient()
      },
    },
    serverFactory: (client) => {
      serversBuilt += 1
      return buildZendeskServer(client)
    },
  }))

  for (const method of ['GET', 'DELETE']) {
    const response = await fetch(`${baseUrl}/mcp`, {
      method,
      headers: { Authorization: `Bearer ${BEARER_TOKEN}` },
    })
    assert.equal(response.status, 405)
    assert.equal(response.headers.get('allow'), 'POST')
  }
  assert.equal(resolverCalls, 0)
  assert.equal(serversBuilt, 0)
})

test('resolver failures are protocol-shaped, secret-free, and happen before serverFactory', async (t) => {
  const errors = []
  const originalConsoleError = console.error
  console.error = (...args) => {
    errors.push(args.join(' '))
  }
  t.after(() => {
    console.error = originalConsoleError
  })

  for (const [error, status, message] of [
    [
      new SafeAuthError('reauthorization_required', {
        correlationId: '00000000-0000-4000-8000-000000000011',
      }),
      401,
      'Unauthorized',
    ],
    [
      new SafeAuthError('temporarily_unavailable', {
        retryable: true,
        correlationId: '00000000-0000-4000-8000-000000000012',
      }),
      503,
      'Authentication temporarily unavailable',
    ],
    [new Error('setup-secret-sentinel'), 500, 'Internal server error'],
  ]) {
    let serversBuilt = 0
    const baseUrl = await listen(
      t,
      makeApp({
        resolver: { resolve: async () => { throw error } },
        serverFactory: () => {
          serversBuilt += 1
          throw new Error('factory-secret-sentinel')
        },
      }),
    )
    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${BEARER_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: '{}',
    })

    assert.equal(response.status, status)
    assert.equal((await response.json()).error.message, message)
    if (status === 401) {
      assert.equal(response.headers.get('www-authenticate'), 'Bearer')
    }
    assert.equal(serversBuilt, 0)
  }
  const rendered = errors.join(' ')
  assert.equal(rendered.includes('setup-secret-sentinel'), false)
  assert.equal(rendered.includes('factory-secret-sentinel'), false)
})

test('two bearer-selected users initialize distinct clients and every POST gets a fresh server', async (t) => {
  let serversBuilt = 0
  let postsSent = 0
  const firstClient = apiClient('first')
  const secondClient = apiClient('second')
  const clientsBuilt = []
  const baseUrl = await listen(
    t,
    makeApp({
      authenticateBearer: (token) => {
        if (token === 'first-bearer') return { userId: 'first-user' }
        if (token === 'second-bearer') return { userId: 'second-user' }
        return undefined
      },
      resolver: {
        resolve: async (userId) =>
          userId === 'first-user' ? firstClient : secondClient,
      },
      serverFactory: (client) => {
        serversBuilt += 1
        clientsBuilt.push(client)
        return buildZendeskServer(client)
      },
    }),
  )

  for (const bearer of ['first-bearer', 'second-bearer']) {
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: {
        headers: { Authorization: `Bearer ${bearer}` },
      },
      fetch: async (input, init) => {
        if (init?.method === 'POST') postsSent += 1
        return fetch(input, init)
      },
    })
    const client = new Client({ name: 'http-test-client', version: '1.0.0' })
    await client.connect(transport)
    try {
      const result = await client.listTools()
      const names = result.tools.map((tool) => tool.name)
      assert.ok(names.includes('get_ticket'))
      assert.ok(names.includes('create_ticket_comment'))
    } finally {
      await client.close()
    }
  }
  assert.ok(postsSent >= 4)
  assert.equal(serversBuilt, postsSent)
  assert.ok(clientsBuilt.includes(firstClient))
  assert.ok(clientsBuilt.includes(secondClient))
  assert.equal(clientsBuilt.some((client) => client !== firstClient && client !== secondClient), false)
})
