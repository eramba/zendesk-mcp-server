import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request } from 'node:http'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

import { createHttpApp } from '../dist/http-app.js'
import { buildZendeskServer } from '../dist/server.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

const BEARER_TOKEN = 'test-bearer-token'

function makeApp(overrides = {}) {
  return createHttpApp({
    host: '127.0.0.1',
    allowedHosts: ['127.0.0.1', 'localhost'],
    bearerToken: BEARER_TOKEN,
    client: new ZendeskClient({
      subdomain: 'example',
      auth: { kind: 'api_token', email: 'agent@example.test', apiToken: 'zendesk-token' },
    }),
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

test('mcp rejects missing and incorrect bearer tokens before building a server', async (t) => {
  let serversBuilt = 0
  const baseUrl = await listen(
    t,
    makeApp({
      serverFactory: (client) => {
        serversBuilt += 1
        return buildZendeskServer(client)
      },
    }),
  )

  for (const authorization of [undefined, 'Bearer wrong-token', 'Basic abc']) {
    const headers = { 'Content-Type': 'application/json' }
    if (authorization) headers.Authorization = authorization
    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers,
      body: '{}',
    })
    assert.equal(response.status, 401)
    assert.equal(response.headers.get('www-authenticate'), 'Bearer')
  }

  assert.equal(serversBuilt, 0)
})

test('host validation rejects an unapproved hostname', async (t) => {
  const baseUrl = await listen(t, makeApp())
  const response = await rawRequest(`${baseUrl}/healthz`, {
    headers: { Host: 'evil.example' },
  })

  assert.equal(response.status, 403)
})

test('authenticated GET and DELETE mcp requests return 405', async (t) => {
  const baseUrl = await listen(t, makeApp())

  for (const method of ['GET', 'DELETE']) {
    const response = await fetch(`${baseUrl}/mcp`, {
      method,
      headers: { Authorization: `Bearer ${BEARER_TOKEN}` },
    })
    assert.equal(response.status, 405)
    assert.equal(response.headers.get('allow'), 'POST')
  }
})

test('unexpected request setup failures return a protocol-shaped 500', async (t) => {
  const errors = []
  const originalConsoleError = console.error
  console.error = (...args) => {
    errors.push(args.join(' '))
  }
  t.after(() => {
    console.error = originalConsoleError
  })

  const baseUrl = await listen(
    t,
    makeApp({
      serverFactory: () => {
        throw new Error('test setup failure')
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

  assert.equal(response.status, 500)
  assert.deepEqual(await response.json(), {
    jsonrpc: '2.0',
    error: { code: -32603, message: 'Internal server error' },
    id: null,
  })
  assert.deepEqual(errors, ['Error handling MCP request: test setup failure'])
})

test('official SDK client initializes and every POST gets a fresh MCP server', async (t) => {
  let serversBuilt = 0
  let postsSent = 0
  const baseUrl = await listen(
    t,
    makeApp({
      serverFactory: (client) => {
        serversBuilt += 1
        return buildZendeskServer(client)
      },
    }),
  )

  const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
    requestInit: {
      headers: { Authorization: `Bearer ${BEARER_TOKEN}` },
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
    assert.ok(postsSent >= 2)
    assert.equal(serversBuilt, postsSent)
  } finally {
    await client.close()
  }
})
