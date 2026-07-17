import assert from 'node:assert/strict'
import { once } from 'node:events'
import { request } from 'node:http'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import express from 'express'

import { createHttpApp } from '../dist/http-app.js'
import { buildZendeskServer } from '../dist/server.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

const RESOURCE_METADATA_URL =
  'https://broker.example.test/.well-known/oauth-protected-resource/mcp'
const SCOPES = ['zendesk:read', 'zendesk:write']
const TOKENS = {
  principalA: 'mcp-access-a',
  principalB: 'mcp-access-b',
  missingRead: 'mcp-missing-read',
  missingWrite: 'mcp-missing-write',
  missingPrincipal: 'mcp-missing-principal',
  numericPrincipal: 'mcp-numeric-principal',
}

function oauthRouter() {
  const router = express.Router()
  for (const [method, path] of [
    ['get', '/.well-known/oauth-protected-resource/mcp'],
    ['get', '/.well-known/oauth-authorization-server'],
    ['post', '/register'],
    ['get', '/authorize'],
    ['post', '/token'],
    ['post', '/revoke'],
    ['post', '/oauth/consent'],
    ['get', '/oauth/zendesk/callback'],
  ]) {
    router[method](path, (_req, res) => {
      res.setHeader('X-OAuth-Route', path)
      res.status(204).end()
    })
  }
  return router
}

function authInfo(token, scopes, extra) {
  return {
    token,
    clientId: 'public-client',
    scopes,
    expiresAt: Math.floor(Date.now() / 1_000) + 3_600,
    resource: new URL('https://broker.example.test/mcp'),
    extra,
  }
}

function makeApp(overrides = {}) {
  const calls = {
    resolver: [],
    servers: [],
    verifier: [],
  }
  const provider = {
    async verifyAccessToken(token) {
      calls.verifier.push(token)
      switch (token) {
        case TOKENS.principalA:
          return authInfo(token, [...SCOPES], { principalId: 'principal-a' })
        case TOKENS.principalB:
          return authInfo(token, [...SCOPES], { principalId: 'principal-b' })
        case TOKENS.missingRead:
          return authInfo(token, ['zendesk:write'], { principalId: 'principal-a' })
        case TOKENS.missingWrite:
          return authInfo(token, ['zendesk:read'], { principalId: 'principal-a' })
        case TOKENS.missingPrincipal:
          return authInfo(token, [...SCOPES], {})
        case TOKENS.numericPrincipal:
          return authInfo(token, [...SCOPES], { principalId: 123 })
        default:
          throw new InvalidTokenError('access token is invalid')
      }
    },
  }
  const resolver = {
    async resolve(principalId) {
      calls.resolver.push(principalId)
      return new ZendeskClient({
        subdomain: 'example',
        auth: {
          kind: 'oauth',
          accessToken: `zendesk-${principalId}`,
          principalEpoch: 1,
          credentialVersion: 1,
          async onUnauthorized() {
            assert.fail('HTTP fixture must not refresh Zendesk credentials')
          },
        },
        fetch: async () => {
          assert.fail('HTTP fixture must not call Zendesk')
        },
      })
    },
  }
  const serverFactory = (client) => {
    calls.servers.push(client)
    return buildZendeskServer(client)
  }
  const app = createHttpApp({
    host: '127.0.0.1',
    allowedHosts: ['127.0.0.1', 'localhost'],
    provider,
    resolver,
    oauthRouter: oauthRouter(),
    resourceMetadataUrl: RESOURCE_METADATA_URL,
    isReady: () => true,
    serverFactory,
    ...overrides,
  })
  return { app, calls, provider, resolver, serverFactory }
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

function bearer(token) {
  return { Authorization: `Bearer ${token}` }
}

function sdkClient(baseUrl, token, name, onPost = () => undefined) {
  const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
    requestInit: { headers: bearer(token) },
    fetch: async (input, init) => {
      if (init?.method === 'POST') onPost()
      return fetch(input, init)
    },
  })
  return {
    client: new Client({ name, version: '1.0.0' }),
    transport,
  }
}

function resultJson(result) {
  assert.equal(result.content.length, 1)
  assert.equal(result.content[0].type, 'text')
  return JSON.parse(result.content[0].text)
}

test('healthz reports local readiness without bearer, resolver, server, or Zendesk access', async (t) => {
  let ready = true
  const { app, calls } = makeApp({ isReady: () => ready })
  const baseUrl = await listen(t, app)

  let response = await fetch(`${baseUrl}/healthz`)
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { ok: true })

  ready = false
  response = await fetch(`${baseUrl}/healthz`)
  assert.equal(response.status, 503)
  assert.deepEqual(await response.json(), { ok: false })
  assert.deepEqual(calls, { resolver: [], servers: [], verifier: [] })
})

test('mcp returns exact OAuth 401 challenges before resolving credentials', async (t) => {
  const { app, calls } = makeApp()
  const baseUrl = await listen(t, app)
  const expectedPrefix =
    'Bearer error="invalid_token", error_description="Missing Authorization header"'
  const expectedSuffix =
    `, scope="${SCOPES.join(' ')}", resource_metadata="${RESOURCE_METADATA_URL}"`

  let response = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  })
  assert.equal(response.status, 401)
  assert.equal(response.headers.get('www-authenticate'), expectedPrefix + expectedSuffix)
  assert.deepEqual(await response.json(), {
    error: 'invalid_token',
    error_description: 'Missing Authorization header',
  })

  response = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: { ...bearer('invalid-mcp-access'), 'Content-Type': 'application/json' },
    body: '{}',
  })
  assert.equal(response.status, 401)
  assert.equal(
    response.headers.get('www-authenticate'),
    'Bearer error="invalid_token", error_description="access token is invalid"' + expectedSuffix,
  )
  assert.deepEqual(await response.json(), {
    error: 'invalid_token',
    error_description: 'access token is invalid',
  })
  assert.deepEqual(calls.resolver, [])
  assert.deepEqual(calls.servers, [])
})

test('mcp returns exact 403 for a valid bearer missing either required scope', async (t) => {
  const { app, calls } = makeApp()
  const baseUrl = await listen(t, app)
  const expectedChallenge =
    `Bearer error="insufficient_scope", error_description="Insufficient scope", scope="${SCOPES.join(' ')}", resource_metadata="${RESOURCE_METADATA_URL}"`

  for (const token of [TOKENS.missingRead, TOKENS.missingWrite]) {
    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...bearer(token), 'Content-Type': 'application/json' },
      body: '{}',
    })
    assert.equal(response.status, 403)
    assert.equal(response.headers.get('www-authenticate'), expectedChallenge)
    assert.deepEqual(await response.json(), {
      error: 'insufficient_scope',
      error_description: 'Insufficient scope',
    })
  }

  assert.deepEqual(calls.resolver, [])
  assert.deepEqual(calls.servers, [])
})

test('host validation rejects an unapproved hostname', async (t) => {
  const { app } = makeApp()
  const baseUrl = await listen(t, app)
  const response = await rawRequest(`${baseUrl}/healthz`, {
    headers: { Host: 'evil.example' },
  })

  assert.equal(response.status, 403)
})

test('GET and DELETE require bearer then return protocol 405 without resolving credentials', async (t) => {
  const { app, calls } = makeApp()
  const baseUrl = await listen(t, app)

  for (const method of ['GET', 'DELETE']) {
    let response = await fetch(`${baseUrl}/mcp`, { method })
    assert.equal(response.status, 401)

    response = await fetch(`${baseUrl}/mcp`, {
      method,
      headers: bearer(TOKENS.principalA),
    })
    assert.equal(response.status, 405)
    assert.equal(response.headers.get('allow'), 'POST')
    assert.deepEqual(await response.json(), {
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Method not allowed' },
      id: null,
    })
  }

  assert.deepEqual(calls.resolver, [])
  assert.deepEqual(calls.servers, [])
})

test('OAuth metadata, registration, consent, and callback routes remain public', async (t) => {
  const { app, calls } = makeApp()
  const baseUrl = await listen(t, app)
  for (const [method, path] of [
    ['GET', '/.well-known/oauth-protected-resource/mcp'],
    ['GET', '/.well-known/oauth-authorization-server'],
    ['POST', '/register'],
    ['GET', '/authorize'],
    ['POST', '/token'],
    ['POST', '/revoke'],
    ['POST', '/oauth/consent'],
    ['GET', '/oauth/zendesk/callback'],
  ]) {
    const response = await fetch(`${baseUrl}${path}`, { method })
    assert.equal(response.status, 204, `${method} ${path}`)
    assert.equal(response.headers.get('x-oauth-route'), path)
  }
  assert.deepEqual(calls, { resolver: [], servers: [], verifier: [] })
})

test('valid principal bearer resolves once and creates a fresh server for every POST', async (t) => {
  const { app, calls } = makeApp()
  const baseUrl = await listen(t, app)
  let postsSent = 0
  const { client, transport } = sdkClient(
    baseUrl,
    TOKENS.principalA,
    'fresh-server-client',
    () => {
      postsSent += 1
    },
  )

  await client.connect(transport)
  try {
    const result = await client.listTools()
    const names = result.tools.map((tool) => tool.name)
    assert.ok(names.includes('get_ticket'))
    assert.ok(names.includes('create_ticket_comment'))
    assert.ok(postsSent >= 2)
    assert.equal(calls.resolver.length, postsSent)
    assert.deepEqual(calls.resolver, Array(postsSent).fill('principal-a'))
    assert.equal(calls.servers.length, postsSent)
    assert.equal(new Set(calls.servers).size, postsSent)
  } finally {
    await client.close()
  }
})

test('concurrent principal A/B POSTs keep Zendesk Bearer results and errors isolated', async (t) => {
  const zendeskRequests = []
  const zendeskFetch = async (input, init = {}) => {
    const url = new URL(input instanceof Request ? input.url : input)
    const headers = new Headers(input instanceof Request ? input.headers : undefined)
    for (const [name, value] of new Headers(init.headers)) headers.set(name, value)
    const authorization = headers.get('authorization')
    const ticketId = Number(/\/tickets\/(\d+)\.json$/.exec(url.pathname)?.[1])
    zendeskRequests.push({ authorization, ticketId })

    if (authorization === 'Bearer zendesk-principal-a' && ticketId === 303) {
      await new Promise((resolve) => setImmediate(resolve))
      return new Response('UPSTREAM_A_SECRET_SENTINEL', { status: 500 })
    }
    const expectedPrincipal = authorization === 'Bearer zendesk-principal-a'
      ? 'a'
      : authorization === 'Bearer zendesk-principal-b'
        ? 'b'
        : undefined
    assert.ok(expectedPrincipal, `unexpected Zendesk authorization scheme for ticket ${ticketId}`)
    await new Promise((resolve) => setImmediate(resolve))
    return new Response(
      JSON.stringify({ ticket: { id: ticketId, subject: `principal-${expectedPrincipal}` } }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    )
  }
  const resolverCalls = []
  const resolver = {
    async resolve(principalId) {
      resolverCalls.push(principalId)
      return new ZendeskClient({
        subdomain: 'example',
        auth: {
          kind: 'oauth',
          accessToken: `zendesk-${principalId}`,
          principalEpoch: 1,
          credentialVersion: 1,
          async onUnauthorized() {
            assert.fail('isolation fixture must not refresh')
          },
        },
        fetch: zendeskFetch,
      })
    },
  }
  const { app, calls } = makeApp({ resolver })
  const baseUrl = await listen(t, app)
  const a = sdkClient(baseUrl, TOKENS.principalA, 'principal-a-client')
  const b = sdkClient(baseUrl, TOKENS.principalB, 'principal-b-client')

  await Promise.all([a.client.connect(a.transport), b.client.connect(b.transport)])
  try {
    const [resultA, resultB] = await Promise.all([
      a.client.callTool({ name: 'get_ticket', arguments: { ticket_id: 101 } }),
      b.client.callTool({ name: 'get_ticket', arguments: { ticket_id: 202 } }),
    ])
    assert.equal(resultJson(resultA).subject, 'principal-a')
    assert.equal(resultJson(resultB).subject, 'principal-b')

    const [errorA, laterB] = await Promise.all([
      a.client.callTool({ name: 'get_ticket', arguments: { ticket_id: 303 } }),
      b.client.callTool({ name: 'get_ticket', arguments: { ticket_id: 404 } }),
    ])
    assert.equal(errorA.isError, true)
    assert.match(errorA.content[0].text, /temporarily_unavailable/)
    assert.doesNotMatch(errorA.content[0].text, /UPSTREAM_A_SECRET_SENTINEL|principal-b/)
    assert.equal(laterB.isError, undefined)
    assert.equal(resultJson(laterB).subject, 'principal-b')
  } finally {
    await Promise.all([a.client.close(), b.client.close()])
  }

  assert.deepEqual(zendeskRequests.toSorted((left, right) => left.ticketId - right.ticketId), [
    { authorization: 'Bearer zendesk-principal-a', ticketId: 101 },
    { authorization: 'Bearer zendesk-principal-b', ticketId: 202 },
    { authorization: 'Bearer zendesk-principal-a', ticketId: 303 },
    { authorization: 'Bearer zendesk-principal-b', ticketId: 404 },
  ])
  assert.ok(resolverCalls.includes('principal-a'))
  assert.ok(resolverCalls.includes('principal-b'))
  assert.equal(calls.servers.length, resolverCalls.length)
})

test('non-string principals and setup failures return sanitized protocol 500 responses', async (t) => {
  const errors = []
  const originalConsoleError = console.error
  console.error = (...args) => {
    errors.push(args.join(' '))
  }
  t.after(() => {
    console.error = originalConsoleError
  })

  const { app, calls } = makeApp()
  const baseUrl = await listen(t, app)
  for (const token of [TOKENS.missingPrincipal, TOKENS.numericPrincipal]) {
    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...bearer(token), 'Content-Type': 'application/json' },
      body: '{}',
    })
    assert.equal(response.status, 500)
    assert.deepEqual(await response.json(), {
      jsonrpc: '2.0',
      error: { code: -32603, message: 'Internal server error' },
      id: null,
    })
  }
  assert.deepEqual(calls.resolver, [])
  assert.deepEqual(calls.servers, [])

  const sensitive = 'SETUP_DETAIL_WITH_TOKEN_AND_ZENDESK_VALUE'
  const failing = makeApp({
    serverFactory: () => {
      throw new Error(sensitive)
    },
  })
  const failingUrl = await listen(t, failing.app)
  const response = await fetch(`${failingUrl}/mcp`, {
    method: 'POST',
    headers: { ...bearer(TOKENS.principalA), 'Content-Type': 'application/json' },
    body: '{}',
  })
  assert.equal(response.status, 500)
  assert.deepEqual(await response.json(), {
    jsonrpc: '2.0',
    error: { code: -32603, message: 'Internal server error' },
    id: null,
  })
  assert.equal(failing.calls.resolver.length, 1)
  assert.equal(failing.calls.servers.length, 0)
  assert.deepEqual(errors, [
    'Error handling MCP request',
    'Error handling MCP request',
    'Error handling MCP request',
  ])
  assert.equal(errors.some((line) => line.includes(sensitive)), false)
})
