import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { readFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import express from 'express'

import { createHttpApp } from '../dist/http-app.js'
import { createZendeskOAuthRouter } from '../dist/oauth/oauth-router.js'

const ROOT = new URL('../', import.meta.url)
const SMOKE_SCRIPT = new URL('../scripts/smoke-http.mjs', import.meta.url)
const SCOPES = ['zendesk:read', 'zendesk:write']

async function reserveLocalPort() {
  const reservation = createServer()
  reservation.listen(0, '127.0.0.1')
  await once(reservation, 'listening')
  const address = reservation.address()
  assert.ok(address && typeof address === 'object')
  await new Promise((resolve, reject) => {
    reservation.close((error) => error ? reject(error) : resolve())
  })
  return address.port
}

async function startProductionFixture(t) {
  const port = await reserveLocalPort()
  const issuer = `http://127.0.0.1:${port}/`
  const resource = `${issuer}mcp`
  const requests = []
  const calls = { resolver: 0, serverFactory: 0, verifier: 0 }
  const clientsStore = {
    getClient: () => undefined,
    registerClient: () => {
      throw new Error('smoke fixture must not register a client')
    },
  }
  const provider = {
    clientsStore,
    authorize: async () => {
      throw new Error('smoke fixture must not authorize a client')
    },
    challengeForAuthorizationCode: async () => '',
    exchangeAuthorizationCode: async () => {
      throw new Error('smoke fixture must not exchange a code')
    },
    exchangeRefreshToken: async () => {
      throw new Error('smoke fixture must not refresh a token')
    },
    async verifyAccessToken() {
      calls.verifier += 1
      throw new Error('smoke fixture must not verify a copied bearer')
    },
    revokeToken: async () => {
      throw new Error('smoke fixture must not revoke a token')
    },
  }
  const oauthRouter = createZendeskOAuthRouter({
    provider,
    issuerUrl: new URL(issuer),
    resourceUrl: new URL(resource),
    consentHandler: (_req, res) => res.status(204).end(),
    callbackHandler: (_req, res) => res.status(204).end(),
  })
  const productionApp = createHttpApp({
    host: '127.0.0.1',
    allowedHosts: ['127.0.0.1', 'localhost'],
    provider,
    resolver: {
      async resolve() {
        calls.resolver += 1
        throw new Error('smoke fixture must not resolve Zendesk credentials')
      },
    },
    oauthRouter,
    resourceMetadataUrl: `${issuer}.well-known/oauth-protected-resource/mcp`,
    isReady: () => true,
    serverFactory: () => {
      calls.serverFactory += 1
      throw new Error('smoke fixture must not initialize an MCP server')
    },
  })
  const fixture = express()
  fixture.use((req, _res, next) => {
    requests.push({
      method: req.method,
      path: req.path,
      authorization: req.get('authorization'),
    })
    next()
  })
  fixture.use(productionApp)

  const listener = fixture.listen(port, '127.0.0.1')
  await once(listener, 'listening')
  t.after(async () => {
    if (!listener.listening) return
    await new Promise((resolve, reject) => {
      listener.close((error) => error ? reject(error) : resolve())
    })
  })
  return { calls, issuer, requests, resource }
}

async function runSmoke(env) {
  const child = spawn(process.execPath, [fileURLToPath(SMOKE_SCRIPT)], {
    cwd: fileURLToPath(ROOT),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 5_000,
  })
  let stdout = ''
  let stderr = ''
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  child.stdout.on('data', (chunk) => { stdout += chunk })
  child.stderr.on('data', (chunk) => { stderr += chunk })
  const [code, signal] = await once(child, 'close')
  return { code, signal, stderr, stdout }
}

test('requires only MCP_URL and validates exact OAuth discovery without credentials', async (t) => {
  const missingUrl = await runSmoke({})
  assert.notEqual(missingUrl.code, 0)
  assert.match(missingUrl.stderr, /Missing required environment variable: MCP_URL/)

  const fixture = await startProductionFixture(t)
  const result = await runSmoke({ MCP_URL: fixture.resource })

  assert.equal(result.signal, null)
  assert.equal(result.code, 0, result.stderr)
  assert.equal(result.stderr, '')
  assert.deepEqual(JSON.parse(result.stdout), {
    ok: true,
    issuer: fixture.issuer,
    resource: fixture.resource,
  })
  assert.deepEqual(fixture.requests, [
    { method: 'GET', path: '/healthz', authorization: undefined },
    { method: 'GET', path: '/mcp', authorization: undefined },
    {
      method: 'GET',
      path: '/.well-known/oauth-protected-resource/mcp',
      authorization: undefined,
    },
    {
      method: 'GET',
      path: '/.well-known/oauth-authorization-server',
      authorization: undefined,
    },
  ])
  assert.deepEqual(fixture.calls, { resolver: 0, serverFactory: 0, verifier: 0 })
})

test('uses fetch discovery only and contains no credential or MCP client path', async () => {
  const source = await readFile(SMOKE_SCRIPT, 'utf8')

  assert.match(source, /\bfetch\s*\(/)
  assert.doesNotMatch(source, /@modelcontextprotocol|\bClient\b|StreamableHTTPClientTransport/)
  assert.doesNotMatch(
    source,
    /MCP_BEARER_TOKEN|ZENDESK_(?:EMAIL|API_KEY|OAUTH_CLIENT_SECRET)|listTools|callTool/,
  )
})
