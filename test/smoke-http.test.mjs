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
const PROTECTED_RESOURCE_PATH = '/.well-known/oauth-protected-resource/mcp'
const AUTHORIZATION_SERVER_PATH = '/.well-known/oauth-authorization-server'

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

async function startProductionFixture(t, mutateContract = () => ({})) {
  const port = await reserveLocalPort()
  const issuer = `http://127.0.0.1:${port}/`
  const resource = `${issuer}mcp`
  const resourceMetadataUrl = `${issuer}.well-known/oauth-protected-resource/mcp`
  const contract = {
    challenge: `Bearer error="invalid_token", error_description="Missing Authorization header", scope="${SCOPES.join(' ')}", resource_metadata="${resourceMetadataUrl}"`,
    protectedResource: {
      resource,
      authorization_servers: [issuer],
      scopes_supported: [...SCOPES],
    },
    authorizationServer: {
      issuer,
      authorization_endpoint: `${issuer}authorize`,
      response_types_supported: ['code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint: `${issuer}token`,
      token_endpoint_auth_methods_supported: ['none'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      scopes_supported: [...SCOPES],
      revocation_endpoint: `${issuer}revoke`,
      revocation_endpoint_auth_methods_supported: ['none'],
      registration_endpoint: `${issuer}register`,
    },
  }
  const overrides = mutateContract(structuredClone(contract))
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
    resourceMetadataUrl,
    isReady: () => true,
    serverFactory: () => {
      calls.serverFactory += 1
      throw new Error('smoke fixture must not initialize an MCP server')
    },
  })
  const fixture = express()
  fixture.use((req, res, next) => {
    requests.push({
      method: req.method,
      path: req.path,
      authorization: req.get('authorization'),
    })
    if (req.path === '/mcp' && overrides.challenge !== undefined) {
      res.setHeader('WWW-Authenticate', overrides.challenge)
      res.status(401).json({ error: 'unauthorized' })
      return
    }
    if (
      req.path === PROTECTED_RESOURCE_PATH &&
      overrides.protectedResource !== undefined
    ) {
      res.json(overrides.protectedResource)
      return
    }
    if (
      req.path === AUTHORIZATION_SERVER_PATH &&
      overrides.authorizationServer !== undefined
    ) {
      res.json(overrides.authorizationServer)
      return
    }
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
  return { calls, contract, issuer, requests, resource }
}

async function startHungFixture(t) {
  const server = createServer(() => undefined)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(async () => {
    server.closeAllConnections()
    if (!server.listening) return
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve())
    })
  })
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  return `http://127.0.0.1:${address.port}/mcp`
}

async function runSmoke(env, timeout = 7_500) {
  const child = spawn(process.execPath, [fileURLToPath(SMOKE_SCRIPT)], {
    cwd: fileURLToPath(ROOT),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout,
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
  assert.deepEqual(
    [...source.matchAll(/requiredEnv\('([^']+)'\)/g)].map((match) => match[1]),
    ['MCP_URL'],
  )
  assert.match(source, /AbortSignal\.timeout\([\d_]+\)/)
  assert.doesNotMatch(source, /@modelcontextprotocol|\bClient\b|StreamableHTTPClientTransport/)
  assert.doesNotMatch(
    source,
    /MCP_BEARER_TOKEN|ZENDESK_(?:EMAIL|API_KEY|OAUTH_CLIENT_SECRET)|listTools|callTool/,
  )
})

test('one fixed overall deadline aborts a hung HTTP request with safe output', async (t) => {
  const resource = await startHungFixture(t)
  const startedAt = Date.now()
  const result = await runSmoke({ MCP_URL: resource })
  const elapsedMs = Date.now() - startedAt

  assert.equal(result.signal, null)
  assert.equal(result.code, 1)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr, 'HTTP OAuth smoke timed out\n')
  assert.ok(elapsedMs < 7_000, `smoke exceeded bounded deadline: ${elapsedMs}ms`)
})

test('fails closed for challenge and OAuth metadata mismatches or insecure extras', async (t) => {
  const cases = [
    {
      name: 'wrong challenge metadata URL',
      mutate: ({ challenge }) => ({
        challenge: challenge.replace(PROTECTED_RESOURCE_PATH, '/wrong-metadata'),
      }),
    },
    {
      name: 'extra challenge attribute',
      mutate: ({ challenge }) => ({
        challenge: `${challenge}, authorization_uri="http://attacker.invalid/authorize"`,
      }),
    },
    {
      name: 'wrong resource',
      mutate: ({ protectedResource }) => ({
        protectedResource: { ...protectedResource, resource: `${protectedResource.resource}/other` },
      }),
    },
    {
      name: 'wrong issuer',
      mutate: ({ authorizationServer }) => ({
        authorizationServer: { ...authorizationServer, issuer: 'http://attacker.invalid/' },
      }),
    },
    ...[
      ['authorization_endpoint', 'authorize-other'],
      ['token_endpoint', 'token-other'],
      ['revocation_endpoint', 'revoke-other'],
      ['registration_endpoint', 'register-other'],
    ].map(([field, path]) => ({
      name: `wrong ${field}`,
      mutate: ({ authorizationServer }) => ({
        authorizationServer: {
          ...authorizationServer,
          [field]: new URL(path, authorizationServer.issuer).href,
        },
      }),
    })),
    ...[
      ['response_types_supported', ['code', 'token']],
      ['code_challenge_methods_supported', ['S256', 'plain']],
      ['grant_types_supported', ['authorization_code', 'refresh_token', 'client_credentials']],
      ['scopes_supported', [...SCOPES, 'admin']],
    ].map(([field, value]) => ({
      name: `insecure ${field} extra`,
      mutate: ({ authorizationServer }) => ({
        authorizationServer: { ...authorizationServer, [field]: value },
      }),
    })),
    ...[
      'token_endpoint_auth_methods_supported',
      'revocation_endpoint_auth_methods_supported',
    ].map((field) => ({
      name: `insecure ${field} extra`,
      mutate: ({ authorizationServer }) => ({
        authorizationServer: {
          ...authorizationServer,
          [field]: ['none', 'client_secret_post'],
        },
      }),
    })),
    {
      name: 'extra authorization metadata field',
      mutate: ({ authorizationServer }) => ({
        authorizationServer: { ...authorizationServer, insecure_extension: true },
      }),
    },
  ]

  for (const scenario of cases) {
    const fixture = await startProductionFixture(t, scenario.mutate)
    const result = await runSmoke({ MCP_URL: fixture.resource })
    assert.equal(result.signal, null, scenario.name)
    assert.equal(result.code, 1, scenario.name)
    assert.equal(result.stdout, '', scenario.name)
    assert.doesNotMatch(result.stderr, /attacker|client_secret_post|admin/, scenario.name)
  }
})
