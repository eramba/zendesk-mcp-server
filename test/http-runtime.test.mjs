import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const CONFIG = {
  host: '127.0.0.1',
  port: 38184,
  allowedHosts: ['broker.example.test', 'localhost', '127.0.0.1'],
  publicBaseUrl: new URL('https://broker.example.test/'),
  issuerUrl: new URL('https://broker.example.test/'),
  mcpResourceUrl: new URL('https://broker.example.test/mcp'),
  zendeskCallbackUrl: new URL('https://broker.example.test/oauth/zendesk/callback'),
  zendeskSubdomain: 'example',
  zendeskOAuthClientId: 'fixed-client-id',
  zendeskOAuthClientSecret: 'fixed-client-secret',
  oauthEncryptionKey: Buffer.alloc(32, 91),
  oauthDbPath: '/tmp/oauth-runtime-test.sqlite',
  mcpAccessTokenTtlSeconds: 900,
  zendeskHttpTimeoutMs: 15_000,
}

async function runtimeModule() {
  return import('../dist/http-runtime.js')
}

function fixture(overrides = {}) {
  const events = []
  let ready = true
  let appOptions
  let gatewayOptions
  const app = { kind: 'express-app' }
  const store = {
    assertReady() {
      events.push('readiness')
      if (!ready) throw new Error('store is not ready')
    },
    isReady() {
      events.push('local readiness')
      return ready
    },
    releaseClaims(owner, now) {
      events.push(`release claims:${owner}:${now}`)
      return 0
    },
    close() {
      events.push('store close')
    },
  }
  const dependencies = {
    now: () => 1_700_000_000,
    randomOwner: () => 'runtime-worker-owner',
    createCipher(key) {
      events.push('cipher')
      assert.equal(key, CONFIG.oauthEncryptionKey)
      return { kind: 'cipher' }
    },
    openStore(options) {
      events.push('store/migrate')
      assert.equal(options.path, CONFIG.oauthDbPath)
      assert.equal(options.cipher.kind, 'cipher')
      assert.equal(options.mcpResourceUrl, CONFIG.mcpResourceUrl)
      return store
    },
    createZendesk(options) {
      events.push('Zendesk gateway')
      gatewayOptions = options
      assert.deepEqual(
        {
          subdomain: options.subdomain,
          clientId: options.clientId,
          clientSecret: options.clientSecret,
          callbackUrl: options.callbackUrl.href,
          scopes: options.scopes,
          timeoutMs: options.timeoutMs,
        },
        {
          subdomain: 'example',
          clientId: 'fixed-client-id',
          clientSecret: 'fixed-client-secret',
          callbackUrl: 'https://broker.example.test/oauth/zendesk/callback',
          scopes: ['read', 'tickets:write'],
          timeoutMs: 15_000,
        },
      )
      return { kind: 'zendesk-gateway' }
    },
    createConsent(options) {
      events.push('consent')
      assert.equal(options.store, store)
      assert.equal(options.zendesk.kind, 'zendesk-gateway')
      assert.equal(options.publicBaseUrl, CONFIG.publicBaseUrl)
      assert.equal(options.subdomain, 'example')
      return { begin: async () => {}, handlePost: async () => {} }
    },
    createCallback(options) {
      events.push('callback')
      assert.equal(options.store, store)
      assert.equal(options.zendesk.kind, 'zendesk-gateway')
      assert.equal(options.subdomain, 'example')
      return { handle: async () => {} }
    },
    createProvider(options) {
      events.push('provider')
      assert.equal(options.store, store)
      assert.equal(options.resourceUrl, CONFIG.mcpResourceUrl)
      assert.equal(options.accessTokenTtlSeconds, 900)
      assert.equal(typeof options.startAuthorization, 'function')
      return { kind: 'provider' }
    },
    createRouter(options) {
      events.push('router')
      assert.equal(options.provider.kind, 'provider')
      assert.equal(options.issuerUrl, CONFIG.issuerUrl)
      assert.equal(options.resourceUrl, CONFIG.mcpResourceUrl)
      assert.equal(typeof options.consentHandler, 'function')
      assert.equal(typeof options.callbackHandler, 'function')
      return { kind: 'oauth-router' }
    },
    createResolver(options) {
      events.push('resolver')
      assert.equal(options.store, store)
      assert.equal(options.zendesk.kind, 'zendesk-gateway')
      assert.equal(options.subdomain, 'example')
      assert.equal(options.timeoutMs, 15_000)
      return { resolve: async () => assert.fail('runtime fixture must not resolve') }
    },
    createWorker(options) {
      events.push('worker')
      assert.equal(options.store, store)
      assert.equal(options.zendesk.kind, 'zendesk-gateway')
      assert.equal(options.timeoutMs, 15_000)
      assert.equal(options.randomOwner(), 'runtime-worker-owner')
      return {
        start() {
          events.push('worker start')
        },
        async stop() {
          events.push('stop claims')
          assert.equal(gatewayOptions.shutdownSignal.aborted, false)
          await Promise.resolve()
          assert.equal(gatewayOptions.shutdownSignal.aborted, true)
          events.push('abort/drain worker')
        },
      }
    },
    createApp(options) {
      events.push('app')
      appOptions = options
      assert.equal(options.host, '127.0.0.1')
      assert.deepEqual(options.allowedHosts, CONFIG.allowedHosts)
      assert.equal(options.provider.kind, 'provider')
      assert.equal(options.oauthRouter.kind, 'oauth-router')
      assert.equal(
        options.resourceMetadataUrl,
        'https://broker.example.test/.well-known/oauth-protected-resource/mcp',
      )
      return app
    },
    ...overrides,
  }
  return {
    app,
    dependencies,
    events,
    get appOptions() { return appOptions },
    get ready() { return ready },
    set ready(value) { ready = value },
    store,
  }
}

test('constructs the OAuth-only runtime in migration-safe dependency order', async () => {
  const { createHttpRuntime } = await runtimeModule()
  const f = fixture()
  const runtime = createHttpRuntime(CONFIG, f.dependencies)

  assert.equal(runtime.app, f.app)
  assert.deepEqual(f.events, [
    'cipher',
    'store/migrate',
    'Zendesk gateway',
    'consent',
    'callback',
    'provider',
    'router',
    'resolver',
    'worker',
    'app',
  ])

  assert.equal(f.appOptions.isReady(), true)
  assert.equal(f.events.at(-1), 'local readiness')
})

test('fails closed when cipher or store migration initialization fails', async () => {
  const { createHttpRuntime } = await runtimeModule()

  const cipherEvents = []
  const cipherFailure = fixture({
    createCipher() {
      cipherEvents.push('cipher')
      throw new Error('cipher startup failed')
    },
  })
  assert.throws(
    () => createHttpRuntime(CONFIG, cipherFailure.dependencies),
    /cipher startup failed/,
  )
  assert.deepEqual(cipherEvents, ['cipher'])
  assert.deepEqual(cipherFailure.events, [])

  const migrationEvents = []
  const migrationFailure = fixture({
    createCipher() {
      migrationEvents.push('cipher')
      return { kind: 'cipher' }
    },
    openStore() {
      migrationEvents.push('store/migrate')
      throw new Error('store migration failed')
    },
  })
  assert.throws(
    () => createHttpRuntime(CONFIG, migrationFailure.dependencies),
    /store migration failed/,
  )
  assert.deepEqual(migrationEvents, ['cipher', 'store/migrate'])
  assert.deepEqual(migrationFailure.events, [])
})

test('starts the worker only after local readiness and shuts down once in bounded order', async () => {
  const { attachHttpListener, createHttpRuntime } = await runtimeModule()
  const f = fixture()
  const runtime = createHttpRuntime(CONFIG, f.dependencies)
  f.events.length = 0

  f.ready = false
  assert.throws(() => runtime.startWorker(), /store is not ready/)
  assert.deepEqual(f.events, ['readiness'])

  f.ready = true
  runtime.startWorker()
  attachHttpListener(runtime, async () => {
    f.events.push('listener close')
  })

  await Promise.all([runtime.shutdown('SIGTERM'), runtime.shutdown('SIGINT')])
  assert.deepEqual(f.events, [
    'readiness',
    'readiness',
    'worker start',
    'stop claims',
    'abort/drain worker',
    'listener close',
    'release claims:runtime-worker-owner:1700000000',
    'store close',
  ])
})

test('HTTP entrypoint has no shared bearer, Basic credentials, or global ZendeskClient', async () => {
  const source = await readFile(new URL('../src/http.ts', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /readHttpConfig|readZendeskConfig|MCP_BEARER_TOKEN/)
  assert.doesNotMatch(source, /from ["']\.\/zendesk-client\.js["']|new ZendeskClient\s*\(/)
})

test('HTTP runtime has no global credential-bound ZendeskClient', async () => {
  const [{ createHttpRuntime }, source] = await Promise.all([
    runtimeModule(),
    readFile(new URL('../src/http-runtime.ts', import.meta.url), 'utf8'),
  ])
  assert.equal(typeof createHttpRuntime, 'function')
  assert.doesNotMatch(source, /from ["']\.\/zendesk-client\.js["']|new ZendeskClient\s*\(/)
})
