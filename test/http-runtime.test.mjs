import assert from 'node:assert/strict'
import { once } from 'node:events'
import { readFile } from 'node:fs/promises'
import { createServer, request } from 'node:http'
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

async function lifecycleModule() {
  return import('../dist/http-lifecycle.js')
}

async function appModule() {
  return import('../dist/http-app.js')
}

async function oauthRouterModule() {
  return import('../dist/oauth/oauth-router.js')
}

async function waitFor(predicate, message) {
  const deadline = Date.now() + 2_000
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${message}`)
    await new Promise((resolve) => setImmediate(resolve))
  }
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

test('forced connection close still waits for the listener close callback before store teardown', async () => {
  const [
    { closeHttpListener },
    { attachHttpListener, createHttpRuntime },
  ] = await Promise.all([lifecycleModule(), runtimeModule()])
  const f = fixture()
  const runtime = createHttpRuntime(CONFIG, f.dependencies)
  f.events.length = 0
  let closeCallback
  const listener = {
    close(callback) {
      f.events.push('listener close requested')
      closeCallback = callback
    },
    closeAllConnections() {
      f.events.push('force close connections')
    },
  }
  runtime.startWorker()
  attachHttpListener(runtime, () => closeHttpListener(listener, {
    graceMs: 0,
    onGraceExpired() {
      f.events.push('grace expired')
    },
  }))

  let shutdownSettled = false
  const shutdown = runtime.shutdown('SIGTERM').finally(() => {
    shutdownSettled = true
  })
  try {
    await waitFor(
      () => f.events.includes('force close connections'),
      'forced listener connection close',
    )

    assert.equal(shutdownSettled, false)
    assert.deepEqual(f.events, [
      'readiness',
      'worker start',
      'stop claims',
      'abort/drain worker',
      'listener close requested',
      'grace expired',
      'force close connections',
    ])
  } finally {
    if (typeof closeCallback === 'function') {
      f.events.push('listener close callback')
      closeCallback()
    }
    await Promise.allSettled([shutdown])
  }

  await shutdown
  assert.deepEqual(f.events, [
    'readiness',
    'worker start',
    'stop claims',
    'abort/drain worker',
    'listener close requested',
    'grace expired',
    'force close connections',
    'listener close callback',
    'release claims:runtime-worker-owner:1700000000',
    'store close',
  ])
})

test('real forced listener close does not tear down the store before an aborted handler promise drains', async () => {
  const [
    { createHttpApp },
    { closeHttpListener },
    { createZendeskOAuthRouter },
    { attachHttpListener, createHttpRuntime },
  ] = await Promise.all([
    appModule(),
    lifecycleModule(),
    oauthRouterModule(),
    runtimeModule(),
  ])
  let shutdownSignal
  let handlerSawReady
  let resolveHandlerStarted
  let resolveHandlerContinuation
  let resolveListenerClosed
  const handlerStarted = new Promise((resolve) => {
    resolveHandlerStarted = resolve
  })
  const handlerContinuation = new Promise((resolve) => {
    resolveHandlerContinuation = resolve
  })
  const listenerClosed = new Promise((resolve) => {
    resolveListenerClosed = resolve
  })
  const f = fixture({
    createZendesk(options) {
      shutdownSignal = options.shutdownSignal
      return { kind: 'zendesk-gateway' }
    },
    createConsent() {
      return {
        begin: async () => {},
        async handlePost(_request, response) {
          f.events.push('handler start')
          resolveHandlerStarted()
          if (!shutdownSignal.aborted) {
            await once(shutdownSignal, 'abort')
          }
          f.events.push('handler abort observed')
          await handlerContinuation
          f.events.push('handler continuation')
          handlerSawReady = f.store.isReady()
          response.status(204).end()
        },
      }
    },
    createProvider() {
      return {
        kind: 'provider',
        clientsStore: {
          async registerClient(client) { return client },
        },
        async revokeToken() {},
      }
    },
    createWorker() {
      return {
        start() {},
        async stop() {
          f.events.push('stop claims')
          assert.equal(shutdownSignal.aborted, false)
          await Promise.resolve()
          assert.equal(shutdownSignal.aborted, true)
          f.events.push('abort/drain worker')
        },
      }
    },
    createRouter: createZendeskOAuthRouter,
    createApp: createHttpApp,
  })
  const closeStore = f.store.close
  f.store.close = () => {
    f.ready = false
    closeStore.call(f.store)
  }
  const runtime = createHttpRuntime(CONFIG, f.dependencies)
  f.events.length = 0
  const listener = runtime.app.listen(0, '127.0.0.1')
  await once(listener, 'listening')
  const address = listener.address()
  assert.notEqual(address, null)
  assert.equal(typeof address, 'object')
  attachHttpListener(runtime, async () => {
    await closeHttpListener(listener, { graceMs: 0 })
    f.events.push('listener close callback')
    resolveListenerClosed()
  })

  const clientRequest = new Promise((resolve) => {
    const outgoing = request({
      host: '127.0.0.1',
      port: address.port,
      path: '/oauth/consent',
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        host: '127.0.0.1',
      },
    }, (response) => {
      response.resume()
      response.on('end', resolve)
    })
    outgoing.on('error', resolve)
    outgoing.end('decision=deny')
  })
  await handlerStarted

  const shutdown = runtime.shutdown('SIGTERM')
  await listenerClosed
  await new Promise((resolve) => setImmediate(resolve))
  try {
    assert.equal(f.events.includes('handler abort observed'), true)
    assert.equal(f.events.includes('store close'), false)
    assert.equal(f.events.some((event) => event.startsWith('release claims:')), false)
  } finally {
    resolveHandlerContinuation()
    await Promise.allSettled([shutdown, clientRequest])
  }

  assert.equal(handlerSawReady, true)
  assert.ok(f.events.indexOf('handler continuation') < f.events.indexOf('store close'))
  assert.ok(f.events.indexOf('local readiness') < f.events.indexOf('store close'))
  assert.deepEqual(f.events.slice(-2), [
    'release claims:runtime-worker-owner:1700000000',
    'store close',
  ])
})

test('operation drain timeout fails safely without releasing claims or closing the live store', async () => {
  const { attachHttpListener, createHttpRuntime } = await runtimeModule()
  const f = fixture({ shutdownTimeoutMs: 0 })
  const runtime = createHttpRuntime(CONFIG, f.dependencies)
  f.events.length = 0
  let keepOperationPending
  const pending = new Promise((resolve) => {
    keepOperationPending = resolve
  })
  void f.appOptions.operationTracker.track(async () => pending)
  attachHttpListener(runtime, async () => {
    f.events.push('listener close')
  })

  try {
    await assert.rejects(
      runtime.shutdown('SIGTERM'),
      { message: 'HTTP operations did not drain before shutdown deadline' },
    )
    assert.deepEqual(f.events, [
      'stop claims',
      'abort/drain worker',
      'listener close',
    ])
    assert.equal(f.ready, true)
  } finally {
    keepOperationPending()
  }
})

test('one absolute shutdown deadline gives worker, listener, and drain only the remaining budget', async () => {
  const { attachHttpListener, createHttpRuntime } = await runtimeModule()
  let monotonicNow = 0
  const listenerBudgets = []
  const drainBudgets = []
  const f = fixture({
    shutdownTimeoutMs: 10_000,
    monotonicNow: () => monotonicNow,
    createWorker() {
      return {
        start() {},
        async stop() {
          f.events.push('stop claims')
          monotonicNow += 2_000
          f.events.push('abort/drain worker')
        },
      }
    },
  })
  const runtime = createHttpRuntime(CONFIG, f.dependencies)
  f.events.length = 0
  f.appOptions.operationTracker.drain = async (remainingMs) => {
    drainBudgets.push(remainingMs)
  }
  attachHttpListener(runtime, async (remainingMs) => {
    listenerBudgets.push(remainingMs)
    monotonicNow += 5_000
    f.events.push('listener close')
  })

  await Promise.all([runtime.shutdown('SIGTERM'), runtime.shutdown('SIGINT')])

  assert.deepEqual(listenerBudgets, [8_000])
  assert.deepEqual(drainBudgets, [3_000])
  assert.equal(monotonicNow, 7_000)
  assert.deepEqual(f.events, [
    'stop claims',
    'abort/drain worker',
    'listener close',
    'release claims:runtime-worker-owner:1700000000',
    'store close',
  ])
})

test('listener exhausting the absolute deadline gives live operations zero budget and never closes the store', async () => {
  const { attachHttpListener, createHttpRuntime } = await runtimeModule()
  let monotonicNow = 0
  const listenerBudgets = []
  const drainBudgets = []
  const f = fixture({
    shutdownTimeoutMs: 10_000,
    monotonicNow: () => monotonicNow,
  })
  const runtime = createHttpRuntime(CONFIG, f.dependencies)
  f.events.length = 0
  let resolveOperation
  const pendingOperation = new Promise((resolve) => {
    resolveOperation = resolve
  })
  void f.appOptions.operationTracker.track(async () => pendingOperation)
  const originalDrain = f.appOptions.operationTracker.drain.bind(
    f.appOptions.operationTracker,
  )
  f.appOptions.operationTracker.drain = async (remainingMs) => {
    drainBudgets.push(remainingMs)
    return originalDrain(remainingMs)
  }
  attachHttpListener(runtime, async (remainingMs) => {
    listenerBudgets.push(remainingMs)
    monotonicNow = 10_000
    f.events.push('listener close')
  })

  try {
    await assert.rejects(
      runtime.shutdown('SIGTERM'),
      { message: 'HTTP operations did not drain before shutdown deadline' },
    )
    assert.deepEqual(listenerBudgets, [10_000])
    assert.deepEqual(drainBudgets, [0])
    assert.equal(monotonicNow, 10_000)
    assert.deepEqual(f.events, [
      'stop claims',
      'abort/drain worker',
      'listener close',
    ])
    assert.equal(f.ready, true)
  } finally {
    resolveOperation()
  }
})

test('asynchronous listen errors enter the same one-shot runtime shutdown as signals', async () => {
  const [
    { startHttpLifecycle },
    { createHttpRuntime },
  ] = await Promise.all([lifecycleModule(), runtimeModule()])
  const f = fixture()
  const runtime = createHttpRuntime(CONFIG, f.dependencies)
  f.events.length = 0
  let resolveStoreClosed
  const storeClosed = new Promise((resolve) => {
    resolveStoreClosed = resolve
  })
  const closeStore = f.store.close
  f.store.close = () => {
    closeStore.call(f.store)
    resolveStoreClosed()
  }
  let errorHandler
  const signalHandlers = new Map()
  const logs = []
  const processState = {
    exitCode: undefined,
    once(signal, handler) {
      signalHandlers.set(signal, handler)
    },
  }
  const listener = {
    on(event, handler) {
      assert.equal(event, 'error')
      errorHandler = handler
    },
    close(callback) {
      f.events.push('listener close')
      callback()
    },
    closeAllConnections() {
      assert.fail('immediate listener close must not reach the grace timer')
    },
  }

  startHttpLifecycle(runtime, listener, {
    process: processState,
    logError(...values) {
      logs.push(values.join(' '))
    },
  })
  assert.equal(typeof errorHandler, 'function')
  assert.deepEqual([...signalHandlers.keys()], ['SIGINT', 'SIGTERM'])

  const error = Object.assign(new Error('address already in use'), { code: 'EADDRINUSE' })
  errorHandler(error)
  await storeClosed

  assert.equal(processState.exitCode, 1)
  assert.deepEqual(logs, ['HTTP listener error: address already in use'])
  const errorShutdownEvents = [
    'readiness',
    'worker start',
    'stop claims',
    'abort/drain worker',
    'listener close',
    'release claims:runtime-worker-owner:1700000000',
    'store close',
  ]
  assert.deepEqual(f.events, errorShutdownEvents)

  signalHandlers.get('SIGINT')()
  signalHandlers.get('SIGTERM')()
  await Promise.resolve()
  assert.deepEqual(f.events, errorShutdownEvents)
})

test('real EADDRINUSE listen failure treats an unstarted listener as closed and tears down once', async () => {
  const [
    { startHttpLifecycle },
    { createHttpRuntime },
  ] = await Promise.all([lifecycleModule(), runtimeModule()])
  const occupied = createServer()
  occupied.listen(0, '127.0.0.1')
  await once(occupied, 'listening')
  const address = occupied.address()
  assert.ok(address && typeof address === 'object')

  const f = fixture()
  const runtime = createHttpRuntime(CONFIG, f.dependencies)
  f.events.length = 0
  let resolveStoreClosed
  const storeClosed = new Promise((resolve) => {
    resolveStoreClosed = resolve
  })
  const closeStore = f.store.close
  f.store.close = () => {
    closeStore.call(f.store)
    resolveStoreClosed()
  }
  const listener = createServer()
  const listenerError = once(listener, 'error')
  const logs = []
  const processState = {
    exitCode: undefined,
    once() {},
  }

  try {
    listener.listen(address.port, '127.0.0.1')
    startHttpLifecycle(runtime, listener, {
      process: processState,
      logError(...values) {
        logs.push(values.join(' '))
      },
    })
    const [error] = await listenerError
    assert.equal(error.code, 'EADDRINUSE')
    await Promise.race([
      storeClosed,
      new Promise((_, reject) => setTimeout(
        () => reject(new Error('store did not close after EADDRINUSE')),
        50,
      )),
    ])
  } finally {
    await new Promise((resolve) => occupied.close(resolve))
  }

  assert.equal(processState.exitCode, 1)
  assert.equal(logs.some((message) => message.startsWith('HTTP listener error:')), true)
  assert.equal(logs.some((message) => message.startsWith('HTTP shutdown error:')), false)
  assert.deepEqual(f.events, [
    'readiness',
    'worker start',
    'stop claims',
    'abort/drain worker',
    'release claims:runtime-worker-owner:1700000000',
    'store close',
  ])
})

test('HTTP entrypoint has no shared bearer, Basic credentials, or global ZendeskClient', async () => {
  const source = await readFile(new URL('../src/http.ts', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /readHttpConfig|readZendeskConfig|MCP_BEARER_TOKEN/)
  assert.doesNotMatch(source, /from ["']\.\/zendesk-client\.js["']|new ZendeskClient\s*\(/)
})

test('HTTP entrypoint does not finish grace close before the listener callback', async () => {
  const source = await readFile(new URL('../src/http.ts', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /closeAllConnections\(\);\s*finish\(\)/s)
})

test('HTTP entrypoint routes listen errors through the shared shutdown lifecycle', async () => {
  const source = await readFile(new URL('../src/http.ts', import.meta.url), 'utf8')
  assert.match(source, /startHttpLifecycle\(runtime, listener\)/)
})

test('HTTP runtime has no global credential-bound ZendeskClient', async () => {
  const [{ createHttpRuntime }, source] = await Promise.all([
    runtimeModule(),
    readFile(new URL('../src/http-runtime.ts', import.meta.url), 'utf8'),
  ])
  assert.equal(typeof createHttpRuntime, 'function')
  assert.doesNotMatch(source, /from ["']\.\/zendesk-client\.js["']|new ZendeskClient\s*\(/)
})

test('HTTP runtime composes promise-based operation tracking across mutable OAuth and MCP routes', async () => {
  const [runtimeSource, appSource, routerSource] = await Promise.all([
    readFile(new URL('../src/http-runtime.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src/http-app.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src/oauth/oauth-router.ts', import.meta.url), 'utf8'),
  ])

  assert.match(runtimeSource, /operationTracker\.drain/)
  assert.match(appSource, /operationTracker/)
  assert.match(appSource, /requireBearerAuth/)
  assert.match(appSource, /app\.post\("\/mcp"/)
  assert.match(routerSource, /operationTracker/)
  assert.match(routerSource, /consentHandler/)
  assert.match(routerSource, /callbackHandler/)
  assert.match(routerSource, /authorizationHandler|clientRegistrationHandler/)
  assert.match(routerSource, /tokenHandler|revocationHandler/)
})
