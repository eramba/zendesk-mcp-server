import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createHttpRuntime } from '../dist/http-runtime.js'

const config = {
  host: '127.0.0.1',
  port: 3000,
  allowedHosts: ['127.0.0.1'],
  publicBaseUrl: new URL('http://127.0.0.1:3000/'),
  zendeskSubdomain: 'acme',
  zendeskOAuthClientId: 'internal-mcp',
  zendeskOAuthClientSecret: 'client-secret-sentinel',
  oauthEncryptionKey: Buffer.alloc(32, 3),
  oauthDbPath: '/tmp/not-used.sqlite',
  zendeskCallbackUrl: new URL('http://127.0.0.1:3000/oauth/callback'),
  selfServiceEnrollmentEnabled: true,
}

test('runtime wires one fixed store, OAuth gateway, resolver, handlers, and app', () => {
  const calls = []
  const store = {
    authenticateBearer: (token) => ({ userId: token }),
    close: () => calls.push('store.close'),
  }
  const oauth = { fixed: 'oauth' }
  const resolver = { resolve: async () => ({}) }
  const handlers = {
    link() {},
    callback() {},
    createAccount() {},
    startEnrollment() {},
  }
  const app = { fixed: 'app' }

  const runtime = createHttpRuntime(config, {
    openStore: (options) => {
      calls.push('store.open')
      assert.equal(options.path, config.oauthDbPath)
      assert.equal(options.subdomain, 'acme')
      assert.equal(options.clientId, 'internal-mcp')
      return store
    },
    createOAuth: (options) => {
      calls.push('oauth.create')
      assert.equal(options.subdomain, 'acme')
      assert.equal(options.clientId, 'internal-mcp')
      assert.equal(options.callbackUrl.href, config.zendeskCallbackUrl.href)
      assert.equal(options.signal.aborted, false)
      return oauth
    },
    createResolver: (options) => {
      calls.push('resolver.create')
      assert.equal(options.store, store)
      assert.equal(options.oauth, oauth)
      assert.equal(options.subdomain, 'acme')
      assert.equal(options.signal.aborted, false)
      return resolver
    },
    createHandlers: (options) => {
      calls.push('handlers.create')
      assert.equal(options.store, store)
      assert.equal(options.oauth, oauth)
      assert.equal(options.publicBaseUrl.href, config.publicBaseUrl.href)
      assert.equal(options.selfServiceEnabled, true)
      return handlers
    },
    createApp: (options) => {
      calls.push('app.create')
      assert.deepEqual(options.authenticateBearer('selected-user'), {
        userId: 'selected-user',
      })
      assert.equal(options.resolver, resolver)
      assert.equal(options.linkHandlers, handlers)
      assert.equal(options.selfServiceEnrollmentEnabled, true)
      return app
    },
  })

  assert.equal(runtime.app, app)
  assert.equal(runtime.shutdownSignal.aborted, false)
  runtime.beginShutdown()
  assert.equal(runtime.shutdownSignal.aborted, true)
  runtime.close()
  runtime.close()
  assert.deepEqual(calls, [
    'store.open',
    'oauth.create',
    'resolver.create',
    'handlers.create',
    'app.create',
    'store.close',
  ])
})

test('runtime fails before app creation when the durable store cannot open', () => {
  let appCalls = 0
  assert.throws(
    () => createHttpRuntime(config, {
      openStore: () => {
        throw new Error('wrong-key-secret-sentinel')
      },
      createApp: () => {
        appCalls += 1
        return {}
      },
    }),
    (error) => {
      assert.equal(error.message.includes('wrong-key-secret-sentinel'), false)
      return true
    },
  )
  assert.equal(appCalls, 0)
})

test('default app keeps health public without bearer, credential, or OAuth access', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-http-runtime-'))
  let oauthCalls = 0
  const runtime = createHttpRuntime({
    ...config,
    oauthDbPath: join(directory, 'oauth.sqlite'),
  }, {
    createOAuth: () => ({
      authorizationUrl: () => {
        oauthCalls += 1
        return new URL('https://acme.zendesk.com/oauth/authorizations/new')
      },
      exchangeCode: async () => {
        oauthCalls += 1
        throw new Error('not expected')
      },
      refresh: async () => {
        oauthCalls += 1
        throw new Error('not expected')
      },
      currentUser: async () => {
        oauthCalls += 1
        throw new Error('not expected')
      },
      revokeCurrent: async () => {
        oauthCalls += 1
      },
    }),
  })
  t.after(() => runtime.close())
  const listener = runtime.app.listen(0, '127.0.0.1')
  t.after(() => listener.close())
  await new Promise((resolve) => listener.once('listening', resolve))
  const address = listener.address()
  const response = await fetch(`http://127.0.0.1:${address.port}/healthz`)

  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { ok: true })
  assert.equal(oauthCalls, 0)
})
