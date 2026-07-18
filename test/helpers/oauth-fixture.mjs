import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { readFile, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createHttpApp } from '../../dist/http-app.js'
import { ConsentController } from '../../dist/oauth/consent.js'
import { createZendeskOAuthRouter } from '../../dist/oauth/oauth-router.js'
import { ZendeskRevocationWorker } from '../../dist/oauth/revocation-worker.js'
import { openSqliteOAuthStore } from '../../dist/oauth/sqlite-store.js'
import { TokenCipher } from '../../dist/oauth/token-cipher.js'
import { ZendeskBrokerOAuthProvider } from '../../dist/oauth/zendesk-broker-provider.js'
import { ZendeskCallbackController } from '../../dist/oauth/zendesk-callback.js'
import { ZendeskClientResolver } from '../../dist/oauth/zendesk-client-resolver.js'
import { ZendeskOAuthClient } from '../../dist/oauth/zendesk-oauth-client.js'

const SCOPES = ['zendesk:read', 'zendesk:write']
const ZENDESK_SCOPES = ['read', 'tickets:write']
const COOKIE_NAME = '__Secure-zendesk_oauth_consent'

function responseJson(body, status = 200) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: status === 204 ? undefined : { 'content-type': 'application/json' },
  })
}

function requestParts(input, init = {}) {
  const url = new URL(input instanceof Request ? input.url : input)
  const headers = new Headers(input instanceof Request ? input.headers : undefined)
  for (const [name, value] of new Headers(init.headers)) headers.set(name, value)
  return {
    url,
    headers,
    method: (init.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase(),
  }
}

async function requestBody(input, init) {
  if (init.body !== undefined && init.body !== null) return String(init.body)
  return input instanceof Request ? input.clone().text() : ''
}

function createIntegratedFakeZendesk(now) {
  const requests = []
  const authorizationCodes = new Map()
  const accessOwners = new Map()
  const refreshOwners = new Map()
  const ticketFailures = new Map()
  const waiters = []
  const barriers = []
  let refreshSequence = 0

  function notify(request) {
    for (let index = waiters.length - 1; index >= 0; index -= 1) {
      if (waiters[index].predicate(request)) {
        const [waiter] = waiters.splice(index, 1)
        waiter.resolve(request)
      }
    }
  }

  async function waitAtBarrier(request) {
    const barrier = barriers.find((candidate) =>
      !candidate.released && candidate.predicate(request))
    if (!barrier) return
    barrier.active += 1
    barrier.maxActive = Math.max(barrier.maxActive, barrier.active)
    if (barrier.active >= barrier.expectedCount) barrier.resolveReached()
    try {
      await barrier.pendingRelease
    } finally {
      barrier.active -= 1
    }
  }

  function ownerFrom(headers) {
    const authorization = headers.get('authorization')
    if (!authorization?.startsWith('Bearer ')) return undefined
    return accessOwners.get(authorization.slice('Bearer '.length))
  }

  const fetch = async (input, init = {}) => {
    const { url, headers, method } = requestParts(input, init)
    const body = await requestBody(input, init)
    let json
    if (body && headers.get('content-type')?.includes('application/json')) {
      json = JSON.parse(body)
    }
    const request = {
      method,
      pathname: url.pathname,
      authorization: headers.get('authorization'),
      json,
      url: url.href,
    }
    requests.push(request)
    notify(request)
    await waitAtBarrier(request)

    if (method === 'POST' && url.pathname === '/oauth/tokens') {
      if (json?.grant_type === 'authorization_code') {
        const grant = authorizationCodes.get(json.code)
        if (!grant) return responseJson({ error: 'invalid_grant' }, 400)
        authorizationCodes.delete(json.code)
        accessOwners.set(grant.accessToken, grant.zendeskUserId)
        refreshOwners.set(grant.refreshToken, grant.zendeskUserId)
        return responseJson({
          access_token: grant.accessToken,
          refresh_token: grant.refreshToken,
          token_type: 'Bearer',
          scope: ZENDESK_SCOPES.join(' '),
          expires_in: grant.accessExpiresIn,
          refresh_token_expires_in: grant.refreshExpiresIn,
        })
      }
      if (json?.grant_type === 'refresh_token') {
        const zendeskUserId = refreshOwners.get(json.refresh_token)
        if (!zendeskUserId) return responseJson({ error: 'invalid_grant' }, 400)
        refreshOwners.delete(json.refresh_token)
        refreshSequence += 1
        const accessToken = `upstream-access-${zendeskUserId}-refresh-${refreshSequence}`
        const refreshToken = `upstream-refresh-${zendeskUserId}-refresh-${refreshSequence}`
        accessOwners.set(accessToken, zendeskUserId)
        refreshOwners.set(refreshToken, zendeskUserId)
        return responseJson({
          access_token: accessToken,
          refresh_token: refreshToken,
          token_type: 'Bearer',
          scope: ZENDESK_SCOPES.join(' '),
          expires_in: 1_800,
          refresh_token_expires_in: 2_592_000,
        })
      }
      return responseJson({ error: 'invalid_request' }, 400)
    }

    const zendeskUserId = ownerFrom(headers)
    if (!zendeskUserId) return responseJson({ error: 'unauthorized' }, 401)

    if (method === 'GET' && url.pathname === '/api/v2/users/me.json') {
      return responseJson({ user: { id: Number(zendeskUserId) } })
    }
    if (method === 'DELETE' && url.pathname === '/api/v2/oauth/tokens/current.json') {
      accessOwners.delete(headers.get('authorization').slice('Bearer '.length))
      return responseJson(undefined, 204)
    }

    const ticketMatch = /^\/api\/v2\/tickets\/(\d+)\.json$/.exec(url.pathname)
    if (method === 'GET' && ticketMatch) {
      const ticketId = Number(ticketMatch[1])
      const failure = ticketFailures.get(`${zendeskUserId}:${ticketId}`)
      if (failure) return responseJson({ error: failure }, 500)
      return responseJson({
        ticket: {
          id: ticketId,
          subject: `Principal ${zendeskUserId} ticket`,
          description: `Visible only to ${zendeskUserId}`,
        },
      })
    }
    if (method === 'GET' && url.pathname === '/api/v2/help_center/sections.json') {
      return responseJson({
        sections: [{ id: Number(zendeskUserId) + 1_000, name: `Principal ${zendeskUserId}` }],
        links: { next: null },
      })
    }
    const articleMatch = /^\/api\/v2\/help_center\/sections\/(\d+)\/articles\.json$/.exec(url.pathname)
    if (method === 'GET' && articleMatch) {
      return responseJson({
        articles: [{
          id: Number(articleMatch[1]) + 1,
          title: `Principal ${zendeskUserId} article`,
          body: `Knowledge for ${zendeskUserId}`,
        }],
        links: { next: null },
      })
    }
    return responseJson({ error: 'not_found' }, 404)
  }

  return {
    fetch,
    requests,
    registerAuthorizationCode(code, {
      zendeskUserId,
      accessToken = `upstream-access-${zendeskUserId}`,
      refreshToken = `upstream-refresh-${zendeskUserId}`,
      accessExpiresIn = 1_800,
      refreshExpiresIn = 2_592_000,
    }) {
      authorizationCodes.set(code, {
        zendeskUserId: String(zendeskUserId),
        accessToken,
        refreshToken,
        accessExpiresIn,
        refreshExpiresIn,
      })
    },
    failTicket(zendeskUserId, ticketId, sentinel) {
      ticketFailures.set(`${zendeskUserId}:${ticketId}`, sentinel)
    },
    waitForRequest(predicate, { timeoutMs = 1_000 } = {}) {
      const existing = requests.find(predicate)
      if (existing) return Promise.resolve(existing)
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
        return Promise.reject(new Error('Fake Zendesk wait timeout must be a positive integer'))
      }
      return new Promise((resolve, reject) => {
        const waiter = {
          predicate,
          resolve(request) {
            clearTimeout(waiter.timeout)
            resolve(request)
          },
          timeout: undefined,
        }
        waiter.timeout = setTimeout(() => {
          const index = waiters.indexOf(waiter)
          if (index !== -1) waiters.splice(index, 1)
          reject(new Error(`Timed out waiting for fake Zendesk request after ${timeoutMs}ms`))
        }, timeoutMs)
        waiters.push(waiter)
      })
    },
    holdRequests(predicate, expectedCount, { timeoutMs = 1_000 } = {}) {
      if (!Number.isSafeInteger(expectedCount) || expectedCount <= 0) {
        throw new Error('Fake Zendesk barrier count must be a positive integer')
      }
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
        throw new Error('Fake Zendesk barrier timeout must be a positive integer')
      }
      let resolveReached
      let rejectReached
      let resolveRelease
      const barrier = {
        active: 0,
        maxActive: 0,
        expectedCount,
        predicate,
        reached: new Promise((resolve, reject) => {
          resolveReached = resolve
          rejectReached = reject
        }),
        pendingRelease: new Promise((resolve) => { resolveRelease = resolve }),
        released: false,
        resolveReached() {
          clearTimeout(barrier.timeout)
          resolveReached()
        },
        release() {
          if (barrier.released) return
          barrier.released = true
          clearTimeout(barrier.timeout)
          resolveRelease()
          const index = barriers.indexOf(barrier)
          if (index !== -1) barriers.splice(index, 1)
        },
        timeout: undefined,
      }
      barrier.timeout = setTimeout(() => {
        barrier.release()
        rejectReached(new Error(
          `Timed out waiting for ${expectedCount} concurrent fake Zendesk requests after ${timeoutMs}ms`,
        ))
      }, timeoutMs)
      barriers.push(barrier)
      return barrier
    },
    accessOwner(accessToken) {
      return accessOwners.get(accessToken)
    },
  }
}

function hiddenFields(html) {
  return Object.fromEntries(
    [...html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)]
      .map((match) => [match[1], match[2]]),
  )
}

async function closeListener(listener) {
  if (!listener?.listening) return
  await new Promise((resolve, reject) => {
    listener.close((error) => error ? reject(error) : resolve())
  })
}

export async function createOAuthFixture(t, options = {}) {
  const now = options.currentTime ?? { value: Math.floor(Date.now() / 1_000) }
  const directoryPrefix = join(tmpdir(), 'zendesk-oauth-e2e-')
  const directory = await mkdtemp(directoryPrefix)
  const dbPath = join(directory, 'oauth.sqlite')
  const publicBaseUrl = new URL('https://broker.example.test/')
  const resourceUrl = new URL('/mcp', publicBaseUrl)
  const redirectUri = options.redirectUri ?? 'http://127.0.0.1:43123/callback'
  const fakeZendesk = createIntegratedFakeZendesk(now)
  const originalFetch = globalThis.fetch
  const originalConsole = {
    error: console.error,
    log: console.log,
    warn: console.warn,
  }
  const logs = []
  let store
  let listener
  let worker
  let baseUrl
  let client
  let login
  let mcpCode
  let backupSequence = 0
  let closed = false

  const collect = (...args) => logs.push(args.map(String).join(' '))
  console.error = collect
  console.log = collect
  console.warn = collect
  globalThis.fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input)
    return url.hostname.endsWith('.zendesk.com')
      ? fakeZendesk.fetch(input, init)
      : originalFetch(input, init)
  }

  async function buildRuntime() {
    store = openSqliteOAuthStore({
      path: dbPath,
      cipher: new TokenCipher(Buffer.alloc(32, options.keyByte ?? 109)),
      mcpResourceUrl: resourceUrl,
      now: () => now.value,
    })
    const zendesk = new ZendeskOAuthClient({
      subdomain: 'example',
      clientId: 'zendesk-client-id',
      clientSecret: options.clientSecret ?? 'ZENDESK_CLIENT_SECRET_SENTINEL',
      callbackUrl: new URL('/oauth/zendesk/callback', publicBaseUrl),
      scopes: ZENDESK_SCOPES,
      timeoutMs: 1_000,
      fetch: fakeZendesk.fetch,
      now: () => now.value,
    })
    const consent = new ConsentController({
      store,
      zendesk,
      publicBaseUrl,
      subdomain: 'example',
      now: () => now.value,
    })
    const callback = new ZendeskCallbackController({
      store,
      zendesk,
      subdomain: 'example',
      now: () => now.value,
    })
    const provider = new ZendeskBrokerOAuthProvider({
      store,
      resourceUrl,
      accessTokenTtlSeconds: 900,
      startAuthorization: consent.begin,
      now: () => now.value,
    })
    const router = createZendeskOAuthRouter({
      provider,
      issuerUrl: publicBaseUrl,
      resourceUrl,
      consentHandler: consent.handlePost,
      callbackHandler: callback.handle,
    })
    const resolver = new ZendeskClientResolver({
      store,
      zendesk,
      subdomain: 'example',
      timeoutMs: 1_000,
      fetch: fakeZendesk.fetch,
      now: () => now.value,
    })
    const app = createHttpApp({
      host: '127.0.0.1',
      allowedHosts: ['127.0.0.1', 'localhost'],
      provider,
      resolver,
      oauthRouter: router,
      resourceMetadataUrl: new URL('/.well-known/oauth-protected-resource/mcp', publicBaseUrl).href,
      isReady: () => store.isReady(),
    })
    listener = app.listen(0, '127.0.0.1')
    await once(listener, 'listening')
    const address = listener.address()
    assert.ok(address && typeof address === 'object')
    baseUrl = `http://127.0.0.1:${address.port}`
    return { provider, zendesk }
  }

  t.after(async () => {
    if (closed) return
    closed = true
    const failures = []
    try {
      try {
        await worker?.stop()
      } catch (error) {
        failures.push(error)
      }
      try {
        await closeListener(listener)
      } catch (error) {
        failures.push(error)
      }
      try {
        store?.close()
      } catch (error) {
        failures.push(error)
      }
      try {
        if (!directory.startsWith(directoryPrefix)) {
          throw new Error('OAuth fixture cleanup path escaped its temporary prefix')
        }
        await rm(directory, { recursive: true, force: true })
      } catch (error) {
        failures.push(error)
      }
    } finally {
      globalThis.fetch = originalFetch
      console.error = originalConsole.error
      console.log = originalConsole.log
      console.warn = originalConsole.warn
    }
    if (failures.length === 1) throw failures[0]
    if (failures.length > 1) throw new AggregateError(failures, 'OAuth fixture cleanup failed')
  })

  let runtime
  try {
    runtime = await buildRuntime()
  } catch (error) {
    globalThis.fetch = originalFetch
    console.error = originalConsole.error
    console.log = originalConsole.log
    console.warn = originalConsole.warn
    throw error
  }

  async function request(path, init) {
    const response = await originalFetch(`${baseUrl}${path}`, init)
    const text = await response.text()
    let json
    if (text) {
      try {
        json = JSON.parse(text)
      } catch {
        const data = text.split('\n').find((line) => line.startsWith('data: '))
        if (data) json = JSON.parse(data.slice('data: '.length))
      }
    }
    return { response, status: response.status, text, json }
  }

  async function registerClient(overrides = {}) {
    const registration = await request('/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        application_type: 'native',
        redirect_uris: [overrides.redirectUri ?? redirectUri],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        client_name: overrides.clientName ?? 'Codex Desktop',
        scope: SCOPES.join(' '),
        ...overrides.metadata,
      }),
    })
    assert.equal(registration.status, 201, registration.text)
    client = registration.json
    return client
  }

  async function beginBrowserLogin(overrides = {}) {
    assert.ok(client, 'registerClient must run before beginBrowserLogin')
    const verifier = overrides.verifier ?? 'v'.repeat(43)
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    const state = overrides.state ?? `mcp-state-${client.client_id.slice(0, 8)}`
    const url = new URL('/authorize', baseUrl)
    url.search = new URLSearchParams({
      response_type: 'code',
      client_id: overrides.clientId ?? client.client_id,
      redirect_uri: overrides.redirectUri ?? client.redirect_uris[0],
      code_challenge: overrides.codeChallenge ?? challenge,
      code_challenge_method: overrides.codeChallengeMethod ?? 'S256',
      scope: overrides.scope ?? SCOPES.join(' '),
      state,
      ...(overrides.omitResource ? {} : { resource: overrides.resource ?? resourceUrl.href }),
    }).toString()
    const result = await request(`${url.pathname}${url.search}`, { redirect: 'manual' })
    if (result.status === 200) {
      const fields = hiddenFields(result.text)
      const setCookie = result.response.headers.get('set-cookie')
      assert.ok(setCookie)
      login = {
        verifier,
        state,
        fields,
        cookie: setCookie.split(';', 1)[0],
        client,
      }
    }
    return result
  }

  async function confirmConsent(overrides = {}) {
    assert.ok(login, 'beginBrowserLogin must run before confirmConsent')
    const result = await request('/oauth/consent', {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: overrides.origin ?? publicBaseUrl.origin,
        cookie: overrides.cookie ?? login.cookie,
      },
      body: new URLSearchParams({
        transaction: overrides.transaction ?? login.fields.transaction,
        csrf: overrides.csrf ?? login.fields.csrf,
        decision: overrides.decision ?? 'confirm',
      }),
    })
    if (result.status === 302 && (overrides.decision ?? 'confirm') === 'confirm') {
      const location = new URL(result.response.headers.get('location'))
      login.upstreamState = location.searchParams.get('state')
    }
    return result
  }

  async function completeZendeskCallback({
    zendeskUserId = '101',
    code = `zendesk-code-${zendeskUserId}`,
    accessToken,
    refreshToken,
    accessExpiresIn,
    refreshExpiresIn,
  } = {}) {
    assert.ok(login?.upstreamState, 'confirmConsent must run before completeZendeskCallback')
    fakeZendesk.registerAuthorizationCode(code, {
      zendeskUserId,
      accessToken,
      refreshToken,
      accessExpiresIn,
      refreshExpiresIn,
    })
    const result = await request(
      `/oauth/zendesk/callback?${new URLSearchParams({ state: login.upstreamState, code })}`,
      { redirect: 'manual' },
    )
    if (result.status === 302) {
      const location = new URL(result.response.headers.get('location'))
      mcpCode = location.searchParams.get('code')
      login.callbackLocation = location
    }
    return result
  }

  async function exchangeMcpCode(overrides = {}) {
    const body = {
      grant_type: 'authorization_code',
      client_id: overrides.clientId ?? login?.client.client_id,
      code: overrides.code ?? mcpCode,
      code_verifier: overrides.verifier ?? login?.verifier,
      redirect_uri: overrides.redirectUri ?? login?.client.redirect_uris[0],
      ...(overrides.omitResource ? {} : { resource: overrides.resource ?? resourceUrl.href }),
    }
    const result = await request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body),
    })
    if (!overrides.raw) assert.equal(result.status, 200, result.text)
    return overrides.raw ? result : result.json
  }

  async function refreshMcp(refreshToken, overrides = {}) {
    const result = await request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: overrides.clientId ?? client.client_id,
        refresh_token: refreshToken,
        ...(overrides.scope === undefined ? {} : { scope: overrides.scope }),
        ...(overrides.omitResource ? {} : { resource: overrides.resource ?? resourceUrl.href }),
      }),
    })
    return overrides.raw ? result : result.json
  }

  async function revoke(token, overrides = {}) {
    return request('/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: overrides.clientId ?? client.client_id,
        token,
        token_type_hint: overrides.tokenTypeHint ?? 'refresh_token',
      }),
    })
  }

  async function callMcp(accessToken, rpc) {
    return request('/mcp', {
      method: 'POST',
      headers: {
        accept: 'application/json, text/event-stream',
        authorization: `Bearer ${accessToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(rpc),
    })
  }

  async function loginPrincipal({ zendeskUserId, label = zendeskUserId, ...grant } = {}) {
    if (!client) await registerClient()
    await beginBrowserLogin({ state: `state-${label}` })
    await confirmConsent()
    await completeZendeskCallback({ zendeskUserId, ...grant })
    return exchangeMcpCode()
  }

  const fixture = {
    SCOPES,
    dbPath,
    directory,
    fakeZendesk,
    logs,
    now,
    publicBaseUrl,
    redirectUri,
    resourceUrl,
    request,
    registerClient,
    beginBrowserLogin,
    confirmConsent,
    completeZendeskCallback,
    exchangeMcpCode,
    refreshMcp,
    revoke,
    callMcp,
    loginPrincipal,
    async discover() {
      const protectedMetadata = await request('/.well-known/oauth-protected-resource/mcp')
      const authorizationMetadata = await request('/.well-known/oauth-authorization-server')
      return { protected: protectedMetadata.json, authorization: authorizationMetadata.json }
    },
    async restart() {
      await worker?.stop()
      worker = undefined
      await closeListener(listener)
      store.close()
      runtime = await buildRuntime()
      return fixture
    },
    async runRevocationWorker({ timeoutMs = 1_000 } = {}) {
      worker = new ZendeskRevocationWorker({
        store,
        zendesk: runtime.zendesk,
        timeoutMs: 1_000,
        pollIntervalMs: 10,
        randomOwner: () => 'oauth-e2e-worker',
        now: () => now.value,
      })
      const requestSeen = fakeZendesk.waitForRequest(
        ({ method, pathname }) => method === 'DELETE' && pathname === '/api/v2/oauth/tokens/current.json',
        { timeoutMs },
      )
      worker.start()
      try {
        return await requestSeen
      } finally {
        await worker.stop()
        worker = undefined
      }
    },
    disconnect(zendeskUserId) {
      return store.disconnectUser('example', String(zendeskUserId), now.value)
    },
    get store() { return store },
    get client() { return client },
    get login() { return login },
    get mcpCode() { return mcpCode },
    get baseUrl() { return baseUrl },
    async databaseBytes() {
      backupSequence += 1
      const backup = join(directory, `oauth-backup-${backupSequence}.sqlite`)
      await store.backup(backup)
      return readFile(backup)
    },
  }
  return fixture
}
