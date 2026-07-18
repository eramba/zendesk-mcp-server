import assert from 'node:assert/strict'
import { access } from 'node:fs/promises'
import test from 'node:test'

import { createOAuthFixture } from './helpers/oauth-fixture.mjs'

const TOOL_NAMES = [
  'create_ticket',
  'create_ticket_comment',
  'get_ticket',
  'get_ticket_audits',
  'get_ticket_comments',
  'get_tickets',
  'list_ticket_fields',
  'search',
  'search_organizations',
  'search_tickets',
  'search_users',
  'update_ticket',
]

function toolCall(id, ticketId) {
  return {
    jsonrpc: '2.0',
    id,
    method: 'tools/call',
    params: { name: 'get_ticket', arguments: { ticket_id: ticketId } },
  }
}

function resourceRead(id) {
  return {
    jsonrpc: '2.0',
    id,
    method: 'resources/read',
    params: { uri: 'zendesk://knowledge-base' },
  }
}

function toolResult(rpcResponse) {
  return JSON.parse(rpcResponse.json.result.content[0].text)
}

function oauthError(result) {
  if (result.json?.error) return result.json.error
  const location = result.response.headers.get('location')
  return location ? new URL(location).searchParams.get('error') : undefined
}

test('completes discovery, browser login, code exchange, and authenticated MCP use', async (t) => {
  const fixture = await createOAuthFixture(t)

  const discovery = await fixture.discover()
  assert.equal(discovery.protected.resource, fixture.resourceUrl.href)
  assert.equal(discovery.authorization.issuer, fixture.publicBaseUrl.href)

  await fixture.registerClient()
  await fixture.beginBrowserLogin()
  await fixture.confirmConsent()
  await fixture.completeZendeskCallback({ zendeskUserId: '101' })
  const tokens = await fixture.exchangeMcpCode()

  const initialized = await fixture.callMcp(tokens.access_token, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'oauth-e2e', version: '1.0.0' },
    },
  })
  assert.equal(initialized.status, 200)
  assert.equal(initialized.json.result.serverInfo.name, 'zendesk-mcp-server')

  const tools = await fixture.callMcp(tokens.access_token, {
    jsonrpc: '2.0', id: 2, method: 'tools/list', params: {},
  })
  assert.deepEqual(tools.json.result.tools.map(({ name }) => name).toSorted(), TOOL_NAMES)

  const prompts = await fixture.callMcp(tokens.access_token, {
    jsonrpc: '2.0', id: 3, method: 'prompts/list', params: {},
  })
  assert.deepEqual(
    prompts.json.result.prompts.map(({ name }) => name).toSorted(),
    ['analyze-ticket', 'draft-ticket-response'],
  )

  const resources = await fixture.callMcp(tokens.access_token, {
    jsonrpc: '2.0', id: 4, method: 'resources/list', params: {},
  })
  assert.deepEqual(
    resources.json.result.resources.map(({ uri }) => uri).toSorted(),
    ['zendesk://knowledge-base'],
  )

  const ticket = await fixture.callMcp(tokens.access_token, {
    jsonrpc: '2.0',
    id: 5,
    method: 'tools/call',
    params: { name: 'get_ticket', arguments: { ticket_id: 42 } },
  })
  assert.equal(JSON.parse(ticket.json.result.content[0].text).subject, 'Principal 101 ticket')

  const resource = await fixture.callMcp(tokens.access_token, {
    jsonrpc: '2.0',
    id: 6,
    method: 'resources/read',
    params: { uri: 'zendesk://knowledge-base' },
  })
  assert.equal(resource.json.result.contents[0].uri, 'zendesk://knowledge-base')
  assert.match(resource.json.result.contents[0].text, /Principal 101 article/)
})

test('keeps concurrent principal Bearers, results, and resource caches isolated', async (t) => {
  const fixture = await createOAuthFixture(t)
  const a = await fixture.loginPrincipal({ zendeskUserId: '101', label: 'a' })
  const b = await fixture.loginPrincipal({ zendeskUserId: '202', label: 'b' })

  const barrier = fixture.fakeZendesk.holdRequests(
    ({ pathname }) => pathname.startsWith('/api/v2/tickets/'),
    2,
  )
  const ticketRequests = Promise.all([
    fixture.callMcp(a.access_token, toolCall(10, 101)),
    fixture.callMcp(b.access_token, toolCall(11, 202)),
  ])
  await barrier.reached
  try {
    assert.equal(barrier.active, 2)
    assert.equal(barrier.maxActive, 2)
  } finally {
    barrier.release()
  }
  const [ticketA, ticketB] = await ticketRequests

  const [resourceA, resourceB] = await Promise.all([
    fixture.callMcp(a.access_token, resourceRead(12)),
    fixture.callMcp(b.access_token, resourceRead(13)),
  ])

  assert.equal(toolResult(ticketA).subject, 'Principal 101 ticket')
  assert.equal(toolResult(ticketB).subject, 'Principal 202 ticket')
  assert.match(resourceA.json.result.contents[0].text, /Principal 101 article/)
  assert.doesNotMatch(resourceA.json.result.contents[0].text, /Principal 202 article/)
  assert.match(resourceB.json.result.contents[0].text, /Principal 202 article/)
  assert.doesNotMatch(resourceB.json.result.contents[0].text, /Principal 101 article/)

  const [resourceBAfterCache, resourceAAfterCache] = await Promise.all([
    fixture.callMcp(b.access_token, resourceRead(14)),
    fixture.callMcp(a.access_token, resourceRead(15)),
  ])
  assert.match(resourceBAfterCache.json.result.contents[0].text, /Principal 202 article/)
  assert.doesNotMatch(resourceBAfterCache.json.result.contents[0].text, /Principal 101 article/)
  assert.match(resourceAAfterCache.json.result.contents[0].text, /Principal 101 article/)
  assert.doesNotMatch(resourceAAfterCache.json.result.contents[0].text, /Principal 202 article/)

  const apiAuthorizations = fixture.fakeZendesk.requests
    .filter(({ pathname }) => pathname.startsWith('/api/v2/tickets/'))
    .map(({ authorization }) => authorization)
    .toSorted()
  assert.deepEqual(apiAuthorizations, [
    'Bearer upstream-access-101',
    'Bearer upstream-access-202',
  ])
})

test('enforces metadata, resource, redirect, PKCE, code, refresh, and revoke bindings', async (t) => {
  const fixture = await createOAuthFixture(t)
  const discovery = await fixture.discover()
  assert.deepEqual(discovery.protected, {
    resource: fixture.resourceUrl.href,
    authorization_servers: [fixture.publicBaseUrl.href],
    scopes_supported: fixture.SCOPES,
  })
  assert.deepEqual(discovery.authorization, {
    issuer: fixture.publicBaseUrl.href,
    authorization_endpoint: new URL('/authorize', fixture.publicBaseUrl).href,
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint: new URL('/token', fixture.publicBaseUrl).href,
    token_endpoint_auth_methods_supported: ['none'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    scopes_supported: fixture.SCOPES,
    revocation_endpoint: new URL('/revoke', fixture.publicBaseUrl).href,
    revocation_endpoint_auth_methods_supported: ['none'],
    registration_endpoint: new URL('/register', fixture.publicBaseUrl).href,
  })

  const firstClient = await fixture.registerClient()
  const wrongPkceMethod = await fixture.beginBrowserLogin({ codeChallengeMethod: 'plain' })
  assert.equal(oauthError(wrongPkceMethod), 'invalid_request')
  const missingResource = await fixture.beginBrowserLogin({ omitResource: true })
  assert.equal(missingResource.status, 302)
  assert.equal(
    new URL(missingResource.response.headers.get('location')).searchParams.get('error'),
    'invalid_target',
  )

  const wrongRedirect = await fixture.beginBrowserLogin({
    redirectUri: 'http://127.0.0.1:49999/not-registered',
  })
  assert.equal(wrongRedirect.status, 400)
  assert.equal(wrongRedirect.json.error, 'invalid_request')

  await fixture.beginBrowserLogin({ state: 'binding-state' })
  await fixture.confirmConsent()
  await fixture.completeZendeskCallback({ zendeskUserId: '303' })

  const wrongVerifier = await fixture.exchangeMcpCode({ verifier: 'x'.repeat(43), raw: true })
  assert.equal(wrongVerifier.status, 400)
  assert.equal(wrongVerifier.json.error, 'invalid_grant')
  const missingTokenResource = await fixture.exchangeMcpCode({ omitResource: true, raw: true })
  assert.equal(missingTokenResource.status, 400)
  assert.equal(missingTokenResource.json.error, 'invalid_target')
  const wrongTokenRedirect = await fixture.exchangeMcpCode({
    redirectUri: 'http://127.0.0.1:49999/not-registered',
    raw: true,
  })
  assert.equal(wrongTokenRedirect.status, 400)
  assert.equal(wrongTokenRedirect.json.error, 'invalid_grant')

  const secondClient = await fixture.registerClient({ clientName: 'Other Codex client' })
  const crossClientCode = await fixture.exchangeMcpCode({
    clientId: secondClient.client_id,
    raw: true,
  })
  assert.equal(crossClientCode.status, 400)
  assert.equal(crossClientCode.json.error, 'invalid_grant')
  const successfulCode = fixture.mcpCode
  const tokens = await fixture.exchangeMcpCode({ clientId: firstClient.client_id })

  const replayedCode = await fixture.exchangeMcpCode({
    clientId: firstClient.client_id,
    code: successfulCode,
    raw: true,
  })
  assert.equal(replayedCode.status, 400)
  assert.equal(replayedCode.json.error, 'invalid_grant')

  const crossClientRefresh = await fixture.refreshMcp(tokens.refresh_token, {
    clientId: secondClient.client_id,
    raw: true,
  })
  assert.equal(crossClientRefresh.status, 400)
  assert.equal(crossClientRefresh.json.error, 'invalid_grant')
  assert.equal((await fixture.callMcp(tokens.access_token, toolCall(16, 303))).status, 200)

  const crossClientRevoke = await fixture.revoke(tokens.refresh_token, {
    clientId: secondClient.client_id,
  })
  assert.equal(crossClientRevoke.status, 200)
  assert.equal((await fixture.callMcp(tokens.access_token, toolCall(14, 303))).status, 200)

  const wrongRefreshResource = await fixture.refreshMcp(tokens.refresh_token, {
    clientId: firstClient.client_id,
    resource: 'https://other.example.test/mcp',
    raw: true,
  })
  assert.equal(wrongRefreshResource.status, 400)
  assert.equal(wrongRefreshResource.json.error, 'invalid_target')
  assert.equal((await fixture.callMcp(tokens.access_token, toolCall(15, 303))).status, 401)

  const scopeFamily = await fixture.loginPrincipal({ zendeskUserId: '304', label: 'scope' })
  const wrongRefreshScope = await fixture.refreshMcp(scopeFamily.refresh_token, {
    clientId: secondClient.client_id,
    scope: 'zendesk:read',
    raw: true,
  })
  assert.equal(wrongRefreshScope.status, 400)
  assert.equal(wrongRefreshScope.json.error, 'invalid_grant')
  assert.equal((await fixture.callMcp(scopeFamily.access_token, toolCall(17, 304))).status, 401)
})

test('rotates MCP R1 to R2 to R3, refreshes upstream once, and survives restart with omitted resource', async (t) => {
  const fixture = await createOAuthFixture(t)
  const r1 = await fixture.loginPrincipal({ zendeskUserId: '404', label: 'refresh' })
  fixture.now.value += 1_750

  const r2 = await fixture.refreshMcp(r1.refresh_token, { omitResource: true })
  assert.notEqual(r2.refresh_token, r1.refresh_token)
  const refreshedTicket = await fixture.callMcp(r2.access_token, toolCall(20, 404))
  assert.equal(toolResult(refreshedTicket).subject, 'Principal 404 ticket')
  const upstreamRefreshes = fixture.fakeZendesk.requests.filter(
    ({ pathname, json }) => pathname === '/oauth/tokens' && json?.grant_type === 'refresh_token',
  )
  assert.equal(upstreamRefreshes.length, 1)
  assert.equal(upstreamRefreshes[0].json.refresh_token, 'upstream-refresh-404')

  await fixture.restart()
  fixture.now.value += 1
  const r3 = await fixture.refreshMcp(r2.refresh_token, { omitResource: true })
  assert.notEqual(r3.refresh_token, r2.refresh_token)
  const afterRestart = await fixture.callMcp(r3.access_token, toolCall(21, 405))
  assert.equal(toolResult(afterRestart).subject, 'Principal 404 ticket')
  assert.ok(fixture.fakeZendesk.requests.some(({ pathname, authorization }) =>
    pathname === '/api/v2/tickets/405.json'
      && authorization === 'Bearer upstream-access-404-refresh-1'))

  const replay = await fixture.refreshMcp(r1.refresh_token, { omitResource: true, raw: true })
  assert.equal(replay.status, 400)
  assert.equal(replay.json.error, 'invalid_grant')
  assert.equal((await fixture.callMcp(r3.access_token, toolCall(22, 406))).status, 401)
})

test('distinguishes local credential deletion from RFC 7009 family revocation', async (t) => {
  const fixture = await createOAuthFixture(t)
  const locallyRetained = await fixture.loginPrincipal({ zendeskUserId: '505', label: 'local' })
  const otherFamily = await fixture.loginPrincipal({ zendeskUserId: '505', label: 'other-family' })

  let localCredential = { ...locallyRetained }
  localCredential = undefined
  assert.equal(localCredential, undefined)
  assert.equal((await fixture.callMcp(locallyRetained.access_token, toolCall(30, 505))).status, 200)

  const revoked = await fixture.revoke(locallyRetained.refresh_token)
  assert.equal(revoked.status, 200)
  assert.equal((await fixture.callMcp(locallyRetained.access_token, toolCall(31, 506))).status, 401)
  assert.equal((await fixture.callMcp(otherFamily.access_token, toolCall(32, 507))).status, 200)
})

test('disconnect invalidates locally before an eligible outbox revokes through fake upstream', async (t) => {
  const fixture = await createOAuthFixture(t)
  await assert.rejects(
    fixture.runRevocationWorker({ timeoutMs: 20 }),
    /Timed out waiting for fake Zendesk request/,
  )
  const tokens = await fixture.loginPrincipal({ zendeskUserId: '606', label: 'disconnect' })

  const disconnected = fixture.disconnect('606')
  assert.equal(disconnected.kind, 'disconnected')
  assert.equal(disconnected.revokedFamilies, 1)
  assert.equal((await fixture.callMcp(tokens.access_token, toolCall(40, 606))).status, 401)

  const upstream = await fixture.runRevocationWorker()
  assert.equal(upstream.authorization, 'Bearer upstream-access-606')
  assert.equal(
    fixture.store.claimDueRevocation('post-completion-check', fixture.now.value, fixture.now.value + 6),
    undefined,
  )
})

test('keeps secret sentinels out of logs, database, HTTP errors, MCP output, and metadata', async (t) => {
  const fixture = await createOAuthFixture(t)
  const sentinels = [
    'ZENDESK_CLIENT_SECRET_SENTINEL',
    'UPSTREAM_CODE_SECRET_SENTINEL',
    'UPSTREAM_ACCESS_SECRET_SENTINEL',
    'UPSTREAM_REFRESH_SECRET_SENTINEL',
    'ORIGINAL_STATE_SECRET_SENTINEL',
    'UPSTREAM_ERROR_BODY_SECRET_SENTINEL',
  ]
  await fixture.registerClient()
  await fixture.beginBrowserLogin({ state: sentinels[4] })
  await fixture.confirmConsent()
  await fixture.completeZendeskCallback({
    zendeskUserId: '707',
    code: sentinels[1],
    accessToken: sentinels[2],
    refreshToken: sentinels[3],
  })
  const tokens = await fixture.exchangeMcpCode()
  sentinels.push(fixture.mcpCode, tokens.access_token, tokens.refresh_token)
  fixture.fakeZendesk.failTicket('707', 707, sentinels[5])

  const tool = await fixture.callMcp(tokens.access_token, toolCall(50, 707))
  assert.equal(tool.json.result.isError, true)
  const metadata = await fixture.discover()
  const malformed = await fixture.request(
    `/oauth/zendesk/callback?state=${encodeURIComponent(sentinels[0])}&code=${encodeURIComponent(sentinels[1])}`,
    { redirect: 'manual' },
  )
  const database = (await fixture.databaseBytes()).toString('latin1')
  const surfaces = [
    fixture.logs.join('\n'),
    database,
    malformed.text,
    JSON.stringify(tool.json),
    JSON.stringify(metadata),
  ]
  for (const sentinel of sentinels) {
    for (const surface of surfaces) assert.equal(surface.includes(sentinel), false, sentinel)
  }
})

test('returns only stable errors for malformed consent, callback, and token inputs', async (t) => {
  const fixture = await createOAuthFixture(t)
  const client = await fixture.registerClient()
  const sentinel = 'MALFORMED_INPUT_SECRET_SENTINEL'

  const consent = await fixture.request('/oauth/consent', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: fixture.publicBaseUrl.origin,
    },
    body: new URLSearchParams({ transaction: sentinel, csrf: sentinel, decision: 'confirm' }),
  })
  assert.equal(consent.status, 400)
  assert.equal(consent.text, 'Invalid consent request')

  const callback = await fixture.request(
    `/oauth/zendesk/callback?state=${sentinel}&code=${sentinel}`,
    { redirect: 'manual' },
  )
  assert.equal(callback.status, 400)
  assert.match(callback.text, /Reference correlation [0-9a-f-]{36}/)

  const token = await fixture.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: client.client_id,
      code: sentinel,
      code_verifier: sentinel,
      redirect_uri: fixture.redirectUri,
      resource: fixture.resourceUrl.href,
    }),
  })
  assert.equal(token.status, 400)
  assert.equal(token.json.error, 'invalid_grant')
  assert.deepEqual(Object.keys(token.json).toSorted(), ['error', 'error_description'])

  for (const surface of [consent.text, callback.text, token.text, fixture.logs.join('\n')]) {
    assert.equal(surface.includes(sentinel), false)
  }
})

test('a principal A failure never falls back to B or a default account', async (t) => {
  const fixture = await createOAuthFixture(t)
  const a = await fixture.loginPrincipal({ zendeskUserId: '808', label: 'failure-a' })
  const b = await fixture.loginPrincipal({ zendeskUserId: '909', label: 'healthy-b' })
  fixture.fakeZendesk.failTicket('808', 808, 'FAILURE_A_UPSTREAM_SECRET')

  const barrier = fixture.fakeZendesk.holdRequests(
    ({ pathname }) =>
      pathname === '/api/v2/tickets/808.json'
      || pathname === '/api/v2/tickets/909.json',
    2,
  )
  const requests = Promise.all([
    fixture.callMcp(a.access_token, toolCall(60, 808)),
    fixture.callMcp(b.access_token, toolCall(61, 909)),
  ])
  await barrier.reached
  try {
    assert.equal(barrier.active, 2)
    assert.equal(barrier.maxActive, 2)
  } finally {
    barrier.release()
  }
  const [failedA, healthyB] = await requests

  assert.equal(failedA.json.result.isError, true)
  assert.match(failedA.json.result.content[0].text, /temporarily_unavailable/)
  assert.doesNotMatch(failedA.json.result.content[0].text, /FAILURE_A_UPSTREAM_SECRET|Principal 909/)
  assert.deepEqual(toolResult(healthyB), {
    id: 909,
    subject: 'Principal 909 ticket',
    description: 'Visible only to 909',
    status: null,
    priority: null,
    type: null,
    created_at: null,
    updated_at: null,
    requester_id: null,
    assignee_id: null,
    organization_id: null,
    tags: [],
  })

  const relevant = fixture.fakeZendesk.requests.filter(
    ({ pathname }) => pathname === '/api/v2/tickets/808.json' || pathname === '/api/v2/tickets/909.json',
  )
  assert.deepEqual(relevant.map(({ pathname, authorization }) => ({ pathname, authorization }))
    .toSorted((left, right) => left.pathname.localeCompare(right.pathname)), [
    {
      pathname: '/api/v2/tickets/808.json',
      authorization: 'Bearer upstream-access-808',
    },
    {
      pathname: '/api/v2/tickets/909.json',
      authorization: 'Bearer upstream-access-909',
    },
  ])
  assert.equal(relevant.some(({ authorization }) => !authorization?.startsWith('Bearer ')), false)
})

test('bounds absent fake Zendesk requests and removes the complete fixture directory', async (t) => {
  let directory
  await t.test('fixture scope', async (fixtureTest) => {
    const fixture = await createOAuthFixture(fixtureTest)
    directory = fixture.directory
    await fixture.databaseBytes()
    await assert.rejects(
      fixture.fakeZendesk.waitForRequest(() => false, { timeoutMs: 20 }),
      /Timed out waiting for fake Zendesk request/,
    )
  })

  await assert.rejects(access(directory), { code: 'ENOENT' })
})
