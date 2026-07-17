import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import Database from 'better-sqlite3'

import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher, randomOpaque } from '../dist/oauth/token-cipher.js'

const NOW = 1_700_000_000
const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const RESOURCE = 'https://dev-server.tail22145b.ts.net/mcp'
const CODE_CHALLENGE = 'C'.repeat(43)
const SCOPES = ['zendesk:read', 'zendesk:write']
const VALID_CLIENT = {
  redirect_uris: [REDIRECT_URI],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'Codex Desktop',
  scope: SCOPES.join(' '),
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-login-'))
  const path = join(directory, 'oauth.sqlite')
  const store = openSqliteOAuthStore({
    path,
    cipher: new TokenCipher(Buffer.alloc(32, 21)),
    now: () => NOW,
  })
  t.after(() => store.close())
  const client = store.registerClient(VALID_CLIENT)
  return { directory, path, store, client }
}

function loginInput(clientId, originalState) {
  return {
    clientId,
    redirectUri: REDIRECT_URI,
    codeChallenge: CODE_CHALLENGE,
    scopes: [...SCOPES],
    resource: RESOURCE,
    originalState,
    subdomain: 'example',
    now: NOW,
  }
}

function assertOpaque(value) {
  assert.match(value, /^[A-Za-z0-9_-]+$/)
  assert.ok(Buffer.from(value, 'base64url').length >= 32)
}

function countOccurrences(bytes, value) {
  return bytes.toString('latin1').split(value).length - 1
}

function assertContainsNone(value, secrets) {
  for (const secret of secrets) {
    assert.equal(value.includes(secret), false, `plaintext value leaked: ${secret}`)
  }
}

function captureConsole(operation) {
  const captured = []
  const methods = ['debug', 'error', 'info', 'log', 'warn']
  const originals = Object.fromEntries(methods.map((method) => [method, console[method]]))
  for (const method of methods) {
    console[method] = (...values) => captured.push(values.map(String).join(' '))
  }
  try {
    return { result: operation(), captured }
  } finally {
    for (const method of methods) console[method] = originals[method]
  }
}

async function backupBytes(store, directory, name) {
  const destination = join(directory, name)
  await store.backup(destination)
  return readFile(destination)
}

function loginRows(path) {
  const db = new Database(path, { readonly: true })
  try {
    return db.prepare('SELECT * FROM login_transactions ORDER BY id').all()
  } finally {
    db.close()
  }
}

test('login confirmation and Zendesk callback state are one-time and encrypted', async (t) => {
  const { directory, path, store, client } = await fixture(t)
  const originalState = 'mcp-state-byte-for-byte-%2F-✓'
  const before = await backupBytes(store, directory, 'before-login.sqlite')
  const logged = []

  const startedCapture = captureConsole(() => store.beginLogin(loginInput(client.client_id, originalState)))
  const started = startedCapture.result
  logged.push(...startedCapture.captured)

  assertOpaque(started.transactionToken)
  assertOpaque(started.consentCsrf)
  assertOpaque(started.browserNonce)
  assert.equal(started.expiresAt, NOW + 600)
  assert.equal(new Set([
    started.transactionToken,
    started.consentCsrf,
    started.browserNonce,
  ]).size, 3)

  const rawLoginValues = [
    started.transactionToken,
    started.consentCsrf,
    started.browserNonce,
    originalState,
    REDIRECT_URI,
    CODE_CHALLENGE,
  ]
  const pendingRow = loginRows(path)[0]
  assertContainsNone(JSON.stringify(pendingRow), rawLoginValues)

  const afterBegin = await backupBytes(store, directory, 'after-begin.sqlite')
  assert.equal(
    countOccurrences(afterBegin, REDIRECT_URI),
    countOccurrences(before, REDIRECT_URI),
    'beginLogin must not add another plaintext copy of the registered redirect',
  )
  assertContainsNone(
    afterBegin.toString('latin1'),
    [started.transactionToken, started.consentCsrf, started.browserNonce, originalState, CODE_CHALLENGE],
  )

  const decisionInput = {
    transactionToken: started.transactionToken,
    consentCsrf: started.consentCsrf,
    browserNonce: started.browserNonce,
    decision: 'confirm',
    now: NOW,
  }
  const decisionCapture = captureConsole(() => store.decideConsent(decisionInput))
  const decision = decisionCapture.result
  logged.push(...decisionCapture.captured)
  assert.equal(decision.kind, 'confirmed')
  assertOpaque(decision.upstreamState)
  assert.deepEqual(store.decideConsent(decisionInput), { kind: 'invalid' })

  const upstreamPendingRow = loginRows(path)[0]
  assertContainsNone(JSON.stringify(upstreamPendingRow), [...rawLoginValues, decision.upstreamState])
  const afterConfirm = await backupBytes(store, directory, 'after-confirm.sqlite')
  assertContainsNone(afterConfirm.toString('latin1'), [
    started.transactionToken,
    started.consentCsrf,
    started.browserNonce,
    originalState,
    CODE_CHALLENGE,
    decision.upstreamState,
  ])
  assertContainsNone(logged.join('\n'), [...rawLoginValues, decision.upstreamState])

  const callback = store.claimZendeskCallback(decision.upstreamState, NOW)
  assert.deepEqual(callback, {
    transactionId: callback.transactionId,
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    originalState,
    codeChallenge: CODE_CHALLENGE,
    scopes: SCOPES,
    resource: RESOURCE,
    createdAt: NOW,
  })
  assert.match(callback.transactionId, /^[A-Za-z0-9_-]+$/)
  assert.equal(store.claimZendeskCallback(decision.upstreamState, NOW), undefined)
})

test('wrong, mixed, and expired browser bindings do not advance login rows', async (t) => {
  const { path, store, client } = await fixture(t)
  const first = store.beginLogin(loginInput(client.client_id, 'first-state'))
  const second = store.beginLogin(loginInput(client.client_id, 'second-state'))
  const confirm = (started, overrides = {}) => store.decideConsent({
    transactionToken: started.transactionToken,
    consentCsrf: started.consentCsrf,
    browserNonce: started.browserNonce,
    decision: 'confirm',
    now: NOW,
    ...overrides,
  })
  const assertBothPending = () => assert.deepEqual(
    loginRows(path).map(({ status }) => status),
    ['consent_pending', 'consent_pending'],
  )

  assert.deepEqual(confirm(first, { consentCsrf: randomOpaque() }), { kind: 'invalid' })
  assertBothPending()
  assert.deepEqual(confirm(first, { browserNonce: randomOpaque() }), { kind: 'invalid' })
  assertBothPending()
  assert.deepEqual(confirm(first, {
    consentCsrf: second.consentCsrf,
    browserNonce: second.browserNonce,
  }), { kind: 'invalid' })
  assertBothPending()
  assert.deepEqual(confirm(first, { now: first.expiresAt }), { kind: 'invalid' })
  assertBothPending()

  assert.equal(confirm(second).kind, 'confirmed')
  assert.deepEqual(
    loginRows(path).map(({ status }) => status).sort(),
    ['consent_pending', 'upstream_pending'],
  )
})

test('denial consumes consent once and returns only the stored redirect context', async (t) => {
  const { store, client } = await fixture(t)
  const originalState = 'denied-original-state'
  const started = store.beginLogin(loginInput(client.client_id, originalState))
  const deniedInput = {
    transactionToken: started.transactionToken,
    consentCsrf: started.consentCsrf,
    browserNonce: started.browserNonce,
    decision: 'deny',
    now: NOW,
  }

  assert.deepEqual(store.decideConsent(deniedInput), {
    kind: 'denied',
    redirectUri: REDIRECT_URI,
    originalState,
  })
  assert.deepEqual(store.decideConsent(deniedInput), { kind: 'invalid' })
})

test('beginLogin validates the persisted client, exact redirect, scopes, and canonical resource', async (t) => {
  const { path, store, client } = await fixture(t)
  const valid = loginInput(client.client_id, 'validation-state')
  const invalid = [
    { ...valid, clientId: randomOpaque() },
    { ...valid, redirectUri: 'http://127.0.0.1:43123/other' },
    { ...valid, scopes: ['zendesk:read'] },
    { ...valid, scopes: [...SCOPES, 'zendesk:write'] },
    { ...valid, resource: 'https://dev-server.tail22145b.ts.net:443/mcp' },
  ]

  for (const input of invalid) {
    assert.throws(() => store.beginLogin(input), /invalid login request/i)
  }
  assert.equal(loginRows(path).length, 0)
})

test('failLogin consumes only a claimed callback and returns its trusted redirect context', async (t) => {
  const { store, client } = await fixture(t)
  const originalState = 'failed-original-state'
  const started = store.beginLogin(loginInput(client.client_id, originalState))
  const confirmed = store.decideConsent({
    transactionToken: started.transactionToken,
    consentCsrf: started.consentCsrf,
    browserNonce: started.browserNonce,
    decision: 'confirm',
    now: NOW,
  })
  assert.equal(confirmed.kind, 'confirmed')
  const claimed = store.claimZendeskCallback(confirmed.upstreamState, NOW)

  assert.deepEqual(store.failLogin(claimed.transactionId, NOW), {
    redirectUri: REDIRECT_URI,
    originalState,
  })
  assert.equal(store.failLogin(claimed.transactionId, NOW), undefined)
})
