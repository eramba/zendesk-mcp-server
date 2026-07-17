import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import Database from 'better-sqlite3'

import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher } from '../dist/oauth/token-cipher.js'

const VALID_CLIENT = {
  redirect_uris: ['http://127.0.0.1:43123/callback'],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'Codex Desktop',
  scope: 'zendesk:read zendesk:write',
}

async function openStoreFixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-client-'))
  const path = join(directory, 'oauth.sqlite')
  const store = openSqliteOAuthStore({
    path,
    cipher: new TokenCipher(Buffer.alloc(32, 16)),
    now: () => 1_700_000_000,
    ...options,
  })
  t.after(() => store.close())
  return { path, store }
}

test('registerClient generates and persists the canonical public profile', async (t) => {
  const { store } = await openStoreFixture(t)
  const registered = store.registerClient(VALID_CLIENT)
  assert.match(registered.client_id, /^[A-Za-z0-9_-]{43,}$/)
  assert.equal(registered.client_secret, undefined)
  assert.equal(registered.token_endpoint_auth_method, 'none')
  assert.deepEqual(registered.grant_types, ['authorization_code', 'refresh_token'])
  assert.deepEqual(registered.response_types, ['code'])
  assert.equal(registered.scope, 'zendesk:read zendesk:write')
  assert.deepEqual(store.getClient(registered.client_id), registered)
})

test('registerClient permits exact explicit-port localhost callbacks and defaults scope', async (t) => {
  const { store } = await openStoreFixture(t)
  const registered = store.registerClient({
    ...VALID_CLIENT,
    redirect_uris: ['http://localhost:53123/a/path'],
    scope: undefined,
  })
  assert.equal(registered.scope, 'zendesk:read zendesk:write')
})

test('registerClient rejects unsupported authentication, grants, responses, and scope', async (t) => {
  const { store } = await openStoreFixture(t)
  const invalid = [
    { ...VALID_CLIENT, token_endpoint_auth_method: 'client_secret_post' },
    { ...VALID_CLIENT, grant_types: ['authorization_code'] },
    { ...VALID_CLIENT, grant_types: ['authorization_code', 'refresh_token', 'refresh_token'] },
    { ...VALID_CLIENT, response_types: ['code', 'token'] },
    { ...VALID_CLIENT, response_types: ['code', 'code'] },
    { ...VALID_CLIENT, scope: 'zendesk:read' },
  ]

  for (const candidate of invalid) {
    assert.throws(() => store.registerClient(candidate), /invalid_client_metadata/i)
  }
  assert.equal(store.inspectForTest().clientCount, 0)
})

test('registerClient rejects malformed and unsafe redirect URI dimensions', async (t) => {
  const { store } = await openStoreFixture(t)
  const invalidRedirects = [
    ['not a URL'],
    { ...VALID_CLIENT, redirect_uris: ['https://127.0.0.1:43123/callback'] },
    ['http://example.test:43123/callback'],
    { ...VALID_CLIENT, redirect_uris: ['http://127.0.0.1/callback'] },
    ['http://127.0.0.1:80/callback'],
    ['http://127.0.0.1:0/callback'],
    { ...VALID_CLIENT, redirect_uris: ['http://127.0.0.1:43123/callback?x=1'] },
    ['http://127.0.0.1:43123/callback#fragment'],
    { ...VALID_CLIENT, redirect_uris: ['http://user@localhost:43123/callback'] },
    ['http://user:password@localhost:43123/callback'],
    [],
    [42],
  ]

  for (const value of invalidRedirects) {
    const candidate = Array.isArray(value)
      ? { ...VALID_CLIENT, redirect_uris: value }
      : value
    assert.throws(() => store.registerClient(candidate), /invalid_client_metadata/i)
  }
  assert.equal(store.inspectForTest().clientCount, 0)
})

test('registerClient rejects every named unsupported metadata field', async (t) => {
  const { store } = await openStoreFixture(t)
  const unsupported = {
    client_uri: 'http://localhost:43123/client',
    logo_uri: 'http://localhost:43123/logo',
    contacts: ['admin@example.test'],
    tos_uri: 'http://localhost:43123/terms',
    policy_uri: 'http://localhost:43123/policy',
    jwks_uri: 'http://localhost:43123/jwks',
    jwks: { keys: [] },
    software_id: 'software-id',
    software_version: '1.0.0',
    software_statement: 'statement',
  }

  for (const [field, value] of Object.entries(unsupported)) {
    assert.throws(
      () => store.registerClient({ ...VALID_CLIENT, [field]: value }),
      /invalid_client_metadata/i,
      field,
    )
  }
  assert.equal(store.inspectForTest().clientCount, 0)
})

test('registerClient deduplicates equivalent redirects and deterministically rehydrates them', async (t) => {
  const { store } = await openStoreFixture(t)
  const registered = store.registerClient({
    ...VALID_CLIENT,
    redirect_uris: [
      'http://LOCALHOST:43123/a/../callback',
      'http://127.0.0.1:53123/z',
      'http://localhost:43123/callback',
      'http://127.0.0.1:53123/z',
    ],
  })

  assert.deepEqual(registered.redirect_uris, [
    'http://127.0.0.1:53123/z',
    'http://localhost:43123/callback',
  ])
  assert.deepEqual(store.getClient(registered.client_id), registered)
})

test('registerClient enforces printable client name boundaries', async (t) => {
  const { store } = await openStoreFixture(t)
  const accepted = store.registerClient({ ...VALID_CLIENT, client_name: 'x'.repeat(200) })
  assert.equal(accepted.client_name.length, 200)

  for (const clientName of ['', 'x'.repeat(201), 'unsafe\nname', 'unsafe\u007fname']) {
    assert.throws(
      () => store.registerClient({ ...VALID_CLIENT, client_name: clientName }),
      /invalid_client_metadata/i,
    )
  }
  assert.equal(store.inspectForTest().clientCount, 1)
})

test('registerClient rejects caller-owned identifiers and secrets', async (t) => {
  const { store } = await openStoreFixture(t)
  const forbidden = {
    client_id: 'caller-id',
    client_id_issued_at: 1_600_000_000,
    client_secret: 'caller-secret',
    client_secret_expires_at: 1_800_000_000,
  }

  for (const [field, value] of Object.entries(forbidden)) {
    assert.throws(
      () => store.registerClient({ ...VALID_CLIENT, [field]: value }),
      /invalid_client_metadata/i,
      field,
    )
  }
  assert.equal(store.inspectForTest().clientCount, 0)
})

test('generated client ID collision preserves the original client and redirects', async (t) => {
  const generatedId = 'A'.repeat(43)
  const { path, store } = await openStoreFixture(t, { randomToken: () => generatedId })
  const original = store.registerClient(VALID_CLIENT)

  assert.throws(() =>
    store.registerClient({
      ...VALID_CLIENT,
      redirect_uris: ['http://localhost:53123/second'],
    }),
  )
  assert.deepEqual(store.getClient(generatedId), original)
  assert.equal(store.inspectForTest().clientCount, 1)

  const db = new Database(path, { readonly: true })
  t.after(() => db.close())
  assert.equal(
    db.prepare('SELECT COUNT(*) AS count FROM oauth_client_redirect_uris').get().count,
    1,
  )
})

test('redirect insertion failure atomically rolls back the client and redirects', async (t) => {
  const { path, store } = await openStoreFixture(t)
  const db = new Database(path)
  db.exec(`
    CREATE TRIGGER fail_redirect_insert
    BEFORE INSERT ON oauth_client_redirect_uris
    BEGIN
      SELECT RAISE(ABORT, 'simulated redirect insert failure');
    END;
  `)
  db.close()

  assert.throws(() => store.registerClient(VALID_CLIENT), /simulated redirect insert failure/)
  assert.equal(store.inspectForTest().clientCount, 0)

  const inspection = new Database(path, { readonly: true })
  t.after(() => inspection.close())
  assert.equal(inspection.prepare('SELECT COUNT(*) AS count FROM oauth_clients').get().count, 0)
  assert.equal(
    inspection.prepare('SELECT COUNT(*) AS count FROM oauth_client_redirect_uris').get().count,
    0,
  )
})
