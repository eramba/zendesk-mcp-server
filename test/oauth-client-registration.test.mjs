import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

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

async function openStoreFixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-client-'))
  const store = openSqliteOAuthStore({
    path: join(directory, 'oauth.sqlite'),
    cipher: new TokenCipher(Buffer.alloc(32, 16)),
    now: () => 1_700_000_000,
  })
  t.after(() => store.close())
  return store
}

test('registerClient generates and persists the canonical public profile', async (t) => {
  const store = await openStoreFixture(t)
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
  const store = await openStoreFixture(t)
  const registered = store.registerClient({
    ...VALID_CLIENT,
    redirect_uris: ['http://localhost:53123/a/path'],
    scope: undefined,
  })
  assert.equal(registered.scope, 'zendesk:read zendesk:write')
})

test('registerClient rejects every unsupported profile without persisting it', async (t) => {
  const store = await openStoreFixture(t)
  const invalid = [
    { ...VALID_CLIENT, token_endpoint_auth_method: 'client_secret_post' },
    { ...VALID_CLIENT, grant_types: ['authorization_code'] },
    { ...VALID_CLIENT, response_types: ['code', 'token'] },
    { ...VALID_CLIENT, scope: 'zendesk:read' },
    { ...VALID_CLIENT, redirect_uris: ['https://example.test/callback'] },
    { ...VALID_CLIENT, redirect_uris: ['http://127.0.0.1/callback'] },
    { ...VALID_CLIENT, redirect_uris: ['http://127.0.0.1:43123/callback?x=1'] },
    { ...VALID_CLIENT, redirect_uris: ['http://user@localhost:43123/callback'] },
    { ...VALID_CLIENT, jwks: { keys: [] } },
    { ...VALID_CLIENT, software_statement: 'statement' },
    { ...VALID_CLIENT, client_name: 'x'.repeat(201) },
    { ...VALID_CLIENT, client_name: 'unsafe\nname' },
  ]

  for (const candidate of invalid) {
    assert.throws(() => store.registerClient(candidate), /invalid_client_metadata/i)
  }
  assert.equal(store.inspectForTest().clientCount, 0)
})
