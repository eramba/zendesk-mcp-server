import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import Database from 'better-sqlite3'

import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher, hashOpaque, randomOpaque } from '../dist/oauth/token-cipher.js'

const NOW = 1_700_000_000
const ACCESS_TTL = 3_600
const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const RESOURCE = 'https://dev-server.tail22145b.ts.net/mcp'
const CODE_CHALLENGE = 'C'.repeat(43)
const MCP_SCOPES = ['zendesk:read', 'zendesk:write']
const VALID_CLIENT = {
  redirect_uris: [REDIRECT_URI],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'Codex Desktop',
  scope: MCP_SCOPES.join(' '),
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-access-'))
  const path = join(directory, 'oauth.sqlite')
  const cipher = new TokenCipher(Buffer.alloc(32, 31))
  const store = openSqliteOAuthStore({
    path,
    cipher,
    mcpResourceUrl: new URL(RESOURCE),
    now: () => NOW,
  })
  t.after(() => store.close())
  const client = store.registerClient(VALID_CLIENT)
  return { directory, path, cipher, store, client }
}

function openIssuanceStore(t, path, cipher, options = {}) {
  const store = openSqliteOAuthStore({
    path,
    cipher,
    mcpResourceUrl: new URL(RESOURCE),
    now: () => NOW,
    ...options,
  })
  t.after(() => store.close())
  return store
}

function query(path, sql, ...parameters) {
  const db = new Database(path, { readonly: true })
  try {
    return db.prepare(sql).all(...parameters)
  } finally {
    db.close()
  }
}

function execute(path, operation) {
  const db = new Database(path)
  try {
    return operation(db)
  } finally {
    db.close()
  }
}

async function databaseBytes(store, directory) {
  const destination = join(directory, 'token-inspection.sqlite')
  await store.backup(destination)
  return readFile(destination)
}

function commitAuthorizationCode(store, clientId, label, now = NOW) {
  const started = store.beginLogin({
    clientId,
    redirectUri: REDIRECT_URI,
    codeChallenge: CODE_CHALLENGE,
    scopes: [...MCP_SCOPES].reverse(),
    resource: RESOURCE,
    originalState: `state-${label}`,
    subdomain: 'example',
    now,
  })
  const consent = store.decideConsent({
    transactionToken: started.transactionToken,
    consentCsrf: started.consentCsrf,
    browserNonce: started.browserNonce,
    decision: 'confirm',
    now,
  })
  assert.equal(consent.kind, 'confirmed')
  const callback = store.claimZendeskCallback(consent.upstreamState, now)
  assert.ok(callback)
  const staged = store.stageLoginGrant({
    transactionId: callback.transactionId,
    subdomain: 'example',
    grant: {
      accessToken: `zendesk-access-${label}`,
      refreshToken: `zendesk-refresh-${label}`,
      accessExpiresAt: now + 3_600,
      refreshExpiresAt: now + 86_400,
      scopes: ['tickets:write', 'read'],
    },
    now,
  })
  return store.commitLogin({
    transactionId: callback.transactionId,
    stageId: staged.stageId,
    zendeskUserId: '424242',
    now,
  })
}

function exchangeInput(clientId, authorizationCode, overrides = {}) {
  return {
    clientId,
    authorizationCode,
    redirectUri: REDIRECT_URI,
    resource: RESOURCE,
    now: NOW,
    accessTokenTtlSeconds: ACCESS_TTL,
    ...overrides,
  }
}

function issuanceCounts(path) {
  return {
    families: query(path, 'SELECT COUNT(*) AS count FROM token_families')[0].count,
    access: query(path, 'SELECT COUNT(*) AS count FROM access_tokens')[0].count,
    refresh: query(path, 'SELECT COUNT(*) AS count FROM refresh_token_generations')[0].count,
  }
}

test('challenge lookup is read-only and a valid code atomically issues hash-only audience-bound tokens', async (t) => {
  const { directory, path, store, client } = await fixture(t)
  const committed = commitAuthorizationCode(store, client.client_id, 'success')

  assert.equal(store.challengeForAuthorizationCode(client.client_id, committed.authorizationCode, NOW), CODE_CHALLENGE)
  assert.equal(store.challengeForAuthorizationCode(client.client_id, committed.authorizationCode, NOW), CODE_CHALLENGE)
  assert.equal(query(path, 'SELECT consumed_at FROM authorization_codes')[0].consumed_at, null)

  const tokens = store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, committed.authorizationCode))
  assert.equal(tokens.token_type, 'Bearer')
  assert.equal(tokens.expires_in, ACCESS_TTL)
  assert.equal(tokens.scope, MCP_SCOPES.join(' '))
  assert.equal(Buffer.from(tokens.access_token, 'base64url').length, 32)
  assert.equal(Buffer.from(tokens.refresh_token, 'base64url').length, 32)
  assert.notEqual(tokens.access_token, tokens.refresh_token)
  assert.deepEqual(store.lookupAccessToken(tokens.access_token, NOW), {
    clientId: client.client_id,
    principalId: committed.principalId,
    scopes: MCP_SCOPES,
    resource: RESOURCE,
    expiresAt: NOW + ACCESS_TTL,
  })

  const codes = query(path, 'SELECT * FROM authorization_codes')
  const families = query(path, 'SELECT * FROM token_families')
  const access = query(path, 'SELECT * FROM access_tokens')
  const refresh = query(path, 'SELECT * FROM refresh_token_generations')
  assert.equal(codes[0].consumed_at, NOW)
  assert.equal(families.length, 1)
  assert.equal(families[0].client_id, client.client_id)
  assert.equal(families[0].principal_id, committed.principalId)
  assert.equal(families[0].principal_epoch, committed.principalEpoch)
  assert.equal(families[0].scopes, MCP_SCOPES.join(' '))
  assert.equal(families[0].resource, RESOURCE)
  assert.equal(families[0].created_at, NOW)
  assert.equal(families[0].last_used_at, NOW)
  assert.equal(access.length, 1)
  assert.equal(access[0].token_hash, hashOpaque(tokens.access_token))
  assert.equal(access[0].expires_at, NOW + ACCESS_TTL)
  assert.equal(refresh.length, 1)
  assert.equal(refresh[0].token_hash, hashOpaque(tokens.refresh_token))
  assert.equal(refresh[0].generation, 1)
  assert.equal(refresh[0].status, 'current')
  assert.equal(refresh[0].expires_at, NOW + 2_592_000)
  for (const value of [codes[0].expires_at, families[0].created_at, access[0].expires_at, refresh[0].expires_at]) {
    assert.equal(Number.isSafeInteger(value), true)
  }
  const bytes = await databaseBytes(store, directory)
  assert.equal(bytes.includes(Buffer.from(tokens.access_token, 'utf8')), false)
  assert.equal(bytes.includes(Buffer.from(tokens.refresh_token, 'utf8')), false)
})

test('code challenge and exchange reject client, redirect, resource, expiry, and reuse mismatches without partial families', async (t) => {
  const { path, store, client } = await fixture(t)
  const committed = commitAuthorizationCode(store, client.client_id, 'bindings')
  const otherClient = store.registerClient({ ...VALID_CLIENT, client_name: 'Other client' })

  assert.equal(store.challengeForAuthorizationCode(otherClient.client_id, committed.authorizationCode, NOW), undefined)
  assert.equal(store.challengeForAuthorizationCode(client.client_id, committed.authorizationCode, NOW + 600), undefined)
  for (const overrides of [
    { clientId: otherClient.client_id },
    { redirectUri: undefined },
    { redirectUri: 'http://127.0.0.1:43124/callback' },
    { resource: undefined },
    { resource: 'https://other.example.test/mcp' },
    { now: NOW + 600 },
  ]) {
    assert.throws(
      () => store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, committed.authorizationCode, overrides)),
      /invalid authorization code/i,
    )
    assert.equal(query(path, 'SELECT COUNT(*) AS count FROM token_families')[0].count, 0)
    assert.equal(query(path, 'SELECT consumed_at FROM authorization_codes')[0].consumed_at, null)
  }

  store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, committed.authorizationCode))
  assert.equal(store.challengeForAuthorizationCode(client.client_id, committed.authorizationCode, NOW), undefined)
  assert.throws(
    () => store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, committed.authorizationCode)),
    /invalid authorization code/i,
  )
  assert.equal(query(path, 'SELECT COUNT(*) AS count FROM token_families')[0].count, 1)
})

test('access lookup fails closed for expiry, revocation, altered scope, and wrong resource', async (t) => {
  const { path, store, client } = await fixture(t)
  const committed = commitAuthorizationCode(store, client.client_id, 'lookup')
  const tokens = store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, committed.authorizationCode))
  const familyId = query(path, 'SELECT id FROM token_families')[0].id

  assert.equal(store.lookupAccessToken(tokens.access_token, NOW + ACCESS_TTL), undefined)
  const corruptions = [
    ["UPDATE token_families SET revoked_at = ? WHERE id = ?", [NOW + 1, familyId]],
    ["UPDATE token_families SET scopes = 'zendesk:read' WHERE id = ?", [familyId]],
    ["UPDATE token_families SET resource = 'https://other.example.test/mcp' WHERE id = ?", [familyId]],
  ]
  for (const [sql, parameters] of corruptions) {
    execute(path, (db) => {
      db.prepare("UPDATE token_families SET client_id = ?, scopes = ?, resource = ?, revoked_at = NULL WHERE id = ?")
        .run(client.client_id, MCP_SCOPES.join(' '), RESOURCE, familyId)
      db.prepare(sql).run(...parameters)
    })
    assert.equal(store.lookupAccessToken(tokens.access_token, NOW), undefined)
  }
})

test('code exchange and access lookup require an active principal at the exact lifecycle epoch', async (t) => {
  const states = [
    { label: 'stale', sql: "UPDATE principals SET lifecycle_epoch = lifecycle_epoch + 1" },
    { label: 'disconnected', sql: "UPDATE principals SET status = 'disconnected', disconnected_at = ?" },
    { label: 'reauthorization', sql: "UPDATE principals SET status = 'reauthorization_required'" },
  ]

  for (const state of states) {
    await t.test(state.label, async (t) => {
      const { path, store, client } = await fixture(t)
      const first = commitAuthorizationCode(store, client.client_id, `${state.label}-access`)
      const tokens = store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, first.authorizationCode))
      const second = commitAuthorizationCode(store, client.client_id, `${state.label}-code`, NOW + 1)

      execute(path, (db) => {
        if (state.label === 'disconnected') db.prepare(state.sql).run(NOW + 2)
        else db.prepare(state.sql).run()
      })

      assert.equal(store.lookupAccessToken(tokens.access_token, NOW + 2), undefined)
      assert.throws(
        () => store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, second.authorizationCode, { now: NOW + 2 })),
        /invalid authorization code/i,
      )
      assert.equal(query(path, 'SELECT consumed_at FROM authorization_codes WHERE code_hash = ?', hashOpaque(second.authorizationCode))[0].consumed_at, null)
      assert.equal(query(path, 'SELECT COUNT(*) AS count FROM token_families')[0].count, 1)
    })
  }
})

test('access-token TTL must be a positive safe integer that cannot overflow epoch seconds', async (t) => {
  const { path, store, client } = await fixture(t)
  const committed = commitAuthorizationCode(store, client.client_id, 'ttl')
  for (const accessTokenTtlSeconds of [0, -1, 1.5, Number.MAX_SAFE_INTEGER]) {
    assert.throws(
      () => store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, committed.authorizationCode, { accessTokenTtlSeconds })),
      /invalid authorization code/i,
    )
  }
  assert.equal(query(path, 'SELECT consumed_at FROM authorization_codes')[0].consumed_at, null)
  assert.equal(query(path, 'SELECT COUNT(*) AS count FROM token_families')[0].count, 0)
})

test('a post-consumption issuance failure rolls back the code and every partial token row', async (t) => {
  const { path, store, client } = await fixture(t)
  const committed = commitAuthorizationCode(store, client.client_id, 'trigger-rollback')
  const before = issuanceCounts(path)
  execute(path, (db) => db.exec(`
    CREATE TRIGGER abort_refresh_generation
    BEFORE INSERT ON refresh_token_generations
    BEGIN
      SELECT RAISE(ABORT, 'injected refresh insert failure');
    END;
  `))

  assert.throws(
    () => store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, committed.authorizationCode)),
    /injected refresh insert failure/i,
  )

  assert.equal(
    query(path, 'SELECT consumed_at FROM authorization_codes WHERE code_hash = ?', hashOpaque(committed.authorizationCode))[0].consumed_at,
    null,
  )
  assert.deepEqual(issuanceCounts(path), before)
})

test('invalid and colliding injected random values never consume the code or leave partial rows', async (t) => {
  for (const testCase of [
    { label: 'malformed token', randomToken: () => 'too-short' },
    { label: 'access equals refresh', value: randomOpaque() },
    { label: 'token equals authorization code', authorizationCollision: true },
  ]) {
    await t.test(testCase.label, async (t) => {
      const { path, cipher, store, client } = await fixture(t)
      const committed = commitAuthorizationCode(store, client.client_id, `random-${testCase.label}`)
      const randomToken = testCase.authorizationCollision
        ? () => committed.authorizationCode
        : testCase.randomToken ?? (() => testCase.value)
      const issuanceStore = openIssuanceStore(t, path, cipher, { randomToken })

      assert.throws(
        () => issuanceStore.consumeCodeAndIssueFamily(exchangeInput(client.client_id, committed.authorizationCode)),
        /random source is invalid/i,
      )
      assert.equal(
        query(path, 'SELECT consumed_at FROM authorization_codes WHERE code_hash = ?', hashOpaque(committed.authorizationCode))[0].consumed_at,
        null,
      )
      assert.deepEqual(issuanceCounts(path), { families: 0, access: 0, refresh: 0 })
    })
  }

  await t.test('access hash already exists', async (t) => {
    const { path, cipher, store, client } = await fixture(t)
    const firstCode = commitAuthorizationCode(store, client.client_id, 'existing-token-first')
    const firstTokens = store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, firstCode.authorizationCode))
    const secondCode = commitAuthorizationCode(store, client.client_id, 'existing-token-second', NOW + 1)
    const generated = [firstTokens.access_token, randomOpaque()]
    const issuanceStore = openIssuanceStore(t, path, cipher, {
      randomToken: () => generated.shift(),
    })

    assert.throws(
      () => issuanceStore.consumeCodeAndIssueFamily(exchangeInput(client.client_id, secondCode.authorizationCode, { now: NOW + 1 })),
      /random source is invalid/i,
    )
    assert.equal(
      query(path, 'SELECT consumed_at FROM authorization_codes WHERE code_hash = ?', hashOpaque(secondCode.authorizationCode))[0].consumed_at,
      null,
    )
    assert.deepEqual(issuanceCounts(path), { families: 1, access: 1, refresh: 1 })
    assert.deepEqual(store.lookupAccessToken(firstTokens.access_token, NOW + 1), {
      clientId: client.client_id,
      principalId: firstCode.principalId,
      scopes: MCP_SCOPES,
      resource: RESOURCE,
      expiresAt: NOW + ACCESS_TTL,
    })
  })
})

test('initial issuance rejects cross-table token collisions before one token can resolve to two same-client families', async (t) => {
  for (const testCase of [
    {
      label: 'new access equals existing refresh',
      generated(first) {
        return [first.refresh_token, randomOpaque()]
      },
      presented(first) {
        return first.refresh_token
      },
    },
    {
      label: 'new refresh equals existing access',
      generated(first) {
        return [randomOpaque(), first.access_token]
      },
      presented(first) {
        return first.access_token
      },
    },
  ]) {
    await t.test(testCase.label, async (t) => {
      const { path, cipher, store, client } = await fixture(t)
      const firstCode = commitAuthorizationCode(store, client.client_id, `${testCase.label}-first`)
      const first = store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, firstCode.authorizationCode))
      const firstFamilyId = query(path, 'SELECT id FROM token_families')[0].id
      const secondCode = commitAuthorizationCode(store, client.client_id, `${testCase.label}-second`, NOW + 1)
      const generated = testCase.generated(first)
      const collidingStore = openIssuanceStore(t, path, cipher, {
        randomToken: () => generated.shift(),
      })

      assert.throws(
        () => collidingStore.consumeCodeAndIssueFamily(exchangeInput(client.client_id, secondCode.authorizationCode, { now: NOW + 1 })),
        /random source is invalid/i,
      )
      assert.equal(
        query(path, 'SELECT consumed_at FROM authorization_codes WHERE code_hash = ?', hashOpaque(secondCode.authorizationCode))[0].consumed_at,
        null,
      )
      assert.deepEqual(issuanceCounts(path), { families: 1, access: 1, refresh: 1 })
      assert.deepEqual(
        query(path, 'SELECT id, revoked_at FROM token_families'),
        [{ id: firstFamilyId, revoked_at: null }],
      )

      store.revokeFamilyByPresentedToken(client.client_id, testCase.presented(first), NOW + 2)
      assert.deepEqual(
        query(path, 'SELECT id, revoked_at FROM token_families'),
        [{ id: firstFamilyId, revoked_at: NOW + 2 }],
      )
    })
  }
})

test('access lookup fails closed when the owning client scope is noncanonical or the client row is missing', async (t) => {
  const { path, store, client } = await fixture(t)
  const committed = commitAuthorizationCode(store, client.client_id, 'client-join')
  const tokens = store.consumeCodeAndIssueFamily(exchangeInput(client.client_id, committed.authorizationCode))

  execute(path, (db) => {
    db.pragma('ignore_check_constraints = ON')
    db.prepare("UPDATE oauth_clients SET scope = 'zendesk:read' WHERE client_id = ?").run(client.client_id)
  })
  assert.equal(store.lookupAccessToken(tokens.access_token, NOW), undefined)

  execute(path, (db) => {
    db.pragma('ignore_check_constraints = ON')
    db.prepare('UPDATE oauth_clients SET scope = ? WHERE client_id = ?').run(MCP_SCOPES.join(' '), client.client_id)
    db.pragma('foreign_keys = OFF')
    db.prepare('DELETE FROM oauth_clients WHERE client_id = ?').run(client.client_id)
  })
  assert.equal(store.lookupAccessToken(tokens.access_token, NOW), undefined)
})
