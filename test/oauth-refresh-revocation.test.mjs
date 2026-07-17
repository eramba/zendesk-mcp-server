import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { Worker } from 'node:worker_threads'

import Database from 'better-sqlite3'

import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher, hashOpaque, randomOpaque } from '../dist/oauth/token-cipher.js'

const NOW = 1_700_000_000
const ACCESS_TTL = 3_600
const REFRESH_TTL = 2_592_000
const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const RESOURCE = 'https://dev-server.tail22145b.ts.net/mcp'
const OTHER_RESOURCE = 'https://other.example.test/mcp'
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
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-refresh-'))
  const path = join(directory, 'oauth.sqlite')
  const cipher = new TokenCipher(Buffer.alloc(32, 47))
  const stores = []
  const open = (options = {}) => {
    const store = openSqliteOAuthStore({
      path,
      cipher,
      mcpResourceUrl: new URL(RESOURCE),
      now: () => NOW,
      ...options,
    })
    stores.push(store)
    return store
  }
  t.after(() => {
    for (const store of stores) store.close()
  })
  const store = open()
  const client = store.registerClient(VALID_CLIENT)
  return { directory, path, cipher, open, store, client }
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

async function databaseBytes(store, directory, label) {
  const destination = join(directory, `${label}.sqlite`)
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

function issueFamily(store, clientId, label, now = NOW) {
  const committed = commitAuthorizationCode(store, clientId, label, now)
  const tokens = store.consumeCodeAndIssueFamily({
    clientId,
    authorizationCode: committed.authorizationCode,
    redirectUri: REDIRECT_URI,
    resource: RESOURCE,
    now,
    accessTokenTtlSeconds: ACCESS_TTL,
  })
  return { committed, tokens }
}

function refreshInput(clientId, refreshToken, overrides = {}) {
  return {
    clientId,
    refreshToken,
    scopes: [...MCP_SCOPES],
    resource: RESOURCE,
    canonicalResource: RESOURCE,
    now: NOW,
    accessTokenTtlSeconds: ACCESS_TTL,
    ...overrides,
  }
}

function rotationWorker(workerData) {
  const sqliteStoreUrl = new URL('../dist/oauth/sqlite-store.js', import.meta.url).href
  const tokenCipherUrl = new URL('../dist/oauth/token-cipher.js', import.meta.url).href
  const source = `
    import { parentPort, workerData } from 'node:worker_threads'
    import { openSqliteOAuthStore } from ${JSON.stringify(sqliteStoreUrl)}
    import { TokenCipher } from ${JSON.stringify(tokenCipherUrl)}

    const gate = new Int32Array(workerData.gate)
    const store = openSqliteOAuthStore({
      path: workerData.path,
      cipher: new TokenCipher(Buffer.alloc(32, 47)),
      mcpResourceUrl: new URL(workerData.resource),
      now: () => workerData.input.now,
      busyTimeoutMs: 5_000,
    })
    parentPort.postMessage({ event: 'ready' })
    Atomics.wait(gate, 0, 0)
    try {
      parentPort.postMessage({ event: 'result', result: store.rotateRefreshToken(workerData.input) })
    } catch (error) {
      parentPort.postMessage({ event: 'error', message: error instanceof Error ? error.message : String(error) })
    } finally {
      store.close()
    }
  `
  return new Worker(new URL(`data:text/javascript,${encodeURIComponent(source)}`), { workerData })
}

function waitForWorkerEvent(worker, event, timeoutMs = 6_000) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => finish(new Error(`worker did not emit ${event}`)), timeoutMs)
    const onError = (error) => finish(error)
    const onMessage = (message) => {
      if (message.event === 'error') finish(new Error(message.message))
      else if (message.event === event) finish(undefined, message)
    }
    const finish = (error, value) => {
      clearTimeout(timeout)
      worker.off('error', onError)
      worker.off('message', onMessage)
      if (error) reject(error)
      else resolve(value)
    }
    worker.on('error', onError)
    worker.on('message', onMessage)
  })
}

function familyRows(path) {
  return query(path, 'SELECT * FROM token_families ORDER BY created_at, id')
}

function generationRows(path) {
  return query(path, 'SELECT * FROM refresh_token_generations ORDER BY family_id, generation')
}

test('rotates R1 to R2 to R3 with atomic hash-only generation transitions', async (t) => {
  const { directory, path, store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'chain').tokens

  const first = store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token))
  assert.equal(first.kind, 'issued')
  const second = store.rotateRefreshToken(refreshInput(client.client_id, first.tokens.refresh_token, { now: NOW + 1 }))
  assert.equal(second.kind, 'issued')

  const generations = generationRows(path)
  assert.equal(generations.length, 3)
  assert.deepEqual(generations.map((row) => [row.generation, row.status, row.successor_generation]), [
    [1, 'consumed', 2],
    [2, 'consumed', 3],
    [3, 'current', null],
  ])
  assert.equal(generations[0].token_hash, hashOpaque(r1.refresh_token))
  assert.equal(generations[1].token_hash, hashOpaque(first.tokens.refresh_token))
  assert.equal(generations[2].token_hash, hashOpaque(second.tokens.refresh_token))
  assert.equal(generations[0].consumed_at, NOW)
  assert.equal(generations[1].consumed_at, NOW + 1)
  assert.equal(generations[2].expires_at, NOW + 1 + REFRESH_TTL)
  assert.equal(query(path, 'SELECT COUNT(*) AS count FROM access_tokens')[0].count, 3)
  assert.deepEqual(store.lookupAccessToken(second.tokens.access_token, NOW + 1), {
    clientId: client.client_id,
    principalId: issuePrincipal(path),
    scopes: MCP_SCOPES,
    resource: RESOURCE,
    expiresAt: NOW + 1 + ACCESS_TTL,
  })

  const bytes = await databaseBytes(store, directory, 'hash-only')
  for (const raw of [first.tokens.access_token, first.tokens.refresh_token, second.tokens.access_token, second.tokens.refresh_token]) {
    assert.equal(bytes.includes(Buffer.from(raw, 'utf8')), false)
  }
})

function issuePrincipal(path) {
  return query(path, 'SELECT principal_id FROM token_families LIMIT 1')[0].principal_id
}

test('concurrent store transactions presenting R1 produce one issuance and one exact idempotent response', async (t) => {
  const { path, store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'concurrent').tokens
  const gateBuffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT)
  const gate = new Int32Array(gateBuffer)
  const input = refreshInput(client.client_id, r1.refresh_token)
  const workers = [
    rotationWorker({ path, resource: RESOURCE, input, gate: gateBuffer }),
    rotationWorker({ path, resource: RESOURCE, input, gate: gateBuffer }),
  ]
  t.after(async () => Promise.all(workers.map((worker) => worker.terminate())))
  await Promise.all(workers.map((worker) => waitForWorkerEvent(worker, 'ready')))
  const results = workers.map((worker) => waitForWorkerEvent(worker, 'result'))
  Atomics.store(gate, 0, 1)
  Atomics.notify(gate, 0, workers.length)
  const [first, second] = (await Promise.all(results)).map((message) => message.result)

  const winner = first.kind === 'issued' ? first : second
  const loser = first.kind === 'idempotent' ? first : second
  assert.equal(winner.kind, 'issued')
  assert.deepEqual(loser, { kind: 'idempotent', tokens: winner.tokens })
  assert.equal(generationRows(path).length, 2)
  assert.equal(generationRows(path).filter((row) => row.status === 'current').length, 1)
})

test('an exact R1 retry inside 60 seconds returns the encrypted cached response', async (t) => {
  const { path, store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'retry').tokens
  const issued = store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token, { scopes: undefined, resource: undefined }))
  assert.equal(issued.kind, 'issued')

  const retry = store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token, {
    scopes: undefined,
    resource: undefined,
    now: NOW + 59,
  }))
  assert.deepEqual(retry, { kind: 'idempotent', tokens: issued.tokens })
  const consumed = generationRows(path)[0]
  assert.ok(consumed.encrypted_retry_response_json)
  assert.equal(consumed.retry_response_expires_at, NOW + 60)
  assert.equal(familyRows(path)[0].revoked_at, null)
})

test('R1 at the retry deadline is replay, clears only retry ciphertext, and revokes its family', async (t) => {
  const { path, store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'after-window').tokens
  store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token))

  assert.deepEqual(
    store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token, { now: NOW + 60 })),
    { kind: 'invalid_grant', reason: 'replay' },
  )
  const generations = generationRows(path)
  assert.equal(generations[0].encrypted_retry_response_json, null)
  assert.equal(generations[0].token_hash, hashOpaque(r1.refresh_token))
  assert.equal(generations[0].expires_at, NOW + REFRESH_TTL)
  assert.equal(familyRows(path)[0].revoked_at, NOW + 60)
})

test('R1 replay after R2 advances to R3 revokes the family instead of returning stale R2', async (t) => {
  const { path, store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'advanced').tokens
  const r2 = store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token))
  assert.equal(r2.kind, 'issued')
  const r3 = store.rotateRefreshToken(refreshInput(client.client_id, r2.tokens.refresh_token, { now: NOW + 1 }))
  assert.equal(r3.kind, 'issued')

  assert.deepEqual(
    store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token, { now: NOW + 2 })),
    { kind: 'invalid_grant', reason: 'replay' },
  )
  assert.equal(familyRows(path)[0].revoked_at, NOW + 2)
  assert.deepEqual(
    store.rotateRefreshToken(refreshInput(client.client_id, r3.tokens.refresh_token, { now: NOW + 3 })),
    { kind: 'invalid_grant', reason: 'revoked' },
  )
})

test('wrong client cannot rotate or revoke another client family', async (t) => {
  const { path, store, client } = await fixture(t)
  const otherClient = store.registerClient({ ...VALID_CLIENT, client_name: 'Other client' })
  const r1 = issueFamily(store, client.client_id, 'wrong-client').tokens

  assert.deepEqual(
    store.rotateRefreshToken(refreshInput(otherClient.client_id, r1.refresh_token)),
    { kind: 'invalid_grant', reason: 'binding_mismatch' },
  )
  assert.equal(familyRows(path)[0].revoked_at, null)
  assert.equal(store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token)).kind, 'issued')
})

for (const mismatch of [
  { label: 'scope', overrides: { scopes: ['zendesk:read'] } },
  { label: 'supplied resource', overrides: { resource: OTHER_RESOURCE } },
  { label: 'canonical resource', overrides: { canonicalResource: OTHER_RESOURCE } },
]) {
  test(`${mismatch.label} mismatch rejects the refresh and revokes only its owning family`, async (t) => {
    const { path, store, client } = await fixture(t)
    const r1 = issueFamily(store, client.client_id, `wrong-${mismatch.label}`).tokens

    assert.deepEqual(
      store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token, mismatch.overrides)),
      { kind: 'invalid_grant', reason: 'binding_mismatch' },
    )
    assert.equal(familyRows(path)[0].revoked_at, NOW)
  })
}

test('omitted scope and resource inherit the immutable canonical family bindings', async (t) => {
  const { store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'inherit').tokens

  const result = store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token, {
    scopes: undefined,
    resource: undefined,
  }))
  assert.equal(result.kind, 'issued')
  assert.equal(result.tokens.scope, MCP_SCOPES.join(' '))
})

test('family revocation suppresses a valid cached retry during the grace window', async (t) => {
  const { store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'revoked-retry').tokens
  const r2 = store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token))
  assert.equal(r2.kind, 'issued')

  store.revokeFamilyByPresentedToken(client.client_id, r2.tokens.access_token, NOW + 1)
  assert.deepEqual(
    store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token, { now: NOW + 2 })),
    { kind: 'invalid_grant', reason: 'revoked' },
  )
})

test('an expired consumed R1 returns expired without revoking its healthy family', async (t) => {
  const { path, store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'expired').tokens
  const r2 = store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token, { now: NOW + 1 }))
  assert.equal(r2.kind, 'issued')

  assert.deepEqual(
    store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token, { now: NOW + REFRESH_TTL })),
    { kind: 'invalid_grant', reason: 'expired' },
  )
  assert.equal(familyRows(path)[0].revoked_at, null)
  assert.equal(
    store.rotateRefreshToken(refreshInput(client.client_id, r2.tokens.refresh_token, { now: NOW + REFRESH_TTL })).kind,
    'issued',
  )
})

test('a retry response survives process reopen and decrypts with exact AAD', async (t) => {
  const { open, store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'restart').tokens
  const r2 = store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token))
  assert.equal(r2.kind, 'issued')
  store.close()

  const reopened = open({ now: () => NOW + 30 })
  assert.deepEqual(
    reopened.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token, { now: NOW + 30 })),
    { kind: 'idempotent', tokens: r2.tokens },
  )
})

test('recovery clears expired retry ciphertext but retains the consumed replay marker', async (t) => {
  const { path, store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'recovery').tokens
  store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token))

  store.recover(NOW + 60)
  const row = generationRows(path)[0]
  assert.equal(row.encrypted_retry_response_json, null)
  assert.equal(row.retry_response_expires_at, NOW + 60)
  assert.equal(row.status, 'consumed')
  assert.equal(row.token_hash, hashOpaque(r1.refresh_token))
  assert.equal(familyRows(path)[0].revoked_at, null)
})

test('replay revokes only one of two families belonging to the same principal', async (t) => {
  const { path, store, client } = await fixture(t)
  const familyA = issueFamily(store, client.client_id, 'family-a', NOW).tokens
  const familyB = issueFamily(store, client.client_id, 'family-b', NOW + 1).tokens
  const a2 = store.rotateRefreshToken(refreshInput(client.client_id, familyA.refresh_token, { now: NOW + 2 }))
  assert.equal(a2.kind, 'issued')

  assert.deepEqual(
    store.rotateRefreshToken(refreshInput(client.client_id, familyA.refresh_token, { now: NOW + 62 })),
    { kind: 'invalid_grant', reason: 'replay' },
  )
  const families = familyRows(path)
  assert.equal(families.filter((row) => row.revoked_at !== null).length, 1)
  assert.equal(families.filter((row) => row.revoked_at === null).length, 1)
  assert.equal(
    store.rotateRefreshToken(refreshInput(client.client_id, familyB.refresh_token, { now: NOW + 62 })).kind,
    'issued',
  )
})

test('RFC revocation accepts owned access or refresh tokens and ignores unknown or cross-client values', async (t) => {
  const { path, store, client } = await fixture(t)
  const otherClient = store.registerClient({ ...VALID_CLIENT, client_name: 'Other client' })
  const accessFamily = issueFamily(store, client.client_id, 'revoke-access', NOW).tokens
  const refreshFamily = issueFamily(store, client.client_id, 'revoke-refresh', NOW + 1).tokens

  store.revokeFamilyByPresentedToken(otherClient.client_id, accessFamily.access_token, NOW + 2)
  store.revokeFamilyByPresentedToken(client.client_id, randomOpaque(), NOW + 2)
  assert.equal(familyRows(path).every((row) => row.revoked_at === null), true)

  store.revokeFamilyByPresentedToken(client.client_id, accessFamily.access_token, NOW + 3)
  store.revokeFamilyByPresentedToken(client.client_id, refreshFamily.refresh_token, NOW + 4)
  assert.deepEqual(familyRows(path).map((row) => row.revoked_at).sort(), [NOW + 3, NOW + 4])
  store.revokeFamilyByPresentedToken(client.client_id, accessFamily.access_token, NOW + 5)
  assert.deepEqual(familyRows(path).map((row) => row.revoked_at).sort(), [NOW + 3, NOW + 4])
})

test('invalid rotation entropy rolls back consumption and every partial successor row', async (t) => {
  const { path, open, store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'entropy').tokens
  const repeated = randomOpaque()
  const broken = open({ randomToken: () => repeated })

  assert.throws(
    () => broken.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token)),
    /random source is invalid/i,
  )
  assert.deepEqual(generationRows(path).map((row) => [row.generation, row.status]), [[1, 'current']])
  assert.equal(query(path, 'SELECT COUNT(*) AS count FROM access_tokens')[0].count, 1)
  assert.equal(store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token)).kind, 'issued')
})

test('a successor insert failure rolls back the current-generation consumption', async (t) => {
  const { path, store, client } = await fixture(t)
  const r1 = issueFamily(store, client.client_id, 'rollback').tokens
  execute(path, (db) => db.exec(`
    CREATE TRIGGER abort_refresh_rotation
    BEFORE INSERT ON refresh_token_generations
    WHEN NEW.generation > 1
    BEGIN
      SELECT RAISE(ABORT, 'injected successor failure');
    END;
  `))

  assert.throws(
    () => store.rotateRefreshToken(refreshInput(client.client_id, r1.refresh_token)),
    /injected successor failure/i,
  )
  assert.deepEqual(generationRows(path).map((row) => [row.generation, row.status, row.consumed_at]), [[1, 'current', null]])
  assert.equal(query(path, 'SELECT COUNT(*) AS count FROM access_tokens')[0].count, 1)
})
