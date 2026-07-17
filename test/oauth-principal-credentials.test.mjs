import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import Database from 'better-sqlite3'

import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher, hashOpaque } from '../dist/oauth/token-cipher.js'

const NOW = 1_700_000_000
const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const RESOURCE = 'https://dev-server.tail22145b.ts.net/mcp'
const CODE_CHALLENGE = 'C'.repeat(43)
const MCP_SCOPES = ['zendesk:read', 'zendesk:write']
const SUBDOMAIN = 'example'
const USER_ID = '424242'
const VALID_CLIENT = {
  redirect_uris: [REDIRECT_URI],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'Codex Desktop',
  scope: MCP_SCOPES.join(' '),
}

async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-principal-'))
  const path = join(directory, 'oauth.sqlite')
  const cipher = new TokenCipher(Buffer.alloc(32, 23))
  const store = openSqliteOAuthStore({
    path,
    cipher,
    mcpResourceUrl: new URL(RESOURCE),
    now: () => NOW,
    ...options,
  })
  t.after(() => store.close())
  const client = store.registerClient(VALID_CLIENT)
  return { directory, path, cipher, store, client }
}

function loginInput(clientId, originalState, now = NOW) {
  return {
    clientId,
    redirectUri: REDIRECT_URI,
    codeChallenge: CODE_CHALLENGE,
    scopes: [...MCP_SCOPES],
    resource: RESOURCE,
    originalState,
    subdomain: SUBDOMAIN,
    now,
  }
}

function claimLogin(store, clientId, originalState, now = NOW) {
  const started = store.beginLogin(loginInput(clientId, originalState, now))
  const decision = store.decideConsent({
    transactionToken: started.transactionToken,
    consentCsrf: started.consentCsrf,
    browserNonce: started.browserNonce,
    decision: 'confirm',
    now,
  })
  assert.equal(decision.kind, 'confirmed')
  const callback = store.claimZendeskCallback(decision.upstreamState, now)
  assert.ok(callback)
  return { callback, decision, started }
}

function grant(label, now = NOW) {
  return {
    accessToken: `access-${label}-SENTINEL`,
    refreshToken: `refresh-${label}-SENTINEL`,
    accessExpiresAt: now + 3_600,
    refreshExpiresAt: now + 86_400,
    scopes: ['read', 'tickets:write'],
  }
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

async function databaseBytes(store, directory, name) {
  const destination = join(directory, name)
  await store.backup(destination)
  return readFile(destination)
}

function assertSecretsAbsent(value, secrets) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8')
  for (const secret of secrets) {
    assert.equal(bytes.includes(Buffer.from(secret, 'utf8')), false, `plaintext leaked: ${secret}`)
  }
}

function inspectCredential(path, cipher) {
  const row = query(
    path,
    `SELECT c.*, p.subdomain
     FROM zendesk_credentials c JOIN principals p ON p.id = c.principal_id`,
  )[0]
  assert.ok(row)
  const plaintext = cipher.decrypt(JSON.parse(row.encrypted_grant_json), {
    kind: 'zendesk_credential',
    rowId: row.principal_id,
    expiresAt: row.refresh_expires_at,
    subdomain: row.subdomain,
    principalId: row.principal_id,
    credentialVersion: row.credential_version,
    principalEpoch: row.principal_epoch,
  })
  return { row, grant: JSON.parse(plaintext) }
}

function seedDisconnect(path, cipher, principalId, disconnectedAt, status = 'pending') {
  execute(path, (db) => {
    const credential = db.prepare(
      'SELECT * FROM zendesk_credentials WHERE principal_id = ?',
    ).get(principalId)
    const outboxId = `outbox-${disconnectedAt}-${status}`
    const retentionExpiresAt = disconnectedAt + 86_400
    const plaintext = cipher.decrypt(JSON.parse(credential.encrypted_grant_json), {
      kind: 'zendesk_credential',
      rowId: principalId,
      expiresAt: credential.refresh_expires_at,
      subdomain: SUBDOMAIN,
      principalId,
      credentialVersion: credential.credential_version,
      principalEpoch: credential.principal_epoch,
    })
    const outboxGrant = cipher.encrypt(plaintext, {
      kind: 'disconnect_outbox',
      rowId: outboxId,
      expiresAt: retentionExpiresAt,
      subdomain: SUBDOMAIN,
      principalId,
      credentialVersion: credential.credential_version,
      principalEpoch: credential.principal_epoch,
    })
    db.transaction(() => {
      db.prepare(
        `UPDATE principals
         SET status = 'disconnected', disconnected_at = ?, updated_at = ?
         WHERE id = ?`,
      ).run(disconnectedAt, disconnectedAt, principalId)
      db.prepare('DELETE FROM zendesk_credentials WHERE principal_id = ?').run(principalId)
      db.prepare(
        `INSERT INTO revocation_outbox (
           id, principal_id, captured_principal_epoch, credential_version,
           encrypted_grant_json, status, next_attempt_at, claim_owner,
           claim_expires_at, retention_expires_at, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        outboxId,
        principalId,
        credential.principal_epoch,
        credential.credential_version,
        JSON.stringify(outboxGrant),
        status,
        disconnectedAt,
        status === 'claimed' ? 'worker-1' : null,
        status === 'claimed' ? disconnectedAt + 300 : null,
        retentionExpiresAt,
        disconnectedAt,
      )
    })()
  })
}

test('staged login grants are encrypted, unavailable as credentials, and discard-only', async (t) => {
  const { directory, path, store, client } = await fixture(t)
  const { callback } = claimLogin(store, client.client_id, 'stage-state-SENTINEL')
  const stagedGrant = grant('staged')

  const { result: staged, captured } = captureConsole(() => store.stageLoginGrant({
    transactionId: callback.transactionId,
    subdomain: SUBDOMAIN,
    grant: stagedGrant,
    now: NOW,
  }))

  const rows = query(path, 'SELECT * FROM staged_grants')
  assert.equal(rows.length, 1)
  assert.equal(rows[0].id, staged.stageId)
  assert.equal(rows[0].purpose, 'login')
  assert.equal(rows[0].status, 'staged')
  assert.equal(rows[0].expires_at, NOW + 600)
  assertSecretsAbsent(JSON.stringify(rows[0]), [stagedGrant.accessToken, stagedGrant.refreshToken])
  assert.equal(query(path, 'SELECT * FROM zendesk_credentials').length, 0)
  assert.equal(store.discardStagedGrant(staged.stageId, NOW), true)
  assert.equal(store.discardStagedGrant(staged.stageId, NOW), false)
  assert.equal(query(path, 'SELECT status FROM staged_grants')[0].status, 'discard_only')

  const bytes = await databaseBytes(store, directory, 'staged.sqlite')
  assertSecretsAbsent(bytes, [stagedGrant.accessToken, stagedGrant.refreshToken])
  assertSecretsAbsent(captured.join('\n'), [stagedGrant.accessToken, stagedGrant.refreshToken])
})

test('first callback atomically creates the stable principal, credential, code, and completed login', async (t) => {
  const { path, cipher, store, client } = await fixture(t)
  const originalState = 'first-state-SENTINEL'
  const { callback } = claimLogin(store, client.client_id, originalState)
  const firstGrant = grant('first')
  const { stageId } = store.stageLoginGrant({
    transactionId: callback.transactionId,
    subdomain: SUBDOMAIN,
    grant: firstGrant,
    now: NOW,
  })

  const committed = store.commitLogin({
    transactionId: callback.transactionId,
    stageId,
    zendeskUserId: USER_ID,
    now: NOW,
  })

  assert.deepEqual(committed, {
    redirectUri: REDIRECT_URI,
    originalState,
    principalId: committed.principalId,
    principalEpoch: 1,
    authorizationCode: committed.authorizationCode,
  })
  assert.equal(Buffer.from(committed.authorizationCode, 'base64url').length, 32)
  const principal = query(path, 'SELECT * FROM principals')[0]
  assert.equal(principal.id, committed.principalId)
  assert.equal(principal.subdomain, SUBDOMAIN)
  assert.equal(principal.zendesk_user_id, USER_ID)
  assert.equal(principal.status, 'active')
  assert.equal(principal.lifecycle_epoch, 1)
  const credential = inspectCredential(path, cipher)
  assert.equal(credential.row.credential_version, 1)
  assert.equal(credential.row.principal_epoch, 1)
  assert.deepEqual(credential.grant, firstGrant)
  const codes = query(path, 'SELECT * FROM authorization_codes')
  assert.equal(codes.length, 1)
  assert.equal(codes[0].code_hash, hashOpaque(committed.authorizationCode))
  assert.equal(codes[0].client_id, client.client_id)
  assert.equal(codes[0].redirect_uri, REDIRECT_URI)
  assert.equal(codes[0].code_challenge, CODE_CHALLENGE)
  assert.equal(codes[0].scopes, MCP_SCOPES.join(' '))
  assert.equal(codes[0].resource, RESOURCE)
  assert.equal(codes[0].principal_epoch, 1)
  assert.equal(codes[0].expires_at, NOW + 600)
  assert.equal(query(path, 'SELECT status FROM login_transactions')[0].status, 'complete')
  assert.equal(query(path, 'SELECT * FROM staged_grants').length, 0)
})

test('injected commit failure rolls back principal, credential, code, login, and stage changes', async (t) => {
  const failure = new Error('injected login commit failure')
  const { path, store, client } = await fixture(t, {
    testHooks: { beforeLoginWrites: () => { throw failure } },
  })
  const { callback } = claimLogin(store, client.client_id, 'rollback-state')
  const { stageId } = store.stageLoginGrant({
    transactionId: callback.transactionId,
    subdomain: SUBDOMAIN,
    grant: grant('rollback'),
    now: NOW,
  })

  assert.throws(
    () => store.commitLogin({
      transactionId: callback.transactionId,
      stageId,
      zendeskUserId: USER_ID,
      now: NOW,
    }),
    /injected login commit failure/,
  )
  assert.equal(query(path, 'SELECT * FROM principals').length, 0)
  assert.equal(query(path, 'SELECT * FROM zendesk_credentials').length, 0)
  assert.equal(query(path, 'SELECT * FROM authorization_codes').length, 0)
  assert.equal(query(path, 'SELECT status FROM login_transactions')[0].status, 'callback_claimed')
  assert.equal(query(path, 'SELECT id, status FROM staged_grants')[0].id, stageId)
  assert.equal(query(path, 'SELECT id, status FROM staged_grants')[0].status, 'staged')
})

test('active re-login increments only credential version and preserves every family marker', async (t) => {
  const { path, cipher, store, client } = await fixture(t)
  const first = claimLogin(store, client.client_id, 'first-family-state')
  const firstStage = store.stageLoginGrant({
    transactionId: first.callback.transactionId,
    subdomain: SUBDOMAIN,
    grant: grant('family-first'),
    now: NOW,
  })
  const initial = store.commitLogin({
    transactionId: first.callback.transactionId,
    stageId: firstStage.stageId,
    zendeskUserId: USER_ID,
    now: NOW,
  })
  execute(path, (db) => {
    const insert = db.prepare(
      `INSERT INTO token_families (
         id, client_id, principal_id, principal_epoch, scopes, resource,
         created_at, last_used_at, revoked_at, revoke_reason
       ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)`,
    )
    insert.run('family-active', client.client_id, initial.principalId, MCP_SCOPES.join(' '), RESOURCE, NOW, NOW, null, null)
    insert.run('family-revoked', client.client_id, initial.principalId, MCP_SCOPES.join(' '), RESOURCE, NOW, NOW, NOW + 1, 'manual')
  })

  const second = claimLogin(store, client.client_id, 'second-family-state', NOW + 2)
  const replacementGrant = grant('family-second', NOW + 2)
  const secondStage = store.stageLoginGrant({
    transactionId: second.callback.transactionId,
    subdomain: SUBDOMAIN,
    grant: replacementGrant,
    now: NOW + 2,
  })
  const relogin = store.commitLogin({
    transactionId: second.callback.transactionId,
    stageId: secondStage.stageId,
    zendeskUserId: USER_ID,
    now: NOW + 2,
  })

  assert.equal(relogin.principalId, initial.principalId)
  assert.equal(relogin.principalEpoch, 1)
  assert.equal(query(path, 'SELECT COUNT(*) AS count FROM principals')[0].count, 1)
  assert.equal(inspectCredential(path, cipher).row.credential_version, 2)
  assert.deepEqual(inspectCredential(path, cipher).grant, replacementGrant)
  assert.deepEqual(
    query(path, 'SELECT id, revoked_at, revoke_reason FROM token_families ORDER BY id'),
    [
      { id: 'family-active', revoked_at: null, revoke_reason: null },
      { id: 'family-revoked', revoked_at: NOW + 1, revoke_reason: 'manual' },
    ],
  )
})

test('concurrent callbacks serialize to the last credential without upstream cleanup', async (t) => {
  const { path, cipher, store, client } = await fixture(t)
  const other = openSqliteOAuthStore({
    path,
    cipher,
    mcpResourceUrl: new URL(RESOURCE),
    now: () => NOW,
  })
  t.after(() => other.close())
  const first = claimLogin(store, client.client_id, 'concurrent-first')
  const second = claimLogin(other, client.client_id, 'concurrent-second', NOW + 1)
  const firstGrant = grant('concurrent-first')
  const secondGrant = grant('concurrent-second', NOW + 1)
  const firstStage = store.stageLoginGrant({ transactionId: first.callback.transactionId, subdomain: SUBDOMAIN, grant: firstGrant, now: NOW })
  const secondStage = other.stageLoginGrant({ transactionId: second.callback.transactionId, subdomain: SUBDOMAIN, grant: secondGrant, now: NOW + 1 })

  const firstCommit = store.commitLogin({ transactionId: first.callback.transactionId, stageId: firstStage.stageId, zendeskUserId: USER_ID, now: NOW + 1 })
  const secondCommit = other.commitLogin({ transactionId: second.callback.transactionId, stageId: secondStage.stageId, zendeskUserId: USER_ID, now: NOW + 2 })

  assert.equal(secondCommit.principalId, firstCommit.principalId)
  assert.equal(secondCommit.principalEpoch, firstCommit.principalEpoch)
  const current = inspectCredential(path, cipher)
  assert.equal(current.row.credential_version, 2)
  assert.deepEqual(current.grant, secondGrant)
  assert.equal(query(path, 'SELECT * FROM staged_grants').length, 0)
  assert.equal(query(path, 'SELECT * FROM revocation_outbox').length, 0)
})

test('disconnect timing rejects an older callback and later login cancels only pending cleanup', async (t) => {
  const { path, cipher, store, client } = await fixture(t)
  const before = claimLogin(store, client.client_id, 'before-disconnect')
  const beforeStage = store.stageLoginGrant({ transactionId: before.callback.transactionId, subdomain: SUBDOMAIN, grant: grant('before-disconnect'), now: NOW })
  const installed = store.commitLogin({ transactionId: before.callback.transactionId, stageId: beforeStage.stageId, zendeskUserId: USER_ID, now: NOW })

  const oldCallback = claimLogin(store, client.client_id, 'old-callback', NOW + 5)
  const disconnectedAt = NOW + 10
  seedDisconnect(path, cipher, installed.principalId, disconnectedAt)
  const oldStage = store.stageLoginGrant({ transactionId: oldCallback.callback.transactionId, subdomain: SUBDOMAIN, grant: grant('old-callback', NOW + 11), now: NOW + 11 })
  assert.throws(
    () => store.commitLogin({ transactionId: oldCallback.callback.transactionId, stageId: oldStage.stageId, zendeskUserId: USER_ID, now: NOW + 11 }),
    /invalid login commit/i,
  )
  assert.equal(store.discardStagedGrant(oldStage.stageId, NOW + 11), true)
  assert.equal(query(path, 'SELECT status FROM principals')[0].status, 'disconnected')
  assert.equal(query(path, 'SELECT * FROM revocation_outbox').length, 1)

  const later = claimLogin(store, client.client_id, 'later-callback', disconnectedAt + 1)
  const laterGrant = grant('later-callback', disconnectedAt + 1)
  const laterStage = store.stageLoginGrant({ transactionId: later.callback.transactionId, subdomain: SUBDOMAIN, grant: laterGrant, now: disconnectedAt + 1 })
  const reactivated = store.commitLogin({ transactionId: later.callback.transactionId, stageId: laterStage.stageId, zendeskUserId: USER_ID, now: disconnectedAt + 1 })

  assert.equal(reactivated.principalId, installed.principalId)
  assert.equal(reactivated.principalEpoch, 2)
  assert.deepEqual(
    query(path, 'SELECT status, lifecycle_epoch, disconnected_at FROM principals'),
    [{ status: 'active', lifecycle_epoch: 2, disconnected_at: null }],
  )
  assert.equal(query(path, 'SELECT * FROM revocation_outbox').length, 0)
  assert.equal(inspectCredential(path, cipher).row.credential_version, 2)
  assert.deepEqual(inspectCredential(path, cipher).grant, laterGrant)
})

test('a claimed disconnect cleanup blocks reactivation until release or completion', async (t) => {
  const { path, cipher, store, client } = await fixture(t)
  const initialLogin = claimLogin(store, client.client_id, 'claimed-initial')
  const initialStage = store.stageLoginGrant({ transactionId: initialLogin.callback.transactionId, subdomain: SUBDOMAIN, grant: grant('claimed-initial'), now: NOW })
  const installed = store.commitLogin({ transactionId: initialLogin.callback.transactionId, stageId: initialStage.stageId, zendeskUserId: USER_ID, now: NOW })
  const disconnectedAt = NOW + 10
  seedDisconnect(path, cipher, installed.principalId, disconnectedAt, 'claimed')

  const blocked = claimLogin(store, client.client_id, 'claimed-blocked', disconnectedAt + 1)
  const blockedStage = store.stageLoginGrant({ transactionId: blocked.callback.transactionId, subdomain: SUBDOMAIN, grant: grant('claimed-blocked', disconnectedAt + 1), now: disconnectedAt + 1 })
  assert.throws(
    () => store.commitLogin({ transactionId: blocked.callback.transactionId, stageId: blockedStage.stageId, zendeskUserId: USER_ID, now: disconnectedAt + 1 }),
    /invalid login commit/i,
  )

  execute(path, (db) => db.prepare(
    `UPDATE revocation_outbox
     SET status = 'pending', claim_owner = NULL, claim_expires_at = NULL
     WHERE principal_id = ?`,
  ).run(installed.principalId))
  const released = store.commitLogin({ transactionId: blocked.callback.transactionId, stageId: blockedStage.stageId, zendeskUserId: USER_ID, now: disconnectedAt + 2 })
  assert.equal(released.principalEpoch, 2)
  assert.equal(query(path, 'SELECT * FROM revocation_outbox').length, 0)

  const secondDisconnect = disconnectedAt + 10
  seedDisconnect(path, cipher, installed.principalId, secondDisconnect, 'claimed')
  const completedClaim = claimLogin(store, client.client_id, 'claimed-completed', secondDisconnect + 1)
  const completedStage = store.stageLoginGrant({ transactionId: completedClaim.callback.transactionId, subdomain: SUBDOMAIN, grant: grant('claimed-completed', secondDisconnect + 1), now: secondDisconnect + 1 })
  execute(path, (db) => db.prepare(
    `UPDATE revocation_outbox SET completed_at = ? WHERE principal_id = ?`,
  ).run(secondDisconnect + 1, installed.principalId))
  const afterCompletion = store.commitLogin({ transactionId: completedClaim.callback.transactionId, stageId: completedStage.stageId, zendeskUserId: USER_ID, now: secondDisconnect + 2 })
  assert.equal(afterCompletion.principalEpoch, 3)
  assert.equal(query(path, 'SELECT completed_at FROM revocation_outbox').length, 1)
  assert.equal(query(path, 'SELECT completed_at FROM revocation_outbox')[0].completed_at, secondDisconnect + 1)
})

test('plaintext grants, OAuth state, MCP codes, and email sentinels never reach DB bytes or logs', async (t) => {
  const { directory, store, client } = await fixture(t)
  const originalState = 'state-secret@example.test-SENTINEL'
  const secretGrant = grant('email-user@example.test')
  const captured = captureConsole(() => {
    const { callback } = claimLogin(store, client.client_id, originalState)
    const { stageId } = store.stageLoginGrant({ transactionId: callback.transactionId, subdomain: SUBDOMAIN, grant: secretGrant, now: NOW })
    return store.commitLogin({ transactionId: callback.transactionId, stageId, zendeskUserId: USER_ID, now: NOW })
  })
  const secrets = [
    secretGrant.accessToken,
    secretGrant.refreshToken,
    originalState,
    captured.result.authorizationCode,
    'email-user@example.test',
  ]

  assertSecretsAbsent(await databaseBytes(store, directory, 'no-plaintext.sqlite'), secrets)
  assertSecretsAbsent(captured.captured.join('\n'), secrets)
})
