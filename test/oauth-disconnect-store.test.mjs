import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import Database from 'better-sqlite3'

import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher } from '../dist/oauth/token-cipher.js'

const NOW = 1_700_000_000
const ACCESS_TTL = 3_600
const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const RESOURCE = 'https://dev-server.tail22145b.ts.net/mcp'
const CODE_CHALLENGE = 'C'.repeat(43)
const MCP_SCOPES = ['zendesk:read', 'zendesk:write']
const ZENDESK_SCOPES = ['read', 'tickets:write']
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
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-disconnect-'))
  const path = join(directory, 'oauth.sqlite')
  const cipher = new TokenCipher(Buffer.alloc(32, 59))
  const stores = []
  const open = (overrides = {}) => {
    const store = openSqliteOAuthStore({
      path,
      cipher,
      mcpResourceUrl: new URL(RESOURCE),
      now: () => NOW,
      ...options,
      ...overrides,
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

function grant(label, now = NOW) {
  return {
    accessToken: `zendesk-access-${label}-SENTINEL`,
    refreshToken: `zendesk-refresh-${label}-SENTINEL`,
    accessExpiresAt: now + 3_600,
    refreshExpiresAt: now + 86_400,
    scopes: [...ZENDESK_SCOPES],
  }
}

function beginClaimedLogin(store, clientId, label, { subdomain = SUBDOMAIN, now = NOW } = {}) {
  const started = store.beginLogin({
    clientId,
    redirectUri: REDIRECT_URI,
    codeChallenge: CODE_CHALLENGE,
    scopes: [...MCP_SCOPES],
    resource: RESOURCE,
    originalState: `state-${label}`,
    subdomain,
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
  return callback
}

function login(store, clientId, label, {
  subdomain = SUBDOMAIN,
  zendeskUserId = USER_ID,
  now = NOW,
  installedGrant = grant(label, now),
} = {}) {
  const callback = beginClaimedLogin(store, clientId, label, { subdomain, now })
  const staged = store.stageLoginGrant({
    transactionId: callback.transactionId,
    subdomain,
    grant: installedGrant,
    now,
  })
  const committed = store.commitLogin({
    transactionId: callback.transactionId,
    stageId: staged.stageId,
    zendeskUserId,
    now,
  })
  return { committed, grant: installedGrant }
}

function issueFamily(store, clientId, label, options = {}) {
  const loggedIn = login(store, clientId, label, options)
  const tokens = store.consumeCodeAndIssueFamily({
    clientId,
    authorizationCode: loggedIn.committed.authorizationCode,
    redirectUri: REDIRECT_URI,
    resource: RESOURCE,
    now: options.now ?? NOW,
    accessTokenTtlSeconds: ACCESS_TTL,
  })
  return { ...loggedIn, tokens }
}

function decryptOutboxGrant(path, cipher, outboxId) {
  const row = query(
    path,
    `SELECT o.*, p.subdomain
     FROM revocation_outbox o JOIN principals p ON p.id = o.principal_id
     WHERE o.id = ?`,
    outboxId,
  )[0]
  assert.ok(row)
  const plaintext = cipher.decrypt(JSON.parse(row.encrypted_grant_json), {
    kind: 'disconnect_outbox',
    rowId: row.id,
    expiresAt: row.retention_expires_at,
    subdomain: row.subdomain,
    principalId: row.principal_id,
    credentialVersion: row.credential_version,
    principalEpoch: row.captured_principal_epoch,
  })
  return { row, grant: JSON.parse(plaintext) }
}

async function databaseBytes(store, directory, label) {
  const destination = join(directory, `${label}.sqlite`)
  await store.backup(destination)
  return readFile(destination)
}

test('disconnect is one atomic lifecycle transition with an encrypted exact-grant tombstone', async (t) => {
  const { directory, path, cipher, store, client } = await fixture(t)
  const first = issueFamily(store, client.client_id, 'family-one', { now: NOW })
  const second = issueFamily(store, client.client_id, 'family-two', { now: NOW + 1 })
  const pending = login(store, client.client_id, 'pending-code', { now: NOW + 2 })
  const disconnectAt = NOW + 10

  const originalTransaction = Database.prototype.transaction
  let immediateCalls = 0
  let deferredCalls = 0
  Database.prototype.transaction = function (...args) {
    const transaction = originalTransaction.apply(this, args)
    const wrapped = (...callArgs) => {
      deferredCalls += 1
      return transaction(...callArgs)
    }
    wrapped.immediate = (...callArgs) => {
      immediateCalls += 1
      return transaction.immediate(...callArgs)
    }
    return wrapped
  }
  let result
  try {
    result = store.disconnectUser(SUBDOMAIN, USER_ID, disconnectAt)
  } finally {
    Database.prototype.transaction = originalTransaction
  }

  assert.deepEqual(result, {
    kind: 'disconnected',
    principalId: first.committed.principalId,
    revokedFamilies: 2,
    outboxId: result.outboxId,
  })
  assert.equal(immediateCalls, 1)
  assert.equal(deferredCalls, 0)
  assert.deepEqual(
    query(path, 'SELECT status, lifecycle_epoch, disconnected_at, updated_at FROM principals'),
    [{ status: 'disconnected', lifecycle_epoch: 2, disconnected_at: disconnectAt, updated_at: disconnectAt }],
  )
  assert.deepEqual(
    query(path, 'SELECT revoked_at, revoke_reason FROM token_families ORDER BY created_at'),
    [
      { revoked_at: disconnectAt, revoke_reason: 'principal_disconnect' },
      { revoked_at: disconnectAt, revoke_reason: 'principal_disconnect' },
    ],
  )
  assert.equal(query(path, 'SELECT * FROM zendesk_credentials').length, 0)
  assert.equal(query(path, 'SELECT consumed_at FROM authorization_codes WHERE consumed_at IS NULL').length, 0)
  assert.equal(
    query(path, 'SELECT consumed_at FROM authorization_codes WHERE code_hash IS NOT NULL').every((row) => row.consumed_at !== null),
    true,
  )
  assert.equal(store.lookupAccessToken(second.tokens.access_token, disconnectAt), undefined)
  assert.equal(store.challengeForAuthorizationCode(client.client_id, pending.committed.authorizationCode, disconnectAt), undefined)

  const tombstone = decryptOutboxGrant(path, cipher, result.outboxId)
  assert.deepEqual(tombstone.grant, pending.grant)
  assert.equal(tombstone.row.status, 'pending')
  assert.equal(tombstone.row.captured_principal_epoch, 2)
  assert.equal(tombstone.row.credential_version, 3)
  assert.equal(tombstone.row.attempt_count, 0)
  assert.equal(tombstone.row.next_attempt_at, disconnectAt)
  assert.equal(tombstone.row.retention_expires_at, pending.grant.refreshExpiresAt + 604_800)
  assert.equal(tombstone.row.claim_owner, null)
  assert.equal(tombstone.row.claim_expires_at, null)
  assert.equal(tombstone.row.completed_at, null)

  const bytes = await databaseBytes(store, directory, 'disconnect-encrypted')
  assert.equal(bytes.includes(Buffer.from(pending.grant.accessToken, 'utf8')), false)
  assert.equal(bytes.includes(Buffer.from(pending.grant.refreshToken, 'utf8')), false)

  assert.deepEqual(store.disconnectUser(SUBDOMAIN, USER_ID, disconnectAt + 1), {
    kind: 'already_disconnected',
    principalId: result.principalId,
  })
  assert.equal(query(path, 'SELECT COUNT(*) AS count FROM revocation_outbox')[0].count, 1)
  assert.equal(query(path, 'SELECT lifecycle_epoch FROM principals')[0].lifecycle_epoch, 2)
  assert.deepEqual(store.disconnectUser('missing', USER_ID, disconnectAt), { kind: 'not_found' })
})

test('disconnect rolls every local mutation back when tombstone staging fails', async (t) => {
  const { path, store, client } = await fixture(t)
  const issued = issueFamily(store, client.client_id, 'rollback')
  const before = {
    principal: query(path, 'SELECT * FROM principals'),
    credential: query(path, 'SELECT * FROM zendesk_credentials'),
    code: query(path, 'SELECT * FROM authorization_codes'),
    family: query(path, 'SELECT * FROM token_families'),
  }
  execute(path, (db) => db.exec(`
    CREATE TRIGGER abort_disconnect_outbox
    BEFORE INSERT ON revocation_outbox
    BEGIN
      SELECT RAISE(ABORT, 'injected disconnect staging failure');
    END;
  `))

  assert.throws(
    () => store.disconnectUser(SUBDOMAIN, USER_ID, NOW + 10),
    /injected disconnect staging failure/i,
  )
  assert.deepEqual(query(path, 'SELECT * FROM principals'), before.principal)
  assert.deepEqual(query(path, 'SELECT * FROM zendesk_credentials'), before.credential)
  assert.deepEqual(query(path, 'SELECT * FROM authorization_codes'), before.code)
  assert.deepEqual(query(path, 'SELECT * FROM token_families'), before.family)
  assert.equal(query(path, 'SELECT * FROM revocation_outbox').length, 0)
  assert.ok(store.lookupAccessToken(issued.tokens.access_token, NOW + 10))
})

test('claims are owner-guarded leases with exact retry attempts, renewal, completion, and abort release', async (t) => {
  const { path, store, client } = await fixture(t)
  const installed = login(store, client.client_id, 'leased')
  const disconnected = store.disconnectUser(SUBDOMAIN, USER_ID, NOW + 10)
  assert.equal(disconnected.kind, 'disconnected')

  assert.equal(store.claimDueRevocation('', NOW + 10, NOW + 40), undefined)
  assert.equal(store.claimDueRevocation('worker-a', NOW + 10, NOW + 10), undefined)
  const first = store.claimDueRevocation('worker-a', NOW + 10, NOW + 40)
  assert.deepEqual(first, {
    outboxId: disconnected.outboxId,
    principalId: installed.committed.principalId,
    capturedPrincipalEpoch: 2,
    credentialVersion: 1,
    grant: installed.grant,
    attemptCount: 1,
    retentionExpiresAt: installed.grant.refreshExpiresAt + 604_800,
  })
  assert.equal(store.claimDueRevocation('worker-b', NOW + 10, NOW + 40), undefined)
  assert.equal(store.renewRevocationClaim(disconnected.outboxId, 'worker-b', NOW + 50), false)
  assert.equal(store.renewRevocationClaim(disconnected.outboxId, 'worker-a', NOW + 40), false)
  assert.equal(store.renewRevocationClaim(disconnected.outboxId, 'worker-a', NOW + 50), true)
  assert.equal(query(path, 'SELECT claim_expires_at FROM revocation_outbox')[0].claim_expires_at, NOW + 50)

  const firstBackoff = Math.min(900, 5 * 2 ** Math.max(0, first.attemptCount - 1))
  assert.equal(store.rescheduleRevocation(disconnected.outboxId, 'worker-b', 'transport', NOW + 10 + firstBackoff), false)
  assert.equal(store.rescheduleRevocation(disconnected.outboxId, 'worker-a', '', NOW + 10 + firstBackoff), false)
  assert.equal(store.rescheduleRevocation(disconnected.outboxId, 'worker-a', 'transport', NOW + 10 + firstBackoff), true)
  assert.deepEqual(
    query(path, 'SELECT status, attempt_count, next_attempt_at, claim_owner, claim_expires_at, last_error_category FROM revocation_outbox'),
    [{
      status: 'pending',
      attempt_count: 1,
      next_attempt_at: NOW + 15,
      claim_owner: null,
      claim_expires_at: null,
      last_error_category: 'transport',
    }],
  )
  assert.equal(store.claimDueRevocation('worker-b', NOW + 14, NOW + 60), undefined)
  const second = store.claimDueRevocation('worker-b', NOW + 15, NOW + 60)
  assert.equal(second.attemptCount, 2)
  assert.equal(store.releaseClaims('worker-a', NOW + 16), 0)
  assert.equal(store.releaseClaims('worker-b', NOW + 16), 1)
  assert.deepEqual(
    query(path, 'SELECT status, next_attempt_at, claim_owner, claim_expires_at FROM revocation_outbox'),
    [{ status: 'pending', next_attempt_at: NOW + 16, claim_owner: null, claim_expires_at: null }],
  )
  const third = store.claimDueRevocation('worker-c', NOW + 16, NOW + 70)
  assert.equal(third.attemptCount, 3)
  assert.equal(store.completeRevocation(disconnected.outboxId, 'worker-b', NOW + 17), false)
  assert.equal(store.completeRevocation(disconnected.outboxId, 'worker-c', NOW + 17), true)
  assert.equal(store.completeRevocation(disconnected.outboxId, 'worker-c', NOW + 18), false)
  assert.equal(query(path, 'SELECT completed_at FROM revocation_outbox')[0].completed_at, NOW + 17)
  assert.equal(store.claimDueRevocation('worker-d', NOW + 18, NOW + 80), undefined)
})

test('an expired claim is reclaimed after reopen and only for the still-disconnected captured epoch', async (t) => {
  const { path, open, store, client } = await fixture(t)
  login(store, client.client_id, 'crash')
  const disconnected = store.disconnectUser(SUBDOMAIN, USER_ID, NOW + 10)
  const claimed = store.claimDueRevocation('dead-worker', NOW + 10, NOW + 20)
  assert.ok(claimed)
  store.close()

  const reopened = open({ now: () => NOW + 20 })
  assert.deepEqual(
    query(path, 'SELECT status, claim_owner, claim_expires_at FROM revocation_outbox'),
    [{ status: 'pending', claim_owner: null, claim_expires_at: null }],
  )
  const reclaimed = reopened.claimDueRevocation('replacement-worker', NOW + 20, NOW + 50)
  assert.equal(reclaimed.outboxId, disconnected.outboxId)
  assert.equal(reclaimed.attemptCount, 2)
  assert.equal(reopened.releaseClaims('replacement-worker', NOW + 21), 1)

  execute(path, (db) => db.prepare(
    'UPDATE principals SET lifecycle_epoch = lifecycle_epoch + 1 WHERE id = ?',
  ).run(claimed.principalId))
  assert.equal(reopened.claimDueRevocation('ineligible-worker', NOW + 21, NOW + 60), undefined)

  execute(path, (db) => db.prepare(
    'UPDATE principals SET lifecycle_epoch = ? WHERE id = ?',
  ).run(claimed.capturedPrincipalEpoch, claimed.principalId))
  assert.ok(reopened.claimDueRevocation('eligible-worker', NOW + 21, NOW + 60))
  execute(path, (db) => db.prepare(
    `INSERT INTO zendesk_credentials (
       principal_id, credential_version, principal_epoch, encrypted_grant_json,
       access_expires_at, refresh_expires_at, scopes, updated_at
     ) SELECT principal_id, credential_version, captured_principal_epoch,
              encrypted_grant_json, ?, retention_expires_at, ?, ?
       FROM revocation_outbox WHERE id = ?`,
  ).run(NOW + 3_600, ZENDESK_SCOPES.join(' '), NOW + 22, disconnected.outboxId))
  assert.equal(reopened.renewRevocationClaim(disconnected.outboxId, 'eligible-worker', NOW + 70), false)
})

test('reactivation cancels pending cleanup, while an active claim blocks it until release', async (t) => {
  const { path, store, client } = await fixture(t)
  const initial = login(store, client.client_id, 'initial')
  store.disconnectUser(SUBDOMAIN, USER_ID, NOW + 10)

  const reactivated = login(store, client.client_id, 'reactivated', { now: NOW + 11 })
  assert.equal(reactivated.committed.principalId, initial.committed.principalId)
  assert.equal(reactivated.committed.principalEpoch, 3)
  assert.equal(query(path, 'SELECT * FROM revocation_outbox').length, 0)

  const secondDisconnect = store.disconnectUser(SUBDOMAIN, USER_ID, NOW + 20)
  assert.equal(secondDisconnect.kind, 'disconnected')
  assert.ok(store.claimDueRevocation('worker-a', NOW + 20, NOW + 50))
  const callback = beginClaimedLogin(store, client.client_id, 'blocked', { now: NOW + 21 })
  const staged = store.stageLoginGrant({
    transactionId: callback.transactionId,
    subdomain: SUBDOMAIN,
    grant: grant('blocked', NOW + 21),
    now: NOW + 21,
  })
  assert.throws(
    () => store.commitLogin({
      transactionId: callback.transactionId,
      stageId: staged.stageId,
      zendeskUserId: USER_ID,
      now: NOW + 21,
    }),
    /invalid login commit/i,
  )
  assert.equal(store.releaseClaims('worker-a', NOW + 22), 1)
  const released = store.commitLogin({
    transactionId: callback.transactionId,
    stageId: staged.stageId,
    zendeskUserId: USER_ID,
    now: NOW + 22,
  })
  assert.equal(released.principalEpoch, 5)
  assert.equal(query(path, 'SELECT * FROM revocation_outbox').length, 0)
})

test('disconnect and claims isolate principals, and non-disconnect credential paths never create outbox rows', async (t) => {
  const { path, store, client } = await fixture(t)
  const principalA = issueFamily(store, client.client_id, 'principal-a', {
    subdomain: 'alpha',
    zendeskUserId: 'user-a',
    now: NOW,
  })
  const principalB = issueFamily(store, client.client_id, 'principal-b', {
    subdomain: 'beta',
    zendeskUserId: 'user-b',
    now: NOW + 1,
  })

  const reloginB = login(store, client.client_id, 'principal-b-relogin', {
    subdomain: 'beta',
    zendeskUserId: 'user-b',
    now: NOW + 2,
  })
  const discardedCallback = beginClaimedLogin(store, client.client_id, 'discarded', {
    subdomain: 'beta',
    now: NOW + 3,
  })
  const discarded = store.stageLoginGrant({
    transactionId: discardedCallback.transactionId,
    subdomain: 'beta',
    grant: grant('discarded', NOW + 3),
    now: NOW + 3,
  })
  assert.equal(store.discardStagedGrant(discarded.stageId, NOW + 3), true)
  assert.equal(query(path, 'SELECT * FROM revocation_outbox').length, 0)

  const disconnectedA = store.disconnectUser('alpha', 'user-a', NOW + 10)
  assert.equal(disconnectedA.principalId, principalA.committed.principalId)
  assert.deepEqual(
    query(path, 'SELECT subdomain, status, lifecycle_epoch FROM principals ORDER BY subdomain'),
    [
      { subdomain: 'alpha', status: 'disconnected', lifecycle_epoch: 2 },
      { subdomain: 'beta', status: 'active', lifecycle_epoch: 1 },
    ],
  )
  assert.equal(store.lookupAccessToken(principalA.tokens.access_token, NOW + 10), undefined)
  assert.ok(store.lookupAccessToken(principalB.tokens.access_token, NOW + 10))
  assert.equal(query(path, 'SELECT credential_version FROM zendesk_credentials WHERE principal_id = ?', principalB.committed.principalId)[0].credential_version, 2)
  assert.equal(reloginB.committed.principalId, principalB.committed.principalId)
  const claim = store.claimDueRevocation('isolated-worker', NOW + 10, NOW + 40)
  assert.equal(claim.principalId, principalA.committed.principalId)
  assert.equal(query(path, 'SELECT COUNT(*) AS count FROM revocation_outbox')[0].count, 1)
})

test('disconnect and lease APIs reject invalid identifiers, times, leases, and owners without mutation', async (t) => {
  const { path, store, client } = await fixture(t)
  login(store, client.client_id, 'validation')
  for (const [subdomain, userId, now] of [
    ['', USER_ID, NOW],
    ['Bad.Domain', USER_ID, NOW],
    [SUBDOMAIN, '', NOW],
    [SUBDOMAIN, USER_ID, -1],
    [SUBDOMAIN, USER_ID, 1.5],
  ]) {
    assert.deepEqual(store.disconnectUser(subdomain, userId, now), { kind: 'not_found' })
  }
  assert.equal(query(path, 'SELECT status FROM principals')[0].status, 'active')
  const disconnected = store.disconnectUser(SUBDOMAIN, USER_ID, NOW + 10)
  assert.equal(disconnected.kind, 'disconnected')

  for (const [owner, now, lease] of [
    ['', NOW + 10, NOW + 20],
    ['bad\nowner', NOW + 10, NOW + 20],
    ['x'.repeat(201), NOW + 10, NOW + 20],
    ['worker', -1, NOW + 20],
    ['worker', NOW + 10, NOW + 10],
    ['worker', NOW + 10, Number.MAX_SAFE_INTEGER + 1],
  ]) {
    assert.equal(store.claimDueRevocation(owner, now, lease), undefined)
  }
  assert.equal(query(path, 'SELECT status FROM revocation_outbox')[0].status, 'pending')
  assert.equal(store.releaseClaims('', NOW + 10), 0)
  assert.equal(store.releaseClaims('worker', -1), 0)
  assert.equal(store.completeRevocation(disconnected.outboxId, '', NOW + 10), false)
  assert.equal(store.rescheduleRevocation(disconnected.outboxId, '', 'transport', NOW + 20), false)
})
