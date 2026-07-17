import assert from 'node:assert/strict'
import { access, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import Database from 'better-sqlite3'

import { runOAuthAdmin } from '../dist/oauth/admin.js'
import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher } from '../dist/oauth/token-cipher.js'

const REDIRECT_URI = 'http://127.0.0.1:43123/callback'
const RESOURCE = 'https://dev-server.tail22145b.ts.net/mcp'
const CODE_CHALLENGE = 'C'.repeat(43)
const MCP_SCOPES = ['zendesk:read', 'zendesk:write']
const SUBDOMAIN = 'example'
const DATABASE_PATH_SENTINEL = 'DATABASE_PATH_SENTINEL'
const EMAIL_SENTINEL = 'operator-email-sentinel@example.test'
const CIPHERTEXT_SENTINEL = 'CIPHERTEXT_SENTINEL'
const VALID_CLIENT = {
  redirect_uris: [REDIRECT_URI],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  client_name: 'Codex Desktop',
  scope: MCP_SCOPES.join(' '),
}

function query(path, sql, ...parameters) {
  const db = new Database(path, { readonly: true })
  try {
    return db.prepare(sql).all(...parameters)
  } finally {
    db.close()
  }
}

function execute(path, sql, ...parameters) {
  const db = new Database(path)
  try {
    return db.prepare(sql).run(...parameters)
  } finally {
    db.close()
  }
}

function login(store, clientId, label, zendeskUserId, now) {
  const started = store.beginLogin({
    clientId,
    redirectUri: REDIRECT_URI,
    codeChallenge: CODE_CHALLENGE,
    scopes: [...MCP_SCOPES],
    resource: RESOURCE,
    originalState: `state-${label}`,
    subdomain: SUBDOMAIN,
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
  const grant = {
    accessToken: `zendesk-access-${label}-SENTINEL`,
    refreshToken: `zendesk-refresh-${label}-SENTINEL`,
    accessExpiresAt: now + 3_600,
    refreshExpiresAt: now + 86_400,
    scopes: ['read', 'tickets:write'],
  }
  const staged = store.stageLoginGrant({
    transactionId: callback.transactionId,
    subdomain: SUBDOMAIN,
    grant,
    now,
  })
  const committed = store.commitLogin({
    transactionId: callback.transactionId,
    stageId: staged.stageId,
    zendeskUserId,
    now,
  })
  return { committed, grant }
}

function issueFamily(store, clientId, label, zendeskUserId, now) {
  const loggedIn = login(store, clientId, label, zendeskUserId, now)
  const tokens = store.consumeCodeAndIssueFamily({
    clientId,
    authorizationCode: loggedIn.committed.authorizationCode,
    redirectUri: REDIRECT_URI,
    resource: RESOURCE,
    now,
    accessTokenTtlSeconds: 3_600,
  })
  return { ...loggedIn, tokens }
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), `zendesk-oauth-${DATABASE_PATH_SENTINEL}-`))
  const path = join(directory, `${DATABASE_PATH_SENTINEL}.sqlite`)
  const key = Buffer.alloc(32, 71)
  const now = Math.floor(Date.now() / 1000)
  const store = openSqliteOAuthStore({
    path,
    cipher: new TokenCipher(key),
    mcpResourceUrl: new URL(RESOURCE),
    now: () => now,
  })
  const client = store.registerClient(VALID_CLIENT)
  const first = issueFamily(store, client.client_id, 'first-raw-token', '123', now)
  const second = issueFamily(store, client.client_id, 'second-raw-token', '123', now + 1)
  const other = issueFamily(store, client.client_id, 'other-raw-token', '456', now + 2)
  store.close()

  const families = query(
    path,
    `SELECT token_families.id, principals.zendesk_user_id
     FROM token_families
     JOIN principals ON principals.id = token_families.principal_id
     ORDER BY token_families.created_at`,
  )
  const [firstFamily, secondFamily, otherFamily] = families
  const unsafeClientName = `Codex\u001b[31m${CIPHERTEXT_SENTINEL}\nClient`
  execute(path, 'UPDATE oauth_clients SET client_name = ? WHERE client_id = ?', unsafeClientName, client.client_id)

  const env = {
    ZENDESK_SUBDOMAIN: SUBDOMAIN,
    OAUTH_ENCRYPTION_KEY: key.toString('base64'),
    OAUTH_DB_PATH: path,
    ZENDESK_EMAIL: EMAIL_SENTINEL,
    ZENDESK_API_KEY: 'legacy-api-token-SENTINEL',
    ZENDESK_OAUTH_CLIENT_SECRET: 'oauth-client-secret-SENTINEL',
  }
  t.after(() => rm(directory, { recursive: true, force: true }))
  return {
    directory,
    path,
    key,
    now,
    env,
    first,
    second,
    other,
    firstFamily,
    secondFamily,
    otherFamily,
  }
}

async function invoke(argv, env, runtime) {
  const stdout = []
  const stderr = []
  const exitCode = await runOAuthAdmin(argv, env, {
    stdout: (message) => stdout.push(message),
    stderr: (message) => stderr.push(message),
  }, runtime)
  return { exitCode, stdout, stderr, output: [...stdout, ...stderr].join('\n') }
}

function assertNoSensitiveOutput(result, fixtureValue) {
  const forbidden = [
    fixtureValue.first.tokens.access_token,
    fixtureValue.first.tokens.refresh_token,
    fixtureValue.second.tokens.access_token,
    fixtureValue.second.tokens.refresh_token,
    fixtureValue.other.tokens.access_token,
    fixtureValue.other.tokens.refresh_token,
    fixtureValue.first.grant.accessToken,
    fixtureValue.first.grant.refreshToken,
    fixtureValue.second.grant.accessToken,
    fixtureValue.second.grant.refreshToken,
    fixtureValue.other.grant.accessToken,
    fixtureValue.other.grant.refreshToken,
    fixtureValue.env.OAUTH_ENCRYPTION_KEY,
    fixtureValue.env.ZENDESK_API_KEY,
    fixtureValue.env.ZENDESK_OAUTH_CLIENT_SECRET,
    EMAIL_SENTINEL,
    fixtureValue.path,
  ]
  for (const secret of forbidden) {
    assert.equal(result.output.includes(secret), false, secret)
  }
}

test('sessions prints only safe session summaries and escapes stored terminal controls', async (t) => {
  const seeded = await fixture(t)
  const result = await invoke(['sessions', '--zendesk-user-id', '123'], seeded.env)

  assert.equal(result.exitCode, 0)
  assert.equal(result.stderr.length, 0)
  assert.equal(result.stdout.length, 2)
  const sessions = result.stdout.map((line) => JSON.parse(line))
  assert.deepEqual(sessions.map((session) => session.familyId), [
    seeded.firstFamily.id,
    seeded.secondFamily.id,
  ])
  for (const session of sessions) {
    assert.deepEqual(Object.keys(session).sort(), [
      'clientName',
      'createdAt',
      'expiresAt',
      'familyId',
      'lastUsedAt',
      'redirectUri',
      'status',
    ])
    assert.equal(session.clientName, `Codex?[31m${CIPHERTEXT_SENTINEL}?Client`)
    assert.equal(session.redirectUri, REDIRECT_URI)
    assert.equal(Number.isSafeInteger(session.createdAt), true)
    assert.equal(Number.isSafeInteger(session.lastUsedAt), true)
    assert.equal(Number.isSafeInteger(session.expiresAt), true)
    assert.equal(session.status, 'active')
  }
  for (const line of result.stdout) assert.doesNotMatch(line, /[\u0000-\u001f\u007f]/)
  assertNoSensitiveOutput(result, seeded)
})

test('mutations require literal confirmation and malformed arguments exit 2 without changes', async (t) => {
  const seeded = await fixture(t)
  const before = {
    families: query(seeded.path, 'SELECT id, revoked_at FROM token_families ORDER BY id'),
    principals: query(seeded.path, 'SELECT id, status, lifecycle_epoch FROM principals ORDER BY id'),
    outbox: query(seeded.path, 'SELECT id FROM revocation_outbox'),
  }

  for (const argv of [
    ['revoke-family', '--family-id', 'family-1'],
    ['revoke-family', '--family-id', seeded.firstFamily.id, '--confirm=yes'],
    ['disconnect-user', '--zendesk-user-id', '123'],
    ['sessions'],
    ['sessions', '--zendesk-user-id', '12x'],
    ['unknown-command'],
  ]) {
    const result = await invoke(argv, seeded.env)
    assert.equal(result.exitCode, 2, argv.join(' '))
    assertNoSensitiveOutput(result, seeded)
  }

  assert.deepEqual(query(seeded.path, 'SELECT id, revoked_at FROM token_families ORDER BY id'), before.families)
  assert.deepEqual(query(seeded.path, 'SELECT id, status, lifecycle_epoch FROM principals ORDER BY id'), before.principals)
  assert.deepEqual(query(seeded.path, 'SELECT id FROM revocation_outbox'), before.outbox)
})

test('confirmed family revoke changes only the named family', async (t) => {
  const seeded = await fixture(t)
  const result = await invoke(
    ['revoke-family', '--family-id', seeded.firstFamily.id, '--confirm'],
    seeded.env,
  )

  assert.equal(result.exitCode, 0)
  const families = query(
    seeded.path,
    'SELECT id, revoked_at, revoke_reason FROM token_families ORDER BY created_at',
  )
  assert.equal(families[0].id, seeded.firstFamily.id)
  assert.equal(Number.isSafeInteger(families[0].revoked_at), true)
  assert.equal(families[0].revoke_reason, 'operator')
  assert.deepEqual(families.slice(1), [
    { id: seeded.secondFamily.id, revoked_at: null, revoke_reason: null },
    { id: seeded.otherFamily.id, revoked_at: null, revoke_reason: null },
  ])
  assert.equal(query(seeded.path, 'SELECT COUNT(*) AS count FROM zendesk_credentials')[0].count, 2)
  assert.equal(query(seeded.path, 'SELECT COUNT(*) AS count FROM revocation_outbox')[0].count, 0)
  assertNoSensitiveOutput(result, seeded)
})

test('confirmed disconnect isolates one principal and enqueues only its cleanup', async (t) => {
  const seeded = await fixture(t)
  const result = await invoke(
    ['disconnect-user', '--zendesk-user-id', '123', '--confirm'],
    seeded.env,
  )

  assert.equal(result.exitCode, 0)
  assert.deepEqual(
    query(seeded.path, 'SELECT zendesk_user_id, status, lifecycle_epoch FROM principals ORDER BY zendesk_user_id'),
    [
      { zendesk_user_id: '123', status: 'disconnected', lifecycle_epoch: 2 },
      { zendesk_user_id: '456', status: 'active', lifecycle_epoch: 1 },
    ],
  )
  assert.deepEqual(
    query(
      seeded.path,
      `SELECT principals.zendesk_user_id, token_families.revoked_at, token_families.revoke_reason
       FROM token_families JOIN principals ON principals.id = token_families.principal_id
       ORDER BY token_families.created_at`,
    ).map((row) => ({ ...row, revoked: row.revoked_at !== null, revoked_at: undefined })),
    [
      { zendesk_user_id: '123', revoke_reason: 'principal_disconnect', revoked: true, revoked_at: undefined },
      { zendesk_user_id: '123', revoke_reason: 'principal_disconnect', revoked: true, revoked_at: undefined },
      { zendesk_user_id: '456', revoke_reason: null, revoked: false, revoked_at: undefined },
    ],
  )
  assert.deepEqual(
    query(
      seeded.path,
      `SELECT principals.zendesk_user_id
       FROM revocation_outbox JOIN principals ON principals.id = revocation_outbox.principal_id`,
    ),
    [{ zendesk_user_id: '123' }],
  )
  assert.deepEqual(
    query(
      seeded.path,
      `SELECT principals.zendesk_user_id
       FROM zendesk_credentials JOIN principals ON principals.id = zendesk_credentials.principal_id`,
    ),
    [{ zendesk_user_id: '456' }],
  )
  assertNoSensitiveOutput(result, seeded)
})

test('backup is create-only, readable with the correct key, and reports no protected values', async (t) => {
  const seeded = await fixture(t)
  const destination = `/data/backups/oauth-admin-${process.pid}-${Date.now()}.sqlite`
  const backupDirectory = join(seeded.directory, 'backups')
  const physicalDestination = join(backupDirectory, destination.split('/').at(-1))
  const runtime = { backupDirectory }

  const created = await invoke(['backup', '--destination', destination], seeded.env, runtime)
  assert.equal(created.exitCode, 0)
  await access(physicalDestination)
  const bytes = await readFile(physicalDestination)
  assert.equal(bytes.includes(Buffer.from(seeded.first.grant.accessToken, 'utf8')), false)
  assert.equal(bytes.includes(Buffer.from(seeded.first.grant.refreshToken, 'utf8')), false)
  const restored = openSqliteOAuthStore({
    path: physicalDestination,
    cipher: new TokenCipher(seeded.key),
  })
  restored.close()
  assert.throws(
    () => openSqliteOAuthStore({ path: physicalDestination, cipher: new TokenCipher(Buffer.alloc(32, 72)) }),
    /encryption key/i,
  )
  assertNoSensitiveOutput(created, seeded)
  assert.equal(created.output.includes(destination), false)

  const refused = await invoke(['backup', '--destination', destination], seeded.env, runtime)
  assert.equal(refused.exitCode, 2)
  assertNoSensitiveOutput(refused, seeded)
  assert.equal(refused.output.includes(destination), false)

  for (const invalid of [
    ['backup'],
    ['backup', '--destination', 'relative.sqlite'],
    ['backup', '--destination', '/tmp/outside.sqlite'],
    ['backup', '--destination', '/data/backups/../outside.sqlite'],
  ]) {
    assert.equal((await invoke(invalid, seeded.env, runtime)).exitCode, 2)
  }
})

test('store and cipher failures exit 1 with value-free output and leave the store reopenable', async (t) => {
  const seeded = await fixture(t)
  const wrongKey = {
    ...seeded.env,
    OAUTH_ENCRYPTION_KEY: Buffer.alloc(32, 99).toString('base64'),
  }
  const failed = await invoke(['sessions', '--zendesk-user-id', '123'], wrongKey)
  assert.equal(failed.exitCode, 1)
  assertNoSensitiveOutput(failed, seeded)
  assert.equal(failed.output.includes(wrongKey.OAUTH_ENCRYPTION_KEY), false)

  const reopened = openSqliteOAuthStore({
    path: seeded.path,
    cipher: new TokenCipher(seeded.key),
  })
  reopened.close()
})
