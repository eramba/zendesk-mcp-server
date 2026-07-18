import assert from 'node:assert/strict'
import { existsSync, statSync } from 'node:fs'
import { mkdtemp, readFile, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import Database from 'better-sqlite3'

import { SQLITE_MIGRATIONS } from '../dist/oauth/sqlite-schema.js'
import { openSqliteOAuthStore } from '../dist/oauth/sqlite-store.js'
import { TokenCipher } from '../dist/oauth/token-cipher.js'

async function fixture(t, key = Buffer.alloc(32, 4)) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-store-'))
  const path = join(directory, 'oauth.sqlite')
  const store = openSqliteOAuthStore({ path, cipher: new TokenCipher(key), now: () => 1_700_000_000 })
  t.after(() => store.close())
  return { directory, path, store }
}

test('new store migrates once with durable SQLite pragmas and restrictive modes', async (t) => {
  const { directory, path, store } = await fixture(t)
  assert.equal(store.isReady(), true)
  assert.deepEqual(store.inspectForTest().pragmas, {
    foreignKeys: 1,
    journalMode: 'wal',
    synchronous: 2,
    trustedSchema: 0,
    secureDelete: 1,
  })
  assert.equal(store.inspectForTest().schemaVersion, 2)
  assert.equal((await stat(directory)).mode & 0o777, 0o700)
  assert.equal((await stat(path)).mode & 0o777, 0o600)
})

test('migration and key check are idempotent across restart', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-reopen-'))
  const path = join(directory, 'oauth.sqlite')
  const key = Buffer.alloc(32, 5)
  openSqliteOAuthStore({ path, cipher: new TokenCipher(key) }).close()
  const reopened = openSqliteOAuthStore({ path, cipher: new TokenCipher(key) })
  t.after(() => reopened.close())
  assert.equal(reopened.inspectForTest().schemaVersion, 2)
  assert.equal(reopened.inspectForTest().migrationCount, 2)
})

test('version 2 migration backfills only unambiguous legacy family redirects', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-v1-migration-'))
  const path = join(directory, 'oauth.sqlite')
  const key = Buffer.alloc(32, 16)
  const cipher = new TokenCipher(key)
  const db = new Database(path)
  db.exec(SQLITE_MIGRATIONS[0].sql)
  db.prepare('INSERT INTO store_metadata (key, value) VALUES (?, ?)').run(
    'encryption_key_check',
    JSON.stringify(cipher.encrypt('oauth-key-check-sentinel', {
      kind: 'key_check',
      rowId: 'store-key-check',
      expiresAt: 253402300799,
    })),
  )
  db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)').run(1_700_000_000)
  const insertClient = db.prepare(`
    INSERT INTO oauth_clients (
      client_id, client_id_issued_at, token_endpoint_auth_method,
      grant_types_json, response_types_json, scope, client_name,
      metadata_json, created_at
    ) VALUES (?, ?, 'none', '["authorization_code","refresh_token"]', '["code"]',
              'zendesk:read zendesk:write', ?, '{}', ?)
  `)
  const insertRedirect = db.prepare(
    'INSERT INTO oauth_client_redirect_uris (client_id, redirect_uri) VALUES (?, ?)',
  )
  const insertPrincipal = db.prepare(`
    INSERT INTO principals (
      id, subdomain, zendesk_user_id, status, lifecycle_epoch,
      disconnected_at, created_at, updated_at
    ) VALUES (?, 'example', ?, 'active', 1, NULL, ?, ?)
  `)
  const insertFamily = db.prepare(`
    INSERT INTO token_families (
      id, client_id, principal_id, principal_epoch, scopes, resource,
      created_at, last_used_at, revoked_at, revoke_reason
    ) VALUES (?, ?, ?, 1, 'zendesk:read zendesk:write',
              'https://example.test/mcp', ?, ?, NULL, NULL)
  `)
  const insertRefresh = db.prepare(`
    INSERT INTO refresh_token_generations (
      token_hash, family_id, generation, status, created_at, expires_at,
      consumed_at, successor_generation, encrypted_retry_response_json,
      retry_response_expires_at
    ) VALUES (?, ?, 1, 'current', ?, ?, NULL, NULL, NULL, NULL)
  `)

  insertClient.run('single-client', 1_700_000_000, 'Single redirect', 1_700_000_000)
  insertRedirect.run('single-client', 'http://127.0.0.1:43123/callback')
  insertPrincipal.run('single-principal', '101', 1_700_000_000, 1_700_000_000)
  insertFamily.run('A'.repeat(43), 'single-client', 'single-principal', 1_700_000_000, 1_700_000_000)
  insertRefresh.run('single-refresh-hash', 'A'.repeat(43), 1_700_000_000, 1_800_000_000)

  insertClient.run('multi-client', 1_700_000_001, 'Multiple redirects', 1_700_000_001)
  insertRedirect.run('multi-client', 'http://127.0.0.1:43122/a')
  insertRedirect.run('multi-client', 'http://127.0.0.1:43123/callback')
  insertPrincipal.run('multi-principal', '202', 1_700_000_001, 1_700_000_001)
  insertFamily.run('B'.repeat(43), 'multi-client', 'multi-principal', 1_700_000_001, 1_700_000_001)
  insertRefresh.run('multi-refresh-hash', 'B'.repeat(43), 1_700_000_001, 1_800_000_001)
  db.close()

  const store = openSqliteOAuthStore({ path, cipher, now: () => 1_700_000_010 })
  t.after(() => store.close())
  assert.equal(store.inspectForTest().schemaVersion, 2)
  assert.equal(store.inspectForTest().migrationCount, 2)
  assert.equal(
    store.listSessions('example', '101', 1_700_000_010)[0].redirectUri,
    'http://127.0.0.1:43123/callback',
  )
  assert.throws(
    () => store.listSessions('example', '202', 1_700_000_010),
    /session redirect is unavailable/i,
  )
})

test('wrong restore key and unknown newer schema fail closed', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-key-'))
  const path = join(directory, 'oauth.sqlite')
  const first = openSqliteOAuthStore({ path, cipher: new TokenCipher(Buffer.alloc(32, 6)) })
  first.close()
  assert.throws(
    () => openSqliteOAuthStore({ path, cipher: new TokenCipher(Buffer.alloc(32, 7)) }),
    /encryption key/i,
  )

  const db = new Database(path)
  db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (999, ?)').run(1_700_000_001)
  db.close()
  assert.throws(
    () => openSqliteOAuthStore({ path, cipher: new TokenCipher(Buffer.alloc(32, 6)) }),
    /newer schema version/i,
  )
})

test('an initialized store with a missing key check fails closed for every key', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-missing-key-check-'))
  const path = join(directory, 'oauth.sqlite')
  const originalKey = Buffer.alloc(32, 11)
  openSqliteOAuthStore({ path, cipher: new TokenCipher(originalKey) }).close()

  const db = new Database(path)
  db.prepare("DELETE FROM store_metadata WHERE key = 'encryption_key_check'").run()
  db.close()

  for (const key of [originalKey, Buffer.alloc(32, 12)]) {
    assert.throws(() => {
      const reopened = openSqliteOAuthStore({ path, cipher: new TokenCipher(key) })
      reopened.close()
    }, /encryption key/i)
  }
})

test('store fails closed when an effective security pragma does not match', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-oauth-pragma-mismatch-'))
  const path = join(directory, 'oauth.sqlite')
  const originalPragma = Database.prototype.pragma
  Database.prototype.pragma = function (source, options) {
    if (source === 'trusted_schema = OFF') return []
    return originalPragma.call(this, source, options)
  }
  try {
    assert.throws(() => {
      const opened = openSqliteOAuthStore({ path, cipher: new TokenCipher(Buffer.alloc(32, 13)) })
      opened.close()
    }, /failed to initialize/i)
  } finally {
    Database.prototype.pragma = originalPragma
  }
})

test('backup is consistent and still requires the separate encryption key', async (t) => {
  const { directory, store } = await fixture(t, Buffer.alloc(32, 8))
  const backup = join(directory, 'backup.sqlite')
  await store.backup(backup)
  const bytes = await readFile(backup)
  assert.doesNotMatch(bytes.toString('utf8'), /oauth-key-check-sentinel/)

  const restored = openSqliteOAuthStore({
    path: backup,
    cipher: new TokenCipher(Buffer.alloc(32, 8)),
  })
  restored.close()
  assert.throws(
    () => openSqliteOAuthStore({ path: backup, cipher: new TokenCipher(Buffer.alloc(32, 9)) }),
    /encryption key/i,
  )
})

test('backup destination is mode 0600 before and after SQLite writes', async (t) => {
  const { directory, store } = await fixture(t, Buffer.alloc(32, 14))
  const backup = join(directory, 'permission-safe-backup.sqlite')
  const previousUmask = process.umask(0)
  const backupPromise = store.backup(backup)
  let modeWhileBackupRuns = null
  try {
    modeWhileBackupRuns = existsSync(backup) ? statSync(backup).mode & 0o777 : null
  } finally {
    process.umask(previousUmask)
    await backupPromise
  }
  assert.equal(modeWhileBackupRuns, 0o600)
  assert.equal((await stat(backup)).mode & 0o777, 0o600)
})

test('failed backup removes its pre-created private destination', async (t) => {
  const { directory, store } = await fixture(t, Buffer.alloc(32, 15))
  const backup = join(directory, 'failed-backup.sqlite')
  const originalBackup = Database.prototype.backup
  Database.prototype.backup = async function (destination) {
    assert.equal(existsSync(destination) ? statSync(destination).mode & 0o777 : null, 0o600)
    throw new Error('simulated backup failure')
  }
  try {
    await assert.rejects(store.backup(backup), /simulated backup failure/)
  } finally {
    Database.prototype.backup = originalBackup
  }
  assert.equal(existsSync(backup), false)
})
