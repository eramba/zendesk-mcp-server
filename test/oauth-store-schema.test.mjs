import assert from 'node:assert/strict'
import { existsSync, statSync } from 'node:fs'
import { mkdtemp, readFile, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

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
  assert.equal(store.inspectForTest().schemaVersion, 1)
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
  assert.equal(reopened.inspectForTest().schemaVersion, 1)
  assert.equal(reopened.inspectForTest().migrationCount, 1)
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

  const Database = (await import('better-sqlite3')).default
  const db = new Database(path)
  db.prepare('UPDATE schema_migrations SET version = 999').run()
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

  const Database = (await import('better-sqlite3')).default
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
  const Database = (await import('better-sqlite3')).default
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
  const Database = (await import('better-sqlite3')).default
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
