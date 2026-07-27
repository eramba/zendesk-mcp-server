import assert from 'node:assert/strict'
import { access, chmod, mkdtemp, readFile, stat } from 'node:fs/promises'
import { constants } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import {
  SecretCipher,
  hashOpaque,
  randomOpaque,
} from '../dist/internal-auth/crypto.js'
import { InternalAuthStore } from '../dist/internal-auth/store.js'

const NOW = 1_700_000_000
const KEY = Buffer.alloc(32, 7)

async function fixture(t, key = KEY) {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-internal-auth-'))
  const path = join(directory, 'oauth.sqlite')
  const store = InternalAuthStore.open({
    path,
    cipher: new SecretCipher(key),
    subdomain: 'acme',
    clientId: 'internal-mcp',
    now: () => NOW,
  })
  t.after(() => store.close())
  return { directory, path, store }
}

async function databaseFiles(path) {
  const candidates = [path, `${path}-wal`, `${path}-shm`]
  const existing = []
  for (const candidate of candidates) {
    try {
      await access(candidate, constants.F_OK)
      existing.push(candidate)
    } catch {
      // The WAL and SHM files are optional after a checkpoint.
    }
  }
  return existing
}

test('SecretCipher round trips with associated data and rejects unsafe envelopes', () => {
  const cipher = new SecretCipher(KEY)
  const plaintext = 'access-token-sentinel'
  const envelope = cipher.encrypt(plaintext, 'grant:user-1:1')

  assert.equal(envelope.includes(plaintext), false)
  assert.equal(cipher.decrypt(envelope, 'grant:user-1:1'), plaintext)
  assert.throws(
    () => cipher.decrypt(envelope, 'grant:user-2:1'),
    /Unable to decrypt stored credential/,
  )
  assert.throws(
    () => new SecretCipher(Buffer.alloc(31)),
    /exactly 32 bytes/,
  )

  for (const malformed of [
    'not-json',
    '{}',
    JSON.stringify({ version: 2, nonce: '', ciphertext: '', tag: '' }),
    JSON.stringify({ version: 1, nonce: '*', ciphertext: '', tag: '' }),
    JSON.stringify({
      version: 1,
      nonce: Buffer.alloc(11).toString('base64url'),
      ciphertext: '',
      tag: Buffer.alloc(16).toString('base64url'),
    }),
    JSON.stringify({
      version: 1,
      nonce: Buffer.alloc(12).toString('base64url'),
      ciphertext: '',
      tag: Buffer.alloc(15).toString('base64url'),
    }),
  ]) {
    assert.throws(
      () => cipher.decrypt(malformed, 'grant:user-1:1'),
      /Unable to decrypt stored credential/,
    )
  }
})

test('opaque values use strong random base64url and stable SHA-256 lookup', () => {
  const values = new Set()
  for (let index = 0; index < 100; index += 1) {
    const value = randomOpaque(index % 2 === 0 ? 'zmcp_' : '')
    assert.match(
      value,
      index % 2 === 0
        ? /^zmcp_[A-Za-z0-9_-]{43}$/
        : /^[A-Za-z0-9_-]{43}$/,
    )
    values.add(value)
  }
  assert.equal(values.size, 100)
  assert.equal(
    hashOpaque('lookup-sentinel'),
    '64eIpleECB1hEmnV6FcIYYHGu9OhS7epXPrazXH_pdM',
  )
})

test('creates only the focused schema and a mode-0600 database', async (t) => {
  const { path, store } = await fixture(t)
  const Database = (await import('better-sqlite3')).default
  const database = new Database(path, { readonly: true })
  t.after(() => database.close())

  const tables = database
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .all()
    .map(({ name }) => name)

  assert.deepEqual(tables, [
    'internal_users',
    'oauth_grants',
    'oauth_invitations',
    'store_metadata',
  ])
  assert.equal(database.pragma('journal_mode', { simple: true }), 'wal')

  const mode = (await stat(path)).mode & 0o777
  assert.equal(mode, 0o600)
  assert.deepEqual(store.inspectUsers(), [])
})

test('creates unique pending users without persisting bearer or invitation plaintext', async (t) => {
  const { path, store } = await fixture(t)
  const created = []

  for (let index = 0; index < 100; index += 1) {
    created.push(store.createPendingUser(`User ${index}`))
  }

  assert.equal(new Set(created.map(({ userId }) => userId)).size, 100)
  assert.equal(new Set(created.map(({ bearer }) => bearer)).size, 100)
  assert.equal(new Set(created.map(({ invitation }) => invitation)).size, 100)

  for (const user of created) {
    assert.match(user.userId, /^[0-9a-f-]{36}$/)
    assert.match(user.bearer, /^zmcp_[A-Za-z0-9_-]{43}$/)
    assert.match(user.invitation, /^[A-Za-z0-9_-]{43}$/)
    assert.equal(user.expiresAt, NOW + 30 * 60)
    assert.equal(store.authenticateBearer(user.bearer), undefined)
  }
  assert.equal(store.authenticateBearer('zmcp_unknown'), undefined)
  assert.equal(store.authenticateBearer(''), undefined)

  for (const file of await databaseFiles(path)) {
    const bytes = await readFile(file)
    for (const { bearer, invitation } of created) {
      assert.equal(bytes.includes(Buffer.from(bearer)), false)
      assert.equal(bytes.includes(Buffer.from(invitation)), false)
    }
  }

  const users = store.inspectUsers()
  assert.equal(users.length, 100)
  assert.deepEqual(users.find(({ label }) => label === 'User 0'), {
    id: created[0].userId,
    label: 'User 0',
    status: 'pending',
    zendeskUserId: null,
    zendeskName: null,
    zendeskEmail: null,
    createdAt: NOW,
    updatedAt: NOW,
    revokedAt: null,
    invitationStatus: 'pending',
    invitationExpiresAt: NOW + 30 * 60,
  })
})

test('validates labels without echoing rejected values', async (t) => {
  const { store } = await fixture(t)
  for (const label of ['', '   ', 'x'.repeat(129), 'line\nbreak']) {
    assert.throws(() => store.createPendingUser(label), (error) => {
      assert.match(error.message, /label/)
      if (label.length > 0) assert.equal(error.message.includes(label), false)
      return true
    })
  }
})

test('reopens with the same key and fails closed with a different key', async (t) => {
  const { path, store } = await fixture(t)
  const created = store.createPendingUser('Martin')
  store.close()

  const reopened = InternalAuthStore.open({
    path,
    cipher: new SecretCipher(KEY),
    subdomain: 'acme',
    clientId: 'internal-mcp',
    now: () => NOW,
  })
  assert.equal(reopened.inspectUsers()[0].id, created.userId)
  reopened.close()

  assert.throws(
    () =>
      InternalAuthStore.open({
        path,
        cipher: new SecretCipher(Buffer.alloc(32, 8)),
        subdomain: 'acme',
        clientId: 'internal-mcp',
        now: () => NOW,
      }),
    (error) => {
      assert.match(error.message, /Unable to open OAuth credential store/)
      assert.equal(error.message.includes(KEY.toString('base64url')), false)
      return true
    },
  )
})

test('malformed key-check ciphertext fails closed without exposing the value', async (t) => {
  const { path, store } = await fixture(t)
  store.close()

  const Database = (await import('better-sqlite3')).default
  const database = new Database(path)
  database
    .prepare("UPDATE store_metadata SET value = ? WHERE key = 'key_check'")
    .run('malformed-ciphertext-sentinel')
  database.close()
  await chmod(path, 0o600)

  assert.throws(
    () =>
      InternalAuthStore.open({
        path,
        cipher: new SecretCipher(KEY),
        subdomain: 'acme',
        clientId: 'internal-mcp',
        now: () => NOW,
      }),
    (error) => {
      assert.match(error.message, /Unable to open OAuth credential store/)
      assert.equal(error.message.includes('malformed-ciphertext-sentinel'), false)
      return true
    },
  )
})
