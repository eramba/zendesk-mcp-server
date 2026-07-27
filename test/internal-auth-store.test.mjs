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
  const clock = { value: NOW }
  const store = InternalAuthStore.open({
    path,
    cipher: new SecretCipher(key),
    subdomain: 'acme',
    clientId: 'internal-mcp',
    now: () => clock.value,
  })
  t.after(() => store.close())
  return { clock, directory, path, store }
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

function grant(label, accessExpiresAt = NOW + 1_800) {
  return {
    accessToken: `access-${label}-sentinel`,
    refreshToken: `refresh-${label}-sentinel`,
    accessExpiresAt,
    refreshExpiresAt: NOW + 30 * 24 * 60 * 60,
    scopes: ['read', 'tickets:write'],
  }
}

function claimInvitation(store, created, state = randomOpaque()) {
  const started = store.startInvitation(created.invitation, state)
  assert.ok(started)
  const claimed = store.claimAuthorization(state)
  assert.ok(claimed)
  assert.equal(claimed.kind, 'invitation')
  return claimed
}

function activate(store, created, identityId, label = identityId) {
  const claimed = claimInvitation(store, created)
  return store.completeLink({
    ...claimed,
    identity: {
      id: identityId,
      name: `Agent ${label}`,
      email: `${label}@example.test`,
      role: 'agent',
    },
    grant: grant(label),
  })
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
    'oauth_self_enrollments',
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

test('invitation start and callback claim are expiry-bound and one-time', async (t) => {
  const { clock, path, store } = await fixture(t)
  const created = store.createPendingUser('Martin')
  const state = randomOpaque()

  assert.equal(store.startInvitation('unknown-invitation', state), undefined)
  const started = store.startInvitation(created.invitation, state)
  assert.deepEqual(started, {
    invitationId: assert.match(started.invitationId, /^[0-9a-f-]{36}$/) ?? started.invitationId,
    userId: created.userId,
    expiresAt: NOW + 30 * 60,
  })
  assert.equal(store.startInvitation(created.invitation, randomOpaque()), undefined)
  assert.equal(store.claimAuthorization(randomOpaque()), undefined)

  const claimed = store.claimAuthorization(state)
  assert.deepEqual(claimed, {
    kind: 'invitation',
    invitationId: started.invitationId,
    userId: created.userId,
  })
  assert.equal(store.claimAuthorization(state), undefined)

  for (const file of await databaseFiles(path)) {
    const bytes = await readFile(file)
    assert.equal(bytes.includes(Buffer.from(created.invitation)), false)
    assert.equal(bytes.includes(Buffer.from(state)), false)
  }

  const expired = store.createPendingUser('Expired')
  clock.value = expired.expiresAt
  assert.equal(
    store.startInvitation(expired.invitation, randomOpaque()),
    undefined,
  )
})

test('self-enrollment authorization states are hash-only expiry-bound and one-time', async (t) => {
  const { clock, path, store } = await fixture(t)
  const created = []

  for (let index = 0; index < 100; index += 1) {
    created.push(store.createSelfEnrollment())
  }

  assert.equal(new Set(created.map(({ state }) => state)).size, 100)
  for (const enrollment of created) {
    assert.match(enrollment.state, /^[A-Za-z0-9_-]{43}$/)
    assert.equal(enrollment.expiresAt, NOW + 10 * 60)
  }

  const claimed = store.claimAuthorization(created[0].state)
  assert.deepEqual(claimed, {
    kind: 'self_enrollment',
    enrollmentId:
      assert.match(claimed.enrollmentId, /^[0-9a-f-]{36}$/) ??
      claimed.enrollmentId,
  })
  assert.equal(store.claimAuthorization(created[0].state), undefined)

  clock.value = created[1].expiresAt
  assert.equal(store.claimAuthorization(created[1].state), undefined)

  for (const file of await databaseFiles(path)) {
    const bytes = await readFile(file)
    for (const { state } of created) {
      assert.equal(bytes.includes(Buffer.from(state)), false)
    }
  }
})

test('authorization state claim has exactly one winner across store connections', async (t) => {
  const { path, store } = await fixture(t)
  const enrollment = store.createSelfEnrollment()
  const observer = InternalAuthStore.open({
    path,
    cipher: new SecretCipher(KEY),
    subdomain: 'acme',
    clientId: 'internal-mcp',
    now: () => NOW,
  })
  t.after(() => observer.close())

  const results = [
    store.claimAuthorization(enrollment.state),
    observer.claimAuthorization(enrollment.state),
  ]
  assert.equal(results.filter(Boolean).length, 1)
  assert.equal(results.find(Boolean).kind, 'self_enrollment')
})

test('self-enrollment atomically creates one hash-only bearer for one eligible identity', async (t) => {
  const { path, store } = await fixture(t)
  const enrollment = store.createSelfEnrollment()
  const claimed = store.claimAuthorization(enrollment.state)
  assert.equal(claimed.kind, 'self_enrollment')

  const created = store.completeSelfEnrollment({
    enrollmentId: claimed.enrollmentId,
    identity: {
      id: '4242',
      name: 'Authoritative Agent',
      email: 'agent@example.test',
      role: 'agent',
    },
    grant: grant('self-service'),
  })
  assert.equal(created.kind, 'created')
  assert.match(created.userId, /^[0-9a-f-]{36}$/)
  assert.match(created.bearer, /^zmcp_[A-Za-z0-9_-]{43}$/)
  assert.deepEqual(store.authenticateBearer(created.bearer), {
    userId: created.userId,
  })
  assert.throws(
    () =>
      store.completeSelfEnrollment({
        enrollmentId: claimed.enrollmentId,
        identity: {
          id: '4243',
          name: 'Replay Agent',
          email: 'replay@example.test',
          role: 'agent',
        },
        grant: grant('replay'),
      }),
    /Unable to complete self-service enrollment/,
  )
  assert.equal(store.inspectUsers().length, 1)
  assert.deepEqual(store.inspectUsers()[0], {
    id: created.userId,
    label: 'Authoritative Agent',
    status: 'active',
    zendeskUserId: '4242',
    zendeskName: 'Authoritative Agent',
    zendeskEmail: 'agent@example.test',
    createdAt: NOW,
    updatedAt: NOW,
    revokedAt: null,
    invitationStatus: 'none',
    invitationExpiresAt: null,
  })

  const duplicateEnrollment = store.createSelfEnrollment()
  const duplicateClaim = store.claimAuthorization(duplicateEnrollment.state)
  assert.deepEqual(
    store.completeSelfEnrollment({
      enrollmentId: duplicateClaim.enrollmentId,
      identity: {
        id: '4242',
        name: 'Renamed Agent',
        email: 'renamed@example.test',
        role: 'admin',
      },
      grant: grant('duplicate'),
    }),
    { kind: 'already_registered' },
  )
  assert.equal(store.inspectUsers().length, 1)

  for (const file of await databaseFiles(path)) {
    const bytes = await readFile(file)
    for (const secret of [
      created.bearer,
      grant('self-service').accessToken,
      grant('self-service').refreshToken,
      grant('duplicate').accessToken,
      grant('duplicate').refreshToken,
    ]) {
      assert.equal(bytes.includes(Buffer.from(secret)), false)
    }
  }
})

test('self-enrollment rejects ineligible or invalid activation without a partial user', async (t) => {
  const { store } = await fixture(t)

  for (const [role, userGrant] of [
    ['end-user', grant('end-user')],
    ['agent', grant('expired', NOW - 1)],
  ]) {
    const enrollment = store.createSelfEnrollment()
    const claimed = store.claimAuthorization(enrollment.state)
    assert.throws(
      () =>
        store.completeSelfEnrollment({
          enrollmentId: claimed.enrollmentId,
          identity: {
            id: role === 'end-user' ? '5001' : '5002',
            name: 'Rejected identity',
            email: 'rejected@example.test',
            role,
          },
          grant: userGrant,
        }),
      /Unable to complete self-service enrollment/,
    )
  }

  assert.deepEqual(store.inspectUsers(), [])
})

test('callback completion activates only the claimed mapping from authoritative identity', async (t) => {
  const { path, store } = await fixture(t)
  const martin = store.createPendingUser('Administrator label')
  const adrian = store.createPendingUser('Adrian')
  const installed = activate(store, martin, '101', 'martin')

  assert.deepEqual(installed, {
    userId: martin.userId,
    zendeskUserId: '101',
    version: 1,
    grant: grant('martin'),
  })
  assert.deepEqual(store.authenticateBearer(martin.bearer), {
    userId: martin.userId,
  })
  assert.equal(store.authenticateBearer(adrian.bearer), undefined)
  assert.deepEqual(store.loadCredential(martin.userId), installed)

  const metadata = store.inspectUsers().find(({ id }) => id === martin.userId)
  assert.equal(metadata.label, 'Administrator label')
  assert.equal(metadata.zendeskUserId, '101')
  assert.equal(metadata.zendeskName, 'Agent martin')
  assert.equal(metadata.zendeskEmail, 'martin@example.test')
  assert.equal(metadata.status, 'active')

  for (const file of await databaseFiles(path)) {
    const bytes = await readFile(file)
    assert.equal(bytes.includes(Buffer.from(grant('martin').accessToken)), false)
    assert.equal(bytes.includes(Buffer.from(grant('martin').refreshToken)), false)
  }
})

test('callback mismatch and duplicate identity do not activate another mapping', async (t) => {
  const { store } = await fixture(t)
  const first = store.createPendingUser('First')
  const second = store.createPendingUser('Second')
  activate(store, first, '202', 'first')

  const secondClaim = claimInvitation(store, second)
  assert.throws(
    () =>
      store.completeLink({
        ...secondClaim,
        userId: first.userId,
        identity: { id: '303', name: null, email: null, role: 'agent' },
        grant: grant('mismatch'),
      }),
    /Unable to activate linked user/,
  )
  assert.equal(store.authenticateBearer(second.bearer), undefined)

  assert.throws(
    () =>
      store.completeLink({
        ...secondClaim,
        identity: {
          id: '202',
          name: 'Duplicate',
          email: null,
          role: 'agent',
        },
        grant: grant('duplicate'),
      }),
    /Unable to activate linked user/,
  )
  assert.equal(store.authenticateBearer(second.bearer), undefined)
  assert.equal(store.loadCredential(second.userId), undefined)
  assert.equal(
    store.inspectUsers().find(({ id }) => id === second.userId).status,
    'pending',
  )
})

test('malformed encrypted grants fail closed without exposing ciphertext', async (t) => {
  const { path, store } = await fixture(t)
  const created = store.createPendingUser('Martin')
  activate(store, created, '404', 'malformed')
  store.close()

  const Database = (await import('better-sqlite3')).default
  const database = new Database(path)
  database
    .prepare('UPDATE oauth_grants SET encrypted_grant = ? WHERE user_id = ?')
    .run('malformed-grant-sentinel', created.userId)
  database.close()

  const reopened = InternalAuthStore.open({
    path,
    cipher: new SecretCipher(KEY),
    subdomain: 'acme',
    clientId: 'internal-mcp',
    now: () => NOW,
  })
  t.after(() => reopened.close())
  assert.throws(() => reopened.loadCredential(created.userId), (error) => {
    assert.match(error.message, /Unable to load OAuth credential/)
    assert.equal(error.message.includes('malformed-grant-sentinel'), false)
    return true
  })
})

test('conditional refresh persists a rotated grant and stale writers adopt it', async (t) => {
  const { path, store } = await fixture(t)
  const created = store.createPendingUser('Martin')
  const initial = activate(store, created, '505', 'initial')
  const rotated = grant('rotated', NOW + 3_600)

  const installed = store.installRefreshedGrant({
    userId: created.userId,
    expectedVersion: initial.version,
    grant: rotated,
  })
  assert.deepEqual(installed, {
    kind: 'installed',
    snapshot: {
      userId: created.userId,
      zendeskUserId: '505',
      version: 2,
      grant: rotated,
    },
  })

  const observer = InternalAuthStore.open({
    path,
    cipher: new SecretCipher(KEY),
    subdomain: 'acme',
    clientId: 'internal-mcp',
    now: () => NOW,
  })
  assert.deepEqual(observer.loadCredential(created.userId), installed.snapshot)
  observer.close()

  assert.deepEqual(
    store.installRefreshedGrant({
      userId: created.userId,
      expectedVersion: 1,
      grant: grant('stale'),
    }),
    { kind: 'newer', snapshot: installed.snapshot },
  )
})

test('terminal reauthorization disables only the current grant and issues no bearer', async (t) => {
  const { store } = await fixture(t)
  const first = store.createPendingUser('First')
  const second = store.createPendingUser('Second')
  const firstSnapshot = activate(store, first, '601', 'first')
  activate(store, second, '602', 'second')

  assert.equal(
    store.markReauthorizationRequired(first.userId, firstSnapshot.version + 1),
    false,
  )
  assert.equal(
    store.markReauthorizationRequired(first.userId, firstSnapshot.version),
    true,
  )
  assert.equal(store.authenticateBearer(first.bearer), undefined)
  assert.equal(store.loadCredential(first.userId), undefined)
  assert.deepEqual(store.authenticateBearer(second.bearer), {
    userId: second.userId,
  })

  const reauthorization = store.createReauthorization(first.userId)
  assert.deepEqual(Object.keys(reauthorization).sort(), [
    'expiresAt',
    'invitation',
  ])
  assert.match(reauthorization.invitation, /^[A-Za-z0-9_-]{43}$/)
  assert.equal(reauthorization.expiresAt, NOW + 30 * 60)
  assert.equal(
    store.inspectUsers().find(({ id }) => id === first.userId).status,
    'reauthorization_required',
  )
})

test('revocation blocks access atomically and returns a bounded in-memory grant', async (t) => {
  const { store } = await fixture(t)
  const created = store.createPendingUser('Martin')
  const snapshot = activate(store, created, '701', 'revoke')

  assert.deepEqual(store.revokeUser(created.userId), {
    kind: 'revoked',
    capturedGrant: snapshot.grant,
  })
  assert.equal(store.authenticateBearer(created.bearer), undefined)
  assert.equal(store.loadCredential(created.userId), undefined)
  assert.equal(
    store.inspectUsers().find(({ id }) => id === created.userId).status,
    'revoked',
  )
  assert.deepEqual(store.revokeUser(created.userId), {
    kind: 'already_revoked',
  })
  assert.deepEqual(store.revokeUser('00000000-0000-0000-0000-000000000000'), {
    kind: 'not_found',
  })
  assert.throws(
    () => store.createReauthorization(created.userId),
    /Unable to create reauthorization invitation/,
  )
})

test('reauthorization replaces expired invitations without a worker', async (t) => {
  const { clock, path, store } = await fixture(t)
  const created = store.createPendingUser('Martin')
  clock.value = created.expiresAt
  const replacement = store.createReauthorization(created.userId)

  assert.notEqual(replacement.invitation, created.invitation)
  const Database = (await import('better-sqlite3')).default
  const database = new Database(path, { readonly: true })
  const count = database
    .prepare('SELECT COUNT(*) AS count FROM oauth_invitations WHERE user_id = ?')
    .get(created.userId).count
  database.close()
  assert.equal(count, 1)
})

test('online backup is consistent, mode-0600, and bound to the encryption key', async (t) => {
  const { directory, store } = await fixture(t)
  const created = store.createPendingUser('Martin')
  activate(store, created, '801', 'backup')
  const destination = join(directory, 'backup.sqlite')

  await store.backup(destination)
  assert.equal((await stat(destination)).mode & 0o777, 0o600)

  const backup = InternalAuthStore.open({
    path: destination,
    cipher: new SecretCipher(KEY),
    subdomain: 'acme',
    clientId: 'internal-mcp',
    now: () => NOW,
  })
  assert.deepEqual(backup.authenticateBearer(created.bearer), {
    userId: created.userId,
  })
  backup.close()

  assert.throws(
    () =>
      InternalAuthStore.open({
        path: destination,
        cipher: new SecretCipher(Buffer.alloc(32, 9)),
        subdomain: 'acme',
        clientId: 'internal-mcp',
        now: () => NOW,
      }),
    /Unable to open OAuth credential store/,
  )
})
