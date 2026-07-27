import assert from 'node:assert/strict'
import { mkdtemp, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { runAdmin } from '../dist/admin.js'
import { SecretCipher, randomOpaque } from '../dist/internal-auth/crypto.js'
import { InternalAuthStore } from '../dist/internal-auth/store.js'

const NOW = Math.floor(Date.now() / 1_000)
const KEY = Buffer.alloc(32, 29)

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'zendesk-admin-'))
  const env = {
    HOST: '127.0.0.1',
    PORT: '3000',
    MCP_ALLOWED_HOSTS: '127.0.0.1',
    PUBLIC_BASE_URL: 'http://127.0.0.1:3000',
    ZENDESK_SUBDOMAIN: 'acme',
    ZENDESK_OAUTH_CLIENT_ID: 'internal-mcp',
    ZENDESK_OAUTH_CLIENT_SECRET: 'client-secret-sentinel',
    OAUTH_ENCRYPTION_KEY: KEY.toString('base64url'),
    OAUTH_DB_PATH: join(directory, 'oauth.sqlite'),
  }
  return { directory, env }
}

async function command(env, argv, dependencies = {}) {
  const stdout = []
  const stderr = []
  const code = await runAdmin(argv, {
    env,
    stdout: (line) => stdout.push(line),
    stderr: (line) => stderr.push(line),
    ...dependencies,
  })
  return { code, stdout, stderr }
}

function field(lines, name) {
  const line = lines.find((candidate) => candidate.startsWith(`${name}: `))
  assert.ok(line, `missing ${name}`)
  return line.slice(name.length + 2)
}

function openStore(env) {
  return InternalAuthStore.open({
    path: env.OAUTH_DB_PATH,
    cipher: new SecretCipher(KEY),
    subdomain: 'acme',
    clientId: 'internal-mcp',
  })
}

test('create prints one-time bearer/link while list returns metadata only', async () => {
  const { env } = await fixture()
  const created = await command(env, ['create', '--label', 'Martin'])
  assert.equal(created.code, 0)
  assert.deepEqual(created.stderr, [])
  const userId = field(created.stdout, 'user_id')
  const bearer = field(created.stdout, 'mcp_bearer')
  const link = new URL(field(created.stdout, 'link_url'))
  assert.match(userId, /^[0-9a-f-]{36}$/)
  assert.match(bearer, /^zmcp_[A-Za-z0-9_-]{43}$/)
  assert.match(link.searchParams.get('invitation'), /^[A-Za-z0-9_-]{43}$/)
  assert.match(created.stdout.join('\n'), /shown once/i)

  const listed = await command(env, ['list'])
  assert.equal(listed.code, 0)
  const rendered = listed.stdout.join('\n')
  assert.equal(rendered.includes(userId), true)
  assert.equal(rendered.includes('Martin'), true)
  for (const secret of [
    bearer,
    link.searchParams.get('invitation'),
    env.OAUTH_ENCRYPTION_KEY,
    env.ZENDESK_OAUTH_CLIENT_SECRET,
  ]) {
    assert.equal(rendered.includes(secret), false)
  }
  assert.equal(listed.stderr.length, 0)
})

test('reauthorize prints only a new one-time link and never a bearer', async () => {
  const { env } = await fixture()
  const created = await command(env, ['create', '--label', 'Adrian'])
  const userId = field(created.stdout, 'user_id')
  const bearer = field(created.stdout, 'mcp_bearer')
  const store = openStore(env)
  const invitation = new URL(field(created.stdout, 'link_url')).searchParams.get('invitation')
  const state = randomOpaque()
  const started = store.startInvitation(invitation, state)
  const claimed = store.claimAuthorization(state)
  assert.equal(claimed.kind, 'invitation')
  store.completeLink({
    ...claimed,
    identity: {
      id: '901',
      name: 'Adrian',
      email: 'adrian@example.test',
      role: 'agent',
    },
    grant: {
      accessToken: 'access-admin-sentinel',
      refreshToken: 'refresh-admin-sentinel',
      accessExpiresAt: NOW + 1_800,
      refreshExpiresAt: NOW + 2_592_000,
      scopes: ['read', 'tickets:write'],
    },
  })
  store.markReauthorizationRequired(userId, 1)
  store.close()

  const result = await command(env, ['reauthorize', '--user', userId])
  assert.equal(result.code, 0)
  assert.match(field(result.stdout, 'link_url'), /\/oauth\/link\?invitation=/)
  const rendered = result.stdout.join('\n')
  assert.equal(rendered.includes(bearer), false)
  assert.equal(rendered.includes('mcp_bearer'), false)
})

test('revoke commits locally before optional bounded upstream revocation', async () => {
  const { env } = await fixture()
  let release
  const upstream = new Promise((resolve) => {
    release = resolve
  })
  const events = []
  const fakeStore = {
    revokeUser: () => {
      events.push('local-revoked')
      return {
        kind: 'revoked',
        capturedGrant: {
          accessToken: 'access-revoke-sentinel',
          refreshToken: 'refresh-revoke-sentinel',
        },
      }
    },
    close: () => events.push('store-closed'),
  }
  const pending = command(
    env,
    ['revoke', '--user', '00000000-0000-4000-8000-000000000099', '--upstream'],
    {
      openStore: () => fakeStore,
      createOAuth: () => ({
        revokeCurrent: async (accessToken) => {
          events.push('upstream-started')
          assert.equal(accessToken, 'access-revoke-sentinel')
          await upstream
          events.push('upstream-finished')
        },
      }),
    },
  )
  await new Promise((resolve) => setImmediate(resolve))
  assert.deepEqual(events, ['local-revoked', 'upstream-started'])
  release()
  const result = await pending
  assert.equal(result.code, 0)
  assert.equal(field(result.stdout, 'local'), 'revoked')
  assert.equal(field(result.stdout, 'upstream'), 'succeeded')
  assert.deepEqual(events, [
    'local-revoked',
    'upstream-started',
    'upstream-finished',
    'store-closed',
  ])
  assert.equal(result.stdout.join('\n').includes('access-revoke-sentinel'), false)
})

test('reset removes one local mapping before bounded upstream revocation', async () => {
  const { env } = await fixture()
  const events = []
  const fakeStore = {
    resetUser: () => {
      events.push('local-reset')
      return {
        kind: 'reset',
        capturedGrant: {
          accessToken: 'access-reset-sentinel',
          refreshToken: 'refresh-reset-sentinel',
        },
      }
    },
    close: () => events.push('store-closed'),
  }
  const result = await command(
    env,
    ['reset', '--user', '00000000-0000-4000-8000-000000000098', '--upstream'],
    {
      openStore: () => fakeStore,
      createOAuth: () => ({
        revokeCurrent: async (accessToken) => {
          events.push('upstream-revoked')
          assert.equal(accessToken, 'access-reset-sentinel')
        },
      }),
    },
  )

  assert.equal(result.code, 0)
  assert.equal(field(result.stdout, 'local'), 'reset')
  assert.equal(field(result.stdout, 'upstream'), 'succeeded')
  assert.deepEqual(events, [
    'local-reset',
    'upstream-revoked',
    'store-closed',
  ])
  assert.equal(result.stdout.join('\n').includes('access-reset-sentinel'), false)
  assert.equal(result.stdout.join('\n').includes('refresh-reset-sentinel'), false)
})

test('reset accepts a user email without rendering the selector', async () => {
  const { env } = await fixture()
  const email = 'colleague@example.test'
  const fakeStore = {
    resetUserByEmail: (value) => {
      assert.equal(value, email)
      return { kind: 'reset' }
    },
    close: () => undefined,
  }
  const result = await command(
    env,
    ['reset', '--user-email', email, '--upstream'],
    { openStore: () => fakeStore },
  )

  assert.equal(result.code, 0)
  assert.equal(field(result.stdout, 'local'), 'reset')
  assert.equal(field(result.stdout, 'upstream'), 'unavailable')
  assert.equal(result.stdout.join('\n').includes(email), false)
  assert.deepEqual(result.stderr, [])
})

test('revoke without upstream and backup report bounded outcomes and mode 0600', async () => {
  const { directory, env } = await fixture()
  const created = await command(env, ['create', '--label', 'Backup'])
  const userId = field(created.stdout, 'user_id')
  const revoked = await command(env, ['revoke', '--user', userId])
  assert.equal(revoked.code, 0)
  assert.equal(field(revoked.stdout, 'local'), 'revoked')
  assert.equal(field(revoked.stdout, 'upstream'), 'not_attempted')

  const destination = join(directory, 'backups', 'oauth.sqlite')
  const backedUp = await command(env, ['backup', '--output', destination])
  assert.equal(backedUp.code, 0)
  assert.equal(field(backedUp.stdout, 'backup'), destination)
  assert.equal((await stat(destination)).mode & 0o777, 0o600)
})

test('invalid commands and identifiers fail with sanitized usage', async () => {
  const { env } = await fixture()
  for (const argv of [
    [],
    ['retrieve', '--user', 'anything'],
    ['revoke', '--user', 'not-a-uuid'],
    ['reset', '--user', '00000000-0000-4000-8000-000000000098'],
    ['reset', '--user-email', 'not-an-email', '--upstream'],
    ['backup', '--output', 'relative.sqlite'],
  ]) {
    const result = await command(env, argv)
    assert.notEqual(result.code, 0)
    assert.equal(result.stdout.length, 0)
    const rendered = result.stderr.join('\n')
    assert.match(rendered, /Usage|failed/)
    assert.equal(rendered.includes(env.OAUTH_ENCRYPTION_KEY), false)
    assert.equal(rendered.includes(env.ZENDESK_OAUTH_CLIENT_SECRET), false)
  }
})
