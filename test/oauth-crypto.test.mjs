import assert from 'node:assert/strict'
import test from 'node:test'

import {
  TokenCipher,
  digestBinding,
  hashOpaque,
  randomOpaque,
} from '../dist/oauth/token-cipher.js'

const key = Buffer.alloc(32, 9)
const credentialContext = {
  kind: 'zendesk_credential',
  rowId: 'credential-1',
  expiresAt: 1_800_000_000,
  subdomain: 'example',
  principalId: 'principal-1',
  credentialVersion: 4,
  principalEpoch: 2,
}

test('TokenCipher round-trips only with the exact record context', () => {
  const cipher = new TokenCipher(key)
  const encrypted = cipher.encrypt('access-secret refresh-secret', credentialContext)

  assert.equal(cipher.decrypt(encrypted, credentialContext), 'access-secret refresh-secret')
  assert.doesNotMatch(JSON.stringify(encrypted), /access-secret|refresh-secret/)

  for (const changed of [
    { ...credentialContext, rowId: 'credential-2' },
    { ...credentialContext, principalId: 'principal-2' },
    { ...credentialContext, credentialVersion: 5 },
    { ...credentialContext, principalEpoch: 3 },
    { ...credentialContext, expiresAt: 1_800_000_001 },
  ]) {
    assert.throws(() => cipher.decrypt(encrypted, changed))
  }
})

test('TokenCipher rejects wrong keys and tampering', () => {
  const cipher = new TokenCipher(key)
  const encrypted = cipher.encrypt('secret', credentialContext)
  const flip = (value) => `${value.slice(0, -1)}${value.endsWith('A') ? 'B' : 'A'}`

  assert.throws(() => new TokenCipher(Buffer.alloc(32, 8)).decrypt(encrypted, credentialContext))
  assert.throws(() => cipher.decrypt({ ...encrypted, nonce: flip(encrypted.nonce) }, credentialContext))
  assert.throws(() =>
    cipher.decrypt({ ...encrypted, ciphertext: flip(encrypted.ciphertext) }, credentialContext),
  )
  assert.throws(() => cipher.decrypt({ ...encrypted, tag: flip(encrypted.tag) }, credentialContext))
})

test('TokenCipher rejects moving every record kind across its bound dimensions', () => {
  const cipher = new TokenCipher(key)
  const contexts = [
    {
      kind: 'login', rowId: 'login-1', expiresAt: 1_800_000_000, subdomain: 'example',
      clientId: 'client-1', browserNonceHash: 'nonce-1', redirectDigest: 'redirect-1', resourceDigest: 'resource-1',
    },
    {
      kind: 'staged_grant', rowId: 'stage-1', expiresAt: 1_800_000_000, purpose: 'refresh', subdomain: 'example',
      expectedPrincipalId: 'principal-1', expectedPrincipalEpoch: 2, expectedCredentialVersion: 4,
    },
    {
      kind: 'disconnect_outbox', rowId: 'outbox-1', expiresAt: 1_800_000_000, subdomain: 'example',
      principalId: 'principal-1', credentialVersion: 4, principalEpoch: 2,
    },
    {
      kind: 'mcp_refresh_retry', rowId: 'refresh-1', expiresAt: 1_800_000_000, familyId: 'family-1',
      clientId: 'client-1', resource: 'https://example.test/mcp', scopes: 'zendesk:read zendesk:write', generation: 2,
    },
  ]
  for (const context of contexts) {
    const encrypted = cipher.encrypt('secret', context)
    assert.throws(() => cipher.decrypt(encrypted, { ...context, rowId: `${context.rowId}-moved` }))
    assert.throws(() => cipher.decrypt(encrypted, { ...context, expiresAt: context.expiresAt + 1 }))
  }
})

test('opaque values have at least 256 bits and hashes are deterministic lookup values', () => {
  const first = randomOpaque()
  const second = randomOpaque()
  assert.notEqual(first, second)
  assert.ok(Buffer.from(first, 'base64url').length >= 32)
  assert.equal(hashOpaque(first), hashOpaque(first))
  assert.notEqual(hashOpaque(first), first)
  assert.equal(digestBinding('https://localhost:1234/callback'), digestBinding('https://localhost:1234/callback'))
})

test('constructor requires exactly one 256-bit key', () => {
  assert.throws(() => new TokenCipher(Buffer.alloc(31)), /32 bytes/)
  assert.throws(() => new TokenCipher(Buffer.alloc(33)), /32 bytes/)
})
