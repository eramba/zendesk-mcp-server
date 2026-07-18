import assert from 'node:assert/strict'
import test from 'node:test'

import { createOAuthMetadata } from '@modelcontextprotocol/sdk/server/auth/router.js'

const ISSUER = new URL('https://oauth.example.test')

test('SDK 1.26 stock metadata still advertises confidential revocation authentication', () => {
  const metadata = createOAuthMetadata({
    provider: {
      clientsStore: {
        getClient: () => undefined,
        registerClient: () => {
          throw new Error('not used')
        },
      },
      authorize: async () => {},
      challengeForAuthorizationCode: async () => '',
      exchangeAuthorizationCode: async () => ({ access_token: '', token_type: 'Bearer' }),
      exchangeRefreshToken: async () => ({ access_token: '', token_type: 'Bearer' }),
      verifyAccessToken: async () => {
        throw new Error('not used')
      },
      revokeToken: async () => {},
    },
    issuerUrl: ISSUER,
  })

  assert.deepEqual(metadata.token_endpoint_auth_methods_supported, [
    'client_secret_post',
    'none',
  ])
  assert.deepEqual(metadata.revocation_endpoint_auth_methods_supported, [
    'client_secret_post',
  ])
})
