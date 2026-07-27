import assert from 'node:assert/strict'
import test from 'node:test'

import { readHttpOAuthConfig, readZendeskConfig } from '../dist/config.js'

const ZENDESK_ENV = {
  ZENDESK_SUBDOMAIN: 'example',
  ZENDESK_EMAIL: 'agent@example.test',
  ZENDESK_API_KEY: 'zendesk-token',
}

const HTTP_ENV = {
  PUBLIC_BASE_URL: 'https://mcp.example.test',
  ZENDESK_SUBDOMAIN: 'acme',
  ZENDESK_OAUTH_CLIENT_ID: 'internal-mcp',
  ZENDESK_OAUTH_CLIENT_SECRET: 'client-secret-sentinel',
  OAUTH_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64url'),
  OAUTH_DB_PATH: '/var/lib/zendesk-mcp/oauth.sqlite',
}

test('readZendeskConfig returns the required values', () => {
  assert.deepEqual(readZendeskConfig(ZENDESK_ENV), {
    subdomain: 'example',
    email: 'agent@example.test',
    apiKey: 'zendesk-token',
  })
})

test('readZendeskConfig reports every missing key without values', () => {
  assert.throws(
    () => readZendeskConfig({ ZENDESK_SUBDOMAIN: 'example' }),
    /Missing required environment variables: ZENDESK_EMAIL, ZENDESK_API_KEY/,
  )
})

test('readHttpOAuthConfig applies safe local defaults and a fixed callback', () => {
  const config = readHttpOAuthConfig(HTTP_ENV)

  assert.deepEqual(config, {
    host: '0.0.0.0',
    port: 3000,
    allowedHosts: ['localhost', '127.0.0.1'],
    publicBaseUrl: new URL('https://mcp.example.test/'),
    zendeskSubdomain: 'acme',
    zendeskOAuthClientId: 'internal-mcp',
    zendeskOAuthClientSecret: 'client-secret-sentinel',
    oauthEncryptionKey: Buffer.alloc(32, 7),
    oauthDbPath: '/var/lib/zendesk-mcp/oauth.sqlite',
    zendeskCallbackUrl: new URL('https://mcp.example.test/oauth/callback'),
    selfServiceEnrollmentEnabled: false,
  })
})

test('readHttpOAuthConfig parses explicit deployment values', () => {
  assert.deepEqual(
    readHttpOAuthConfig({
      ...HTTP_ENV,
      HOST: '127.0.0.1',
      PORT: '38184',
      MCP_ALLOWED_HOSTS: 'dev-server, 100.83.206.45,dev-server',
    }),
    {
      host: '127.0.0.1',
      port: 38184,
      allowedHosts: ['dev-server', '100.83.206.45'],
      publicBaseUrl: new URL('https://mcp.example.test/'),
      zendeskSubdomain: 'acme',
      zendeskOAuthClientId: 'internal-mcp',
      zendeskOAuthClientSecret: 'client-secret-sentinel',
      oauthEncryptionKey: Buffer.alloc(32, 7),
      oauthDbPath: '/var/lib/zendesk-mcp/oauth.sqlite',
      zendeskCallbackUrl: new URL('https://mcp.example.test/oauth/callback'),
      selfServiceEnrollmentEnabled: false,
    },
  )
})

test('readHttpOAuthConfig reports every missing key without values', () => {
  assert.throws(() => readHttpOAuthConfig({}), (error) => {
    assert.match(error.message, /Missing required environment variables:/)
    for (const key of Object.keys(HTTP_ENV)) assert.match(error.message, new RegExp(key))
    assert.equal(error.message.includes('client-secret-sentinel'), false)
    return true
  })
})

test('readHttpOAuthConfig strictly parses optional self-service enrollment', () => {
  assert.equal(
    readHttpOAuthConfig({
      ...HTTP_ENV,
      SELF_SERVICE_ENROLLMENT_ENABLED: 'true',
    }).selfServiceEnrollmentEnabled,
    true,
  )
  assert.equal(
    readHttpOAuthConfig({
      ...HTTP_ENV,
      SELF_SERVICE_ENROLLMENT_ENABLED: 'false',
    }).selfServiceEnrollmentEnabled,
    false,
  )

  for (const value of ['', '1', 'yes', 'TRUE', ' false ', 'flag-secret-sentinel']) {
    assert.throws(
      () =>
        readHttpOAuthConfig({
          ...HTTP_ENV,
          SELF_SERVICE_ENROLLMENT_ENABLED: value,
        }),
      (error) => {
        assert.match(error.message, /SELF_SERVICE_ENROLLMENT_ENABLED/)
        if (value.length > 0) assert.equal(error.message.includes(value), false)
        return true
      },
    )
  }
})

test('readHttpOAuthConfig rejects invalid TCP ports', () => {
  for (const port of ['', '0', '65536', '3.5', 'not-a-port']) {
    assert.throws(
      () => readHttpOAuthConfig({ ...HTTP_ENV, PORT: port }),
      /PORT must be an integer between 1 and 65535/,
    )
  }
})

test('readHttpOAuthConfig rejects an explicitly empty allowed-host set', () => {
  assert.throws(
    () =>
      readHttpOAuthConfig({
        ...HTTP_ENV,
        MCP_ALLOWED_HOSTS: ' , ',
      }),
    /MCP_ALLOWED_HOSTS must contain at least one hostname/,
  )
})

test('readHttpOAuthConfig accepts HTTP only for loopback development origins', () => {
  for (const publicBaseUrl of [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://[::1]:3000',
  ]) {
    assert.equal(
      readHttpOAuthConfig({ ...HTTP_ENV, PUBLIC_BASE_URL: publicBaseUrl })
        .publicBaseUrl.href,
      `${publicBaseUrl}/`,
    )
  }
})

test('readHttpOAuthConfig rejects unsafe or noncanonical public URLs', () => {
  for (const publicBaseUrl of [
    'http://mcp.example.test',
    'ftp://mcp.example.test',
    'https://user:pass@mcp.example.test',
    'https://mcp.example.test/path',
    'https://mcp.example.test?query=1',
    'https://mcp.example.test#fragment',
    'not-a-url',
  ]) {
    assert.throws(
      () => readHttpOAuthConfig({ ...HTTP_ENV, PUBLIC_BASE_URL: publicBaseUrl }),
      /PUBLIC_BASE_URL/,
    )
  }
})

test('readHttpOAuthConfig rejects unsafe Zendesk subdomains', () => {
  for (const subdomain of [
    '',
    '-acme',
    'acme-',
    'acme.example',
    'https://acme',
    'acme/zendesk',
    'a'.repeat(64),
  ]) {
    assert.throws(
      () => readHttpOAuthConfig({ ...HTTP_ENV, ZENDESK_SUBDOMAIN: subdomain }),
      /ZENDESK_SUBDOMAIN/,
    )
  }
})

test('readHttpOAuthConfig rejects noncanonical or wrong-length encryption keys', () => {
  for (const encryptionKey of [
    '',
    Buffer.alloc(31, 7).toString('base64url'),
    Buffer.alloc(33, 7).toString('base64url'),
    Buffer.alloc(32, 7).toString('base64'),
    `${Buffer.alloc(32, 7).toString('base64url')}=`,
    'not base64url!',
  ]) {
    assert.throws(
      () => readHttpOAuthConfig({ ...HTTP_ENV, OAUTH_ENCRYPTION_KEY: encryptionKey }),
      /OAUTH_ENCRYPTION_KEY/,
    )
  }
})

test('readHttpOAuthConfig rejects relative database paths', () => {
  assert.throws(
    () => readHttpOAuthConfig({ ...HTTP_ENV, OAUTH_DB_PATH: './oauth.sqlite' }),
    /OAUTH_DB_PATH/,
  )
})
