import assert from 'node:assert/strict'
import test from 'node:test'

import { readHttpConfig, readHttpOAuthConfig, readZendeskConfig } from '../dist/config.js'

const ZENDESK_ENV = {
  ZENDESK_SUBDOMAIN: 'example',
  ZENDESK_EMAIL: 'agent@example.test',
  ZENDESK_API_KEY: 'zendesk-token',
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

test('readHttpConfig applies safe local defaults', () => {
  assert.deepEqual(readHttpConfig({ MCP_BEARER_TOKEN: 'server-secret' }), {
    host: '0.0.0.0',
    port: 3000,
    bearerToken: 'server-secret',
    allowedHosts: ['localhost', '127.0.0.1'],
  })
})

test('readHttpConfig parses explicit deployment values', () => {
  assert.deepEqual(
    readHttpConfig({
      HOST: '127.0.0.1',
      PORT: '38184',
      MCP_BEARER_TOKEN: 'server-secret',
      MCP_ALLOWED_HOSTS: 'dev-server, 100.83.206.45,dev-server',
    }),
    {
      host: '127.0.0.1',
      port: 38184,
      bearerToken: 'server-secret',
      allowedHosts: ['dev-server', '100.83.206.45'],
    },
  )
})

test('readHttpConfig rejects a missing bearer token', () => {
  assert.throws(
    () => readHttpConfig({}),
    /Missing required environment variable: MCP_BEARER_TOKEN/,
  )
})

test('readHttpConfig rejects invalid TCP ports', () => {
  for (const port of ['', '0', '65536', '3.5', 'not-a-port']) {
    assert.throws(
      () => readHttpConfig({ MCP_BEARER_TOKEN: 'server-secret', PORT: port }),
      /PORT must be an integer between 1 and 65535/,
    )
  }
})

test('readHttpConfig rejects an explicitly empty allowed-host set', () => {
  assert.throws(
    () =>
      readHttpConfig({
        MCP_BEARER_TOKEN: 'server-secret',
        MCP_ALLOWED_HOSTS: ' , ',
      }),
    /MCP_ALLOWED_HOSTS must contain at least one hostname/,
  )
})

const HTTP_OAUTH_ENV = {
  HOST: '127.0.0.1',
  PORT: '38184',
  MCP_ALLOWED_HOSTS: 'dev-server.tail22145b.ts.net,localhost,127.0.0.1',
  PUBLIC_BASE_URL: 'https://dev-server.tail22145b.ts.net',
  ZENDESK_SUBDOMAIN: 'example',
  ZENDESK_OAUTH_CLIENT_ID: 'oauth-client-id',
  ZENDESK_OAUTH_CLIENT_SECRET: 'oauth-client-secret',
  OAUTH_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64'),
  OAUTH_DB_PATH: '/data/oauth.sqlite',
}

test('readHttpOAuthConfig returns canonical URLs and defaults', () => {
  const config = readHttpOAuthConfig(HTTP_OAUTH_ENV)
  assert.equal(config.host, '127.0.0.1')
  assert.equal(config.port, 38184)
  assert.deepEqual(config.allowedHosts, [
    'dev-server.tail22145b.ts.net',
    'localhost',
    '127.0.0.1',
  ])
  assert.equal(config.publicBaseUrl.href, 'https://dev-server.tail22145b.ts.net/')
  assert.equal(config.issuerUrl.href, 'https://dev-server.tail22145b.ts.net/')
  assert.equal(config.mcpResourceUrl.href, 'https://dev-server.tail22145b.ts.net/mcp')
  assert.equal(
    config.zendeskCallbackUrl.href,
    'https://dev-server.tail22145b.ts.net/oauth/zendesk/callback',
  )
  assert.equal(config.zendeskSubdomain, 'example')
  assert.equal(config.oauthEncryptionKey.length, 32)
  assert.equal(config.oauthDbPath, '/data/oauth.sqlite')
  assert.equal(config.mcpAccessTokenTtlSeconds, 900)
  assert.equal(config.zendeskHttpTimeoutMs, 15000)
})

test('readHttpOAuthConfig reports every missing key without values', () => {
  assert.throws(
    () => readHttpOAuthConfig({}),
    /PUBLIC_BASE_URL, ZENDESK_SUBDOMAIN, ZENDESK_OAUTH_CLIENT_ID, ZENDESK_OAUTH_CLIENT_SECRET, OAUTH_ENCRYPTION_KEY, OAUTH_DB_PATH/,
  )
})

test('readHttpOAuthConfig rejects unsafe origins, subdomains, keys, and ranges', () => {
  const cases = [
    ['PUBLIC_BASE_URL', 'http://dev-server.tail22145b.ts.net', /HTTPS origin/],
    ['PUBLIC_BASE_URL', 'https://user:pass@dev-server.tail22145b.ts.net', /HTTPS origin/],
    ['PUBLIC_BASE_URL', 'https://dev-server.tail22145b.ts.net/path', /HTTPS origin/],
    ['PUBLIC_BASE_URL', 'https://dev-server.tail22145b.ts.net/?query=1', /HTTPS origin/],
    ['PUBLIC_BASE_URL', 'https://dev-server.tail22145b.ts.net/#fragment', /HTTPS origin/],
    ['PUBLIC_BASE_URL', 'https://other.example.test', /MCP_ALLOWED_HOSTS/],
    ['ZENDESK_SUBDOMAIN', 'two.labels', /DNS label/],
    ['ZENDESK_SUBDOMAIN', '-invalid', /DNS label/],
    ['OAUTH_ENCRYPTION_KEY', Buffer.alloc(31).toString('base64'), /32 decoded bytes/],
    ['OAUTH_DB_PATH', 'relative.sqlite', /absolute path/],
    ['MCP_ACCESS_TOKEN_TTL_SECONDS', '59', /60 and 3600/],
    ['MCP_ACCESS_TOKEN_TTL_SECONDS', '3601', /60 and 3600/],
    ['ZENDESK_HTTP_TIMEOUT_MS', '999', /1000 and 60000/],
    ['ZENDESK_HTTP_TIMEOUT_MS', '60001', /1000 and 60000/],
  ]

  for (const [key, value, expected] of cases) {
    assert.throws(
      () => readHttpOAuthConfig({ ...HTTP_OAUTH_ENV, [key]: value }),
      expected,
      String(key),
    )
  }
})
