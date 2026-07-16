import assert from 'node:assert/strict'
import test from 'node:test'

import { readHttpConfig, readZendeskConfig } from '../dist/config.js'

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
