import assert from 'node:assert/strict'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { buildZendeskServer } from '../dist/server.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

const currentUserPayload = {
  id: 9873843,
  name: 'Roger Wilco',
  email: 'roger@example.test',
  role: 'agent',
  created_at: '2026-07-01T10:00:00Z',
  updated_at: '2026-07-27T09:00:00Z',
  organization_id: 57542,
  suspended: false,
  active: true,
}

const normalizedCurrentUser = {
  ...currentUserPayload,
  alias: null,
  phone: null,
  verified: false,
  role_type: null,
  custom_role_id: null,
  default_group_id: null,
  locale: null,
  locale_id: null,
  time_zone: null,
  external_id: null,
  tags: [],
  user_fields: {},
  last_login_at: null,
}

function currentUserClient(requests) {
  return new ZendeskClient({
    subdomain: 'example',
    auth: {
      kind: 'oauth',
      accessToken: 'access-token-sentinel',
      onUnauthorized: async () => assert.fail('fresh token must not refresh'),
    },
    fetch: async (input, init = {}) => {
      requests.push({
        url: String(input),
        method: init.method ?? 'GET',
        authorization: new Headers(init.headers).get('authorization'),
      })
      return new Response(JSON.stringify({
        user: {
          ...currentUserPayload,
          authenticity_token: 'not-exposed-by-the-tool',
        },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    },
  })
}

test('getCurrentUser calls the official users/me endpoint with the selected OAuth token', async () => {
  const requests = []
  const user = await currentUserClient(requests).getCurrentUser()

  assert.deepEqual(user, normalizedCurrentUser)
  assert.deepEqual(requests, [{
    url: 'https://example.zendesk.com/api/v2/users/me.json',
    method: 'GET',
    authorization: 'Bearer access-token-sentinel',
  }])
})

test('get_current_user exposes the authenticated Zendesk identity through MCP', async () => {
  const requests = []
  const server = buildZendeskServer(currentUserClient(requests))
  const client = new Client({ name: 'current-user-test-client', version: '1.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()

  await server.connect(serverTransport)
  await client.connect(clientTransport)

  try {
    const tools = await client.listTools()
    assert.ok(tools.tools.some((tool) => tool.name === 'get_current_user'))

    const result = await client.callTool({
      name: 'get_current_user',
      arguments: {},
    })

    assert.equal(result.isError, undefined)
    assert.deepEqual(JSON.parse(result.content[0].text), normalizedCurrentUser)
    assert.equal(requests.length, 1)
  } finally {
    await client.close()
    await server.close()
  }
})
