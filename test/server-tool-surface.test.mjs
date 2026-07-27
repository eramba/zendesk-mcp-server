import assert from 'node:assert/strict'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { buildZendeskServer } from '../dist/server.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

const expectedTools = [
  'create_ticket',
  'create_ticket_comment',
  'get_current_user',
  'get_organization',
  'get_ticket',
  'get_ticket_audits',
  'get_ticket_comments',
  'get_ticket_metrics',
  'get_tickets',
  'get_user',
  'list_assignable_groups',
  'list_custom_statuses',
  'list_group_members',
  'list_organization_tickets',
  'list_ticket_fields',
  'list_ticket_forms',
  'list_user_tickets',
  'list_view_tickets',
  'list_views',
  'search',
  'search_organizations',
  'search_tickets',
  'search_users',
  'update_ticket',
]

test('server publishes the complete stable MCP surface', async () => {
  const zendesk = new ZendeskClient({
    subdomain: 'example',
    auth: {
      kind: 'api-token',
      email: 'agent@example.test',
      token: 'token-sentinel',
    },
    fetch: async () => assert.fail('surface discovery must not call Zendesk'),
  })
  const server = buildZendeskServer(zendesk)
  const client = new Client({ name: 'surface-test-client', version: '1.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()

  await server.connect(serverTransport)
  await client.connect(clientTransport)

  try {
    const tools = await client.listTools()
    const prompts = await client.listPrompts()
    const resources = await client.listResources()

    assert.deepEqual(tools.tools.map(({ name }) => name).sort(), [...expectedTools].sort())
    assert.deepEqual(
      prompts.prompts.map(({ name }) => name).sort(),
      ['analyze-ticket', 'draft-ticket-response'],
    )
    assert.deepEqual(resources.resources.map(({ uri }) => uri), ['zendesk://knowledge-base'])
  } finally {
    await client.close()
    await server.close()
  }
})
