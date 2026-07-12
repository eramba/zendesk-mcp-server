import assert from 'node:assert/strict'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { buildZendeskServer } from '../dist/server.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

test('publishes inline image retrieval instructions during MCP initialization', async () => {
  const zendesk = new ZendeskClient('example', 'agent@example.test', 'test-token')
  const server = buildZendeskServer(zendesk)
  const client = new Client({ name: 'test-client', version: '1.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()

  await server.connect(serverTransport)
  await client.connect(clientTransport)

  try {
    const instructions = client.getInstructions() ?? ''

    assert.match(instructions, /normal HTTP GET/i)
    assert.match(instructions, /do not use HEAD/i)
    assert.match(instructions, /inspect the local image/i)
  } finally {
    await client.close()
    await server.close()
  }
})
