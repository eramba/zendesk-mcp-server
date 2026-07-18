import assert from 'node:assert/strict'
import test from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { buildZendeskServer } from '../dist/server.js'
import { ZendeskClient } from '../dist/zendesk-client.js'

test('publishes safe Zendesk attachment retrieval instructions during MCP initialization', async () => {
  const zendesk = new ZendeskClient({
    subdomain: 'example',
    auth: { kind: 'api_token', email: 'agent@example.test', apiToken: 'test-token' },
  })
  const server = buildZendeskServer(zendesk)
  const client = new Client({ name: 'test-client', version: '1.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()

  await server.connect(serverTransport)
  await client.connect(clientTransport)

  try {
    const instructions = client.getInstructions() ?? ''

    assert.match(instructions, /comments may contain an attachments array/i)
    assert.match(instructions, /normal HTTP GET/i)
    assert.match(instructions, /follows redirects/i)
    assert.match(instructions, /do not use HEAD/i)
    assert.match(instructions, /do not send Zendesk API credentials/i)
    assert.match(instructions, /sensitive access links/i)
    assert.match(instructions, /marked deleted/i)
    assert.match(instructions, /malicious/i)
    assert.match(instructions, /list their contents first/i)
    assert.match(instructions, /dedicated directory/i)
    assert.match(instructions, /never execute/i)
    assert.match(instructions, /report download, extraction, or inspection failures/i)
    assert.doesNotMatch(
      instructions,
      /ZENDESK_(?:EMAIL|API_KEY)|MCP_BEARER_TOKEN|Authorization:\s*Bearer/i,
      'model-visible instructions must not teach credential or bearer injection',
    )
  } finally {
    await client.close()
    await server.close()
  }
})
