import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'

function requiredEnv(name) {
  const value = process.env[name]
  if (!value?.trim()) throw new Error(`Missing required environment variable: ${name}`)
  return value
}

const url = new URL(requiredEnv('MCP_URL'))
const bearerToken = requiredEnv('MCP_BEARER_TOKEN')
const verifyZendesk = process.argv.includes('--zendesk')
const transport = new StreamableHTTPClientTransport(url, {
  requestInit: {
    headers: { Authorization: `Bearer ${bearerToken}` },
  },
})
const client = new Client({ name: 'zendesk-mcp-smoke', version: '1.0.0' })
let connected = false

try {
  await client.connect(transport)
  connected = true
  const tools = await client.listTools()

  if (verifyZendesk) {
    const result = await client.callTool({
      name: 'get_tickets',
      arguments: {
        page: 1,
        per_page: 1,
        sort_by: 'updated_at',
        sort_order: 'desc',
      },
    })
    if (result.isError) throw new Error('Read-only Zendesk smoke call failed')
  }

  console.log(
    JSON.stringify({
      ok: true,
      toolCount: tools.tools.length,
      zendeskRead: verifyZendesk,
    }),
  )
} finally {
  if (connected) await client.close()
}
