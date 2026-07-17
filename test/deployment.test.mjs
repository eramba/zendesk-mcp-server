import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

test('Docker Compose publishes the MCP port on loopback by default', async () => {
  const compose = await readFile(new URL('../docker-compose.yml', import.meta.url), 'utf8')

  assert.match(
    compose,
    /\$\{MCP_BIND_ADDRESS:-127\.0\.0\.1\}:\$\{MCP_HOST_PORT:-38184\}:3000/,
  )
})
