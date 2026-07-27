import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import test from 'node:test'

const execFileAsync = promisify(execFile)

test('fake-only local smoke proves health, auth rejection, MCP initialization, and zero Zendesk calls', async () => {
  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    ['scripts/smoke-http-local.mjs'],
    {
      cwd: new URL('../', import.meta.url),
      timeout: 20_000,
      env: { ...process.env, NODE_ENV: 'test' },
    },
  )
  assert.equal(stderr, '')
  const result = JSON.parse(stdout)
  assert.deepEqual(result, {
    ok: true,
    healthStatus: 200,
    unauthenticatedStatus: 401,
    initialized: true,
    toolsListed: true,
    zendeskRequests: 0,
  })
})
