import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const root = new URL('../', import.meta.url)

test('container deployment retains non-root/read-only hardening and persists only /data', async () => {
  const [dockerfile, compose] = await Promise.all([
    readFile(new URL('Dockerfile', root), 'utf8'),
    readFile(new URL('docker-compose.yml', root), 'utf8'),
  ])

  assert.match(dockerfile, /\bUSER node\b/)
  assert.match(dockerfile, /mkdir .*\/data/)
  assert.match(dockerfile, /chown .*node.*\/data/)
  assert.match(compose, /\bread_only:\s*true/)
  assert.match(compose, /no-new-privileges:true/)
  assert.match(compose, /tmpfs:\s*\n\s+- \/tmp/)
  assert.match(compose, /zendesk_mcp_data:\/data/)
  assert.match(compose, /^volumes:\s*\n\s+zendesk_mcp_data:/m)
  assert.match(compose, /OAUTH_DB_PATH:\s*\/data\/oauth\.sqlite/)
  assert.equal(compose.includes('MCP_BEARER_TOKEN:'), false)
  assert.equal(compose.includes('ZENDESK_API_KEY:'), false)
  assert.equal(compose.includes('ZENDESK_EMAIL:'), false)
})

test('HTTP and stdio environment examples keep authentication boundaries separate', async () => {
  const [httpExample, stdioExample] = await Promise.all([
    readFile(new URL('.env.example', root), 'utf8'),
    readFile(new URL('.env.stdio.example', root), 'utf8'),
  ])
  for (const name of [
    'PUBLIC_BASE_URL',
    'ZENDESK_SUBDOMAIN',
    'ZENDESK_OAUTH_CLIENT_ID',
    'ZENDESK_OAUTH_CLIENT_SECRET',
    'OAUTH_ENCRYPTION_KEY',
    'OAUTH_DB_PATH',
    'MCP_ALLOWED_HOSTS',
  ]) {
    assert.match(httpExample, new RegExp(`^${name}=`, 'm'))
  }
  assert.equal(httpExample.includes('MCP_BEARER_TOKEN='), false)
  assert.equal(httpExample.includes('ZENDESK_API_KEY='), false)
  assert.match(stdioExample, /^ZENDESK_EMAIL=/m)
  assert.match(stdioExample, /^ZENDESK_API_KEY=/m)
  assert.equal(stdioExample.includes('OAUTH_ENCRYPTION_KEY='), false)
})

test('local smoke script is explicitly fake-only and reports zero Zendesk requests', async () => {
  const [script, packageJson] = await Promise.all([
    readFile(new URL('scripts/smoke-http-local.mjs', root), 'utf8'),
    readFile(new URL('package.json', root), 'utf8').then(JSON.parse),
  ])
  assert.equal(packageJson.scripts['smoke:http:local'], 'node scripts/smoke-http-local.mjs')
  assert.match(script, /zendeskRequests/)
  assert.match(script, /assert\.equal\(zendeskRequests,\s*0\)/)
  assert.equal(script.includes('process.env.ZENDESK'), false)
})
