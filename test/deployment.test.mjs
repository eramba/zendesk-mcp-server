import assert from 'node:assert/strict'
import { access, readFile } from 'node:fs/promises'
import test from 'node:test'

const ROOT = new URL('../', import.meta.url)

async function read(relativePath) {
  return readFile(new URL(relativePath, ROOT), 'utf8')
}

function environmentKeys(template) {
  return template
    .split('\n')
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => line.slice(0, line.indexOf('=')))
}

test('Docker Compose preserves the loopback-only hardened service and OAuth volume', async () => {
  const compose = await read('docker-compose.yml')
  const portsBlock = compose.match(/^\s{4}ports:\n((?:\s{6}- .+\n?)+)/m)
  const serviceVolumesBlock = compose.match(/^\s{4}volumes:\n((?:\s{6}- .+\n?)+)/m)

  assert.deepEqual(
    portsBlock?.[1].trim().split('\n').map((line) => line.trim()),
    ['- "${MCP_BIND_ADDRESS:-127.0.0.1}:${MCP_HOST_PORT:-38184}:3000"'],
  )
  assert.deepEqual(
    serviceVolumesBlock?.[1].trim().split('\n').map((line) => line.trim()),
    ['- oauth-data:/data'],
  )
  assert.match(compose, /^\s{4}read_only: true$/m)
  assert.match(compose, /^\s{4}tmpfs:\n\s{6}- \/tmp$/m)
  assert.match(compose, /^\s{4}security_opt:\n\s{6}- no-new-privileges:true$/m)
  assert.match(compose, /^\s{4}stop_grace_period: 15s$/m)
  assert.match(compose, /fetch\('http:\/\/127\.0\.0\.1:3000\/healthz'\)/)
  assert.match(compose, /^volumes:\n\s{2}oauth-data:$/m)
})

test('build stage compiles SQLite once and prunes development dependencies', async () => {
  const dockerfile = await read('Dockerfile')
  const [buildStage] = dockerfile.split(
    /(?=^FROM node:22-alpine AS runtime$)/m,
  )

  assert.ok(buildStage)
  assert.match(buildStage, /RUN apk add --no-cache python3 make g\+\+/)
  assert.match(buildStage, /RUN npm ci/)
  assert.match(buildStage, /RUN npm run build && npm prune --omit=dev/)
})

test('runtime copies the built production tree without installing or compiling', async () => {
  const dockerfile = await read('Dockerfile')
  const runtimeStage = dockerfile.split(
    /(?=^FROM node:22-alpine AS runtime$)/m,
  )[1]

  assert.ok(runtimeStage)
  assert.doesNotMatch(runtimeStage, /npm (?:ci|install)|apk add|python3|make|g\+\+/)
  assert.match(runtimeStage, /COPY --from=build --chown=node:node \/app\/package\.json \/app\/package-lock\.json \.\//)
  assert.match(runtimeStage, /COPY --from=build --chown=node:node \/app\/node_modules \.\/node_modules/)
  assert.match(runtimeStage, /COPY --from=build --chown=node:node \/app\/dist \.\/dist/)
  assert.match(runtimeStage, /COPY --chown=node:node scripts\/oauth-admin\.mjs \.\/scripts\/oauth-admin\.mjs/)

  const dataSetup = runtimeStage.indexOf('RUN mkdir /data && chown node:node /data && chmod 0700 /data')
  const nonRootUser = runtimeStage.indexOf('USER node')
  assert.notEqual(dataSetup, -1)
  assert.ok(dataSetup < nonRootUser)
})

test('HTTP and stdio environment templates contain only transport-specific keys', async () => {
  const httpTemplate = await read('.env.http.example')
  const stdioTemplate = await read('.env.stdio.example')

  assert.deepEqual(environmentKeys(httpTemplate), [
    'PUBLIC_BASE_URL',
    'ZENDESK_SUBDOMAIN',
    'ZENDESK_OAUTH_CLIENT_ID',
    'ZENDESK_OAUTH_CLIENT_SECRET',
    'OAUTH_ENCRYPTION_KEY',
    'OAUTH_DB_PATH',
    'MCP_ALLOWED_HOSTS',
    'HOST',
    'PORT',
    'MCP_ACCESS_TOKEN_TTL_SECONDS',
    'ZENDESK_HTTP_TIMEOUT_MS',
    'MCP_BIND_ADDRESS',
    'MCP_HOST_PORT',
  ])
  assert.match(httpTemplate, /^OAUTH_ENCRYPTION_KEY=<separately-generated-base64-32-byte-key>$/m)
  assert.match(httpTemplate, /^OAUTH_DB_PATH=\/data\/oauth\.sqlite$/m)
  assert.doesNotMatch(
    httpTemplate,
    /MCP_BEARER_TOKEN|ZENDESK_EMAIL|ZENDESK_API_KEY/,
  )

  assert.deepEqual(environmentKeys(stdioTemplate), [
    'ZENDESK_SUBDOMAIN',
    'ZENDESK_EMAIL',
    'ZENDESK_API_KEY',
  ])
})

test('the real environment stays ignored and the combined template is deleted', async () => {
  const gitignore = await read('.gitignore')

  assert.match(gitignore, /^\.env$/m)
  await assert.rejects(access(new URL('.env.example', ROOT)), { code: 'ENOENT' })
})
