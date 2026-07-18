const MCP_SCOPES = ['zendesk:read', 'zendesk:write']

class SmokeError extends Error {}

function requiredEnv(name) {
  const value = process.env[name]
  if (!value?.trim()) throw new SmokeError(`Missing required environment variable: ${name}`)
  return value
}

function assertSmoke(condition, message) {
  if (!condition) throw new SmokeError(message)
}

function exactKeys(value, expected) {
  return value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort())
}

function exactArray(value, expected) {
  return Array.isArray(value) &&
    JSON.stringify(value) === JSON.stringify(expected)
}

function parseBearerChallenge(header) {
  assertSmoke(typeof header === 'string', 'MCP response is missing its OAuth challenge')
  const prefix = /^Bearer\s+/.exec(header)
  assertSmoke(prefix !== null, 'MCP response has an invalid OAuth challenge')

  const attributes = new Map()
  let remainder = header.slice(prefix[0].length)
  while (remainder.length > 0) {
    const attribute = /^([A-Za-z][A-Za-z0-9_-]*)="((?:[^"\\]|\\.)*)"(?:,\s*|$)/.exec(remainder)
    assertSmoke(attribute !== null, 'MCP response has an invalid OAuth challenge')
    assertSmoke(!attributes.has(attribute[1]), 'MCP response has an invalid OAuth challenge')
    attributes.set(attribute[1], attribute[2].replace(/\\(.)/g, '$1'))
    remainder = remainder.slice(attribute[0].length)
  }
  return attributes
}

async function fetchJson(url, expectedStatus, failureMessage, signal) {
  let response
  try {
    response = await fetch(url, { signal })
  } catch {
    throw new SmokeError(failureMessage)
  }
  assertSmoke(response.status === expectedStatus, failureMessage)
  try {
    return { response, json: await response.json() }
  } catch {
    throw new SmokeError(failureMessage)
  }
}

async function run(signal) {
  let resourceUrl
  try {
    resourceUrl = new URL(requiredEnv('MCP_URL'))
  } catch (error) {
    if (error instanceof SmokeError) throw error
    throw new SmokeError('MCP_URL must be an absolute URL')
  }
  assertSmoke(resourceUrl.pathname === '/mcp', 'MCP_URL must identify the canonical /mcp resource')
  assertSmoke(resourceUrl.search === '' && resourceUrl.hash === '', 'MCP_URL must identify the canonical /mcp resource')

  const healthUrl = new URL('/healthz', resourceUrl)
  const health = await fetchJson(healthUrl, 200, 'HTTP readiness check failed', signal)
  assertSmoke(exactKeys(health.json, ['ok']) && health.json.ok === true, 'HTTP readiness check failed')

  let unauthorized
  try {
    unauthorized = await fetch(resourceUrl, { signal })
  } catch {
    throw new SmokeError('MCP OAuth challenge check failed')
  }
  assertSmoke(unauthorized.status === 401, 'MCP OAuth challenge check failed')
  const challenge = parseBearerChallenge(unauthorized.headers.get('www-authenticate'))
  assertSmoke(
    exactArray([...challenge.keys()], ['error', 'error_description', 'scope', 'resource_metadata']) &&
      challenge.get('error') === 'invalid_token' &&
      challenge.get('error_description') === 'Missing Authorization header' &&
      challenge.get('scope') === MCP_SCOPES.join(' '),
    'MCP response has an invalid OAuth challenge',
  )

  const expectedResourceMetadataUrl = new URL(
    '/.well-known/oauth-protected-resource/mcp',
    resourceUrl,
  )
  let resourceMetadataUrl
  try {
    resourceMetadataUrl = new URL(challenge.get('resource_metadata'))
  } catch {
    throw new SmokeError('MCP response has an invalid OAuth challenge')
  }
  assertSmoke(
    resourceMetadataUrl.href === expectedResourceMetadataUrl.href,
    'MCP response has an invalid OAuth challenge',
  )

  const protectedResource = await fetchJson(
    resourceMetadataUrl,
    200,
    'Protected-resource metadata check failed',
    signal,
  )
  assertSmoke(
    exactKeys(protectedResource.json, ['resource', 'authorization_servers', 'scopes_supported']) &&
      protectedResource.json.resource === resourceUrl.href &&
      exactArray(protectedResource.json.scopes_supported, MCP_SCOPES) &&
      Array.isArray(protectedResource.json.authorization_servers) &&
      protectedResource.json.authorization_servers.length === 1,
    'Protected-resource metadata check failed',
  )

  let issuerUrl
  try {
    issuerUrl = new URL(protectedResource.json.authorization_servers[0])
  } catch {
    throw new SmokeError('Protected-resource metadata check failed')
  }
  assertSmoke(issuerUrl.origin === resourceUrl.origin && issuerUrl.pathname === '/', 'Protected-resource metadata check failed')
  assertSmoke(issuerUrl.search === '' && issuerUrl.hash === '', 'Protected-resource metadata check failed')

  const authorizationMetadataUrl = new URL('/.well-known/oauth-authorization-server', issuerUrl)
  const authorizationServer = await fetchJson(
    authorizationMetadataUrl,
    200,
    'Authorization-server metadata check failed',
    signal,
  )
  const metadata = authorizationServer.json
  assertSmoke(
    exactKeys(metadata, [
      'issuer',
      'authorization_endpoint',
      'response_types_supported',
      'code_challenge_methods_supported',
      'token_endpoint',
      'token_endpoint_auth_methods_supported',
      'grant_types_supported',
      'scopes_supported',
      'revocation_endpoint',
      'revocation_endpoint_auth_methods_supported',
      'registration_endpoint',
    ]) &&
      metadata.issuer === issuerUrl.href &&
      metadata.authorization_endpoint === new URL('/authorize', issuerUrl).href &&
      exactArray(metadata.response_types_supported, ['code']) &&
      exactArray(metadata.code_challenge_methods_supported, ['S256']) &&
      metadata.token_endpoint === new URL('/token', issuerUrl).href &&
      exactArray(metadata.token_endpoint_auth_methods_supported, ['none']) &&
      exactArray(metadata.grant_types_supported, ['authorization_code', 'refresh_token']) &&
      exactArray(metadata.scopes_supported, MCP_SCOPES) &&
      metadata.revocation_endpoint === new URL('/revoke', issuerUrl).href &&
      exactArray(metadata.revocation_endpoint_auth_methods_supported, ['none']) &&
      metadata.registration_endpoint === new URL('/register', issuerUrl).href,
    'Authorization-server metadata check failed',
  )

  console.log(JSON.stringify({
    ok: true,
    issuer: issuerUrl.href,
    resource: resourceUrl.href,
  }))
}

const deadlineSignal = AbortSignal.timeout(5_000)

try {
  await run(deadlineSignal)
} catch (error) {
  console.error(
    deadlineSignal.aborted
      ? 'HTTP OAuth smoke timed out'
      : error instanceof SmokeError
        ? error.message
        : 'HTTP OAuth smoke failed',
  )
  process.exitCode = 1
}
