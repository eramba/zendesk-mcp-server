import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const README = new URL('../README.md', import.meta.url)
const DOCKERFILE = new URL('../Dockerfile', import.meta.url)

test('documents separate stdio API-token and HTTP OAuth setup', async () => {
  const readme = await readFile(README, 'utf8')

  assert.match(readme, /\.env\.stdio\.example/)
  assert.match(readme, /\.env\.http\.example/)
  assert.match(readme, /\$\{PUBLIC_BASE_URL\}\/oauth\/zendesk\/callback/)
  assert.match(readme, /\bread tickets:write\b/)
  assert.match(readme, /tailscale serve --bg http:\/\/127\.0\.0\.1:38184(?:\s|`)/)

  const httpSection = readme.match(/### Streamable HTTP\n([\s\S]*?)(?=## Environment variables)/)?.[1]
  assert.ok(httpSection, 'README must retain a Streamable HTTP section')
  assert.doesNotMatch(httpSection, /MCP_BEARER_TOKEN|bearer_token_env_var\s*=/)
})

test('documents URL-only Codex login and exact local versus server revocation semantics', async () => {
  const readme = await readFile(README, 'utf8')
  const codexConfig = readme.match(/```toml\n\[mcp_servers\.zendesk\]\n([\s\S]*?)```/)?.[1]

  assert.ok(codexConfig, 'README must contain the Codex zendesk TOML entry')
  assert.match(codexConfig, /^url = "https:\/\/.+\/mcp"$/m)
  assert.doesNotMatch(codexConfig, /Authorization|bearer_token_env_var|env_http_headers|http_headers/)
  assert.match(readme, /codex mcp login zendesk/)
  assert.match(readme, /codex mcp logout zendesk/)
  assert.match(readme, /local(?:-only| credentials| token)|client-local/i)
  assert.match(readme, /npm run oauth:sessions -- --zendesk-user-id <id>/)
  assert.match(readme, /npm run oauth:revoke-family -- --family-id <id> --confirm/)
  assert.match(readme, /npm run oauth:disconnect-user -- --zendesk-user-id <id> --confirm/)
})

test('documents safe backup, restore, cutover, rollback, retirement, and orphan-grant recovery', async () => {
  const [readme, dockerfile] = await Promise.all([
    readFile(README, 'utf8'),
    readFile(DOCKERFILE, 'utf8'),
  ])
  const restore = readme.match(/## Backup and restore\n([\s\S]*?)(?=## Maintenance-window cutover)/)?.[1]

  assert.ok(restore, 'README must contain a bounded backup and restore section')
  const shellBlocks = [...restore.matchAll(/```bash\n([\s\S]*?)```/g)]
    .map((match) => match[1])
  const seed = shellBlocks.find((block) => block.includes('cp /restore-input/'))
  const verification = shellBlocks.find((block) =>
    block.includes('scripts/oauth-admin.mjs sessions'))
  assert.ok(seed, 'restore procedure must have a dedicated seed command')
  assert.ok(verification, 'restore procedure must have a dedicated admin verification command')
  assert.match(
    restore,
    /npm run oauth:backup -- --destination \/data\/backups\/<new-name>\.sqlite/,
  )
  assert.match(restore, /checkpoint/i)
  assert.match(restore, /disposable volume/i)
  assert.match(restore, /encryption key[\s\S]{0,120}(?:separate|separately)/i)
  assert.match(restore, /RESTORE_IMAGE="\$\(docker compose images --quiet zendesk-mcp\)"/)
  assert.match(restore, /--network none/)
  assert.match(restore, /--entrypoint node/)
  assert.match(restore, /protected root-owned backup/i)
  assert.match(seed, /--user root/)
  assert.match(
    seed,
    /cp \/restore-input\/<new-name>\.sqlite \/data\/oauth\.sqlite && chown node:node \/data\/oauth\.sqlite && chmod 0600 \/data\/oauth\.sqlite/,
  )
  assert.match(dockerfile, /^USER node$/m)
  assert.doesNotMatch(verification, /--user(?:=|\s+)root/)
  assert.match(seed, /set -euo pipefail/)
  assert.match(seed, /RESTORE_DRILL_NONCE="\$\(openssl rand -hex 16\)"/)
  assert.match(
    seed,
    /\[\[ "\$RESTORE_DRILL_NONCE" =~ \^\[0-9a-f\]\{32\}\$ \]\]/,
  )
  assert.match(
    seed,
    /RESTORE_DRILL_VOLUME="zendesk-oauth-restore-drill-\$\{RESTORE_DRILL_NONCE\}"/,
  )
  assert.match(
    seed,
    /\[\[ "\$RESTORE_DRILL_VOLUME" =~ \^zendesk-oauth-restore-drill-\[0-9a-f\]\{32\}\$ \]\]/,
  )
  assert.match(seed, /RESTORE_DRILL_CREATED=false/)
  assert.match(seed, /cleanup_restore_drill\(\)/)
  assert.match(seed, /\[\[ "\$RESTORE_DRILL_CREATED" == true \]\] \|\| return 0/)
  assert.match(seed, /docker volume inspect[\s\S]+"\$RESTORE_DRILL_VOLUME"/)
  assert.match(seed, /\[\[ "\$owned_nonce" == "\$RESTORE_DRILL_NONCE" \]\] \|\| return 1/)
  assert.match(seed, /docker volume rm "\$RESTORE_DRILL_VOLUME"/)
  assert.match(seed, /trap cleanup_restore_drill EXIT/)
  assert.match(
    seed,
    /docker volume create --label "zendesk\.oauth\.restore-drill=\$RESTORE_DRILL_NONCE" "\$RESTORE_DRILL_VOLUME"/,
  )
  assert.match(seed, /RESTORE_DRILL_CREATED=true/)
  assert.match(seed, /source="\$RESTORE_DRILL_VOLUME",target=\/data/)
  assert.match(verification, /source="\$RESTORE_DRILL_VOLUME",target=\/data/)
  assert.match(restore, /--env ZENDESK_SUBDOMAIN/)
  assert.match(restore, /--env OAUTH_ENCRYPTION_KEY/)
  assert.match(restore, /--env OAUTH_DB_PATH=\/data\/oauth\.sqlite/)
  assert.match(restore, /scripts\/oauth-admin\.mjs sessions --zendesk-user-id <known-id>/)
  assert.match(restore, /cleanup_restore_drill\n\s*trap - EXIT/)
  assert.doesNotMatch(
    restore,
    /docker volume (?:create|rm) zendesk-oauth-restore-drill(?:\s|$)/,
  )
  assert.doesNotMatch(restore, /npm (?:run )?start|docker compose up|start the same application image/i)
  assert.match(readme, /maintenance window/i)
  assert.match(readme, /inventory/i)
  assert.match(readme, /http_headers\.Authorization/)
  assert.match(readme, /bearer_token_env_var/)
  assert.match(readme, /env_http_headers\.Authorization/)
  assert.match(readme, /redact/i)
  assert.match(readme, /roll back|rollback/i)
  assert.match(readme, /image[\s\S]{0,100}environment[\s\S]{0,100}client config/i)
  assert.match(readme, /retir/i)
  assert.match(readme, /ordinary re-login|ordinary relogin/i)
  assert.match(readme, /orphan/i)
  assert.match(readme, /Zendesk tenant[\s-](?:side )?(?:token )?audit/i)
})
