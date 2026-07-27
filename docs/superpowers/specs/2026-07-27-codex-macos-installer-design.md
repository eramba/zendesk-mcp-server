# Codex macOS Installer Command Design

## Goal

Make the one-time self-enrollment success page usable by a non-technical macOS
colleague even when a stale `zendesk` MCP entry already exists in Codex.

## Recommended flow

The one-time success page continues to display the personal bearer. It then
shows these two configuration paths in this order:

1. A recommended, complete macOS shell command that the user copies into
   Terminal. The command prompts for the bearer without echoing it, validates
   its public shape, upserts the `zendesk` MCP URL through `codex mcp add`, adds
   the static `Authorization` header to `~/.codex/config.toml`, sets mode `0600`,
   masks the configured header through `codex mcp get zendesk`, and tells the
   user to restart Codex.
2. The existing complete TOML configuration fragment as a manual copy-paste
   fallback.

The installer does not run `codex mcp remove`. The current Codex CLI implements
`mcp add` as an upsert for the same server name, so the add operation replaces
the stale server entry before the new static header is appended.

## Installer shown on the page

The entire block below is shown in one `<pre>` element. The MCP URL is rendered
from the same canonical server-side `mcpUrl` already used by the TOML fallback.
The bearer is deliberately absent from the command so it is not copied into
shell history or exposed as a process argument.

```bash
/bin/zsh -c '
set -e
umask 077
command -v codex >/dev/null || {
  echo "Codex CLI is not installed."
  exit 1
}

read -r -s "token?Paste MCP bearer: "
echo

[[ "$token" =~ ^zmcp_[A-Za-z0-9_-]{43}$ ]] || {
  echo "Invalid MCP bearer."
  exit 1
}

codex mcp add zendesk \
  --url "${mcpUrl}"

config="$HOME/.codex/config.toml"
chmod 600 "$config"
printf "\n[mcp_servers.zendesk.http_headers]\nAuthorization = \"Bearer %s\"\n" "$token" >> "$config"
unset token

codex mcp get zendesk
echo
echo "Zendesk MCP configured. Restart Codex."
'
```

## Security and failure behavior

- The page keeps `Cache-Control: no-store` and the existing browser security
  headers.
- The bearer remains visible only on the one-time success page and the manual
  TOML fallback. It is not interpolated into the installer command.
- `read -s` prevents terminal echo, and the fixed installer text keeps the
  bearer out of shell history.
- The installer accepts only the existing `zmcp_` prefix followed by exactly 43
  base64url characters.
- `set -e` stops on a missing or failed Codex operation. `umask 077` and the
  pre-write `chmod 600` ensure the token is never appended to a permissive
  config file. A missing CLI or invalid
  bearer receives a bounded message that contains no secret.
- The generated MCP URL and every dynamic HTML value remain escaped before
  rendering.
- The static header is intentionally stored in the user's protected Codex
  configuration because this is the persistent behavior required across macOS
  restarts. The config is set to mode `0600`.

## Verification

Focused tests must prove that the success page:

- contains the complete installer command and complete TOML fallback;
- uses the canonical MCP URL in both outputs;
- contains no bearer value inside the installer command;
- contains the bearer in the one-time TOML fallback;
- HTML-escapes all dynamic output;
- retains the existing no-store and browser-security behavior.

The full TypeScript check, test suite, fake-only HTTP smoke test, and local
Docker build must pass. The rebuilt local deployment must remain healthy. A
real bearer must never be printed by verification commands.
