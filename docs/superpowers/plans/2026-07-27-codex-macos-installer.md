# Codex macOS Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a one-block macOS Codex installer to the one-time enrollment success page while retaining the complete TOML fallback.

**Architecture:** Extend the existing `enrollmentSuccessPage` renderer, which already owns the one-time bearer and canonical MCP URL. The installer will upsert the `zendesk` server through the Codex CLI, then add the persistent static authorization header without embedding the bearer in the copied command.

**Tech Stack:** TypeScript, Express, Node.js test runner, zsh, Codex CLI

## Global Constraints

- The entire installer is displayed in one `<pre>` element for a single copy-paste into macOS Terminal.
- The bearer is collected by a hidden terminal prompt and must not appear in the installer text.
- The installer validates `zmcp_` followed by exactly 43 base64url characters.
- The existing complete TOML configuration remains available as a manual fallback.
- The existing `no-store`, CSP, and browser security headers remain unchanged.
- No new endpoint, dependency, or client-side script is introduced.

---

### Task 1: Render the persistent Codex installer

**Files:**
- Modify: `test/oauth-linking.test.mjs`
- Modify: `src/internal-auth/link-handlers.ts`

**Interfaces:**
- Consumes: `enrollmentSuccessPage({ userId, bearer, mcpUrl })` and the existing `/oauth/callback` response.
- Produces: success HTML containing `<pre id="codex-installer">` and `<pre id="codex-config">` blocks.

- [x] **Step 1: Write the failing route test**

Extend the eligible self-enrollment test to extract both identified `<pre>` blocks. Assert that the installer contains the literal canonical URL, hidden `read`, bearer-shape validation, `codex mcp add zendesk`, protected config write, masked verification, and restart instruction. Assert that it does not contain the newly issued bearer, while the manual fallback contains both the URL and that bearer.

- [x] **Step 2: Run the focused test to verify RED**

Run:

```bash
npm run build && node --test --test-name-pattern='self-service agent receives' test/oauth-linking.test.mjs
```

Expected: FAIL because `codex-installer` and `codex-config` identified blocks do not exist.

- [x] **Step 3: Implement the minimal renderer change**

Inside `enrollmentSuccessPage`, construct a fixed zsh installer string that:

```bash
set -e
umask 077
command -v codex >/dev/null
read -r -s "token?Paste MCP bearer: "
[[ "$token" =~ ^zmcp_[A-Za-z0-9_-]{43}$ ]]
codex mcp add zendesk --url "<canonical mcp URL>"
config="$HOME/.codex/config.toml"
chmod 600 "$config"
printf '\n[mcp_servers.zendesk.http_headers]\nAuthorization = "Bearer %s"\n' "$token" >> "$config"
unset token
codex mcp get zendesk
```

Render the escaped installer under a recommended heading and the existing escaped full TOML fragment under a manual fallback heading.

- [x] **Step 4: Run the focused test to verify GREEN**

Run:

```bash
npm run build && node --test --test-name-pattern='self-service agent receives' test/oauth-linking.test.mjs
```

Expected: PASS.

- [x] **Step 5: Run integrated verification**

Run:

```bash
npm run check
npm test
npm audit
npm run smoke:http:local
docker compose build
docker compose up -d --build --force-recreate --wait
docker compose ps
curl --fail --silent http://127.0.0.1:38184/healthz
```

Expected: all commands exit 0, all tests pass, the audit reports no vulnerabilities, and the local container is healthy. Preserve the existing Docker volume and enrollment database.

- [x] **Step 6: Commit and push the scoped change**

```bash
git add src/internal-auth/link-handlers.ts test/oauth-linking.test.mjs docs/superpowers/specs/2026-07-27-codex-macos-installer-design.md docs/superpowers/plans/2026-07-27-codex-macos-installer.md
git commit -m "feat: add Codex macOS enrollment installer"
git push origin codex/zendesk-internal-user-bearers
```
