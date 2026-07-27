import { createHash } from "node:crypto";

import type { RequestHandler, Response } from "express";

import { randomOpaque } from "./crypto.js";
import { SafeAuthError } from "./errors.js";
import type { InternalAuthStore, OAuthGrant } from "./store.js";
import {
  isEligibleZendeskIdentity,
  type ZendeskOAuthGateway,
} from "./zendesk-oauth.js";

const INVALID_LINK_PAGE =
  "<!doctype html><title>Link unavailable</title><p>This linking URL is invalid, expired, or already used.</p>";
const INVALID_CALLBACK_PAGE =
  "<!doctype html><title>Link failed</title><p>This authorization callback is invalid or expired. Ask the administrator for a new linking URL.</p>";
const FAILED_CALLBACK_PAGE =
  "<!doctype html><title>Link failed</title><p>Zendesk linking could not be completed. Ask the administrator for help.</p>";
const INELIGIBLE_PAGE =
  "<!doctype html><title>Enrollment unavailable</title><p>Only Zendesk agents and administrators can create an MCP account.</p>";
const ALREADY_REGISTERED_PAGE =
  "<!doctype html><title>Already registered</title><p>This Zendesk identity is already registered. Contact the administrator if you need help with your bearer.</p>";
const SUCCESS_PAGE =
  "<!doctype html><title>Zendesk linked</title><p>Your Zendesk identity is linked. You can close this window.</p>";
const PAGE_STYLES = `
:root {
  color-scheme: light;
  font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #172033;
  background: #f4f7fb;
  font-synthesis: none;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at top left, rgba(63, 81, 181, 0.13), transparent 32rem),
    linear-gradient(180deg, #f8faff 0%, #eef3f9 100%);
}
.page {
  width: min(100% - 32px, 980px);
  margin: 0 auto;
  padding: 48px 0 64px;
}
.card {
  overflow: hidden;
  padding: clamp(24px, 5vw, 52px);
  border: 1px solid #dce4ef;
  border-radius: 24px;
  background: rgba(255, 255, 255, 0.96);
  box-shadow: 0 24px 64px rgba(27, 39, 67, 0.12);
}
.card--compact { max-width: 680px; margin: 8vh auto 0; }
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 28px;
  color: #4053b5;
  font-size: 14px;
  font-weight: 750;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.brand-mark {
  display: grid;
  width: 34px;
  height: 34px;
  place-items: center;
  border-radius: 10px;
  color: #fff;
  background: linear-gradient(135deg, #5367d5, #293a91);
  box-shadow: 0 8px 18px rgba(64, 83, 181, 0.28);
}
h1, h2 { margin: 0; color: #101827; letter-spacing: -0.025em; }
h1 { max-width: 760px; font-size: clamp(32px, 5vw, 48px); line-height: 1.08; }
h2 { font-size: clamp(22px, 3vw, 28px); line-height: 1.2; }
p { color: #506078; font-size: 16px; line-height: 1.65; }
.lead { max-width: 720px; margin: 16px 0 30px; font-size: 18px; }
.notice {
  display: flex;
  gap: 14px;
  margin: 28px 0;
  padding: 16px 18px;
  border: 1px solid #f2cf82;
  border-radius: 14px;
  color: #6b4700;
  background: #fff9e9;
  line-height: 1.5;
}
.notice-mark { font-size: 20px; line-height: 1.2; }
.credentials {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
  margin: 28px 0 38px;
}
.credential {
  min-width: 0;
  padding: 16px;
  border: 1px solid #dde5f0;
  border-radius: 14px;
  background: #f8faff;
}
.label {
  display: block;
  margin-bottom: 9px;
  color: #65738a;
  font-size: 12px;
  font-weight: 750;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.section {
  margin-top: 26px;
  padding-top: 30px;
  border-top: 1px solid #e5eaf1;
}
.section-heading { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.badge {
  display: inline-flex;
  align-items: center;
  min-height: 26px;
  padding: 4px 10px;
  border-radius: 999px;
  color: #283b9a;
  background: #e9edff;
  font-size: 12px;
  font-weight: 750;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
pre {
  max-width: 100%;
  margin: 14px 0 0;
  padding: 18px 20px;
  overflow: auto;
  border: 1px solid #1e2c46;
  border-radius: 14px;
  color: #d8e5ff;
  background: #0d1729;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.06);
  font: 13px/1.55 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  tab-size: 2;
  white-space: pre;
}
.credential pre {
  margin: 0;
  padding: 0;
  border: 0;
  border-radius: 0;
  color: #24314a;
  background: transparent;
  box-shadow: none;
  font-size: 13px;
}
button {
  min-height: 48px;
  padding: 0 22px;
  border: 0;
  border-radius: 12px;
  color: #fff;
  background: linear-gradient(135deg, #4e64d4, #30439e);
  box-shadow: 0 10px 22px rgba(48, 67, 158, 0.24);
  cursor: pointer;
  font: inherit;
  font-weight: 700;
}
button:hover { filter: brightness(1.05); }
button:focus-visible { outline: 3px solid #aab7ff; outline-offset: 3px; }
.footnote { margin: 20px 0 0; color: #748198; font-size: 14px; }
@media (max-width: 680px) {
  .page { width: min(100% - 20px, 980px); padding: 18px 0 32px; }
  .card { padding: 24px 18px; border-radius: 18px; }
  .credentials { grid-template-columns: 1fr; }
  .section-heading { align-items: flex-start; flex-direction: column; }
  pre { padding: 15px; font-size: 12px; }
}`;
const PAGE_STYLE_HASH = createHash("sha256")
  .update(PAGE_STYLES)
  .digest("base64");
const PAGE_HEAD = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>${PAGE_STYLES}</style>`;
const CREATE_ACCOUNT_PAGE = `<!doctype html>
<html lang="en">
<head>
${PAGE_HEAD}
<title>Create Zendesk MCP account</title>
</head>
<body>
<main class="page">
  <section class="card card--compact">
    <div class="brand"><span class="brand-mark" aria-hidden="true">Z</span>Zendesk MCP</div>
    <h1>Create your MCP account</h1>
    <p class="lead">Connect your Zendesk agent or administrator identity to receive one personal MCP bearer.</p>
    <form method="post" action="/create-account">
      <button type="submit">Connect Zendesk</button>
    </form>
    <p class="footnote">You will review access in Zendesk before anything is connected.</p>
  </section>
</main>
</body>
</html>`;

type BrowserHeaderOptions = {
  referrerPolicy?: "no-referrer" | "same-origin";
  formActionOrigin?: string;
};

function browserHeaders(
  response: Response,
  options: BrowserHeaderOptions = {},
): void {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Pragma", "no-cache");
  response.setHeader(
    "Referrer-Policy",
    options.referrerPolicy ?? "no-referrer",
  );
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader(
    "Content-Security-Policy",
    `default-src 'none'; style-src 'sha256-${PAGE_STYLE_HASH}'; form-action 'self'${options.formActionOrigin ? ` ${options.formActionOrigin}` : ""}; base-uri 'none'; frame-ancestors 'none'`,
  );
  response.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
}

function html(
  response: Response,
  status: number,
  body: string,
  options: BrowserHeaderOptions = {},
): void {
  browserHeaders(response, options);
  response.status(status).type("html").send(body);
}

function singleQuery(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function enrollmentSuccessPage(input: {
  userId: string;
  bearer: string;
  mcpUrl: string;
}): string {
  const installer = [
    "/bin/zsh -c '",
    "set -e",
    "umask 077",
    "command -v codex >/dev/null || {",
    '  echo "Codex CLI is not installed."',
    "  exit 1",
    "}",
    "",
    'read -r -s "token?Paste MCP bearer: "',
    "echo",
    "",
    '[[ "$token" =~ ^zmcp_[A-Za-z0-9_-]{43}$ ]] || {',
    '  echo "Invalid MCP bearer."',
    "  exit 1",
    "}",
    "",
    "codex mcp add zendesk \\",
    `  --url "${input.mcpUrl}"`,
    "",
    'config="$HOME/.codex/config.toml"',
    'chmod 600 "$config"',
    'printf "\\n[mcp_servers.zendesk.http_headers]\\nAuthorization = \\"Bearer %s\\"\\n" "$token" >> "$config"',
    "unset token",
    "",
    "codex mcp get zendesk",
    "echo",
    'echo "Zendesk MCP configured. Restart Codex."',
    "'",
  ].join("\n");
  const config = [
    "[mcp_servers.zendesk]",
    `url = "${input.mcpUrl}"`,
    "",
    "[mcp_servers.zendesk.http_headers]",
    `Authorization = "Bearer ${input.bearer}"`,
  ].join("\n");
  return `<!doctype html>
<html lang="en">
<head>
${PAGE_HEAD}
<title>Zendesk MCP account created</title>
</head>
<body>
<main class="page">
  <article class="card">
    <div class="brand"><span class="brand-mark" aria-hidden="true">Z</span>Zendesk MCP</div>
    <h1>Your account is ready</h1>
    <p class="lead">Your Zendesk identity is connected. Finish the setup in Codex using the recommended command below.</p>
    <div class="notice" role="alert"><span class="notice-mark" aria-hidden="true">!</span><strong>The MCP bearer is displayed once and cannot be recovered. Copy it now.</strong></div>
    <section class="credentials" aria-label="Account credentials">
      <div class="credential"><span class="label">User ID</span><pre>${escapeHtml(input.userId)}</pre></div>
      <div class="credential"><span class="label">MCP bearer</span><pre>${escapeHtml(input.bearer)}</pre></div>
    </section>
    <section class="section">
      <div class="section-heading"><span class="badge">Recommended</span><h2>Configure Codex automatically</h2></div>
      <p>Copy and run this entire command in Terminal. When prompted, paste the MCP bearer shown above and press Enter. Restart Codex when it finishes.</p>
      <pre id="codex-installer">${escapeHtml(installer)}</pre>
    </section>
    <section class="section">
      <h2>Manual fallback</h2>
      <p>If the installer cannot be used, replace the existing zendesk block in ~/.codex/config.toml with this complete configuration:</p>
      <pre id="codex-config">${escapeHtml(config)}</pre>
    </section>
  </article>
</main>
</body>
</html>`;
}

async function revokeBestEffort(
  oauth: ZendeskOAuthGateway,
  grant: OAuthGrant,
): Promise<void> {
  await oauth.revokeCurrent(grant.accessToken).catch(() => undefined);
}

export function createLinkHandlers(options: {
  store: InternalAuthStore;
  oauth: ZendeskOAuthGateway;
  publicBaseUrl: URL;
  zendeskAuthorizationOrigin: URL;
  selfServiceEnabled: boolean;
  now?: () => number;
}): {
  link: RequestHandler;
  createAccount: RequestHandler;
  startEnrollment: RequestHandler;
  callback: RequestHandler;
} {
  const publicBaseUrl = new URL(options.publicBaseUrl.href);
  const zendeskAuthorizationOrigin = new URL(
    options.zendeskAuthorizationOrigin.origin,
  );
  const selfServiceEnabled = options.selfServiceEnabled;

  const createAccount: RequestHandler = (_request, response) => {
    if (!selfServiceEnabled) {
      html(response, 404, "<!doctype html><title>Not found</title>");
      return;
    }
    html(response, 200, CREATE_ACCOUNT_PAGE, {
      referrerPolicy: "same-origin",
      formActionOrigin: zendeskAuthorizationOrigin.origin,
    });
  };

  const startEnrollment: RequestHandler = (request, response) => {
    if (!selfServiceEnabled) {
      html(response, 404, "<!doctype html><title>Not found</title>");
      return;
    }
    if (request.get("origin") !== publicBaseUrl.origin) {
      html(
        response,
        403,
        "<!doctype html><title>Enrollment denied</title><p>This enrollment request is not allowed.</p>",
      );
      return;
    }

    try {
      const enrollment = options.store.createSelfEnrollment();
      const upstream = options.oauth.authorizationUrl(enrollment.state);
      browserHeaders(response);
      response.redirect(302, upstream.href);
    } catch {
      console.error("OAuth self-service enrollment start failed");
      html(response, 503, FAILED_CALLBACK_PAGE);
    }
  };

  const link: RequestHandler = (request, response) => {
    browserHeaders(response);
    const invitation = singleQuery(request.query.invitation);
    if (!invitation || !/^[A-Za-z0-9_-]{43}$/.test(invitation)) {
      html(response, 400, INVALID_LINK_PAGE);
      return;
    }

    const state = randomOpaque();
    const started = options.store.startInvitation(invitation, state);
    if (!started) {
      html(response, 410, INVALID_LINK_PAGE);
      return;
    }

    try {
      const upstream = options.oauth.authorizationUrl(state);
      response.redirect(302, upstream.href);
    } catch {
      console.error("OAuth linking start failed");
      html(response, 500, FAILED_CALLBACK_PAGE);
    }
  };

  const callback: RequestHandler = async (request, response) => {
    browserHeaders(response);
    const state = singleQuery(request.query.state);
    const code = singleQuery(request.query.code);
    const upstreamError = singleQuery(request.query.error);
    if (
      !state ||
      !/^[A-Za-z0-9_-]{43}$/.test(state) ||
      (code === undefined && upstreamError === undefined) ||
      (code !== undefined && upstreamError !== undefined)
    ) {
      html(response, 400, INVALID_CALLBACK_PAGE);
      return;
    }

    const claimed = options.store.claimAuthorization(state);
    if (!claimed) {
      html(response, 400, INVALID_CALLBACK_PAGE);
      return;
    }
    if (upstreamError !== undefined || code === undefined) {
      html(response, 400, INVALID_CALLBACK_PAGE);
      return;
    }

    const controller = new AbortController();
    const abort = () => controller.abort();
    request.once("aborted", abort);
    let grant: OAuthGrant | undefined;
    try {
      grant = await options.oauth.exchangeCode(code, controller.signal);
      const identity = await options.oauth.currentUser(
        grant.accessToken,
        controller.signal,
      );

      if (claimed.kind === "invitation") {
        options.store.completeLink({
          ...claimed,
          identity,
          grant,
        });
        html(response, 200, SUCCESS_PAGE);
        return;
      }

      if (!isEligibleZendeskIdentity(identity)) {
        await revokeBestEffort(options.oauth, grant);
        html(response, 403, INELIGIBLE_PAGE);
        return;
      }
      const created = options.store.completeSelfEnrollment({
        enrollmentId: claimed.enrollmentId,
        identity,
        grant,
      });
      if (created.kind === "already_registered") {
        await revokeBestEffort(options.oauth, grant);
        html(response, 409, ALREADY_REGISTERED_PAGE);
        return;
      }
      html(
        response,
        200,
        enrollmentSuccessPage({
          userId: created.userId,
          bearer: created.bearer,
          mcpUrl: new URL("/mcp", publicBaseUrl).href,
        }),
      );
    } catch (error) {
      if (grant) await revokeBestEffort(options.oauth, grant);
      if (error instanceof SafeAuthError) {
        console.error(
          `OAuth linking failed (${error.category}, ${error.correlationId})`,
        );
      } else {
        console.error("OAuth linking failed");
      }
      if (!response.headersSent) {
        html(response, 502, FAILED_CALLBACK_PAGE);
      }
    } finally {
      request.removeListener("aborted", abort);
    }
  };

  return { link, createAccount, startEnrollment, callback };
}
