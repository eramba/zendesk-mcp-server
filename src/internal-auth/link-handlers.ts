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
const CREATE_ACCOUNT_PAGE = `<!doctype html>
<title>Create Zendesk MCP account</title>
<h1>Create Zendesk MCP account</h1>
<p>Connect your Zendesk agent or administrator identity to receive one personal MCP bearer.</p>
<form method="post" action="/create-account">
  <button type="submit">Connect Zendesk</button>
</form>`;

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
    `default-src 'none'; form-action 'self'${options.formActionOrigin ? ` ${options.formActionOrigin}` : ""}; base-uri 'none'; frame-ancestors 'none'`,
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
<title>Zendesk MCP account created</title>
<h1>Zendesk MCP account created</h1>
<p><strong>The MCP bearer is displayed once and cannot be recovered. Copy it now.</strong></p>
<p>user_id:</p><pre>${escapeHtml(input.userId)}</pre>
<p>mcp_bearer:</p><pre>${escapeHtml(input.bearer)}</pre>
<h2>Recommended: configure Codex automatically</h2>
<p>Copy and run this entire command in Terminal. When prompted, paste the MCP bearer shown above and press Enter. Restart Codex when it finishes.</p>
<pre id="codex-installer">${escapeHtml(installer)}</pre>
<h2>Manual fallback</h2>
<p>If the installer cannot be used, replace the existing zendesk block in ~/.codex/config.toml with this complete configuration:</p>
<pre id="codex-config">${escapeHtml(config)}</pre>`;
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
