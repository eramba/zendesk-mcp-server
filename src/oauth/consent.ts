import type { Request, RequestHandler, Response } from "express";
import type { AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

import { OAUTH_PATHS } from "./constants.js";
import type { OAuthStore } from "./store.js";
import type { AuthorizationStarter } from "./zendesk-broker-provider.js";
import type { ZendeskOAuthGateway } from "./zendesk-oauth-client.js";

const CONSENT_COOKIE = "__Secure-zendesk_oauth_consent";
const CONSENT_COOKIE_ATTRIBUTES =
  `HttpOnly; Secure; SameSite=Strict; Path=${OAUTH_PATHS.consent}`;
const CLEAR_CONSENT_COOKIE =
  `${CONSENT_COOKIE}=; ${CONSENT_COOKIE_ATTRIBUTES}; Max-Age=0`;
const CONSENT_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'";

export type ConsentControllerOptions = {
  store: OAuthStore;
  zendesk: ZendeskOAuthGateway;
  publicBaseUrl: URL;
  subdomain: string;
  now?: () => number;
};

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    switch (character) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      default: return "&#39;";
    }
  });
}

function isFormContentType(value: string | undefined): boolean {
  return value?.split(";", 1)[0]?.trim().toLowerCase()
    === "application/x-www-form-urlencoded";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hardenConsentPostResponse(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Set-Cookie", CLEAR_CONSENT_COOKIE);
}

export const consentPostResponseHeaders: RequestHandler = (_req, res, next) => {
  hardenConsentPostResponse(res);
  next();
};

function readNamedCookie(header: string | undefined): string | undefined {
  if (header === undefined) return undefined;
  const matches: string[] = [];
  for (const segment of header.split(";")) {
    const separator = segment.indexOf("=");
    if (separator < 0) continue;
    const name = segment.slice(0, separator).trim();
    if (name === CONSENT_COOKIE) matches.push(segment.slice(separator + 1));
  }
  return matches.length === 1 && /^[A-Za-z0-9_-]+$/.test(matches[0])
    ? matches[0]
    : undefined;
}

function renderConsentPage(
  client: OAuthClientInformationFull,
  params: AuthorizationParams,
  transactionToken: string,
  consentCsrf: string,
): string {
  const callbackHost = new URL(params.redirectUri).host;
  const resource = params.resource?.href;
  if (resource === undefined) throw new Error("consent resource is required");
  const clientName = client.client_name ?? "Unnamed OAuth client";
  const scopes = (params.scopes ?? [])
    .map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`)
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Authorize Zendesk MCP access</title>
  <style>
    body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;color:#172033}
    main{border:1px solid #cad2df;border-radius:.75rem;padding:1.5rem}code{overflow-wrap:anywhere}
    .warning{background:#fff4ce;border-radius:.4rem;padding:.75rem}.actions{display:flex;gap:.75rem;margin-top:1.5rem}
    button{font:inherit;padding:.6rem 1rem}button[value=confirm]{font-weight:700}
  </style>
</head>
<body>
<main>
  <h1>Authorize Zendesk MCP access</h1>
  <p><strong>Unverified client name:</strong> ${escapeHtml(clientName)}</p>
  <p><strong>Callback host and port:</strong> <code>${escapeHtml(callbackHost)}</code></p>
  <p><strong>Resource:</strong> <code>${escapeHtml(resource)}</code></p>
  <p><strong>Requested MCP scopes:</strong></p>
  <ul>${scopes}</ul>
  <p class="warning"><strong>Warning:</strong> A localhost callback can be impersonated by another local process. Continue only if you initiated this login.</p>
  <form method="post" action="${OAUTH_PATHS.consent}">
    <input type="hidden" name="transaction" value="${escapeHtml(transactionToken)}">
    <input type="hidden" name="csrf" value="${escapeHtml(consentCsrf)}">
    <div class="actions">
      <button type="submit" name="decision" value="confirm">Continue to Zendesk</button>
      <button type="submit" name="decision" value="deny">Deny</button>
    </div>
  </form>
</main>
</body>
</html>`;
}

export class ConsentController {
  readonly #store: OAuthStore;
  readonly #zendesk: ZendeskOAuthGateway;
  readonly #publicOrigin: string;
  readonly #subdomain: string;
  readonly #now: () => number;

  constructor(options: ConsentControllerOptions) {
    this.#store = options.store;
    this.#zendesk = options.zendesk;
    this.#publicOrigin = new URL(options.publicBaseUrl.href).origin;
    this.#subdomain = options.subdomain;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1_000));
  }

  readonly begin: AuthorizationStarter = async (client, params, res) => {
    const resource = params.resource?.href;
    if (resource === undefined) throw new Error("consent resource is required");
    const started = this.#store.beginLogin({
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      scopes: params.scopes ?? [],
      resource,
      originalState: params.state,
      subdomain: this.#subdomain,
      now: this.#now(),
    });

    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Content-Security-Policy", CONSENT_CSP);
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader(
      "Set-Cookie",
      `${CONSENT_COOKIE}=${started.browserNonce}; ${CONSENT_COOKIE_ATTRIBUTES}; Max-Age=600`,
    );
    res.status(200).type("html").send(renderConsentPage(
      client,
      params,
      started.transactionToken,
      started.consentCsrf,
    ));
  };

  readonly handlePost = async (req: Request, res: Response): Promise<void> => {
    hardenConsentPostResponse(res);

    const browserNonce = readNamedCookie(req.headers.cookie);
    const body: unknown = req.body;
    if (
      !isFormContentType(req.headers["content-type"])
      || req.headers.origin !== this.#publicOrigin
      || browserNonce === undefined
      || !isRecord(body)
      || Object.keys(body).length !== 3
      || typeof body.transaction !== "string"
      || typeof body.csrf !== "string"
      || (body.decision !== "confirm" && body.decision !== "deny")
    ) {
      res.status(400).type("text").send("Invalid consent request");
      return;
    }

    const result = this.#store.decideConsent({
      transactionToken: body.transaction,
      consentCsrf: body.csrf,
      browserNonce,
      decision: body.decision,
      now: this.#now(),
    });
    if (result.kind === "invalid") {
      res.status(400).type("text").send("Invalid consent request");
      return;
    }

    if (result.kind === "confirmed") {
      const upstream = this.#zendesk.createAuthorizationUrl(result.upstreamState);
      res.redirect(302, upstream.href);
      return;
    }

    const redirect = new URL(result.redirectUri);
    redirect.searchParams.set("error", "access_denied");
    if (result.originalState !== undefined) {
      redirect.searchParams.set("state", result.originalState);
    }
    res.redirect(302, redirect.href);
  };
}
