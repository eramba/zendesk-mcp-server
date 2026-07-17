import { randomUUID } from "node:crypto";

import type { Request, Response } from "express";

import { ZendeskUpstreamError } from "./errors.js";
import type {
  OAuthRedirectContext,
  OAuthStore,
  ZendeskCallbackContext,
  LoginCommitResult,
} from "./store.js";
import type { ZendeskOAuthGateway } from "./zendesk-oauth-client.js";

const ERROR_CSP = "default-src 'none'; frame-ancestors 'none'";

type CallbackError = "access_denied" | "server_error" | "temporarily_unavailable";

export type ZendeskCallbackControllerOptions = {
  store: OAuthStore;
  zendesk: ZendeskOAuthGateway;
  subdomain: string;
  now?: () => number;
};

function scalarQueryField(req: Request, name: string): string | undefined {
  const value = req.query[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function hasQueryField(req: Request, name: string): boolean {
  return Object.prototype.hasOwnProperty.call(req.query, name);
}

function appendErrorRedirect(
  context: OAuthRedirectContext,
  error: CallbackError,
): URL {
  const redirect = new URL(context.redirectUri);
  redirect.searchParams.set("error", error);
  if (context.originalState !== undefined) {
    redirect.searchParams.set("state", context.originalState);
  }
  return redirect;
}

function appendSuccessRedirect(
  context: OAuthRedirectContext,
  authorizationCode: string,
): URL {
  const redirect = new URL(context.redirectUri);
  redirect.searchParams.set("code", authorizationCode);
  if (context.originalState !== undefined) {
    redirect.searchParams.set("state", context.originalState);
  }
  return redirect;
}

function classifyFailure(error: unknown): CallbackError {
  return error instanceof ZendeskUpstreamError && error.retryable
    ? "temporarily_unavailable"
    : "server_error";
}

function hardenBrowserResponse(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
}

function renderUntrustedError(res: Response): void {
  const correlationId = randomUUID();
  hardenBrowserResponse(res);
  res.setHeader("Content-Security-Policy", ERROR_CSP);
  res.setHeader("X-Frame-Options", "DENY");
  res.status(400).type("html").send(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Unable to continue</title></head>
<body><main><h1>Unable to continue</h1><p>The request could not be completed. Reference correlation ${correlationId}.</p></main></body>
</html>`);
}

export class ZendeskCallbackController {
  readonly #store: OAuthStore;
  readonly #zendesk: ZendeskOAuthGateway;
  readonly #subdomain: string;
  readonly #now: () => number;

  constructor(options: ZendeskCallbackControllerOptions) {
    this.#store = options.store;
    this.#zendesk = options.zendesk;
    this.#subdomain = options.subdomain;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1_000));
  }

  readonly handle = async (req: Request, res: Response): Promise<void> => {
    const upstreamState = scalarQueryField(req, "state");
    if (upstreamState === undefined) {
      renderUntrustedError(res);
      return;
    }

    let callback: ZendeskCallbackContext | undefined;
    try {
      callback = this.#store.claimZendeskCallback(upstreamState, this.#now());
    } catch {
      renderUntrustedError(res);
      return;
    }
    if (callback === undefined) {
      renderUntrustedError(res);
      return;
    }

    const upstreamError = scalarQueryField(req, "error");
    if (hasQueryField(req, "error")) {
      await this.#failTrusted(
        callback,
        undefined,
        upstreamError === "access_denied" ? "access_denied" : "server_error",
        res,
      );
      return;
    }

    const code = scalarQueryField(req, "code");
    if (code === undefined) {
      await this.#failTrusted(callback, undefined, "server_error", res);
      return;
    }

    let stageId: string | undefined;
    let committed: LoginCommitResult;
    try {
      const grant = await this.#zendesk.exchangeAuthorizationCode(code);
      stageId = this.#store.stageLoginGrant({
        transactionId: callback.transactionId,
        subdomain: this.#subdomain,
        grant,
        now: this.#now(),
      }).stageId;
      const identity = await this.#zendesk.getCurrentUser(grant.accessToken);
      committed = this.#store.commitLogin({
        transactionId: callback.transactionId,
        stageId,
        zendeskUserId: identity.zendeskUserId,
        now: this.#now(),
      });
    } catch (error) {
      await this.#failTrusted(callback, stageId, classifyFailure(error), res);
      return;
    }

    hardenBrowserResponse(res);
    res.redirect(302, appendSuccessRedirect(
      committed,
      committed.authorizationCode,
    ).href);
  };

  async #failTrusted(
    callback: ZendeskCallbackContext,
    stageId: string | undefined,
    error: CallbackError,
    res: Response,
  ): Promise<void> {
    if (stageId !== undefined) {
      try {
        this.#store.discardStagedGrant(stageId, this.#now());
      } catch {
        // The staged grant remains unavailable and startup recovery fails it closed.
      }
    }
    try {
      this.#store.failLogin(callback.transactionId, this.#now());
    } catch {
      // The already claimed transaction remains unavailable for replay.
    }

    hardenBrowserResponse(res);
    res.redirect(302, appendErrorRedirect(callback, error).href);
  }
}
