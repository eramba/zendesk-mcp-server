import type { RequestHandler, Response } from "express";

import { randomOpaque } from "./crypto.js";
import { SafeAuthError } from "./errors.js";
import type { InternalAuthStore, OAuthGrant } from "./store.js";
import type { ZendeskOAuthGateway } from "./zendesk-oauth.js";

const INVALID_LINK_PAGE =
  "<!doctype html><title>Link unavailable</title><p>This linking URL is invalid, expired, or already used.</p>";
const INVALID_CALLBACK_PAGE =
  "<!doctype html><title>Link failed</title><p>This authorization callback is invalid or expired. Ask the administrator for a new linking URL.</p>";
const FAILED_CALLBACK_PAGE =
  "<!doctype html><title>Link failed</title><p>Zendesk linking could not be completed. Ask the administrator for a new linking URL.</p>";
const SUCCESS_PAGE =
  "<!doctype html><title>Zendesk linked</title><p>Your Zendesk identity is linked. You can close this window.</p>";

function browserHeaders(response: Response): void {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Pragma", "no-cache");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
}

function html(response: Response, status: number, body: string): void {
  browserHeaders(response);
  response.status(status).type("html").send(body);
}

function singleQuery(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function createLinkHandlers(options: {
  store: InternalAuthStore;
  oauth: ZendeskOAuthGateway;
  now?: () => number;
}): {
  link: RequestHandler;
  callback: RequestHandler;
} {
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

    const claimed = options.store.claimCallback(state);
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
      options.store.completeLink({
        ...claimed,
        identity,
        grant,
      });
      html(response, 200, SUCCESS_PAGE);
    } catch (error) {
      if (grant) {
        await options.oauth
          .revokeCurrent(grant.accessToken)
          .catch(() => undefined);
      }
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

  return { link, callback };
}
