import { randomUUID } from "node:crypto";

import { ZENDESK_SCOPES } from "./constants.js";
import { ZendeskUpstreamError, type ZendeskErrorCategory } from "./errors.js";
import type { ZendeskGrant } from "./store.js";

const ACCESS_TTL_SECONDS = 1_800;
const REFRESH_TTL_SECONDS = 2_592_000;
const APPROVED_SCOPE = ZENDESK_SCOPES.join(" ");

export interface ZendeskOAuthGateway {
  createAuthorizationUrl(state: string): URL;
  exchangeAuthorizationCode(code: string, signal?: AbortSignal): Promise<ZendeskGrant>;
  refreshCredential(refreshToken: string, signal?: AbortSignal): Promise<ZendeskGrant>;
  getCurrentUser(accessToken: string, signal?: AbortSignal): Promise<{ zendeskUserId: string }>;
  revokeCurrentToken(accessToken: string, signal?: AbortSignal): Promise<void>;
}

export type ZendeskOAuthClientOptions = {
  subdomain: string;
  clientId: string;
  clientSecret: string;
  callbackUrl: URL;
  scopes: readonly string[];
  timeoutMs: number;
  shutdownSignal?: AbortSignal;
  fetch?: typeof globalThis.fetch;
  now?: () => number;
};

type TokenResponse = {
  access_token: string;
  refresh_token: string;
  token_type: string;
  scope: string;
  expires_in: number;
  refresh_token_expires_in: number;
};

type ErrorClassification = {
  category: ZendeskErrorCategory;
  retryable: boolean;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

function hasApprovedScopes(scopes: readonly string[]): boolean {
  return scopes.length === ZENDESK_SCOPES.length
    && ZENDESK_SCOPES.every((scope) => scopes.includes(scope));
}

function parseTokenResponse(value: unknown): TokenResponse | undefined {
  if (!isRecord(value)) return undefined;
  const accessToken = value.access_token;
  const refreshToken = value.refresh_token;
  const tokenType = value.token_type;
  const scope = value.scope;
  const expiresIn = value.expires_in;
  const refreshTokenExpiresIn = value.refresh_token_expires_in;
  if (
    typeof accessToken !== "string"
    || accessToken.length === 0
    || typeof refreshToken !== "string"
    || refreshToken.length === 0
    || typeof tokenType !== "string"
    || tokenType.toLowerCase() !== "bearer"
    || scope !== APPROVED_SCOPE
    || !isPositiveInteger(expiresIn)
    || !isPositiveInteger(refreshTokenExpiresIn)
  ) {
    return undefined;
  }
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: tokenType,
    scope,
    expires_in: expiresIn,
    refresh_token_expires_in: refreshTokenExpiresIn,
  };
}

function classifyStatus(status: number, invalidGrant: boolean): ErrorClassification {
  if (invalidGrant) return { category: "invalid_grant", retryable: false };
  if (status === 401) return { category: "unauthorized", retryable: false };
  if (status === 403) return { category: "forbidden", retryable: false };
  if (status === 429) return { category: "rate_limited", retryable: true };
  if (status >= 500) return { category: "temporarily_unavailable", retryable: true };
  return { category: "invalid_request", retryable: false };
}

function upstreamError(
  category: ZendeskErrorCategory,
  status: number | undefined,
  retryable: boolean,
): ZendeskUpstreamError {
  return new ZendeskUpstreamError(category, status, retryable, randomUUID());
}

function combineAbortSignals(
  timeoutMs: number,
  signals: readonly (AbortSignal | undefined)[],
): { signal: AbortSignal; dispose: () => void } {
  const controller = new AbortController();
  const abort = () => controller.abort();
  const activeSignals = signals.filter((signal): signal is AbortSignal => signal !== undefined);
  for (const signal of activeSignals) {
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  }
  const timeout = setTimeout(abort, timeoutMs);
  return {
    signal: controller.signal,
    dispose: () => {
      clearTimeout(timeout);
      for (const signal of activeSignals) signal.removeEventListener("abort", abort);
    },
  };
}

export class ZendeskOAuthClient implements ZendeskOAuthGateway {
  readonly #origin: URL;
  readonly #clientId: string;
  readonly #clientSecret: string;
  readonly #callbackUrl: URL;
  readonly #timeoutMs: number;
  readonly #shutdownSignal: AbortSignal | undefined;
  readonly #fetch: typeof globalThis.fetch;
  readonly #now: () => number;

  constructor(options: ZendeskOAuthClientOptions) {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(options.subdomain)) {
      throw new Error("subdomain must be one DNS label");
    }
    if (!hasApprovedScopes(options.scopes)) {
      throw new Error(`scopes must be exactly ${APPROVED_SCOPE}`);
    }
    if (!Number.isInteger(options.timeoutMs) || options.timeoutMs <= 0) {
      throw new Error("timeoutMs must be a positive integer");
    }
    this.#origin = new URL(`https://${options.subdomain}.zendesk.com`);
    this.#clientId = options.clientId;
    this.#clientSecret = options.clientSecret;
    this.#callbackUrl = new URL(options.callbackUrl.href);
    this.#timeoutMs = options.timeoutMs;
    this.#shutdownSignal = options.shutdownSignal;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1_000));
  }

  createAuthorizationUrl(state: string): URL {
    const url = new URL("/oauth/authorizations/new", this.#origin);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: this.#clientId,
      redirect_uri: this.#callbackUrl.href,
      scope: APPROVED_SCOPE,
      state,
      expires_in: String(ACCESS_TTL_SECONDS),
      refresh_token_expires_in: String(REFRESH_TTL_SECONDS),
    }).toString();
    return url;
  }

  exchangeAuthorizationCode(code: string, signal?: AbortSignal): Promise<ZendeskGrant> {
    return this.#requestGrant({
      grant_type: "authorization_code",
      code,
      client_id: this.#clientId,
      client_secret: this.#clientSecret,
      redirect_uri: this.#callbackUrl.href,
      scope: APPROVED_SCOPE,
      expires_in: ACCESS_TTL_SECONDS,
      refresh_token_expires_in: REFRESH_TTL_SECONDS,
    }, signal);
  }

  refreshCredential(refreshToken: string, signal?: AbortSignal): Promise<ZendeskGrant> {
    return this.#requestGrant({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.#clientId,
      client_secret: this.#clientSecret,
      scope: APPROVED_SCOPE,
      expires_in: ACCESS_TTL_SECONDS,
      refresh_token_expires_in: REFRESH_TTL_SECONDS,
    }, signal);
  }

  async getCurrentUser(
    accessToken: string,
    signal?: AbortSignal,
  ): Promise<{ zendeskUserId: string }> {
    const response = await this.#request("/api/v2/users/me.json", {
      method: "GET",
      headers: { authorization: `Bearer ${accessToken}` },
    }, signal, true);
    const body = response.body;
    if (!isRecord(body) || !isRecord(body.user) || !isPositiveInteger(body.user.id)) {
      throw upstreamError("invalid_response", response.status, false);
    }
    return { zendeskUserId: String(body.user.id) };
  }

  async revokeCurrentToken(accessToken: string, signal?: AbortSignal): Promise<void> {
    await this.#request("/api/v2/oauth/tokens/current.json", {
      method: "DELETE",
      headers: { authorization: `Bearer ${accessToken}` },
    }, signal);
  }

  async #requestGrant(body: Record<string, unknown>, signal?: AbortSignal): Promise<ZendeskGrant> {
    const response = await this.#request("/oauth/tokens", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }, signal, true);
    const parsed = parseTokenResponse(response.body);
    if (!parsed) throw upstreamError("invalid_response", response.status, false);
    const now = Math.floor(this.#now());
    return {
      accessToken: parsed.access_token,
      refreshToken: parsed.refresh_token,
      accessExpiresAt: now + parsed.expires_in,
      refreshExpiresAt: now + parsed.refresh_token_expires_in,
      scopes: [...ZENDESK_SCOPES],
    };
  }

  async #request(
    pathname: string,
    init: RequestInit,
    callSignal?: AbortSignal,
    readJson = false,
  ): Promise<{ body: unknown; status: number }> {
    const { signal, dispose } = combineAbortSignals(
      this.#timeoutMs,
      [callSignal, this.#shutdownSignal],
    );
    try {
      const response = await this.#fetch(new URL(pathname, this.#origin), {
        ...init,
        redirect: "error",
        signal,
      });
      if (!response.ok) {
        let invalidGrant = false;
        try {
          const body: unknown = await response.json();
          invalidGrant = isRecord(body) && body.error === "invalid_grant";
        } catch {
          // The body is intentionally discarded after best-effort classification.
        }
        if (signal.aborted) throw upstreamError("aborted", undefined, false);
        const classification = classifyStatus(response.status, invalidGrant);
        throw upstreamError(classification.category, response.status, classification.retryable);
      }
      if (!readJson) return { body: undefined, status: response.status };
      try {
        return { body: await response.json(), status: response.status };
      } catch {
        if (signal.aborted) throw upstreamError("aborted", undefined, false);
        throw upstreamError("invalid_response", response.status, false);
      }
    } catch (error) {
      if (error instanceof ZendeskUpstreamError) throw error;
      if (signal.aborted) throw upstreamError("aborted", undefined, false);
      throw upstreamError("temporarily_unavailable", undefined, true);
    } finally {
      dispose();
    }
  }
}
