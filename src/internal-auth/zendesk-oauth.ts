import type { OAuthGrant, ZendeskIdentity } from "./store.js";
import {
  SafeAuthError,
  type SafeAuthErrorCategory,
} from "./errors.js";

const ACCESS_TTL_SECONDS = 1_800;
const REFRESH_TTL_SECONDS = 2_592_000;
const APPROVED_SCOPES = ["read", "tickets:write"] as const;
const APPROVED_SCOPE = APPROVED_SCOPES.join(" ");
const MAX_ERROR_BODY_BYTES = 8_192;

export interface ZendeskOAuthGateway {
  authorizationUrl(state: string): URL;
  exchangeCode(code: string, signal?: AbortSignal): Promise<OAuthGrant>;
  refresh(refreshToken: string, signal?: AbortSignal): Promise<OAuthGrant>;
  currentUser(
    accessToken: string,
    signal?: AbortSignal,
  ): Promise<ZendeskIdentity>;
  revokeCurrent(accessToken: string, signal?: AbortSignal): Promise<void>;
}

export type ZendeskOAuthOptions = {
  subdomain: string;
  clientId: string;
  clientSecret: string;
  callbackUrl: URL;
  timeoutMs: number;
  signal?: AbortSignal;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

export function isEligibleZendeskIdentity(
  identity: ZendeskIdentity,
): boolean {
  return identity.role === "agent" || identity.role === "admin";
}

function parseTokenResponse(value: unknown): TokenResponse | undefined {
  if (!isRecord(value)) return undefined;
  const scopes = typeof value.scope === "string"
    ? [...new Set(value.scope.split(/\s+/).filter(Boolean))]
    : [];
  if (
    typeof value.access_token !== "string" ||
    value.access_token.length === 0 ||
    typeof value.refresh_token !== "string" ||
    value.refresh_token.length === 0 ||
    typeof value.token_type !== "string" ||
    value.token_type.toLowerCase() !== "bearer" ||
    scopes.length !== APPROVED_SCOPES.length ||
    !APPROVED_SCOPES.every((scope) => scopes.includes(scope)) ||
    !isPositiveSafeInteger(value.expires_in) ||
    !isPositiveSafeInteger(value.refresh_token_expires_in) ||
    value.refresh_token_expires_in <= value.expires_in
  ) {
    return undefined;
  }
  return {
    access_token: value.access_token,
    refresh_token: value.refresh_token,
    token_type: value.token_type,
    scope: value.scope as string,
    expires_in: value.expires_in,
    refresh_token_expires_in: value.refresh_token_expires_in,
  };
}

function combinedSignal(
  timeoutMs: number,
  signals: Array<AbortSignal | undefined>,
): { signal: AbortSignal; dispose(): void } {
  const controller = new AbortController();
  const active = signals.filter(
    (signal): signal is AbortSignal => signal !== undefined,
  );
  const abort = () => controller.abort();
  for (const signal of active) {
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  }
  const timeout = setTimeout(abort, timeoutMs);
  timeout.unref?.();
  return {
    signal: controller.signal,
    dispose() {
      clearTimeout(timeout);
      for (const signal of active) {
        signal.removeEventListener("abort", abort);
      }
    },
  };
}

async function readBoundedBody(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (length <= MAX_ERROR_BODY_BYTES) {
      const item = await reader.read();
      if (item.done) break;
      length += item.value.byteLength;
      if (length > MAX_ERROR_BODY_BYTES) break;
      chunks.push(item.value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString("utf8");
}

function classification(
  status: number,
  invalidGrant: boolean,
): { category: SafeAuthErrorCategory; retryable: boolean } {
  if (invalidGrant) return { category: "invalid_grant", retryable: false };
  if (status === 401) return { category: "unauthorized", retryable: false };
  if (status === 403) return { category: "forbidden", retryable: false };
  if (status === 429) return { category: "rate_limited", retryable: true };
  if (status >= 500 || (status >= 300 && status < 400)) {
    return { category: "temporarily_unavailable", retryable: true };
  }
  return { category: "invalid_response", retryable: false };
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

  constructor(options: ZendeskOAuthOptions) {
    if (
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(
        options.subdomain,
      )
    ) {
      throw new Error("Zendesk subdomain must be one DNS label");
    }
    if (
      options.clientId.length === 0 ||
      options.clientSecret.length === 0 ||
      !Number.isSafeInteger(options.timeoutMs) ||
      options.timeoutMs <= 0
    ) {
      throw new Error("Zendesk OAuth configuration is invalid");
    }
    this.#origin = new URL(
      `https://${options.subdomain.toLowerCase()}.zendesk.com`,
    );
    this.#clientId = options.clientId;
    this.#clientSecret = options.clientSecret;
    this.#callbackUrl = new URL(options.callbackUrl.href);
    this.#timeoutMs = options.timeoutMs;
    this.#shutdownSignal = options.signal;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1_000));
  }

  authorizationUrl(state: string): URL {
    if (!/^[A-Za-z0-9_-]{43}$/.test(state)) {
      throw new Error("OAuth state is invalid");
    }
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

  exchangeCode(code: string, signal?: AbortSignal): Promise<OAuthGrant> {
    return this.#grant(
      {
        grant_type: "authorization_code",
        code,
        client_id: this.#clientId,
        client_secret: this.#clientSecret,
        redirect_uri: this.#callbackUrl.href,
        scope: APPROVED_SCOPE,
        expires_in: ACCESS_TTL_SECONDS,
        refresh_token_expires_in: REFRESH_TTL_SECONDS,
      },
      signal,
    );
  }

  refresh(
    refreshToken: string,
    signal?: AbortSignal,
  ): Promise<OAuthGrant> {
    return this.#grant(
      {
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: this.#clientId,
        client_secret: this.#clientSecret,
        scope: APPROVED_SCOPE,
        expires_in: ACCESS_TTL_SECONDS,
        refresh_token_expires_in: REFRESH_TTL_SECONDS,
      },
      signal,
    );
  }

  async currentUser(
    accessToken: string,
    signal?: AbortSignal,
  ): Promise<ZendeskIdentity> {
    const body = await this.#requestJson(
      "/api/v2/users/me.json",
      {
        method: "GET",
        headers: { authorization: `Bearer ${accessToken}` },
      },
      signal,
    );
    if (!isRecord(body) || !isRecord(body.user)) {
      throw new SafeAuthError("invalid_response");
    }
    const id = body.user.id;
    const name = body.user.name;
    const email = body.user.email;
    const role = body.user.role;
    if (
      !isPositiveSafeInteger(id) ||
      (name !== undefined && name !== null && typeof name !== "string") ||
      (email !== undefined && email !== null && typeof email !== "string") ||
      (role !== "end-user" && role !== "agent" && role !== "admin")
    ) {
      throw new SafeAuthError("invalid_response");
    }
    return {
      id: String(id),
      name: typeof name === "string" && name.length > 0 ? name : null,
      email: typeof email === "string" && email.length > 0 ? email : null,
      role,
    };
  }

  async revokeCurrent(
    accessToken: string,
    signal?: AbortSignal,
  ): Promise<void> {
    await this.#request(
      "/api/v2/oauth/tokens/current.json",
      {
        method: "DELETE",
        headers: { authorization: `Bearer ${accessToken}` },
      },
      signal,
      false,
    );
  }

  async #grant(
    requestBody: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<OAuthGrant> {
    const body = await this.#requestJson(
      "/oauth/tokens",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(requestBody),
      },
      signal,
    );
    const parsed = parseTokenResponse(body);
    if (!parsed) throw new SafeAuthError("invalid_response");
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new SafeAuthError("invalid_response");
    }
    const accessExpiresAt = now + parsed.expires_in;
    const refreshExpiresAt = now + parsed.refresh_token_expires_in;
    if (
      !Number.isSafeInteger(accessExpiresAt) ||
      !Number.isSafeInteger(refreshExpiresAt)
    ) {
      throw new SafeAuthError("invalid_response");
    }
    return {
      accessToken: parsed.access_token,
      refreshToken: parsed.refresh_token,
      accessExpiresAt,
      refreshExpiresAt,
      scopes: [...APPROVED_SCOPES],
    };
  }

  #requestJson(
    path: string,
    init: RequestInit,
    signal?: AbortSignal,
  ): Promise<unknown> {
    return this.#request(path, init, signal, true);
  }

  async #request(
    path: string,
    init: RequestInit,
    callSignal: AbortSignal | undefined,
    readJson: boolean,
  ): Promise<unknown> {
    const combined = combinedSignal(this.#timeoutMs, [
      callSignal,
      this.#shutdownSignal,
    ]);
    try {
      const response = await this.#fetch(new URL(path, this.#origin), {
        ...init,
        redirect: "error",
        signal: combined.signal,
      });
      if (!response.ok) {
        const text = await readBoundedBody(response);
        let invalidGrant = false;
        try {
          const body: unknown = JSON.parse(text);
          invalidGrant = isRecord(body) && body.error === "invalid_grant";
        } catch {
          invalidGrant = false;
        }
        if (combined.signal.aborted) {
          throw new SafeAuthError("aborted");
        }
        const classified = classification(response.status, invalidGrant);
        throw new SafeAuthError(classified.category, {
          retryable: classified.retryable,
          status: response.status,
        });
      }
      if (!readJson) {
        await response.body?.cancel().catch(() => undefined);
        return undefined;
      }
      const text = await readBoundedBody(response);
      try {
        return JSON.parse(text);
      } catch {
        throw new SafeAuthError("invalid_response", {
          status: response.status,
        });
      }
    } catch (error) {
      if (error instanceof SafeAuthError) throw error;
      if (combined.signal.aborted) throw new SafeAuthError("aborted");
      throw new SafeAuthError("temporarily_unavailable", {
        retryable: true,
      });
    } finally {
      combined.dispose();
    }
  }
}
