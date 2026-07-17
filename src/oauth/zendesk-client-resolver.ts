import { randomUUID } from "node:crypto";

import { ZendeskClient } from "../zendesk-client.js";
import { REFRESH_SKEW_SECONDS } from "./constants.js";
import { ReauthorizationRequiredError } from "./errors.js";
import type {
  CredentialSnapshot,
  OAuthStore,
} from "./store.js";
import type { ZendeskOAuthGateway } from "./zendesk-oauth-client.js";

export interface ZendeskClientResolverLike {
  resolve(principalId: string): Promise<ZendeskClient>;
}

export type ZendeskClientResolverOptions = {
  store: OAuthStore;
  zendesk: ZendeskOAuthGateway;
  subdomain: string;
  now?: () => number;
  refreshSkewSeconds?: number;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
};

export class ZendeskClientResolver implements ZendeskClientResolverLike {
  readonly #store: OAuthStore;
  readonly #zendesk: ZendeskOAuthGateway;
  readonly #subdomain: string;
  readonly #now: () => number;
  readonly #refreshSkewSeconds: number;
  readonly #timeoutMs: number | undefined;
  readonly #fetch: typeof globalThis.fetch | undefined;
  readonly #refreshes = new Map<string, Promise<CredentialSnapshot>>();

  constructor(options: ZendeskClientResolverOptions) {
    const refreshSkewSeconds = options.refreshSkewSeconds ?? REFRESH_SKEW_SECONDS;
    if (!Number.isSafeInteger(refreshSkewSeconds) || refreshSkewSeconds < 0) {
      throw new Error("refreshSkewSeconds must be a non-negative integer");
    }
    if (
      options.timeoutMs !== undefined &&
      (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0)
    ) {
      throw new Error("timeoutMs must be a positive integer");
    }
    this.#store = options.store;
    this.#zendesk = options.zendesk;
    this.#subdomain = options.subdomain;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1_000));
    this.#refreshSkewSeconds = refreshSkewSeconds;
    this.#timeoutMs = options.timeoutMs;
    this.#fetch = options.fetch;
  }

  async resolve(principalId: string): Promise<ZendeskClient> {
    const snapshot = this.#store.loadCredential(principalId);
    if (!snapshot) throw new ReauthorizationRequiredError(randomUUID());
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new Error("resolver clock is invalid");
    }
    const current = snapshot.grant.accessExpiresAt > now + this.#refreshSkewSeconds
      ? snapshot
      : await this.#refresh(snapshot);
    return this.#client(current);
  }

  async #refresh(snapshot: CredentialSnapshot): Promise<CredentialSnapshot> {
    const existing = this.#refreshes.get(snapshot.principalId);
    if (existing) return existing;

    const pending = this.#refreshSnapshot(snapshot);
    this.#refreshes.set(snapshot.principalId, pending);
    try {
      return await pending;
    } finally {
      if (this.#refreshes.get(snapshot.principalId) === pending) {
        this.#refreshes.delete(snapshot.principalId);
      }
    }
  }

  async #refreshSnapshot(snapshot: CredentialSnapshot): Promise<CredentialSnapshot> {
    const grant = await this.#zendesk.refreshCredential(snapshot.grant.refreshToken);
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new Error("resolver clock is invalid");
    }
    const { stageId } = this.#store.stageRefreshGrant({
      principalId: snapshot.principalId,
      expectedPrincipalEpoch: snapshot.principalEpoch,
      expectedCredentialVersion: snapshot.credentialVersion,
      grant,
      now,
    });
    try {
      const identity = await this.#zendesk.getCurrentUser(grant.accessToken);
      if (identity.zendeskUserId !== snapshot.zendeskUserId) {
        throw new Error("Zendesk identity changed during refresh");
      }
      const result = this.#store.installStagedRefresh(stageId, this.#now());
      if (result.kind === "installed" || result.kind === "winner") {
        return result.snapshot;
      }
      throw new ReauthorizationRequiredError(randomUUID());
    } catch (error) {
      this.#store.discardStagedGrant(stageId, this.#now());
      throw error;
    }
  }

  #client(snapshot: CredentialSnapshot): ZendeskClient {
    return new ZendeskClient({
      subdomain: this.#subdomain,
      auth: {
        kind: "oauth",
        accessToken: snapshot.grant.accessToken,
        principalEpoch: snapshot.principalEpoch,
        credentialVersion: snapshot.credentialVersion,
        onUnauthorized: async () => ({
          kind: "stale_failure",
          correlationId: randomUUID(),
        }),
      },
      timeoutMs: this.#timeoutMs,
      fetch: this.#fetch,
    });
  }
}
