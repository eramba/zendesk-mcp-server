import { randomUUID } from "node:crypto";

import {
  ZendeskClient,
  type OAuthUnauthorizedResult,
} from "../zendesk-client.js";
import { REFRESH_SKEW_SECONDS } from "./constants.js";
import {
  ReauthorizationRequiredError,
  ZendeskUpstreamError,
} from "./errors.js";
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

type RefreshFlight = {
  principalEpoch: number;
  credentialVersion: number;
  pending: Promise<CredentialSnapshot>;
};

export class ZendeskClientResolver implements ZendeskClientResolverLike {
  readonly #store: OAuthStore;
  readonly #zendesk: ZendeskOAuthGateway;
  readonly #subdomain: string;
  readonly #now: () => number;
  readonly #refreshSkewSeconds: number;
  readonly #timeoutMs: number | undefined;
  readonly #fetch: typeof globalThis.fetch | undefined;
  readonly #refreshes = new Map<string, RefreshFlight>();

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

  async #refresh(
    snapshot: CredentialSnapshot,
    signal?: AbortSignal,
  ): Promise<CredentialSnapshot> {
    const existing = this.#refreshes.get(snapshot.principalId);
    if (
      existing &&
      existing.principalEpoch === snapshot.principalEpoch &&
      existing.credentialVersion === snapshot.credentialVersion
    ) {
      return existing.pending;
    }

    const pending = this.#refreshSnapshot(snapshot, signal);
    const flight: RefreshFlight = {
      principalEpoch: snapshot.principalEpoch,
      credentialVersion: snapshot.credentialVersion,
      pending,
    };
    this.#refreshes.set(snapshot.principalId, flight);
    try {
      return await pending;
    } finally {
      if (this.#refreshes.get(snapshot.principalId) === flight) {
        this.#refreshes.delete(snapshot.principalId);
      }
    }
  }

  async #refreshSnapshot(
    snapshot: CredentialSnapshot,
    signal?: AbortSignal,
  ): Promise<CredentialSnapshot> {
    const grant = await this.#zendesk.refreshCredential(snapshot.grant.refreshToken, signal);
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new Error("resolver clock is invalid");
    }
    let stageId: string;
    try {
      ({ stageId } = this.#store.stageRefreshGrant({
        principalId: snapshot.principalId,
        expectedPrincipalEpoch: snapshot.principalEpoch,
        expectedCredentialVersion: snapshot.credentialVersion,
        grant,
        now,
      }));
    } catch (error) {
      const current = this.#store.loadCredential(snapshot.principalId);
      if (current && !this.#sameCredential(current, snapshot)) return current;
      if (!current) throw new ReauthorizationRequiredError(randomUUID());
      throw error;
    }
    try {
      const identity = await this.#zendesk.getCurrentUser(grant.accessToken, signal);
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

  async #onUnauthorized(
    principalId: string,
    input: {
      principalEpoch: number;
      credentialVersion: number;
      terminal: boolean;
      signal: AbortSignal;
    },
  ): Promise<OAuthUnauthorizedResult> {
    if (input.terminal) {
      return this.#terminalFailure(
        principalId,
        input.principalEpoch,
        input.credentialVersion,
      );
    }

    const current = this.#store.loadCredential(principalId);
    if (!current) {
      return { kind: "stale_failure", correlationId: randomUUID() };
    }
    if (
      current.principalEpoch !== input.principalEpoch ||
      current.credentialVersion !== input.credentialVersion
    ) {
      return this.#retry(current);
    }

    try {
      return this.#retry(await this.#refresh(current, input.signal));
    } catch (error) {
      if (error instanceof ZendeskUpstreamError && error.category === "invalid_grant") {
        return this.#terminalFailure(
          principalId,
          current.principalEpoch,
          current.credentialVersion,
        );
      }
      if (error instanceof ReauthorizationRequiredError) {
        return { kind: "stale_failure", correlationId: randomUUID() };
      }
      throw error;
    }
  }

  #terminalFailure(
    principalId: string,
    expectedPrincipalEpoch: number,
    expectedCredentialVersion: number,
  ): OAuthUnauthorizedResult {
    const correlationId = randomUUID();
    const changed = this.#store.markReauthorizationRequiredIfCurrent({
      principalId,
      expectedPrincipalEpoch,
      expectedCredentialVersion,
      now: this.#now(),
    });
    if (changed) return { kind: "reauthorization_required", correlationId };

    this.#store.loadCredential(principalId);
    return { kind: "stale_failure", correlationId };
  }

  #retry(snapshot: CredentialSnapshot): OAuthUnauthorizedResult {
    return {
      kind: "retry",
      accessToken: snapshot.grant.accessToken,
      principalEpoch: snapshot.principalEpoch,
      credentialVersion: snapshot.credentialVersion,
    };
  }

  #sameCredential(left: CredentialSnapshot, right: CredentialSnapshot): boolean {
    return left.principalEpoch === right.principalEpoch &&
      left.credentialVersion === right.credentialVersion;
  }

  #client(snapshot: CredentialSnapshot): ZendeskClient {
    return new ZendeskClient({
      subdomain: this.#subdomain,
      auth: {
        kind: "oauth",
        accessToken: snapshot.grant.accessToken,
        principalEpoch: snapshot.principalEpoch,
        credentialVersion: snapshot.credentialVersion,
        onUnauthorized: (input) => this.#onUnauthorized(snapshot.principalId, input),
      },
      timeoutMs: this.#timeoutMs,
      fetch: this.#fetch,
    });
  }
}
