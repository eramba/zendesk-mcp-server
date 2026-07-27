import {
  ZendeskClient,
  type OAuthUnauthorizedResult,
} from "../zendesk-client.js";
import { SafeAuthError } from "./errors.js";
import type {
  CredentialSnapshot,
  InternalAuthStore,
} from "./store.js";
import type { ZendeskOAuthGateway } from "./zendesk-oauth.js";

export interface UserClientResolverLike {
  resolve(userId: string, signal?: AbortSignal): Promise<ZendeskClient>;
}

type ResolverOptions = {
  store: InternalAuthStore;
  oauth: ZendeskOAuthGateway;
  subdomain: string;
  now?: () => number;
  refreshSkewSeconds?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
  fetch?: typeof globalThis.fetch;
};

type PendingRefresh = {
  version: number;
  pending: Promise<CredentialSnapshot>;
};

export class UserClientResolver implements UserClientResolverLike {
  readonly #store: InternalAuthStore;
  readonly #oauth: ZendeskOAuthGateway;
  readonly #subdomain: string;
  readonly #now: () => number;
  readonly #refreshSkewSeconds: number;
  readonly #timeoutMs: number;
  readonly #shutdownSignal: AbortSignal | undefined;
  readonly #fetch: typeof globalThis.fetch | undefined;
  readonly #refreshes = new Map<string, PendingRefresh>();

  constructor(options: ResolverOptions) {
    this.#store = options.store;
    this.#oauth = options.oauth;
    this.#subdomain = options.subdomain;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1_000));
    this.#refreshSkewSeconds = options.refreshSkewSeconds ?? 60;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#shutdownSignal = options.signal;
    this.#fetch = options.fetch;
    if (
      !Number.isSafeInteger(this.#refreshSkewSeconds) ||
      this.#refreshSkewSeconds < 0 ||
      !Number.isSafeInteger(this.#timeoutMs) ||
      this.#timeoutMs <= 0
    ) {
      throw new Error("User client resolver configuration is invalid");
    }
  }

  async resolve(
    userId: string,
    signal?: AbortSignal,
  ): Promise<ZendeskClient> {
    let snapshot = this.#safeLoad(userId);
    if (!snapshot) throw new SafeAuthError("unauthorized", { status: 401 });

    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new SafeAuthError("temporarily_unavailable", { retryable: true });
    }
    const combinedSignal = this.#combinedSignal(signal);
    if (snapshot.grant.accessExpiresAt <= now + this.#refreshSkewSeconds) {
      snapshot = await this.#refresh(snapshot, combinedSignal);
    }
    return this.#client(snapshot, combinedSignal);
  }

  #client(
    initialSnapshot: CredentialSnapshot,
    signal: AbortSignal | undefined,
  ): ZendeskClient {
    let activeSnapshot = initialSnapshot;
    return new ZendeskClient({
      subdomain: this.#subdomain,
      auth: {
        kind: "oauth",
        accessToken: initialSnapshot.grant.accessToken,
        onUnauthorized: async ({
          terminal,
          signal: callSignal,
        }): Promise<OAuthUnauthorizedResult> => {
          if (terminal) {
            const disabled = this.#store.markReauthorizationRequired(
              activeSnapshot.userId,
              activeSnapshot.version,
            );
            if (disabled) {
              return {
                kind: "reauthorization_required",
                correlationId: new SafeAuthError(
                  "reauthorization_required",
                ).correlationId,
              };
            }
            return {
              kind: "stale_failure",
              correlationId: new SafeAuthError("unauthorized").correlationId,
            };
          }

          activeSnapshot = await this.#refresh(
            activeSnapshot,
            this.#combinedSignal(callSignal),
          );
          return {
            kind: "retry",
            accessToken: activeSnapshot.grant.accessToken,
          };
        },
      },
      timeoutMs: this.#timeoutMs,
      signal,
      fetch: this.#fetch,
    });
  }

  async #refresh(
    requested: CredentialSnapshot,
    signal?: AbortSignal,
  ): Promise<CredentialSnapshot> {
    const current = this.#safeLoad(requested.userId);
    if (!current) {
      throw new SafeAuthError("reauthorization_required", { status: 401 });
    }
    if (current.version !== requested.version) return current;

    const existing = this.#refreshes.get(requested.userId);
    if (existing) {
      return this.#waitForRefresh(existing.pending, signal);
    }

    const entry: PendingRefresh = {
      version: current.version,
      pending: this.#performRefresh(current, this.#shutdownSignal),
    };
    this.#refreshes.set(current.userId, entry);
    const clear = () => {
      if (this.#refreshes.get(current.userId) === entry) {
        this.#refreshes.delete(current.userId);
      }
    };
    void entry.pending.then(clear, clear);
    return this.#waitForRefresh(entry.pending, signal);
  }

  async #waitForRefresh(
    pending: Promise<CredentialSnapshot>,
    signal?: AbortSignal,
  ): Promise<CredentialSnapshot> {
    let abort: (() => void) | undefined;
    const aborted = new Promise<never>((_resolve, reject) => {
      if (!signal) return;
      abort = () => {
        reject(new SafeAuthError("aborted", { retryable: true }));
      };
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    });

    try {
      return signal ? await Promise.race([pending, aborted]) : await pending;
    } catch (error) {
      if (error instanceof SafeAuthError) throw error;
      throw new SafeAuthError("temporarily_unavailable", { retryable: true });
    } finally {
      if (signal && abort) signal.removeEventListener("abort", abort);
    }
  }

  async #performRefresh(
    snapshot: CredentialSnapshot,
    signal?: AbortSignal,
  ): Promise<CredentialSnapshot> {
    const now = this.#now();
    if (
      !Number.isSafeInteger(now) ||
      now < 0 ||
      snapshot.grant.refreshExpiresAt <= now
    ) {
      return this.#disable(snapshot);
    }

    try {
      const grant = await this.#oauth.refresh(
        snapshot.grant.refreshToken,
        signal,
      );
      const identity = await this.#oauth.currentUser(
        grant.accessToken,
        signal,
      );
      if (identity.id !== snapshot.zendeskUserId) {
        return this.#disable(snapshot);
      }
      const installed = this.#store.installRefreshedGrant({
        userId: snapshot.userId,
        expectedVersion: snapshot.version,
        grant,
      });
      if (installed.kind === "inactive") {
        throw new SafeAuthError("reauthorization_required", { status: 401 });
      }
      return installed.snapshot;
    } catch (error) {
      if (
        error instanceof SafeAuthError &&
        error.category === "invalid_grant"
      ) {
        return this.#disable(snapshot);
      }
      if (error instanceof SafeAuthError) throw error;
      throw new SafeAuthError("temporarily_unavailable", { retryable: true });
    }
  }

  #disable(snapshot: CredentialSnapshot): never {
    const changed = this.#store.markReauthorizationRequired(
      snapshot.userId,
      snapshot.version,
    );
    if (!changed) {
      const winner = this.#safeLoad(snapshot.userId);
      if (winner) {
        throw new SafeAuthError("temporarily_unavailable", {
          retryable: true,
        });
      }
    }
    throw new SafeAuthError("reauthorization_required", { status: 401 });
  }

  #safeLoad(userId: string): CredentialSnapshot | undefined {
    try {
      return this.#store.loadCredential(userId);
    } catch {
      throw new SafeAuthError("temporarily_unavailable", { retryable: true });
    }
  }

  #combinedSignal(signal?: AbortSignal): AbortSignal | undefined {
    const signals = [signal, this.#shutdownSignal].filter(
      (item): item is AbortSignal => item !== undefined,
    );
    if (signals.length === 0) return undefined;
    if (signals.length === 1) return signals[0];
    return AbortSignal.any(signals);
  }
}
