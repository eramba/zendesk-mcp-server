import { randomUUID } from "node:crypto";

import { ZendeskUpstreamError } from "./errors.js";
import type { OAuthStore, RevocationClaim } from "./store.js";
import type { ZendeskOAuthGateway } from "./zendesk-oauth-client.js";

const LEASE_MARGIN_MS = 5_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const MAX_RETRY_SECONDS = 900;

export type ZendeskRevocationWorkerOptions = {
  store: OAuthStore;
  zendesk: ZendeskOAuthGateway;
  timeoutMs: number;
  now?: () => number;
  randomOwner?: () => string;
  pollIntervalMs?: number;
};

function validOwner(owner: string): boolean {
  return /^[\x20-\x7e]{1,200}$/.test(owner);
}

function retryDelaySeconds(attemptCount: number): number | undefined {
  if (!Number.isSafeInteger(attemptCount) || attemptCount < 1) return undefined;
  return Math.min(MAX_RETRY_SECONDS, 5 * 2 ** Math.min(30, attemptCount - 1));
}

function waitWithSignal(promise: Promise<void>, signal?: AbortSignal): Promise<void> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(new DOMException("Aborted", "AbortError"));
  return new Promise<void>((resolve, reject) => {
    const onAbort = () => {
      signal.removeEventListener("abort", onAbort);
      reject(new DOMException("Aborted", "AbortError"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      () => {
        signal.removeEventListener("abort", onAbort);
        resolve();
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

export class ZendeskRevocationWorker {
  readonly #store: OAuthStore;
  readonly #zendesk: ZendeskOAuthGateway;
  readonly #now: () => number;
  readonly #owner: string;
  readonly #pollIntervalMs: number;
  readonly #leaseSeconds: number;
  #running = false;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #inFlight: Promise<void> | undefined;
  #controller: AbortController | undefined;

  constructor(options: ZendeskRevocationWorkerOptions) {
    if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0) {
      throw new Error("timeoutMs must be a positive integer");
    }
    const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs <= 0) {
      throw new Error("pollIntervalMs must be a positive integer");
    }
    const leaseSeconds = Math.ceil((options.timeoutMs + LEASE_MARGIN_MS) / 1_000);
    if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds <= 0) {
      throw new Error("revocation lease duration is invalid");
    }
    const owner = (options.randomOwner ?? randomUUID)();
    if (!validOwner(owner)) throw new Error("revocation owner is invalid");

    this.#store = options.store;
    this.#zendesk = options.zendesk;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1_000));
    this.#owner = owner;
    this.#pollIntervalMs = pollIntervalMs;
    this.#leaseSeconds = leaseSeconds;
  }

  start(): void {
    if (this.#running) return;
    this.#running = true;
    this.#schedule(0);
  }

  async stop(signal?: AbortSignal): Promise<void> {
    this.#running = false;
    if (this.#timer !== undefined) {
      clearTimeout(this.#timer);
      this.#timer = undefined;
    }
    this.#controller?.abort();
    await this.drain(signal);
  }

  async drain(signal?: AbortSignal): Promise<void> {
    const inFlight = this.#inFlight;
    if (inFlight) await waitWithSignal(inFlight, signal);
  }

  #schedule(delayMs: number): void {
    if (!this.#running || this.#timer !== undefined || this.#inFlight !== undefined) return;
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      if (!this.#running || this.#inFlight !== undefined) return;
      const inFlight = this.#processNext();
      this.#inFlight = inFlight;
      void inFlight.finally(() => {
        if (this.#inFlight === inFlight) this.#inFlight = undefined;
        this.#schedule(this.#pollIntervalMs);
      });
    }, delayMs);
    this.#timer.unref?.();
  }

  #clock(): number | undefined {
    const now = Math.floor(this.#now());
    return Number.isSafeInteger(now) && now >= 0 ? now : undefined;
  }

  #leaseDeadline(now: number, previous?: number): number | undefined {
    if (now > Number.MAX_SAFE_INTEGER - this.#leaseSeconds) return undefined;
    const fromNow = now + this.#leaseSeconds;
    const deadline = previous === undefined ? fromNow : Math.max(fromNow, previous + 1);
    return Number.isSafeInteger(deadline) ? deadline : undefined;
  }

  async #processNext(): Promise<void> {
    const now = this.#clock();
    if (now === undefined) return;
    const leaseExpiresAt = this.#leaseDeadline(now);
    if (leaseExpiresAt === undefined) return;
    const claim = this.#store.claimDueRevocation(this.#owner, now, leaseExpiresAt);
    if (!claim) return;

    const controller = new AbortController();
    this.#controller = controller;
    try {
      await this.#processClaim(claim, leaseExpiresAt, controller.signal);
    } catch (error) {
      const failureNow = this.#clock();
      if (failureNow === undefined) return;
      if (controller.signal.aborted) {
        this.#store.releaseClaims(this.#owner, failureNow);
        return;
      }
      if (error instanceof ZendeskUpstreamError && error.retryable) {
        const delay = retryDelaySeconds(claim.attemptCount);
        if (delay !== undefined && failureNow <= Number.MAX_SAFE_INTEGER - delay) {
          this.#store.rescheduleRevocation(
            claim.outboxId,
            this.#owner,
            error.category,
            failureNow + delay,
          );
        }
        return;
      }
      if (error instanceof ZendeskUpstreamError && error.category === "aborted") {
        this.#store.releaseClaims(this.#owner, failureNow);
        return;
      }
      if (error instanceof ZendeskUpstreamError) {
        this.#store.completeRevocation(claim.outboxId, this.#owner, failureNow);
        return;
      }
      this.#store.releaseClaims(this.#owner, failureNow);
    } finally {
      if (this.#controller === controller) this.#controller = undefined;
    }
  }

  async #processClaim(
    claim: RevocationClaim,
    initialLeaseExpiresAt: number,
    signal: AbortSignal,
  ): Promise<void> {
    const initialNow = this.#clock();
    if (initialNow === undefined) return;
    if (claim.grant.refreshExpiresAt <= initialNow) {
      this.#store.completeRevocation(claim.outboxId, this.#owner, initialNow);
      return;
    }

    try {
      await this.#zendesk.revokeCurrentToken(claim.grant.accessToken, signal);
      const completedAt = this.#clock();
      if (completedAt !== undefined) {
        this.#store.completeRevocation(claim.outboxId, this.#owner, completedAt);
      }
      return;
    } catch (error) {
      if (
        !(error instanceof ZendeskUpstreamError)
        || error.category !== "unauthorized"
      ) {
        throw error;
      }
    }

    const refreshNow = this.#clock();
    if (refreshNow === undefined) return;
    if (claim.grant.refreshExpiresAt <= refreshNow) {
      this.#store.completeRevocation(claim.outboxId, this.#owner, refreshNow);
      return;
    }
    const refreshLease = this.#leaseDeadline(refreshNow, initialLeaseExpiresAt);
    if (
      refreshLease === undefined
      || !this.#store.renewRevocationClaim(claim.outboxId, this.#owner, refreshLease)
    ) {
      return;
    }

    const refreshed = await this.#zendesk.refreshCredential(claim.grant.refreshToken, signal);
    const revokeNow = this.#clock();
    if (revokeNow === undefined) return;
    if (
      !this.#store.replaceRevocationGrant(
        claim.outboxId,
        this.#owner,
        refreshed,
        revokeNow,
      )
    ) {
      return;
    }
    const revokeLease = this.#leaseDeadline(revokeNow, refreshLease);
    if (
      revokeLease === undefined
      || !this.#store.renewRevocationClaim(claim.outboxId, this.#owner, revokeLease)
    ) {
      return;
    }

    try {
      await this.#zendesk.revokeCurrentToken(refreshed.accessToken, signal);
    } catch (error) {
      if (
        error instanceof ZendeskUpstreamError
        && error.category === "unauthorized"
      ) {
        const completedAt = this.#clock();
        if (completedAt !== undefined) {
          this.#store.completeRevocation(claim.outboxId, this.#owner, completedAt);
        }
        return;
      }
      throw error;
    }

    const completedAt = this.#clock();
    if (completedAt !== undefined) {
      this.#store.completeRevocation(claim.outboxId, this.#owner, completedAt);
    }
  }
}
