import { randomUUID } from "node:crypto";

import type { Express, Router } from "express";

import type { HttpOAuthConfig } from "./config.js";
import { createHttpApp, type HttpAppOptions } from "./http-app.js";
import {
  DEFAULT_HTTP_SHUTDOWN_TIMEOUT_MS,
  HttpOperationTracker,
} from "./http-operation-tracker.js";
import { ConsentController, type ConsentControllerOptions } from "./oauth/consent.js";
import { OAUTH_PATHS, ZENDESK_SCOPES } from "./oauth/constants.js";
import {
  createZendeskOAuthRouter,
  type ZendeskOAuthRouterOptions,
} from "./oauth/oauth-router.js";
import { ZendeskRevocationWorker } from "./oauth/revocation-worker.js";
import { openSqliteOAuthStore } from "./oauth/sqlite-store.js";
import type { OAuthStore } from "./oauth/store.js";
import { TokenCipher } from "./oauth/token-cipher.js";
import {
  ZendeskBrokerOAuthProvider,
  type ZendeskBrokerOAuthProviderOptions,
} from "./oauth/zendesk-broker-provider.js";
import {
  ZendeskCallbackController,
  type ZendeskCallbackControllerOptions,
} from "./oauth/zendesk-callback.js";
import {
  ZendeskClientResolver,
  type ZendeskClientResolverLike,
  type ZendeskClientResolverOptions,
} from "./oauth/zendesk-client-resolver.js";
import {
  ZendeskOAuthClient,
  type ZendeskOAuthClientOptions,
  type ZendeskOAuthGateway,
} from "./oauth/zendesk-oauth-client.js";

export type HttpRuntime = {
  app: Express;
  startWorker(): void;
  shutdown(signal: NodeJS.Signals): Promise<void>;
};

type RevocationWorkerLike = {
  start(): void;
  stop(signal?: AbortSignal): Promise<void>;
};

type RuntimeDependencies = {
  now(): number;
  randomOwner(): string;
  createCipher(key: Buffer): TokenCipher;
  openStore: typeof openSqliteOAuthStore;
  createZendesk(options: ZendeskOAuthClientOptions): ZendeskOAuthGateway;
  createConsent(options: ConsentControllerOptions): ConsentController;
  createCallback(options: ZendeskCallbackControllerOptions): ZendeskCallbackController;
  createProvider(options: ZendeskBrokerOAuthProviderOptions): ZendeskBrokerOAuthProvider;
  createRouter(options: ZendeskOAuthRouterOptions): Router;
  createResolver(options: ZendeskClientResolverOptions): ZendeskClientResolverLike;
  createWorker(
    options: ConstructorParameters<typeof ZendeskRevocationWorker>[0],
  ): RevocationWorkerLike;
  createApp(options: HttpAppOptions): Express;
  shutdownTimeoutMs?: number;
  monotonicNow?(): number;
};

const defaultDependencies: RuntimeDependencies = {
  now: () => Math.floor(Date.now() / 1_000),
  randomOwner: randomUUID,
  createCipher: (key) => new TokenCipher(key),
  openStore: openSqliteOAuthStore,
  createZendesk: (options) => new ZendeskOAuthClient(options),
  createConsent: (options) => new ConsentController(options),
  createCallback: (options) => new ZendeskCallbackController(options),
  createProvider: (options) => new ZendeskBrokerOAuthProvider(options),
  createRouter: createZendeskOAuthRouter,
  createResolver: (options) => new ZendeskClientResolver(options),
  createWorker: (options) => new ZendeskRevocationWorker(options),
  createApp: createHttpApp,
  shutdownTimeoutMs: DEFAULT_HTTP_SHUTDOWN_TIMEOUT_MS,
  monotonicNow: () => Number(process.hrtime.bigint() / 1_000_000n),
};

type ListenerCloser = (remainingMs: number) => Promise<void>;

const listenerClosers = new WeakMap<HttpRuntime, ListenerCloser>();

export function attachHttpListener(
  runtime: HttpRuntime,
  closeListener: ListenerCloser,
): void {
  if (listenerClosers.get(runtime) !== undefined) {
    throw new Error("HTTP listener is already attached");
  }
  listenerClosers.set(runtime, closeListener);
}

export function createHttpRuntime(
  config: HttpOAuthConfig,
  dependencies: RuntimeDependencies = defaultDependencies,
): HttpRuntime {
  const shutdownController = new AbortController();
  const operationTracker = new HttpOperationTracker(shutdownController.signal);
  let store: OAuthStore | undefined;

  try {
    const cipher = dependencies.createCipher(config.oauthEncryptionKey);
    const initializedStore = dependencies.openStore({
      path: config.oauthDbPath,
      cipher,
      mcpResourceUrl: config.mcpResourceUrl,
      now: dependencies.now,
    });
    store = initializedStore;
    const zendesk = dependencies.createZendesk({
      subdomain: config.zendeskSubdomain,
      clientId: config.zendeskOAuthClientId,
      clientSecret: config.zendeskOAuthClientSecret,
      callbackUrl: config.zendeskCallbackUrl,
      scopes: [...ZENDESK_SCOPES],
      timeoutMs: config.zendeskHttpTimeoutMs,
      shutdownSignal: shutdownController.signal,
      now: dependencies.now,
    });
    const consent = dependencies.createConsent({
      store: initializedStore,
      zendesk,
      publicBaseUrl: config.publicBaseUrl,
      subdomain: config.zendeskSubdomain,
      now: dependencies.now,
    });
    const callback = dependencies.createCallback({
      store: initializedStore,
      zendesk,
      subdomain: config.zendeskSubdomain,
      now: dependencies.now,
    });
    const provider = dependencies.createProvider({
      store: initializedStore,
      resourceUrl: config.mcpResourceUrl,
      accessTokenTtlSeconds: config.mcpAccessTokenTtlSeconds,
      startAuthorization: consent.begin,
      now: dependencies.now,
    });
    const oauthRouter = dependencies.createRouter({
      provider,
      issuerUrl: config.issuerUrl,
      resourceUrl: config.mcpResourceUrl,
      consentHandler: consent.handlePost,
      callbackHandler: callback.handle,
      operationTracker,
    });
    const resolver = dependencies.createResolver({
      store: initializedStore,
      zendesk,
      subdomain: config.zendeskSubdomain,
      timeoutMs: config.zendeskHttpTimeoutMs,
      now: dependencies.now,
    });
    const workerOwner = dependencies.randomOwner();
    const worker = dependencies.createWorker({
      store: initializedStore,
      zendesk,
      timeoutMs: config.zendeskHttpTimeoutMs,
      now: dependencies.now,
      randomOwner: () => workerOwner,
    });
    const app = dependencies.createApp({
      host: config.host,
      allowedHosts: config.allowedHosts,
      provider,
      resolver,
      oauthRouter,
      resourceMetadataUrl: new URL(
        OAUTH_PATHS.protectedResourceMetadata,
        config.publicBaseUrl,
      ).href,
      isReady: () => initializedStore.isReady(),
      operationTracker,
    });

    let shutdownPromise: Promise<void> | undefined;
    let runtime: HttpRuntime;

    const shutdownTimeoutMs =
      dependencies.shutdownTimeoutMs ?? DEFAULT_HTTP_SHUTDOWN_TIMEOUT_MS;
    if (!Number.isSafeInteger(shutdownTimeoutMs) || shutdownTimeoutMs < 0) {
      throw new Error("HTTP shutdown timeout must be a non-negative integer");
    }
    const monotonicNow = dependencies.monotonicNow ??
      (() => Number(process.hrtime.bigint() / 1_000_000n));

    const remainingUntil = (deadlineMs: number): number => {
      const currentMs = monotonicNow();
      if (!Number.isSafeInteger(currentMs) || currentMs < 0) {
        throw new Error("HTTP shutdown clock returned an invalid time");
      }
      return Math.max(0, deadlineMs - currentMs);
    };

    const waitForPhase = async (
      phase: Promise<void>,
      deadlineMs: number,
      timeoutMessage: string,
    ): Promise<void> => {
      const remainingMs = remainingUntil(deadlineMs);
      let timeout: NodeJS.Timeout | undefined;
      try {
        await Promise.race([
          phase,
          new Promise<never>((_resolve, reject) => {
            timeout = setTimeout(() => reject(new Error(timeoutMessage)), remainingMs);
          }),
        ]);
      } finally {
        if (timeout) clearTimeout(timeout);
      }
    };

    const stop = async (deadlineMs: number): Promise<void> => {
      const failures: unknown[] = [];
      let safeToCloseStore = true;
      let stopping: Promise<void> | undefined;
      try {
        stopping = worker.stop();
      } catch (error) {
        failures.push(error);
        safeToCloseStore = false;
      }
      shutdownController.abort();
      if (stopping) {
        try {
          await waitForPhase(
            stopping,
            deadlineMs,
            "HTTP worker did not stop before shutdown deadline",
          );
        } catch (error) {
          failures.push(error);
          safeToCloseStore = false;
        }
      }

      const closeListener = listenerClosers.get(runtime);
      if (closeListener) {
        try {
          const closing = closeListener(remainingUntil(deadlineMs));
          await waitForPhase(
            closing,
            deadlineMs,
            "HTTP listener did not close before shutdown deadline",
          );
        } catch (error) {
          failures.push(error);
          safeToCloseStore = false;
        }
      }

      try {
        await operationTracker.drain(remainingUntil(deadlineMs));
      } catch (error) {
        failures.push(error);
        safeToCloseStore = false;
      }

      if (safeToCloseStore) {
        try {
          initializedStore.releaseClaims(workerOwner, dependencies.now());
        } catch (error) {
          failures.push(error);
        }
        try {
          initializedStore.close();
        } catch (error) {
          failures.push(error);
        }
      }

      if (failures.length === 1) throw failures[0];
      if (failures.length > 1) {
        throw new AggregateError(failures, "HTTP runtime shutdown failed");
      }
    };

    runtime = {
      app,
      startWorker() {
        initializedStore.assertReady();
        worker.start();
      },
      shutdown(_signal) {
        shutdownPromise ??= (async () => {
          const startedAtMs = monotonicNow();
          if (!Number.isSafeInteger(startedAtMs) || startedAtMs < 0) {
            throw new Error("HTTP shutdown clock returned an invalid time");
          }
          if (startedAtMs > Number.MAX_SAFE_INTEGER - shutdownTimeoutMs) {
            throw new Error("HTTP shutdown deadline is outside the safe range");
          }
          await stop(startedAtMs + shutdownTimeoutMs);
        })();
        return shutdownPromise;
      },
    };
    return runtime;
  } catch (error) {
    shutdownController.abort();
    try {
      store?.close();
    } catch {
      // Preserve the original construction failure.
    }
    throw error;
  }
}
