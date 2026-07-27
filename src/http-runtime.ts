import type { Express } from "express";

import type { HttpOAuthConfig } from "./config.js";
import { createHttpApp, type HttpAppOptions } from "./http-app.js";
import {
  UserClientResolver,
  type UserClientResolverLike,
} from "./internal-auth/client-resolver.js";
import { SecretCipher } from "./internal-auth/crypto.js";
import { createLinkHandlers } from "./internal-auth/link-handlers.js";
import { InternalAuthStore } from "./internal-auth/store.js";
import {
  ZendeskOAuthClient,
  type ZendeskOAuthGateway,
  type ZendeskOAuthOptions,
} from "./internal-auth/zendesk-oauth.js";

export type HttpRuntime = {
  app: Express;
  shutdownSignal: AbortSignal;
  beginShutdown(): void;
  close(): void;
};

export type HttpRuntimeDependencies = {
  openStore?: typeof InternalAuthStore.open;
  createOAuth?: (options: ZendeskOAuthOptions) => ZendeskOAuthGateway;
  createResolver?: (options: {
    store: InternalAuthStore;
    oauth: ZendeskOAuthGateway;
    subdomain: string;
    timeoutMs: number;
    signal: AbortSignal;
  }) => UserClientResolverLike;
  createHandlers?: typeof createLinkHandlers;
  createApp?: (options: HttpAppOptions) => Express;
};

export function createHttpRuntime(
  config: HttpOAuthConfig,
  dependencies: HttpRuntimeDependencies = {},
): HttpRuntime {
  const shutdown = new AbortController();
  const openStore = dependencies.openStore ?? InternalAuthStore.open;
  let store: InternalAuthStore;
  try {
    store = openStore({
      path: config.oauthDbPath,
      cipher: new SecretCipher(config.oauthEncryptionKey),
      subdomain: config.zendeskSubdomain,
      clientId: config.zendeskOAuthClientId,
    });
  } catch {
    throw new Error("Unable to initialize HTTP authentication runtime");
  }

  try {
    const oauth = (dependencies.createOAuth ??
      ((options) => new ZendeskOAuthClient(options)))({
      subdomain: config.zendeskSubdomain,
      clientId: config.zendeskOAuthClientId,
      clientSecret: config.zendeskOAuthClientSecret,
      callbackUrl: config.zendeskCallbackUrl,
      timeoutMs: 10_000,
      signal: shutdown.signal,
    });
    const resolver = (dependencies.createResolver ??
      ((options) => new UserClientResolver(options)))({
      store,
      oauth,
      subdomain: config.zendeskSubdomain,
      timeoutMs: 10_000,
      signal: shutdown.signal,
    });
    const linkHandlers = (dependencies.createHandlers ?? createLinkHandlers)({
      store,
      oauth,
      publicBaseUrl: config.publicBaseUrl,
      zendeskAuthorizationOrigin: new URL(
        `https://${config.zendeskSubdomain}.zendesk.com`,
      ),
      selfServiceEnabled: config.selfServiceEnrollmentEnabled,
    });
    const app = (dependencies.createApp ?? createHttpApp)({
      host: config.host,
      allowedHosts: config.allowedHosts,
      authenticateBearer: (token) => store.authenticateBearer(token),
      resolver,
      selfServiceEnrollmentEnabled: config.selfServiceEnrollmentEnabled,
      linkHandlers,
    });
    let closed = false;
    return {
      app,
      shutdownSignal: shutdown.signal,
      beginShutdown() {
        shutdown.abort();
      },
      close() {
        if (closed) return;
        closed = true;
        shutdown.abort();
        store.close();
      },
    };
  } catch {
    store.close();
    throw new Error("Unable to initialize HTTP authentication runtime");
  }
}
