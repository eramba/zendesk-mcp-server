import express, {
  type RequestHandler,
  type Router,
} from "express";
import { rateLimit } from "express-rate-limit";
import { authorizationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/authorize.js";
import { metadataHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/metadata.js";
import { clientRegistrationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/register.js";
import { revocationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/revoke.js";
import { tokenHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/token.js";
import {
  createOAuthMetadata,
  mcpAuthMetadataRouter,
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";

import {
  createStandaloneHttpOperationTracker,
  type HttpOperationTracker,
  trackHttpHandler,
  trackRouterOperations,
} from "../http-operation-tracker.js";
import { MCP_SCOPES, OAUTH_PATHS } from "./constants.js";
import { consentPostResponseHeaders } from "./consent.js";
import type { ZendeskBrokerOAuthProvider } from "./zendesk-broker-provider.js";

const FIFTEEN_MINUTES_MS = 15 * 60 * 1_000;
const ONE_HOUR_MS = 60 * 60 * 1_000;

const standardRateLimit = (windowMs: number, max: number) => ({
  windowMs,
  max,
  standardHeaders: true,
  legacyHeaders: false,
});

const browserRateLimit = () =>
  rateLimit(standardRateLimit(FIFTEEN_MINUTES_MS, 60));

export type ZendeskOAuthRouterOptions = {
  provider: ZendeskBrokerOAuthProvider;
  issuerUrl: URL;
  resourceUrl: URL;
  consentHandler: RequestHandler;
  callbackHandler: RequestHandler;
  operationTracker?: HttpOperationTracker;
};

export function createZendeskOAuthRouter(
  options: ZendeskOAuthRouterOptions,
): Router {
  const operationTracker =
    options.operationTracker ?? createStandaloneHttpOperationTracker();
  const oauthMetadata: OAuthMetadata = {
    ...createOAuthMetadata({
      provider: options.provider,
      issuerUrl: options.issuerUrl,
      scopesSupported: [...MCP_SCOPES],
    }),
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
  };

  const router = express.Router();

  router.use(
    OAUTH_PATHS.authorizationServerMetadata,
    metadataHandler(oauthMetadata),
  );
  router.use(
    mcpAuthMetadataRouter({
      oauthMetadata,
      resourceServerUrl: options.resourceUrl,
      scopesSupported: [...MCP_SCOPES],
    }),
  );
  router.use(
    OAUTH_PATHS.register,
    trackRouterOperations(
      clientRegistrationHandler({
        clientsStore: options.provider.clientsStore,
        clientIdGeneration: false,
        rateLimit: standardRateLimit(ONE_HOUR_MS, 20),
      }),
      operationTracker,
    ),
  );
  router.use(
    OAUTH_PATHS.authorize,
    trackRouterOperations(
      authorizationHandler({
        provider: options.provider,
        rateLimit: standardRateLimit(FIFTEEN_MINUTES_MS, 60),
      }),
      operationTracker,
    ),
  );
  router.use(
    OAUTH_PATHS.token,
    trackRouterOperations(
      tokenHandler({
        provider: options.provider,
        rateLimit: standardRateLimit(FIFTEEN_MINUTES_MS, 120),
      }),
      operationTracker,
    ),
  );
  router.use(
    OAUTH_PATHS.revoke,
    trackRouterOperations(
      revocationHandler({
        provider: options.provider,
        rateLimit: standardRateLimit(FIFTEEN_MINUTES_MS, 120),
      }),
      operationTracker,
    ),
  );
  router.post(
    OAUTH_PATHS.consent,
    consentPostResponseHeaders,
    browserRateLimit(),
    express.urlencoded({
      extended: false,
      limit: "4kb",
      parameterLimit: 4,
    }),
    trackHttpHandler(operationTracker, options.consentHandler),
  );
  router.get(
    OAUTH_PATHS.zendeskCallback,
    browserRateLimit(),
    trackHttpHandler(operationTracker, options.callbackHandler),
  );

  return router;
}
