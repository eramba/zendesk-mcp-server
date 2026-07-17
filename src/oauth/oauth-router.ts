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

import { MCP_SCOPES, OAUTH_PATHS } from "./constants.js";
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
};

export function createZendeskOAuthRouter(
  options: ZendeskOAuthRouterOptions,
): Router {
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
    clientRegistrationHandler({
      clientsStore: options.provider.clientsStore,
      clientIdGeneration: false,
      rateLimit: standardRateLimit(ONE_HOUR_MS, 20),
    }),
  );
  router.use(
    OAUTH_PATHS.authorize,
    authorizationHandler({
      provider: options.provider,
      rateLimit: standardRateLimit(FIFTEEN_MINUTES_MS, 60),
    }),
  );
  router.use(
    OAUTH_PATHS.token,
    tokenHandler({
      provider: options.provider,
      rateLimit: standardRateLimit(FIFTEEN_MINUTES_MS, 120),
    }),
  );
  router.use(
    OAUTH_PATHS.revoke,
    revocationHandler({
      provider: options.provider,
      rateLimit: standardRateLimit(FIFTEEN_MINUTES_MS, 120),
    }),
  );
  router.post(
    OAUTH_PATHS.consent,
    browserRateLimit(),
    express.urlencoded({
      extended: false,
      limit: "4kb",
      parameterLimit: 4,
    }),
    options.consentHandler,
  );
  router.get(
    OAUTH_PATHS.zendeskCallback,
    browserRateLimit(),
    options.callbackHandler,
  );

  return router;
}
