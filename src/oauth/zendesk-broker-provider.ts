import type { Response } from "express";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import {
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type {
  AuthorizationParams,
  OAuthServerProvider,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";

import { normalizeMcpScopes } from "./constants.js";
import type { OAuthStore } from "./store.js";

const providerErrors = {
  missingRedirect: InvalidRequestError,
  wrongOrReusedCode: InvalidGrantError,
  badScope: InvalidScopeError,
  missingOrWrongResource: InvalidTargetError,
  invalidBearer: InvalidTokenError,
} as const;

export type AuthorizationStarter = (
  client: OAuthClientInformationFull,
  params: AuthorizationParams,
  res: Response,
) => Promise<void>;

export type ZendeskBrokerOAuthProviderOptions = {
  store: OAuthStore;
  resourceUrl: URL;
  accessTokenTtlSeconds: number;
  startAuthorization: AuthorizationStarter;
  now?: () => number;
};

export class ZendeskBrokerOAuthProvider implements OAuthServerProvider {
  readonly skipLocalPkceValidation: false = false;

  readonly #store: OAuthStore;
  readonly #resourceUrl: URL;
  readonly #resource: string;
  readonly #accessTokenTtlSeconds: number;
  readonly #startAuthorization: AuthorizationStarter;
  readonly #now: () => number;

  constructor(options: ZendeskBrokerOAuthProviderOptions) {
    this.#store = options.store;
    this.#resourceUrl = new URL(options.resourceUrl.href);
    this.#resource = this.#resourceUrl.href;
    this.#accessTokenTtlSeconds = options.accessTokenTtlSeconds;
    this.#startAuthorization = options.startAuthorization;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1_000));
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return this.#store;
  }

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    this.#requireCanonicalResource(params.resource);
    if (!client.redirect_uris.includes(params.redirectUri)) {
      throw new providerErrors.missingRedirect("redirect_uri is not registered");
    }

    let scopes: string[];
    try {
      scopes = normalizeMcpScopes(params.scopes ?? []);
    } catch {
      throw new providerErrors.badScope("scope is invalid");
    }

    await this.#startAuthorization(client, { ...params, scopes }, res);
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    code: string,
  ): Promise<string> {
    const challenge = this.#store.challengeForAuthorizationCode(
      client.client_id,
      code,
      this.#now(),
    );
    if (challenge === undefined) {
      throw new providerErrors.wrongOrReusedCode("authorization code is invalid");
    }
    return challenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    code: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    if (redirectUri === undefined) {
      throw new providerErrors.missingRedirect("redirect_uri is required");
    }
    this.#requireCanonicalResource(resource);

    try {
      return {
        ...this.#store.consumeCodeAndIssueFamily({
          clientId: client.client_id,
          authorizationCode: code,
          redirectUri,
          resource: this.#resource,
          now: this.#now(),
          accessTokenTtlSeconds: this.#accessTokenTtlSeconds,
        }),
      };
    } catch (error) {
      if (error instanceof Error && error.message === "invalid authorization code") {
        throw new providerErrors.wrongOrReusedCode("authorization code is invalid");
      }
      throw error;
    }
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    token: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    if (resource !== undefined && resource.href !== this.#resource) {
      throw new providerErrors.missingOrWrongResource("resource is invalid");
    }

    const result = this.#store.rotateRefreshToken({
      clientId: client.client_id,
      refreshToken: token,
      scopes,
      resource: resource?.href,
      canonicalResource: this.#resource,
      now: this.#now(),
      accessTokenTtlSeconds: this.#accessTokenTtlSeconds,
    });
    if (result.kind === "invalid_grant") {
      throw new providerErrors.wrongOrReusedCode("refresh token is invalid");
    }
    return { ...result.tokens };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const stored = this.#store.lookupAccessToken(token, this.#now());
    if (
      stored === undefined ||
      stored.resource !== this.#resource ||
      !Number.isSafeInteger(stored.expiresAt)
    ) {
      throw new providerErrors.invalidBearer("access token is invalid");
    }

    return {
      token,
      clientId: stored.clientId,
      scopes: [...stored.scopes],
      expiresAt: stored.expiresAt,
      resource: new URL(this.#resourceUrl.href),
      extra: { principalId: stored.principalId },
    };
  }

  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    this.#store.revokeFamilyByPresentedToken(client.client_id, request.token, this.#now());
  }

  #requireCanonicalResource(resource: URL | undefined): void {
    if (resource === undefined || resource.href !== this.#resource) {
      throw new providerErrors.missingOrWrongResource("resource is required and must be canonical");
    }
  }
}
