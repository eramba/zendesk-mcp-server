import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export type RecoverySummary = {
  expiredLogins: number;
  discardedStages: number;
  reclaimedClaims: number;
};

export type StoreInspection = {
  schemaVersion: number;
  migrationCount: number;
  clientCount: number;
  pragmas: {
    foreignKeys: number;
    journalMode: string;
    synchronous: number;
    trustedSchema: number;
    secureDelete: number;
  };
};

export type BeginLoginInput = {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource: string;
  originalState: string | undefined;
  subdomain: string;
  now: number;
};

export type LoginStart = {
  transactionToken: string;
  consentCsrf: string;
  browserNonce: string;
  expiresAt: number;
};

export type ConsentDecisionInput = {
  transactionToken: string;
  consentCsrf: string;
  browserNonce: string;
  decision: "confirm" | "deny";
  now: number;
};

export type OAuthRedirectContext = {
  redirectUri: string;
  originalState: string | undefined;
};

export type ZendeskGrant = {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
  scopes: string[];
};

export type StageLoginGrantInput = {
  transactionId: string;
  subdomain: string;
  grant: ZendeskGrant;
  now: number;
};

export type CommitLoginInput = {
  transactionId: string;
  stageId: string;
  zendeskUserId: string;
  now: number;
};

export type LoginCommitResult = OAuthRedirectContext & {
  principalId: string;
  principalEpoch: number;
  authorizationCode: string;
};

export type IssuedTokens = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
};

export type CodeExchangeInput = {
  clientId: string;
  authorizationCode: string;
  redirectUri: string;
  resource: string;
  now: number;
  accessTokenTtlSeconds: number;
};

export type RefreshExchangeInput = {
  clientId: string;
  refreshToken: string;
  scopes: string[] | undefined;
  resource: string | undefined;
  canonicalResource: string;
  now: number;
  accessTokenTtlSeconds: number;
};

export type RefreshExchangeResult =
  | { kind: "issued"; tokens: IssuedTokens }
  | { kind: "idempotent"; tokens: IssuedTokens }
  | {
      kind: "invalid_grant";
      reason: "expired" | "replay" | "revoked" | "binding_mismatch";
    };

export type StoredAuthInfo = {
  clientId: string;
  principalId: string;
  scopes: string[];
  resource: string;
  expiresAt: number;
};

export type ConsentDecisionResult =
  | { kind: "confirmed"; upstreamState: string }
  | ({ kind: "denied" } & OAuthRedirectContext)
  | { kind: "invalid" };

export type ZendeskCallbackContext = OAuthRedirectContext & {
  transactionId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource: string;
  createdAt: number;
};

export interface OAuthStore extends OAuthRegisteredClientsStore {
  getClient(clientId: string): OAuthClientInformationFull | undefined;
  registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
  ): OAuthClientInformationFull;
  beginLogin(input: BeginLoginInput): LoginStart;
  decideConsent(input: ConsentDecisionInput): ConsentDecisionResult;
  claimZendeskCallback(
    upstreamState: string,
    now: number,
  ): ZendeskCallbackContext | undefined;
  stageLoginGrant(input: StageLoginGrantInput): { stageId: string };
  commitLogin(input: CommitLoginInput): LoginCommitResult;
  challengeForAuthorizationCode(
    clientId: string,
    code: string,
    now: number,
  ): string | undefined;
  consumeCodeAndIssueFamily(input: CodeExchangeInput): IssuedTokens;
  rotateRefreshToken(input: RefreshExchangeInput): RefreshExchangeResult;
  revokeFamilyByPresentedToken(clientId: string, token: string, now: number): void;
  lookupAccessToken(token: string, now: number): StoredAuthInfo | undefined;
  discardStagedGrant(stageId: string, now: number): boolean;
  failLogin(transactionId: string, now: number): OAuthRedirectContext | undefined;
  isReady(): boolean;
  assertReady(): void;
  recover(now: number): RecoverySummary;
  backup(destination: string): Promise<void>;
  inspectForTest(): StoreInspection;
  close(): void;
}
