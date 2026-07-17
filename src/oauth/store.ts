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
  failLogin(transactionId: string, now: number): OAuthRedirectContext | undefined;
  isReady(): boolean;
  assertReady(): void;
  recover(now: number): RecoverySummary;
  backup(destination: string): Promise<void>;
  inspectForTest(): StoreInspection;
  close(): void;
}
