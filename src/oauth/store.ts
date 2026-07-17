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

export interface OAuthStore extends OAuthRegisteredClientsStore {
  getClient(clientId: string): OAuthClientInformationFull | undefined;
  registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
  ): OAuthClientInformationFull;
  isReady(): boolean;
  assertReady(): void;
  recover(now: number): RecoverySummary;
  backup(destination: string): Promise<void>;
  inspectForTest(): StoreInspection;
  close(): void;
}
