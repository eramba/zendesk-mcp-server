import { timingSafeEqual } from "node:crypto";
import {
  chmodSync,
  closeSync,
  fchmodSync,
  mkdirSync,
  openSync,
  unlinkSync,
} from "node:fs";
import { dirname, isAbsolute } from "node:path";

import Database from "better-sqlite3";
import { InvalidClientMetadataError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

import {
  AUTHORIZATION_CODE_TTL_SECONDS,
  LOGIN_TTL_SECONDS,
  MCP_REFRESH_RETRY_SECONDS,
  MCP_REFRESH_TTL_SECONDS,
  MCP_SCOPE,
  MCP_SCOPES,
  ZENDESK_SCOPES,
  normalizeMcpScopes,
} from "./constants.js";
import { SCHEMA_VERSION, SQLITE_MIGRATIONS } from "./sqlite-schema.js";
import type {
  BeginLoginInput,
  CodeExchangeInput,
  CommitLoginInput,
  ConsentDecisionInput,
  ConsentDecisionResult,
  CredentialSnapshot,
  DisconnectResult,
  InstallRefreshResult,
  LoginCommitResult,
  LoginStart,
  OAuthRedirectContext,
  OAuthStore,
  RefreshExchangeInput,
  RefreshExchangeResult,
  RevocationClaim,
  RecoverySummary,
  IssuedTokens,
  StageLoginGrantInput,
  StageRefreshInput,
  StoredAuthInfo,
  StoreInspection,
  ZendeskGrant,
  ZendeskCallbackContext,
} from "./store.js";
import {
  digestBinding,
  hashOpaque,
  randomOpaque,
  TokenCipher,
  type EncryptedValue,
} from "./token-cipher.js";

const KEY_CHECK_METADATA = "encryption_key_check";
const KEY_CHECK_SENTINEL = "oauth-key-check-sentinel";
const KEY_CHECK_CONTEXT = {
  kind: "key_check",
  rowId: "store-key-check",
  expiresAt: 253402300799,
} as const;

const STARTUP_ERROR = "OAuth store failed to initialize";
const INVALID_KEY_ERROR = "OAuth store encryption key is invalid";
const NEWER_SCHEMA_ERROR = "OAuth store has newer schema version";
const SUPPORTED_GRANT_TYPES = ["authorization_code", "refresh_token"] as const;
const SUPPORTED_RESPONSE_TYPES = ["code"] as const;
const UNSUPPORTED_CLIENT_FIELDS = [
  "client_uri",
  "logo_uri",
  "contacts",
  "tos_uri",
  "policy_uri",
  "jwks_uri",
  "jwks",
  "software_id",
  "software_version",
  "software_statement",
] as const;

export type SqliteOAuthStoreOptions = {
  path: string;
  cipher: TokenCipher;
  mcpResourceUrl?: URL;
  now?: () => number;
  randomId?: () => string;
  randomToken?: (bytes?: number) => string;
  busyTimeoutMs?: number;
  testHooks?: {
    beforeLoginCommit?: () => void;
  };
};

type VersionRow = { version: number };
type CountRow = { count: number };
type MetadataRow = { value: string };
type ClientRow = {
  client_id: string;
  client_id_issued_at: number;
  token_endpoint_auth_method: string;
  grant_types_json: string;
  response_types_json: string;
  scope: string;
  client_name: string | null;
};
type RedirectRow = { redirect_uri: string };
type EffectivePragmas = StoreInspection["pragmas"] & { busyTimeout: number };
type LoginStatus =
  | "consent_pending"
  | "upstream_pending"
  | "callback_claimed"
  | "complete"
  | "failed"
  | "denied";
type LoginRow = {
  id: string;
  transaction_hash: string;
  upstream_state_hash: string | null;
  client_id: string;
  browser_nonce_hash: string;
  consent_csrf_hash: string;
  encrypted_payload_json: string;
  status: LoginStatus;
  created_at: number;
  expires_at: number;
  consented_at: number | null;
  completed_at: number | null;
};
type PrincipalRow = {
  id: string;
  subdomain: string;
  zendesk_user_id: string;
  status: "active" | "disconnected" | "reauthorization_required";
  lifecycle_epoch: number;
  disconnected_at: number | null;
  created_at: number;
  updated_at: number;
};
type StagedGrantRow = {
  id: string;
  login_transaction_id: string | null;
  purpose: "login" | "refresh";
  subdomain: string;
  expected_principal_id: string | null;
  expected_principal_epoch: number | null;
  expected_credential_version: number | null;
  encrypted_grant_json: string;
  status: "staged" | "discard_only";
  created_at: number;
  expires_at: number;
};
type MaximumCredentialVersionRow = { version: number };
type ClaimedOutboxRow = { present: number };
type CredentialRow = {
  principal_id: string;
  credential_version: number;
  principal_epoch: number;
  encrypted_grant_json: string;
  access_expires_at: number;
  refresh_expires_at: number;
  scopes: string;
  updated_at: number;
};
type RevocationOutboxRow = {
  id: string;
  principal_id: string;
  captured_principal_epoch: number;
  credential_version: number;
  encrypted_grant_json: string;
  status: "pending" | "claimed";
  attempt_count: number;
  next_attempt_at: number;
  claim_owner: string | null;
  claim_expires_at: number | null;
  retention_expires_at: number;
  last_error_category: string | null;
  created_at: number;
  completed_at: number | null;
  subdomain: string;
};
type AuthorizationCodeRow = {
  code_hash: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scopes: string;
  resource: string;
  principal_id: string;
  principal_epoch: number;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
};
type AccessTokenRow = {
  client_id: string;
  principal_id: string;
  principal_epoch: number;
  scopes: string;
  resource: string;
  expires_at: number;
  principal_status: PrincipalRow["status"];
  lifecycle_epoch: number;
  client_scope: string;
};
type RefreshGenerationRow = {
  token_hash: string;
  family_id: string;
  generation: number;
  status: "current" | "consumed";
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
  successor_generation: number | null;
  encrypted_retry_response_json: string | null;
  retry_response_expires_at: number | null;
  client_id: string;
  principal_id: string;
  principal_epoch: number;
  scopes: string;
  resource: string;
  revoked_at: number | null;
  principal_status: PrincipalRow["status"];
  lifecycle_epoch: number;
  client_scope: string;
};
type SuccessorGenerationRow = {
  token_hash: string;
  status: "current" | "consumed";
  consumed_at: number | null;
};

type EncryptedLoginPayload = {
  originalState: string | undefined;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource: string;
};

type LoginAadFields = {
  subdomain: string;
  redirectDigest: string;
  resourceDigest: string;
};

type StoredLoginPayload = LoginAadFields & {
  encrypted: EncryptedValue;
};

type LifecycleStore = Pick<
  OAuthStore,
  | "getClient"
  | "registerClient"
  | "beginLogin"
  | "decideConsent"
  | "claimZendeskCallback"
  | "stageLoginGrant"
  | "commitLogin"
  | "loadCredential"
  | "stageRefreshGrant"
  | "installStagedRefresh"
  | "markReauthorizationRequiredIfCurrent"
  | "challengeForAuthorizationCode"
  | "consumeCodeAndIssueFamily"
  | "rotateRefreshToken"
  | "revokeFamilyByPresentedToken"
  | "disconnectUser"
  | "claimDueRevocation"
  | "renewRevocationClaim"
  | "replaceRevocationGrant"
  | "rescheduleRevocation"
  | "completeRevocation"
  | "releaseClaims"
  | "lookupAccessToken"
  | "discardStagedGrant"
  | "failLogin"
  | "isReady"
  | "assertReady"
  | "recover"
  | "backup"
  | "inspectForTest"
  | "close"
>;

type ClientRegistration = Omit<
  OAuthClientInformationFull,
  "client_id" | "client_id_issued_at"
>;

function invalidClientMetadata(): InvalidClientMetadataError {
  return new InvalidClientMetadataError("invalid_client_metadata");
}

function invalidLoginRequest(): Error {
  return new Error("invalid login request");
}

function invalidLoginCommit(): Error {
  return new Error("invalid login commit");
}

function invalidAuthorizationCode(): Error {
  return new Error("invalid authorization code");
}

function sameSet(actual: readonly string[] | undefined, expected: readonly string[]): boolean {
  return Boolean(
    actual &&
      actual.length === expected.length &&
      expected.every((value) => actual.includes(value)),
  );
}

function normalizeRedirectUri(value: string): string {
  try {
    const url = new URL(value);
    const valid =
      url.protocol === "http:" &&
      (url.hostname === "127.0.0.1" || url.hostname === "localhost") &&
      url.port !== "" &&
      Number(url.port) > 0 &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "";
    if (!valid) throw invalidClientMetadata();
    return url.href;
  } catch (error) {
    if (error instanceof InvalidClientMetadataError) throw error;
    throw invalidClientMetadata();
  }
}

function canonicalMcpResource(value: URL | undefined): string | undefined {
  if (value === undefined) return undefined;
  try {
    const url = new URL(value.href);
    if (!(
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.hash === "" &&
      url.href === value.href
    )) {
      throw new Error("invalid MCP resource URL");
    }
    return url.href;
  } catch {
    throw new Error("OAuth store MCP resource URL is invalid");
  }
}

function isOpaque(value: string): boolean {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length >= 32 && decoded.toString("base64url") === value;
}

function loginCipherContext(row: LoginRow, stored: LoginAadFields) {
  return {
    kind: "login" as const,
    rowId: row.id,
    expiresAt: row.expires_at,
    subdomain: stored.subdomain,
    clientId: row.client_id,
    browserNonceHash: row.browser_nonce_hash,
    redirectDigest: stored.redirectDigest,
    resourceDigest: stored.resourceDigest,
  };
}

function parseStoredLoginPayload(row: LoginRow): StoredLoginPayload {
  const stored = JSON.parse(row.encrypted_payload_json) as Partial<StoredLoginPayload>;
  if (
    typeof stored !== "object" ||
    stored === null ||
    typeof stored.subdomain !== "string" ||
    typeof stored.redirectDigest !== "string" ||
    typeof stored.resourceDigest !== "string" ||
    typeof stored.encrypted !== "object" ||
    stored.encrypted === null
  ) {
    throw new Error("invalid encrypted login payload");
  }
  return stored as StoredLoginPayload;
}

function decryptLoginPayload(cipher: TokenCipher, row: LoginRow): EncryptedLoginPayload {
  const stored = parseStoredLoginPayload(row);

  const serialized = cipher.decrypt(
    stored.encrypted,
    loginCipherContext(row, stored),
  );
  const payload = JSON.parse(serialized) as Partial<EncryptedLoginPayload>;
  const originalStateValid =
    payload.originalState === undefined || typeof payload.originalState === "string";
  if (
    typeof payload !== "object" ||
    payload === null ||
    !originalStateValid ||
    typeof payload.redirectUri !== "string" ||
    typeof payload.codeChallenge !== "string" ||
    !Array.isArray(payload.scopes) ||
    payload.scopes.length !== MCP_SCOPES.length ||
    !payload.scopes.every((scope) => typeof scope === "string") ||
    !sameSet(payload.scopes, MCP_SCOPES) ||
    typeof payload.resource !== "string" ||
    digestBinding(payload.redirectUri) !== stored.redirectDigest ||
    digestBinding(payload.resource) !== stored.resourceDigest
  ) {
    throw new Error("invalid encrypted login payload");
  }
  return payload as EncryptedLoginPayload;
}

function validStoreTime(now: number): boolean {
  return Number.isSafeInteger(now) && now >= 0;
}

function validSubdomain(subdomain: string): boolean {
  return /^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(subdomain);
}

function validZendeskUserId(zendeskUserId: string): boolean {
  return (
    typeof zendeskUserId === "string" &&
    zendeskUserId.length > 0 &&
    zendeskUserId.length <= 128 &&
    !/[\u0000-\u001f\u007f]/.test(zendeskUserId)
  );
}

function validClaimOwner(owner: string): boolean {
  return typeof owner === "string" && /^[\x20-\x7e]{1,200}$/.test(owner);
}

function validErrorCategory(category: string): boolean {
  return typeof category === "string" && /^[\x20-\x7e]{1,100}$/.test(category);
}

function revocationBackoffSeconds(attemptCount: number): number | undefined {
  if (!Number.isSafeInteger(attemptCount) || attemptCount < 1) return undefined;
  const exponent = attemptCount - 1;
  return exponent >= 8 ? 900 : 5 * 2 ** exponent;
}

function normalizeZendeskGrant(grant: ZendeskGrant, now: number): ZendeskGrant | undefined {
  if (
    !grant ||
    typeof grant !== "object" ||
    typeof grant.accessToken !== "string" ||
    grant.accessToken.length === 0 ||
    typeof grant.refreshToken !== "string" ||
    grant.refreshToken.length === 0 ||
    !Number.isSafeInteger(grant.accessExpiresAt) ||
    grant.accessExpiresAt <= now ||
    !Number.isSafeInteger(grant.refreshExpiresAt) ||
    grant.refreshExpiresAt <= grant.accessExpiresAt ||
    !Array.isArray(grant.scopes) ||
    !grant.scopes.every((scope) => typeof scope === "string") ||
    !sameSet(grant.scopes, ZENDESK_SCOPES)
  ) {
    return undefined;
  }
  return { ...grant, scopes: [...ZENDESK_SCOPES] };
}

function stagedGrantCipherContext(row: StagedGrantRow) {
  return {
    kind: "staged_grant" as const,
    rowId: row.id,
    expiresAt: row.expires_at,
    purpose: row.purpose,
    subdomain: row.subdomain,
    expectedPrincipalId: row.expected_principal_id,
    expectedCredentialVersion: row.expected_credential_version,
    expectedPrincipalEpoch: row.expected_principal_epoch,
  };
}

function decryptStagedGrant(
  cipher: TokenCipher,
  row: StagedGrantRow,
  now: number,
): ZendeskGrant {
  const grant = JSON.parse(
    cipher.decrypt(
      JSON.parse(row.encrypted_grant_json) as EncryptedValue,
      stagedGrantCipherContext(row),
    ),
  ) as ZendeskGrant;
  const normalized = normalizeZendeskGrant(grant, now);
  if (!normalized) throw invalidLoginCommit();
  return normalized;
}

function decryptCredentialGrant(
  cipher: TokenCipher,
  principal: PrincipalRow,
  credential: CredentialRow,
): ZendeskGrant {
  const grant = JSON.parse(
    cipher.decrypt(
      JSON.parse(credential.encrypted_grant_json) as EncryptedValue,
      {
        kind: "zendesk_credential",
        rowId: principal.id,
        expiresAt: credential.refresh_expires_at,
        subdomain: principal.subdomain,
        principalId: principal.id,
        credentialVersion: credential.credential_version,
        principalEpoch: credential.principal_epoch,
      },
    ),
  ) as Partial<ZendeskGrant>;
  if (
    typeof grant !== "object" ||
    grant === null ||
    typeof grant.accessToken !== "string" ||
    grant.accessToken.length === 0 ||
    typeof grant.refreshToken !== "string" ||
    grant.refreshToken.length === 0 ||
    !Number.isSafeInteger(grant.accessExpiresAt) ||
    !Number.isSafeInteger(grant.refreshExpiresAt) ||
    (grant.refreshExpiresAt ?? 0) <= (grant.accessExpiresAt ?? 0) ||
    !Array.isArray(grant.scopes) ||
    !grant.scopes.every((scope) => typeof scope === "string") ||
    !sameSet(grant.scopes, ZENDESK_SCOPES)
  ) {
    throw new Error("invalid encrypted Zendesk credential");
  }
  return { ...(grant as ZendeskGrant), scopes: [...ZENDESK_SCOPES] };
}

function credentialSnapshot(
  cipher: TokenCipher,
  principal: PrincipalRow,
  credential: CredentialRow,
): CredentialSnapshot | undefined {
  if (
    principal.status !== "active" ||
    principal.lifecycle_epoch !== credential.principal_epoch
  ) {
    return undefined;
  }
  return {
    principalId: principal.id,
    zendeskUserId: principal.zendesk_user_id,
    principalEpoch: principal.lifecycle_epoch,
    credentialVersion: credential.credential_version,
    status: principal.status,
    grant: decryptCredentialGrant(cipher, principal, credential),
  };
}

function decryptRevocationGrant(
  cipher: TokenCipher,
  row: RevocationOutboxRow,
): ZendeskGrant {
  const grant = JSON.parse(
    cipher.decrypt(
      JSON.parse(row.encrypted_grant_json) as EncryptedValue,
      {
        kind: "disconnect_outbox",
        rowId: row.id,
        expiresAt: row.retention_expires_at,
        subdomain: row.subdomain,
        principalId: row.principal_id,
        credentialVersion: row.credential_version,
        principalEpoch: row.captured_principal_epoch,
      },
    ),
  ) as Partial<ZendeskGrant>;
  if (
    typeof grant !== "object" ||
    grant === null ||
    typeof grant.accessToken !== "string" ||
    grant.accessToken.length === 0 ||
    typeof grant.refreshToken !== "string" ||
    grant.refreshToken.length === 0 ||
    !Number.isSafeInteger(grant.accessExpiresAt) ||
    !Number.isSafeInteger(grant.refreshExpiresAt) ||
    (grant.refreshExpiresAt ?? 0) <= (grant.accessExpiresAt ?? 0) ||
    !Array.isArray(grant.scopes) ||
    !grant.scopes.every((scope) => typeof scope === "string") ||
    !sameSet(grant.scopes, ZENDESK_SCOPES)
  ) {
    throw new Error("invalid encrypted revocation grant");
  }
  return { ...(grant as ZendeskGrant), scopes: [...ZENDESK_SCOPES] };
}

function validateClientRegistration(client: ClientRegistration): {
  redirectUris: string[];
  clientName: string;
} {
  const runtimeClient = client as ClientRegistration & Record<string, unknown>;
  if (
    client.token_endpoint_auth_method !== "none" ||
    !sameSet(client.grant_types, SUPPORTED_GRANT_TYPES) ||
    !sameSet(client.response_types, SUPPORTED_RESPONSE_TYPES) ||
    (client.scope !== undefined && client.scope !== MCP_SCOPE) ||
    typeof client.client_name !== "string" ||
    !/^[\x20-\x7e]{1,200}$/.test(client.client_name) ||
    !Array.isArray(client.redirect_uris) ||
    client.redirect_uris.length === 0 ||
    client.redirect_uris.some((value) => typeof value !== "string") ||
    UNSUPPORTED_CLIENT_FIELDS.some((field) => runtimeClient[field] !== undefined) ||
    runtimeClient.client_id !== undefined ||
    runtimeClient.client_id_issued_at !== undefined ||
    client.client_secret !== undefined ||
    client.client_secret_expires_at !== undefined
  ) {
    throw invalidClientMetadata();
  }

  const redirectUris = [
    ...new Set(client.redirect_uris.map((value) => normalizeRedirectUri(value))),
  ].sort();
  if (redirectUris.length === 0) throw invalidClientMetadata();
  return { redirectUris, clientName: client.client_name };
}

function schemaVersion(db: Database.Database): number {
  const exists = db
    .prepare<[], { present: number }>(
      "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
    )
    .get();
  if (!exists) return 0;
  return (
    db
      .prepare<[], VersionRow>("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations")
      .get()?.version ?? 0
  );
}

function applyMigrations(
  db: Database.Database,
  currentVersion: number,
  now: number,
  cipher: TokenCipher,
): void {
  for (const migration of SQLITE_MIGRATIONS) {
    if (migration.version <= currentVersion) continue;
    db.transaction(() => {
      db.exec(migration.sql);
      if (migration.version === 1) {
        const encrypted = cipher.encrypt(KEY_CHECK_SENTINEL, KEY_CHECK_CONTEXT);
        db.prepare("INSERT INTO store_metadata (key, value) VALUES (?, ?)").run(
          KEY_CHECK_METADATA,
          JSON.stringify(encrypted),
        );
      }
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(
        migration.version,
        now,
      );
    })();
  }
}

function verifyEncryptionKey(db: Database.Database, cipher: TokenCipher): void {
  const metadata = db
    .prepare<[string], MetadataRow>("SELECT value FROM store_metadata WHERE key = ?")
    .get(KEY_CHECK_METADATA);

  if (!metadata) throw new Error(INVALID_KEY_ERROR);

  try {
    const decrypted = Buffer.from(
      cipher.decrypt(JSON.parse(metadata.value) as EncryptedValue, KEY_CHECK_CONTEXT),
      "utf8",
    );
    const expected = Buffer.from(KEY_CHECK_SENTINEL, "utf8");
    const comparable = Buffer.alloc(expected.length);
    decrypted.copy(comparable, 0, 0, expected.length);
    if (decrypted.length !== expected.length || !timingSafeEqual(comparable, expected)) {
      throw new Error(INVALID_KEY_ERROR);
    }
  } catch {
    throw new Error(INVALID_KEY_ERROR);
  }
}

function readEffectivePragmas(db: Database.Database): EffectivePragmas {
  return {
    foreignKeys: db.pragma("foreign_keys", { simple: true }) as number,
    journalMode: db.pragma("journal_mode", { simple: true }) as string,
    synchronous: db.pragma("synchronous", { simple: true }) as number,
    busyTimeout: db.pragma("busy_timeout", { simple: true }) as number,
    trustedSchema: db.pragma("trusted_schema", { simple: true }) as number,
    secureDelete: db.pragma("secure_delete", { simple: true }) as number,
  };
}

function verifyEffectivePragmas(db: Database.Database, busyTimeoutMs: number): void {
  const pragmas = readEffectivePragmas(db);
  if (
    pragmas.foreignKeys !== 1 ||
    pragmas.journalMode !== "wal" ||
    pragmas.synchronous !== 2 ||
    pragmas.busyTimeout !== busyTimeoutMs ||
    pragmas.trustedSchema !== 0 ||
    pragmas.secureDelete !== 1
  ) {
    throw new Error("OAuth store pragma verification failed");
  }
}

function recoverRows(db: Database.Database, now: number): RecoverySummary {
  return db.transaction(() => {
    db.prepare(
      `UPDATE refresh_token_generations
       SET encrypted_retry_response_json = NULL
       WHERE retry_response_expires_at IS NOT NULL
         AND retry_response_expires_at <= ?`,
    ).run(now);
    const expiredLogins = db
      .prepare(
        `UPDATE login_transactions
         SET status = 'failed', completed_at = ?
         WHERE expires_at <= ?
           AND status IN ('consent_pending', 'upstream_pending', 'callback_claimed')`,
      )
      .run(now, now).changes;
    db
      .prepare(
        `UPDATE staged_grants
         SET status = 'discard_only'
         WHERE status = 'staged' AND expires_at <= ?`,
      )
      .run(now);
    const discardedStages = db
      .prepare("DELETE FROM staged_grants WHERE status = 'discard_only'")
      .run().changes;
    db.prepare(
      `UPDATE revocation_outbox
       SET status = 'claimed', encrypted_grant_json = '{}',
           claim_owner = NULL, claim_expires_at = NULL,
           completed_at = COALESCE(completed_at, ?)
       WHERE retention_expires_at <= ?`,
    ).run(now, now);
    const reclaimedClaims = db
      .prepare(
        `UPDATE revocation_outbox
         SET status = 'pending', claim_owner = NULL, claim_expires_at = NULL
         WHERE status = 'claimed'
           AND completed_at IS NULL
           AND claim_expires_at <= ?`,
      )
      .run(now).changes;
    return { expiredLogins, discardedStages, reclaimedClaims };
  }).immediate();
}

class SqliteOAuthStore implements LifecycleStore {
  readonly #db: Database.Database;
  readonly #cipher: TokenCipher;
  readonly #mcpResource: string | undefined;
  readonly #now: () => number;
  readonly #randomId: () => string;
  readonly #randomToken: (bytes?: number) => string;
  readonly #testHooks: SqliteOAuthStoreOptions["testHooks"];
  #ready = false;

  constructor(
    db: Database.Database,
    cipher: TokenCipher,
    mcpResource: string | undefined,
    now: () => number,
    randomId: () => string,
    randomToken: (bytes?: number) => string,
    testHooks: SqliteOAuthStoreOptions["testHooks"],
  ) {
    this.#db = db;
    this.#cipher = cipher;
    this.#mcpResource = mcpResource;
    this.#now = now;
    this.#randomId = randomId;
    this.#randomToken = randomToken;
    this.#testHooks = testHooks;
  }

  markReady(): void {
    this.#ready = true;
  }

  isReady(): boolean {
    return this.#ready && this.#db.open;
  }

  assertReady(): void {
    if (!this.isReady()) throw new Error("OAuth store is not ready");
  }

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    this.assertReady();
    const row = this.#db
      .prepare<[string], ClientRow>(
        `SELECT client_id, client_id_issued_at, token_endpoint_auth_method,
                grant_types_json, response_types_json, scope, client_name
         FROM oauth_clients
         WHERE client_id = ?`,
      )
      .get(clientId);
    if (!row) return undefined;

    const redirectUris = this.#db
      .prepare<[string], RedirectRow>(
        `SELECT redirect_uri
         FROM oauth_client_redirect_uris
         WHERE client_id = ?
         ORDER BY redirect_uri`,
      )
      .all(clientId)
      .map(({ redirect_uri }) => redirect_uri);

    return {
      client_id: row.client_id,
      client_id_issued_at: row.client_id_issued_at,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: row.token_endpoint_auth_method,
      grant_types: JSON.parse(row.grant_types_json) as string[],
      response_types: JSON.parse(row.response_types_json) as string[],
      scope: row.scope,
      client_name: row.client_name ?? undefined,
    };
  }

  registerClient(client: ClientRegistration): OAuthClientInformationFull {
    this.assertReady();
    const { redirectUris, clientName } = validateClientRegistration(client);
    const clientId = this.#randomToken(32);
    const issuedAt = Math.floor(this.#now());
    if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) {
      throw new Error("OAuth store clock is invalid");
    }

    const registered: OAuthClientInformationFull = {
      client_id: clientId,
      client_id_issued_at: issuedAt,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "none",
      grant_types: [...SUPPORTED_GRANT_TYPES],
      response_types: [...SUPPORTED_RESPONSE_TYPES],
      scope: MCP_SCOPE,
      client_name: clientName,
    };

    this.#db.transaction(() => {
      this.#db
        .prepare(
          `INSERT INTO oauth_clients (
             client_id, client_id_issued_at, token_endpoint_auth_method,
             grant_types_json, response_types_json, scope, client_name,
             metadata_json, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          clientId,
          issuedAt,
          registered.token_endpoint_auth_method,
          JSON.stringify(registered.grant_types),
          JSON.stringify(registered.response_types),
          registered.scope,
          clientName,
          JSON.stringify(registered),
          issuedAt,
        );
      const insertRedirect = this.#db.prepare(
        `INSERT INTO oauth_client_redirect_uris (client_id, redirect_uri)
         VALUES (?, ?)`,
      );
      for (const redirectUri of redirectUris) insertRedirect.run(clientId, redirectUri);
    })();

    return registered;
  }

  beginLogin(input: BeginLoginInput): LoginStart {
    this.assertReady();
    let scopes: string[];
    try {
      scopes = normalizeMcpScopes(input.scopes);
    } catch {
      throw invalidLoginRequest();
    }
    if (
      input.scopes.length !== scopes.length ||
      this.#mcpResource === undefined ||
      input.resource !== this.#mcpResource ||
      typeof input.codeChallenge !== "string" ||
      input.codeChallenge.length === 0 ||
      !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(input.subdomain) ||
      (input.originalState !== undefined && typeof input.originalState !== "string") ||
      !Number.isSafeInteger(input.now) ||
      input.now < 0 ||
      input.now > Number.MAX_SAFE_INTEGER - LOGIN_TTL_SECONDS
    ) {
      throw invalidLoginRequest();
    }

    return this.#db.transaction(() => {
      const registeredRedirect = this.#db
        .prepare<[string, string], { present: number }>(
          `SELECT 1 AS present
           FROM oauth_client_redirect_uris
           WHERE client_id = ? AND redirect_uri = ?`,
        )
        .get(input.clientId, input.redirectUri);
      if (!registeredRedirect) throw invalidLoginRequest();

      const id = this.#randomToken(32);
      const transactionToken = this.#randomToken(32);
      const consentCsrf = this.#randomToken(32);
      const browserNonce = this.#randomToken(32);
      const opaqueValues = [id, transactionToken, consentCsrf, browserNonce];
      if (
        opaqueValues.some((value) => !isOpaque(value)) ||
        new Set(opaqueValues).size !== opaqueValues.length
      ) {
        throw new Error("OAuth store random source is invalid");
      }

      const expiresAt = input.now + LOGIN_TTL_SECONDS;
      const browserNonceHash = hashOpaque(browserNonce);
      const stored: LoginAadFields = {
        subdomain: input.subdomain,
        redirectDigest: digestBinding(input.redirectUri),
        resourceDigest: digestBinding(input.resource),
      };
      const payload: EncryptedLoginPayload = {
        originalState: input.originalState,
        redirectUri: input.redirectUri,
        codeChallenge: input.codeChallenge,
        scopes,
        resource: input.resource,
      };
      const encrypted = this.#cipher.encrypt(
        JSON.stringify(payload),
        loginCipherContext(
          {
            id,
            transaction_hash: hashOpaque(transactionToken),
            upstream_state_hash: null,
            client_id: input.clientId,
            browser_nonce_hash: browserNonceHash,
            consent_csrf_hash: hashOpaque(consentCsrf),
            encrypted_payload_json: "",
            status: "consent_pending",
            created_at: input.now,
            expires_at: expiresAt,
            consented_at: null,
            completed_at: null,
          },
          stored,
        ),
      );

      this.#db
        .prepare(
          `INSERT INTO login_transactions (
             id, transaction_hash, upstream_state_hash, client_id,
             browser_nonce_hash, consent_csrf_hash, encrypted_payload_json,
             status, created_at, expires_at, consented_at, completed_at
           ) VALUES (?, ?, NULL, ?, ?, ?, ?, 'consent_pending', ?, ?, NULL, NULL)`,
        )
        .run(
          id,
          hashOpaque(transactionToken),
          input.clientId,
          browserNonceHash,
          hashOpaque(consentCsrf),
          JSON.stringify({ ...stored, encrypted } satisfies StoredLoginPayload),
          input.now,
          expiresAt,
        );

      return { transactionToken, consentCsrf, browserNonce, expiresAt };
    })();
  }

  decideConsent(input: ConsentDecisionInput): ConsentDecisionResult {
    this.assertReady();
    if (
      (input.decision !== "confirm" && input.decision !== "deny") ||
      !Number.isSafeInteger(input.now) ||
      input.now < 0
    ) {
      return { kind: "invalid" };
    }

    return this.#db.transaction((): ConsentDecisionResult => {
      const transactionHash = hashOpaque(input.transactionToken);
      const csrfHash = hashOpaque(input.consentCsrf);
      const browserNonceHash = hashOpaque(input.browserNonce);
      const row = this.#db
        .prepare<[string, string, string, number], LoginRow>(
          `SELECT * FROM login_transactions
           WHERE transaction_hash = ?
             AND consent_csrf_hash = ?
             AND browser_nonce_hash = ?
             AND status = 'consent_pending'
             AND expires_at > ?`,
        )
        .get(transactionHash, csrfHash, browserNonceHash, input.now);
      if (!row) return { kind: "invalid" };

      let payload: EncryptedLoginPayload;
      try {
        payload = decryptLoginPayload(this.#cipher, row);
      } catch {
        return { kind: "invalid" };
      }

      if (input.decision === "deny") {
        const consumed = this.#db
          .prepare(
            `UPDATE login_transactions
             SET status = 'denied', consented_at = ?, completed_at = ?
             WHERE id = ? AND status = 'consent_pending' AND expires_at > ?`,
          )
          .run(input.now, input.now, row.id, input.now).changes;
        if (consumed !== 1) return { kind: "invalid" };
        return {
          kind: "denied",
          redirectUri: payload.redirectUri,
          originalState: payload.originalState,
        };
      }

      const upstreamState = this.#randomToken(32);
      if (!isOpaque(upstreamState)) throw new Error("OAuth store random source is invalid");
      const upstreamStateHash = hashOpaque(upstreamState);
      if (
        [row.transaction_hash, row.consent_csrf_hash, row.browser_nonce_hash].includes(
          upstreamStateHash,
        )
      ) {
        throw new Error("OAuth store random source is invalid");
      }
      const consumed = this.#db
        .prepare(
          `UPDATE login_transactions
           SET status = 'upstream_pending', upstream_state_hash = ?, consented_at = ?
           WHERE id = ? AND status = 'consent_pending' AND expires_at > ?`,
        )
        .run(upstreamStateHash, input.now, row.id, input.now).changes;
      if (consumed !== 1) return { kind: "invalid" };
      return { kind: "confirmed", upstreamState };
    })();
  }

  claimZendeskCallback(
    upstreamState: string,
    now: number,
  ): ZendeskCallbackContext | undefined {
    this.assertReady();
    if (!Number.isSafeInteger(now) || now < 0) return undefined;

    return this.#db.transaction(() => {
      const row = this.#db
        .prepare<[string, number], LoginRow>(
          `SELECT * FROM login_transactions
           WHERE upstream_state_hash = ?
             AND status = 'upstream_pending'
             AND expires_at > ?`,
        )
        .get(hashOpaque(upstreamState), now);
      if (!row) return undefined;

      let payload: EncryptedLoginPayload;
      try {
        payload = decryptLoginPayload(this.#cipher, row);
      } catch {
        return undefined;
      }
      const claimed = this.#db
        .prepare(
          `UPDATE login_transactions
           SET status = 'callback_claimed'
           WHERE id = ? AND status = 'upstream_pending' AND expires_at > ?`,
        )
        .run(row.id, now).changes;
      if (claimed !== 1) return undefined;

      return {
        transactionId: row.id,
        clientId: row.client_id,
        redirectUri: payload.redirectUri,
        originalState: payload.originalState,
        codeChallenge: payload.codeChallenge,
        scopes: payload.scopes,
        resource: payload.resource,
        createdAt: row.created_at,
      };
    })();
  }

  stageLoginGrant(input: StageLoginGrantInput): { stageId: string } {
    this.assertReady();
    const grant = normalizeZendeskGrant(input.grant, input.now);
    if (
      !validStoreTime(input.now) ||
      typeof input.transactionId !== "string" ||
      !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(input.subdomain) ||
      !grant
    ) {
      throw invalidLoginCommit();
    }

    return this.#db.transaction(() => {
      const login = this.#db
        .prepare<[string, number], LoginRow>(
          `SELECT * FROM login_transactions
           WHERE id = ? AND status = 'callback_claimed' AND expires_at > ?`,
        )
        .get(input.transactionId, input.now);
      if (!login) throw invalidLoginCommit();

      let storedLogin: StoredLoginPayload;
      try {
        storedLogin = parseStoredLoginPayload(login);
        decryptLoginPayload(this.#cipher, login);
      } catch {
        throw invalidLoginCommit();
      }
      if (storedLogin.subdomain !== input.subdomain) throw invalidLoginCommit();

      const stageId = this.#randomId();
      if (!isOpaque(stageId)) throw new Error("OAuth store random source is invalid");
      const stage: StagedGrantRow = {
        id: stageId,
        login_transaction_id: login.id,
        purpose: "login",
        subdomain: input.subdomain,
        expected_principal_id: null,
        expected_principal_epoch: null,
        expected_credential_version: null,
        encrypted_grant_json: "",
        status: "staged",
        created_at: input.now,
        expires_at: login.expires_at,
      };
      const encrypted = this.#cipher.encrypt(
        JSON.stringify(grant),
        stagedGrantCipherContext(stage),
      );
      this.#db
        .prepare(
          `INSERT INTO staged_grants (
             id, login_transaction_id, purpose, subdomain,
             expected_principal_id, expected_principal_epoch,
             expected_credential_version, encrypted_grant_json,
             status, created_at, expires_at
           ) VALUES (?, ?, 'login', ?, NULL, NULL, NULL, ?, 'staged', ?, ?)`,
        )
        .run(
          stage.id,
          stage.login_transaction_id,
          stage.subdomain,
          JSON.stringify(encrypted),
          stage.created_at,
          stage.expires_at,
        );
      return { stageId };
    })();
  }

  commitLogin(input: CommitLoginInput): LoginCommitResult {
    this.assertReady();
    if (
      !validStoreTime(input.now) ||
      input.now > Number.MAX_SAFE_INTEGER - AUTHORIZATION_CODE_TTL_SECONDS ||
      typeof input.transactionId !== "string" ||
      typeof input.stageId !== "string" ||
      typeof input.zendeskUserId !== "string" ||
      input.zendeskUserId.length === 0 ||
      input.zendeskUserId.length > 128 ||
      /[\u0000-\u001f\u007f]/.test(input.zendeskUserId)
    ) {
      throw invalidLoginCommit();
    }

    return this.#db.transaction((): LoginCommitResult => {
      const login = this.#db
        .prepare<[string, number], LoginRow>(
          `SELECT * FROM login_transactions
           WHERE id = ? AND status = 'callback_claimed' AND expires_at > ?`,
        )
        .get(input.transactionId, input.now);
      const stage = this.#db
        .prepare<[string, string, number], StagedGrantRow>(
          `SELECT * FROM staged_grants
           WHERE id = ?
             AND login_transaction_id = ?
             AND purpose = 'login'
             AND status = 'staged'
             AND expires_at > ?`,
        )
        .get(input.stageId, input.transactionId, input.now);
      if (!login || !stage) throw invalidLoginCommit();

      let payload: EncryptedLoginPayload;
      let storedLogin: StoredLoginPayload;
      let grant: ZendeskGrant;
      try {
        storedLogin = parseStoredLoginPayload(login);
        payload = decryptLoginPayload(this.#cipher, login);
        grant = decryptStagedGrant(this.#cipher, stage, input.now);
      } catch {
        throw invalidLoginCommit();
      }
      if (
        storedLogin.subdomain !== stage.subdomain ||
        stage.expected_principal_id !== null ||
        stage.expected_principal_epoch !== null ||
        stage.expected_credential_version !== null
      ) {
        throw invalidLoginCommit();
      }

      const existing = this.#db
        .prepare<[string, string], PrincipalRow>(
          `SELECT * FROM principals WHERE subdomain = ? AND zendesk_user_id = ?`,
        )
        .get(stage.subdomain, input.zendeskUserId);
      const principalId = existing?.id ?? this.#randomId();
      if (!isOpaque(principalId)) throw new Error("OAuth store random source is invalid");

      let principalEpoch = existing?.lifecycle_epoch ?? 1;
      if (existing?.status === "disconnected") {
        if (
          existing.disconnected_at === null ||
          login.created_at <= existing.disconnected_at
        ) {
          throw invalidLoginCommit();
        }
        const claimed = this.#db
          .prepare<[string, number, number], ClaimedOutboxRow>(
            `SELECT 1 AS present FROM revocation_outbox
             WHERE principal_id = ?
               AND captured_principal_epoch = ?
               AND status = 'claimed'
               AND completed_at IS NULL
               AND claim_expires_at > ?
             LIMIT 1`,
          )
          .get(existing.id, existing.lifecycle_epoch, input.now);
        if (claimed) throw invalidLoginCommit();
        principalEpoch += 1;
      }

      const maximumVersion = this.#db
        .prepare<[string, string], MaximumCredentialVersionRow>(
          `SELECT MAX(version) AS version FROM (
             SELECT credential_version AS version
             FROM zendesk_credentials WHERE principal_id = ?
             UNION ALL
             SELECT credential_version AS version
             FROM revocation_outbox WHERE principal_id = ?
           )`,
        )
        .get(principalId, principalId)?.version ?? 0;
      const credentialVersion = maximumVersion + 1;
      if (!Number.isSafeInteger(credentialVersion) || credentialVersion < 1) {
        throw invalidLoginCommit();
      }

      if (!existing) {
        this.#db
          .prepare(
            `INSERT INTO principals (
               id, subdomain, zendesk_user_id, status, lifecycle_epoch,
               disconnected_at, created_at, updated_at
             ) VALUES (?, ?, ?, 'active', 1, NULL, ?, ?)`,
          )
          .run(principalId, stage.subdomain, input.zendeskUserId, input.now, input.now);
      } else {
        if (existing.status === "disconnected") {
          this.#db
            .prepare(
              `DELETE FROM revocation_outbox
               WHERE principal_id = ?
                 AND captured_principal_epoch = ?
                 AND completed_at IS NULL
                 AND (
                   status = 'pending'
                   OR (status = 'claimed' AND claim_expires_at <= ?)
                 )`,
            )
            .run(existing.id, existing.lifecycle_epoch, input.now);
        }
        this.#db
          .prepare(
            `UPDATE principals
             SET status = 'active', lifecycle_epoch = ?, disconnected_at = NULL, updated_at = ?
             WHERE id = ?`,
          )
          .run(principalEpoch, input.now, principalId);
      }

      const encryptedCredential = this.#cipher.encrypt(JSON.stringify(grant), {
        kind: "zendesk_credential",
        rowId: principalId,
        expiresAt: grant.refreshExpiresAt,
        subdomain: stage.subdomain,
        principalId,
        credentialVersion,
        principalEpoch,
      });
      this.#db
        .prepare(
          `INSERT INTO zendesk_credentials (
             principal_id, credential_version, principal_epoch, encrypted_grant_json,
             access_expires_at, refresh_expires_at, scopes, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(principal_id) DO UPDATE SET
             credential_version = excluded.credential_version,
             principal_epoch = excluded.principal_epoch,
             encrypted_grant_json = excluded.encrypted_grant_json,
             access_expires_at = excluded.access_expires_at,
             refresh_expires_at = excluded.refresh_expires_at,
             scopes = excluded.scopes,
             updated_at = excluded.updated_at`,
        )
        .run(
          principalId,
          credentialVersion,
          principalEpoch,
          JSON.stringify(encryptedCredential),
          grant.accessExpiresAt,
          grant.refreshExpiresAt,
          grant.scopes.join(" "),
          input.now,
        );

      const authorizationCode = this.#randomToken(32);
      if (!isOpaque(authorizationCode)) {
        throw new Error("OAuth store random source is invalid");
      }
      const codeHash = hashOpaque(authorizationCode);
      if (
        [
          login.transaction_hash,
          login.upstream_state_hash,
          login.browser_nonce_hash,
          login.consent_csrf_hash,
        ].includes(codeHash)
      ) {
        throw new Error("OAuth store random source is invalid");
      }
      this.#db
        .prepare(
          `INSERT INTO authorization_codes (
             code_hash, client_id, redirect_uri, code_challenge, scopes, resource,
             principal_id, principal_epoch, created_at, expires_at, consumed_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
        )
        .run(
          codeHash,
          login.client_id,
          payload.redirectUri,
          payload.codeChallenge,
          payload.scopes.join(" "),
          payload.resource,
          principalId,
          principalEpoch,
          input.now,
          input.now + AUTHORIZATION_CODE_TTL_SECONDS,
        );

      const completed = this.#db
        .prepare(
          `UPDATE login_transactions
           SET status = 'complete', completed_at = ?
           WHERE id = ? AND status = 'callback_claimed' AND expires_at > ?`,
        )
        .run(input.now, login.id, input.now).changes;
      const deletedStage = this.#db
        .prepare(
          `DELETE FROM staged_grants WHERE id = ? AND status = 'staged'`,
        )
        .run(stage.id).changes;
      if (completed !== 1 || deletedStage !== 1) throw invalidLoginCommit();

      this.#testHooks?.beforeLoginCommit?.();

      return {
        redirectUri: payload.redirectUri,
        originalState: payload.originalState,
        principalId,
        principalEpoch,
        authorizationCode,
      };
    }).immediate();
  }

  loadCredential(principalId: string): CredentialSnapshot | undefined {
    this.assertReady();
    if (typeof principalId !== "string" || principalId.length === 0) return undefined;
    return this.#db.transaction(() => {
      const principal = this.#db
        .prepare<[string], PrincipalRow>("SELECT * FROM principals WHERE id = ?")
        .get(principalId);
      if (!principal || principal.status !== "active") return undefined;
      const credential = this.#db
        .prepare<[string], CredentialRow>(
          "SELECT * FROM zendesk_credentials WHERE principal_id = ?",
        )
        .get(principalId);
      if (!credential) return undefined;
      return credentialSnapshot(this.#cipher, principal, credential);
    })();
  }

  stageRefreshGrant(input: StageRefreshInput): { stageId: string } {
    this.assertReady();
    const grant = normalizeZendeskGrant(input.grant, input.now);
    if (
      !validStoreTime(input.now) ||
      typeof input.principalId !== "string" ||
      input.principalId.length === 0 ||
      !Number.isSafeInteger(input.expectedPrincipalEpoch) ||
      input.expectedPrincipalEpoch < 1 ||
      !Number.isSafeInteger(input.expectedCredentialVersion) ||
      input.expectedCredentialVersion < 1 ||
      !grant
    ) {
      throw new Error("invalid refresh stage");
    }

    return this.#db.transaction(() => {
      const principal = this.#db
        .prepare<[string, number, number, number], PrincipalRow>(
          `SELECT principals.*
           FROM principals
           JOIN zendesk_credentials
             ON zendesk_credentials.principal_id = principals.id
           WHERE principals.id = ?
             AND principals.status = 'active'
             AND principals.lifecycle_epoch = ?
             AND zendesk_credentials.principal_epoch = ?
             AND zendesk_credentials.credential_version = ?`,
        )
        .get(
          input.principalId,
          input.expectedPrincipalEpoch,
          input.expectedPrincipalEpoch,
          input.expectedCredentialVersion,
        );
      if (!principal) throw new Error("invalid refresh stage");
      const stageId = this.#randomId();
      if (!isOpaque(stageId)) throw new Error("OAuth store random source is invalid");
      const stage: StagedGrantRow = {
        id: stageId,
        login_transaction_id: null,
        purpose: "refresh",
        subdomain: principal.subdomain,
        expected_principal_id: input.principalId,
        expected_principal_epoch: input.expectedPrincipalEpoch,
        expected_credential_version: input.expectedCredentialVersion,
        encrypted_grant_json: "",
        status: "staged",
        created_at: input.now,
        expires_at: grant.accessExpiresAt,
      };
      const encrypted = this.#cipher.encrypt(
        JSON.stringify(grant),
        stagedGrantCipherContext(stage),
      );
      this.#db
        .prepare(
          `INSERT INTO staged_grants (
             id, login_transaction_id, purpose, subdomain,
             expected_principal_id, expected_principal_epoch,
             expected_credential_version, encrypted_grant_json,
             status, created_at, expires_at
           ) VALUES (?, NULL, 'refresh', ?, ?, ?, ?, ?, 'staged', ?, ?)`,
        )
        .run(
          stage.id,
          stage.subdomain,
          stage.expected_principal_id,
          stage.expected_principal_epoch,
          stage.expected_credential_version,
          JSON.stringify(encrypted),
          stage.created_at,
          stage.expires_at,
        );
      return { stageId };
    }).immediate();
  }

  installStagedRefresh(stageId: string, now: number): InstallRefreshResult {
    this.assertReady();
    if (typeof stageId !== "string" || !validStoreTime(now)) {
      throw new Error("invalid refresh stage");
    }

    return this.#db.transaction((): InstallRefreshResult => {
      const stage = this.#db
        .prepare<[string, number], StagedGrantRow>(
          `SELECT * FROM staged_grants
           WHERE id = ? AND purpose = 'refresh' AND status = 'staged' AND expires_at > ?`,
        )
        .get(stageId, now);
      if (
        !stage ||
        stage.expected_principal_id === null ||
        stage.expected_principal_epoch === null ||
        stage.expected_credential_version === null
      ) {
        throw new Error("invalid refresh stage");
      }
      let grant: ZendeskGrant;
      try {
        grant = decryptStagedGrant(this.#cipher, stage, now);
      } catch {
        throw new Error("invalid refresh stage");
      }

      const principal = this.#db
        .prepare<[string], PrincipalRow>("SELECT * FROM principals WHERE id = ?")
        .get(stage.expected_principal_id);
      const credential = principal
        ? this.#db
            .prepare<[string], CredentialRow>(
              "SELECT * FROM zendesk_credentials WHERE principal_id = ?",
            )
            .get(principal.id)
        : undefined;
      const current = principal && credential
        ? credentialSnapshot(this.#cipher, principal, credential)
        : undefined;

      if (
        current &&
        current.principalEpoch === stage.expected_principal_epoch &&
        current.credentialVersion === stage.expected_credential_version
      ) {
        const credentialVersion = current.credentialVersion + 1;
        if (!Number.isSafeInteger(credentialVersion)) {
          throw new Error("OAuth credential version overflow");
        }
        const encrypted = this.#cipher.encrypt(JSON.stringify(grant), {
          kind: "zendesk_credential",
          rowId: current.principalId,
          expiresAt: grant.refreshExpiresAt,
          subdomain: stage.subdomain,
          principalId: current.principalId,
          credentialVersion,
          principalEpoch: current.principalEpoch,
        });
        const installed = this.#db
          .prepare(
            `UPDATE zendesk_credentials
             SET credential_version = ?, encrypted_grant_json = ?,
                 access_expires_at = ?, refresh_expires_at = ?, scopes = ?, updated_at = ?
             WHERE principal_id = ? AND principal_epoch = ? AND credential_version = ?`,
          )
          .run(
            credentialVersion,
            JSON.stringify(encrypted),
            grant.accessExpiresAt,
            grant.refreshExpiresAt,
            grant.scopes.join(" "),
            now,
            current.principalId,
            current.principalEpoch,
            current.credentialVersion,
          ).changes;
        if (installed !== 1) throw new Error("OAuth credential changed concurrently");
        const deleted = this.#db
          .prepare("DELETE FROM staged_grants WHERE id = ? AND status = 'staged'")
          .run(stage.id).changes;
        if (deleted !== 1) throw new Error("OAuth refresh stage changed concurrently");
        return {
          kind: "installed",
          snapshot: {
            ...current,
            credentialVersion,
            grant,
          },
        };
      }

      const deleted = this.#db
        .prepare("DELETE FROM staged_grants WHERE id = ? AND status = 'staged'")
        .run(stage.id).changes;
      if (deleted !== 1) throw new Error("OAuth refresh stage changed concurrently");
      if (current) return { kind: "winner", snapshot: current };
      return { kind: "disconnected" };
    }).immediate();
  }

  markReauthorizationRequiredIfCurrent(input: {
    principalId: string;
    expectedPrincipalEpoch: number;
    expectedCredentialVersion: number;
    now: number;
  }): boolean {
    this.assertReady();
    if (
      typeof input.principalId !== "string" ||
      input.principalId.length === 0 ||
      !Number.isSafeInteger(input.expectedPrincipalEpoch) ||
      input.expectedPrincipalEpoch < 1 ||
      !Number.isSafeInteger(input.expectedCredentialVersion) ||
      input.expectedCredentialVersion < 1 ||
      !validStoreTime(input.now)
    ) {
      return false;
    }

    return this.#db.transaction(() => {
      const principal = this.#db
        .prepare<[string], PrincipalRow>("SELECT * FROM principals WHERE id = ?")
        .get(input.principalId);
      const credential = principal
        ? this.#db
            .prepare<[string], CredentialRow>(
              "SELECT * FROM zendesk_credentials WHERE principal_id = ?",
            )
            .get(principal.id)
        : undefined;
      if (
        !principal ||
        !credential ||
        principal.status !== "active" ||
        principal.lifecycle_epoch !== input.expectedPrincipalEpoch ||
        credential.principal_epoch !== input.expectedPrincipalEpoch ||
        credential.credential_version !== input.expectedCredentialVersion
      ) {
        return false;
      }
      const nextEpoch = principal.lifecycle_epoch + 1;
      if (!Number.isSafeInteger(nextEpoch)) {
        throw new Error("OAuth principal lifecycle epoch overflow");
      }
      const changed = this.#db
        .prepare(
          `UPDATE principals
           SET status = 'reauthorization_required', lifecycle_epoch = ?, updated_at = ?
           WHERE id = ? AND status = 'active' AND lifecycle_epoch = ?`,
        )
        .run(nextEpoch, input.now, principal.id, principal.lifecycle_epoch).changes;
      if (changed !== 1) return false;
      this.#db
        .prepare(
          `UPDATE authorization_codes SET consumed_at = ?
           WHERE principal_id = ? AND consumed_at IS NULL`,
        )
        .run(input.now, principal.id);
      this.#db
        .prepare(
          `UPDATE token_families
           SET revoked_at = ?, revoke_reason = 'principal_reauthorization_required'
           WHERE principal_id = ? AND revoked_at IS NULL`,
        )
        .run(input.now, principal.id);
      this.#db
        .prepare(
          `DELETE FROM staged_grants
           WHERE expected_principal_id = ? AND status = 'staged'`,
        )
        .run(principal.id);
      return true;
    }).immediate();
  }

  challengeForAuthorizationCode(
    clientId: string,
    code: string,
    now: number,
  ): string | undefined {
    this.assertReady();
    if (
      typeof clientId !== "string" ||
      !isOpaque(code) ||
      !validStoreTime(now) ||
      this.#mcpResource === undefined
    ) {
      return undefined;
    }

    return this.#db
      .prepare<[string, string, number, string, string], { code_challenge: string }>(
        `SELECT authorization_codes.code_challenge
         FROM authorization_codes
         JOIN principals
           ON principals.id = authorization_codes.principal_id
          AND principals.lifecycle_epoch = authorization_codes.principal_epoch
         WHERE authorization_codes.code_hash = ?
           AND authorization_codes.client_id = ?
           AND authorization_codes.consumed_at IS NULL
           AND authorization_codes.expires_at > ?
           AND authorization_codes.scopes = ?
           AND authorization_codes.resource = ?
           AND principals.status = 'active'`,
      )
      .get(hashOpaque(code), clientId, now, MCP_SCOPE, this.#mcpResource)?.code_challenge;
  }

  consumeCodeAndIssueFamily(input: CodeExchangeInput): IssuedTokens {
    this.assertReady();
    if (
      typeof input !== "object" ||
      input === null ||
      typeof input.clientId !== "string" ||
      !isOpaque(input.authorizationCode) ||
      typeof input.redirectUri !== "string" ||
      typeof input.resource !== "string" ||
      !validStoreTime(input.now) ||
      !Number.isSafeInteger(input.accessTokenTtlSeconds) ||
      input.accessTokenTtlSeconds <= 0 ||
      input.now > Number.MAX_SAFE_INTEGER - input.accessTokenTtlSeconds ||
      input.now > Number.MAX_SAFE_INTEGER - MCP_REFRESH_TTL_SECONDS ||
      this.#mcpResource === undefined ||
      input.resource !== this.#mcpResource
    ) {
      throw invalidAuthorizationCode();
    }

    return this.#db.transaction((): IssuedTokens => {
      const codeHash = hashOpaque(input.authorizationCode);
      const code = this.#db
        .prepare<
          [string, string, string, string, number, string],
          AuthorizationCodeRow
        >(
          `SELECT authorization_codes.*
           FROM authorization_codes
           JOIN principals
             ON principals.id = authorization_codes.principal_id
            AND principals.lifecycle_epoch = authorization_codes.principal_epoch
           WHERE authorization_codes.code_hash = ?
             AND authorization_codes.client_id = ?
             AND authorization_codes.redirect_uri = ?
             AND authorization_codes.resource = ?
             AND authorization_codes.expires_at > ?
             AND authorization_codes.consumed_at IS NULL
             AND authorization_codes.scopes = ?
             AND principals.status = 'active'`,
        )
        .get(
          codeHash,
          input.clientId,
          input.redirectUri,
          input.resource,
          input.now,
          MCP_SCOPE,
        );
      if (!code) throw invalidAuthorizationCode();

      const familyId = this.#randomId();
      const accessToken = this.#randomToken(32);
      const refreshToken = this.#randomToken(32);
      const opaqueValues = [familyId, accessToken, refreshToken];
      if (
        opaqueValues.some((value) => !isOpaque(value)) ||
        new Set([...opaqueValues, input.authorizationCode]).size !== 4
      ) {
        throw new Error("OAuth store random source is invalid");
      }
      const accessHash = hashOpaque(accessToken);
      const refreshHash = hashOpaque(refreshToken);
      const tokenCollision = this.#db
        .prepare<[string, string, string, string], { present: number }>(
          `SELECT 1 AS present FROM (
             SELECT token_hash FROM access_tokens WHERE token_hash IN (?, ?)
             UNION ALL
             SELECT token_hash FROM refresh_token_generations WHERE token_hash IN (?, ?)
           ) LIMIT 1`,
        )
        .get(accessHash, refreshHash, accessHash, refreshHash);
      if (tokenCollision) {
        throw new Error("OAuth store random source is invalid");
      }

      const consumed = this.#db
        .prepare(
          `UPDATE authorization_codes
           SET consumed_at = ?
           WHERE code_hash = ?
             AND consumed_at IS NULL
             AND expires_at > ?`,
        )
        .run(input.now, codeHash, input.now).changes;
      if (consumed !== 1) throw invalidAuthorizationCode();

      this.#db
        .prepare(
          `INSERT INTO token_families (
             id, client_id, principal_id, principal_epoch, scopes, resource,
             created_at, last_used_at, revoked_at, revoke_reason
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
        )
        .run(
          familyId,
          code.client_id,
          code.principal_id,
          code.principal_epoch,
          MCP_SCOPE,
          code.resource,
          input.now,
          input.now,
        );
      this.#db
        .prepare(
          `INSERT INTO access_tokens (token_hash, family_id, created_at, expires_at)
           VALUES (?, ?, ?, ?)`,
        )
        .run(
          accessHash,
          familyId,
          input.now,
          input.now + input.accessTokenTtlSeconds,
        );
      this.#db
        .prepare(
          `INSERT INTO refresh_token_generations (
             token_hash, family_id, generation, status, created_at, expires_at,
             consumed_at, successor_generation, encrypted_retry_response_json,
             retry_response_expires_at
           ) VALUES (?, ?, 1, 'current', ?, ?, NULL, NULL, NULL, NULL)`,
        )
        .run(
          refreshHash,
          familyId,
          input.now,
          input.now + MCP_REFRESH_TTL_SECONDS,
        );

      return {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: input.accessTokenTtlSeconds,
        refresh_token: refreshToken,
        scope: MCP_SCOPE,
      };
    }).immediate();
  }

  rotateRefreshToken(input: RefreshExchangeInput): RefreshExchangeResult {
    this.assertReady();
    if (
      typeof input !== "object" ||
      input === null ||
      typeof input.clientId !== "string" ||
      typeof input.refreshToken !== "string" ||
      !isOpaque(input.refreshToken)
    ) {
      return { kind: "invalid_grant", reason: "replay" };
    }
    if (
      !validStoreTime(input.now) ||
      !Number.isSafeInteger(input.accessTokenTtlSeconds) ||
      input.accessTokenTtlSeconds <= 0 ||
      input.now > Number.MAX_SAFE_INTEGER - input.accessTokenTtlSeconds ||
      input.now > Number.MAX_SAFE_INTEGER - MCP_REFRESH_TTL_SECONDS ||
      typeof input.canonicalResource !== "string" ||
      (input.resource !== undefined && typeof input.resource !== "string") ||
      (input.scopes !== undefined &&
        (!Array.isArray(input.scopes) ||
          !input.scopes.every((scope) => typeof scope === "string")))
    ) {
      return { kind: "invalid_grant", reason: "binding_mismatch" };
    }

    return this.#db.transaction((): RefreshExchangeResult => {
      this.#db.prepare(
        `UPDATE refresh_token_generations
         SET encrypted_retry_response_json = NULL
         WHERE retry_response_expires_at IS NOT NULL
           AND retry_response_expires_at <= ?`,
      ).run(input.now);

      const row = this.#db
        .prepare<[string], RefreshGenerationRow>(
          `SELECT refresh_token_generations.*,
                  token_families.client_id,
                  token_families.principal_id,
                  token_families.principal_epoch,
                  token_families.scopes,
                  token_families.resource,
                  token_families.revoked_at,
                  principals.status AS principal_status,
                  principals.lifecycle_epoch,
                  oauth_clients.scope AS client_scope
           FROM refresh_token_generations
           JOIN token_families
             ON token_families.id = refresh_token_generations.family_id
           JOIN principals ON principals.id = token_families.principal_id
           JOIN oauth_clients ON oauth_clients.client_id = token_families.client_id
           WHERE refresh_token_generations.token_hash = ?`,
        )
        .get(hashOpaque(input.refreshToken));
      if (!row) return { kind: "invalid_grant", reason: "replay" };
      if (row.expires_at <= input.now) {
        return { kind: "invalid_grant", reason: "expired" };
      }
      if (row.client_id !== input.clientId) {
        return { kind: "invalid_grant", reason: "binding_mismatch" };
      }
      if (row.revoked_at !== null) {
        return { kind: "invalid_grant", reason: "revoked" };
      }

      const scopesMatch =
        input.scopes === undefined || sameSet(input.scopes, MCP_SCOPES);
      const bindingsMatch =
        scopesMatch &&
        row.scopes === MCP_SCOPE &&
        row.client_scope === MCP_SCOPE &&
        this.#mcpResource !== undefined &&
        row.resource === this.#mcpResource &&
        input.canonicalResource === this.#mcpResource &&
        (input.resource === undefined || input.resource === row.resource);
      if (!bindingsMatch) {
        this.#db
          .prepare(
            `UPDATE token_families
             SET revoked_at = ?, revoke_reason = 'refresh_binding_mismatch'
             WHERE id = ? AND client_id = ? AND revoked_at IS NULL`,
          )
          .run(input.now, row.family_id, input.clientId);
        return { kind: "invalid_grant", reason: "binding_mismatch" };
      }

      if (
        row.principal_status !== "active" ||
        row.lifecycle_epoch !== row.principal_epoch
      ) {
        this.#db
          .prepare(
            `UPDATE token_families
             SET revoked_at = ?, revoke_reason = 'principal_inactive'
             WHERE id = ? AND client_id = ? AND revoked_at IS NULL`,
          )
          .run(input.now, row.family_id, input.clientId);
        return { kind: "invalid_grant", reason: "revoked" };
      }

      if (row.status === "consumed") {
        const successor =
          row.successor_generation === null
            ? undefined
            : this.#db
                .prepare<[string, number], SuccessorGenerationRow>(
                  `SELECT token_hash, status, consumed_at
                   FROM refresh_token_generations
                   WHERE family_id = ? AND generation = ?`,
                )
                .get(row.family_id, row.successor_generation);
        if (
          row.encrypted_retry_response_json !== null &&
          row.retry_response_expires_at !== null &&
          row.retry_response_expires_at > input.now &&
          successor?.status === "current" &&
          successor.consumed_at === null
        ) {
          try {
            const tokens = JSON.parse(
              this.#cipher.decrypt(
                JSON.parse(row.encrypted_retry_response_json) as EncryptedValue,
                {
                  kind: "mcp_refresh_retry",
                  rowId: row.token_hash,
                  expiresAt: row.expires_at,
                  familyId: row.family_id,
                  clientId: row.client_id,
                  resource: row.resource,
                  scopes: row.scopes,
                  generation: row.generation,
                },
              ),
            ) as Partial<IssuedTokens>;
            const accessPresent =
              typeof tokens.access_token === "string" &&
              this.#db
                .prepare<[string, string], { present: number }>(
                  `SELECT 1 AS present FROM access_tokens
                   WHERE token_hash = ? AND family_id = ?`,
                )
                .get(hashOpaque(tokens.access_token), row.family_id);
            if (
              typeof tokens.access_token === "string" &&
              isOpaque(tokens.access_token) &&
              typeof tokens.refresh_token === "string" &&
              isOpaque(tokens.refresh_token) &&
              tokens.access_token !== tokens.refresh_token &&
              tokens.token_type === "Bearer" &&
              Number.isSafeInteger(tokens.expires_in) &&
              (tokens.expires_in ?? 0) > 0 &&
              tokens.scope === MCP_SCOPE &&
              hashOpaque(tokens.refresh_token) === successor.token_hash &&
              Boolean(accessPresent)
            ) {
              return { kind: "idempotent", tokens: tokens as IssuedTokens };
            }
          } catch {
            // Treat an undecryptable or malformed cache as a replay below.
          }
        }

        this.#db
          .prepare(
            `UPDATE token_families
             SET revoked_at = ?, revoke_reason = 'refresh_replay'
             WHERE id = ? AND client_id = ? AND revoked_at IS NULL`,
          )
          .run(input.now, row.family_id, input.clientId);
        return { kind: "invalid_grant", reason: "replay" };
      }

      const successorGeneration = row.generation + 1;
      if (!Number.isSafeInteger(successorGeneration)) {
        throw new Error("OAuth refresh generation overflow");
      }
      const accessToken = this.#randomToken(32);
      const refreshToken = this.#randomToken(32);
      if (
        !isOpaque(accessToken) ||
        !isOpaque(refreshToken) ||
        new Set([input.refreshToken, accessToken, refreshToken]).size !== 3
      ) {
        throw new Error("OAuth store random source is invalid");
      }
      const accessHash = hashOpaque(accessToken);
      const refreshHash = hashOpaque(refreshToken);
      const collision = this.#db
        .prepare<[string, string, string, string, string, string], { present: number }>(
          `SELECT 1 AS present FROM (
             SELECT token_hash AS value FROM access_tokens
             WHERE token_hash IN (?, ?)
             UNION ALL
             SELECT token_hash AS value FROM refresh_token_generations
             WHERE token_hash IN (?, ?)
             UNION ALL
             SELECT code_hash AS value FROM authorization_codes
             WHERE code_hash IN (?, ?)
           ) LIMIT 1`,
        )
        .get(
          accessHash,
          refreshHash,
          accessHash,
          refreshHash,
          accessHash,
          refreshHash,
        );
      if (collision) throw new Error("OAuth store random source is invalid");

      const tokens: IssuedTokens = {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: input.accessTokenTtlSeconds,
        refresh_token: refreshToken,
        scope: MCP_SCOPE,
      };
      const encryptedRetry = this.#cipher.encrypt(JSON.stringify(tokens), {
        kind: "mcp_refresh_retry",
        rowId: row.token_hash,
        expiresAt: row.expires_at,
        familyId: row.family_id,
        clientId: row.client_id,
        resource: row.resource,
        scopes: row.scopes,
        generation: row.generation,
      });
      const consumed = this.#db
        .prepare(
          `UPDATE refresh_token_generations
           SET status = 'consumed', consumed_at = ?, successor_generation = ?,
               encrypted_retry_response_json = ?, retry_response_expires_at = ?
           WHERE token_hash = ?
             AND family_id = ?
             AND status = 'current'
             AND consumed_at IS NULL
             AND expires_at > ?`,
        )
        .run(
          input.now,
          successorGeneration,
          JSON.stringify(encryptedRetry),
          input.now + MCP_REFRESH_RETRY_SECONDS,
          row.token_hash,
          row.family_id,
          input.now,
        ).changes;
      if (consumed !== 1) {
        throw new Error("OAuth refresh generation changed concurrently");
      }
      this.#db
        .prepare(
          `INSERT INTO access_tokens (token_hash, family_id, created_at, expires_at)
           VALUES (?, ?, ?, ?)`,
        )
        .run(
          accessHash,
          row.family_id,
          input.now,
          input.now + input.accessTokenTtlSeconds,
        );
      this.#db
        .prepare(
          `INSERT INTO refresh_token_generations (
             token_hash, family_id, generation, status, created_at, expires_at,
             consumed_at, successor_generation, encrypted_retry_response_json,
             retry_response_expires_at
           ) VALUES (?, ?, ?, 'current', ?, ?, NULL, NULL, NULL, NULL)`,
        )
        .run(
          refreshHash,
          row.family_id,
          successorGeneration,
          input.now,
          input.now + MCP_REFRESH_TTL_SECONDS,
        );
      this.#db
        .prepare(
          `UPDATE token_families SET last_used_at = ?
           WHERE id = ? AND client_id = ? AND revoked_at IS NULL`,
        )
        .run(input.now, row.family_id, input.clientId);
      return { kind: "issued", tokens };
    }).immediate();
  }

  revokeFamilyByPresentedToken(clientId: string, token: string, now: number): void {
    this.assertReady();
    if (
      typeof clientId !== "string" ||
      typeof token !== "string" ||
      !isOpaque(token) ||
      !validStoreTime(now)
    ) {
      return;
    }
    const tokenHash = hashOpaque(token);
    this.#db.transaction(() => {
      this.#db
        .prepare(
          `UPDATE token_families
           SET revoked_at = ?, revoke_reason = 'rfc7009'
           WHERE client_id = ?
             AND revoked_at IS NULL
             AND id IN (
               SELECT family_id FROM access_tokens WHERE token_hash = ?
               UNION
               SELECT family_id FROM refresh_token_generations WHERE token_hash = ?
             )`,
        )
        .run(now, clientId, tokenHash, tokenHash);
    }).immediate();
  }

  disconnectUser(
    subdomain: string,
    zendeskUserId: string,
    now: number,
  ): DisconnectResult {
    this.assertReady();
    if (
      typeof subdomain !== "string" ||
      !validSubdomain(subdomain) ||
      !validZendeskUserId(zendeskUserId) ||
      !validStoreTime(now)
    ) {
      return { kind: "not_found" };
    }

    return this.#db.transaction((): DisconnectResult => {
      const principal = this.#db
        .prepare<[string, string], PrincipalRow>(
          `SELECT * FROM principals
           WHERE subdomain = ? AND zendesk_user_id = ?`,
        )
        .get(subdomain, zendeskUserId);
      if (!principal) return { kind: "not_found" };
      if (principal.status === "disconnected") {
        return { kind: "already_disconnected", principalId: principal.id };
      }

      const credential = this.#db
        .prepare<[string], CredentialRow>(
          `SELECT * FROM zendesk_credentials WHERE principal_id = ?`,
        )
        .get(principal.id);
      if (!credential) throw new Error("OAuth principal credential is unavailable");
      const grant = decryptCredentialGrant(this.#cipher, principal, credential);
      const capturedPrincipalEpoch = principal.lifecycle_epoch + 1;
      if (!Number.isSafeInteger(capturedPrincipalEpoch)) {
        throw new Error("OAuth principal lifecycle epoch overflow");
      }
      if (grant.refreshExpiresAt > Number.MAX_SAFE_INTEGER - 604_800) {
        throw new Error("OAuth revocation retention expiry overflow");
      }
      const retentionExpiresAt = grant.refreshExpiresAt + 604_800;
      const outboxId = this.#randomId();
      if (!isOpaque(outboxId)) throw new Error("OAuth store random source is invalid");
      const encryptedGrant = this.#cipher.encrypt(JSON.stringify(grant), {
        kind: "disconnect_outbox",
        rowId: outboxId,
        expiresAt: retentionExpiresAt,
        subdomain: principal.subdomain,
        principalId: principal.id,
        credentialVersion: credential.credential_version,
        principalEpoch: capturedPrincipalEpoch,
      });

      const updated = this.#db
        .prepare(
          `UPDATE principals
           SET status = 'disconnected', lifecycle_epoch = ?,
               disconnected_at = ?, updated_at = ?
           WHERE id = ? AND status <> 'disconnected' AND lifecycle_epoch = ?`,
        )
        .run(
          capturedPrincipalEpoch,
          now,
          now,
          principal.id,
          principal.lifecycle_epoch,
        ).changes;
      if (updated !== 1) throw new Error("OAuth principal changed concurrently");

      const revokedFamilies = this.#db
        .prepare(
          `UPDATE token_families
           SET revoked_at = ?, revoke_reason = 'principal_disconnect'
           WHERE principal_id = ? AND revoked_at IS NULL`,
        )
        .run(now, principal.id).changes;
      this.#db
        .prepare(
          `UPDATE authorization_codes
           SET consumed_at = ?
           WHERE principal_id = ? AND consumed_at IS NULL`,
        )
        .run(now, principal.id);
      const deletedCredential = this.#db
        .prepare(
          `DELETE FROM zendesk_credentials
           WHERE principal_id = ?
             AND credential_version = ?
             AND principal_epoch = ?`,
        )
        .run(
          principal.id,
          credential.credential_version,
          credential.principal_epoch,
        ).changes;
      if (deletedCredential !== 1) {
        throw new Error("OAuth principal credential changed concurrently");
      }
      this.#db
        .prepare(
          `INSERT INTO revocation_outbox (
             id, principal_id, captured_principal_epoch, credential_version,
             encrypted_grant_json, status, attempt_count, next_attempt_at,
             claim_owner, claim_expires_at, retention_expires_at,
             last_error_category, created_at, completed_at
           ) VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, NULL, NULL, ?, NULL, ?, NULL)`,
        )
        .run(
          outboxId,
          principal.id,
          capturedPrincipalEpoch,
          credential.credential_version,
          JSON.stringify(encryptedGrant),
          now,
          retentionExpiresAt,
          now,
        );

      return {
        kind: "disconnected",
        principalId: principal.id,
        revokedFamilies,
        outboxId,
      };
    }).immediate();
  }

  claimDueRevocation(
    owner: string,
    now: number,
    leaseExpiresAt: number,
  ): RevocationClaim | undefined {
    this.assertReady();
    if (
      !validClaimOwner(owner) ||
      !validStoreTime(now) ||
      !validStoreTime(leaseExpiresAt) ||
      leaseExpiresAt <= now
    ) {
      return undefined;
    }

    return this.#db.transaction((): RevocationClaim | undefined => {
      this.#db
        .prepare(
          `UPDATE revocation_outbox
           SET status = 'pending', claim_owner = NULL, claim_expires_at = NULL
           WHERE status = 'claimed'
             AND completed_at IS NULL
             AND claim_expires_at <= ?`,
        )
        .run(now);
      const row = this.#db
        .prepare<[number, number], RevocationOutboxRow>(
          `SELECT revocation_outbox.*, principals.subdomain
           FROM revocation_outbox
           JOIN principals ON principals.id = revocation_outbox.principal_id
           WHERE revocation_outbox.status = 'pending'
             AND revocation_outbox.completed_at IS NULL
             AND revocation_outbox.next_attempt_at <= ?
             AND revocation_outbox.retention_expires_at > ?
             AND principals.status = 'disconnected'
             AND principals.lifecycle_epoch = revocation_outbox.captured_principal_epoch
             AND NOT EXISTS (
               SELECT 1 FROM zendesk_credentials
               WHERE zendesk_credentials.principal_id = revocation_outbox.principal_id
             )
           ORDER BY revocation_outbox.next_attempt_at,
                    revocation_outbox.created_at,
                    revocation_outbox.id
           LIMIT 1`,
        )
        .get(now, now);
      if (!row || leaseExpiresAt > row.retention_expires_at) return undefined;
      const attemptCount = row.attempt_count + 1;
      if (!Number.isSafeInteger(attemptCount) || attemptCount < 1) {
        throw new Error("OAuth revocation attempt count overflow");
      }
      const claimed = this.#db
        .prepare(
          `UPDATE revocation_outbox
           SET status = 'claimed', attempt_count = ?, claim_owner = ?, claim_expires_at = ?
           WHERE id = ?
             AND status = 'pending'
             AND completed_at IS NULL
             AND next_attempt_at <= ?
             AND retention_expires_at > ?
             AND EXISTS (
               SELECT 1 FROM principals
               WHERE principals.id = revocation_outbox.principal_id
                 AND principals.status = 'disconnected'
                 AND principals.lifecycle_epoch = revocation_outbox.captured_principal_epoch
             )
             AND NOT EXISTS (
               SELECT 1 FROM zendesk_credentials
               WHERE zendesk_credentials.principal_id = revocation_outbox.principal_id
             )`,
        )
        .run(
          attemptCount,
          owner,
          leaseExpiresAt,
          row.id,
          now,
          now,
        ).changes;
      if (claimed !== 1) return undefined;
      const grant = decryptRevocationGrant(this.#cipher, row);
      return {
        outboxId: row.id,
        principalId: row.principal_id,
        capturedPrincipalEpoch: row.captured_principal_epoch,
        credentialVersion: row.credential_version,
        grant,
        attemptCount,
        retentionExpiresAt: row.retention_expires_at,
      };
    }).immediate();
  }

  renewRevocationClaim(
    outboxId: string,
    owner: string,
    leaseExpiresAt: number,
  ): boolean {
    this.assertReady();
    const storeNow = Math.floor(this.#now());
    if (
      typeof outboxId !== "string" ||
      outboxId.length === 0 ||
      !validClaimOwner(owner) ||
      !validStoreTime(storeNow) ||
      !validStoreTime(leaseExpiresAt) ||
      leaseExpiresAt <= storeNow
    ) {
      return false;
    }
    return this.#db.transaction(() =>
      this.#db
        .prepare(
          `UPDATE revocation_outbox
           SET claim_expires_at = ?
           WHERE id = ?
             AND status = 'claimed'
             AND completed_at IS NULL
             AND claim_owner = ?
             AND claim_expires_at > ?
             AND claim_expires_at < ?
             AND retention_expires_at >= ?
             AND EXISTS (
               SELECT 1 FROM principals
               WHERE principals.id = revocation_outbox.principal_id
                 AND principals.status = 'disconnected'
                 AND principals.lifecycle_epoch = revocation_outbox.captured_principal_epoch
             )
             AND NOT EXISTS (
               SELECT 1 FROM zendesk_credentials
               WHERE zendesk_credentials.principal_id = revocation_outbox.principal_id
             )`,
        )
        .run(
          leaseExpiresAt,
          outboxId,
          owner,
          storeNow,
          leaseExpiresAt,
          leaseExpiresAt,
        ).changes === 1,
    ).immediate();
  }

  replaceRevocationGrant(
    outboxId: string,
    owner: string,
    grant: ZendeskGrant,
    now: number,
  ): boolean {
    this.assertReady();
    const normalized = normalizeZendeskGrant(grant, now);
    if (
      typeof outboxId !== "string" ||
      outboxId.length === 0 ||
      !validClaimOwner(owner) ||
      !validStoreTime(now) ||
      normalized === undefined ||
      normalized.refreshExpiresAt > Number.MAX_SAFE_INTEGER - 604_800
    ) {
      return false;
    }
    const grantRetentionExpiresAt = normalized.refreshExpiresAt + 604_800;

    return this.#db.transaction(() => {
      const row = this.#db
        .prepare<[string, string, number, number], RevocationOutboxRow>(
          `SELECT revocation_outbox.*, principals.subdomain
           FROM revocation_outbox
           JOIN principals ON principals.id = revocation_outbox.principal_id
           WHERE revocation_outbox.id = ?
             AND revocation_outbox.status = 'claimed'
             AND revocation_outbox.completed_at IS NULL
             AND revocation_outbox.claim_owner = ?
             AND revocation_outbox.claim_expires_at > ?
             AND revocation_outbox.retention_expires_at > ?
             AND principals.status = 'disconnected'
             AND principals.lifecycle_epoch = revocation_outbox.captured_principal_epoch
             AND NOT EXISTS (
               SELECT 1 FROM zendesk_credentials
               WHERE zendesk_credentials.principal_id = revocation_outbox.principal_id
             )`,
        )
        .get(outboxId, owner, now, now);
      if (!row || row.claim_expires_at === null) return false;
      const retentionExpiresAt = Math.max(
        row.retention_expires_at,
        grantRetentionExpiresAt,
      );
      if (row.claim_expires_at > retentionExpiresAt) return false;
      const encryptedGrant = this.#cipher.encrypt(JSON.stringify(normalized), {
        kind: "disconnect_outbox",
        rowId: row.id,
        expiresAt: retentionExpiresAt,
        subdomain: row.subdomain,
        principalId: row.principal_id,
        credentialVersion: row.credential_version,
        principalEpoch: row.captured_principal_epoch,
      });
      return (
        this.#db
          .prepare(
            `UPDATE revocation_outbox
             SET encrypted_grant_json = ?, retention_expires_at = ?
             WHERE id = ?
               AND status = 'claimed'
               AND completed_at IS NULL
               AND claim_owner = ?
               AND claim_expires_at > ?
               AND EXISTS (
                 SELECT 1 FROM principals
                 WHERE principals.id = revocation_outbox.principal_id
                   AND principals.status = 'disconnected'
                   AND principals.lifecycle_epoch = revocation_outbox.captured_principal_epoch
               )
               AND NOT EXISTS (
                 SELECT 1 FROM zendesk_credentials
                 WHERE zendesk_credentials.principal_id = revocation_outbox.principal_id
               )`,
          )
          .run(
            JSON.stringify(encryptedGrant),
            retentionExpiresAt,
            outboxId,
            owner,
            now,
          ).changes === 1
      );
    }).immediate();
  }

  rescheduleRevocation(
    outboxId: string,
    owner: string,
    category: string,
    nextAttemptAt: number,
  ): boolean {
    this.assertReady();
    const storeNow = Math.floor(this.#now());
    if (
      typeof outboxId !== "string" ||
      outboxId.length === 0 ||
      !validClaimOwner(owner) ||
      !validErrorCategory(category) ||
      !validStoreTime(storeNow) ||
      !validStoreTime(nextAttemptAt)
    ) {
      return false;
    }
    return this.#db.transaction(() => {
      const row = this.#db
        .prepare<[string, string, number], { attempt_count: number }>(
          `SELECT attempt_count FROM revocation_outbox
           WHERE id = ?
             AND status = 'claimed'
             AND completed_at IS NULL
             AND claim_owner = ?
             AND claim_expires_at > ?`,
        )
        .get(outboxId, owner, storeNow);
      if (!row) return false;
      const backoffSeconds = revocationBackoffSeconds(row.attempt_count);
      if (
        backoffSeconds === undefined ||
        storeNow > Number.MAX_SAFE_INTEGER - backoffSeconds ||
        nextAttemptAt !== storeNow + backoffSeconds
      ) {
        return false;
      }
      return (
        this.#db
          .prepare(
            `UPDATE revocation_outbox
             SET status = 'pending', next_attempt_at = ?, claim_owner = NULL,
                 claim_expires_at = NULL, last_error_category = ?
             WHERE id = ?
               AND status = 'claimed'
               AND completed_at IS NULL
               AND claim_owner = ?
               AND claim_expires_at > ?
               AND retention_expires_at > ?
               AND attempt_count = ?`,
          )
          .run(
            nextAttemptAt,
            category,
            outboxId,
            owner,
            storeNow,
            nextAttemptAt,
            row.attempt_count,
          ).changes === 1
      );
    }).immediate();
  }

  completeRevocation(outboxId: string, owner: string, now: number): boolean {
    this.assertReady();
    if (
      typeof outboxId !== "string" ||
      outboxId.length === 0 ||
      !validClaimOwner(owner) ||
      !validStoreTime(now)
    ) {
      return false;
    }
    return (
      this.#db.transaction(() =>
        this.#db
          .prepare(
            `UPDATE revocation_outbox
             SET completed_at = ?, encrypted_grant_json = '{}',
                 claim_owner = NULL, claim_expires_at = NULL
             WHERE id = ?
               AND status = 'claimed'
               AND completed_at IS NULL
               AND claim_owner = ?
               AND claim_expires_at > ?
               AND retention_expires_at > ?`,
          )
          .run(now, outboxId, owner, now, now).changes === 1,
      ).immediate()
    );
  }

  releaseClaims(owner: string, now: number): number {
    this.assertReady();
    if (!validClaimOwner(owner) || !validStoreTime(now)) return 0;
    return this.#db.transaction(() =>
      this.#db
        .prepare(
          `UPDATE revocation_outbox
           SET status = 'pending', next_attempt_at = ?, claim_owner = NULL,
               claim_expires_at = NULL
           WHERE status = 'claimed'
             AND completed_at IS NULL
             AND claim_owner = ?
             AND claim_expires_at > ?
             AND retention_expires_at > ?`,
        )
        .run(now, owner, now, now).changes,
    ).immediate();
  }

  lookupAccessToken(token: string, now: number): StoredAuthInfo | undefined {
    this.assertReady();
    if (
      !isOpaque(token) ||
      !validStoreTime(now) ||
      this.#mcpResource === undefined
    ) {
      return undefined;
    }

    const row = this.#db
      .prepare<[string, number], AccessTokenRow>(
        `SELECT token_families.client_id,
                token_families.principal_id,
                token_families.principal_epoch,
                token_families.scopes,
                token_families.resource,
                access_tokens.expires_at,
                principals.status AS principal_status,
                principals.lifecycle_epoch,
                oauth_clients.scope AS client_scope
         FROM access_tokens
         JOIN token_families ON token_families.id = access_tokens.family_id
         JOIN principals ON principals.id = token_families.principal_id
         JOIN oauth_clients ON oauth_clients.client_id = token_families.client_id
         WHERE access_tokens.token_hash = ?
           AND access_tokens.expires_at > ?
           AND token_families.revoked_at IS NULL
           AND principals.status = 'active'
           AND principals.lifecycle_epoch = token_families.principal_epoch`,
      )
      .get(hashOpaque(token), now);
    if (
      !row ||
      row.principal_status !== "active" ||
      row.lifecycle_epoch !== row.principal_epoch ||
      row.scopes !== MCP_SCOPE ||
      row.client_scope !== MCP_SCOPE ||
      row.resource !== this.#mcpResource ||
      !Number.isSafeInteger(row.expires_at) ||
      row.expires_at <= now
    ) {
      return undefined;
    }

    return {
      clientId: row.client_id,
      principalId: row.principal_id,
      scopes: [...MCP_SCOPES],
      resource: row.resource,
      expiresAt: row.expires_at,
    };
  }

  discardStagedGrant(stageId: string, now: number): boolean {
    this.assertReady();
    if (typeof stageId !== "string" || !validStoreTime(now)) return false;
    return this.#db
      .prepare(
        `UPDATE staged_grants SET status = 'discard_only'
         WHERE id = ? AND status = 'staged'`,
      )
      .run(stageId).changes === 1;
  }

  failLogin(transactionId: string, now: number): OAuthRedirectContext | undefined {
    this.assertReady();
    if (!Number.isSafeInteger(now) || now < 0) return undefined;

    return this.#db.transaction(() => {
      const row = this.#db
        .prepare<[string, number], LoginRow>(
          `SELECT * FROM login_transactions
           WHERE id = ? AND status = 'callback_claimed' AND expires_at > ?`,
        )
        .get(transactionId, now);
      if (!row) return undefined;

      let payload: EncryptedLoginPayload;
      try {
        payload = decryptLoginPayload(this.#cipher, row);
      } catch {
        return undefined;
      }
      const failed = this.#db
        .prepare(
          `UPDATE login_transactions
           SET status = 'failed', completed_at = ?
           WHERE id = ? AND status = 'callback_claimed' AND expires_at > ?`,
        )
        .run(now, row.id, now).changes;
      if (failed !== 1) return undefined;
      return { redirectUri: payload.redirectUri, originalState: payload.originalState };
    })();
  }

  recover(now: number): RecoverySummary {
    this.assertReady();
    return recoverRows(this.#db, now);
  }

  recoverDuringStartup(now: number): RecoverySummary {
    return recoverRows(this.#db, now);
  }

  async backup(destination: string): Promise<void> {
    this.assertReady();
    let descriptor: number | undefined;
    let created = false;
    try {
      descriptor = openSync(destination, "wx", 0o600);
      created = true;
      fchmodSync(descriptor, 0o600);
      closeSync(descriptor);
      descriptor = undefined;
      await this.#db.backup(destination);
      chmodSync(destination, 0o600);
    } catch (error) {
      if (descriptor !== undefined) {
        try {
          closeSync(descriptor);
        } catch {
          // Continue cleanup of the private destination.
        }
      }
      if (created) {
        try {
          unlinkSync(destination);
        } catch {
          // Preserve the original backup failure.
        }
      }
      throw error;
    }
  }

  inspectForTest(): StoreInspection {
    this.assertReady();
    const pragmas = readEffectivePragmas(this.#db);
    return {
      schemaVersion: schemaVersion(this.#db),
      migrationCount:
        this.#db.prepare<[], CountRow>("SELECT COUNT(*) AS count FROM schema_migrations").get()
          ?.count ?? 0,
      clientCount:
        this.#db.prepare<[], CountRow>("SELECT COUNT(*) AS count FROM oauth_clients").get()
          ?.count ?? 0,
      pragmas: {
        foreignKeys: pragmas.foreignKeys,
        journalMode: pragmas.journalMode,
        synchronous: pragmas.synchronous,
        trustedSchema: pragmas.trustedSchema,
        secureDelete: pragmas.secureDelete,
      },
    };
  }

  close(): void {
    if (!this.#db.open) {
      this.#ready = false;
      return;
    }
    try {
      this.#db.pragma("wal_checkpoint(TRUNCATE)");
    } finally {
      this.#ready = false;
      this.#db.close();
    }
  }
}

function valueFreeStartupError(error: unknown): Error {
  if (
    error instanceof Error &&
    [INVALID_KEY_ERROR, NEWER_SCHEMA_ERROR].includes(error.message)
  ) {
    return error;
  }
  return new Error(STARTUP_ERROR);
}

export function openSqliteOAuthStore(options: SqliteOAuthStoreOptions): OAuthStore {
  if (!isAbsolute(options.path)) throw new Error("OAuth store path must be absolute");

  const mcpResource = canonicalMcpResource(options.mcpResourceUrl);
  const busyTimeoutMs = options.busyTimeoutMs ?? 5000;
  if (!Number.isSafeInteger(busyTimeoutMs) || busyTimeoutMs < 0 || busyTimeoutMs > 60_000) {
    throw new Error("OAuth store busy timeout is invalid");
  }

  const parent = dirname(options.path);
  let db: Database.Database | undefined;
  try {
    mkdirSync(parent, { recursive: true, mode: 0o700 });
    chmodSync(parent, 0o700);

    db = new Database(options.path, { timeout: busyTimeoutMs });
    db.pragma("foreign_keys = ON");
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = FULL");
    db.pragma(`busy_timeout = ${busyTimeoutMs}`);
    db.pragma("trusted_schema = OFF");
    db.pragma("secure_delete = ON");
    verifyEffectivePragmas(db, busyTimeoutMs);

    const currentVersion = schemaVersion(db);
    if (currentVersion > SCHEMA_VERSION) throw new Error(NEWER_SCHEMA_ERROR);
    const now = options.now?.() ?? Math.floor(Date.now() / 1000);
    applyMigrations(db, currentVersion, now, options.cipher);
    chmodSync(options.path, 0o600);
    verifyEncryptionKey(db, options.cipher);

    const store = new SqliteOAuthStore(
      db,
      options.cipher,
      mcpResource,
      options.now ?? (() => Math.floor(Date.now() / 1000)),
      options.randomId ?? randomOpaque,
      options.randomToken ?? randomOpaque,
      options.testHooks,
    );
    store.recoverDuringStartup(now);
    store.markReady();
    return store as unknown as OAuthStore;
  } catch (error) {
    if (db?.open) {
      try {
        db.close();
      } catch {
        // Preserve the value-free startup error.
      }
    }
    throw valueFreeStartupError(error);
  }
}
