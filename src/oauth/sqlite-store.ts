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

import { LOGIN_TTL_SECONDS, MCP_SCOPES, normalizeMcpScopes } from "./constants.js";
import { SCHEMA_VERSION, SQLITE_MIGRATIONS } from "./sqlite-schema.js";
import type {
  BeginLoginInput,
  ConsentDecisionInput,
  ConsentDecisionResult,
  LoginStart,
  OAuthRedirectContext,
  OAuthStore,
  RecoverySummary,
  StoreInspection,
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
const MCP_SCOPE = "zendesk:read zendesk:write";
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

function decryptLoginPayload(cipher: TokenCipher, row: LoginRow): EncryptedLoginPayload {
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

  const serialized = cipher.decrypt(
    stored.encrypted as EncryptedValue,
    loginCipherContext(row, stored as StoredLoginPayload),
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
    const expiredLogins = db
      .prepare(
        `UPDATE login_transactions
         SET status = 'failed', completed_at = ?
         WHERE expires_at <= ?
           AND status IN ('consent_pending', 'upstream_pending', 'callback_claimed')`,
      )
      .run(now, now).changes;
    const discardedStages = db
      .prepare(
        `UPDATE staged_grants
         SET status = 'discard_only'
         WHERE status = 'staged' AND expires_at <= ?`,
      )
      .run(now).changes;
    const reclaimedClaims = db
      .prepare(
        `UPDATE revocation_outbox
         SET status = 'pending', claim_owner = NULL, claim_expires_at = NULL
         WHERE status = 'claimed' AND claim_expires_at <= ?`,
      )
      .run(now).changes;
    return { expiredLogins, discardedStages, reclaimedClaims };
  })();
}

class SqliteOAuthStore implements LifecycleStore {
  readonly #db: Database.Database;
  readonly #cipher: TokenCipher;
  readonly #mcpResource: string | undefined;
  readonly #now: () => number;
  readonly #randomToken: (bytes?: number) => string;
  #ready = false;

  constructor(
    db: Database.Database,
    cipher: TokenCipher,
    mcpResource: string | undefined,
    now: () => number,
    randomToken: (bytes?: number) => string,
  ) {
    this.#db = db;
    this.#cipher = cipher;
    this.#mcpResource = mcpResource;
    this.#now = now;
    this.#randomToken = randomToken;
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
      options.randomToken ?? randomOpaque,
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
