import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";

import Database from "better-sqlite3";

import {
  SecretCipher,
  hashOpaque,
  randomOpaque,
} from "./crypto.js";

const SCHEMA_VERSION = "1";
const INVITATION_TTL_SECONDS = 30 * 60;
const KEY_CHECK_PLAINTEXT = "zendesk-internal-user-bearers";

export type OAuthGrant = {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
  scopes: string[];
};

export type UserStatus =
  | "pending"
  | "active"
  | "revoked"
  | "reauthorization_required";

export type CredentialSnapshot = {
  userId: string;
  zendeskUserId: string;
  version: number;
  grant: OAuthGrant;
};

export type UserInspection = {
  id: string;
  label: string;
  status: UserStatus;
  zendeskUserId: string | null;
  zendeskName: string | null;
  zendeskEmail: string | null;
  createdAt: number;
  updatedAt: number;
  revokedAt: number | null;
  invitationStatus: "none" | "pending" | "started" | "consumed" | "expired";
  invitationExpiresAt: number | null;
};

type StoreOptions = {
  path: string;
  cipher: SecretCipher;
  subdomain: string;
  clientId: string;
  now?: () => number;
};

type UserInspectionRow = {
  id: string;
  label: string;
  status: UserStatus;
  zendesk_user_id: string | null;
  zendesk_name: string | null;
  zendesk_email: string | null;
  created_at: number;
  updated_at: number;
  revoked_at: number | null;
  invitation_expires_at: number | null;
  invitation_started_at: number | null;
  invitation_consumed_at: number | null;
};

const SCHEMA = `
CREATE TABLE IF NOT EXISTS store_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS internal_users (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  bearer_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (
    status IN ('pending', 'active', 'revoked', 'reauthorization_required')
  ),
  zendesk_user_id TEXT,
  zendesk_name TEXT,
  zendesk_email TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS internal_users_zendesk_identity_idx
ON internal_users(zendesk_user_id)
WHERE zendesk_user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS oauth_invitations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES internal_users(id) ON DELETE CASCADE,
  invitation_hash TEXT NOT NULL UNIQUE,
  state_hash TEXT UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  started_at INTEGER,
  consumed_at INTEGER,
  CHECK (
    (state_hash IS NULL AND started_at IS NULL)
    OR (state_hash IS NOT NULL AND started_at IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS oauth_invitations_user_idx
ON oauth_invitations(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS oauth_invitations_expiry_idx
ON oauth_invitations(expires_at);

CREATE TABLE IF NOT EXISTS oauth_grants (
  user_id TEXT PRIMARY KEY REFERENCES internal_users(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version >= 1),
  encrypted_grant TEXT NOT NULL,
  access_expires_at INTEGER NOT NULL,
  refresh_expires_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
`;

function assertSafeEpoch(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("Authentication store clock is invalid");
  }
}

function validateLabel(label: string): string {
  const trimmed = label.trim();
  if (
    trimmed.length === 0 ||
    trimmed.length > 128 ||
    /[\r\n\0]/.test(trimmed)
  ) {
    throw new Error("User label must be 1 to 128 single-line characters");
  }
  return trimmed;
}

function sqliteCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const code = Reflect.get(error, "code");
  return typeof code === "string" ? code : undefined;
}

export class InternalAuthStore {
  readonly #database: Database.Database;
  readonly #path: string;
  readonly #cipher: SecretCipher;
  readonly #subdomain: string;
  readonly #clientId: string;
  readonly #now: () => number;
  #closed = false;

  private constructor(
    database: Database.Database,
    options: StoreOptions,
  ) {
    this.#database = database;
    this.#path = options.path;
    this.#cipher = options.cipher;
    this.#subdomain = options.subdomain;
    this.#clientId = options.clientId;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1_000));
  }

  static open(options: StoreOptions): InternalAuthStore {
    mkdirSync(dirname(options.path), { recursive: true, mode: 0o700 });
    let database: Database.Database | undefined;
    try {
      database = new Database(options.path);
      chmodSync(options.path, 0o600);
      database.pragma("foreign_keys = ON");
      database.pragma("journal_mode = WAL");
      database.pragma("synchronous = FULL");
      database.pragma("trusted_schema = OFF");
      database.pragma("secure_delete = ON");
      database.pragma("busy_timeout = 5000");
      database.exec(SCHEMA);

      const store = new InternalAuthStore(database, options);
      store.#initializeMetadata();
      return store;
    } catch {
      try {
        database?.close();
      } catch {
        // Preserve the safe store-open failure.
      }
      throw new Error("Unable to open OAuth credential store");
    }
  }

  createPendingUser(label: string): {
    userId: string;
    bearer: string;
    invitation: string;
    expiresAt: number;
  } {
    const safeLabel = validateLabel(label);
    const now = this.#currentTime();
    const expiresAt = now + INVITATION_TTL_SECONDS;
    if (!Number.isSafeInteger(expiresAt)) {
      throw new Error("Authentication store clock is invalid");
    }

    const insert = this.#database.transaction(() => {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const userId = randomUUID();
        const bearer = randomOpaque("zmcp_");
        const invitation = randomOpaque();
        try {
          this.#database
            .prepare(
              `INSERT INTO internal_users (
                id, label, bearer_hash, status, created_at, updated_at
              ) VALUES (?, ?, ?, 'pending', ?, ?)`,
            )
            .run(userId, safeLabel, hashOpaque(bearer), now, now);
          this.#database
            .prepare(
              `INSERT INTO oauth_invitations (
                id, user_id, invitation_hash, created_at, expires_at
              ) VALUES (?, ?, ?, ?, ?)`,
            )
            .run(
              randomUUID(),
              userId,
              hashOpaque(invitation),
              now,
              expiresAt,
            );
          return { userId, bearer, invitation, expiresAt };
        } catch (error) {
          if (sqliteCode(error) !== "SQLITE_CONSTRAINT_UNIQUE") throw error;
        }
      }
      throw new Error("Unable to allocate unique authentication credentials");
    });

    const created = insert();
    this.#restrictDatabaseFiles();
    return created;
  }

  authenticateBearer(bearer: string): { userId: string } | undefined {
    if (!/^zmcp_[A-Za-z0-9_-]{43}$/.test(bearer)) return undefined;
    const row = this.#database
      .prepare(
        `SELECT internal_users.id
         FROM internal_users
         INNER JOIN oauth_grants
           ON oauth_grants.user_id = internal_users.id
         WHERE internal_users.bearer_hash = ?
           AND internal_users.status = 'active'`,
      )
      .get(hashOpaque(bearer)) as { id: string } | undefined;
    return row ? { userId: row.id } : undefined;
  }

  loadCredential(_userId: string): CredentialSnapshot | undefined {
    return undefined;
  }

  inspectUsers(): UserInspection[] {
    const now = this.#currentTime();
    const rows = this.#database
      .prepare(
        `SELECT
           users.id,
           users.label,
           users.status,
           users.zendesk_user_id,
           users.zendesk_name,
           users.zendesk_email,
           users.created_at,
           users.updated_at,
           users.revoked_at,
           invitation.expires_at AS invitation_expires_at,
           invitation.started_at AS invitation_started_at,
           invitation.consumed_at AS invitation_consumed_at
         FROM internal_users AS users
         LEFT JOIN oauth_invitations AS invitation
           ON invitation.id = (
             SELECT latest.id
             FROM oauth_invitations AS latest
             WHERE latest.user_id = users.id
             ORDER BY latest.created_at DESC, latest.id DESC
             LIMIT 1
           )
         ORDER BY users.created_at, users.id`,
      )
      .all() as UserInspectionRow[];

    return rows.map((row) => {
      let invitationStatus: UserInspection["invitationStatus"] = "none";
      if (row.invitation_expires_at !== null) {
        if (row.invitation_expires_at <= now) invitationStatus = "expired";
        else if (row.invitation_consumed_at !== null) {
          invitationStatus = "consumed";
        } else if (row.invitation_started_at !== null) {
          invitationStatus = "started";
        } else {
          invitationStatus = "pending";
        }
      }
      return {
        id: row.id,
        label: row.label,
        status: row.status,
        zendeskUserId: row.zendesk_user_id,
        zendeskName: row.zendesk_name,
        zendeskEmail: row.zendesk_email,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        revokedAt: row.revoked_at,
        invitationStatus,
        invitationExpiresAt: row.invitation_expires_at,
      };
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    try {
      this.#database.pragma("wal_checkpoint(TRUNCATE)");
    } finally {
      this.#database.close();
    }
  }

  #initializeMetadata(): void {
    const initialize = this.#database.transaction(() => {
      const schema = this.#database
        .prepare("SELECT value FROM store_metadata WHERE key = 'schema_version'")
        .get() as { value: string } | undefined;
      if (!schema) {
        this.#database
          .prepare("INSERT INTO store_metadata (key, value) VALUES (?, ?)")
          .run("schema_version", SCHEMA_VERSION);
      } else if (schema.value !== SCHEMA_VERSION) {
        throw new Error("unsupported schema");
      }

      const associatedData =
        `key-check:v1:${this.#subdomain}:${this.#clientId}`;
      const keyCheck = this.#database
        .prepare("SELECT value FROM store_metadata WHERE key = 'key_check'")
        .get() as { value: string } | undefined;
      if (!keyCheck) {
        this.#database
          .prepare("INSERT INTO store_metadata (key, value) VALUES (?, ?)")
          .run(
            "key_check",
            this.#cipher.encrypt(KEY_CHECK_PLAINTEXT, associatedData),
          );
      } else if (
        this.#cipher.decrypt(keyCheck.value, associatedData) !==
          KEY_CHECK_PLAINTEXT
      ) {
        throw new Error("invalid key check");
      }
    });
    initialize();
    this.#restrictDatabaseFiles();
  }

  #currentTime(): number {
    const now = this.#now();
    assertSafeEpoch(now);
    return now;
  }

  #restrictDatabaseFiles(): void {
    for (const path of [this.#path, `${this.#path}-wal`, `${this.#path}-shm`]) {
      try {
        chmodSync(path, 0o600);
      } catch {
        // WAL and SHM files may not exist at every point in the lifecycle.
      }
    }
  }
}
