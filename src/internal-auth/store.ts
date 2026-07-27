import { chmodSync, mkdirSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { randomUUID } from "node:crypto";

import Database from "better-sqlite3";

import {
  SecretCipher,
  hashOpaque,
  randomOpaque,
} from "./crypto.js";

const SCHEMA_VERSION = "1";
const INVITATION_TTL_SECONDS = 30 * 60;
const SELF_ENROLLMENT_TTL_SECONDS = 10 * 60;
const KEY_CHECK_PLAINTEXT = "zendesk-internal-user-bearers";

export type OAuthGrant = {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
  scopes: string[];
};

export type ZendeskIdentity = {
  id: string;
  name: string | null;
  email: string | null;
  role: "end-user" | "agent" | "admin";
};

export type AuthorizationClaim =
  | {
      kind: "invitation";
      invitationId: string;
      userId: string;
    }
  | {
      kind: "self_enrollment";
      enrollmentId: string;
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

type UserResetResult =
  | { kind: "reset"; capturedGrant?: OAuthGrant }
  | { kind: "not_found" }
  | { kind: "ambiguous" };

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

type CredentialRow = {
  user_id: string;
  status: UserStatus;
  zendesk_user_id: string | null;
  version: number;
  encrypted_grant: string;
};

type InvitationRow = {
  id: string;
  user_id: string;
  expires_at: number;
};

type SelfEnrollmentRow = {
  id: string;
  expires_at: number;
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

CREATE TABLE IF NOT EXISTS oauth_self_enrollments (
  id TEXT PRIMARY KEY,
  state_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS oauth_self_enrollments_expiry_idx
ON oauth_self_enrollments(expires_at);

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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonicalGrant(grant: OAuthGrant): OAuthGrant {
  if (
    typeof grant.accessToken !== "string" ||
    grant.accessToken.length === 0 ||
    typeof grant.refreshToken !== "string" ||
    grant.refreshToken.length === 0 ||
    !Number.isSafeInteger(grant.accessExpiresAt) ||
    !Number.isSafeInteger(grant.refreshExpiresAt) ||
    grant.accessExpiresAt < 0 ||
    grant.refreshExpiresAt <= grant.accessExpiresAt
  ) {
    throw new Error("OAuth grant is invalid");
  }
  const scopes = [...new Set(grant.scopes)];
  if (
    scopes.length !== 2 ||
    !scopes.includes("read") ||
    !scopes.includes("tickets:write")
  ) {
    throw new Error("OAuth grant is invalid");
  }
  return {
    accessToken: grant.accessToken,
    refreshToken: grant.refreshToken,
    accessExpiresAt: grant.accessExpiresAt,
    refreshExpiresAt: grant.refreshExpiresAt,
    scopes: ["read", "tickets:write"],
  };
}

function parseGrant(value: string): OAuthGrant {
  const parsed: unknown = JSON.parse(value);
  if (!isRecord(parsed)) throw new Error("invalid grant");
  return canonicalGrant({
    accessToken: parsed.accessToken as string,
    refreshToken: parsed.refreshToken as string,
    accessExpiresAt: parsed.accessExpiresAt as number,
    refreshExpiresAt: parsed.refreshExpiresAt as number,
    scopes: parsed.scopes as string[],
  });
}

function validateIdentity(identity: ZendeskIdentity): void {
  if (!/^[1-9]\d*$/.test(identity.id)) {
    throw new Error("Zendesk identity is invalid");
  }
  for (const value of [identity.name, identity.email]) {
    if (
      value !== null &&
      (typeof value !== "string" ||
        value.length === 0 ||
        value.length > 512 ||
        /[\r\n\0]/.test(value))
    ) {
      throw new Error("Zendesk identity is invalid");
    }
  }
  if (!(["end-user", "agent", "admin"] as const).includes(identity.role)) {
    throw new Error("Zendesk identity is invalid");
  }
}

function eligibleIdentityLabel(identity: ZendeskIdentity): string {
  if (identity.role !== "agent" && identity.role !== "admin") {
    throw new Error("Zendesk identity is not eligible");
  }
  for (const candidate of [
    identity.name,
    identity.email,
    `Zendesk user ${identity.id}`,
  ]) {
    if (candidate === null) continue;
    try {
      return validateLabel(candidate);
    } catch {
      // Fall through to the next authoritative identity field.
    }
  }
  throw new Error("Zendesk identity has no safe label");
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
      store.#cleanupExpiredAuthorizationState();
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

  createSelfEnrollment(): { state: string; expiresAt: number } {
    const now = this.#currentTime();
    const expiresAt = now + SELF_ENROLLMENT_TTL_SECONDS;
    if (!Number.isSafeInteger(expiresAt)) {
      throw new Error("Authentication store clock is invalid");
    }
    this.#cleanupExpiredAuthorizationState(now);

    const insert = this.#database.transaction(() => {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const state = randomOpaque();
        try {
          this.#database
            .prepare(
              `INSERT INTO oauth_self_enrollments (
                id, state_hash, created_at, expires_at
              ) VALUES (?, ?, ?, ?)`,
            )
            .run(randomUUID(), hashOpaque(state), now, expiresAt);
          return { state, expiresAt };
        } catch (error) {
          if (sqliteCode(error) !== "SQLITE_CONSTRAINT_UNIQUE") throw error;
        }
      }
      throw new Error("Unable to allocate self-service enrollment state");
    });

    const created = insert.immediate();
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

  startInvitation(
    invitation: string,
    state: string,
  ): {
    invitationId: string;
    userId: string;
    expiresAt: number;
  } | undefined {
    if (
      !/^[A-Za-z0-9_-]{43}$/.test(invitation) ||
      !/^[A-Za-z0-9_-]{43}$/.test(state)
    ) {
      return undefined;
    }
    const now = this.#currentTime();
    this.#cleanupExpiredAuthorizationState(now);
    const start = this.#database.transaction(() => {
      const row = this.#database
        .prepare(
          `SELECT invitation.id, invitation.user_id, invitation.expires_at
           FROM oauth_invitations AS invitation
           INNER JOIN internal_users AS users ON users.id = invitation.user_id
           WHERE invitation.invitation_hash = ?
             AND invitation.started_at IS NULL
             AND invitation.consumed_at IS NULL
             AND invitation.expires_at > ?
             AND users.status IN ('pending', 'reauthorization_required')`,
        )
        .get(hashOpaque(invitation), now) as InvitationRow | undefined;
      if (!row) return undefined;
      const result = this.#database
        .prepare(
          `UPDATE oauth_invitations
           SET state_hash = ?, started_at = ?
           WHERE id = ?
             AND started_at IS NULL
             AND consumed_at IS NULL
             AND expires_at > ?`,
        )
        .run(hashOpaque(state), now, row.id, now);
      if (result.changes !== 1) return undefined;
      return {
        invitationId: row.id,
        userId: row.user_id,
        expiresAt: row.expires_at,
      };
    });
    const result = start();
    this.#restrictDatabaseFiles();
    return result;
  }

  claimAuthorization(state: string): AuthorizationClaim | undefined {
    if (!/^[A-Za-z0-9_-]{43}$/.test(state)) return undefined;
    const now = this.#currentTime();
    this.#cleanupExpiredAuthorizationState(now);
    const claim = this.#database.transaction(() => {
      const stateHash = hashOpaque(state);
      const invitation = this.#database
        .prepare(
          `SELECT invitation.id, invitation.user_id, invitation.expires_at
           FROM oauth_invitations AS invitation
           INNER JOIN internal_users AS users ON users.id = invitation.user_id
           WHERE invitation.state_hash = ?
             AND invitation.started_at IS NOT NULL
             AND invitation.consumed_at IS NULL
             AND invitation.expires_at > ?
             AND users.status IN ('pending', 'reauthorization_required')`,
        )
        .get(stateHash, now) as InvitationRow | undefined;
      const enrollment = this.#database
        .prepare(
          `SELECT id, expires_at
           FROM oauth_self_enrollments
           WHERE state_hash = ?
             AND consumed_at IS NULL
             AND expires_at > ?`,
        )
        .get(stateHash, now) as SelfEnrollmentRow | undefined;

      if ((invitation ? 1 : 0) + (enrollment ? 1 : 0) !== 1) {
        return undefined;
      }
      if (invitation) {
        const result = this.#database
          .prepare(
            `UPDATE oauth_invitations
             SET consumed_at = ?
             WHERE id = ?
               AND consumed_at IS NULL
               AND expires_at > ?`,
          )
          .run(now, invitation.id, now);
        if (result.changes !== 1) return undefined;
        return {
          kind: "invitation" as const,
          invitationId: invitation.id,
          userId: invitation.user_id,
        };
      }

      const result = this.#database
        .prepare(
          `UPDATE oauth_self_enrollments
           SET consumed_at = ?
           WHERE id = ?
             AND consumed_at IS NULL
             AND expires_at > ?`,
        )
        .run(now, (enrollment as SelfEnrollmentRow).id, now);
      if (result.changes !== 1) return undefined;
      return {
        kind: "self_enrollment" as const,
        enrollmentId: (enrollment as SelfEnrollmentRow).id,
      };
    });
    const result = claim.immediate();
    this.#restrictDatabaseFiles();
    return result;
  }

  completeLink(input: {
    invitationId: string;
    userId: string;
    identity: ZendeskIdentity;
    grant: OAuthGrant;
  }): CredentialSnapshot {
    try {
      validateIdentity(input.identity);
      const grant = canonicalGrant(input.grant);
      const now = this.#currentTime();
      if (
        grant.accessExpiresAt <= now ||
        grant.refreshExpiresAt <= now
      ) {
        throw new Error("OAuth grant is expired");
      }
      const version = 1;
      const encryptedGrant = this.#encryptGrant(
        input.userId,
        version,
        grant,
      );
      const complete = this.#database.transaction(() => {
        const invitation = this.#database
          .prepare(
            `SELECT invitation.id
             FROM oauth_invitations AS invitation
             INNER JOIN internal_users AS users ON users.id = invitation.user_id
             WHERE invitation.id = ?
               AND invitation.user_id = ?
               AND invitation.started_at IS NOT NULL
               AND invitation.consumed_at IS NOT NULL
               AND invitation.expires_at > ?
               AND users.status IN ('pending', 'reauthorization_required')`,
          )
          .get(input.invitationId, input.userId, now);
        if (!invitation) throw new Error("invalid callback claim");

        this.#database
          .prepare(
            `INSERT INTO oauth_grants (
              user_id, version, encrypted_grant, access_expires_at,
              refresh_expires_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              version = excluded.version,
              encrypted_grant = excluded.encrypted_grant,
              access_expires_at = excluded.access_expires_at,
              refresh_expires_at = excluded.refresh_expires_at,
              updated_at = excluded.updated_at`,
          )
          .run(
            input.userId,
            version,
            encryptedGrant,
            grant.accessExpiresAt,
            grant.refreshExpiresAt,
            now,
          );
        const updated = this.#database
          .prepare(
            `UPDATE internal_users
             SET status = 'active',
                 zendesk_user_id = ?,
                 zendesk_name = ?,
                 zendesk_email = ?,
                 updated_at = ?,
                 revoked_at = NULL
             WHERE id = ?
               AND status IN ('pending', 'reauthorization_required')`,
          )
          .run(
            input.identity.id,
            input.identity.name,
            input.identity.email,
            now,
            input.userId,
          );
        if (updated.changes !== 1) throw new Error("inactive user");
      });
      complete();
      this.#restrictDatabaseFiles();
      return {
        userId: input.userId,
        zendeskUserId: input.identity.id,
        version,
        grant,
      };
    } catch {
      throw new Error("Unable to activate linked user");
    }
  }

  completeSelfEnrollment(input: {
    enrollmentId: string;
    identity: ZendeskIdentity;
    grant: OAuthGrant;
  }):
    | { kind: "created"; userId: string; bearer: string }
    | { kind: "already_registered" } {
    try {
      validateIdentity(input.identity);
      const label = eligibleIdentityLabel(input.identity);
      const grant = canonicalGrant(input.grant);
      const now = this.#currentTime();
      if (grant.accessExpiresAt <= now || grant.refreshExpiresAt <= now) {
        throw new Error("OAuth grant is expired");
      }

      for (let attempt = 0; attempt < 5; attempt += 1) {
        const userId = randomUUID();
        const bearer = randomOpaque("zmcp_");
        const version = 1;
        const encryptedGrant = this.#encryptGrant(userId, version, grant);
        const complete = this.#database.transaction(() => {
          const enrollment = this.#database
            .prepare(
              `SELECT id
               FROM oauth_self_enrollments
               WHERE id = ?
                 AND consumed_at IS NOT NULL
                 AND expires_at > ?`,
            )
            .get(input.enrollmentId, now);
          if (!enrollment) throw new Error("invalid enrollment claim");

          this.#database
            .prepare(
              `INSERT INTO internal_users (
                id, label, bearer_hash, status,
                zendesk_user_id, zendesk_name, zendesk_email,
                created_at, updated_at
              ) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?)`,
            )
            .run(
              userId,
              label,
              hashOpaque(bearer),
              input.identity.id,
              input.identity.name,
              input.identity.email,
              now,
              now,
            );
          this.#database
            .prepare(
              `INSERT INTO oauth_grants (
                user_id, version, encrypted_grant, access_expires_at,
                refresh_expires_at, updated_at
              ) VALUES (?, ?, ?, ?, ?, ?)`,
            )
            .run(
              userId,
              version,
              encryptedGrant,
              grant.accessExpiresAt,
              grant.refreshExpiresAt,
              now,
            );
          const removed = this.#database
            .prepare(
              `DELETE FROM oauth_self_enrollments
               WHERE id = ?
                 AND consumed_at IS NOT NULL
                 AND expires_at > ?`,
            )
            .run(input.enrollmentId, now);
          if (removed.changes !== 1) {
            throw new Error("invalid enrollment completion");
          }
        });

        try {
          complete.immediate();
          this.#restrictDatabaseFiles();
          return { kind: "created", userId, bearer };
        } catch (error) {
          if (sqliteCode(error) !== "SQLITE_CONSTRAINT_UNIQUE") throw error;
          const existingIdentity = this.#database
            .prepare(
              `SELECT 1
               FROM internal_users
               WHERE zendesk_user_id = ?`,
            )
            .get(input.identity.id);
          if (existingIdentity) return { kind: "already_registered" };
        }
      }
      throw new Error("Unable to allocate unique authentication credentials");
    } catch {
      throw new Error("Unable to complete self-service enrollment");
    }
  }

  createReauthorization(userId: string): {
    invitation: string;
    expiresAt: number;
  } {
    try {
      const now = this.#currentTime();
      const expiresAt = now + INVITATION_TTL_SECONDS;
      if (!Number.isSafeInteger(expiresAt)) {
        throw new Error("invalid expiry");
      }
      this.#cleanupExpiredAuthorizationState(now);
      const create = this.#database.transaction(() => {
        const user = this.#database
          .prepare(
            `SELECT id FROM internal_users
             WHERE id = ?
               AND status IN ('pending', 'reauthorization_required')`,
          )
          .get(userId);
        if (!user) throw new Error("invalid user");
        this.#database
          .prepare("DELETE FROM oauth_invitations WHERE user_id = ?")
          .run(userId);

        for (let attempt = 0; attempt < 5; attempt += 1) {
          const invitation = randomOpaque();
          try {
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
            return { invitation, expiresAt };
          } catch (error) {
            if (sqliteCode(error) !== "SQLITE_CONSTRAINT_UNIQUE") throw error;
          }
        }
        throw new Error("unable to allocate invitation");
      });
      const created = create();
      this.#restrictDatabaseFiles();
      return created;
    } catch {
      throw new Error("Unable to create reauthorization invitation");
    }
  }

  loadCredential(userId: string): CredentialSnapshot | undefined {
    const row = this.#loadCredentialRow(userId);
    if (!row || row.status !== "active" || row.zendesk_user_id === null) {
      return undefined;
    }
    try {
      return {
        userId: row.user_id,
        zendeskUserId: row.zendesk_user_id,
        version: row.version,
        grant: this.#decryptGrant(
          row.user_id,
          row.version,
          row.encrypted_grant,
        ),
      };
    } catch {
      throw new Error("Unable to load OAuth credential");
    }
  }

  installRefreshedGrant(input: {
    userId: string;
    expectedVersion: number;
    grant: OAuthGrant;
  }):
    | { kind: "installed"; snapshot: CredentialSnapshot }
    | { kind: "newer"; snapshot: CredentialSnapshot }
    | { kind: "inactive" } {
    const grant = canonicalGrant(input.grant);
    const now = this.#currentTime();
    if (grant.accessExpiresAt <= now || grant.refreshExpiresAt <= now) {
      throw new Error("OAuth grant is expired");
    }

    const install = this.#database.transaction(() => {
      const current = this.loadCredential(input.userId);
      if (!current) return { kind: "inactive" as const };
      if (current.version !== input.expectedVersion) {
        return { kind: "newer" as const, snapshot: current };
      }

      const version = current.version + 1;
      if (!Number.isSafeInteger(version)) {
        throw new Error("OAuth credential version is invalid");
      }
      const encryptedGrant = this.#encryptGrant(
        input.userId,
        version,
        grant,
      );
      const updated = this.#database
        .prepare(
          `UPDATE oauth_grants
           SET version = ?,
               encrypted_grant = ?,
               access_expires_at = ?,
               refresh_expires_at = ?,
               updated_at = ?
           WHERE user_id = ?
             AND version = ?
             AND EXISTS (
               SELECT 1 FROM internal_users
               WHERE id = ? AND status = 'active'
             )`,
        )
        .run(
          version,
          encryptedGrant,
          grant.accessExpiresAt,
          grant.refreshExpiresAt,
          now,
          input.userId,
          input.expectedVersion,
          input.userId,
        );
      if (updated.changes !== 1) {
        const winner = this.loadCredential(input.userId);
        return winner
          ? { kind: "newer" as const, snapshot: winner }
          : { kind: "inactive" as const };
      }
      this.#database
        .prepare("UPDATE internal_users SET updated_at = ? WHERE id = ?")
        .run(now, input.userId);
      return {
        kind: "installed" as const,
        snapshot: {
          userId: input.userId,
          zendeskUserId: current.zendeskUserId,
          version,
          grant,
        },
      };
    });
    const result = install();
    this.#restrictDatabaseFiles();
    return result;
  }

  markReauthorizationRequired(
    userId: string,
    expectedVersion: number,
  ): boolean {
    const now = this.#currentTime();
    const mark = this.#database.transaction(() => {
      const current = this.#database
        .prepare(
          `SELECT grants.version
           FROM oauth_grants AS grants
           INNER JOIN internal_users AS users ON users.id = grants.user_id
           WHERE grants.user_id = ?
             AND grants.version = ?
             AND users.status = 'active'`,
        )
        .get(userId, expectedVersion);
      if (!current) return false;
      const updated = this.#database
        .prepare(
          `UPDATE internal_users
           SET status = 'reauthorization_required', updated_at = ?
           WHERE id = ? AND status = 'active'`,
        )
        .run(now, userId);
      if (updated.changes !== 1) return false;
      this.#database
        .prepare("DELETE FROM oauth_grants WHERE user_id = ?")
        .run(userId);
      this.#database
        .prepare("DELETE FROM oauth_invitations WHERE user_id = ?")
        .run(userId);
      return true;
    });
    const changed = mark();
    this.#restrictDatabaseFiles();
    return changed;
  }

  revokeUser(userId: string):
    | { kind: "revoked"; capturedGrant?: OAuthGrant }
    | { kind: "already_revoked" }
    | { kind: "not_found" } {
    const now = this.#currentTime();
    const revoke = this.#database.transaction(() => {
      const user = this.#database
        .prepare("SELECT status FROM internal_users WHERE id = ?")
        .get(userId) as { status: UserStatus } | undefined;
      if (!user) return { kind: "not_found" as const };
      if (user.status === "revoked") {
        return { kind: "already_revoked" as const };
      }

      let capturedGrant: OAuthGrant | undefined;
      try {
        capturedGrant = this.loadCredential(userId)?.grant;
      } catch {
        capturedGrant = undefined;
      }
      this.#database
        .prepare(
          `UPDATE internal_users
           SET status = 'revoked', updated_at = ?, revoked_at = ?
           WHERE id = ?`,
        )
        .run(now, now, userId);
      this.#database
        .prepare("DELETE FROM oauth_grants WHERE user_id = ?")
        .run(userId);
      this.#database
        .prepare("DELETE FROM oauth_invitations WHERE user_id = ?")
        .run(userId);
      return capturedGrant
        ? { kind: "revoked" as const, capturedGrant }
        : { kind: "revoked" as const };
    });
    const result = revoke();
    this.#restrictDatabaseFiles();
    return result;
  }

  #resetUserRecord(userId: string): UserResetResult {
    const user = this.#database
      .prepare("SELECT 1 FROM internal_users WHERE id = ?")
      .get(userId);
    if (!user) return { kind: "not_found" };

    let capturedGrant: OAuthGrant | undefined;
    try {
      capturedGrant = this.loadCredential(userId)?.grant;
    } catch {
      capturedGrant = undefined;
    }
    const deleted = this.#database
      .prepare("DELETE FROM internal_users WHERE id = ?")
      .run(userId);
    if (deleted.changes !== 1) throw new Error("unable to reset user");
    return capturedGrant
      ? { kind: "reset", capturedGrant }
      : { kind: "reset" };
  }

  resetUser(userId: string): UserResetResult {
    const reset = this.#database.transaction(() =>
      this.#resetUserRecord(userId),
    );
    const result = reset();
    this.#restrictDatabaseFiles();
    return result;
  }

  resetUserByEmail(email: string): UserResetResult {
    const reset = this.#database.transaction(() => {
      const matches = this.#database
        .prepare(
          `SELECT id FROM internal_users
           WHERE zendesk_email COLLATE NOCASE = ?
           ORDER BY id
           LIMIT 2`,
        )
        .all(email) as Array<{ id: string }>;
      if (matches.length === 0) return { kind: "not_found" as const };
      if (matches.length > 1) return { kind: "ambiguous" as const };
      return this.#resetUserRecord(matches[0].id);
    });
    const result = reset();
    this.#restrictDatabaseFiles();
    return result;
  }

  async backup(destination: string): Promise<void> {
    if (!isAbsolute(destination) || destination === this.#path) {
      throw new Error("Backup destination must be a different absolute path");
    }
    mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
    try {
      await this.#database.backup(destination);
      chmodSync(destination, 0o600);
    } catch {
      throw new Error("Unable to create OAuth store backup");
    }
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

  #loadCredentialRow(userId: string): CredentialRow | undefined {
    return this.#database
      .prepare(
        `SELECT
           grants.user_id,
           users.status,
           users.zendesk_user_id,
           grants.version,
           grants.encrypted_grant
         FROM oauth_grants AS grants
         INNER JOIN internal_users AS users ON users.id = grants.user_id
         WHERE grants.user_id = ?`,
      )
      .get(userId) as CredentialRow | undefined;
  }

  #encryptGrant(
    userId: string,
    version: number,
    grant: OAuthGrant,
  ): string {
    return this.#cipher.encrypt(
      JSON.stringify(canonicalGrant(grant)),
      this.#grantAssociatedData(userId, version),
    );
  }

  #decryptGrant(
    userId: string,
    version: number,
    encryptedGrant: string,
  ): OAuthGrant {
    return parseGrant(
      this.#cipher.decrypt(
        encryptedGrant,
        this.#grantAssociatedData(userId, version),
      ),
    );
  }

  #grantAssociatedData(userId: string, version: number): string {
    return `grant:v1:${this.#subdomain}:${this.#clientId}:${userId}:${version}`;
  }

  #cleanupExpiredAuthorizationState(now = this.#currentTime()): void {
    const cleanup = this.#database.transaction(() => {
      this.#database
        .prepare("DELETE FROM oauth_invitations WHERE expires_at <= ?")
        .run(now);
      this.#database
        .prepare("DELETE FROM oauth_self_enrollments WHERE expires_at <= ?")
        .run(now);
    });
    cleanup.immediate();
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
