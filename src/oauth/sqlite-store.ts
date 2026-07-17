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

import { SCHEMA_VERSION, SQLITE_MIGRATIONS } from "./sqlite-schema.js";
import type { OAuthStore, RecoverySummary, StoreInspection } from "./store.js";
import { TokenCipher, type EncryptedValue } from "./token-cipher.js";

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

export type SqliteOAuthStoreOptions = {
  path: string;
  cipher: TokenCipher;
  now?: () => number;
  randomId?: () => string;
  randomToken?: (bytes?: number) => string;
  busyTimeoutMs?: number;
};

type VersionRow = { version: number };
type CountRow = { count: number };
type MetadataRow = { value: string };
type EffectivePragmas = StoreInspection["pragmas"] & { busyTimeout: number };

type LifecycleStore = Pick<
  OAuthStore,
  "isReady" | "assertReady" | "recover" | "backup" | "inspectForTest" | "close"
>;

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
  #ready = false;

  constructor(db: Database.Database) {
    this.#db = db;
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

    const store = new SqliteOAuthStore(db);
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
