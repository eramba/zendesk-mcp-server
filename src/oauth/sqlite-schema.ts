export const SCHEMA_VERSION = 1;

export const SQLITE_MIGRATIONS = [
  {
    version: 1,
    sql: `
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

CREATE TABLE store_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_id_issued_at INTEGER NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL CHECK (token_endpoint_auth_method = 'none'),
  grant_types_json TEXT NOT NULL,
  response_types_json TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope = 'zendesk:read zendesk:write'),
  client_name TEXT,
  metadata_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE oauth_client_redirect_uris (
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE login_transactions (
  id TEXT PRIMARY KEY,
  transaction_hash TEXT NOT NULL UNIQUE,
  upstream_state_hash TEXT UNIQUE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  browser_nonce_hash TEXT NOT NULL,
  consent_csrf_hash TEXT NOT NULL,
  encrypted_payload_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('consent_pending','upstream_pending','callback_claimed','complete','failed','denied')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consented_at INTEGER,
  completed_at INTEGER
);

CREATE TABLE principals (
  id TEXT PRIMARY KEY,
  subdomain TEXT NOT NULL,
  zendesk_user_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','disconnected','reauthorization_required')),
  lifecycle_epoch INTEGER NOT NULL CHECK (lifecycle_epoch >= 1),
  disconnected_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (subdomain, zendesk_user_id)
);

CREATE TABLE zendesk_credentials (
  principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
  credential_version INTEGER NOT NULL CHECK (credential_version >= 1),
  principal_epoch INTEGER NOT NULL,
  encrypted_grant_json TEXT NOT NULL,
  access_expires_at INTEGER NOT NULL,
  refresh_expires_at INTEGER NOT NULL,
  scopes TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE staged_grants (
  id TEXT PRIMARY KEY,
  login_transaction_id TEXT REFERENCES login_transactions(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('login','refresh')),
  subdomain TEXT NOT NULL,
  expected_principal_id TEXT,
  expected_principal_epoch INTEGER,
  expected_credential_version INTEGER,
  encrypted_grant_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('staged','discard_only')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE authorization_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scopes TEXT NOT NULL,
  resource TEXT NOT NULL,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  principal_epoch INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE TABLE token_families (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
  principal_id TEXT NOT NULL REFERENCES principals(id),
  principal_epoch INTEGER NOT NULL,
  scopes TEXT NOT NULL,
  resource TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  revoked_at INTEGER,
  revoke_reason TEXT
);

CREATE TABLE access_tokens (
  token_hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE refresh_token_generations (
  token_hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('current','consumed')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  successor_generation INTEGER,
  encrypted_retry_response_json TEXT,
  retry_response_expires_at INTEGER,
  UNIQUE (family_id, generation)
);

CREATE TABLE revocation_outbox (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  captured_principal_epoch INTEGER NOT NULL,
  credential_version INTEGER NOT NULL,
  encrypted_grant_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','claimed')),
  attempt_count INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  claim_owner TEXT,
  claim_expires_at INTEGER,
  retention_expires_at INTEGER NOT NULL,
  last_error_category TEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);

CREATE INDEX authorization_codes_expiry_idx ON authorization_codes(expires_at);
CREATE INDEX access_tokens_family_idx ON access_tokens(family_id);
CREATE INDEX refresh_generations_family_idx ON refresh_token_generations(family_id, generation);
CREATE INDEX revocation_outbox_due_idx ON revocation_outbox(status, next_attempt_at, claim_expires_at);
CREATE INDEX token_families_principal_idx ON token_families(principal_id, revoked_at);
CREATE INDEX staged_grants_recovery_idx ON staged_grants(status, expires_at);
`,
  },
] as const;
