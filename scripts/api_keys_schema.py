from __future__ import annotations

# Frozen schema exactly as it existed immediately before the api_keys cutover.
# migrate_service_preferences targets this contract; migrate_api_keys sources it.
# Never import live service_manager.db.SCHEMA here.

PRE_API_KEYS_SCHEMA = """
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_ciphertext BLOB NOT NULL,
    password_nonce BLOB NOT NULL,
    password_key_version INTEGER NOT NULL,
    password_changed_at TEXT
);
CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    rotation_days INTEGER CHECK (rotation_days IS NULL OR rotation_days BETWEEN 1 AND 3650)
);
CREATE TABLE account_service (
    account_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'nunca' CHECK (status IN ('ativo', 'nunca', 'inativo')),
    registered INTEGER NOT NULL DEFAULT 0 CHECK (registered IN (0, 1)),
    rotation_days INTEGER CHECK (rotation_days IS NULL OR rotation_days BETWEEN 1 AND 3650),
    rotation_due_at TEXT,
    PRIMARY KEY (account_id, service_id),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE TABLE custom_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    UNIQUE (service_id, name),
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE TABLE field_values (
    field_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    value_ciphertext BLOB NOT NULL,
    value_nonce BLOB NOT NULL,
    value_key_version INTEGER NOT NULL,
    PRIMARY KEY (field_id, account_id),
    FOREIGN KEY (field_id) REFERENCES custom_fields(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE INDEX account_service_service_id ON account_service(service_id);
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operador')),
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    password_changed_at TEXT,
    session_version INTEGER NOT NULL DEFAULT 0 CHECK (session_version >= 0)
);
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('login_failure', 'reveal', 'reveal_blocked', 'audit_degraded')),
    subject TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX security_events_kind_subject_occurred_at
    ON security_events(kind, subject, occurred_at);
CREATE INDEX security_events_kind_source_ip_occurred_at
    ON security_events(kind, source_ip, occurred_at);
CREATE INDEX security_events_occurred_at ON security_events(occurred_at);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor_user_id INTEGER,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    metadata_json TEXT,
    source_ip TEXT,
    user_agent TEXT,
    previous_hash BLOB NOT NULL,
    event_hash BLOB NOT NULL,
    FOREIGN KEY (actor_user_id) REFERENCES users(id)
);
CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;
CREATE TABLE service_members (
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'editor', 'service_admin')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, service_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE INDEX service_members_service_id ON service_members(service_id, user_id);
CREATE TABLE user_service_preferences (
    user_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    is_initial INTEGER NOT NULL DEFAULT 0 CHECK (is_initial IN (0, 1)),
    PRIMARY KEY (user_id, service_id),
    UNIQUE (user_id, position),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX user_service_preferences_one_initial
    ON user_service_preferences(user_id) WHERE is_initial = 1;
CREATE TABLE webhook_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination_host TEXT NOT NULL,
    url_ciphertext BLOB NOT NULL,
    url_nonce BLOB NOT NULL,
    url_key_version INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    signing_secret_ciphertext BLOB NOT NULL,
    signing_secret_nonce BLOB NOT NULL,
    signing_secret_key_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT
);
CREATE TABLE webhook_subscriptions (
    config_id INTEGER NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('login_failures', 'reveal_rate_limit', 'authorization_failure', 'audit_chain_degraded', 'user_deactivated', 'destructive_admin_action')),
    PRIMARY KEY (config_id, event_type),
    FOREIGN KEY (config_id) REFERENCES webhook_configs(id) ON DELETE CASCADE
);
CREATE TABLE webhook_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_id INTEGER NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('login_failures', 'reveal_rate_limit', 'authorization_failure', 'audit_chain_degraded', 'user_deactivated', 'destructive_admin_action', 'test')),
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivering', 'retry', 'succeeded', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
    next_attempt_at TEXT NOT NULL,
    lease_token TEXT,
    leased_at TEXT,
    last_status_code INTEGER,
    last_error TEXT,
    created_at TEXT NOT NULL,
    delivered_at TEXT,
    FOREIGN KEY (config_id) REFERENCES webhook_configs(id)
);
CREATE INDEX webhook_deliveries_status_next_attempt ON webhook_deliveries(status, next_attempt_at, id);
CREATE INDEX webhook_deliveries_config_created ON webhook_deliveries(config_id, created_at);
CREATE TABLE app_settings (
    key TEXT PRIMARY KEY CHECK (key IN ('rotation_enabled')),
    value TEXT NOT NULL CHECK (value IN ('0', '1'))
);
"""

__all__ = ["PRE_API_KEYS_SCHEMA"]
