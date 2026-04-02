ALTER TABLE storage_control
ADD COLUMN IF NOT EXISTS purge_through_sequence BIGINT;

CREATE TABLE IF NOT EXISTS checkpoint_signing_keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signed_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    sequence BIGINT NOT NULL,
    entry_id TEXT NOT NULL,
    ledger_root_hash TEXT NOT NULL,
    checkpoint_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL REFERENCES checkpoint_signing_keys(key_id)
);

CREATE TABLE IF NOT EXISTS checkpoint_anchors (
    anchor_id TEXT PRIMARY KEY,
    checkpoint_id TEXT NOT NULL REFERENCES signed_checkpoints(checkpoint_id),
    provider TEXT NOT NULL,
    reference TEXT NOT NULL,
    anchored_at TEXT NOT NULL,
    anchored_hash TEXT NOT NULL,
    metadata TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signed_checkpoints_created_at
ON signed_checkpoints (created_at DESC, checkpoint_id DESC);

CREATE INDEX IF NOT EXISTS idx_checkpoint_anchors_checkpoint_id
ON checkpoint_anchors (checkpoint_id);

CREATE TABLE IF NOT EXISTS legal_holds (
    id TEXT PRIMARY KEY,
    org_id TEXT,
    matter TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    released_at TEXT,
    release_reason TEXT
);

CREATE TABLE IF NOT EXISTS legal_hold_events (
    id TEXT PRIMARY KEY,
    hold_id TEXT NOT NULL REFERENCES legal_holds(id),
    org_id TEXT,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS purge_events (
    id TEXT PRIMARY KEY,
    purged_at TEXT NOT NULL,
    as_of TEXT NOT NULL,
    deleted_rows BIGINT NOT NULL,
    through_sequence BIGINT NOT NULL,
    through_entry_hash TEXT NOT NULL,
    resume_previous_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_legal_holds_org_id
ON legal_holds (org_id);

CREATE INDEX IF NOT EXISTS idx_legal_holds_released_at
ON legal_holds (released_at);

CREATE INDEX IF NOT EXISTS idx_legal_hold_events_hold_id
ON legal_hold_events (hold_id, occurred_at);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL,
    org_id TEXT NOT NULL,
    project_id TEXT,
    name TEXT NOT NULL,
    credential_type TEXT NOT NULL DEFAULT 'api_key'
        CHECK (credential_type IN ('api_key', 'service_account')),
    created_at TEXT NOT NULL,
    created_by TEXT,
    expires_at TEXT,
    last_used_at TEXT,
    previous_key_id TEXT,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TEXT,
    revocation_reason TEXT,
    roles TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_credentials_org_id
ON credentials (org_id);

CREATE INDEX IF NOT EXISTS idx_credentials_project_id
ON credentials (project_id);

CREATE INDEX IF NOT EXISTS idx_credentials_previous_key_id
ON credentials (previous_key_id);

INSERT INTO credentials (
    id,
    key_hash,
    org_id,
    project_id,
    name,
    credential_type,
    created_at,
    created_by,
    expires_at,
    last_used_at,
    previous_key_id,
    revoked,
    revoked_at,
    revocation_reason,
    roles
)
SELECT
    legacy.id,
    legacy.key_hash,
    legacy.org_id,
    NULL,
    legacy.name,
    'api_key',
    legacy.created_at,
    NULL,
    NULL,
    legacy.last_used_at,
    NULL,
    legacy.revoked,
    NULL,
    NULL,
    CASE
        WHEN legacy.id = (SELECT admin_key_id FROM app_settings WHERE id = 1)
            THEN '["admin"]'
        ELSE '["ingest","query","export"]'
    END
FROM api_keys AS legacy
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    external_subject TEXT NOT NULL,
    email TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login_at TEXT NOT NULL,
    UNIQUE (org_id, external_subject),
    UNIQUE (org_id, email)
);

CREATE INDEX IF NOT EXISTS idx_users_org_id
ON users (org_id);

CREATE INDEX IF NOT EXISTS idx_users_subject
ON users (org_id, external_subject);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    session_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_org_id
ON auth_sessions (org_id);

CREATE TABLE IF NOT EXISTS human_users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_authenticated_at TEXT,
    pending_mfa_secret TEXT,
    mfa_secret TEXT,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enrolled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_human_users_org_id
ON human_users (org_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_human_users_org_email
ON human_users (org_id, email);

CREATE TABLE IF NOT EXISTS org_mfa_policies (
    org_id TEXT PRIMARY KEY,
    policy TEXT NOT NULL CHECK (policy IN ('optional', 'required')),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_challenges_user_id
ON auth_challenges (user_id);

CREATE TABLE IF NOT EXISTS human_recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_human_recovery_codes_user_id
ON human_recovery_codes (user_id);
