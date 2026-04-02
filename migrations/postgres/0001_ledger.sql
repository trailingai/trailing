CREATE TABLE IF NOT EXISTS action_log (
    sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    agent_type TEXT NOT NULL,
    session_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    context TEXT NOT NULL,
    outcome TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    org_id TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS app_settings (
    id INTEGER PRIMARY KEY,
    admin_key_id TEXT,
    CONSTRAINT app_settings_singleton CHECK (id = 1)
);

CREATE TABLE IF NOT EXISTS chain_integrity_checks (
    check_id TEXT PRIMARY KEY,
    checked_at TEXT NOT NULL,
    from_entry_id TEXT,
    to_entry_id TEXT,
    violation_count BIGINT NOT NULL,
    details TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_root_anchors (
    sequence BIGINT PRIMARY KEY,
    entry_id TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    sequence BIGINT NOT NULL UNIQUE,
    entry_id TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS merkle_batches (
    batch_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    start_sequence BIGINT NOT NULL UNIQUE,
    end_sequence BIGINT NOT NULL UNIQUE,
    leaf_count BIGINT NOT NULL,
    root_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS storage_control (
    id INTEGER PRIMARY KEY,
    allow_purge BOOLEAN NOT NULL DEFAULT FALSE,
    min_retention_days BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT storage_control_singleton CHECK (id = 1)
);

CREATE TABLE IF NOT EXISTS ingest_dedup (
    dedup_key TEXT PRIMARY KEY,
    entry_id TEXT,
    recorded_at TEXT NOT NULL
);

INSERT INTO storage_control (id, allow_purge, min_retention_days)
VALUES (1, FALSE, 0)
ON CONFLICT (id) DO NOTHING;

INSERT INTO app_settings (id, admin_key_id)
VALUES (1, NULL)
ON CONFLICT (id) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_action_log_org_id ON action_log (org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_org_id ON api_keys (org_id);
CREATE INDEX IF NOT EXISTS idx_merkle_batches_range ON merkle_batches (start_sequence, end_sequence);

CREATE OR REPLACE FUNCTION trailing_reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION trailing_guard_action_log_delete() RETURNS trigger AS $$
BEGIN
    IF COALESCE((SELECT allow_purge FROM storage_control WHERE id = 1), FALSE) = FALSE THEN
        RAISE EXCEPTION 'action_log deletes are blocked';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS action_log_reject_update ON action_log;
CREATE TRIGGER action_log_reject_update
BEFORE UPDATE ON action_log
FOR EACH ROW
EXECUTE FUNCTION trailing_reject_mutation();

DROP TRIGGER IF EXISTS action_log_reject_delete ON action_log;
CREATE TRIGGER action_log_reject_delete
BEFORE DELETE ON action_log
FOR EACH ROW
EXECUTE FUNCTION trailing_guard_action_log_delete();

DROP TRIGGER IF EXISTS chain_integrity_checks_reject_update ON chain_integrity_checks;
CREATE TRIGGER chain_integrity_checks_reject_update
BEFORE UPDATE OR DELETE ON chain_integrity_checks
FOR EACH ROW
EXECUTE FUNCTION trailing_reject_mutation();

DROP TRIGGER IF EXISTS ledger_root_anchors_reject_update ON ledger_root_anchors;
CREATE TRIGGER ledger_root_anchors_reject_update
BEFORE UPDATE OR DELETE ON ledger_root_anchors
FOR EACH ROW
EXECUTE FUNCTION trailing_reject_mutation();

DROP TRIGGER IF EXISTS ledger_checkpoints_reject_update ON ledger_checkpoints;
CREATE TRIGGER ledger_checkpoints_reject_update
BEFORE UPDATE OR DELETE ON ledger_checkpoints
FOR EACH ROW
EXECUTE FUNCTION trailing_reject_mutation();

DROP TRIGGER IF EXISTS merkle_batches_reject_update ON merkle_batches;
CREATE TRIGGER merkle_batches_reject_update
BEFORE UPDATE OR DELETE ON merkle_batches
FOR EACH ROW
EXECUTE FUNCTION trailing_reject_mutation();
