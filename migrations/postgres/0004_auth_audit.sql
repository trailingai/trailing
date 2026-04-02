CREATE TABLE IF NOT EXISTS auth_audit_log (
    sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    org_id TEXT,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    outcome TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_log_org_id
ON auth_audit_log (org_id);

CREATE INDEX IF NOT EXISTS idx_auth_audit_log_event_type
ON auth_audit_log (event_type);

CREATE OR REPLACE FUNCTION trailing_reject_auth_audit_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'auth_audit_log deletes are blocked';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS auth_audit_log_reject_update ON auth_audit_log;
CREATE TRIGGER auth_audit_log_reject_update
BEFORE UPDATE ON auth_audit_log
FOR EACH ROW
EXECUTE FUNCTION trailing_reject_mutation();

DROP TRIGGER IF EXISTS auth_audit_log_reject_delete ON auth_audit_log;
CREATE TRIGGER auth_audit_log_reject_delete
BEFORE DELETE ON auth_audit_log
FOR EACH ROW
EXECUTE FUNCTION trailing_reject_auth_audit_delete();

GRANT SELECT, INSERT ON auth_audit_log TO trailing_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO trailing_app;
