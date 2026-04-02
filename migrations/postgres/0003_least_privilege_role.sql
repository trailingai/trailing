DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trailing_app') THEN
        CREATE ROLE trailing_app LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            INHERIT;
    END IF;
END;
$$;

GRANT USAGE ON SCHEMA public TO trailing_app;

GRANT SELECT, INSERT ON action_log TO trailing_app;
GRANT SELECT, INSERT ON chain_integrity_checks TO trailing_app;
GRANT SELECT, INSERT ON ledger_root_anchors TO trailing_app;
GRANT SELECT, INSERT ON ledger_checkpoints TO trailing_app;
GRANT SELECT, INSERT ON merkle_batches TO trailing_app;
GRANT SELECT, INSERT ON checkpoint_signing_keys TO trailing_app;
GRANT SELECT, INSERT ON signed_checkpoints TO trailing_app;
GRANT SELECT, INSERT ON checkpoint_anchors TO trailing_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON storage_control TO trailing_app;
GRANT SELECT, INSERT, UPDATE ON api_keys TO trailing_app;
GRANT SELECT, INSERT, UPDATE ON credentials TO trailing_app;
GRANT SELECT, INSERT, UPDATE ON users TO trailing_app;
GRANT SELECT, INSERT, UPDATE ON auth_sessions TO trailing_app;
GRANT SELECT, INSERT, UPDATE ON human_users TO trailing_app;
GRANT SELECT, INSERT, UPDATE ON org_mfa_policies TO trailing_app;
GRANT SELECT, INSERT, UPDATE ON auth_challenges TO trailing_app;
GRANT SELECT, INSERT, UPDATE ON human_recovery_codes TO trailing_app;
GRANT SELECT, INSERT, UPDATE ON legal_holds TO trailing_app;
GRANT SELECT, INSERT ON legal_hold_events TO trailing_app;
GRANT SELECT, INSERT ON purge_events TO trailing_app;
GRANT SELECT, INSERT ON ingest_dedup TO trailing_app;
GRANT SELECT, UPDATE ON app_settings TO trailing_app;
GRANT SELECT ON schema_migrations TO trailing_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO trailing_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO trailing_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT ON TABLES TO trailing_app;
