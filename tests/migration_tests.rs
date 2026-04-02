use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{Duration, TimeZone, Utc};
use rusqlite::{Connection, params};
use serde_json::json;

use trailing::{
    log::{ActionEntry, ActionType, GENESIS_HASH},
    storage::{
        SqliteStorage,
        migration::{MigrationDirection, MigrationOptions, execute as execute_migration},
        verify_chain,
    },
};

fn temp_db_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "trailing-migrate-{test_name}-{}-{nanos}.db",
        std::process::id()
    ))
}

fn root_anchor_path(db_path: &PathBuf) -> PathBuf {
    let mut anchor_path = db_path.as_os_str().to_os_string();
    anchor_path.push(".root");
    PathBuf::from(anchor_path)
}

fn create_legacy_db(test_name: &str, rows: usize) -> PathBuf {
    let db_path = temp_db_path(test_name);
    let conn = Connection::open(&db_path).expect("open legacy db");
    conn.execute_batch(
        "
        CREATE TABLE action_log (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
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

        CREATE TABLE chain_integrity_checks (
            check_id TEXT PRIMARY KEY,
            checked_at TEXT NOT NULL,
            from_entry_id TEXT,
            to_entry_id TEXT,
            violation_count INTEGER NOT NULL,
            details TEXT NOT NULL
        );

        CREATE TABLE storage_control (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            allow_purge INTEGER NOT NULL DEFAULT 0 CHECK (allow_purge IN (0, 1)),
            min_retention_days INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE app_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            admin_key_id TEXT
        );

        CREATE TABLE api_keys (
            id TEXT PRIMARY KEY,
            key_hash TEXT NOT NULL,
            org_id TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
        );

        CREATE TABLE ingest_dedup (
            dedup_key TEXT PRIMARY KEY,
            entry_id TEXT,
            recorded_at TEXT NOT NULL
        );

        INSERT INTO storage_control (id, allow_purge, min_retention_days)
        VALUES (1, 0, 0);

        INSERT INTO app_settings (id, admin_key_id)
        VALUES (1, NULL);

        CREATE TRIGGER action_log_reject_update
        BEFORE UPDATE ON action_log
        BEGIN
            SELECT RAISE(ABORT, 'action_log is append-only');
        END;

        CREATE TRIGGER action_log_reject_delete
        BEFORE DELETE ON action_log
        WHEN COALESCE((SELECT allow_purge FROM storage_control WHERE id = 1), 0) = 0
        BEGIN
            SELECT RAISE(ABORT, 'action_log deletes are blocked');
        END;
        PRAGMA user_version = 1;
        ",
    )
    .expect("create legacy schema");

    let base_time = Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap();
    let mut previous_hash = GENESIS_HASH.to_string();
    let mut latest_hash = None;

    for index in 0..rows {
        let entry = ActionEntry::new_with_timestamp(
            base_time + Duration::seconds(index as i64),
            format!("agent-{index}"),
            "worker",
            format!("session-{}", index % 3),
            match index % 3 {
                0 => ActionType::ToolCall,
                1 => ActionType::Decision,
                _ => ActionType::PolicyCheck,
            },
            json!({ "index": index }),
            json!({ "request_id": format!("req-{index}") }),
            "ok",
            previous_hash.clone(),
        );

        conn.execute(
            "INSERT INTO action_log (
                id,
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
                previous_hash,
                entry_hash,
                org_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)",
            params![
                entry.id.to_string(),
                ActionEntry::canonical_timestamp(&entry.timestamp),
                entry.agent_id,
                entry.agent_type,
                entry.session_id,
                entry.action_type.to_string(),
                entry.payload.to_string(),
                entry.context.to_string(),
                entry.outcome,
                entry.previous_hash,
                entry.entry_hash,
            ],
        )
        .expect("insert legacy entry");

        previous_hash = entry.entry_hash.clone();
        latest_hash = Some(previous_hash.clone());
    }

    if let Some(hash) = latest_hash {
        fs::write(root_anchor_path(&db_path), hash).expect("write root anchor");
    }

    db_path
}

#[test]
fn migration_dry_run_reports_changes_without_mutating_db() {
    let db_path = create_legacy_db("dry-run", 5);

    let outcome = execute_migration(
        &db_path,
        &MigrationOptions {
            apply: false,
            direction: MigrationDirection::Apply,
            verify: true,
        },
        |_| {},
    )
    .expect("dry run should succeed");

    assert!(outcome.dry_run);
    assert_eq!(outcome.before.mode, "legacy");
    assert_eq!(outcome.after.mode, "immutable");
    assert_eq!(outcome.after.checkpoint_rows, 5);

    let conn = Connection::open(&db_path).expect("open db");
    let checkpoint_table_exists: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ledger_checkpoints'
            )",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("check checkpoint table")
        != 0;
    assert!(!checkpoint_table_exists);

    let _ = fs::remove_file(root_anchor_path(&db_path));
    let _ = fs::remove_file(db_path);
}

#[test]
fn migration_apply_backfills_checkpoints_and_verifies() {
    let db_path = create_legacy_db("apply", 8);
    let mut progress = Vec::new();

    let outcome = execute_migration(
        &db_path,
        &MigrationOptions {
            apply: true,
            direction: MigrationDirection::Apply,
            verify: true,
        },
        |event| progress.push(event),
    )
    .expect("migration should succeed");

    assert!(!outcome.dry_run);
    assert_eq!(outcome.after.mode, "immutable");
    assert_eq!(outcome.after.checkpoint_rows, 8);
    assert!(
        outcome
            .verification
            .as_ref()
            .expect("verification summary")
            .verified
    );
    assert!(progress.iter().any(|event| event.phase == "backfill"));

    let storage = SqliteStorage::open(&db_path).expect("open migrated db");
    let violations = verify_chain(storage.connection(), None, None).expect("verify migrated db");
    assert!(violations.is_empty());

    let _ = fs::remove_file(db_path);
}

#[test]
fn migration_rollback_restores_legacy_mode() {
    let db_path = create_legacy_db("rollback", 4);
    execute_migration(
        &db_path,
        &MigrationOptions {
            apply: true,
            direction: MigrationDirection::Apply,
            verify: true,
        },
        |_| {},
    )
    .expect("forward migration should succeed");

    let outcome = execute_migration(
        &db_path,
        &MigrationOptions {
            apply: true,
            direction: MigrationDirection::Rollback,
            verify: true,
        },
        |_| {},
    )
    .expect("rollback should succeed");

    assert_eq!(outcome.after.mode, "legacy");
    assert_eq!(outcome.after.checkpoint_rows, 0);
    assert!(outcome.after.root_anchor_present);

    let conn = Connection::open(&db_path).expect("open db");
    let checkpoint_table_exists: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ledger_checkpoints'
            )",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("check checkpoint table")
        != 0;
    assert!(!checkpoint_table_exists);

    let storage = SqliteStorage::open(&db_path).expect("open rolled back db");
    let violations = verify_chain(storage.connection(), None, None).expect("verify rolled back db");
    assert!(violations.is_empty());

    let _ = fs::remove_file(root_anchor_path(&db_path));
    let _ = fs::remove_file(db_path);
}
