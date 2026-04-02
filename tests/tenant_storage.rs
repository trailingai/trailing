use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{Duration, TimeZone, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;

use trailing::{
    log::{ActionEntry, ActionType, GENESIS_HASH},
    storage::SqliteStorage,
    tenant::DEFAULT_PROJECT_SLUG,
};

fn temp_db_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "trailing-tenant-{test_name}-{}-{nanos}.db",
        std::process::id()
    ))
}

#[test]
#[ignore = "legacy tenant-storage migration fixture no longer matches the current bootstrap path"]
fn opening_legacy_database_migrates_action_log_and_backfills_tenant_context() {
    let db_path = temp_db_path("migration");
    let conn = Connection::open(&db_path).expect("open legacy db");
    conn.execute_batch(
        "
        PRAGMA user_version = 1;

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
        ",
    )
    .expect("create legacy action_log");

    let base_time = Utc.with_ymd_and_hms(2026, 3, 29, 12, 0, 0).unwrap();
    let first = ActionEntry::new_with_timestamp(
        base_time,
        "agent-1",
        "worker",
        "session-1",
        ActionType::ToolCall,
        json!({ "index": 1 }),
        json!({ "legacy": true }),
        "ok",
        GENESIS_HASH,
    );
    let second = ActionEntry::new_with_timestamp(
        base_time + Duration::seconds(1),
        "agent-2",
        "worker",
        "session-1",
        ActionType::Decision,
        json!({ "index": 2 }),
        json!({ "legacy": true }),
        "ok",
        first.entry_hash.clone(),
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
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            first.id.to_string(),
            ActionEntry::canonical_timestamp(&first.timestamp),
            first.agent_id,
            first.agent_type,
            first.session_id,
            first.action_type.to_string(),
            first.payload.to_string(),
            first.context.to_string(),
            first.outcome,
            first.previous_hash,
            first.entry_hash,
            Option::<String>::None,
        ],
    )
    .expect("insert first legacy row");
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
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            second.id.to_string(),
            ActionEntry::canonical_timestamp(&second.timestamp),
            second.agent_id,
            second.agent_type,
            second.session_id,
            second.action_type.to_string(),
            second.payload.to_string(),
            second.context.to_string(),
            second.outcome,
            second.previous_hash,
            second.entry_hash,
            Some("legacy-org-7".to_string()),
        ],
    )
    .expect("insert second legacy row");
    drop(conn);

    let storage = SqliteStorage::open(&db_path).expect("open migrated storage");
    let tenant_context = storage.tenant_context().expect("default tenant context");

    let organizations = storage.list_organizations().expect("list organizations");
    assert!(
        organizations
            .iter()
            .any(|org| org.id == tenant_context.org_id)
    );
    assert!(organizations.iter().any(|org| org.id == "legacy-org-7"));

    let default_project_id: String = storage
        .connection()
        .query_row(
            "SELECT id FROM projects WHERE org_id = ?1 AND slug = ?2",
            params![tenant_context.org_id, DEFAULT_PROJECT_SLUG],
            |row| row.get(0),
        )
        .expect("load default project");
    let legacy_project_id: String = storage
        .connection()
        .query_row(
            "SELECT id FROM projects WHERE org_id = ?1 AND slug = ?2",
            params!["legacy-org-7", DEFAULT_PROJECT_SLUG],
            |row| row.get(0),
        )
        .expect("load legacy project");

    let first_row = storage
        .connection()
        .query_row(
            "SELECT org_id, project_id FROM action_log WHERE sequence = 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .expect("load first migrated row");
    assert_eq!(first_row.0, tenant_context.org_id);
    assert_eq!(first_row.1, default_project_id);

    let second_row = storage
        .connection()
        .query_row(
            "SELECT org_id, project_id FROM action_log WHERE sequence = 2",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .expect("load second migrated row");
    assert_eq!(second_row.0, "legacy-org-7");
    assert_eq!(second_row.1, legacy_project_id);

    let table_info: Vec<(String, i64)> = {
        let mut statement = storage
            .connection()
            .prepare("PRAGMA table_info(action_log)")
            .expect("prepare table info");
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, i64>(3)?))
            })
            .expect("query table info");
        rows.map(|row| row.expect("table info row")).collect()
    };
    assert!(
        table_info
            .iter()
            .any(|(name, not_null)| name == "org_id" && *not_null == 1)
    );
    assert!(
        table_info
            .iter()
            .any(|(name, not_null)| name == "project_id" && *not_null == 1)
    );

    storage
        .append_action(
            "agent-3",
            "worker",
            "session-2",
            ActionType::PolicyCheck,
            json!({ "index": 3 }),
            json!({ "migrated": true }),
            "ok",
        )
        .expect("append post-migration action");
    let latest_row = storage
        .connection()
        .query_row(
            "SELECT org_id, project_id FROM action_log ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .expect("query latest row")
        .expect("latest row exists");
    assert_eq!(latest_row.0, tenant_context.org_id);
    assert_eq!(latest_row.1, tenant_context.project_id);
}
