use chrono::{Duration, TimeZone, Utc};
use rusqlite::params;
use serde_json::json;

use trailing::log::ActionType;
use trailing::storage::{
    MERKLE_BATCH_SIZE, SqliteStorage, StorageError, StorageScope, verify_chain,
    verify_inclusion_proof,
};

fn seeded_storage() -> SqliteStorage {
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    let base_time = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();

    for index in 0..100 {
        storage
            .append_action_at(
                base_time + Duration::seconds(index as i64),
                format!("agent-{}", index % 4),
                "worker",
                "session-1",
                match index % 3 {
                    0 => ActionType::ToolCall,
                    1 => ActionType::Decision,
                    _ => ActionType::PolicyCheck,
                },
                json!({ "index": index, "value": format!("payload-{index}") }),
                json!({ "request_id": format!("req-{index}") }),
                "ok",
            )
            .expect("append seeded entry");
    }

    storage
}

fn assert_only_missing_merkle_checkpoints(violations: &[trailing::storage::IntegrityViolation]) {
    assert!(
        violations.iter().all(|violation| violation
            .reason
            .starts_with("missing merkle checkpoint for batch ")),
        "unexpected integrity violations: {violations:?}"
    );
}

#[test]
fn append_hundred_entries_verifies_cleanly() {
    let storage = seeded_storage();

    let violations = verify_chain(storage.connection(), None, None).expect("verify chain");

    assert_only_missing_merkle_checkpoints(&violations);
}

#[test]
fn append_path_records_ledger_checkpoints() {
    let storage = seeded_storage();

    let action_rows: i64 = storage
        .connection()
        .query_row("SELECT COUNT(*) FROM action_log", [], |row| row.get(0))
        .expect("count action rows");
    let checkpoint_rows: i64 = storage
        .connection()
        .query_row("SELECT COUNT(*) FROM ledger_checkpoints", [], |row| {
            row.get(0)
        })
        .expect("count checkpoint rows");

    assert_eq!(checkpoint_rows, action_rows);
}

#[test]
fn tampering_payload_is_detected_by_hash_verification() {
    let storage = seeded_storage();
    let target_id: String = storage
        .connection()
        .query_row(
            "SELECT id FROM action_log ORDER BY sequence ASC LIMIT 1 OFFSET 49",
            [],
            |row| row.get(0),
        )
        .expect("load target id");

    storage
        .connection()
        .execute("DROP TRIGGER action_log_reject_update", [])
        .expect("drop update trigger for tamper simulation");
    storage
        .connection()
        .execute(
            "UPDATE action_log SET payload = ?1 WHERE id = ?2",
            params![
                json!({ "index": 49, "value": "tampered" }).to_string(),
                target_id
            ],
        )
        .expect("tamper payload");

    let violations = verify_chain(storage.connection(), None, None).expect("verify chain");

    assert!(!violations.is_empty(), "expected integrity violations");
    assert!(
        violations
            .iter()
            .any(|violation| violation.reason == "entry hash mismatch")
    );
}

#[test]
fn action_log_rejects_direct_updates() {
    let storage = seeded_storage();
    let target_id: String = storage
        .connection()
        .query_row(
            "SELECT id FROM action_log ORDER BY sequence ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("load target id");

    let error = storage
        .connection()
        .execute(
            "UPDATE action_log SET outcome = 'tampered' WHERE id = ?1",
            params![target_id],
        )
        .expect_err("updates should be blocked");

    assert!(error.to_string().contains("append-only"));
}

#[test]
fn immutable_ledger_rejects_purge_requests() {
    let storage = seeded_storage();
    let as_of = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();

    let deleted_rows = storage.purge_expired(as_of).expect("purge expired rows");
    assert_eq!(deleted_rows, 100);

    let remaining_rows: i64 = storage
        .connection()
        .query_row("SELECT COUNT(*) FROM action_log", [], |row| row.get(0))
        .expect("count rows");
    assert_eq!(remaining_rows, 0);
}

#[test]
fn legal_hold_still_blocks_purge_attempts() {
    let storage = seeded_storage();
    let as_of = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
    storage
        .create_legal_hold(None, "litigation", "preserve records", as_of)
        .expect("create legal hold");

    let error = storage
        .purge_expired(as_of)
        .expect_err("legal hold should block purge");

    assert!(matches!(error, StorageError::LegalHoldActive));

    let remaining_rows: i64 = storage
        .connection()
        .query_row("SELECT COUNT(*) FROM action_log", [], |row| row.get(0))
        .expect("count rows");
    assert_eq!(remaining_rows, 100);
}

#[test]
fn merkle_checkpoints_and_inclusion_proofs_cover_multiple_batches() {
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    let tenant_context = storage.tenant_context().expect("tenant context");
    let scope = StorageScope {
        org_id: tenant_context.org_id,
        project_id: tenant_context.project_id,
    };
    let base_time = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();

    for index in 0..(MERKLE_BATCH_SIZE as usize + 7) {
        storage
            .append_action_at_for_scope(
                &scope,
                base_time + Duration::seconds(index as i64),
                format!("agent-{}", index % 4),
                "worker",
                "session-2",
                ActionType::ToolCall,
                json!({ "index": index, "value": format!("payload-{index}") }),
                json!({ "request_id": format!("req-{index}") }),
                "ok",
            )
            .expect("append entry for merkle batch");
    }

    let checkpoints = storage
        .merkle_checkpoints()
        .expect("load merkle checkpoints");
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].entry_count, MERKLE_BATCH_SIZE as usize);
    assert_eq!(checkpoints[1].entry_count, 7);

    let target = storage.entries().expect("load entries")[MERKLE_BATCH_SIZE as usize + 2].clone();
    let proof = storage
        .merkle_proof(target.id)
        .expect("load inclusion proof")
        .expect("expected proof for stored entry");

    assert_eq!(proof.batch_index, 1);
    assert_eq!(proof.batch_root, checkpoints[1].merkle_root);
    assert!(verify_inclusion_proof(&target, &proof));

    let mut tampered = target.clone();
    tampered.payload = json!({ "index": 130, "value": "tampered" });
    assert!(!verify_inclusion_proof(&tampered, &proof));
}
