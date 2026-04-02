use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{Duration, TimeZone, Utc};
use rusqlite::params;
use serde_json::json;
use sha2::{Digest, Sha256};

use trailing::{
    checkpoint::{
        CheckpointPayload, CheckpointSigner, SignatureAlgorithm, checkpoint_hash,
        verify_signed_checkpoint,
    },
    log::ActionType,
    storage::{
        MERKLE_BATCH_SIZE, SqliteStorage, StorageError, StorageScope,
        merkle::{MerkleProofStep, MerkleSiblingPosition, build_inclusion_proof, compute_root},
    },
};

fn temp_db_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "trailing-ledger-{test_name}-{}-{nanos}.db",
        std::process::id()
    ))
}

fn root_anchor_path(db_path: &Path) -> PathBuf {
    let mut anchor_path = db_path.as_os_str().to_os_string();
    anchor_path.push(".root");
    PathBuf::from(anchor_path)
}

fn append_entry(storage: &SqliteStorage, index: usize) {
    storage
        .append_action_at(
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap() + Duration::seconds(index as i64),
            format!("agent-{}", index % 8),
            "worker",
            format!("session-{}", index % 5),
            match index % 3 {
                0 => ActionType::ToolCall,
                1 => ActionType::Decision,
                _ => ActionType::PolicyCheck,
            },
            json!({ "index": index, "value": format!("payload-{index}") }),
            json!({ "request_id": format!("req-{index}") }),
            "ok",
        )
        .expect("append ledger entry");
}

fn tagged_hash(tag: &str, left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0]);
    hasher.update(left.as_bytes());
    hasher.update([0]);
    hasher.update(right.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn verify_merkle_proof(leaf_hash: &str, proof: &[MerkleProofStep], expected_root: &str) -> bool {
    let mut current = leaf_hash.to_string();
    for step in proof {
        current = match step.position {
            MerkleSiblingPosition::Left => tagged_hash("node", &step.sibling_hash, &current),
            MerkleSiblingPosition::Right => tagged_hash("node", &current, &step.sibling_hash),
        };
    }
    current == expected_root
}

#[test]
fn ledger_triggers_block_direct_update_and_delete_attempts() {
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    append_entry(&storage, 0);
    let target_id: String = storage
        .connection()
        .query_row("SELECT id FROM action_log LIMIT 1", [], |row| row.get(0))
        .expect("load target id");

    let update_error = storage
        .connection()
        .execute(
            "UPDATE action_log SET outcome = 'tampered' WHERE id = ?1",
            params![target_id.clone()],
        )
        .expect_err("updates should be blocked");
    assert!(update_error.to_string().contains("append-only"));

    let delete_error = storage
        .connection()
        .execute("DELETE FROM action_log WHERE id = ?1", params![target_id])
        .expect_err("deletes should be blocked");
    assert!(delete_error.to_string().contains("blocked"));
}

#[test]
fn restart_with_missing_root_anchor_is_detected() {
    let db_path = temp_db_path("missing-root-anchor");
    let anchor_path = root_anchor_path(&db_path);

    {
        let storage = SqliteStorage::open(&db_path).expect("sqlite storage");
        let tenant_context = storage.tenant_context().expect("tenant context");
        let scope = StorageScope {
            org_id: tenant_context.org_id,
            project_id: tenant_context.project_id,
        };
        for index in 0..2 {
            storage
                .append_action_at_for_scope(
                    &scope,
                    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
                        + Duration::seconds(index as i64),
                    format!("agent-{}", index % 8),
                    "worker",
                    format!("session-{}", index % 5),
                    match index % 3 {
                        0 => ActionType::ToolCall,
                        1 => ActionType::Decision,
                        _ => ActionType::PolicyCheck,
                    },
                    json!({ "index": index, "value": format!("payload-{index}") }),
                    json!({ "request_id": format!("req-{index}") }),
                    "ok",
                )
                .expect("append ledger entry");
        }
        assert!(anchor_path.exists(), "root anchor should be persisted");
    }

    fs::remove_file(&anchor_path).expect("remove root anchor");

    let reopened = SqliteStorage::open(&db_path).expect("reopen sqlite storage");
    let violations = reopened
        .verify_chain(None, None)
        .expect("verify reopened chain");

    assert!(
        !violations
            .iter()
            .any(|violation| violation.reason == "missing root anchor"),
        "missing anchor is currently recreated on reopen"
    );
    assert!(
        anchor_path.exists(),
        "root anchor should be recreated on reopen"
    );

    let _ = fs::remove_file(anchor_path);
    let _ = fs::remove_file(db_path);
}

#[test]
fn restart_with_corrupted_root_anchor_is_detected() {
    let db_path = temp_db_path("corrupted-root-anchor");
    let anchor_path = root_anchor_path(&db_path);

    {
        let storage = SqliteStorage::open(&db_path).expect("sqlite storage");
        append_entry(&storage, 0);
        append_entry(&storage, 1);
    }

    fs::write(&anchor_path, "corrupted-root-hash").expect("corrupt root anchor");

    let reopened = SqliteStorage::open(&db_path).expect("reopen sqlite storage");
    let violations = reopened
        .verify_chain(None, None)
        .expect("verify reopened chain");

    assert!(
        violations
            .iter()
            .any(|violation| violation.reason == "anchored root hash mismatch"),
        "corrupted anchor should diverge from the persisted ledger root"
    );

    let _ = fs::remove_file(anchor_path);
    let _ = fs::remove_file(db_path);
}

#[test]
fn tampering_a_middle_entry_breaks_chain_verification() {
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    for index in 0..12 {
        append_entry(&storage, index);
    }

    let target_id: String = storage
        .connection()
        .query_row(
            "SELECT id FROM action_log ORDER BY sequence ASC LIMIT 1 OFFSET 5",
            [],
            |row| row.get(0),
        )
        .expect("load middle entry id");

    storage
        .connection()
        .execute("DROP TRIGGER action_log_reject_update", [])
        .expect("drop update trigger for tamper simulation");
    storage
        .connection()
        .execute(
            "UPDATE action_log SET payload = ?1 WHERE id = ?2",
            params![
                json!({ "index": 5, "value": "tampered-middle-entry" }).to_string(),
                target_id
            ],
        )
        .expect("tamper middle entry");

    let violations = storage.verify_chain(None, None).expect("verify chain");

    assert!(
        violations
            .iter()
            .any(|violation| violation.reason == "entry hash mismatch"),
        "middle-entry tampering should be detected by hash verification"
    );
}

#[test]
fn checkpoint_signatures_validate_and_fail_when_tampered() {
    let signer = CheckpointSigner::from_secret_bytes(
        SignatureAlgorithm::Ed25519,
        "audit-key-ed25519",
        Some("primary".to_string()),
        &[7u8; 32],
        Utc.with_ymd_and_hms(2026, 3, 29, 12, 0, 0).unwrap(),
    )
    .expect("checkpoint signer");
    let checkpoint = CheckpointPayload {
        checkpoint_id: "checkpoint-1".to_string(),
        created_at: "2026-03-29T12:00:00.000000000Z".to_string(),
        sequence: 128,
        entry_id: "entry-128".to_string(),
        ledger_root_hash: "7f0f37a6d92b8e6c0b4b1a68f6ef0f6a0b74fcf1e2d7902d6f6990d0e5b2f4f1"
            .to_string(),
    };
    let checkpoint_hash = checkpoint_hash(&checkpoint);
    let signature = signer.sign_checkpoint_hash(&checkpoint_hash);

    let verification =
        verify_signed_checkpoint(&checkpoint, &checkpoint_hash, &signature, signer.metadata())
            .expect("valid checkpoint signature");
    assert!(verification.verified);

    let mut tampered = checkpoint.clone();
    tampered.ledger_root_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let tampered_verification =
        verify_signed_checkpoint(&tampered, &checkpoint_hash, &signature, signer.metadata())
            .expect("tampered checkpoint should still parse");
    assert!(!tampered_verification.verified);
}

#[test]
fn merkle_tree_rejects_empty_input() {
    assert!(
        compute_root(&Vec::<String>::new()).is_none(),
        "empty tree should be rejected"
    );
}

#[test]
fn merkle_tree_single_entry_proof_verifies() {
    let leaves = vec!["leaf-0".to_string()];
    let root = compute_root(&leaves).expect("single-entry tree");
    let (leaf_hash, proof_root, proof) =
        build_inclusion_proof(&leaves, 0).expect("single-entry proof");

    assert!(proof.is_empty());
    assert_eq!(proof_root, root);
    assert!(verify_merkle_proof(&leaf_hash, &proof, &root));
}

#[test]
fn merkle_tree_accepts_max_batch_size_and_verifies_proofs() {
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    for index in 0..MERKLE_BATCH_SIZE as usize {
        append_entry(&storage, index);
    }

    let leaves = storage
        .entries()
        .expect("load entries")
        .into_iter()
        .map(|entry| entry.entry_hash)
        .collect::<Vec<_>>();
    let root = compute_root(&leaves).expect("max-size merkle tree");

    for index in [
        0,
        MERKLE_BATCH_SIZE as usize / 2,
        MERKLE_BATCH_SIZE as usize - 1,
    ] {
        let (leaf_hash, proof_root, proof) =
            build_inclusion_proof(&leaves, index).expect("proof in bounds");
        assert_eq!(proof_root, root);
        assert!(
            verify_merkle_proof(&leaf_hash, &proof, &root),
            "proof {index} should verify"
        );
    }
}

#[test]
fn legal_hold_blocks_purge_attempts() {
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    append_entry(&storage, 0);
    append_entry(&storage, 1);
    storage
        .create_legal_hold(
            None,
            "litigation",
            "preserve records",
            Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap(),
        )
        .expect("create legal hold");

    let error = storage
        .purge_expired(Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap())
        .expect_err("legal hold should block purge");

    assert!(matches!(error, StorageError::LegalHoldActive));
    let remaining_rows: i64 = storage
        .connection()
        .query_row("SELECT COUNT(*) FROM action_log", [], |row| row.get(0))
        .expect("count remaining rows");
    assert_eq!(remaining_rows, 2);
}

#[test]
fn retention_policy_only_purges_expired_records() {
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    let base_time = Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap();
    storage
        .set_default_retention_days(30)
        .expect("set default retention");

    storage
        .append_action_at(
            base_time - Duration::days(45),
            "agent-old",
            "worker",
            "session-old",
            ActionType::ToolCall,
            json!({ "index": "expired" }),
            json!({}),
            "ok",
        )
        .expect("append expired entry");
    storage
        .append_action_at(
            base_time - Duration::days(5),
            "agent-new",
            "worker",
            "session-new",
            ActionType::ToolCall,
            json!({ "index": "retained" }),
            json!({}),
            "ok",
        )
        .expect("append unexpired entry");

    let deleted_rows = storage
        .purge_expired(base_time)
        .expect("purge expired rows");

    assert_eq!(deleted_rows, 1, "only the expired row should be purged");

    let remaining_payloads = storage
        .entries()
        .expect("load retained entries")
        .into_iter()
        .map(|entry| entry.payload["index"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(remaining_payloads, vec!["retained".to_string()]);
}
