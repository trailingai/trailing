use chrono::{Duration, TimeZone, Utc};
use rusqlite::params;
use serde_json::json;

use trailing::{
    checkpoint::{CheckpointSigner, SignatureAlgorithm},
    log::ActionType,
    storage::{ExternalAnchorInput, SqliteStorage},
};

fn seeded_storage() -> SqliteStorage {
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    let base_time = Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap();

    for index in 0..3 {
        storage
            .append_action_at(
                base_time + Duration::seconds(index as i64),
                format!("agent-{index}"),
                "worker",
                "session-1",
                ActionType::ToolCall,
                json!({ "index": index }),
                json!({ "request_id": format!("req-{index}") }),
                "ok",
            )
            .expect("append seeded entry");
    }

    storage
}

#[test]
fn ed25519_checkpoints_store_key_metadata_and_anchor_records() {
    let storage = seeded_storage();
    let signer = CheckpointSigner::from_secret_bytes(
        SignatureAlgorithm::Ed25519,
        "audit-key-ed25519",
        Some("primary".to_string()),
        &[5u8; 32],
        Utc.with_ymd_and_hms(2026, 3, 30, 11, 0, 0).unwrap(),
    )
    .expect("create signer");

    let checkpoint = storage
        .create_signed_checkpoint(
            &signer,
            &[ExternalAnchorInput {
                provider: "rfc3161".to_string(),
                reference: "tsa://receipt-123".to_string(),
                anchored_at: Some("2026-03-30T12:00:05Z".to_string()),
                metadata: json!({ "receipt": "abc123" }),
            }],
        )
        .expect("create signed checkpoint");

    assert_eq!(checkpoint.key.key_id, "audit-key-ed25519");
    assert_eq!(checkpoint.key.algorithm, SignatureAlgorithm::Ed25519);
    assert_eq!(checkpoint.anchors.len(), 1);

    let verification = storage
        .verify_signed_checkpoint(&checkpoint.checkpoint_id)
        .expect("verify checkpoint")
        .expect("checkpoint exists");

    assert!(verification.verification.signature_valid);
    assert!(verification.anchor_hashes_valid);
    assert!(verification.verified);
}

#[test]
fn ecdsa_checkpoints_verify_successfully() {
    let storage = seeded_storage();
    let signer = CheckpointSigner::from_secret_bytes(
        SignatureAlgorithm::EcdsaP256Sha256,
        "audit-key-ecdsa",
        Some("backup".to_string()),
        &[9u8; 32],
        Utc.with_ymd_and_hms(2026, 3, 30, 11, 30, 0).unwrap(),
    )
    .expect("create signer");

    let checkpoint = storage
        .create_signed_checkpoint(&signer, &[])
        .expect("create signed checkpoint");

    let verification = storage
        .verify_signed_checkpoint(&checkpoint.checkpoint_id)
        .expect("verify checkpoint")
        .expect("checkpoint exists");

    assert!(verification.verification.signature_valid);
    assert!(verification.verified);
}

#[test]
fn tampered_checkpoint_records_fail_verification() {
    let storage = seeded_storage();
    let signer = CheckpointSigner::from_secret_bytes(
        SignatureAlgorithm::Ed25519,
        "audit-key-ed25519",
        None,
        &[7u8; 32],
        Utc.with_ymd_and_hms(2026, 3, 30, 11, 45, 0).unwrap(),
    )
    .expect("create signer");

    let checkpoint = storage
        .create_signed_checkpoint(
            &signer,
            &[ExternalAnchorInput {
                provider: "notary".to_string(),
                reference: "record-42".to_string(),
                anchored_at: None,
                metadata: json!({ "status": "published" }),
            }],
        )
        .expect("create signed checkpoint");

    storage
        .connection()
        .execute(
            "UPDATE checkpoints SET checkpoint_hash = ?1 WHERE checkpoint_id = ?2",
            params!["tampered", checkpoint.checkpoint_id],
        )
        .expect("tamper checkpoint hash");
    storage
        .connection()
        .execute(
            "UPDATE checkpoint_anchors SET anchored_hash = ?1 WHERE checkpoint_id = ?2",
            params!["tampered-anchor", checkpoint.checkpoint_id],
        )
        .expect("tamper anchor hash");

    let verification = storage
        .verify_signed_checkpoint(&checkpoint.checkpoint_id)
        .expect("verify checkpoint")
        .expect("checkpoint exists");

    assert!(!verification.verification.checkpoint_hash_valid);
    assert!(!verification.verification.signature_valid);
    assert!(!verification.anchor_hashes_valid);
    assert!(!verification.verified);
}
