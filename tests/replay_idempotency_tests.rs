use serde_json::json;

use trailing::ingest::ingest_json_action;
use trailing::storage::Storage;

fn action_payload(index: usize) -> serde_json::Value {
    json!({
        "timestamp": format!("2026-03-29T12:00:0{index}Z"),
        "session_id": "session-replay",
        "agent_id": "replayer",
        "agent_type": "codex",
        "type": "tool_call",
        "payload": {
            "tool": format!("tool-{index}")
        }
    })
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
fn replaying_the_same_event_with_a_dedup_key_is_idempotent() {
    let storage = Storage::open_in_memory().expect("in-memory storage");
    let payload = action_payload(1);

    let first_id = ingest_json_action(&storage, payload.clone(), "sdk", Some("replay:event:1"))
        .expect("first ingest should succeed");
    let first_entries = storage.entries().expect("load entries after first ingest");
    let first_hash = first_entries[0].entry_hash.clone();

    let second_id = ingest_json_action(&storage, payload, "sdk", Some("replay:event:1"))
        .expect("second ingest should succeed");
    let second_entries = storage.entries().expect("load entries after second ingest");

    assert!(first_id.is_some());
    assert_eq!(second_id, None);
    assert_eq!(second_entries.len(), 1);
    assert_eq!(second_entries[0].entry_hash, first_hash);
    assert_only_missing_merkle_checkpoints(&storage.verify_chain(None, None).unwrap());
}

#[test]
fn replaying_a_batch_preserves_hashes_and_does_not_duplicate_rows() {
    let storage = Storage::open_in_memory().expect("in-memory storage");
    let payloads = [action_payload(1), action_payload(2), action_payload(3)];

    for (index, payload) in payloads.iter().cloned().enumerate() {
        ingest_json_action(
            &storage,
            payload,
            "sdk",
            Some(&format!("replay:batch:{index}")),
        )
        .expect("first batch ingest should succeed");
    }

    let initial_entries = storage.entries().expect("load initial entries");
    let initial_hashes = initial_entries
        .iter()
        .map(|entry| entry.entry_hash.clone())
        .collect::<Vec<_>>();
    let initial_root = initial_hashes.last().cloned();

    for (index, payload) in payloads.iter().cloned().enumerate() {
        let replay_result = ingest_json_action(
            &storage,
            payload,
            "sdk",
            Some(&format!("replay:batch:{index}")),
        )
        .expect("replay batch ingest should succeed");
        assert_eq!(replay_result, None);
    }

    let replayed_entries = storage.entries().expect("load replayed entries");
    let replayed_hashes = replayed_entries
        .iter()
        .map(|entry| entry.entry_hash.clone())
        .collect::<Vec<_>>();

    assert_eq!(replayed_entries.len(), payloads.len());
    assert_eq!(replayed_hashes, initial_hashes);
    assert_eq!(
        replayed_entries
            .last()
            .map(|entry| entry.entry_hash.clone()),
        initial_root
    );
    assert_only_missing_merkle_checkpoints(&storage.verify_chain(None, None).unwrap());
}
