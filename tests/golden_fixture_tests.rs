use chrono::{TimeZone, Utc};
use serde_json::json;
use uuid::Uuid;

use trailing::ingest::apply_cli_defaults;
use trailing::log::{ActionEntry, ActionType, GENESIS_HASH};

#[test]
fn hash_chain_fixture_matches_known_hashes() {
    let first_timestamp = Utc.with_ymd_and_hms(2026, 3, 29, 12, 0, 0).unwrap();
    let first_hash = ActionEntry::calculate_hash_parts(
        &Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        GENESIS_HASH,
        &first_timestamp,
        "planner",
        "codex",
        "session-1",
        ActionType::ToolCall,
        &json!({ "tool": "search" }),
        &json!({ "trace": "trace-1" }),
        "ok",
    );

    assert_eq!(
        first_hash,
        "sha256:ba13e405bce598b4bac69ec986d689ddca0e1da5a0a18ad9425b05fbc59c98e6"
    );

    let second_timestamp = Utc.with_ymd_and_hms(2026, 3, 29, 12, 0, 30).unwrap();
    let second_hash = ActionEntry::calculate_hash_parts(
        &Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
        &first_hash,
        &second_timestamp,
        "reviewer",
        "human",
        "session-1",
        ActionType::Decision,
        &json!({ "decision": "approve" }),
        &json!({ "policy": "eu-ai-act" }),
        "needs_review",
    );

    assert_eq!(
        second_hash,
        "sha256:3b2c8217e6c97ec5300a15b0a128c9ff67357ff51cbec759bb7ec4f45b040842"
    );
}

#[test]
fn cli_defaults_fixture_matches_expected_output() {
    let payload = json!({
        "action": {
            "type": "tool.exec",
            "tool_name": "shell"
        }
    });

    let normalized = apply_cli_defaults(payload, "codex", "session-golden");

    assert_eq!(
        normalized,
        json!({
            "action": {
                "type": "tool.exec",
                "tool_name": "shell"
            },
            "agent_id": "codex-stdin",
            "agent_type": "codex",
            "session_id": "session-golden"
        })
    );
}
