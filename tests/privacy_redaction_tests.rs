use serde_json::json;

use trailing::ingest::{REDACTED_VALUE, ingest_json_action, redact_json_fields};
use trailing::storage::Storage;

#[test]
fn redact_json_fields_recursively_replaces_sensitive_keys() {
    let payload = json!({
        "session_id": "session-privacy",
        "agent_id": "agent-1",
        "credentials": {
            "api_key": "secret-key",
            "nested": {
                "SSN": "123-45-6789"
            }
        },
        "contacts": [
            {
                "email": "agent@example.com"
            }
        ],
        "safe_field": "keep-me"
    });

    let redacted = redact_json_fields(payload, &["api_key", "ssn", "email"]);

    assert_eq!(redacted["credentials"]["api_key"], REDACTED_VALUE);
    assert_eq!(redacted["credentials"]["nested"]["SSN"], REDACTED_VALUE);
    assert_eq!(redacted["contacts"][0]["email"], REDACTED_VALUE);
    assert_eq!(redacted["safe_field"], "keep-me");
}

#[test]
fn redacted_payload_is_what_gets_stored() {
    let storage = Storage::open_in_memory().expect("in-memory storage");
    let payload = redact_json_fields(
        json!({
            "timestamp": "2026-03-29T12:00:00Z",
            "session_id": "session-privacy",
            "agent_id": "agent-1",
            "agent_type": "codex",
            "type": "tool_call",
            "payload": {
                "token": "super-secret-token",
                "patient": {
                    "email": "patient@example.com"
                }
            }
        }),
        &["token", "email"],
    );

    ingest_json_action(&storage, payload, "sdk", Some("privacy:redacted"))
        .expect("redacted payload should ingest");

    let entries = storage.entries().expect("load stored entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].payload["payload"]["token"], REDACTED_VALUE);
    assert_eq!(
        entries[0].payload["payload"]["patient"]["email"],
        REDACTED_VALUE
    );
}
