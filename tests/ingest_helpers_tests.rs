use serde_json::json;
use trailing::{
    collector::{OtelSpan, SdkAction, SdkContext, SdkEvent, TraceCollector},
    ingest::{
        helpers::{instrument_policy, instrument_retrieval, retrieval_attributes},
        ingest_json_action,
    },
    log::ActionType,
    storage::{SqliteStorage, Storage},
};

#[test]
fn raw_ingest_prefers_policy_helper_over_action_name_heuristics() {
    let storage = Storage::open_in_memory().expect("in-memory storage");
    let payload = instrument_policy(
        json!({
            "type": "tool.exec",
            "target": "https://example.com/policies/baseline"
        }),
        ["baseline-v1"],
    );

    ingest_json_action(&storage, payload, "test", None).expect("ingest helper payload");

    let entries = storage.entries().expect("load entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action_type, ActionType::PolicyCheck);
}

#[test]
fn sdk_collector_prefers_retrieval_helper_over_action_name_heuristics() {
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    let mut collector = TraceCollector::new(storage);

    let event = SdkEvent {
        agent_id: "agent-1".to_string(),
        agent_type: "Codex".to_string(),
        session_id: "session-1".to_string(),
        action: SdkAction {
            action_type: "policy.review".to_string(),
            tool_name: None,
            target: None,
            parameters: instrument_retrieval(
                json!({ "path": "s3://evidence/session-1.json" }),
                "s3://evidence/session-1.json",
            ),
            result: None,
        },
        context: SdkContext::default(),
    };

    collector
        .ingest_sdk_event(event)
        .expect("collector should ingest canonical sdk payload");

    let entries = collector.storage().entries().expect("load entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action_type, ActionType::DataAccess);
}

#[test]
fn otlp_collector_prefers_attribute_helpers_over_action_name_heuristics() {
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    let mut collector = TraceCollector::new(storage);
    let mut attributes = retrieval_attributes("file:///tmp/audit-log.json");
    attributes.insert("agent.id".to_string(), json!("agent-2"));
    attributes.insert("agent.type".to_string(), json!("Claude Code"));
    attributes.insert("session.id".to_string(), json!("session-2"));

    let span = OtelSpan {
        trace_id: "trace-2".to_string(),
        span_id: "span-2".to_string(),
        name: "policy.review".to_string(),
        attributes,
        start_time: Some("1".to_string()),
        end_time: Some("2".to_string()),
        parent_span_id: None,
        status: Some("ok".to_string()),
    };

    collector
        .ingest_otel_span(span)
        .expect("collector should ingest canonical otlp span");

    let entries = collector.storage().entries().expect("load entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action_type, ActionType::DataAccess);
}
