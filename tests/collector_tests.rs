use serde_json::json;
use trailing::collector::{
    AgentType, InMemoryStorage, OtelSpan, SdkAction, SdkContext, SdkEvent, TraceCollector,
    parse_otlp_http_json,
};

#[test]
fn parses_otlp_http_json_spans() {
    let payload = json!({
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "trace-1",
                                "spanId": "span-1",
                                "parentSpanId": "parent-1",
                                "name": "tool.call",
                                "startTimeUnixNano": "100",
                                "endTimeUnixNano": "200",
                                "attributes": [
                                    {
                                        "key": "agent.type",
                                        "value": { "stringValue": "Codex CLI" }
                                    },
                                    {
                                        "key": "tool.name",
                                        "value": { "stringValue": "shell" }
                                    },
                                    {
                                        "key": "permissions.used",
                                        "value": {
                                            "arrayValue": {
                                                "values": [
                                                    { "stringValue": "workspace-write" },
                                                    { "stringValue": "network-restricted" }
                                                ]
                                            }
                                        }
                                    }
                                ],
                                "status": {
                                    "code": "STATUS_CODE_OK"
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    })
    .to_string();

    let spans = parse_otlp_http_json(&payload).expect("payload should parse");

    assert_eq!(spans.len(), 1);
    let span = &spans[0];
    assert_eq!(span.trace_id, "trace-1");
    assert_eq!(span.parent_span_id.as_deref(), Some("parent-1"));
    assert_eq!(span.attributes["tool.name"], json!("shell"));
    assert_eq!(
        span.attributes["permissions.used"],
        json!(["workspace-write", "network-restricted"])
    );
    assert_eq!(span.status.as_deref(), Some("STATUS_CODE_OK"));
}

#[test]
fn normalizes_sdk_events_into_action_entries() {
    let storage = InMemoryStorage::default();
    let mut collector = TraceCollector::new(storage);

    let event = SdkEvent {
        agent_id: "agent-1".to_string(),
        agent_type: "Claude Code".to_string(),
        session_id: "session-42".to_string(),
        action: SdkAction {
            action_type: "file.read".to_string(),
            tool_name: Some("fs".to_string()),
            target: Some("/tmp/example.txt".to_string()),
            parameters: json!({ "path": "/tmp/example.txt" }),
            result: Some(json!({ "bytes": 128 })),
        },
        context: SdkContext {
            data_accessed: vec!["/tmp/example.txt".to_string()],
            permissions_used: vec!["workspace-write".to_string()],
            policy_refs: vec!["policy-1".to_string()],
        },
    };

    let entry = collector
        .ingest_sdk_event(event)
        .expect("sdk event should normalize");

    assert_eq!(entry.agent_type, AgentType::Claude);
    assert_eq!(entry.action_type, "file.read");
    assert_eq!(entry.tool_name.as_deref(), Some("fs"));
    assert_eq!(entry.payload["path"], json!("/tmp/example.txt"));
    assert_eq!(entry.context.permissions_used, vec!["workspace-write"]);
    assert_eq!(collector.storage().entries().len(), 1);
}

#[test]
fn ingests_otlp_json_into_storage() {
    let payload = json!({
        "spans": [
            {
                "traceId": "trace-9",
                "spanId": "span-9",
                "parentSpanId": "session-root",
                "name": "tool.exec",
                "attributes": {
                    "agent.id": "agent-9",
                    "agent.type": "OpenAI Codex",
                    "tool.name": "terminal",
                    "target": "cargo test",
                    "data.accessed": ["Cargo.toml"],
                    "policy.refs": ["storage-v1"]
                },
                "startTimeUnixNano": "10",
                "endTimeUnixNano": "20",
                "status": "ok"
            }
        ]
    })
    .to_string();

    let mut collector = TraceCollector::new(InMemoryStorage::default());
    let entries = collector
        .ingest_otel_json(&payload)
        .expect("otel payload should ingest");

    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.agent_id, "agent-9");
    assert_eq!(entry.agent_type, AgentType::Codex);
    assert_eq!(entry.session_id, "session-root");
    assert_eq!(entry.action_type, "tool.exec");
    assert_eq!(entry.target.as_deref(), Some("cargo test"));
    assert_eq!(entry.context.data_accessed, vec!["Cargo.toml"]);
    assert_eq!(entry.context.policy_refs, vec!["storage-v1"]);
    assert_eq!(collector.storage().entries(), entries.as_slice());
}

#[test]
fn allows_direct_otel_span_ingestion() {
    let mut collector = TraceCollector::new(InMemoryStorage::default());
    let mut attributes = serde_json::Map::new();
    attributes.insert("agent.type".to_string(), json!("cursor-agent"));
    attributes.insert("session.id".to_string(), json!("session-abc"));

    let span = OtelSpan {
        trace_id: "trace-abc".to_string(),
        span_id: "span-abc".to_string(),
        name: "delegate".to_string(),
        attributes,
        start_time: Some("1".to_string()),
        end_time: Some("2".to_string()),
        parent_span_id: Some("parent-abc".to_string()),
        status: Some("ok".to_string()),
    };

    let entry = collector
        .ingest_otel_span(span)
        .expect("single span should ingest");

    assert_eq!(entry.agent_type, AgentType::Cursor);
    assert_eq!(entry.session_id, "session-abc");
    assert_eq!(collector.storage().entries().len(), 1);
}
