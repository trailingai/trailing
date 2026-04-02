use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};

use trailing::collector::{OtelSpan, SdkAction, SdkContext, SdkEvent};
use trailing::export::{
    ChainIntegrityStatus, ComplianceControl, ComplianceGap, ComplianceReport, ComplianceStatus,
    EvidenceAction, EvidenceMetadata, EvidencePackage, GapSeverity, IntegrityProof, IntegrityState,
    OversightEvent as ExportOversightEvent,
};
use trailing::log::ActionType;
use trailing::oversight::{OversightActor, OversightEvent};

fn assert_json_round_trip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_value(value).expect("value should serialize");
    let decoded: T = serde_json::from_value(encoded).expect("value should deserialize");
    assert_eq!(decoded, *value);
}

fn sample_package() -> EvidencePackage {
    let generated_at = Utc.with_ymd_and_hms(2026, 3, 29, 12, 0, 0).unwrap();

    EvidencePackage::new(
        EvidenceMetadata {
            package_id: "pkg-schema".to_string(),
            subject: "Schema contract".to_string(),
            organization: "Trailing".to_string(),
            generated_at,
            generated_by: "tests".to_string(),
            legal_hold: false,
            sessions: vec!["session-1".to_string()],
            agents: vec!["agent-1".to_string()],
            labels: BTreeMap::from([("framework".to_string(), "eu-ai-act".to_string())]),
        },
        ChainIntegrityStatus {
            status: IntegrityState::Verified,
            last_verified_at: generated_at,
            ledger_root_hash: "root-hash".to_string(),
            broken_links: 0,
            proofs: vec![IntegrityProof {
                proof_id: "proof-1".to_string(),
                scope: "package".to_string(),
                algorithm: "sha256".to_string(),
                value: "proof-value".to_string(),
                verified: true,
            }],
        },
        vec![EvidenceAction {
            action_id: "action-1".to_string(),
            timestamp: generated_at,
            agent_id: "agent-1".to_string(),
            session_id: "session-1".to_string(),
            action_type: "ToolCall".to_string(),
            summary: "Captured action".to_string(),
            input_hash: "input-hash".to_string(),
            output_hash: "output-hash".to_string(),
            legal_hold: false,
        }],
        vec![ExportOversightEvent {
            event_id: "oversight-1".to_string(),
            timestamp: generated_at,
            reviewer: "reviewer".to_string(),
            agent_id: Some("agent-1".to_string()),
            session_id: "session-1".to_string(),
            event_type: "approval".to_string(),
            details: "Approved".to_string(),
            disposition: "accepted".to_string(),
            legal_hold: false,
        }],
        ComplianceReport {
            framework: "eu-ai-act".to_string(),
            status: ComplianceStatus::Compliant,
            controls: vec![ComplianceControl {
                control_id: "EU-AIA-14".to_string(),
                title: "Human oversight".to_string(),
                status: ComplianceStatus::Compliant,
                evidence_refs: vec!["oversight-1".to_string()],
                notes: Some("Human review recorded".to_string()),
            }],
            gaps: vec![ComplianceGap {
                gap_id: "gap-0".to_string(),
                severity: GapSeverity::Low,
                description: "No gap".to_string(),
                remediation_owner: None,
            }],
        },
    )
}

#[test]
fn sdk_event_round_trips_through_json() {
    let event = SdkEvent {
        agent_id: "agent-1".to_string(),
        agent_type: "OpenAI Codex".to_string(),
        session_id: "session-1".to_string(),
        action: SdkAction {
            action_type: "tool.exec".to_string(),
            tool_name: Some("shell".to_string()),
            target: Some("cargo test".to_string()),
            parameters: json!({ "cmd": "cargo test" }),
            result: Some(json!({ "status": "ok" })),
        },
        context: SdkContext {
            data_accessed: vec!["Cargo.toml".to_string()],
            permissions_used: vec!["workspace-write".to_string()],
            policy_refs: vec!["policy://storage".to_string()],
        },
    };

    assert_json_round_trip(&event);
}

#[test]
fn otel_span_round_trips_through_json() {
    let span = OtelSpan {
        trace_id: "trace-1".to_string(),
        span_id: "span-1".to_string(),
        name: "tool.call".to_string(),
        attributes: Map::from_iter([
            ("agent.id".to_string(), Value::String("agent-1".to_string())),
            (
                "permissions.used".to_string(),
                Value::Array(vec![Value::String("workspace-write".to_string())]),
            ),
        ]),
        start_time: Some("100".to_string()),
        end_time: Some("200".to_string()),
        parent_span_id: Some("parent-1".to_string()),
        status: Some("STATUS_CODE_OK".to_string()),
    };

    assert_json_round_trip(&span);
}

#[test]
fn oversight_events_round_trip_with_tagged_event_type() {
    let actor = OversightActor::new("reviewer-1", "human-reviewer", "session-1");
    let approval = OversightEvent::Approval {
        reviewer: "alice".to_string(),
        approved_entry_id: "entry-1".to_string(),
        notes: Some("approved".to_string()),
    };
    let escalation = OversightEvent::Escalation {
        reviewer: "bob".to_string(),
        escalated_entry_id: "entry-2".to_string(),
        escalation_target: "legal".to_string(),
        reason: "manual review required".to_string(),
    };

    assert_json_round_trip(&actor);
    assert_json_round_trip(&approval);
    assert_json_round_trip(&escalation);

    let encoded = serde_json::to_value(&approval).expect("approval should serialize");
    assert_eq!(encoded["event_type"], "Approval");
}

#[test]
fn action_type_wire_format_matches_enum_names() {
    let cases = [
        (ActionType::ToolCall, "\"ToolCall\""),
        (ActionType::SystemWrite, "\"SystemWrite\""),
        (ActionType::DataAccess, "\"DataAccess\""),
        (ActionType::HumanOverride, "\"HumanOverride\""),
        (ActionType::PolicyCheck, "\"PolicyCheck\""),
        (ActionType::Decision, "\"Decision\""),
    ];

    for (action_type, expected_json) in cases {
        let encoded = serde_json::to_string(&action_type).expect("action type should serialize");
        assert_eq!(encoded, expected_json);
        let decoded: ActionType =
            serde_json::from_str(expected_json).expect("action type should deserialize");
        assert_eq!(decoded, action_type);
    }
}

#[test]
fn evidence_package_round_trips_through_json() {
    let package = sample_package();
    assert_json_round_trip(&package);
}
