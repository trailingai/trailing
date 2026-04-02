use serde_json::json;
use trailing::collector::{
    AgentType, InMemoryStorage, SdkAction, SdkContext, SdkEvent, TraceCollector,
};
use trailing::oversight::OversightActor;
use trailing::oversight::OversightEvent;
use trailing::oversight::capture::{
    log_approval, log_escalation, log_kill_switch, log_override, log_oversight_event,
};
use trailing::oversight::chain::{
    Art14ComplianceError, Art14Threshold, OversightChainError, link_oversight_event, linked_action,
    verify_human_oversight,
};

#[test]
fn oversight_events_are_logged_as_human_override_entries() {
    let mut collector = TraceCollector::new(InMemoryStorage::default());
    let action = collector
        .ingest_sdk_event(sample_sdk_event("tool.exec"))
        .unwrap();
    let actor = OversightActor::new("reviewer-1", "human-reviewer", "session-1");

    let approval = log_approval(
        collector.storage_mut(),
        &actor,
        "alice",
        action.entry_id.clone(),
        Some("reviewed manually".to_string()),
    )
    .unwrap();

    assert_eq!(approval.action_type, "HumanOverride");
    assert_eq!(
        approval.modified_entry_id.as_deref(),
        Some(action.entry_id.as_str())
    );
    assert_eq!(
        approval.agent_type,
        AgentType::Unknown("human-reviewer".to_string())
    );
    assert_eq!(approval.payload["event_type"], json!("Approval"));
    assert_eq!(approval.payload["reviewer"], json!("alice"));
    assert_eq!(
        approval.payload["modified_entry_id"],
        json!(action.entry_id)
    );
}

#[test]
fn oversight_links_back_to_the_modified_action_entry() {
    let mut collector = TraceCollector::new(InMemoryStorage::default());
    let action = collector
        .ingest_sdk_event(sample_sdk_event("decision.record"))
        .unwrap();
    let actor = OversightActor::new("reviewer-2", "human-reviewer", "session-2");

    let override_entry = log_override(
        collector.storage_mut(),
        &actor,
        "bob",
        action.entry_id.clone(),
        Some("approved".to_string()),
        "denied",
        "manual review failed",
    )
    .unwrap();

    let chain =
        link_oversight_event(collector.storage().entries(), &override_entry.entry_id).unwrap();
    let linked = linked_action(collector.storage().entries(), &override_entry.entry_id).unwrap();

    assert_eq!(chain.target_entry_id, action.entry_id);
    assert_eq!(linked.entry_id, action.entry_id);
}

#[test]
fn kill_switch_without_target_cannot_form_a_chain() {
    let mut storage = InMemoryStorage::default();
    let actor = OversightActor::new("reviewer-3", "human-reviewer", "session-3");
    let kill_switch = log_kill_switch(
        &mut storage,
        &actor,
        "ops",
        None,
        "global",
        "emergency stop",
    )
    .unwrap();

    let error = link_oversight_event(storage.entries(), &kill_switch.entry_id).unwrap_err();

    assert_eq!(
        error,
        OversightChainError::UnlinkedOversightEntry(kill_switch.entry_id)
    );
}

#[test]
fn art14_compliance_passes_when_human_oversight_is_within_threshold() {
    let mut collector = TraceCollector::new(InMemoryStorage::default());
    let actor = OversightActor::new("reviewer-4", "human-reviewer", "session-4");

    collector
        .ingest_sdk_event(sample_sdk_event("action.1"))
        .unwrap();
    collector
        .ingest_sdk_event(sample_sdk_event("action.2"))
        .unwrap();
    let action = collector
        .ingest_sdk_event(sample_sdk_event("action.3"))
        .unwrap();
    log_escalation(
        collector.storage_mut(),
        &actor,
        "carol",
        action.entry_id.clone(),
        "tier-2",
        "needs sign-off",
    )
    .unwrap();
    collector
        .ingest_sdk_event(sample_sdk_event("action.4"))
        .unwrap();
    collector
        .ingest_sdk_event(sample_sdk_event("action.5"))
        .unwrap();

    let report = verify_human_oversight(
        collector.storage().entries(),
        Art14Threshold {
            max_actions_without_oversight: 3,
        },
    )
    .unwrap();

    assert!(report.is_compliant);
    assert_eq!(report.actions_since_last_oversight, 2);
    assert!(report.last_oversight_entry_id.is_some());
}

#[test]
fn art14_compliance_fails_when_too_many_actions_have_no_human_oversight() {
    let mut collector = TraceCollector::new(InMemoryStorage::default());
    collector
        .ingest_sdk_event(sample_sdk_event("action.1"))
        .unwrap();
    collector
        .ingest_sdk_event(sample_sdk_event("action.2"))
        .unwrap();
    let violating = collector
        .ingest_sdk_event(sample_sdk_event("action.3"))
        .unwrap();

    let report = verify_human_oversight(
        collector.storage().entries(),
        Art14Threshold {
            max_actions_without_oversight: 2,
        },
    )
    .unwrap();

    assert!(!report.is_compliant);
    assert_eq!(
        report.violating_entry_id.as_deref(),
        Some(violating.entry_id.as_str())
    );
    assert_eq!(report.last_oversight_entry_id, None);
}

#[test]
fn art14_threshold_must_be_non_zero() {
    let error = verify_human_oversight(
        &[],
        Art14Threshold {
            max_actions_without_oversight: 0,
        },
    )
    .unwrap_err();

    assert_eq!(error, Art14ComplianceError::InvalidThreshold);
}

#[test]
fn generic_capture_supports_all_oversight_event_variants() {
    let mut collector = TraceCollector::new(InMemoryStorage::default());
    let action = collector
        .ingest_sdk_event(sample_sdk_event("action.1"))
        .unwrap();
    let actor = OversightActor::new("reviewer-5", "human-reviewer", "session-5");

    let approval = log_oversight_event(
        collector.storage_mut(),
        &actor,
        OversightEvent::Approval {
            reviewer: "dana".to_string(),
            approved_entry_id: action.entry_id.clone(),
            notes: None,
        },
    )
    .unwrap();
    let escalation = log_escalation(
        collector.storage_mut(),
        &actor,
        "erin",
        action.entry_id.clone(),
        "legal",
        "policy review",
    )
    .unwrap();
    let kill_switch = log_kill_switch(
        collector.storage_mut(),
        &actor,
        "frank",
        Some(action.entry_id),
        "service",
        "halt processing",
    )
    .unwrap();

    assert_eq!(approval.action_type, "HumanOverride");
    assert_eq!(escalation.action_type, "HumanOverride");
    assert_eq!(kill_switch.action_type, "HumanOverride");
}

fn sample_sdk_event(action_type: &str) -> SdkEvent {
    SdkEvent {
        agent_id: "agent-1".to_string(),
        agent_type: "OpenAI Codex".to_string(),
        session_id: "session-1".to_string(),
        action: SdkAction {
            action_type: action_type.to_string(),
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
    }
}
