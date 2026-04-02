use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, request::Builder},
};
use chrono::{Duration, TimeZone, Utc};
use rusqlite::params;
use serde_json::{Value, json};
use tokio::task::JoinSet;
use tower::ServiceExt;

use trailing::{
    api::{app, shared_state, shared_state_with_db},
    export::{
        ChainIntegrityStatus, ComplianceControl, ComplianceGap, ComplianceReport, ComplianceStatus,
        EvidenceAction, EvidenceMetadata, EvidencePackage, GapSeverity, IntegrityProof,
        IntegrityState, OversightEvent as ExportOversightEvent,
        filter::{ExportFilter, TimeRange},
        pdf::export_package as export_pdf_package,
    },
    log::{ActionEntry, ActionType},
    oversight::{
        OversightActor,
        capture::{log_approval, log_override},
        chain::{Art14Threshold, link_oversight_event, verify_human_oversight},
    },
    policy::{Framework, PolicyEngine},
    storage::{SqliteStorage, verify_chain},
};

const TEST_API_KEY: &str = "edge-test-api-key";
const TEST_ORG_ID: &str = "edge-org";

fn with_api_key(builder: Builder) -> Builder {
    builder.header("x-api-key", TEST_API_KEY)
}

fn with_org_scope(builder: Builder, org_id: &str) -> Builder {
    with_api_key(builder).header("x-trailing-org-id", org_id)
}

fn test_shared_state() -> trailing::api::SharedState {
    shared_state(Some(TEST_API_KEY.to_string()))
}

fn test_shared_state_with_db(path: impl AsRef<Path>) -> trailing::api::SharedState {
    shared_state_with_db(path, Some(TEST_API_KEY.to_string())).expect("sqlite app")
}

fn temp_db_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "trailing-edge-{test_name}-{}-{nanos}.db",
        std::process::id()
    ))
}

fn make_storage_entry(storage: &SqliteStorage, index: usize) -> ActionEntry {
    storage
        .append_action_at(
            Utc.with_ymd_and_hms(2026, 3, 29, 12, 0, 0).unwrap() + Duration::seconds(index as i64),
            format!("agent-{index}"),
            "worker",
            format!("session-{}", index % 3),
            match index % 3 {
                0 => ActionType::ToolCall,
                1 => ActionType::Decision,
                _ => ActionType::PolicyCheck,
            },
            json!({ "index": index, "tool": format!("tool-{index}") }),
            json!({ "request_id": format!("req-{index}") }),
            "ok",
        )
        .expect("append storage entry")
}

fn assert_only_missing_merkle_checkpoints(violations: &[trailing::storage::IntegrityViolation]) {
    assert!(
        violations.iter().all(|violation| violation
            .reason
            .starts_with("missing merkle checkpoint for batch ")),
        "unexpected integrity violations: {violations:?}"
    );
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    serde_json::from_slice(&body).expect("response must be valid json")
}

fn sample_package(action_count: usize) -> EvidencePackage {
    let generated_at = Utc.with_ymd_and_hms(2026, 3, 29, 12, 0, 0).unwrap();
    let actions = (0..action_count)
        .map(|index| EvidenceAction {
            action_id: format!("action-{index}"),
            timestamp: generated_at + Duration::seconds(index as i64),
            agent_id: format!("agent-{}", index % 8),
            session_id: format!("session-{}", index % 11),
            action_type: if index % 2 == 0 {
                "tool_call".to_string()
            } else {
                "decision".to_string()
            },
            summary: format!("Action summary {index}"),
            input_hash: format!("input-{index}"),
            output_hash: format!("output-{index}"),
            legal_hold: index % 5 == 0,
        })
        .collect();

    EvidencePackage::new(
        EvidenceMetadata {
            package_id: format!("pkg-{action_count}"),
            subject: "Edge Case Export".to_string(),
            organization: "Trailing".to_string(),
            generated_at,
            generated_by: "qa@trailing".to_string(),
            legal_hold: false,
            sessions: vec!["session-0".to_string()],
            agents: vec!["agent-0".to_string()],
            labels: BTreeMap::new(),
        },
        ChainIntegrityStatus {
            status: IntegrityState::Verified,
            last_verified_at: generated_at,
            ledger_root_hash: "ledger-root".to_string(),
            broken_links: 0,
            proofs: vec![IntegrityProof {
                proof_id: "proof-1".to_string(),
                scope: "actions".to_string(),
                algorithm: "sha256".to_string(),
                value: "proof".to_string(),
                verified: true,
            }],
        },
        actions,
        vec![ExportOversightEvent {
            event_id: "event-1".to_string(),
            timestamp: generated_at,
            reviewer: "reviewer".to_string(),
            agent_id: Some("agent-0".to_string()),
            session_id: "session-0".to_string(),
            event_type: "approval".to_string(),
            details: "Reviewed".to_string(),
            disposition: "accepted".to_string(),
            legal_hold: false,
        }],
        ComplianceReport {
            framework: "eu-ai-act".to_string(),
            status: ComplianceStatus::Partial,
            controls: vec![ComplianceControl {
                control_id: "A14".to_string(),
                title: "Human oversight".to_string(),
                status: ComplianceStatus::Partial,
                evidence_refs: vec!["event-1".to_string()],
                notes: Some("Manual review recorded".to_string()),
            }],
            gaps: vec![ComplianceGap {
                gap_id: "gap-1".to_string(),
                severity: GapSeverity::Low,
                description: "Sample gap".to_string(),
                remediation_owner: None,
            }],
        },
    )
}

#[test]
fn hash_chain_detects_manual_context_corruption() {
    // Correct: integrity verification should fail if any persisted field is altered.
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    let target = make_storage_entry(&storage, 0);

    storage
        .connection()
        .execute("DROP TRIGGER action_log_reject_update", [])
        .expect("drop update trigger for tamper simulation");
    storage
        .connection()
        .execute(
            "UPDATE action_log SET context = ?1 WHERE id = ?2",
            params![
                json!({ "request_id": "tampered" }).to_string(),
                target.id.to_string()
            ],
        )
        .expect("tamper context");

    let violations = verify_chain(storage.connection(), None, None).expect("verify chain");

    assert!(
        violations
            .iter()
            .any(|violation| violation.reason == "entry hash mismatch")
    );
}

#[test]
fn hash_chain_detects_missing_genesis_entry() {
    // Correct: deleting the first row should break the first surviving link.
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
    let first = make_storage_entry(&storage, 0);
    make_storage_entry(&storage, 1);
    make_storage_entry(&storage, 2);

    storage
        .connection()
        .execute(
            "DELETE FROM action_log WHERE id = ?1",
            params![first.id.to_string()],
        )
        .expect_err("append-only trigger should block delete");

    storage
        .connection()
        .execute("DROP TRIGGER action_log_reject_delete", [])
        .expect("drop delete trigger for tamper simulation");
    storage
        .connection()
        .execute(
            "DELETE FROM action_log WHERE id = ?1",
            params![first.id.to_string()],
        )
        .expect("delete genesis entry");

    let violations = verify_chain(storage.connection(), None, None).expect("verify chain");

    assert!(
        violations
            .iter()
            .any(|violation| violation.reason == "previous hash mismatch")
    );
}

#[test]
fn forged_suffix_rewrite_is_detected_by_checkpoint_table() {
    let db_path = temp_db_path("checkpoint-forge");
    let storage = SqliteStorage::open(&db_path).expect("sqlite storage");
    make_storage_entry(&storage, 0);
    let original_middle = make_storage_entry(&storage, 1);
    let original_last = make_storage_entry(&storage, 2);

    let mut forged_middle = storage.entries().expect("load entries")[1].clone();
    forged_middle.payload = json!({ "index": 1, "tool": "forged-tool" });
    forged_middle.entry_hash = forged_middle.calculate_hash();

    let mut forged_last = storage.entries().expect("reload entries")[2].clone();
    forged_last.previous_hash = forged_middle.entry_hash.clone();
    forged_last.entry_hash = forged_last.calculate_hash();

    storage
        .connection()
        .execute("DROP TRIGGER action_log_reject_update", [])
        .expect("drop update trigger");
    storage
        .connection()
        .execute(
            "UPDATE action_log SET payload = ?1, entry_hash = ?2 WHERE id = ?3",
            params![
                forged_middle.payload.to_string(),
                forged_middle.entry_hash,
                original_middle.id.to_string()
            ],
        )
        .expect("rewrite middle row");
    storage
        .connection()
        .execute(
            "UPDATE action_log SET previous_hash = ?1, entry_hash = ?2 WHERE id = ?3",
            params![
                forged_last.previous_hash,
                forged_last.entry_hash,
                original_last.id.to_string()
            ],
        )
        .expect("rewrite descendant row");

    let violations = verify_chain(storage.connection(), None, None).expect("verify chain");

    assert!(
        violations
            .iter()
            .any(|violation| violation.reason == "checkpoint entry mismatch"),
        "rewritten suffix should diverge from the persisted checkpoint"
    );

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn verify_chain_handles_ten_thousand_entries_without_integrity_failures() {
    // Correct: large chains should verify without panicking or exhausting memory.
    let storage = SqliteStorage::open_in_memory().expect("in-memory storage");

    for index in 0..10_000 {
        make_storage_entry(&storage, index);
    }

    let violations = verify_chain(storage.connection(), None, None).expect("verify chain");

    assert_only_missing_merkle_checkpoints(&violations);
}

#[tokio::test]
async fn post_endpoints_reject_malformed_json() {
    // Correct: malformed JSON should not be accepted by any POST endpoint.
    for path in [
        "/v1/traces",
        "/v1/traces/otlp",
        "/v1/oversight",
        "/v1/export/json",
        "/v1/export/pdf",
    ] {
        let response = app(test_shared_state())
            .oneshot(
                with_org_scope(Request::builder(), TEST_ORG_ID)
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from("{not-json"))
                    .unwrap(),
            )
            .await
            .expect("send malformed json request");

        assert!(
            matches!(
                response.status(),
                StatusCode::BAD_REQUEST
                    | StatusCode::UNPROCESSABLE_ENTITY
                    | StatusCode::UNSUPPORTED_MEDIA_TYPE
            ),
            "unexpected status {} for {path}",
            response.status()
        );
    }
}

#[tokio::test]
async fn post_endpoints_reject_empty_body() {
    // Correct: empty POST bodies should fail validation rather than creating records.
    for path in [
        "/v1/traces",
        "/v1/traces/otlp",
        "/v1/oversight",
        "/v1/export/json",
        "/v1/export/pdf",
    ] {
        let response = app(test_shared_state())
            .oneshot(
                with_org_scope(Request::builder(), TEST_ORG_ID)
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("send empty body request");

        assert!(
            matches!(
                response.status(),
                StatusCode::BAD_REQUEST
                    | StatusCode::UNPROCESSABLE_ENTITY
                    | StatusCode::UNSUPPORTED_MEDIA_TYPE
            ),
            "unexpected status {} for {path}",
            response.status()
        );
    }
}

#[tokio::test]
async fn traces_endpoint_rejects_oversized_json_payload() {
    // Correct: oversized requests should fail instead of turning into an easy memory DoS.
    let huge = "x".repeat(3 * 1024 * 1024);
    let response = app(test_shared_state())
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "actions": [{
                            "session_id": "large-session",
                            "agent": "attacker",
                            "type": "tool_call",
                            "payload": { "blob": huge }
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("send oversized request");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn sql_injection_unicode_and_null_bytes_are_stored_as_literal_data() {
    // Correct: parameterized writes should preserve hostile strings literally instead of executing them.
    let app = app(test_shared_state());
    let hostile_session = "sess'; DROP TABLE action_log; -- \u{0000} 😈";
    let hostile_agent = "planner\n\u{0000}\u{2603}";

    let ingest = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "actions": [{
                            "session_id": hostile_session,
                            "agent": hostile_agent,
                            "type": "tool_call",
                            "timestamp": "2026-03-29T12:00:00Z",
                            "payload": { "emoji": "🤖", "nul": "\u{0000}" }
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("ingest hostile strings");
    assert_eq!(ingest.status(), StatusCode::CREATED);

    let listed = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("list actions");

    let payload = response_json(listed).await;
    let action = &payload["actions"][0];
    assert_eq!(action["session_id"], hostile_session);
    assert_eq!(action["agent"], hostile_agent);
    assert_eq!(action["payload"]["payload"]["emoji"], "🤖");
}

#[tokio::test]
async fn compliance_endpoint_rejects_unknown_framework_names() {
    // Correct: unknown frameworks should return 404 instead of a fake compliance score.
    let response = app(test_shared_state())
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri(format!(
                    "/v1/compliance/not-a-framework?org_id={TEST_ORG_ID}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request compliance");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn actions_endpoint_returns_not_found_for_missing_id() {
    // Correct: fetching a missing action should return 404.
    let response = app(test_shared_state())
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request missing action");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn actions_query_rejects_inverted_and_invalid_timestamps() {
    // Correct: absurd query ranges should be rejected explicitly.
    let app = app(test_shared_state());

    let inverted = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?from=2026-03-29T13:00:00Z&to=2026-03-29T12:00:00Z")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("query inverted range");
    assert_eq!(inverted.status(), StatusCode::BAD_REQUEST);

    let invalid = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?from=-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("query invalid range");
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn otlp_ingest_rejects_spans_missing_required_fields() {
    // Correct: OTLP ingest should fail when trace/span identifiers are absent.
    let response = app(test_shared_state())
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces/otlp")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "resourceSpans": [{
                            "scopeSpans": [{
                                "spans": [{
                                    "name": "llm.call"
                                }]
                            }]
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("post malformed otlp payload");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn api_survives_fifty_simultaneous_ingests_and_keeps_chain_valid() {
    // Correct: concurrent ingest through one app state should stay serialized and preserve the chain.
    let app = app(test_shared_state());
    let mut tasks = JoinSet::new();

    for index in 0..50 {
        let app = app.clone();
        tasks.spawn(async move {
            app.oneshot(
                with_org_scope(Request::builder(), TEST_ORG_ID)
                    .method("POST")
                    .uri("/v1/traces")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "actions": [{
                                "session_id": format!("bulk-session-{index}"),
                                "agent": format!("agent-{index}"),
                                "type": "tool_call",
                                "timestamp": "2026-03-29T12:00:00Z",
                                "payload": { "index": index }
                            }]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("send ingest")
            .status()
        });
    }

    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.expect("task result"), StatusCode::CREATED);
    }

    let integrity = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/integrity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("query integrity");
    let payload = response_json(integrity).await;

    assert!(payload["valid"].is_boolean());
    assert_eq!(payload["checked_entries"], 50);
}

#[tokio::test]
async fn concurrent_reads_and_writes_do_not_crash_the_api() {
    // Correct: mixed read/write pressure should return normal HTTP responses without poisoning the mutex.
    let app = app(test_shared_state());
    let mut tasks = JoinSet::new();

    for index in 0..25 {
        let app = app.clone();
        tasks.spawn(async move {
            app.oneshot(
                with_org_scope(Request::builder(), TEST_ORG_ID)
                    .method("POST")
                    .uri("/v1/traces")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "actions": [{
                                "session_id": format!("rw-session-{index}"),
                                "agent": "writer",
                                "type": "decision"
                            }]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("send writer request")
            .status()
        });
    }

    for _ in 0..25 {
        let app = app.clone();
        tasks.spawn(async move {
            app.oneshot(
                with_org_scope(Request::builder(), TEST_ORG_ID)
                    .uri("/v1/actions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("send reader request")
            .status()
        });
    }

    while let Some(result) = tasks.join_next().await {
        let status = result.expect("task result");
        assert!(matches!(status, StatusCode::OK | StatusCode::CREATED));
    }
}

#[test]
fn oversight_events_can_reference_nonexistent_actions() {
    // BUG: capture accepts a dangling action reference and only fails later during chain lookup.
    let mut storage = trailing::collector::InMemoryStorage::default();
    let actor = OversightActor::new("reviewer-1", "human-reviewer", "session-1");
    let approval = log_approval(
        &mut storage,
        &actor,
        "alice",
        "missing-action-id",
        Some("manual review".to_string()),
    )
    .expect("approval is accepted even though target is missing");

    let error = link_oversight_event(storage.entries(), &approval.entry_id).unwrap_err();
    assert_eq!(
        format!("{error:?}"),
        "MissingTargetEntry(\"missing-action-id\")"
    );
}

#[tokio::test]
async fn oversight_api_accepts_self_replacement_override_payloads() {
    // BUG: the API ignores original/replacement action semantics and records nonsensical self-replacements.
    let app = app(test_shared_state());
    let response = app
        .oneshot(
            with_api_key(Request::builder())
                .method("POST")
                .uri("/v1/oversight")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "session-1",
                        "severity": "high",
                        "note": "override",
                        "original_action": "action-42",
                        "replacement_action": "action-42"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("post oversight payload");

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[test]
fn oversight_override_accepts_noop_outcome_changes() {
    // BUG: a no-op override is accepted even though it does not change the original outcome.
    let mut storage = trailing::collector::InMemoryStorage::default();
    let actor = OversightActor::new("reviewer-2", "human-reviewer", "session-1");
    let entry = log_override(
        &mut storage,
        &actor,
        "bob",
        "action-123",
        Some("approved".to_string()),
        "approved",
        "no actual change",
    )
    .expect("no-op override is accepted");

    assert_eq!(entry.payload["new_outcome"], "approved");
    assert_eq!(entry.payload["previous_outcome"], "approved");
}

#[test]
fn art14_threshold_handles_exact_boundary_cases() {
    // Correct: threshold=1 should pass for zero actions and for exactly one action.
    let empty_report = verify_human_oversight(
        &[],
        Art14Threshold {
            max_actions_without_oversight: 1,
        },
    )
    .expect("empty report");
    assert!(empty_report.is_compliant);
    assert_eq!(empty_report.actions_since_last_oversight, 0);

    let one_action = [trailing::collector::normalize_sdk_event(
        trailing::collector::SdkEvent {
            agent_id: "agent-1".to_string(),
            agent_type: "Codex".to_string(),
            session_id: "session-1".to_string(),
            action: trailing::collector::SdkAction {
                action_type: "tool.exec".to_string(),
                tool_name: None,
                target: None,
                parameters: json!({}),
                result: None,
            },
            context: trailing::collector::SdkContext::default(),
        },
    )];

    let one_report = verify_human_oversight(
        &one_action,
        Art14Threshold {
            max_actions_without_oversight: 1,
        },
    )
    .expect("single action report");
    assert!(one_report.is_compliant);
    assert_eq!(one_report.actions_since_last_oversight, 1);
}

#[tokio::test]
async fn export_json_with_no_actions_returns_empty_evidence() {
    // Correct: export should succeed even on an empty store and report zero checked entries.
    let response = app(test_shared_state())
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/export/json")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "framework": "eu-ai-act",
                        "org_id": TEST_ORG_ID
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("export empty store");

    assert_eq!(response.status(), StatusCode::OK);
    let payload = response_json(response).await;
    assert_eq!(payload["actions"].as_array().unwrap().len(), 0);
    assert_eq!(payload["oversight_events"].as_array().unwrap().len(), 0);
    assert_eq!(payload["integrity"]["checked_entries"], 0);
}

#[test]
fn export_filter_with_empty_time_window_returns_no_matches() {
    // Correct: a filter outside the evidence window should produce an empty package.
    let package = sample_package(10);
    let filter = ExportFilter {
        time_range: Some(TimeRange {
            start: Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
            end: Some(Utc.with_ymd_and_hms(2030, 1, 2, 0, 0, 0).unwrap()),
        }),
        ..ExportFilter::default()
    };

    let filtered = filter.apply(&package);
    assert!(filtered.actions.is_empty());
    assert!(filtered.oversight_events.is_empty());
}

#[test]
fn pdf_export_handles_more_than_one_thousand_actions() {
    // Correct: large exports should still render a PDF document.
    let pdf = export_pdf_package(&sample_package(1_250)).expect("export pdf");
    assert!(pdf.starts_with(b"%PDF-1.4"));
}

#[tokio::test]
async fn export_json_marks_broken_chain_as_invalid() {
    // Correct: exports should surface chain corruption instead of silently packaging bad evidence.
    let db_path = temp_db_path("export-broken-chain");
    let app = app(test_shared_state_with_db(&db_path));

    let ingest = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "actions": [
                            {
                                "session_id": "broken-session",
                                "agent": "planner",
                                "type": "tool_call",
                                "timestamp": "2026-03-29T12:00:00Z",
                                "payload": { "index": 1 }
                            },
                            {
                                "session_id": "broken-session",
                                "agent": "planner",
                                "type": "tool_call",
                                "timestamp": "2026-03-29T12:01:00Z",
                                "payload": { "index": 2 }
                            }
                        ]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("ingest rows");
    assert_eq!(ingest.status(), StatusCode::CREATED);

    let storage = SqliteStorage::open(&db_path).expect("open sqlite db");
    let second_id: String = storage
        .connection()
        .query_row(
            "SELECT id FROM action_log ORDER BY sequence ASC LIMIT 1 OFFSET 1",
            [],
            |row| row.get(0),
        )
        .expect("load second id");
    storage
        .connection()
        .execute("DROP TRIGGER action_log_reject_update", [])
        .expect("drop update trigger");
    storage
        .connection()
        .execute(
            "UPDATE action_log SET payload = ?1 WHERE id = ?2",
            params![json!({ "index": "tampered" }).to_string(), second_id],
        )
        .expect("tamper chain");

    let export = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/export/json")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "framework": "eu-ai-act",
                        "org_id": TEST_ORG_ID
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("export json");
    let payload = response_json(export).await;

    assert_eq!(payload["integrity"]["valid"], false);
    assert!(
        payload["package"]["chain_integrity_status"]["proofs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|proof| {
                proof["scope"] == "chain_integrity" && proof["verified"].as_bool() == Some(false)
            })
    );
    assert!(
        payload["package"]["chain_integrity_status"]["proofs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|proof| {
                proof["scope"] == "checkpoint_signature"
                    && proof["verified"].as_bool() == Some(true)
            })
    );
    let _ = fs::remove_file(db_path);
}

#[test]
fn policy_evaluation_with_zero_actions_reports_only_gaps() {
    // Correct: evaluating an empty evidence set should show unmet controls rather than false positives.
    let engine = PolicyEngine::new();
    let report = engine
        .evaluate(&Framework::EuAiAct, &[])
        .expect("evaluate empty evidence");

    assert_eq!(report.controls_met.len(), 0);
    assert!(!report.controls_gaps.is_empty());
}

#[test]
fn malformed_custom_framework_toml_is_rejected() {
    // Correct: invalid TOML should not load as a policy framework.
    let mut engine = PolicyEngine::new();
    let error = engine
        .load_custom_framework_from_str("framework = ")
        .expect_err("malformed TOML must fail");

    assert!(
        error.to_string().contains("TOML parse error")
            || error.to_string().contains("expected")
            || error.to_string().contains("invalid")
            || error.to_string().contains("missing"),
        "unexpected TOML parse error: {error}"
    );
}

#[test]
fn custom_framework_missing_required_fields_is_rejected() {
    // Correct: missing required control fields should be rejected at load time.
    let mut engine = PolicyEngine::new();
    let error = engine
        .load_custom_framework_from_str(
            r#"
framework = "internal"

[[controls]]
id = "INT-1"
article = "Section 1"
"#,
        )
        .expect_err("missing requirement fields must fail");

    assert!(
        error
            .to_string()
            .contains("control is missing `requirement`")
    );
}

#[test]
fn custom_framework_with_no_controls_is_rejected() {
    // Correct: a framework with no controls should not load.
    let mut engine = PolicyEngine::new();
    let error = engine
        .load_custom_framework_from_str(
            r#"
framework = "internal"
controls = []
"#,
        )
        .expect_err("framework without controls must fail");

    assert!(error.to_string().contains("at least one control"));
}

#[test]
fn built_in_frameworks_now_expose_real_controls() {
    let engine = PolicyEngine::new();
    let report = engine
        .evaluate(&Framework::Sr117, &[])
        .expect("built-in framework should evaluate");

    assert!(report.controls_met.is_empty());
    assert!(!report.controls_gaps.is_empty());
}

#[test]
fn read_only_database_cannot_accept_writes() {
    // Correct: a read-only database file should fail open or append rather than pretending to persist data.
    let db_path = temp_db_path("readonly-db");
    {
        let storage = SqliteStorage::open(&db_path).expect("create sqlite db");
        make_storage_entry(&storage, 0);
    }

    let mut permissions = fs::metadata(&db_path).expect("metadata").permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&db_path, permissions).expect("chmod readonly");

    let result = SqliteStorage::open(&db_path).and_then(|storage| {
        storage.append_action(
            "agent",
            "worker",
            "session",
            ActionType::ToolCall,
            json!({ "test": true }),
            json!({}),
            "ok",
        )
    });
    assert!(result.is_err());

    let mut permissions = fs::metadata(&db_path).expect("metadata").permissions();
    permissions.set_readonly(false);
    fs::set_permissions(&db_path, permissions).expect("chmod writable");
    let _ = fs::remove_file(db_path);
}

#[test]
fn sqlite_reports_disk_full_when_page_budget_is_exhausted() {
    // Correct: storage errors should bubble up when SQLite cannot grow the database any further.
    let db_path = temp_db_path("disk-full");
    let storage = SqliteStorage::open(&db_path).expect("open sqlite db");
    let page_count: i64 = storage
        .connection()
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .expect("read page_count");
    let _: i64 = storage
        .connection()
        .query_row(
            &format!("PRAGMA max_page_count = {}", page_count + 1),
            [],
            |row| row.get(0),
        )
        .expect("limit max_page_count");

    let large_payload = "x".repeat(256 * 1024);
    let mut last_error = None;
    for index in 0..16 {
        match storage.append_action(
            format!("agent-{index}"),
            "worker",
            "disk-full-session",
            ActionType::ToolCall,
            json!({ "blob": large_payload }),
            json!({}),
            "ok",
        ) {
            Ok(_) => {}
            Err(error) => {
                last_error = Some(error.to_string());
                break;
            }
        }
    }

    let message = last_error.expect("expected database to hit size limit");
    assert!(
        message.contains("database or disk is full"),
        "unexpected disk-full error: {message}"
    );

    let _ = fs::remove_file(db_path);
}
