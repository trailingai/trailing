use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, request::Builder},
};
use chrono::{TimeZone, Utc};
use rusqlite::Connection;
use serde_json::{Value, json};
use tower::ServiceExt;

use trailing::api::{
    AppOptions, TRAILING_VERSION, app, shared_state, shared_state_with_db,
    shared_state_with_options,
};
use trailing::checkpoint::{CheckpointSigner, SignatureAlgorithm};
use trailing::storage::{
    ApiKeyRole, ExternalAnchorInput, MfaPolicy, SqliteStorage, Storage, initialize_schema,
};

const TEST_API_KEY: &str = "test-api-key";
const TEST_ORG_ID: &str = "org-test";

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
    shared_state_with_db(path, Some(TEST_API_KEY.to_string())).expect("shared state with db")
}

fn test_shared_state_with_options(options: AppOptions) -> trailing::api::SharedState {
    shared_state_with_options(Some(TEST_API_KEY.to_string()), options)
        .expect("shared state with options")
}

fn temp_db_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "trailing-{test_name}-{}-{nanos}.db",
        std::process::id()
    ))
}

fn auth_db_path(test_name: &str) -> PathBuf {
    let db_path = temp_db_path(test_name);
    let conn = Connection::open(&db_path).expect("open sqlite db");
    initialize_schema(&conn).expect("initialize schema");
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS auth_audit_log (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            org_id TEXT,
            actor_type TEXT NOT NULL,
            actor_id TEXT,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            payload TEXT NOT NULL,
            outcome TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS human_users (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_authenticated_at TEXT,
            pending_mfa_secret TEXT,
            mfa_secret TEXT,
            mfa_enabled INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0, 1)),
            mfa_enrolled_at TEXT
        );

        CREATE TABLE IF NOT EXISTS org_mfa_policies (
            org_id TEXT PRIMARY KEY,
            policy TEXT NOT NULL CHECK (policy IN ('optional', 'required')),
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_challenges (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS human_recovery_codes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT
        );
        ",
    )
    .expect("create auth tables");
    db_path
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn totp_code(secret: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
        .to_string();
    let script = r#"
import base64
import hashlib
import hmac
import sys

secret = sys.argv[1].strip().upper()
timestamp = int(sys.argv[2])
padding = '=' * ((8 - len(secret) % 8) % 8)
key = base64.b32decode(secret + padding, casefold=True)
counter = (timestamp // 30).to_bytes(8, 'big')
digest = hmac.new(key, counter, hashlib.sha1).digest()
offset = digest[-1] & 0x0F
binary = (
    ((digest[offset] & 0x7F) << 24)
    | ((digest[offset + 1] & 0xFF) << 16)
    | ((digest[offset + 2] & 0xFF) << 8)
    | (digest[offset + 3] & 0xFF)
)
print(f"{binary % 1000000:06d}")
"#;
    let output = Command::new("python3")
        .args(["-c", script, secret, &timestamp])
        .output()
        .expect("generate totp code");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[tokio::test]
async fn health_check_returns_ok() {
    let app = app(test_shared_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-trailing-version")
            .unwrap()
            .to_str()
            .unwrap(),
        TRAILING_VERSION
    );
    assert!(response.headers().contains_key("x-request-id"));
    let value = response_json(response).await;
    assert_eq!(value["status"], "ok");
    assert_eq!(value["version"], TRAILING_VERSION);
    assert_eq!(value["total_actions"], 0);
    assert_eq!(value["chain_valid"], true);
    assert!(value["uptime_seconds"].is_u64());
    assert!(value["db_size_bytes"].is_u64());
}

#[tokio::test]
async fn trace_ingest_and_action_queries_work() {
    let app = app(test_shared_state());

    let ingest_response = app
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
                                "session_id": "session-1",
                                "agent": "planner",
                                "type": "tool_call",
                                "timestamp": "2026-03-29T12:00:00Z",
                                "payload": { "tool": "search" }
                            }
                        ]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ingest_response.status(), StatusCode::CREATED);
    let ingest_body = to_bytes(ingest_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let ingest_value: Value = serde_json::from_slice(&ingest_body).unwrap();
    let action_id = ingest_value["action_ids"][0].as_str().unwrap().to_string();

    let query_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=session-1&agent=planner")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(query_response.status(), StatusCode::OK);
    let query_body = to_bytes(query_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let query_value: Value = serde_json::from_slice(&query_body).unwrap();
    assert_eq!(query_value["actions"].as_array().unwrap().len(), 1);
    assert_eq!(query_value["actions"][0]["id"], action_id);

    let single_response = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri(format!("/v1/actions/{action_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(single_response.status(), StatusCode::OK);
    let single_body = to_bytes(single_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let single_value: Value = serde_json::from_slice(&single_body).unwrap();
    assert_eq!(single_value["agent"], "planner");
}

#[tokio::test]
async fn sdk_ingest_extracts_agent_and_action_fields() {
    let app = app(test_shared_state());

    let ingest_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "agent_id": "claude-agent-001",
                        "agent_type": "claude",
                        "session_id": "session-abc",
                        "action": {
                            "type": "ToolCall",
                            "tool_name": "read_file",
                            "target": "/path/to/file",
                            "parameters": { "path": "/path/to/file" },
                            "result": "Success"
                        },
                        "context": {
                            "data_accessed": ["patient_record_123"],
                            "permissions_used": ["phi_read"],
                            "policy_refs": ["hipaa_minimum_necessary"]
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ingest_response.status(), StatusCode::CREATED);

    let actions_response = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=session-abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(actions_response.status(), StatusCode::OK);
    let actions_body = to_bytes(actions_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let actions_value: Value = serde_json::from_slice(&actions_body).unwrap();
    let action = &actions_value["actions"][0];

    assert_eq!(action["agent"], "claude-agent-001");
    assert_ne!(action["agent"], "unknown-agent");
    assert_eq!(action["agent_type"], "claude");
    assert_eq!(action["type"], "ToolCall");
    assert_eq!(action["tool_name"], "read_file");
    assert_eq!(action["target"], "/path/to/file");
    assert_eq!(action["session_id"], "session-abc");
}

#[tokio::test]
async fn otlp_ingest_oversight_export_and_integrity_work() {
    let db_path = temp_db_path("otlp-oversight-export-integrity");
    let app = app(test_shared_state_with_db(&db_path));

    let otlp_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces/otlp")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "resourceSpans": [
                            {
                                "scopeSpans": [
                                    {
                                        "spans": [
                                            {
                                                "traceId": "trace-123",
                                                "spanId": "span-001",
                                                "name": "llm.call",
                                                "agent": "runtime",
                                                "timestamp": "2026-03-29T12:05:00Z"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let otlp_status = otlp_response.status();
    let otlp_body = to_bytes(otlp_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        otlp_status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&otlp_body)
    );

    let oversight_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/oversight")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": TEST_ORG_ID,
                        "session_id": "trace-123",
                        "framework": "eu-ai-act",
                        "severity": "high",
                        "note": "human review completed",
                        "timestamp": "2026-03-29T12:06:00Z"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(oversight_response.status(), StatusCode::CREATED);

    let compliance_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri(format!("/v1/compliance/eu-ai-act?org_id={TEST_ORG_ID}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(compliance_response.status(), StatusCode::OK);
    let compliance_body = to_bytes(compliance_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let compliance_value: Value = serde_json::from_slice(&compliance_body).unwrap();
    assert_eq!(compliance_value["framework"], "eu-ai-act");
    assert!(compliance_value["integrity_valid"].is_boolean());
    assert!(compliance_value["controls_met"].is_array());
    assert!(compliance_value["controls_gaps"].is_array());

    let export_json_response = app
        .clone()
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
        .unwrap();

    assert_eq!(export_json_response.status(), StatusCode::OK);
    let export_json_body = to_bytes(export_json_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let export_json_value: Value = serde_json::from_slice(&export_json_body).unwrap();
    assert_eq!(export_json_value["actions"].as_array().unwrap().len(), 1);
    assert_eq!(
        export_json_value["oversight_events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        !export_json_value["integrity_proofs"]["merkle_root_hash"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    assert!(
        !export_json_value["integrity_proofs"]["checkpoint_signature"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    let package_proofs = export_json_value["package"]["chain_integrity_status"]["proofs"]
        .as_array()
        .unwrap();
    assert!(!package_proofs.is_empty());
    assert!(
        package_proofs
            .iter()
            .any(|proof| proof["scope"] == "chain_integrity")
    );
    assert!(
        package_proofs
            .iter()
            .any(|proof| proof["scope"] == "merkle_inclusion")
    );
    assert!(
        package_proofs
            .iter()
            .any(|proof| proof["scope"] == "checkpoint_signature")
    );

    let export_pdf_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/export/pdf")
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
        .unwrap();

    assert_eq!(export_pdf_response.status(), StatusCode::OK);
    assert_eq!(
        export_pdf_response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/pdf"
    );
    let export_pdf_body = to_bytes(export_pdf_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(export_pdf_body.starts_with(b"%PDF-1."));

    let integrity_response = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/integrity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(integrity_response.status(), StatusCode::OK);
    let integrity_body = to_bytes(integrity_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let integrity_value: Value = serde_json::from_slice(&integrity_body).unwrap();
    assert!(integrity_value["valid"].is_boolean());
    assert_eq!(integrity_value["checked_entries"], 2);
    assert_eq!(integrity_value["root_anchor_persisted"], true);
    assert!(
        !integrity_value["merkle_root_hash"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    assert!(
        !integrity_value["checkpoint_signature"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    let integrity_proofs = integrity_value["proofs"].as_array().unwrap();
    assert!(
        integrity_proofs
            .iter()
            .any(|proof| proof["scope"] == "root_anchor_hash")
    );

    fs::remove_file(db_path).ok();
}

#[tokio::test]
async fn checkpoints_endpoints_return_signed_material_and_verification() {
    let db_path = temp_db_path("checkpoints-api");
    let storage = SqliteStorage::open(&db_path).expect("sqlite storage");
    storage
        .append_action_at(
            Utc.with_ymd_and_hms(2026, 3, 29, 12, 0, 0).unwrap(),
            "planner",
            "worker",
            "session-1",
            trailing::log::ActionType::ToolCall,
            json!({ "tool": "search" }),
            json!({ "request_id": "req-1" }),
            "ok",
        )
        .expect("append action");

    let signer = CheckpointSigner::from_secret_bytes(
        SignatureAlgorithm::Ed25519,
        "audit-key-1",
        Some("primary".to_string()),
        &[13u8; 32],
        Utc.with_ymd_and_hms(2026, 3, 29, 11, 0, 0).unwrap(),
    )
    .expect("create signer");
    let checkpoint = storage
        .create_signed_checkpoint(
            &signer,
            &[ExternalAnchorInput {
                provider: "rfc3161".to_string(),
                reference: "tsa://receipt-1".to_string(),
                anchored_at: Some("2026-03-29T12:00:01Z".to_string()),
                metadata: json!({ "receipt": "proof-1" }),
            }],
        )
        .expect("create checkpoint");

    let app = app(test_shared_state_with_db(&db_path));

    let list_response = app
        .clone()
        .oneshot(
            with_api_key(Request::builder())
                .uri("/v1/checkpoints")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(list_response.status(), StatusCode::OK);
    let list_payload = response_json(list_response).await;
    assert_eq!(list_payload.as_array().unwrap().len(), 1);
    assert_eq!(list_payload[0]["checkpoint_id"], checkpoint.checkpoint_id);

    let detail_response = app
        .oneshot(
            with_api_key(Request::builder())
                .uri(format!("/v1/checkpoints/{}", checkpoint.checkpoint_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(detail_response.status(), StatusCode::OK);
    let detail_payload = response_json(detail_response).await;
    assert_eq!(detail_payload["verification"]["signature_valid"], true);
    assert_eq!(detail_payload["anchor_hashes_valid"], true);
    assert_eq!(detail_payload["verified"], true);
    assert_eq!(detail_payload["checkpoint"]["key"]["key_id"], "audit-key-1");

    let _ = fs::remove_file(&db_path);
    let _ = fs::remove_file(PathBuf::from(format!("{}.root", db_path.display())));
}

#[tokio::test]
async fn otlp_ingest_extracts_resource_agent_fields_and_span_name() {
    let app = app(test_shared_state());

    let ingest_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces/otlp")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "resourceSpans": [
                            {
                                "resource": {
                                    "attributes": [
                                        {
                                            "key": "agent.id",
                                            "value": { "stringValue": "codex-agent-007" }
                                        },
                                        {
                                            "key": "agent.type",
                                            "value": { "stringValue": "codex" }
                                        },
                                        {
                                            "key": "session.id",
                                            "value": { "stringValue": "session-otel-1" }
                                        }
                                    ]
                                },
                                "scopeSpans": [
                                    {
                                        "spans": [
                                            {
                                                "traceId": "trace-otel-1",
                                                "spanId": "span-otel-1",
                                                "name": "ToolCall",
                                                "startTimeUnixNano": "100",
                                                "attributes": [
                                                    {
                                                        "key": "tool.name",
                                                        "value": { "stringValue": "read_file" }
                                                    },
                                                    {
                                                        "key": "target",
                                                        "value": { "stringValue": "/tmp/report.txt" }
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ingest_response.status(), StatusCode::CREATED);

    let actions_response = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=session-otel-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(actions_response.status(), StatusCode::OK);
    let actions_body = to_bytes(actions_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let actions_value: Value = serde_json::from_slice(&actions_body).unwrap();
    let action = &actions_value["actions"][0];

    assert_eq!(action["agent"], "codex-agent-007");
    assert_ne!(action["agent"], "unknown-agent");
    assert_eq!(action["agent_type"], "codex");
    assert_eq!(action["type"], "ToolCall");
    assert_eq!(action["tool_name"], "read_file");
    assert_eq!(action["target"], "/tmp/report.txt");
    assert_eq!(action["session_id"], "session-otel-1");
}

#[tokio::test]
async fn actions_query_can_include_oversight_records_with_explicit_kind_tags() {
    let app = app(test_shared_state());

    let trace_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "actions": [{
                            "session_id": "session-oversight",
                            "agent": "planner",
                            "type": "tool_call",
                            "timestamp": "2026-03-29T12:00:00Z",
                            "payload": { "tool": "search" }
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(trace_response.status(), StatusCode::CREATED);

    let oversight_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/oversight")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": TEST_ORG_ID,
                        "session_id": "session-oversight",
                        "framework": "eu-ai-act",
                        "severity": "high",
                        "note": "manual review completed",
                        "timestamp": "2026-03-29T12:01:00Z"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(oversight_response.status(), StatusCode::CREATED);
    let oversight_body = to_bytes(oversight_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let oversight_value: Value = serde_json::from_slice(&oversight_body).unwrap();
    let oversight_id = oversight_value["id"].as_str().unwrap().to_string();

    let default_query = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=session-oversight")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(default_query.status(), StatusCode::OK);
    let default_body = to_bytes(default_query.into_body(), usize::MAX)
        .await
        .unwrap();
    let default_value: Value = serde_json::from_slice(&default_body).unwrap();
    assert_eq!(default_value["actions"].as_array().unwrap().len(), 1);

    let combined_query = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=session-oversight&include_oversight=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(combined_query.status(), StatusCode::OK);
    let combined_body = to_bytes(combined_query.into_body(), usize::MAX)
        .await
        .unwrap();
    let combined_value: Value = serde_json::from_slice(&combined_body).unwrap();
    assert_eq!(combined_value["actions"].as_array().unwrap().len(), 2);

    let oversight_entry = combined_value["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == oversight_id)
        .expect("oversight entry returned in action stream");
    assert_eq!(oversight_entry["kind"], "oversight");
    assert_eq!(oversight_entry["type"], "HumanOverride");

    let single_response = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri(format!("/v1/actions/{oversight_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(single_response.status(), StatusCode::OK);
    let single_body = to_bytes(single_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let single_value: Value = serde_json::from_slice(&single_body).unwrap();
    assert_eq!(single_value["kind"], "oversight");
}

#[tokio::test]
async fn compliance_endpoint_returns_real_control_results_for_filtered_scope() {
    let db_path = temp_db_path("compliance-real-evaluation");
    let state = test_shared_state_with_db(&db_path);
    Connection::open(&db_path)
        .expect("open sqlite db")
        .execute(
            "UPDATE storage_control SET min_retention_days = 365 WHERE id = 1",
            [],
        )
        .expect("configure retention");
    let app = app(state);

    let ingest_response = app
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
                                "session_id": "scope-a",
                                "agent": "planner",
                                "type": "policy_review",
                                "timestamp": "2026-03-29T12:00:00Z",
                                "payload": {
                                    "tool": "screening",
                                    "policy": "eu-ai-act",
                                    "result": "approved"
                                }
                            },
                            {
                                "session_id": "scope-b",
                                "agent": "planner",
                                "type": "tool_call",
                                "timestamp": "2026-03-29T12:01:00Z",
                                "payload": { "tool": "search" }
                            }
                        ]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ingest_response.status(), StatusCode::CREATED);

    let oversight_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/oversight")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": TEST_ORG_ID,
                        "session_id": "scope-a",
                        "framework": "eu-ai-act",
                        "severity": "high",
                        "note": "human review completed",
                        "timestamp": "2026-03-29T12:02:00Z"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(oversight_response.status(), StatusCode::CREATED);

    let compliance_response = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri(format!(
                    "/v1/compliance/eu-ai-act?org_id={TEST_ORG_ID}&session_id=scope-a"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(compliance_response.status(), StatusCode::OK);
    let compliance_body = to_bytes(compliance_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let compliance_value: Value = serde_json::from_slice(&compliance_body).unwrap();

    assert_eq!(compliance_value["framework"], "eu-ai-act");
    assert_eq!(compliance_value["total_actions"], 1);
    assert_eq!(compliance_value["oversight_events"], 1);
    assert_eq!(compliance_value["score"], 100);

    let met_ids = compliance_value["controls_met"]
        .as_array()
        .unwrap()
        .iter()
        .map(|control| control["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(met_ids.contains(&"EU-AIA-12".to_string()));
    assert!(met_ids.contains(&"EU-AIA-13".to_string()));
    assert!(met_ids.contains(&"EU-AIA-14".to_string()));
    assert!(met_ids.contains(&"EU-AIA-19".to_string()));
    assert!(met_ids.contains(&"EU-AIA-72".to_string()));
    assert!(
        compliance_value["controls_gaps"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let evidence_refs = compliance_value["evidence_refs"].as_array().unwrap();
    assert!(evidence_refs.iter().any(|value| {
        value
            .as_str()
            .unwrap()
            .contains("storage_control:min_retention_days=365")
    }));
    assert!(
        evidence_refs
            .iter()
            .any(|value| value.as_str().unwrap().starts_with("action:"))
    );
    assert!(
        evidence_refs
            .iter()
            .any(|value| value.as_str().unwrap().starts_with("oversight:"))
    );

    fs::remove_file(db_path).ok();
}

#[tokio::test]
async fn compliance_endpoint_supports_all_builtin_frameworks() {
    let db_path = temp_db_path("compliance-framework-support");
    let state = test_shared_state_with_db(&db_path);
    Connection::open(&db_path)
        .expect("open sqlite db")
        .execute(
            "UPDATE storage_control SET min_retention_days = 3650 WHERE id = 1",
            [],
        )
        .expect("configure long retention");
    let app = app(state);

    let ingest_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "framework-session",
                        "agent": "runtime",
                        "type": "policy_check",
                        "timestamp": "2026-03-29T12:05:00Z",
                        "payload": {
                            "policy_refs": ["baseline"],
                            "status": "ok"
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ingest_response.status(), StatusCode::CREATED);

    let oversight_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/oversight")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "framework-session",
                        "framework": "hipaa",
                        "severity": "medium",
                        "note": "reviewed by analyst",
                        "timestamp": "2026-03-29T12:06:00Z"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(oversight_response.status(), StatusCode::CREATED);

    for framework in [
        "eu-ai-act",
        "nist-ai-rmf",
        "sr-11-7",
        "hipaa",
        "fda-21-cfr-part-11",
    ] {
        let response = app
            .clone()
            .oneshot(
                with_org_scope(Request::builder(), TEST_ORG_ID)
                    .uri(format!(
                        "/v1/compliance/{framework}?session_id=framework-session"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "{framework}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["framework"], framework);
        assert!(
            payload["controls_met"].as_array().unwrap().len()
                + payload["controls_gaps"].as_array().unwrap().len()
                > 0
        );
    }

    fs::remove_file(db_path).ok();
}

#[tokio::test]
async fn api_key_auth_is_enforced_when_configured() {
    let app = app(shared_state(Some("secret-key".to_string())));

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = app
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .header("x-api-key", "secret-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(authorized.status(), StatusCode::OK);
}

#[test]
fn api_keys_persist_roles_for_authenticated_principals() {
    let db_path = auth_db_path("api-key-roles");
    let storage = Storage::open(&db_path).expect("storage");

    let admin = storage
        .create_api_key("org-1", "bootstrap-admin")
        .expect("admin key");
    assert_eq!(admin.roles, vec![ApiKeyRole::Admin]);

    let service = storage
        .create_api_key("org-1", "default-service")
        .expect("service key");
    assert_eq!(
        service.roles,
        vec![ApiKeyRole::Ingest, ApiKeyRole::Query, ApiKeyRole::Export]
    );

    let custom = storage
        .create_api_key_with_roles("org-1", "query-only", Some(&[ApiKeyRole::Query]))
        .expect("custom key");
    assert_eq!(custom.roles, vec![ApiKeyRole::Query]);

    let authenticated = storage
        .authenticate_api_key(&custom.key)
        .expect("authenticate")
        .expect("principal");
    assert_eq!(authenticated.roles, vec![ApiKeyRole::Query]);

    let listed = storage.list_api_keys().expect("list");
    assert_eq!(listed[0].roles, vec![ApiKeyRole::Admin]);
    assert_eq!(
        listed[1].roles,
        vec![ApiKeyRole::Ingest, ApiKeyRole::Query, ApiKeyRole::Export]
    );
    assert_eq!(listed[2].roles, vec![ApiKeyRole::Query]);

    fs::remove_file(db_path).ok();
}

#[tokio::test]
async fn stored_api_keys_enable_route_level_authorization() {
    let db_path = auth_db_path("route-level-authorization");
    let storage = Storage::open(&db_path).expect("storage");
    storage
        .create_api_key("org-1", "bootstrap-admin")
        .expect("admin key");
    let query_key = storage
        .create_api_key_with_roles("org-1", "query-only", Some(&[ApiKeyRole::Query]))
        .expect("query key");
    let ingest_key = storage
        .create_api_key_with_roles("org-1", "ingest-only", Some(&[ApiKeyRole::Ingest]))
        .expect("ingest key");
    let export_key = storage
        .create_api_key_with_roles("org-1", "export-only", Some(&[ApiKeyRole::Export]))
        .expect("export key");
    drop(storage);

    let app = app(shared_state_with_db(&db_path, None).expect("sqlite state"));

    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .header("x-api-key", "trailing_invalid_key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);

    let query_ok = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .header("x-api-key", &query_key.key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(query_ok.status(), StatusCode::OK);

    let query_cannot_ingest = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/traces")
                .header("x-api-key", &query_key.key)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "query-denied",
                        "agent": "planner",
                        "type": "tool_call"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(query_cannot_ingest.status(), StatusCode::UNAUTHORIZED);
    let query_cannot_ingest_payload = response_json(query_cannot_ingest).await;
    assert_eq!(query_cannot_ingest_payload["code"], "UNAUTHORIZED");

    let ingest_ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/traces")
                .header("x-api-key", &ingest_key.key)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "ingest-ok",
                        "agent": "planner",
                        "type": "tool_call"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ingest_ok.status(), StatusCode::CREATED);

    let ingest_cannot_query = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .header("x-api-key", &ingest_key.key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ingest_cannot_query.status(), StatusCode::UNAUTHORIZED);

    let query_cannot_export = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/export/json")
                .header("x-api-key", &query_key.key)
                .header("content-type", "application/json")
                .body(Body::from(json!({ "org_id": "org-1" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(query_cannot_export.status(), StatusCode::UNAUTHORIZED);

    let export_ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/export/json")
                .header("x-api-key", &export_key.key)
                .header("content-type", "application/json")
                .body(Body::from(json!({ "org_id": "org-1" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export_ok.status(), StatusCode::OK);

    let export_can_query = app
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .header("x-api-key", &export_key.key)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export_can_query.status(), StatusCode::OK);

    fs::remove_file(db_path).ok();
}

#[tokio::test]
async fn trace_ingest_with_shared_api_key_requires_org_scope_and_scopes_reads() {
    let app = app(shared_state(Some("secret-key".to_string())));

    let missing_org = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/traces")
                .header("x-api-key", "secret-key")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "org-session",
                        "agent": "planner",
                        "type": "tool_call",
                        "payload": { "tool": "search" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Static API key auto-resolves to default org, so missing org header still succeeds
    assert_eq!(missing_org.status(), StatusCode::CREATED);

    let ingested = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/traces")
                .header("x-api-key", "secret-key")
                .header("x-trailing-org-id", "org-a")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "org-session",
                        "agent": "planner",
                        "type": "tool_call",
                        "payload": { "tool": "search" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ingested.status(), StatusCode::CREATED);

    // Static API key auto-resolves to default org, so "unscoped" requests now succeed
    let unscoped_actions = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/actions?session_id=org-session")
                .header("x-api-key", "secret-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unscoped_actions.status(), StatusCode::OK);

    let unscoped_compliance = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/compliance/eu-ai-act?session_id=org-session")
                .header("x-api-key", "secret-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unscoped_compliance.status(), StatusCode::OK);

    let unscoped_export = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/export/json")
                .header("x-api-key", "secret-key")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "framework": "eu-ai-act" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unscoped_export.status(), StatusCode::OK);

    let integrity = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/integrity")
                .header("x-api-key", "secret-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(integrity.status(), StatusCode::OK);

    let scoped = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/actions?session_id=org-session")
                .header("x-api-key", "secret-key")
                .header("x-trailing-org-id", "org-a")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let scoped_payload = response_json(scoped).await;
    assert_eq!(scoped_payload["actions"].as_array().unwrap().len(), 1);

    let other_org = app
        .oneshot(
            Request::builder()
                .uri("/v1/actions?session_id=org-session")
                .header("x-api-key", "secret-key")
                .header("x-trailing-org-id", "org-b")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let other_org_payload = response_json(other_org).await;
    assert_eq!(other_org_payload["actions"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn rate_limiting_returns_429_with_error_code() {
    let app = app(test_shared_state_with_options(AppOptions {
        rate_limit_per_minute: 2,
        rate_limit_per_hour: 120,
        org_rate_limits: HashMap::new(),
        cors_origins: Vec::new(),
        redact_fields: Vec::new(),
    }));

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .header("x-forwarded-for", "203.0.113.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    let limited = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .header("x-forwarded-for", "203.0.113.10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers().contains_key("x-request-id"));
    assert_eq!(
        limited.headers().get("x-trailing-version").unwrap(),
        TRAILING_VERSION
    );
    let payload = response_json(limited).await;
    assert_eq!(payload["code"], "RATE_LIMITED");
}

#[tokio::test]
async fn spoofed_forwarded_headers_do_not_bypass_rate_limiting() {
    let app = app(test_shared_state_with_options(AppOptions {
        rate_limit_per_minute: 1,
        rate_limit_per_hour: 60,
        org_rate_limits: HashMap::new(),
        cors_origins: Vec::new(),
        redact_fields: Vec::new(),
    }));

    let allowed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .header("x-forwarded-for", "203.0.113.10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);

    let limited = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .header("x-forwarded-for", "198.51.100.77")
                .header("x-real-ip", "198.51.100.77")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn default_cors_policy_does_not_allow_arbitrary_origins() {
    let app = app(test_shared_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .header("origin", "https://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-origin"),
        "default CORS policy should stay same-origin"
    );
}

#[tokio::test]
async fn actions_endpoint_returns_pagination_metadata() {
    let app = app(test_shared_state());
    let actions = (0..150)
        .map(|index| {
            json!({
                "session_id": "paged-session",
                "agent": format!("agent-{index}"),
                "type": "tool_call",
                "timestamp": format!("2026-03-29T12:{:02}:00Z", index % 60),
                "payload": { "index": index, "tool": "search" }
            })
        })
        .collect::<Vec<_>>();

    let ingest = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "actions": actions }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ingest.status(), StatusCode::CREATED);

    let default_page = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=paged-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(default_page.status(), StatusCode::OK);
    let default_payload = response_json(default_page).await;
    assert_eq!(default_payload["total"], 150);
    assert_eq!(default_payload["pagination"]["limit"], 100);
    assert_eq!(default_payload["pagination"]["offset"], 0);
    assert_eq!(default_payload["pagination"]["count"], 100);
    assert_eq!(default_payload["pagination"]["has_more"], true);
    assert_eq!(default_payload["actions"].as_array().unwrap().len(), 100);

    let paged = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=paged-session&limit=25&offset=120")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(paged.status(), StatusCode::OK);
    let payload = response_json(paged).await;
    assert_eq!(payload["total"], 150);
    assert_eq!(payload["pagination"]["limit"], 25);
    assert_eq!(payload["pagination"]["offset"], 120);
    assert_eq!(payload["pagination"]["count"], 25);
    assert_eq!(payload["pagination"]["has_more"], true);
    assert_eq!(payload["actions"].as_array().unwrap().len(), 25);
    assert_eq!(payload["actions"][0]["session_id"], "paged-session");
}

#[tokio::test]
async fn error_responses_include_consistent_codes() {
    let protected = app(shared_state(Some("secret-key".to_string())));
    let unauthorized = protected
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let unauthorized_payload = response_json(unauthorized).await;
    assert_eq!(unauthorized_payload["code"], "UNAUTHORIZED");

    let app = app(test_shared_state());

    let invalid_json = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from("{not-json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_json.status(), StatusCode::BAD_REQUEST);
    let invalid_json_payload = response_json(invalid_json).await;
    assert_eq!(invalid_json_payload["code"], "INVALID_JSON");

    let missing_field = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces/otlp")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "resourceSpans": [{
                            "scopeSpans": [{
                                "spans": [{ "name": "llm.call" }]
                            }]
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_field.status(), StatusCode::BAD_REQUEST);
    let missing_field_payload = response_json(missing_field).await;
    assert_eq!(missing_field_payload["code"], "MISSING_FIELD");

    let unsupported_framework = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri(format!(
                    "/v1/compliance/not-a-framework?org_id={TEST_ORG_ID}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsupported_framework.status(), StatusCode::NOT_FOUND);
    let unsupported_framework_payload = response_json(unsupported_framework).await;
    assert_eq!(
        unsupported_framework_payload["code"],
        "UNSUPPORTED_FRAMEWORK"
    );

    let not_found = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
    let not_found_payload = response_json(not_found).await;
    assert_eq!(not_found_payload["code"], "NOT_FOUND");
}

#[tokio::test]
async fn mfa_enrollment_totp_verification_and_audit_events_work() {
    let db_path = auth_db_path("mfa-totp");
    let storage = SqliteStorage::open(&db_path).expect("open sqlite db");
    storage
        .create_human_user(
            "org-mfa",
            "security@example.com",
            "correct horse battery staple",
        )
        .expect("create human user");

    let app = app(test_shared_state_with_db(&db_path));

    let enroll_start = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "org-mfa")
                .method("POST")
                .uri("/v1/auth/mfa/enroll/start")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": "org-mfa",
                        "email": "security@example.com",
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enroll_start.status(), StatusCode::OK);
    let enroll_start_payload = response_json(enroll_start).await;
    assert_eq!(enroll_start_payload["status"], "pending_confirmation");
    let secret = enroll_start_payload["secret"].as_str().unwrap().to_string();
    assert!(
        enroll_start_payload["provisioning_uri"]
            .as_str()
            .unwrap()
            .contains("otpauth://totp/Trailing:security@example.com")
    );

    let enroll_confirm = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "org-mfa")
                .method("POST")
                .uri("/v1/auth/mfa/enroll/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": "org-mfa",
                        "email": "security@example.com",
                        "password": "correct horse battery staple",
                        "code": totp_code(&secret),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enroll_confirm.status(), StatusCode::OK);
    let enroll_confirm_payload = response_json(enroll_confirm).await;
    assert_eq!(enroll_confirm_payload["status"], "enabled");
    assert_eq!(enroll_confirm_payload["mfa_status"], "enabled");
    assert_eq!(
        enroll_confirm_payload["recovery_codes"]
            .as_array()
            .unwrap()
            .len(),
        8
    );

    let challenge = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/challenge")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": "org-mfa",
                        "email": "security@example.com",
                        "password": "correct horse battery staple"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge_payload = response_json(challenge).await;
    assert_eq!(challenge_payload["status"], "challenge_required");
    let challenge_id = challenge_payload["challenge_id"]
        .as_str()
        .unwrap()
        .to_string();

    let verify = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/challenge/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "challenge_id": challenge_id,
                        "code": totp_code(&secret),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify.status(), StatusCode::OK);
    let verify_payload = response_json(verify).await;
    assert_eq!(verify_payload["status"], "authenticated");
    assert_eq!(verify_payload["method"], "totp");
    assert_eq!(verify_payload["mfa_status"], "verified_totp");

    let actions = app
        .oneshot(
            with_org_scope(Request::builder(), "org-mfa")
                .uri("/v1/actions?agent=security@example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(actions.status(), StatusCode::OK);
    let actions_payload = response_json(actions).await;
    let auth_events = actions_payload["actions"].as_array().unwrap();
    assert!(auth_events.iter().any(|action| {
        action["payload"]["event"] == "auth.mfa.enroll.confirm"
            && action["payload"]["mfa_status"] == "enabled"
    }));
    assert!(auth_events.iter().any(|action| {
        action["payload"]["event"] == "auth.mfa.verify"
            && action["payload"]["mfa_status"] == "verified_totp"
    }));

    fs::remove_file(db_path).ok();
}

#[tokio::test]
async fn required_org_policy_requires_enrollment_and_recovery_codes_are_one_time_use() {
    let db_path = auth_db_path("mfa-recovery");
    let storage = SqliteStorage::open(&db_path).expect("open sqlite db");
    storage
        .create_human_user("org-required", "analyst@example.com", "letmein")
        .expect("create human user");
    storage
        .set_org_mfa_policy("org-required", MfaPolicy::Required)
        .expect("set mfa policy");

    let app = app(test_shared_state_with_db(&db_path));

    let blocked = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/challenge")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": "org-required",
                        "email": "analyst@example.com",
                        "password": "letmein"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::OK);
    let blocked_payload = response_json(blocked).await;
    assert_eq!(blocked_payload["status"], "enrollment_required");
    assert_eq!(blocked_payload["mfa_status"], "required_not_enrolled");

    let enroll_start = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "org-required")
                .method("POST")
                .uri("/v1/auth/mfa/enroll/start")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": "org-required",
                        "email": "analyst@example.com",
                        "password": "letmein"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enroll_start.status(), StatusCode::OK);
    let enroll_start_payload = response_json(enroll_start).await;
    let secret = enroll_start_payload["secret"].as_str().unwrap().to_string();

    let enroll_confirm = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "org-required")
                .method("POST")
                .uri("/v1/auth/mfa/enroll/confirm")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": "org-required",
                        "email": "analyst@example.com",
                        "password": "letmein",
                        "code": totp_code(&secret),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enroll_confirm.status(), StatusCode::OK);
    let recovery_code = response_json(enroll_confirm).await["recovery_codes"][0]
        .as_str()
        .unwrap()
        .to_string();

    let challenge = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/challenge")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": "org-required",
                        "email": "analyst@example.com",
                        "password": "letmein"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge_id = response_json(challenge).await["challenge_id"]
        .as_str()
        .unwrap()
        .to_string();

    let verify = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/challenge/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "challenge_id": challenge_id,
                        "code": recovery_code,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify.status(), StatusCode::OK);
    let verify_payload = response_json(verify).await;
    assert_eq!(verify_payload["method"], "recovery_code");
    assert_eq!(verify_payload["recovery_code_used"], true);
    assert_eq!(verify_payload["mfa_status"], "verified_recovery_code");

    let second_challenge = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/challenge")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": "org-required",
                        "email": "analyst@example.com",
                        "password": "letmein"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_challenge.status(), StatusCode::OK);
    let second_challenge_id = response_json(second_challenge).await["challenge_id"]
        .as_str()
        .unwrap()
        .to_string();

    let reused = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/mfa/challenge/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "challenge_id": second_challenge_id,
                        "code": recovery_code,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reused.status(), StatusCode::UNAUTHORIZED);

    let policy = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "org-required")
                .uri("/v1/orgs/org-required/mfa-policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(policy.status(), StatusCode::OK);
    let policy_payload = response_json(policy).await;
    assert_eq!(policy_payload["policy"], "required");

    let update = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "org-required")
                .method("PUT")
                .uri("/v1/orgs/org-required/mfa-policy")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "policy": "optional" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let update_payload = response_json(update).await;
    assert_eq!(update_payload["policy"], "optional");

    fs::remove_file(db_path).ok();
}

#[tokio::test]
async fn trace_ingest_rejects_invalid_payload_shapes() {
    let app = app(test_shared_state());

    let response = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "invalid-shape",
                        "agent": "planner",
                        "type": "tool_call",
                        "payload": "not-an-object"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let payload = response_json(response).await;
    assert_eq!(payload["code"], "INVALID_JSON");
    assert!(payload["error"].as_str().unwrap().contains("payload"));
}

#[tokio::test]
async fn batch_trace_ingest_reports_partial_failures_per_item() {
    let app = app(test_shared_state());

    let response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces/batch")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "actions": [
                            {
                                "session_id": "batch-session",
                                "agent": "planner",
                                "type": "tool_call",
                                "payload": { "tool": "search" }
                            },
                            {
                                "agent": "planner",
                                "type": "tool_call",
                                "payload": { "tool": "search" }
                            }
                        ]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    let payload = response_json(response).await;
    assert_eq!(payload["ingested"], 1);
    assert_eq!(payload["failed"], 1);
    assert_eq!(payload["results"][0]["status"], "accepted");
    assert_eq!(payload["results"][1]["status"], "rejected");
    assert_eq!(payload["results"][1]["error"]["code"], "MISSING_FIELD");

    let actions = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=batch-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let actions_payload = response_json(actions).await;
    assert_eq!(actions_payload["actions"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn request_idempotency_key_reuses_existing_action_id() {
    let app = app(test_shared_state());
    let body = json!({
        "session_id": "idempotent-session",
        "agent": "planner",
        "type": "tool_call",
        "payload": { "tool": "search" }
    })
    .to_string();

    let first = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .header("idempotency-key", "req-123")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_payload = response_json(first).await;
    let action_id = first_payload["action_ids"][0].as_str().unwrap().to_string();

    let second = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .header("idempotency-key", "req-123")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_payload = response_json(second).await;
    assert_eq!(second_payload["ingested"], 0);
    assert_eq!(second_payload["action_ids"][0], action_id);

    let actions = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=idempotent-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let actions_payload = response_json(actions).await;
    assert_eq!(actions_payload["actions"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn configured_redaction_masks_matching_fields_before_persistence() {
    let app = app(test_shared_state_with_options(AppOptions {
        rate_limit_per_minute: 100,
        rate_limit_per_hour: 6000,
        org_rate_limits: HashMap::new(),
        cors_origins: Vec::new(),
        redact_fields: vec!["secret".to_string(), "token".to_string()],
    }));

    let ingest = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "redacted-session",
                        "agent": "planner",
                        "type": "tool_call",
                        "payload": {
                            "secret": "s3cr3t",
                            "nested": { "token": "abc123" }
                        },
                        "action": {
                            "type": "tool_call",
                            "parameters": {
                                "token": "another-secret"
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ingest.status(), StatusCode::CREATED);

    let actions = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=redacted-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let payload = response_json(actions).await;
    let action = &payload["actions"][0]["payload"];
    assert_eq!(action["payload"]["secret"], "[REDACTED]");
    assert_eq!(action["payload"]["nested"]["token"], "[REDACTED]");
    assert_eq!(action["action"]["parameters"]["token"], "[REDACTED]");
}

#[tokio::test]
async fn sqlite_actions_persist_across_restart_equivalent() {
    let db_path = temp_db_path("actions-persist");

    let action_id = {
        let app = app(test_shared_state_with_db(&db_path));
        let ingest_response = app
            .oneshot(
                with_org_scope(Request::builder(), TEST_ORG_ID)
                    .method("POST")
                    .uri("/v1/traces")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "actions": [
                                {
                                    "session_id": "persist-session",
                                    "agent": "planner",
                                    "type": "tool_call",
                                    "timestamp": "2026-03-29T13:00:00Z",
                                    "payload": { "tool": "search" }
                                }
                            ]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(ingest_response.status(), StatusCode::CREATED);
        let ingest_body = to_bytes(ingest_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let ingest_value: Value = serde_json::from_slice(&ingest_body).unwrap();
        ingest_value["action_ids"][0].as_str().unwrap().to_string()
    };

    let app = app(test_shared_state_with_db(&db_path));
    let query_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=persist-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(query_response.status(), StatusCode::OK);
    let query_body = to_bytes(query_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let query_value: Value = serde_json::from_slice(&query_body).unwrap();
    assert_eq!(query_value["actions"].as_array().unwrap().len(), 1);
    assert_eq!(query_value["actions"][0]["id"], action_id);

    let single_response = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri(format!("/v1/actions/{action_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(single_response.status(), StatusCode::OK);
    let single_body = to_bytes(single_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let single_value: Value = serde_json::from_slice(&single_body).unwrap();
    assert_eq!(single_value["session_id"], "persist-session");

    let _ = fs::remove_file(db_path);
}

#[tokio::test]
async fn sqlite_chain_and_oversight_persist_across_restart_equivalent() {
    let db_path = temp_db_path("oversight-persist");

    {
        let app = app(test_shared_state_with_db(&db_path));

        let trace_response = app
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
                                    "session_id": "persist-trace",
                                    "agent": "runtime",
                                    "type": "decision",
                                    "timestamp": "2026-03-29T14:00:00Z"
                                }
                            ]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(trace_response.status(), StatusCode::CREATED);

        let oversight_response = app
            .oneshot(
                with_org_scope(Request::builder(), TEST_ORG_ID)
                    .method("POST")
                    .uri("/v1/oversight")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "org_id": TEST_ORG_ID,
                            "session_id": "persist-trace",
                            "framework": "eu-ai-act",
                            "severity": "high",
                            "note": "manual review recorded",
                            "timestamp": "2026-03-29T14:01:00Z"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(oversight_response.status(), StatusCode::CREATED);
    }

    let app = app(test_shared_state_with_db(&db_path));

    let export_response = app
        .clone()
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
        .unwrap();

    assert_eq!(export_response.status(), StatusCode::OK);
    let export_body = to_bytes(export_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let export_value: Value = serde_json::from_slice(&export_body).unwrap();
    assert_eq!(export_value["actions"].as_array().unwrap().len(), 1);
    assert_eq!(
        export_value["oversight_events"].as_array().unwrap().len(),
        1
    );
    assert!(
        export_value["package"]["chain_integrity_status"]["proofs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|proof| {
                proof["scope"] == "root_anchor_hash"
                    && proof["verified"].as_bool() == Some(true)
                    && proof["value"]
                        .as_str()
                        .unwrap()
                        .contains("root_anchor_hash")
            })
    );

    let integrity_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/integrity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(integrity_response.status(), StatusCode::OK);
    let integrity_body = to_bytes(integrity_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let integrity_value: Value = serde_json::from_slice(&integrity_body).unwrap();
    assert_eq!(integrity_value["valid"], true);
    assert_eq!(integrity_value["checked_entries"], 2);
    assert_eq!(integrity_value["root_anchor_persisted"], true);
    assert!(integrity_value["root_anchor_hash"].is_string());

    let _ = fs::remove_file(db_path);
}

#[tokio::test]
async fn org_settings_crud_persists_across_restart_equivalent() {
    let db_path = temp_db_path("org-settings-persist");

    let initial_app = app(test_shared_state_with_db(&db_path));
    let created = initial_app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .method("PUT")
                .uri("/v1/orgs/acme/settings")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "retention_policy": {
                            "min_retention_days": 180,
                            "legal_hold": true
                        },
                        "enabled_frameworks": ["hipaa", "eu-ai-act"],
                        "guardrail_settings": {
                            "human_review_required": true
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(created.status(), StatusCode::CREATED);
    let created_payload = response_json(created).await;
    assert_eq!(created_payload["org_id"], "acme");
    assert_eq!(
        created_payload["retention_policy"]["min_retention_days"],
        180
    );
    assert_eq!(created_payload["retention_policy"]["legal_hold"], true);
    assert_eq!(
        created_payload["enabled_frameworks"],
        json!(["eu-ai-act", "hipaa"])
    );
    assert_eq!(
        created_payload["guardrail_settings"]["human_review_required"],
        true
    );

    let restarted = app(test_shared_state_with_db(&db_path));
    let fetched = restarted
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .uri("/v1/orgs/acme/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(fetched.status(), StatusCode::OK);
    let fetched_payload = response_json(fetched).await;
    assert_eq!(fetched_payload["org_id"], "acme");
    assert_eq!(fetched_payload["retention_policy"]["legal_hold"], true);

    let updated = restarted
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .method("PUT")
                .uri("/v1/orgs/acme/settings")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "retention_policy": {
                            "min_retention_days": 365
                        },
                        "enabled_frameworks": ["eu-ai-act"],
                        "guardrail_settings": {
                            "approval_required": true
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(updated.status(), StatusCode::OK);
    let updated_payload = response_json(updated).await;
    assert_eq!(
        updated_payload["retention_policy"]["min_retention_days"],
        365
    );
    assert_eq!(updated_payload["enabled_frameworks"], json!(["eu-ai-act"]));
    assert_eq!(
        updated_payload["guardrail_settings"]["approval_required"],
        true
    );

    let deleted = restarted
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .method("DELETE")
                .uri("/v1/orgs/acme/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let missing = restarted
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .uri("/v1/orgs/acme/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let _ = fs::remove_file(db_path);
}

#[tokio::test]
async fn org_settings_are_applied_to_compliance_and_export_paths() {
    let app = app(test_shared_state());

    let settings = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .method("PUT")
                .uri("/v1/orgs/acme/settings")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "retention_policy": {
                            "min_retention_days": 180
                        },
                        "enabled_frameworks": ["eu-ai-act"],
                        "guardrail_settings": {
                            "human_review_required": true
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(settings.status(), StatusCode::CREATED);

    let ingest = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": "acme",
                        "session_id": "org-scope",
                        "agent": "planner",
                        "type": "tool_call",
                        "timestamp": "2026-03-29T15:00:00Z",
                        "payload": { "tool": "search" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ingest.status(), StatusCode::CREATED);

    let compliance = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .uri("/v1/compliance/eu-ai-act?org_id=acme&session_id=org-scope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(compliance.status(), StatusCode::OK);
    let compliance_payload = response_json(compliance).await;
    let met_ids = compliance_payload["controls_met"]
        .as_array()
        .unwrap()
        .iter()
        .map(|control| control["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(met_ids.contains(&"EU-AIA-14".to_string()));
    assert!(met_ids.contains(&"EU-AIA-19".to_string()));
    let evidence_refs = compliance_payload["evidence_refs"].as_array().unwrap();
    assert!(
        evidence_refs
            .iter()
            .any(|value| { value.as_str().unwrap() == "org_settings:acme:retention_policy" })
    );
    assert!(
        evidence_refs
            .iter()
            .any(|value| { value.as_str().unwrap() == "org_settings:acme:guardrail_settings" })
    );

    let export_json = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .method("POST")
                .uri("/v1/export/json")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "framework": "eu-ai-act",
                        "org_id": "acme"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(export_json.status(), StatusCode::OK);
    let export_json_payload = response_json(export_json).await;
    assert_eq!(export_json_payload["org_id"], "acme");
    assert_eq!(export_json_payload["org_settings"]["org_id"], "acme");
    assert_eq!(export_json_payload["actions"].as_array().unwrap().len(), 1);

    let export_pdf = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .method("POST")
                .uri("/v1/export/pdf")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "framework": "eu-ai-act",
                        "org_id": "acme"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(export_pdf.status(), StatusCode::OK);
    let export_pdf_body = to_bytes(export_pdf.into_body(), usize::MAX).await.unwrap();
    let export_pdf_text = String::from_utf8_lossy(&export_pdf_body);
    assert!(export_pdf_text.contains("Organization: acme"));
    assert!(export_pdf_text.contains("Organization retention policy configured"));

    let disabled_framework = app
        .oneshot(
            with_org_scope(Request::builder(), "acme")
                .uri("/v1/compliance/hipaa?org_id=acme&session_id=org-scope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(disabled_framework.status(), StatusCode::BAD_REQUEST);
    let disabled_payload = response_json(disabled_framework).await;
    assert_eq!(disabled_payload["code"], "INVALID_REQUEST");
}
