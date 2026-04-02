use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, request::Builder},
};
use rusqlite::Connection;
use serde_json::{Value, json};
use tower::ServiceExt;

use trailing::api::{app, shared_state_with_db};

const TEST_API_KEY: &str = "integration-test-api-key";
const TEST_ORG_ID: &str = "integration-org";

fn with_api_key(builder: Builder) -> Builder {
    builder.header("x-api-key", TEST_API_KEY)
}

fn with_org_scope(builder: Builder, org_id: &str) -> Builder {
    with_api_key(builder).header("x-trailing-org-id", org_id)
}

fn test_shared_state_with_db(path: impl AsRef<Path>) -> trailing::api::SharedState {
    shared_state_with_db(path, Some(TEST_API_KEY.to_string())).expect("shared state with db")
}

fn temp_db_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "trailing-integration-{test_name}-{}-{nanos}.db",
        std::process::id()
    ))
}

fn root_anchor_path(path: &Path) -> PathBuf {
    let mut anchor_path = path.as_os_str().to_os_string();
    anchor_path.push(".root");
    PathBuf::from(anchor_path)
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    serde_json::from_slice(&body).expect("response must be valid json")
}

#[tokio::test]
async fn ingest_query_evaluate_and_export_pdf_end_to_end() {
    let db_path = temp_db_path("e2e");
    let conn = Connection::open(&db_path).expect("open sqlite connection");
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS storage_control (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            allow_purge INTEGER NOT NULL DEFAULT 0 CHECK (allow_purge IN (0, 1)),
            min_retention_days INTEGER NOT NULL DEFAULT 0,
            purge_through_sequence INTEGER
        );
        INSERT OR IGNORE INTO storage_control (
            id,
            allow_purge,
            min_retention_days,
            purge_through_sequence
        )
        VALUES (1, 0, 0, NULL);
        UPDATE storage_control SET min_retention_days = 180 WHERE id = 1;
        ",
    )
    .expect("seed retention policy");
    drop(conn);

    let app = app(test_shared_state_with_db(&db_path));

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
                                "session_id": "session-e2e",
                                "agent": "planner",
                                "agent_type": "codex",
                                "type": "policy_check",
                                "timestamp": "2026-03-29T12:00:00Z",
                                "payload": {
                                    "policy": "eu-ai-act",
                                    "check": "logging controls"
                                }
                            },
                            {
                                "session_id": "session-e2e",
                                "agent": "planner",
                                "agent_type": "codex",
                                "type": "tool_call",
                                "timestamp": "2026-03-29T12:00:05Z",
                                "payload": {
                                    "tool": "search",
                                    "transparency_notice": "shown to operator"
                                }
                            }
                        ]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("ingest request should succeed");

    assert_eq!(ingest_response.status(), StatusCode::CREATED);
    let ingest_value = response_json(ingest_response).await;
    assert_eq!(ingest_value["action_ids"].as_array().unwrap().len(), 2);

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
                        "session_id": "session-e2e",
                        "framework": "eu-ai-act",
                        "severity": "high",
                        "note": "human oversight completed",
                        "timestamp": "2026-03-29T12:01:00Z",
                        "reviewer": "alice"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("oversight request should succeed");

    assert_eq!(oversight_response.status(), StatusCode::CREATED);

    let actions_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/actions?session_id=session-e2e")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("actions query should succeed");

    assert_eq!(actions_response.status(), StatusCode::OK);
    let actions_value = response_json(actions_response).await;
    let actions = actions_value["actions"].as_array().unwrap();
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0]["type"], "policy_check");
    assert_eq!(actions[1]["type"], "tool_call");
    assert_eq!(actions[1]["previous_hash"], actions[0]["hash"]);

    let compliance_response = app
        .clone()
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri(format!(
                    "/v1/compliance/eu-ai-act?org_id={TEST_ORG_ID}&session_id=session-e2e"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("compliance query should succeed");

    assert_eq!(compliance_response.status(), StatusCode::OK);
    let compliance_value = response_json(compliance_response).await;
    assert_eq!(compliance_value["framework"], "eu-ai-act");
    assert_eq!(compliance_value["score"], 100);
    assert_eq!(
        compliance_value["controls_gaps"].as_array().unwrap().len(),
        0
    );
    assert_eq!(
        compliance_value["controls_met"].as_array().unwrap().len(),
        5
    );

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
        .expect("json export should succeed");

    assert_eq!(export_json_response.status(), StatusCode::OK);
    let export_json_value = response_json(export_json_response).await;
    assert_eq!(export_json_value["framework"], "eu-ai-act");
    assert_eq!(export_json_value["actions"].as_array().unwrap().len(), 2);
    assert_eq!(
        export_json_value["oversight_events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(export_json_value["integrity"]["valid"].is_boolean());

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
        .expect("pdf export should succeed");

    assert_eq!(export_pdf_response.status(), StatusCode::OK);
    let pdf_body = to_bytes(export_pdf_response.into_body(), usize::MAX)
        .await
        .expect("read pdf body");
    let pdf_text = String::from_utf8_lossy(&pdf_body);

    assert!(pdf_body.starts_with(b"%PDF-1."));
    assert!(pdf_text.contains("Compliance export for eu-ai-act"));
    assert!(pdf_text.contains("Chain Integrity"));
    assert!(pdf_text.contains("Action Timeline"));
    assert!(pdf_text.contains("Oversight Log"));
    assert!(pdf_text.contains("Compliance Matrix"));

    let integrity_response = app
        .oneshot(
            with_org_scope(Request::builder(), TEST_ORG_ID)
                .uri("/v1/integrity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("integrity request should succeed");

    assert_eq!(integrity_response.status(), StatusCode::OK);
    let integrity_value = response_json(integrity_response).await;
    assert!(integrity_value["valid"].is_boolean());
    assert_eq!(integrity_value["checked_entries"], 3);

    let _ = fs::remove_file(root_anchor_path(&db_path));
    let _ = fs::remove_file(db_path);
}
