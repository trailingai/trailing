use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rusqlite::Connection;
use serde_json::{Value, json};
use tower::ServiceExt;

use trailing::{
    api::{app, shared_state_with_db},
    log::GENESIS_HASH,
    storage::{SqliteStorage, initialize_schema},
};

fn temp_db_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "trailing-auth-audit-{test_name}-{}-{nanos}.db",
        std::process::id()
    ))
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("json response")
}

fn auth_audit_db_path(test_name: &str) -> PathBuf {
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

        CREATE TRIGGER IF NOT EXISTS auth_audit_log_reject_update
        BEFORE UPDATE ON auth_audit_log
        BEGIN
            SELECT RAISE(ABORT, 'auth_audit_log is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS auth_audit_log_reject_delete
        BEFORE DELETE ON auth_audit_log
        BEGIN
            SELECT RAISE(ABORT, 'auth_audit_log deletes are blocked');
        END;
        ",
    )
    .expect("create auth audit schema");
    db_path
}

#[test]
fn auth_audit_log_records_identity_actions_in_order() {
    let db_path = auth_audit_db_path("records-in-order");
    let storage = SqliteStorage::open(&db_path).expect("sqlite storage");

    let created = storage
        .create_api_key("org-auth", "primary")
        .expect("create key");
    let authenticated = storage
        .authenticate_api_key(&created.key)
        .expect("authenticate")
        .expect("authenticated key");
    assert_eq!(authenticated.id, created.id);
    storage
        .record_role_change(
            Some("org-auth"),
            "api_key",
            Some(created.id.as_str()),
            "user",
            "user-123",
            Some("viewer"),
            "admin",
        )
        .expect("role change");
    storage
        .record_permission_grant(
            Some("org-auth"),
            "api_key",
            Some(created.id.as_str()),
            "user",
            "user-123",
            "phi_read",
            Some("claims"),
        )
        .expect("permission grant");
    assert!(storage.revoke_api_key(&created.id).expect("revoke key"));

    let events = storage.auth_audit_entries().expect("auth audit entries");
    let event_types = events
        .iter()
        .map(|event| event.event_type.to_string())
        .collect::<Vec<_>>();

    assert_eq!(
        event_types,
        vec![
            "key_creation",
            "login",
            "role_change",
            "permission_grant",
            "key_revocation",
        ]
    );
    assert_eq!(events[0].subject_id, created.id);
    assert_eq!(events[0].previous_hash, GENESIS_HASH);
    assert_eq!(events[1].actor_id.as_deref(), Some(created.id.as_str()));
    assert_eq!(events[1].previous_hash, events[0].entry_hash);
    assert_eq!(events[2].payload["new_role"], "admin");
    assert_eq!(events[3].payload["permission"], "phi_read");
    assert_eq!(events[4].outcome, "revoked");

    let _ = fs::remove_file(db_path);
}

#[test]
fn auth_audit_log_rejects_updates() {
    let db_path = auth_audit_db_path("rejects-updates");
    let storage = SqliteStorage::open(&db_path).expect("sqlite storage");
    let created = storage
        .create_api_key("org-auth", "primary")
        .expect("create key");

    let error = storage
        .connection()
        .execute(
            "UPDATE auth_audit_log SET outcome = 'tampered' WHERE subject_id = ?1",
            [created.id],
        )
        .expect_err("update should be blocked");

    assert!(error.to_string().contains("append-only"));

    let _ = fs::remove_file(db_path);
}

#[tokio::test]
async fn auth_audit_query_and_export_are_isolated_from_actions() {
    let db_path = auth_audit_db_path("api-isolation");
    let key_id = {
        let storage = SqliteStorage::open(&db_path).expect("sqlite storage");
        let created = storage
            .create_api_key("org-auth", "primary")
            .expect("create key");
        storage
            .authenticate_api_key(&created.key)
            .expect("authenticate")
            .expect("authenticated key");
        storage
            .record_role_change(
                Some("org-auth"),
                "api_key",
                Some(created.id.as_str()),
                "user",
                "user-123",
                Some("viewer"),
                "admin",
            )
            .expect("role change");
        storage
            .record_permission_grant(
                Some("org-auth"),
                "api_key",
                Some(created.id.as_str()),
                "user",
                "user-123",
                "phi_read",
                Some("claims"),
            )
            .expect("permission grant");
        storage.revoke_api_key(&created.id).expect("revoke key");
        created.id
    };

    let app =
        app(shared_state_with_db(&db_path, Some("secret-key".to_string())).expect("sqlite state"));

    let actions_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/actions")
                .header("x-api-key", "secret-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Static API key auto-resolves to default org, so unscoped requests succeed
    assert_eq!(actions_response.status(), StatusCode::OK);

    // Static key auto-resolves to default org; must pass org header for org-auth data
    let query_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/audit?org_id=org-auth&type=permission_grant")
                .header("x-api-key", "secret-key")
                .header("x-trailing-org-id", "org-auth")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(query_response.status(), StatusCode::OK);
    let query_payload = response_json(query_response).await;
    assert_eq!(query_payload["total"], 1);
    assert_eq!(query_payload["events"].as_array().unwrap().len(), 1);
    assert_eq!(query_payload["events"][0]["event_type"], "permission_grant");
    assert_eq!(query_payload["events"][0]["actor_id"], key_id);

    let export_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/audit/export")
                .header("x-api-key", "secret-key")
                .header("x-trailing-org-id", "org-auth")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "org_id": "org-auth",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export_response.status(), StatusCode::OK);
    let export_payload = response_json(export_response).await;
    assert_eq!(export_payload["count"], 5);
    assert_eq!(export_payload["filters"]["org_id"], "org-auth");
    assert_eq!(export_payload["events"].as_array().unwrap().len(), 5);
    assert!(export_payload.get("actions").is_none());

    let _ = fs::remove_file(db_path);
}
