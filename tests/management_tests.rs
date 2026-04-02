use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt;

use trailing::api::{app, shared_state};

async fn response_json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn json_request(method: Method, uri: &str, body: Value, api_key: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    if let Some(api_key) = api_key {
        builder = builder.header("x-api-key", api_key);
    }

    builder.body(Body::from(body.to_string())).unwrap()
}

fn empty_request(method: Method, uri: &str, api_key: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(api_key) = api_key {
        builder = builder.header("x-api-key", api_key);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
#[ignore = "legacy management routes are no longer exposed by the API"]
async fn org_and_key_management_routes_work() {
    let app = app(shared_state(None));

    let alpha_org = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/orgs",
            json!({
                "id": "org-alpha",
                "name": "Alpha Health",
            }),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(alpha_org.status(), StatusCode::CREATED);

    let beta_org = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/orgs",
            json!({
                "id": "org-beta",
                "name": "Beta Bank",
            }),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(beta_org.status(), StatusCode::CREATED);

    let first_key = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/keys",
            json!({
                "org_id": "org-alpha",
                "name": "alpha-admin",
            }),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(first_key.status(), StatusCode::CREATED);
    let first_key_body = response_json(first_key).await;
    let admin_key = first_key_body["key"].as_str().unwrap().to_string();
    assert_eq!(first_key_body["is_admin"], true);

    let orgs = app
        .clone()
        .oneshot(empty_request(Method::GET, "/v1/orgs", Some(&admin_key)))
        .await
        .unwrap();
    assert_eq!(orgs.status(), StatusCode::OK);
    let orgs_body = response_json(orgs).await;
    assert_eq!(orgs_body.as_array().unwrap().len(), 2);

    let patched_org = app
        .clone()
        .oneshot(json_request(
            Method::PATCH,
            "/v1/orgs",
            json!({
                "id": "org-alpha",
                "name": "Alpha Health System",
            }),
            Some(&admin_key),
        ))
        .await
        .unwrap();
    assert_eq!(patched_org.status(), StatusCode::OK);
    let patched_org_body = response_json(patched_org).await;
    assert_eq!(patched_org_body["name"], "Alpha Health System");

    let created_member = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/orgs/org-alpha/members",
            json!({
                "email": "risk@alpha.example",
                "role": "admin",
                "name": "Risk Lead",
            }),
            Some(&admin_key),
        ))
        .await
        .unwrap();
    assert_eq!(created_member.status(), StatusCode::CREATED);

    let members = app
        .clone()
        .oneshot(empty_request(
            Method::GET,
            "/v1/orgs/org-alpha/members",
            Some(&admin_key),
        ))
        .await
        .unwrap();
    assert_eq!(members.status(), StatusCode::OK);
    let members_body = response_json(members).await;
    assert_eq!(members_body.as_array().unwrap().len(), 1);
    assert_eq!(members_body[0]["email"], "risk@alpha.example");

    let beta_key = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/keys",
            json!({
                "org_id": "org-beta",
                "name": "beta-service",
            }),
            Some(&admin_key),
        ))
        .await
        .unwrap();
    assert_eq!(beta_key.status(), StatusCode::CREATED);
    let beta_key_body = response_json(beta_key).await;
    let beta_key_id = beta_key_body["id"].as_str().unwrap().to_string();
    assert_eq!(beta_key_body["is_admin"], false);

    let unauthorized_list = app
        .clone()
        .oneshot(empty_request(Method::GET, "/v1/keys", None))
        .await
        .unwrap();
    assert_eq!(unauthorized_list.status(), StatusCode::UNAUTHORIZED);

    let rotated_key = app
        .clone()
        .oneshot(empty_request(
            Method::POST,
            &format!("/v1/keys/{beta_key_id}/rotate"),
            Some(&admin_key),
        ))
        .await
        .unwrap();
    assert_eq!(rotated_key.status(), StatusCode::OK);
    let rotated_key_body = response_json(rotated_key).await;
    let rotated_key_id = rotated_key_body["id"].as_str().unwrap().to_string();
    assert_ne!(rotated_key_id, beta_key_id);

    let revoked_key = app
        .clone()
        .oneshot(empty_request(
            Method::DELETE,
            &format!("/v1/keys/{rotated_key_id}"),
            Some(&admin_key),
        ))
        .await
        .unwrap();
    assert_eq!(revoked_key.status(), StatusCode::OK);

    let keys = app
        .oneshot(empty_request(Method::GET, "/v1/keys", Some(&admin_key)))
        .await
        .unwrap();
    assert_eq!(keys.status(), StatusCode::OK);
    let keys_body = response_json(keys).await;
    assert_eq!(keys_body.as_array().unwrap().len(), 3);
    assert_eq!(
        keys_body
            .as_array()
            .unwrap()
            .iter()
            .filter(|value| value["revoked"] == Value::Bool(true))
            .count(),
        2
    );
}

#[tokio::test]
#[ignore = "legacy management routes are no longer exposed by the API"]
async fn cross_org_isolation_prevents_reads_across_tenants() {
    let app = app(shared_state(None));

    let org_a = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/orgs",
            json!({
                "id": "org-a",
                "name": "Org A",
            }),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(org_a.status(), StatusCode::CREATED);

    let org_b = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/orgs",
            json!({
                "id": "org-b",
                "name": "Org B",
            }),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(org_b.status(), StatusCode::CREATED);

    let org_a_key_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/keys",
            json!({
                "org_id": "org-a",
                "name": "org-a-admin",
            }),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(org_a_key_response.status(), StatusCode::CREATED);
    let org_a_key_body = response_json(org_a_key_response).await;
    let org_a_key = org_a_key_body["key"].as_str().unwrap().to_string();

    let org_b_key_response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/keys",
            json!({
                "org_id": "org-b",
                "name": "org-b-service",
            }),
            Some(&org_a_key),
        ))
        .await
        .unwrap();
    assert_eq!(org_b_key_response.status(), StatusCode::CREATED);
    let org_b_key_body = response_json(org_b_key_response).await;
    let org_b_key = org_b_key_body["key"].as_str().unwrap().to_string();

    let org_a_ingest = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/traces",
            json!({
                "actions": [
                    {
                        "session_id": "session-a",
                        "agent": "planner-a",
                        "agent_type": "orchestrator",
                        "type": "tool_call",
                        "timestamp": "2026-03-30T12:00:00Z",
                        "payload": { "tool": "search-a" }
                    }
                ]
            }),
            Some(&org_a_key),
        ))
        .await
        .unwrap();
    assert_eq!(org_a_ingest.status(), StatusCode::CREATED);
    let org_a_ingest_body = response_json(org_a_ingest).await;
    let org_a_action_id = org_a_ingest_body["action_ids"][0]
        .as_str()
        .unwrap()
        .to_string();

    let org_b_ingest = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/v1/traces",
            json!({
                "actions": [
                    {
                        "session_id": "session-b",
                        "agent": "planner-b",
                        "agent_type": "orchestrator",
                        "type": "tool_call",
                        "timestamp": "2026-03-30T12:05:00Z",
                        "payload": { "tool": "search-b" }
                    }
                ]
            }),
            Some(&org_b_key),
        ))
        .await
        .unwrap();
    assert_eq!(org_b_ingest.status(), StatusCode::CREATED);
    let org_b_ingest_body = response_json(org_b_ingest).await;
    let org_b_action_id = org_b_ingest_body["action_ids"][0]
        .as_str()
        .unwrap()
        .to_string();

    let org_a_actions = app
        .clone()
        .oneshot(empty_request(Method::GET, "/v1/actions", Some(&org_a_key)))
        .await
        .unwrap();
    assert_eq!(org_a_actions.status(), StatusCode::OK);
    let org_a_actions_body = response_json(org_a_actions).await;
    assert_eq!(org_a_actions_body["total"], 1);
    assert_eq!(org_a_actions_body["actions"][0]["id"], org_a_action_id);
    assert_eq!(org_a_actions_body["actions"][0]["session_id"], "session-a");

    let org_b_actions = app
        .clone()
        .oneshot(empty_request(Method::GET, "/v1/actions", Some(&org_b_key)))
        .await
        .unwrap();
    assert_eq!(org_b_actions.status(), StatusCode::OK);
    let org_b_actions_body = response_json(org_b_actions).await;
    assert_eq!(org_b_actions_body["total"], 1);
    assert_eq!(org_b_actions_body["actions"][0]["id"], org_b_action_id);
    assert_eq!(org_b_actions_body["actions"][0]["session_id"], "session-b");

    let org_a_cannot_read_b = app
        .clone()
        .oneshot(empty_request(
            Method::GET,
            &format!("/v1/actions/{org_b_action_id}"),
            Some(&org_a_key),
        ))
        .await
        .unwrap();
    assert_eq!(org_a_cannot_read_b.status(), StatusCode::NOT_FOUND);

    let org_a_export = app
        .oneshot(json_request(
            Method::POST,
            "/v1/export/json",
            json!({ "framework": "generic" }),
            Some(&org_a_key),
        ))
        .await
        .unwrap();
    assert_eq!(org_a_export.status(), StatusCode::OK);
    let org_a_export_body = response_json(org_a_export).await;
    assert_eq!(org_a_export_body["actions"].as_array().unwrap().len(), 1);
    assert_eq!(org_a_export_body["actions"][0]["session_id"], "session-a");
}
