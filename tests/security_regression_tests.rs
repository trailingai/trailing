use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, request::Builder},
};
use chrono::Utc;
use rusqlite::Connection;
use serde_json::{Value, json};
use tower::ServiceExt;

use trailing::{
    api::{TRAILING_VERSION, app, shared_state, shared_state_with_db},
    storage::{ApiKeyRole, Storage, initialize_schema},
};

const TEST_API_KEY: &str = "security-test-api-key";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RouteCase {
    method: &'static str,
    template_path: &'static str,
    concrete_path: &'static str,
    public_without_auth: bool,
}

const ROUTES: &[RouteCase] = &[
    RouteCase {
        method: "GET",
        template_path: "/v1/openapi.yml",
        concrete_path: "/v1/openapi.yml",
        public_without_auth: false,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/traces",
        concrete_path: "/v1/traces",
        public_without_auth: false,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/traces/batch",
        concrete_path: "/v1/traces/batch",
        public_without_auth: false,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/traces/otlp",
        concrete_path: "/v1/traces/otlp",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/me",
        concrete_path: "/v1/me",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/events",
        concrete_path: "/v1/events",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/actions",
        concrete_path: "/v1/actions",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/actions/{id}",
        concrete_path: "/v1/actions/test-action",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/auth/audit",
        concrete_path: "/v1/auth/audit",
        public_without_auth: false,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/auth/audit/export",
        concrete_path: "/v1/auth/audit/export",
        public_without_auth: false,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/auth/mfa/challenge",
        concrete_path: "/v1/auth/mfa/challenge",
        public_without_auth: true,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/auth/mfa/challenge/verify",
        concrete_path: "/v1/auth/mfa/challenge/verify",
        public_without_auth: true,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/auth/mfa/enroll/start",
        concrete_path: "/v1/auth/mfa/enroll/start",
        public_without_auth: false,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/auth/mfa/enroll/confirm",
        concrete_path: "/v1/auth/mfa/enroll/confirm",
        public_without_auth: false,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/oversight",
        concrete_path: "/v1/oversight",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/orgs/{org_id}/settings",
        concrete_path: "/v1/orgs/org-a/settings",
        public_without_auth: false,
    },
    RouteCase {
        method: "PUT",
        template_path: "/v1/orgs/{org_id}/settings",
        concrete_path: "/v1/orgs/org-a/settings",
        public_without_auth: false,
    },
    RouteCase {
        method: "DELETE",
        template_path: "/v1/orgs/{org_id}/settings",
        concrete_path: "/v1/orgs/org-a/settings",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/orgs/{org_id}/mfa-policy",
        concrete_path: "/v1/orgs/org-a/mfa-policy",
        public_without_auth: false,
    },
    RouteCase {
        method: "PUT",
        template_path: "/v1/orgs/{org_id}/mfa-policy",
        concrete_path: "/v1/orgs/org-a/mfa-policy",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/admin/orgs/{org_id}/sso/saml",
        concrete_path: "/v1/admin/orgs/org-a/sso/saml",
        public_without_auth: false,
    },
    RouteCase {
        method: "PUT",
        template_path: "/v1/admin/orgs/{org_id}/sso/saml",
        concrete_path: "/v1/admin/orgs/org-a/sso/saml",
        public_without_auth: false,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/sso/saml/{org_id}/acs",
        concrete_path: "/v1/sso/saml/org-a/acs",
        public_without_auth: true,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/compliance/{framework}",
        concrete_path: "/v1/compliance/eu-ai-act",
        public_without_auth: false,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/export/json",
        concrete_path: "/v1/export/json",
        public_without_auth: false,
    },
    RouteCase {
        method: "POST",
        template_path: "/v1/export/pdf",
        concrete_path: "/v1/export/pdf",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/integrity",
        concrete_path: "/v1/integrity",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/checkpoints",
        concrete_path: "/v1/checkpoints",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/checkpoints/{id}",
        concrete_path: "/v1/checkpoints/test-checkpoint",
        public_without_auth: false,
    },
    RouteCase {
        method: "GET",
        template_path: "/v1/health",
        concrete_path: "/v1/health",
        public_without_auth: true,
    },
];

fn with_api_key(builder: Builder, api_key: &str) -> Builder {
    builder.header("x-api-key", api_key)
}

fn temp_db_path(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "trailing-security-regression-{test_name}-{}-{nanos}.db",
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

fn ensure_saml_config_table(path: impl AsRef<std::path::Path>) {
    Connection::open(path)
        .expect("open sqlite db")
        .execute_batch(
            "
            CREATE TABLE IF NOT EXISTS saml_idp_configs (
                org_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                idp_entity_id TEXT NOT NULL,
                sso_url TEXT NOT NULL,
                idp_certificate_pem TEXT NOT NULL,
                sp_entity_id TEXT NOT NULL,
                acs_url TEXT NOT NULL,
                email_attribute TEXT NOT NULL,
                first_name_attribute TEXT,
                last_name_attribute TEXT,
                role_attribute TEXT,
                role_mappings TEXT NOT NULL,
                default_role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            ",
        )
        .expect("create saml config table");
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("valid json response")
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
    String::from_utf8(output.stdout)
        .expect("totp output utf8")
        .trim()
        .to_string()
}

fn bare_request(route: &RouteCase) -> Request<Body> {
    Request::builder()
        .method(route.method)
        .uri(route.concrete_path)
        .body(Body::empty())
        .expect("build request")
}

fn route_specs() -> Vec<(String, String)> {
    let mut routes = ROUTES
        .iter()
        .map(|route| (route.method.to_string(), route.template_path.to_string()))
        .collect::<Vec<_>>();
    routes.sort();
    routes
}

fn router_routes_from_source() -> Vec<(String, String)> {
    let source = include_str!("../src/api/mod.rs");
    let api_start = source
        .find("let api = Router::new()")
        .expect("api router start");
    let api_end = source[api_start..]
        .find(".fallback(v1_not_found);")
        .map(|offset| api_start + offset)
        .expect("api router end");
    let router_block = &source[api_start..api_end];

    let mut routes = Vec::new();
    let mut remaining = router_block;
    while let Some(route_start) = remaining.find(".route(") {
        let after_route = &remaining[route_start + ".route(".len()..];
        let (call, rest) = take_call(after_route);
        let (path, handlers) = parse_route_call(call);

        for (method, handler_name) in [
            ("GET", "get("),
            ("POST", "post("),
            ("PUT", "put("),
            ("DELETE", "delete("),
        ] {
            if handlers.contains(handler_name) {
                routes.push((method.to_string(), format!("/v1{path}")));
            }
        }

        remaining = rest;
    }

    routes.sort();
    routes
}

fn take_call(input: &str) -> (&str, &str) {
    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;

    for (index, ch) in input.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }

            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return (&input[..index], &input[index + 1..]);
                }
            }
            _ => {}
        }
    }

    panic!("unterminated .route(...) call");
}

fn parse_route_call(call: &str) -> (&str, &str) {
    let call = call.trim();
    assert!(
        call.starts_with('"'),
        "route call should start with a path string"
    );
    let path_end = call[1..]
        .find('"')
        .map(|offset| offset + 1)
        .expect("route path should terminate");
    let path = &call[1..path_end];
    let handlers = call[path_end + 1..].trim();
    let handlers = handlers
        .strip_prefix(',')
        .expect("route path should be followed by handlers")
        .trim();
    (path, handlers)
}

fn required_operation_source() -> &'static str {
    let source = include_str!("../src/api/mod.rs");
    let start = source
        .find("fn required_operation(path: &str, method: &axum::http::Method) -> Option<ApiOperation> {")
        .expect("required_operation start");
    let end = source[start..]
        .find("fn requires_org_scope(")
        .map(|offset| start + offset)
        .expect("required_operation end");
    &source[start..end]
}

fn route_has_required_operation_coverage(source: &str, route: &RouteCase) -> bool {
    match (route.method, route.template_path) {
        ("GET", "/v1/openapi.yml")
        | ("GET", "/v1/me")
        | ("GET", "/v1/events")
        | ("GET", "/v1/actions")
        | ("GET", "/v1/auth/audit")
        | ("GET", "/v1/integrity")
        | ("GET", "/v1/checkpoints")
        | ("GET", "/v1/health")
        | ("POST", "/v1/traces")
        | ("POST", "/v1/traces/batch")
        | ("POST", "/v1/traces/otlp")
        | ("POST", "/v1/oversight")
        | ("POST", "/v1/export/json")
        | ("POST", "/v1/export/pdf")
        | ("POST", "/v1/auth/audit/export") => source.contains(&format!(
            "(&axum::http::Method::{}, \"{}\")",
            route.method, route.template_path
        )),
        ("GET", "/v1/orgs/{org_id}/settings")
        | ("PUT", "/v1/orgs/{org_id}/settings")
        | ("DELETE", "/v1/orgs/{org_id}/settings") => {
            source.contains(&format!("(&axum::http::Method::{}, path)", route.method))
                && source
                    .contains("path.starts_with(\"/v1/orgs/\") && path.ends_with(\"/settings\")")
        }
        ("GET", "/v1/orgs/{org_id}/mfa-policy")
        | ("PUT", "/v1/orgs/{org_id}/mfa-policy")
        | ("GET", "/v1/admin/orgs/{org_id}/sso/saml")
        | ("PUT", "/v1/admin/orgs/{org_id}/sso/saml") => {
            source.contains(&format!("(&axum::http::Method::{}, path)", route.method))
                && source
                    .contains("path.starts_with(\"/v1/orgs/\") && path.ends_with(\"/mfa-policy\")")
                && source.contains(
                    "path.starts_with(\"/v1/admin/orgs/\") && path.ends_with(\"/sso/saml\")",
                )
        }
        ("POST", "/v1/sso/saml/{org_id}/acs") => {
            source.contains("(&axum::http::Method::POST, path)")
                && source
                    .contains("path.starts_with(\"/v1/sso/saml/\") && path.ends_with(\"/acs\")")
        }
        ("POST", "/v1/auth/mfa/challenge")
        | ("POST", "/v1/auth/mfa/challenge/verify")
        | ("POST", "/v1/auth/mfa/enroll/start")
        | ("POST", "/v1/auth/mfa/enroll/confirm") => source
            .contains("(&axum::http::Method::POST, path) if path.starts_with(\"/v1/auth/mfa/\")"),
        ("GET", "/v1/actions/{id}")
        | ("GET", "/v1/compliance/{framework}")
        | ("GET", "/v1/checkpoints/{id}") => {
            source.contains("(&axum::http::Method::GET, path)")
                && source.contains("path.starts_with(\"/v1/actions/\")")
                && source.contains("path.starts_with(\"/v1/compliance/\")")
                && source.contains("path.starts_with(\"/v1/checkpoints/\")")
        }
        _ => false,
    }
}

#[tokio::test]
async fn all_protected_v1_endpoints_return_401_without_authentication() {
    let app = app(shared_state(Some(TEST_API_KEY.to_string())));

    for route in ROUTES.iter().filter(|route| !route.public_without_auth) {
        let response = app
            .clone()
            .oneshot(bare_request(route))
            .await
            .expect("unauthenticated request should complete");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{} {} should reject unauthenticated access",
            route.method,
            route.template_path
        );
        let payload = response_json(response).await;
        assert_eq!(
            payload["code"], "UNAUTHORIZED",
            "{} {} should return the unauthorized error code",
            route.method, route.template_path
        );
    }
}

#[tokio::test]
async fn org_scoped_api_keys_cannot_read_other_org_data() {
    let db_path = auth_db_path("org-isolation");
    let storage = Storage::open(&db_path).expect("storage");
    let org_a_key = storage
        .create_api_key_with_roles(
            "org-a",
            "org-a-service",
            Some(&[
                ApiKeyRole::Ingest,
                ApiKeyRole::Query,
                ApiKeyRole::Export,
                ApiKeyRole::Configure,
            ]),
        )
        .expect("create org a key");
    let org_b_key = storage
        .create_api_key_with_roles(
            "org-b",
            "org-b-service",
            Some(&[
                ApiKeyRole::Ingest,
                ApiKeyRole::Query,
                ApiKeyRole::Export,
                ApiKeyRole::Configure,
            ]),
        )
        .expect("create org b key");
    drop(storage);

    let app = app(shared_state_with_db(&db_path, None).expect("sqlite state"));

    let org_a_ingest = app
        .clone()
        .oneshot(
            with_api_key(Request::builder(), &org_a_key.key)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "org-a-session",
                        "agent": "planner",
                        "type": "tool_call",
                        "timestamp": "2026-03-29T12:00:00Z",
                        "payload": { "tool": "search" }
                    })
                    .to_string(),
                ))
                .expect("org a ingest request"),
        )
        .await
        .expect("org a ingest response");
    assert_eq!(org_a_ingest.status(), StatusCode::CREATED);
    let org_a_action_id = response_json(org_a_ingest).await["action_ids"][0]
        .as_str()
        .expect("org a action id")
        .to_string();

    let org_b_ingest = app
        .clone()
        .oneshot(
            with_api_key(Request::builder(), &org_b_key.key)
                .method("POST")
                .uri("/v1/traces")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "session_id": "org-b-session",
                        "agent": "planner",
                        "type": "tool_call",
                        "timestamp": "2026-03-29T12:01:00Z",
                        "payload": { "tool": "search" }
                    })
                    .to_string(),
                ))
                .expect("org b ingest request"),
        )
        .await
        .expect("org b ingest response");
    assert_eq!(org_b_ingest.status(), StatusCode::CREATED);
    let org_b_action_id = response_json(org_b_ingest).await["action_ids"][0]
        .as_str()
        .expect("org b action id")
        .to_string();

    let org_b_settings = app
        .clone()
        .oneshot(
            with_api_key(Request::builder(), &org_b_key.key)
                .method("PUT")
                .uri("/v1/orgs/org-b/settings")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "retention_policy": { "min_retention_days": 365 },
                        "enabled_frameworks": ["eu-ai-act"],
                        "guardrail_settings": { "approval_required": true }
                    })
                    .to_string(),
                ))
                .expect("org b settings request"),
        )
        .await
        .expect("org b settings response");
    assert_eq!(org_b_settings.status(), StatusCode::CREATED);

    let org_a_own_actions = app
        .clone()
        .oneshot(
            with_api_key(Request::builder(), &org_a_key.key)
                .uri("/v1/actions?session_id=org-a-session")
                .body(Body::empty())
                .expect("org a own actions request"),
        )
        .await
        .expect("org a own actions response");
    assert_eq!(org_a_own_actions.status(), StatusCode::OK);
    let org_a_own_actions_payload = response_json(org_a_own_actions).await;
    assert_eq!(org_a_own_actions_payload["total"], 1);
    assert_eq!(
        org_a_own_actions_payload["actions"][0]["id"],
        org_a_action_id
    );

    let spoofed_actions = app
        .clone()
        .oneshot(
            with_api_key(Request::builder(), &org_a_key.key)
                .uri("/v1/actions?session_id=org-b-session")
                .header("x-trailing-org-id", "org-b")
                .body(Body::empty())
                .expect("spoofed actions request"),
        )
        .await
        .expect("spoofed actions response");
    assert_eq!(spoofed_actions.status(), StatusCode::UNAUTHORIZED);

    let spoofed_action_detail = app
        .clone()
        .oneshot(
            with_api_key(Request::builder(), &org_a_key.key)
                .uri(format!("/v1/actions/{org_b_action_id}"))
                .header("x-trailing-org-id", "org-b")
                .body(Body::empty())
                .expect("spoofed action detail request"),
        )
        .await
        .expect("spoofed action detail response");
    assert_eq!(spoofed_action_detail.status(), StatusCode::UNAUTHORIZED);

    let cross_org_export = app
        .clone()
        .oneshot(
            with_api_key(Request::builder(), &org_a_key.key)
                .method("POST")
                .uri("/v1/export/json")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "framework": "eu-ai-act",
                        "org_id": "org-b"
                    })
                    .to_string(),
                ))
                .expect("cross-org export request"),
        )
        .await
        .expect("cross-org export response");
    assert_eq!(cross_org_export.status(), StatusCode::UNAUTHORIZED);

    let cross_org_settings = app
        .oneshot(
            with_api_key(Request::builder(), &org_a_key.key)
                .uri("/v1/orgs/org-b/settings")
                .body(Body::empty())
                .expect("cross-org settings request"),
        )
        .await
        .expect("cross-org settings response");
    assert_eq!(cross_org_settings.status(), StatusCode::UNAUTHORIZED);

    fs::remove_file(db_path).ok();
}

#[tokio::test]
async fn auth_bypass_only_allows_the_explicit_public_endpoints() {
    let db_path = auth_db_path("auth-bypass");
    ensure_saml_config_table(&db_path);
    let storage = Storage::open(&db_path).expect("storage");
    storage
        .create_human_user(
            "org-mfa",
            "security@example.com",
            "correct horse battery staple",
        )
        .expect("create human user");
    let enroll_start = storage
        .start_mfa_enrollment(
            "org-mfa",
            "security@example.com",
            "correct horse battery staple",
        )
        .expect("start mfa enrollment");
    storage
        .confirm_mfa_enrollment(
            "org-mfa",
            "security@example.com",
            "correct horse battery staple",
            &totp_code(&enroll_start.secret),
            Utc::now(),
        )
        .expect("confirm mfa enrollment");
    drop(storage);

    let app = app(shared_state_with_db(&db_path, Some(TEST_API_KEY.to_string())).expect("state"));

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
                .expect("challenge request"),
        )
        .await
        .expect("challenge response");
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge_payload = response_json(challenge).await;
    let challenge_id = challenge_payload["challenge_id"]
        .as_str()
        .expect("challenge id")
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
                        "code": totp_code(&enroll_start.secret),
                    })
                    .to_string(),
                ))
                .expect("verify request"),
        )
        .await
        .expect("verify response");
    assert_eq!(verify.status(), StatusCode::OK);

    let saml_acs = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sso/saml/org-mfa/acs")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "saml_response": "stub-response" }).to_string(),
                ))
                .expect("saml acs request"),
        )
        .await
        .expect("saml acs response");
    assert_eq!(saml_acs.status(), StatusCode::NOT_FOUND);

    for (method, uri, body) in [
        (
            "POST",
            "/v1/auth/mfa/enroll/start",
            json!({
                "org_id": "org-mfa",
                "email": "security@example.com",
                "password": "correct horse battery staple"
            }),
        ),
        (
            "POST",
            "/v1/auth/mfa/enroll/confirm",
            json!({
                "org_id": "org-mfa",
                "email": "security@example.com",
                "password": "correct horse battery staple",
                "code": totp_code(&enroll_start.secret),
            }),
        ),
        (
            "POST",
            "/v1/auth/audit/export",
            json!({ "org_id": "org-mfa" }),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("protected auth route request"),
            )
            .await
            .expect("protected auth route response");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
    }

    let audit_query = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/audit?org_id=org-mfa")
                .body(Body::empty())
                .expect("audit query request"),
        )
        .await
        .expect("audit query response");
    assert_eq!(audit_query.status(), StatusCode::UNAUTHORIZED);

    fs::remove_file(db_path).ok();
}

#[tokio::test]
async fn health_is_always_accessible_without_authentication() {
    let app = app(shared_state(Some(TEST_API_KEY.to_string())));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .expect("health request"),
        )
        .await
        .expect("health response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-trailing-version")
            .expect("version header")
            .to_str()
            .expect("version header utf8"),
        TRAILING_VERSION
    );
    let payload = response_json(response).await;
    assert_eq!(payload["status"], "ok");
}

#[test]
fn all_router_routes_have_matching_required_operation_coverage() {
    let listed_routes = route_specs();
    let source_routes = router_routes_from_source();
    assert_eq!(
        source_routes, listed_routes,
        "the route list in this regression test must track the /v1 router exactly"
    );

    let required_operation = required_operation_source();
    for route in ROUTES {
        assert!(
            route_has_required_operation_coverage(required_operation, route),
            "required_operation() is missing coverage for {} {}",
            route.method,
            route.template_path
        );
    }
}
