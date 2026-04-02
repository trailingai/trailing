use std::{
    cmp::Ordering,
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use async_stream::stream;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{
        Extension, FromRequest, FromRequestParts, Json as AxumJson, Path as AxumPath,
        Query as AxumQuery, Request as AxumRequest, State,
        connect_info::ConnectInfo,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, FORWARDED},
        request::Parts,
    },
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{delete, get, post},
};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use uuid::Uuid;

use crate::{
    auth::{api_key_role_definitions, principal_role_definitions, role_grants_permission},
    dashboard,
    export::{
        self as evidence_export, ChainIntegrityStatus as ExportChainIntegrityStatus,
        ComplianceControl as ExportComplianceControl, ComplianceGap as ExportComplianceGap,
        ComplianceReport as ExportComplianceReport, ComplianceStatus as ExportComplianceStatus,
        EvidenceAction as ExportEvidenceAction, EvidenceMetadata as ExportEvidenceMetadata,
        EvidencePackage as ExportEvidencePackage, GapSeverity,
        IntegrityProof as ExportIntegrityProof, IntegrityState,
        OversightEvent as ExportOversightEvent,
    },
    ingest::helpers::{ActionTypeHints, resolve_action_type},
    landing,
    log::{ActionEntry as StoredActionEntry, ActionType, GENESIS_HASH},
    policy::{
        ActionEntry as PolicyActionEntry, ControlResult as PolicyControlResult,
        Framework as PolicyFramework, PolicyEngine,
    },
    sso::{validate_saml_dependencies, validate_saml_response},
    storage::{
        API_KEY_PREFIX, ApiKeyRole, AuthAuditEntry as StoredAuthAuditEntry,
        AuthenticatedApiKey, AuthenticatedSession, DeduplicationOutcome, LegalHoldRecord,
        MfaChallengeStart, MfaPolicy, OrgSettings, OrgSettingsInput, SamlIdpConfig,
        SignedCheckpoint, Storage, StorageControl, StorageError, StorageScope,
        UpsertSamlIdpConfig, VerifiedCheckpoint, is_valid_internal_role,
    },
    tenant::TenantContext,
    webhook::{WebhookConfig, WebhookEventKind, WebhookNotification, notify_in_background},
};

pub type SharedState = Arc<AppState>;
pub const TRAILING_VERSION: &str = env!("CARGO_PKG_VERSION");

const DEFAULT_RATE_LIMIT_PER_MINUTE: usize = 100;
const DEFAULT_RATE_LIMIT_PER_HOUR: usize = DEFAULT_RATE_LIMIT_PER_MINUTE * 60;
const DEFAULT_ACTIONS_LIMIT: usize = 100;
const MAX_ACTIONS_LIMIT: usize = 1_000;
const OPENAPI_YAML: &str = include_str!("../../openapi.yml");
const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
const VERSION_HEADER: HeaderName = HeaderName::from_static("x-trailing-version");
const RATE_LIMIT_LIMIT_HEADER: HeaderName = HeaderName::from_static("x-ratelimit-limit");
const RATE_LIMIT_REMAINING_HEADER: HeaderName = HeaderName::from_static("x-ratelimit-remaining");
const RATE_LIMIT_RESET_HEADER: HeaderName = HeaderName::from_static("x-ratelimit-reset");
const ORG_ID_HEADER: HeaderName = HeaderName::from_static("x-trailing-org-id");
const IDEMPOTENCY_KEY_HEADER: HeaderName = HeaderName::from_static("idempotency-key");
const X_CONTENT_TYPE_OPTIONS_HEADER: HeaderName =
    HeaderName::from_static("x-content-type-options");
const X_FRAME_OPTIONS_HEADER: HeaderName = HeaderName::from_static("x-frame-options");
const STRICT_TRANSPORT_SECURITY_HEADER: HeaderName =
    HeaderName::from_static("strict-transport-security");
const X_XSS_PROTECTION_HEADER: HeaderName = HeaderName::from_static("x-xss-protection");
const REFERRER_POLICY_HEADER: HeaderName = HeaderName::from_static("referrer-policy");
const X_FORWARDED_PROTO_HEADER: HeaderName = HeaderName::from_static("x-forwarded-proto");
const ANONYMOUS_ORG_ID: &str = "anonymous";
const MINUTE_WINDOW: Duration = Duration::from_secs(60);
const HOUR_WINDOW: Duration = Duration::from_secs(60 * 60);
const LIVE_EVENTS_BUFFER: usize = 256;
const SSE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const PROJECT_ID_HEADER: HeaderName = HeaderName::from_static("x-trailing-project-id");
const REDACTED_VALUE: &str = "[REDACTED]";
const SSO_SESSION_TTL: Duration = Duration::from_secs(60 * 60 * 8);

#[derive(Clone)]
pub struct AppState {
    storage: Arc<Mutex<Storage>>,
    api_key: Option<String>,
    tenant_context: TenantContext,
    default_scope: ResolvedScope,
    auth_tokens: Arc<Mutex<AuthTokenStore>>,
    started_at: Instant,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    cors: CorsConfig,
    redact_fields: Vec<String>,
    live_events: broadcast::Sender<LiveEvent>,
    webhook: Option<WebhookConfig>,
}

#[derive(Clone, Debug)]
pub struct AppOptions {
    pub rate_limit_per_minute: usize,
    pub rate_limit_per_hour: usize,
    pub org_rate_limits: HashMap<String, RateLimitConfig>,
    pub cors_origins: Vec<String>,
    pub redact_fields: Vec<String>,
    pub webhook: Option<WebhookConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub requests_per_minute: usize,
    pub requests_per_hour: usize,
}

#[derive(Clone)]
struct CorsConfig {
    origins: Vec<HeaderValue>,
}

#[derive(Debug)]
struct RateLimiter {
    default_config: RateLimitConfig,
    org_configs: HashMap<String, RateLimitConfig>,
    buckets: HashMap<RateLimitKey, RateLimitBuckets>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RateLimitKey {
    org_id: String,
    bucket_id: String,
}

#[derive(Debug)]
struct RateLimitBuckets {
    per_minute: TokenBucket,
    per_hour: TokenBucket,
}

#[derive(Debug)]
struct TokenBucket {
    capacity: usize,
    tokens: f64,
    refill_per_second: f64,
    window: Duration,
    last_refill: Instant,
}

#[derive(Clone, Copy, Debug)]
struct RateLimitHeaders {
    limit: usize,
    remaining: usize,
    reset_at_epoch: u64,
}

#[derive(Clone, Copy, Debug)]
struct BucketStatus {
    limit: usize,
    remaining: usize,
    reset_after_seconds: u64,
    allowed: bool,
}

#[derive(Clone, Copy, Debug)]
struct RateLimitDecision {
    allowed: bool,
    headers: RateLimitHeaders,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedScope {
    org_id: String,
    project_id: String,
}

#[derive(Debug, Default)]
struct AuthTokenStore {
    service_account_tokens: HashMap<String, RequestAuth>,
    session_tokens: HashMap<String, RequestAuth>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestAuth {
    pub principal_id: Option<String>,
    pub key_id: Option<String>,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub org_id: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub expires_at: Option<String>,
    pub roles: Vec<String>,
    pub is_admin: bool,
    pub rate_limit_bucket: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApiOperation {
    Ingest,
    Query,
    Export,
    Configure,
    Admin,
}

#[derive(Clone, Debug)]
struct ResolvedRequestAuth {
    auth: RequestAuth,
    rate_limit_bucket: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum AuthTokenKind {
    ServiceAccount,
    Session,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    pub id: String,
    pub session_id: String,
    pub agent: String,
    pub agent_type: String,
    pub kind: String,
    #[serde(rename = "type")]
    pub action_type: String,
    pub tool_name: Option<String>,
    pub target: Option<String>,
    pub source: String,
    pub timestamp: String,
    pub payload: Value,
    pub hash: String,
    pub previous_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OversightEvent {
    pub id: String,
    pub session_id: Option<String>,
    pub framework: Option<String>,
    pub severity: String,
    pub note: String,
    pub timestamp: String,
    pub payload: Value,
    pub hash: String,
    pub previous_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAuditRecord {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub org_id: Option<String>,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub subject_type: String,
    pub subject_id: String,
    pub payload: Value,
    pub outcome: String,
    pub hash: String,
    pub previous_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ActionsQuery {
    pub session_id: Option<String>,
    pub agent: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(rename = "type")]
    pub action_type: Option<String>,
    pub include_oversight: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AuthAuditQuery {
    pub org_id: Option<String>,
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub actor_id: Option<String>,
    pub subject_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ActionsListQuery {
    session_id: Option<String>,
    agent: Option<String>,
    from: Option<String>,
    to: Option<String>,
    #[serde(rename = "type")]
    action_type: Option<String>,
    include_oversight: Option<bool>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AuthAuditListQuery {
    org_id: Option<String>,
    #[serde(rename = "type")]
    event_type: Option<String>,
    actor_id: Option<String>,
    subject_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct SamlConfigRequest {
    enabled: Option<bool>,
    idp_entity_id: String,
    sso_url: String,
    idp_certificate_pem: String,
    sp_entity_id: String,
    acs_url: String,
    email_attribute: String,
    first_name_attribute: Option<String>,
    last_name_attribute: Option<String>,
    role_attribute: Option<String>,
    #[serde(default)]
    role_mappings: HashMap<String, String>,
    default_role: String,
}

#[derive(Debug, Deserialize)]
struct SamlAcsJsonRequest {
    saml_response: String,
    relay_state: Option<String>,
}

#[derive(Debug, Serialize)]
struct RetentionSummaryResponse {
    org_id: String,
    effective_retention_days: i64,
    policy_source: String,
    purge_cutoff: String,
    purge_blocked: bool,
    storage_policy: RetentionStoragePolicySummary,
    organization_policy: Option<RetentionOrganizationPolicySummary>,
    active_legal_holds: Vec<LegalHoldRecord>,
    age_distribution: Vec<RetentionAgeBucket>,
    total_records: usize,
    oldest_record_at: Option<String>,
    newest_record_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct RetentionStoragePolicySummary {
    allow_purge: bool,
    min_retention_days: i64,
}

#[derive(Debug, Serialize)]
struct RetentionOrganizationPolicySummary {
    org_id: String,
    retention_policy: Value,
    min_retention_days: Option<i64>,
    legal_hold: bool,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct RetentionAgeBucket {
    label: String,
    min_age_days: i64,
    max_age_days: Option<i64>,
    count: usize,
    oldest_record_at: Option<String>,
    newest_record_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionIdentityResponse {
    session_id: String,
    user_id: String,
    org_id: String,
    email: String,
    display_name: String,
    role: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct MfaChallengeRequest {
    org_id: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct MfaChallengeVerifyRequest {
    challenge_id: String,
    code: String,
}

#[derive(Debug, Deserialize)]
struct MfaEnrollStartRequest {
    org_id: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct MfaEnrollConfirmRequest {
    org_id: String,
    email: String,
    password: String,
    code: String,
}

#[derive(Debug, Deserialize)]
struct MfaPolicyRequest {
    policy: String,
}

#[derive(Debug, Deserialize)]
struct AdminApiKeyCreateRequest {
    name: String,
    role: ApiKeyRole,
}

#[derive(Debug, Serialize)]
struct MaskedApiKeyRecord {
    id: String,
    org_id: String,
    name: String,
    created_at: String,
    last_used_at: Option<String>,
    revoked: bool,
    is_admin: bool,
    roles: Vec<ApiKeyRole>,
    masked_key: String,
}

#[derive(Debug, Serialize)]
struct AdminApiKeysResponse {
    api_keys: Vec<MaskedApiKeyRecord>,
}

#[derive(Debug, Serialize)]
struct RoleDefinitionResponse {
    name: String,
    permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AdminRolesResponse {
    api_key_roles: Vec<RoleDefinitionResponse>,
    principal_roles: Vec<RoleDefinitionResponse>,
}

#[derive(Debug, Deserialize)]
pub struct ExportRequest {
    pub framework: Option<String>,
    pub org_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct AuthAuditExportRequest {
    pub org_id: Option<String>,
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub actor_id: Option<String>,
    pub subject_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ComplianceQuery {
    pub org_id: Option<String>,
    pub session_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OrgSettingsRequest {
    #[serde(default = "empty_json_object")]
    retention_policy: Value,
    #[serde(default)]
    enabled_frameworks: Vec<String>,
    #[serde(default = "empty_json_object")]
    guardrail_settings: Value,
}

#[derive(Debug, Serialize)]
pub struct IntegrityReport {
    pub valid: bool,
    pub checked_entries: usize,
    pub latest_hash: Option<String>,
    pub root_anchor_hash: Option<String>,
    pub root_anchor_persisted: bool,
    pub merkle_root_hash: String,
    pub checkpoint_signature: String,
    pub proofs: Vec<ExportIntegrityProof>,
}

#[derive(Debug, Serialize)]
pub struct ComplianceReport {
    pub framework: String,
    pub total_actions: usize,
    pub oversight_events: usize,
    pub integrity_valid: bool,
    pub score: u8,
    pub controls_met: Vec<ComplianceControlResult>,
    pub controls_gaps: Vec<ComplianceControlResult>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ComplianceControlResult {
    pub id: String,
    pub article: String,
    pub requirement: String,
    pub matched_evidence: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub service: &'static str,
    pub storage: &'static str,
    pub api_key_configured: bool,
}

#[derive(Debug, Serialize)]
struct HealthReport {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    uptime_seconds: u64,
    total_actions: usize,
    db_size_bytes: u64,
    chain_valid: bool,
    sso_available: bool,
}

#[derive(Debug, Serialize)]
struct PaginatedActionsResponse {
    actions: Vec<ActionRecord>,
    total: usize,
    pagination: PaginationMetadata,
}

#[derive(Debug, Serialize)]
struct IngestResponse {
    ingested: usize,
    action_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BatchIngestResponse {
    ingested: usize,
    failed: usize,
    action_ids: Vec<String>,
    results: Vec<BatchIngestItemResult>,
}

#[derive(Debug, Serialize)]
struct BatchIngestItemResult {
    index: usize,
    status: &'static str,
    action_id: Option<String>,
    error: Option<BatchIngestItemError>,
}

#[derive(Debug, Serialize)]
struct BatchIngestItemError {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct PaginatedAuthAuditResponse {
    events: Vec<AuthAuditRecord>,
    total: usize,
    pagination: PaginationMetadata,
}

#[derive(Debug, Serialize)]
struct PaginationMetadata {
    limit: usize,
    offset: usize,
    count: usize,
    has_more: bool,
}

#[derive(Debug, Clone, Copy)]
enum ApiErrorCode {
    InvalidJson,
    MissingField,
    NotFound,
    UnsupportedFramework,
    RateLimited,
    ServiceUnavailable,
    Unauthorized,
    InvalidRequest,
    InternalError,
    RequestTooLarge,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: ApiErrorCode,
    message: String,
    request_id: Option<String>,
}

#[derive(Debug)]
struct LoadedRecords {
    actions: Vec<ActionRecord>,
    oversight_events: Vec<OversightEvent>,
    org_settings: Option<OrgSettings>,
    ledger_entries: Vec<StoredActionEntry>,
}

#[derive(Debug)]
struct LoadedComplianceRecords {
    actions: Vec<StoredActionEntry>,
    oversight_events: Vec<StoredActionEntry>,
    storage_control: StorageControl,
    org_settings: Option<OrgSettings>,
}

#[derive(Debug)]
struct PreparedSdkAction {
    normalized: NormalizedActionRecord,
    idempotency_key: Option<String>,
}

#[derive(Debug)]
struct PersistedActionOutcome {
    action_id: String,
    duplicate: bool,
}

impl PersistedActionOutcome {
    fn action_id(&self) -> &str {
        &self.action_id
    }
}

#[derive(Debug)]
struct NormalizedActionRecord {
    org_id: Option<String>,
    timestamp: Option<String>,
    session_id: String,
    trace_id: Option<String>,
    span_id: Option<String>,
    agent: String,
    agent_type: String,
    action_type: String,
    tool_name: Option<String>,
    target: Option<String>,
    schema_version: Option<String>,
    idempotency_key: Option<String>,
    request_metadata: Option<Value>,
    result_metadata: Option<Value>,
    outcome: String,
    payload: Value,
}

#[derive(Debug, Clone)]
enum LiveEvent {
    Action {
        scope: ResolvedScope,
        action: ActionRecord,
    },
    Oversight {
        scope: ResolvedScope,
        event: OversightEvent,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredKind {
    Action,
    Oversight,
}

struct ApiJson<T>(T);

struct ApiQuery<T>(T);

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: ApiErrorCode::InvalidRequest,
            message: message.into(),
            request_id: None,
        }
    }

    fn invalid_json(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: ApiErrorCode::InvalidJson,
            message: message.into(),
            request_id: None,
        }
    }

    fn missing_field(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: ApiErrorCode::MissingField,
            message: message.into(),
            request_id: None,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ApiErrorCode::InternalError,
            message: message.into(),
            request_id: None,
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: ApiErrorCode::NotFound,
            message: message.into(),
            request_id: None,
        }
    }

    fn unsupported_framework(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: ApiErrorCode::UnsupportedFramework,
            message: message.into(),
            request_id: None,
        }
    }

    fn rate_limited(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: ApiErrorCode::RateLimited,
            message: message.into(),
            request_id: None,
        }
    }

    fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: ApiErrorCode::ServiceUnavailable,
            message: message.into(),
            request_id: None,
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: ApiErrorCode::Unauthorized,
            message: message.into(),
            request_id: None,
        }
    }

    fn request_too_large(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: ApiErrorCode::RequestTooLarge,
            message: message.into(),
            request_id: None,
        }
    }

    fn from_storage(_: StorageError) -> Self {
        Self::internal("the request could not be completed due to a storage failure")
    }

    fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    fn json_body(&self) -> Value {
        let mut payload = Map::new();
        let mut error = Map::new();
        error.insert(
            "code".to_string(),
            Value::String(self.code.as_str().to_string()),
        );
        error.insert("message".to_string(), Value::String(self.message.clone()));
        payload.insert("error".to_string(), Value::Object(error));

        if let Some(request_id) = &self.request_id {
            payload.insert("request_id".to_string(), Value::String(request_id.clone()));
        }

        Value::Object(payload)
    }
}

impl ApiErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "INVALID_JSON",
            Self::MissingField => "MISSING_FIELD",
            Self::NotFound => "NOT_FOUND",
            Self::UnsupportedFramework => "UNSUPPORTED_FRAMEWORK",
            Self::RateLimited => "RATE_LIMITED",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::InternalError => "INTERNAL_ERROR",
            Self::RequestTooLarge => "REQUEST_TOO_LARGE",
        }
    }
}

impl Default for AppOptions {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            rate_limit_per_hour: DEFAULT_RATE_LIMIT_PER_HOUR,
            org_rate_limits: HashMap::new(),
            cors_origins: Vec::new(),
            redact_fields: Vec::new(),
            webhook: None,
        }
    }
}

impl RateLimitConfig {
    pub fn new(requests_per_minute: usize, requests_per_hour: usize) -> Self {
        Self {
            requests_per_minute,
            requests_per_hour,
        }
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.requests_per_minute == 0 {
            return Err("rate limit per minute must be greater than zero".into());
        }
        if self.requests_per_hour == 0 {
            return Err("rate limit per hour must be greater than zero".into());
        }

        Ok(())
    }
}

impl RequestAuth {
    pub fn anonymous() -> Self {
        Self::default()
    }

    pub fn new(
        principal_id: impl Into<String>,
        org_id: Option<String>,
        roles: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let roles = roles.into_iter().map(Into::into).collect::<Vec<_>>();
        let is_admin = roles.iter().any(|role| role == "admin");
        Self {
            principal_id: Some(principal_id.into()),
            org_id,
            roles,
            is_admin,
            rate_limit_bucket: String::new(),
            ..Self::default()
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.principal_id.is_some()
    }

    fn allows(&self, operation: ApiOperation) -> bool {
        self.roles.iter().any(|role| role_grants(role, operation))
    }

    fn require(&self, operation: ApiOperation) -> Result<(), ApiError> {
        if self.allows(operation) {
            Ok(())
        } else {
            Err(ApiError::unauthorized(format!(
                "missing permission `{}`",
                operation.as_str()
            )))
        }
    }
}

impl ApiOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::Query => "query",
            Self::Export => "export",
            Self::Configure => "configure",
            Self::Admin => "admin",
        }
    }
}

fn role_grants(role: &str, operation: ApiOperation) -> bool {
    role_grants_permission(role, operation.as_str())
}

impl CorsConfig {
    fn from_origins(origins: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let origins = origins
            .into_iter()
            .map(|origin| origin.trim().to_string())
            .filter(|origin| !origin.is_empty())
            .map(|origin| {
                if origin == "*" {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "wildcard CORS origins are not allowed",
                    )
                    .into())
                } else {
                    HeaderValue::from_str(&origin)
                        .map_err(Box::<dyn std::error::Error>::from)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { origins })
    }

    fn build_layer(&self) -> CorsLayer {
        if self.origins.is_empty() {
            CorsLayer::new()
        } else {
            CorsLayer::new()
                .allow_methods(Any)
                .allow_headers(Any)
                .allow_origin(AllowOrigin::list(self.origins.iter().cloned()))
        }
    }
}

impl RateLimiter {
    fn new(default_config: RateLimitConfig, org_configs: HashMap<String, RateLimitConfig>) -> Self {
        Self {
            default_config,
            org_configs,
            buckets: HashMap::new(),
        }
    }

    fn check(&mut self, key: RateLimitKey, now: Instant, now_epoch: u64) -> RateLimitDecision {
        self.prune_idle(now);

        let config = self
            .org_configs
            .get(&key.org_id)
            .cloned()
            .unwrap_or_else(|| self.default_config.clone());
        let buckets = self
            .buckets
            .entry(key)
            .or_insert_with(|| RateLimitBuckets::new(&config, now));

        buckets.evaluate(now, now_epoch)
    }

    fn prune_idle(&mut self, now: Instant) {
        self.buckets.retain(|_, buckets| !buckets.is_idle(now));
    }
}

impl RateLimitBuckets {
    fn new(config: &RateLimitConfig, now: Instant) -> Self {
        Self {
            per_minute: TokenBucket::new(config.requests_per_minute, MINUTE_WINDOW, now),
            per_hour: TokenBucket::new(config.requests_per_hour, HOUR_WINDOW, now),
        }
    }

    fn evaluate(&mut self, now: Instant, now_epoch: u64) -> RateLimitDecision {
        let minute_before = self.per_minute.status(now, false);
        let hour_before = self.per_hour.status(now, false);

        let allowed = minute_before.allowed && hour_before.allowed;
        if allowed {
            self.per_minute.consume();
            self.per_hour.consume();
        }

        let minute_after = self.per_minute.status(now, allowed);
        let hour_after = self.per_hour.status(now, allowed);
        let active = BucketStatus::choose(minute_after, hour_after, allowed);

        RateLimitDecision {
            allowed,
            headers: RateLimitHeaders {
                limit: active.limit,
                remaining: active.remaining,
                reset_at_epoch: now_epoch.saturating_add(active.reset_after_seconds),
            },
        }
    }

    fn is_idle(&self, now: Instant) -> bool {
        self.per_minute.is_idle(now) && self.per_hour.is_idle(now)
    }
}

impl TokenBucket {
    fn new(capacity: usize, window: Duration, now: Instant) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_per_second: capacity as f64 / window.as_secs_f64(),
            window,
            last_refill: now,
        }
    }

    fn status(&mut self, now: Instant, consumed: bool) -> BucketStatus {
        self.refill(now);

        let allowed = self.tokens >= 1.0;
        let remaining_tokens = if consumed {
            self.tokens.floor()
        } else if allowed {
            (self.tokens.floor() - 1.0).max(0.0)
        } else {
            0.0
        };

        BucketStatus {
            limit: self.capacity,
            remaining: remaining_tokens as usize,
            reset_after_seconds: self.reset_after_seconds(allowed),
            allowed,
        }
    }

    fn consume(&mut self) {
        self.tokens = (self.tokens - 1.0).max(0.0);
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        if elapsed.is_zero() {
            return;
        }

        self.tokens = (self.tokens + elapsed.as_secs_f64() * self.refill_per_second)
            .min(self.capacity as f64);
        self.last_refill = now;
    }

    fn reset_after_seconds(&self, allowed: bool) -> u64 {
        let missing = if allowed {
            (self.capacity as f64 - self.tokens).min(1.0)
        } else {
            (1.0 - self.tokens).max(0.0)
        };

        if missing <= f64::EPSILON {
            0
        } else {
            (missing / self.refill_per_second).ceil() as u64
        }
    }

    fn is_idle(&self, now: Instant) -> bool {
        self.tokens >= self.capacity as f64
            && now.saturating_duration_since(self.last_refill) >= self.window
    }
}

impl BucketStatus {
    fn choose(left: Self, right: Self, allowed: bool) -> Self {
        if !allowed {
            return if left.allowed != right.allowed {
                if left.allowed { right } else { left }
            } else if left.reset_after_seconds >= right.reset_after_seconds {
                left
            } else {
                right
            };
        }

        match (left.remaining * right.limit).cmp(&(right.remaining * left.limit)) {
            Ordering::Less => left,
            Ordering::Greater => right,
            Ordering::Equal => {
                if left.limit <= right.limit {
                    left
                } else {
                    right
                }
            }
        }
    }
}

impl StoredKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::Oversight => "oversight",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.json_body())).into_response()
    }
}

impl<S, T> FromRequest<S> for ApiJson<T>
where
    AxumJson<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: AxumRequest, state: &S) -> Result<Self, Self::Rejection> {
        match AxumJson::<T>::from_request(req, state).await {
            Ok(AxumJson(value)) => Ok(Self(value)),
            Err(rejection) => Err(map_json_rejection(rejection)),
        }
    }
}

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    AxumQuery<T>: FromRequestParts<S, Rejection = QueryRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match AxumQuery::<T>::from_request_parts(parts, state).await {
            Ok(AxumQuery(value)) => Ok(Self(value)),
            Err(rejection) => Err(ApiError::bad_request(rejection.body_text())),
        }
    }
}

impl<S> FromRequestParts<S> for RequestAuth
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<RequestAuth>()
            .cloned()
            .unwrap_or_default())
    }
}

pub fn shared_state(api_key: Option<String>) -> SharedState {
    let storage = Storage::open_in_memory().expect("failed to initialize in-memory sqlite storage");
    state_with_storage(storage, api_key, AppOptions::default())
        .expect("default app options must be valid")
}

pub fn shared_state_with_db(
    path: impl AsRef<Path>,
    api_key: Option<String>,
) -> Result<SharedState, StorageError> {
    Storage::open(path).map(|storage| {
        state_with_storage(storage, api_key, AppOptions::default())
            .expect("default app options must be valid")
    })
}

pub fn shared_state_with_options(
    api_key: Option<String>,
    options: AppOptions,
) -> Result<SharedState, Box<dyn std::error::Error>> {
    let storage = Storage::open_in_memory()?;
    state_with_storage(storage, api_key, options)
}

pub fn shared_state_with_db_and_options(
    path: impl AsRef<Path>,
    api_key: Option<String>,
    options: AppOptions,
) -> Result<SharedState, Box<dyn std::error::Error>> {
    let storage = Storage::open(path)?;
    state_with_storage(storage, api_key, options)
}

fn state_with_storage(
    storage: Storage,
    api_key: Option<String>,
    options: AppOptions,
) -> Result<SharedState, Box<dyn std::error::Error>> {
    let default_rate_limit =
        RateLimitConfig::new(options.rate_limit_per_minute, options.rate_limit_per_hour);
    default_rate_limit.validate()?;
    for config in options.org_rate_limits.values() {
        config.validate()?;
    }

    let (live_events, _) = broadcast::channel(LIVE_EVENTS_BUFFER);
    let tenant_context = storage.tenant_context()?;
    let default_scope = default_scope(&tenant_context);

    Ok(Arc::new(AppState {
        storage: Arc::new(Mutex::new(storage)),
        api_key,
        tenant_context,
        default_scope,
        auth_tokens: Arc::new(Mutex::new(AuthTokenStore::default())),
        started_at: Instant::now(),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(
            default_rate_limit,
            options.org_rate_limits,
        ))),
        cors: CorsConfig::from_origins(options.cors_origins)?,
        redact_fields: normalize_redact_fields(options.redact_fields),
        live_events,
        webhook: options.webhook,
    }))
}

fn default_scope(tenant_context: &TenantContext) -> ResolvedScope {
    ResolvedScope {
        org_id: tenant_context.org_id.clone(),
        project_id: tenant_context.project_id.clone(),
    }
}

fn register_auth_token(
    state: &SharedState,
    token: impl Into<String>,
    auth: RequestAuth,
    kind: AuthTokenKind,
) -> Result<(), String> {
    let token = token.into();
    if token.trim().is_empty() {
        return Err("auth token cannot be empty".to_string());
    }
    if !auth.is_authenticated() {
        return Err("authenticated request auth requires a principal_id".to_string());
    }

    let mut auth_tokens = state
        .auth_tokens
        .lock()
        .map_err(|_| "auth token store lock poisoned".to_string())?;

    match kind {
        AuthTokenKind::ServiceAccount => {
            auth_tokens.service_account_tokens.insert(token, auth);
        }
        AuthTokenKind::Session => {
            auth_tokens.session_tokens.insert(token, auth);
        }
    }

    Ok(())
}

pub fn register_session_token(
    state: &SharedState,
    token: impl Into<String>,
    auth: RequestAuth,
) -> Result<(), String> {
    register_auth_token(state, token, auth, AuthTokenKind::Session)
}

pub fn register_service_account_token(
    state: &SharedState,
    token: impl Into<String>,
    auth: RequestAuth,
) -> Result<(), String> {
    register_auth_token(state, token, auth, AuthTokenKind::ServiceAccount)
}

pub fn app(state: SharedState) -> Router {
    let api = Router::new()
        .route("/openapi.yml", get(get_openapi_spec))
        .route("/traces", post(post_traces))
        .route("/traces/batch", post(post_traces_batch))
        .route("/traces/otlp", post(post_traces_otlp))
        .route("/me", get(get_me))
        .route("/events", get(get_events))
        .route("/actions", get(get_actions))
        .route("/actions/{id}", get(get_action))
        .route(
            "/admin/api-keys",
            get(get_admin_api_keys).post(post_admin_api_key),
        )
        .route("/admin/api-keys/{key_id}", delete(delete_admin_api_key))
        .route("/admin/roles", get(get_admin_roles))
        .route("/retention/summary", get(get_retention_summary))
        .route("/auth/audit", get(get_auth_audit))
        .route("/auth/audit/export", post(post_auth_audit_export))
        .route("/auth/mfa/challenge", post(post_mfa_challenge))
        .route(
            "/auth/mfa/challenge/verify",
            post(post_mfa_challenge_verify),
        )
        .route("/auth/mfa/enroll/start", post(post_mfa_enroll_start))
        .route("/auth/mfa/enroll/confirm", post(post_mfa_enroll_confirm))
        .route("/oversight", post(post_oversight))
        .route(
            "/orgs/{org_id}/settings",
            get(get_org_settings)
                .put(put_org_settings)
                .delete(delete_org_settings),
        )
        .route(
            "/orgs/{org_id}/mfa-policy",
            get(get_org_mfa_policy).put(put_org_mfa_policy),
        )
        .route(
            "/admin/orgs/{org_id}/sso/saml",
            get(get_saml_config).put(put_saml_config),
        )
        .route("/sso/saml/{org_id}/acs", post(post_saml_acs))
        .route("/compliance/{framework}", get(get_compliance))
        .route("/export/json", post(post_export_json))
        .route("/export/pdf", post(post_export_pdf))
        .route("/integrity", get(get_integrity))
        .route("/checkpoints", get(get_checkpoints))
        .route("/checkpoints/{id}", get(get_checkpoint))
        .route("/health", get(get_health))
        .fallback(v1_not_found);

    let cors = state.cors.build_layer();

    Router::new()
        .route("/", get(landing::index))
        .route("/dashboard", get(dashboard::index))
        .nest("/v1", api)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_request_middleware,
        ))
        .layer(cors)
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}

pub async fn serve(
    port: u16,
    api_key: Option<String>,
    db_path: impl AsRef<Path>,
    options: AppOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = shared_state_with_db_and_options(db_path, api_key, options)?;
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

pub async fn query_actions_for_cli(
    state: &SharedState,
    query: ActionsQuery,
) -> Result<Vec<ActionRecord>, String> {
    run_action_query(state, &RequestAuth::default(), &query)
        .await
        .map_err(|err| err.message)
}

pub async fn query_auth_audit_for_cli(
    state: &SharedState,
    query: AuthAuditQuery,
) -> Result<Vec<AuthAuditRecord>, String> {
    run_auth_audit_query(state, &query)
        .await
        .map_err(|err| err.message)
}

pub async fn export_json_for_cli(
    state: &SharedState,
    framework: Option<String>,
) -> Result<Value, String> {
    build_export_json(state, &RequestAuth::default(), framework, None)
        .await
        .map_err(|err| err.message)
}

pub async fn export_pdf_for_cli(
    state: &SharedState,
    framework: Option<String>,
) -> Result<Vec<u8>, String> {
    build_export_pdf(state, &RequestAuth::default(), framework, None)
        .await
        .map_err(|err| err.message)
}

pub async fn export_auth_audit_for_cli(
    state: &SharedState,
    request: AuthAuditExportRequest,
) -> Result<Value, String> {
    build_auth_audit_export(state, &RequestAuth::default(), &request)
        .await
        .map_err(|err| err.message)
}

pub async fn verify_integrity_for_cli(state: &SharedState) -> IntegrityReport {
    verify_integrity(state).await
}

pub fn status_report(api_key: Option<&str>) -> StatusReport {
    StatusReport {
        service: "trailing",
        storage: "sqlite",
        api_key_configured: api_key.is_some(),
    }
}

async fn api_request_middleware(
    State(state): State<SharedState>,
    mut request: AxumRequest,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let is_api_request = path.starts_with("/v1/");
    let is_public_request = is_public_api_route(&method, &path);
    let client_ip = client_ip(&request);
    let request_id = Uuid::new_v4().to_string();
    let started_at = Instant::now();
    let is_preflight = method == axum::http::Method::OPTIONS;
    let resolved_auth = resolve_request_auth(&state, &request);
    let mut rate_limit_headers = None;
    let auth_required = if is_api_request && !is_preflight {
        match auth_required(&state) {
            Ok(required) => required,
            Err(error) => {
                let mut response = error.with_request_id(&request_id).into_response();
                set_standard_headers(&mut response, &request_id);
                log_request(
                    &method,
                    &path,
                    response.status(),
                    started_at.elapsed(),
                    &client_ip,
                    &request_id,
                );
                return response;
            }
        }
    } else {
        false
    };

    let resolved_auth = match resolved_auth {
        Ok(auth) => auth,
        Err(error) if is_api_request && !is_preflight => {
            let mut response = error.with_request_id(&request_id).into_response();
            set_standard_headers(&mut response, &request_id);
            log_request(
                &method,
                &path,
                response.status(),
                started_at.elapsed(),
                &client_ip,
                &request_id,
            );
            return response;
        }
        Err(_) => ResolvedRequestAuth {
            auth: RequestAuth::anonymous(),
            rate_limit_bucket: None,
        },
    };

    request.extensions_mut().insert(resolved_auth.auth.clone());
    let rate_limit_bucket = resolved_auth
        .rate_limit_bucket
        .as_deref()
        .unwrap_or(&client_ip);
    let rate_limit_result = if is_api_request && !is_preflight {
        let now_epoch = Utc::now().timestamp().max(0) as u64;
        let decision = rate_limit_decision(
            &state,
            &resolved_auth.auth,
            rate_limit_bucket,
            started_at,
            now_epoch,
        );
        rate_limit_headers = Some(decision.headers);
        Some(decision)
    } else {
        None
    };

    let mut response = if is_api_request && !is_preflight {
        if auth_required && !is_public_request && !resolved_auth.auth.is_authenticated() {
            ApiError::unauthorized("missing authentication credentials").into_response()
        } else if resolved_auth.auth.is_authenticated() {
            match required_operation(&path, &method)
                .map(|operation| resolved_auth.auth.require(operation))
                .transpose()
            {
                Ok(_) => {
                    if requires_org_scope(&path, &method, &state, &resolved_auth.auth) {
                        ApiError::unauthorized("org-scoped credentials required").into_response()
                    } else if rate_limit_result.is_some_and(|decision| !decision.allowed) {
                        ApiError::rate_limited("rate limit exceeded").into_response()
                    } else if let Err(error) = attach_scope(&state, &mut request) {
                        error.into_response()
                    } else {
                        next.run(request).await
                    }
                }
                Err(error) => error.into_response(),
            }
        } else {
            if requires_org_scope(&path, &method, &state, &resolved_auth.auth) {
                ApiError::unauthorized("org-scoped credentials required").into_response()
            } else if rate_limit_result.is_some_and(|decision| !decision.allowed) {
                ApiError::rate_limited("rate limit exceeded").into_response()
            } else if let Err(error) = attach_scope(&state, &mut request) {
                error.into_response()
            } else {
                next.run(request).await
            }
        }
    } else if !rate_limit_decision(
        &state,
        &RequestAuth::anonymous(),
        &client_ip,
        started_at,
        Utc::now().timestamp().max(0) as u64,
    )
    .allowed
    {
        ApiError::rate_limited("rate limit exceeded").into_response()
    } else {
        if let Err(error) = attach_scope(&state, &mut request) {
            error.into_response()
        } else {
            next.run(request).await
        }
    };

    response = attach_request_id_to_error_response(response, &request_id).await;
    set_standard_headers(&mut response, &request_id);
    if let Some(headers) = rate_limit_headers {
        set_rate_limit_headers(&mut response, headers);
    }

    if is_api_request {
        log_request(
            &method,
            &path,
            response.status(),
            started_at.elapsed(),
            &client_ip,
            &request_id,
        );
    }

    response
}

async fn security_headers_middleware(request: AxumRequest, next: Next) -> Response {
    let uses_tls = request_uses_tls(&request);
    let mut response = next.run(request).await;
    set_security_headers(&mut response, uses_tls);
    response
}

fn attach_scope(state: &SharedState, request: &mut AxumRequest) -> Result<(), ApiError> {
    if request.uri().path() == "/v1/openapi.yml" {
        return Ok(());
    }

    let auth = request.extensions().get::<RequestAuth>();
    let scope = resolve_scope(state, request.headers(), auth)?;
    request.extensions_mut().insert(scope);
    Ok(())
}

fn resolve_scope(
    state: &SharedState,
    headers: &axum::http::HeaderMap,
    auth: Option<&RequestAuth>,
) -> Result<ResolvedScope, ApiError> {
    let requested_org_id = header_scope_value(headers, &ORG_ID_HEADER)?;
    let org_id = resolve_request_org_scope(
        auth.unwrap_or(&RequestAuth::default()),
        requested_org_id.as_deref(),
    )?
    .unwrap_or_else(|| state.default_scope.org_id.clone());
    let project_id = header_scope_value(headers, &PROJECT_ID_HEADER)?
        .unwrap_or_else(|| state.default_scope.project_id.clone());

    Ok(ResolvedScope { org_id, project_id })
}

fn header_scope_value(
    headers: &axum::http::HeaderMap,
    name: &HeaderName,
) -> Result<Option<String>, ApiError> {
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ApiError::bad_request(format!("invalid `{name}` header")))
                .map(str::trim)
                .map(|value| {
                    if value.is_empty() {
                        Err(ApiError::bad_request(format!("missing `{name}` value")))
                    } else {
                        Ok(value.to_string())
                    }
                })?
        })
        .transpose()
}

fn auth_required(state: &SharedState) -> Result<bool, ApiError> {
    let _ = state;
    Ok(true)
}

fn is_public_api_route(method: &axum::http::Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&axum::http::Method::POST, "/v1/auth/mfa/challenge")
            | (&axum::http::Method::POST, "/v1/auth/mfa/challenge/verify")
            | (&axum::http::Method::GET, "/v1/health")
    ) || (*method == axum::http::Method::POST
        && path.starts_with("/v1/sso/saml/")
        && path.ends_with("/acs"))
}

fn required_operation(path: &str, method: &axum::http::Method) -> Option<ApiOperation> {
    match (method, path) {
        (&axum::http::Method::GET, "/v1/openapi.yml")
        | (&axum::http::Method::GET, "/v1/me")
        | (&axum::http::Method::GET, "/v1/events")
        | (&axum::http::Method::GET, "/v1/actions")
        | (&axum::http::Method::GET, "/v1/retention/summary")
        | (&axum::http::Method::GET, "/v1/auth/audit")
        | (&axum::http::Method::GET, "/v1/integrity")
        | (&axum::http::Method::GET, "/v1/checkpoints")
        | (&axum::http::Method::GET, "/v1/health") => Some(ApiOperation::Query),
        (&axum::http::Method::GET, "/v1/admin/api-keys")
        | (&axum::http::Method::POST, "/v1/admin/api-keys")
        | (&axum::http::Method::GET, "/v1/admin/roles") => Some(ApiOperation::Admin),
        (&axum::http::Method::POST, "/v1/traces")
        | (&axum::http::Method::POST, "/v1/traces/batch")
        | (&axum::http::Method::POST, "/v1/traces/otlp")
        | (&axum::http::Method::POST, "/v1/oversight") => Some(ApiOperation::Ingest),
        (&axum::http::Method::POST, "/v1/export/json")
        | (&axum::http::Method::POST, "/v1/export/pdf")
        | (&axum::http::Method::POST, "/v1/auth/audit/export") => Some(ApiOperation::Export),
        (&axum::http::Method::GET, path)
        | (&axum::http::Method::PUT, path)
        | (&axum::http::Method::DELETE, path)
            if path.starts_with("/v1/orgs/") && path.ends_with("/settings") =>
        {
            Some(ApiOperation::Configure)
        }
        (&axum::http::Method::GET, path) | (&axum::http::Method::PUT, path)
            if (path.starts_with("/v1/orgs/") && path.ends_with("/mfa-policy"))
                || (path.starts_with("/v1/admin/orgs/") && path.ends_with("/sso/saml")) =>
        {
            Some(ApiOperation::Configure)
        }
        (&axum::http::Method::POST, path)
            if path.starts_with("/v1/sso/saml/") && path.ends_with("/acs") =>
        {
            None
        }
        (&axum::http::Method::POST, path) if path.starts_with("/v1/auth/mfa/") => None,
        (&axum::http::Method::GET, path)
            if path.starts_with("/v1/actions/")
                || path.starts_with("/v1/compliance/")
                || path.starts_with("/v1/checkpoints/") =>
        {
            Some(ApiOperation::Query)
        }
        (&axum::http::Method::DELETE, path) if path.starts_with("/v1/admin/api-keys/") => {
            Some(ApiOperation::Admin)
        }
        (_, path) if path.starts_with("/v1/") => {
            eprintln!(
                "{}",
                json!({
                    "level": "warn",
                    "message": "unrecognized API route missing permission mapping",
                    "method": method.as_str(),
                    "path": path,
                })
            );
            Some(ApiOperation::Admin)
        }
        _ => None,
    }
}

fn requires_org_scope(
    path: &str,
    method: &axum::http::Method,
    state: &SharedState,
    auth: &RequestAuth,
) -> bool {
    method == axum::http::Method::POST
        && matches!(path, "/v1/traces" | "/v1/traces/batch" | "/v1/traces/otlp")
        && (state.api_key.is_some() || auth.is_authenticated())
        && auth.org_id.is_none()
}

fn resolve_request_auth(
    state: &SharedState,
    request: &AxumRequest,
) -> Result<ResolvedRequestAuth, ApiError> {
    if let Some(api_key) = api_key_header(request.headers())? {
        return resolve_api_key_auth(state, request.headers(), api_key);
    }

    if let Some(token) = bearer_token(request.headers())? {
        return resolve_bearer_or_api_key_auth(state, request.headers(), token);
    }

    if let Some(token) = events_query_token(request)? {
        return resolve_bearer_or_api_key_auth(state, request.headers(), token);
    }

    if let Some(token) = session_cookie_token(request.headers())? {
        return resolve_session_token_auth(state, token);
    }

    Ok(ResolvedRequestAuth {
        auth: RequestAuth::anonymous(),
        rate_limit_bucket: None,
    })
}

fn resolve_api_key_auth(
    state: &SharedState,
    headers: &HeaderMap,
    raw_key: &str,
) -> Result<ResolvedRequestAuth, ApiError> {
    let stored_key = state
        .storage
        .lock()
        .map_err(|_| ApiError::internal("failed to process the request"))?
        .authenticate_api_key(raw_key)
        .map_err(ApiError::from_storage)?;

    if let Some(stored_key) = stored_key {
        let auth = request_auth_from_api_key(stored_key);

        return Ok(ResolvedRequestAuth {
            rate_limit_bucket: Some(auth.rate_limit_bucket.clone()),
            auth,
        });
    }

    if state
        .api_key
        .as_deref()
        .is_some_and(|expected| api_key_matches(expected, raw_key))
    {
        let org_id = header_string(headers, &ORG_ID_HEADER)
            .or_else(|| Some("00000000-0000-0000-0000-000000000000".to_string()));
        let rate_limit_bucket = org_id
            .as_ref()
            .map(|org_id| format!("org:{org_id}"))
            .unwrap_or_else(|| "shared-key".to_string());

        return Ok(ResolvedRequestAuth {
            auth: RequestAuth {
                principal_id: Some("legacy-api-key".to_string()),
                org_id,
                roles: vec!["admin".to_string()],
                is_admin: true,
                rate_limit_bucket: rate_limit_bucket.clone(),
                ..RequestAuth::default()
            },
            rate_limit_bucket: Some(rate_limit_bucket),
        });
    }

    Err(ApiError::unauthorized("missing or invalid API key"))
}

fn resolve_bearer_auth(state: &SharedState, token: &str) -> Result<ResolvedRequestAuth, ApiError> {
    {
        let auth_tokens = state
            .auth_tokens
            .lock()
            .map_err(|_| ApiError::internal("failed to process the request"))?;

        if let Some(auth) = auth_tokens.service_account_tokens.get(token) {
            return Ok(ResolvedRequestAuth {
                auth: auth.clone(),
                rate_limit_bucket: auth.principal_id.as_ref().map(|id| format!("service:{id}")),
            });
        }

        if let Some(auth) = auth_tokens.session_tokens.get(token) {
            return Ok(ResolvedRequestAuth {
                auth: auth.clone(),
                rate_limit_bucket: auth.principal_id.as_ref().map(|id| format!("session:{id}")),
            });
        }
    }

    let session = state
        .storage
        .lock()
        .map_err(|_| ApiError::internal("failed to process the request"))?
        .authenticate_session(token)
        .map_err(ApiError::from_storage)?;

    if let Some(session) = session {
        let auth = request_auth_from_session(session);
        return Ok(ResolvedRequestAuth {
            rate_limit_bucket: Some(auth.rate_limit_bucket.clone()),
            auth,
        });
    }

    Err(ApiError::unauthorized("missing or invalid bearer token"))
}

fn resolve_bearer_or_api_key_auth(
    state: &SharedState,
    headers: &HeaderMap,
    token: &str,
) -> Result<ResolvedRequestAuth, ApiError> {
    match resolve_bearer_auth(state, token) {
        Ok(auth) => Ok(auth),
        Err(error) if error.status == StatusCode::UNAUTHORIZED => {
            match resolve_api_key_auth(state, headers, token) {
                Ok(auth) => Ok(auth),
                Err(api_key_error) if api_key_error.status == StatusCode::UNAUTHORIZED => {
                    Err(ApiError::unauthorized("missing or invalid bearer token"))
                }
                Err(api_key_error) => Err(api_key_error),
            }
        }
        Err(error) => Err(error),
    }
}

fn resolve_session_token_auth(
    state: &SharedState,
    token: &str,
) -> Result<ResolvedRequestAuth, ApiError> {
    resolve_bearer_auth(state, token)
}

fn events_query_token(request: &AxumRequest) -> Result<Option<&str>, ApiError> {
    if request.uri().path() != "/v1/events" {
        return Ok(None);
    }

    let Some(query) = request.uri().query() else {
        return Ok(None);
    };

    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name != "token" {
            continue;
        }

        let token = value.trim();
        if token.is_empty() {
            return Err(ApiError::unauthorized("missing token query parameter"));
        }

        return Ok(Some(token));
    }

    Ok(None)
}

fn api_key_header(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    match headers.get("x-api-key") {
        Some(value) => {
            Ok(Some(value.to_str().map_err(|_| {
                ApiError::unauthorized("invalid x-api-key header")
            })?))
        }
        None => Ok(None),
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| ApiError::unauthorized("invalid authorization header"))?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or_else(|| ApiError::unauthorized("invalid authorization header"))?;

    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(ApiError::unauthorized("unsupported authorization scheme"));
    }

    let token = token.trim();
    if token.is_empty() {
        return Err(ApiError::unauthorized("missing bearer token"));
    }

    Ok(Some(token))
}

fn session_cookie_token(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    for value in headers.get_all(COOKIE) {
        let value = value
            .to_str()
            .map_err(|_| ApiError::unauthorized("invalid cookie header"))?;

        for cookie in value.split(';') {
            let Some((name, token)) = cookie.trim().split_once('=') else {
                continue;
            };
            if matches!(
                name.trim(),
                "session" | "session_token" | "trailing_session"
            ) {
                let token = token.trim();
                if token.is_empty() {
                    return Err(ApiError::unauthorized("missing session token"));
                }
                return Ok(Some(token));
            }
        }
    }

    Ok(None)
}

fn request_auth_from_api_key(authenticated: AuthenticatedApiKey) -> RequestAuth {
    RequestAuth {
        principal_id: Some(authenticated.id.clone()),
        key_id: Some(authenticated.id.clone()),
        org_id: Some(authenticated.org_id.clone()),
        roles: authenticated
            .roles
            .iter()
            .map(|role| role.as_str().to_string())
            .collect(),
        is_admin: authenticated.is_admin,
        rate_limit_bucket: format!("api-key:{}", authenticated.id),
        ..RequestAuth::default()
    }
}

fn request_auth_from_session(authenticated: AuthenticatedSession) -> RequestAuth {
    let role = authenticated.role.clone();
    RequestAuth {
        principal_id: Some(authenticated.user_id.clone()),
        session_id: Some(authenticated.id.clone()),
        user_id: Some(authenticated.user_id.clone()),
        org_id: Some(authenticated.org_id.clone()),
        email: Some(authenticated.email.clone()),
        display_name: Some(authenticated.display_name.clone()),
        expires_at: Some(authenticated.expires_at.clone()),
        roles: vec![role.clone()],
        is_admin: role == "admin",
        rate_limit_bucket: format!("session:{}", authenticated.id),
        ..RequestAuth::default()
    }
}

fn header_string(headers: &HeaderMap, name: &HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn role_definition_response(role: &crate::auth::RoleDefinition) -> RoleDefinitionResponse {
    RoleDefinitionResponse {
        name: role.name.to_string(),
        permissions: role
            .permissions
            .iter()
            .map(|permission| permission.to_string())
            .collect(),
    }
}

fn masked_api_key(key_id: &str) -> String {
    format!("{API_KEY_PREFIX}{key_id}_********")
}

fn map_json_rejection(rejection: JsonRejection) -> ApiError {
    match rejection {
        JsonRejection::JsonDataError(error) => {
            let message = error.body_text();
            if message.contains("missing field") {
                ApiError::missing_field(message)
            } else {
                ApiError::invalid_json(message)
            }
        }
        JsonRejection::JsonSyntaxError(error) => ApiError::invalid_json(error.body_text()),
        JsonRejection::MissingJsonContentType(error) => ApiError::invalid_json(error.body_text()),
        JsonRejection::BytesRejection(error) => {
            if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::request_too_large(error.body_text())
            } else {
                ApiError::invalid_json(error.body_text())
            }
        }
        _ => ApiError::invalid_json(rejection.body_text()),
    }
}

fn rate_limit_decision(
    state: &SharedState,
    auth: &RequestAuth,
    bucket_id: &str,
    now: Instant,
    now_epoch: u64,
) -> RateLimitDecision {
    let mut limiter = match state.rate_limiter.lock() {
        Ok(limiter) => limiter,
        Err(_) => {
            return RateLimitDecision {
                allowed: true,
                headers: RateLimitHeaders {
                    limit: 0,
                    remaining: 0,
                    reset_at_epoch: now_epoch,
                },
            };
        }
    };
    limiter.check(
        RateLimitKey {
            org_id: auth
                .org_id
                .clone()
                .unwrap_or_else(|| ANONYMOUS_ORG_ID.to_string()),
            bucket_id: bucket_id.to_string(),
        },
        now,
        now_epoch,
    )
}

fn api_key_matches(expected: &str, provided: &str) -> bool {
    let expected_digest = Sha256::digest(expected.as_bytes());
    let provided_digest = Sha256::digest(provided.as_bytes());
    constant_time_eq(expected_digest.as_slice(), provided_digest.as_slice())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (lhs, rhs) in left.iter().zip(right.iter()) {
        diff |= lhs ^ rhs;
    }

    diff == 0
}

fn client_ip(request: &AxumRequest) -> String {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn set_standard_headers(response: &mut Response, request_id: &str) {
    if let Ok(request_id) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, request_id);
    }
    response
        .headers_mut()
        .insert(VERSION_HEADER, HeaderValue::from_static(TRAILING_VERSION));
}

fn set_security_headers(response: &mut Response, uses_tls: bool) {
    response.headers_mut().insert(
        X_CONTENT_TYPE_OPTIONS_HEADER,
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(X_FRAME_OPTIONS_HEADER, HeaderValue::from_static("DENY"));
    response
        .headers_mut()
        .insert(X_XSS_PROTECTION_HEADER, HeaderValue::from_static("0"));
    response.headers_mut().insert(
        REFERRER_POLICY_HEADER,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    if uses_tls {
        response.headers_mut().insert(
            STRICT_TRANSPORT_SECURITY_HEADER,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
}

fn set_rate_limit_headers(response: &mut Response, headers: RateLimitHeaders) {
    if let Ok(limit) = HeaderValue::from_str(&headers.limit.to_string()) {
        response
            .headers_mut()
            .insert(RATE_LIMIT_LIMIT_HEADER, limit);
    }
    if let Ok(remaining) = HeaderValue::from_str(&headers.remaining.to_string()) {
        response
            .headers_mut()
            .insert(RATE_LIMIT_REMAINING_HEADER, remaining);
    }
    if let Ok(reset) = HeaderValue::from_str(&headers.reset_at_epoch.to_string()) {
        response
            .headers_mut()
            .insert(RATE_LIMIT_RESET_HEADER, reset);
    }
}

fn log_request(
    method: &axum::http::Method,
    path: &str,
    status: StatusCode,
    duration: Duration,
    client_ip: &str,
    request_id: &str,
) {
    eprintln!(
        "{}",
        json!({
            "method": method.as_str(),
            "path": path,
            "status_code": status.as_u16(),
            "duration_ms": duration.as_millis(),
            "client_ip": client_ip,
            "request_id": request_id,
        })
    );
}

fn request_uses_tls(request: &AxumRequest) -> bool {
    request
        .uri()
        .scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
        || header_uses_tls(request.headers())
}

fn header_uses_tls(headers: &HeaderMap) -> bool {
    headers
        .get(&X_FORWARDED_PROTO_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(forwarded_proto_contains_https)
        || headers
            .get(FORWARDED)
            .and_then(|value| value.to_str().ok())
            .is_some_and(forwarded_header_contains_https)
}

fn forwarded_proto_contains_https(value: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|proto| proto.eq_ignore_ascii_case("https"))
}

fn forwarded_header_contains_https(value: &str) -> bool {
    value.split(',').any(|entry| {
        entry.split(';').any(|segment| {
            let Some((name, forwarded_value)) = segment.trim().split_once('=') else {
                return false;
            };

            name.trim().eq_ignore_ascii_case("proto")
                && forwarded_value.trim_matches('"').eq_ignore_ascii_case("https")
        })
    })
}

async fn attach_request_id_to_error_response(response: Response, request_id: &str) -> Response {
    if !(response.status().is_client_error() || response.status().is_server_error()) {
        return response;
    }

    let is_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if !is_json {
        return response;
    }

    let (parts, body) = response.into_parts();
    let Ok(body) = to_bytes(body, usize::MAX).await else {
        return ApiError::internal("failed to process the request")
            .with_request_id(request_id)
            .into_response();
    };
    let mut payload = match serde_json::from_slice::<Value>(&body) {
        Ok(payload) => payload,
        Err(_) => return rebuild_response(parts, body.to_vec()),
    };

    let should_attach = payload
        .as_object()
        .and_then(|object| object.get("error"))
        .and_then(Value::as_object)
        .is_some_and(|error| error.contains_key("code") && error.contains_key("message"));
    if !should_attach {
        return rebuild_response(parts, body.to_vec());
    }

    let Some(object) = payload.as_object_mut() else {
        return rebuild_response(parts, body.to_vec());
    };
    if object.contains_key("request_id") {
        return rebuild_response(parts, body.to_vec());
    }

    object.insert(
        "request_id".to_string(),
        Value::String(request_id.to_string()),
    );
    match serde_json::to_vec(&payload) {
        Ok(body) => rebuild_response(parts, body),
        Err(_) => rebuild_response(parts, body.to_vec()),
    }
}

fn rebuild_response(mut parts: axum::http::response::Parts, body: Vec<u8>) -> Response {
    parts.headers.remove(CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(body))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn v1_not_found() -> ApiError {
    ApiError::not_found("route not found")
}

async fn get_openapi_spec() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "application/yaml; charset=utf-8")],
        OPENAPI_YAML,
    )
}

async fn get_events(
    State(state): State<SharedState>,
    Extension(scope): Extension<ResolvedScope>,
) -> impl IntoResponse {
    let mut receiver = state.live_events.subscribe();
    let stream = stream! {
        loop {
            let live_event = match receiver.recv().await {
                Ok(live_event) => live_event,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            };

            let event = match live_event {
                LiveEvent::Action { scope: event_scope, action } if event_scope == scope => {
                    sse_json_event("action", &action)
                }
                LiveEvent::Oversight { scope: event_scope, event } if event_scope == scope => {
                    sse_json_event("oversight", &event)
                }
                _ => None,
            };

            if let Some(event) = event {
                yield Result::<Event, Infallible>::Ok(event);
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(SSE_HEARTBEAT_INTERVAL)
            .text("heartbeat"),
    )
}

async fn post_traces(
    State(state): State<SharedState>,
    auth: RequestAuth,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<Value>,
) -> Result<Response, ApiError> {
    ensure_trace_ingest_allowed(&auth)?;
    if payload.get("actions").is_some() {
        return ingest_batch_payload(
            &state,
            &auth,
            payload,
            "sdk",
            header_string(&headers, &IDEMPOTENCY_KEY_HEADER),
        )
        .await;
    }

    let outcome = ingest_single_payload(
        &state,
        &auth,
        payload,
        "sdk",
        header_string(&headers, &IDEMPOTENCY_KEY_HEADER),
    )
    .await?;
    Ok(single_ingest_response(outcome).into_response())
}

async fn post_traces_batch(
    State(state): State<SharedState>,
    auth: RequestAuth,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<Value>,
) -> Result<Response, ApiError> {
    ensure_trace_ingest_allowed(&auth)?;
    ingest_batch_payload(
        &state,
        &auth,
        payload,
        "sdk",
        header_string(&headers, &IDEMPOTENCY_KEY_HEADER),
    )
    .await
}

async fn post_traces_otlp(
    State(state): State<SharedState>,
    auth: RequestAuth,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<Value>,
) -> Result<impl IntoResponse, ApiError> {
    ensure_trace_ingest_allowed(&auth)?;
    let actions = ingest_otlp_payload(
        &state,
        &auth,
        payload,
        header_string(&headers, &IDEMPOTENCY_KEY_HEADER),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(IngestResponse {
            ingested: actions.len(),
            action_ids: actions,
        }),
    ))
}

async fn get_actions(
    State(state): State<SharedState>,
    auth: RequestAuth,
    ApiQuery(query): ApiQuery<ActionsListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let actions = run_action_query(
        &state,
        &auth,
        &ActionsQuery {
            session_id: query.session_id,
            agent: query.agent,
            from: query.from,
            to: query.to,
            action_type: query.action_type,
            include_oversight: query.include_oversight,
        },
    )
    .await?;
    let total = actions.len();
    let limit = query
        .limit
        .unwrap_or(DEFAULT_ACTIONS_LIMIT)
        .min(MAX_ACTIONS_LIMIT);
    let offset = query.offset.unwrap_or(0);
    let paged_actions = actions
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    let count = paged_actions.len();

    Ok(Json(PaginatedActionsResponse {
        actions: paged_actions,
        total,
        pagination: PaginationMetadata {
            limit,
            offset,
            count,
            has_more: offset.saturating_add(count) < total,
        },
    }))
}

async fn get_action(
    State(state): State<SharedState>,
    auth: RequestAuth,
    AxumPath(id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    let action = load_action_records(&state, &auth, true)?
        .into_iter()
        .find(|action| action.id == id)
        .ok_or_else(|| ApiError::not_found(format!("action {id} not found")))?;

    Ok(Json(action))
}

async fn get_me(auth: RequestAuth) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(require_sso_session(&auth)?))
}

async fn post_admin_api_key(
    State(state): State<SharedState>,
    Extension(scope): Extension<ResolvedScope>,
    ApiJson(request): ApiJson<AdminApiKeyCreateRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let created = lock_storage(&state)?
        .create_api_key_with_roles(
            &scope.org_id,
            &request.name,
            Some(std::slice::from_ref(&request.role)),
        )
        .map_err(ApiError::from_storage)?;

    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_admin_api_keys(
    State(state): State<SharedState>,
    Extension(scope): Extension<ResolvedScope>,
) -> Result<impl IntoResponse, ApiError> {
    let api_keys = lock_storage(&state)?
        .list_api_keys_for_org(&scope.org_id)
        .map_err(ApiError::from_storage)?
        .into_iter()
        .map(|key| MaskedApiKeyRecord {
            masked_key: masked_api_key(&key.id),
            id: key.id,
            org_id: key.org_id,
            name: key.name,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
            revoked: key.revoked,
            is_admin: key.is_admin,
            roles: key.roles,
        })
        .collect();

    Ok(Json(AdminApiKeysResponse { api_keys }))
}

async fn delete_admin_api_key(
    State(state): State<SharedState>,
    Extension(scope): Extension<ResolvedScope>,
    AxumPath(key_id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    let revoked = lock_storage(&state)?
        .revoke_api_key_for_org(&scope.org_id, &key_id)
        .map_err(ApiError::from_storage)?;

    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!(
            "API key {key_id} not found for org {}",
            scope.org_id
        )))
    }
}

async fn get_admin_roles() -> Result<impl IntoResponse, ApiError> {
    Ok(Json(AdminRolesResponse {
        api_key_roles: api_key_role_definitions()
            .iter()
            .map(role_definition_response)
            .collect(),
        principal_roles: principal_role_definitions()
            .iter()
            .map(role_definition_response)
            .collect(),
    }))
}

async fn get_saml_config(
    State(state): State<SharedState>,
    auth: RequestAuth,
    AxumPath(org_id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    ensure_saml_admin_access(&state, &auth, &org_id)?;
    let storage = lock_storage(&state)?;
    let config = storage
        .saml_config(&org_id)
        .map_err(ApiError::from_storage)?
        .ok_or_else(|| ApiError::not_found(format!("SAML config for org `{org_id}` not found")))?;
    Ok(Json(config))
}

async fn put_saml_config(
    State(state): State<SharedState>,
    auth: RequestAuth,
    AxumPath(org_id): AxumPath<String>,
    ApiJson(request): ApiJson<SamlConfigRequest>,
) -> Result<impl IntoResponse, ApiError> {
    ensure_saml_admin_access(&state, &auth, &org_id)?;
    validate_saml_config_request(&request)?;
    let config = lock_storage(&state)?
        .upsert_saml_config(
            &org_id,
            UpsertSamlIdpConfig {
                enabled: request.enabled.unwrap_or(true),
                idp_entity_id: request.idp_entity_id,
                sso_url: request.sso_url,
                idp_certificate_pem: request.idp_certificate_pem,
                sp_entity_id: request.sp_entity_id,
                acs_url: request.acs_url,
                email_attribute: request.email_attribute,
                first_name_attribute: request.first_name_attribute,
                last_name_attribute: request.last_name_attribute,
                role_attribute: request.role_attribute,
                role_mappings: request.role_mappings,
                default_role: request.default_role,
            },
        )
        .map_err(ApiError::from_storage)?;
    Ok((StatusCode::CREATED, Json(config)))
}

async fn post_saml_acs(
    State(state): State<SharedState>,
    AxumPath(org_id): AxumPath<String>,
    request: AxumRequest,
) -> Result<impl IntoResponse, ApiError> {
    let payload = parse_saml_acs_request(request).await?;
    let (config, session) = {
        let storage = lock_storage(&state)?;
        let config = storage
            .saml_config(&org_id)
            .map_err(ApiError::from_storage)?
            .ok_or_else(|| {
                ApiError::not_found(format!("SAML config for org `{org_id}` not found"))
            })?;
        if !config.enabled {
            return Err(ApiError::unauthorized(
                "SAML is disabled for this organization",
            ));
        }

        let claims = validate_saml_response(&payload.saml_response, &config).map_err(|error| {
            if error.is_dependency_error() {
                ApiError::service_unavailable(error.to_string())
            } else {
                ApiError::unauthorized("invalid SAML assertion".to_string())
            }
        })?;
        let role = resolve_internal_role(&config, &claims.role_values);
        let user = storage
            .provision_sso_user(
                &org_id,
                &claims.subject,
                &claims.email,
                claims.first_name.as_deref(),
                claims.last_name.as_deref(),
                &role,
            )
            .map_err(ApiError::from_storage)?;
        let session = storage
            .create_sso_session(&user, SSO_SESSION_TTL)
            .map_err(ApiError::from_storage)?;
        (config, session)
    };

    Ok(Json(json!({
        "org_id": config.org_id,
        "session_token": session.token,
        "expires_at": session.expires_at,
        "relay_state": payload.relay_state,
        "user": session.user,
    })))
}

async fn post_mfa_challenge(
    State(state): State<SharedState>,
    ApiJson(request): ApiJson<MfaChallengeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let result = {
        let storage = lock_storage(&state)?;
        storage
            .create_mfa_challenge(
                &request.org_id,
                &request.email,
                &request.password,
                current_time(),
            )
            .map_err(map_auth_storage_error)?
    };

    match result {
        MfaChallengeStart::Authenticated {
            user_id,
            org_id,
            email,
        } => {
            append_auth_audit_event(
                &state,
                &org_id,
                &user_id,
                &email,
                "auth.mfa.challenge",
                "not_enabled",
                "authenticated",
                json!({
                    "event": "auth.mfa.challenge",
                    "org_id": org_id,
                    "user_id": user_id,
                    "email": email,
                    "mfa_status": "not_enabled",
                    "result": "authenticated",
                }),
            )?;

            Ok(Json(json!({
                "status": "authenticated",
                "org_id": org_id,
                "email": email,
                "mfa_required": false,
                "mfa_status": "not_enabled",
            })))
        }
        MfaChallengeStart::ChallengeRequired {
            user_id,
            org_id,
            email,
            challenge_id,
            expires_at,
        } => {
            append_auth_audit_event(
                &state,
                &org_id,
                &user_id,
                &email,
                "auth.mfa.challenge",
                "challenge_required",
                "pending",
                json!({
                    "event": "auth.mfa.challenge",
                    "org_id": org_id,
                    "user_id": user_id,
                    "email": email,
                    "challenge_id": challenge_id,
                    "expires_at": expires_at,
                    "mfa_status": "challenge_required",
                    "result": "pending",
                }),
            )?;

            Ok(Json(json!({
                "status": "challenge_required",
                "org_id": org_id,
                "email": email,
                "challenge_id": challenge_id,
                "expires_at": expires_at,
                "mfa_required": true,
                "available_methods": ["totp", "recovery_code"],
                "mfa_status": "challenge_required",
            })))
        }
        MfaChallengeStart::EnrollmentRequired {
            user_id,
            org_id,
            email,
        } => {
            append_auth_audit_event(
                &state,
                &org_id,
                &user_id,
                &email,
                "auth.mfa.challenge",
                "required_not_enrolled",
                "blocked",
                json!({
                    "event": "auth.mfa.challenge",
                    "org_id": org_id,
                    "user_id": user_id,
                    "email": email,
                    "mfa_status": "required_not_enrolled",
                    "result": "blocked",
                }),
            )?;

            Ok(Json(json!({
                "status": "enrollment_required",
                "org_id": org_id,
                "email": email,
                "mfa_required": true,
                "mfa_status": "required_not_enrolled",
            })))
        }
    }
}

async fn post_mfa_challenge_verify(
    State(state): State<SharedState>,
    ApiJson(request): ApiJson<MfaChallengeVerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let result = {
        let storage = lock_storage(&state)?;
        storage
            .verify_mfa_challenge(&request.challenge_id, &request.code, current_time())
            .map_err(map_auth_storage_error)?
    };

    append_auth_audit_event(
        &state,
        &result.org_id,
        &result.user_id,
        &result.email,
        "auth.mfa.verify",
        if result.recovery_code_used {
            "verified_recovery_code"
        } else {
            "verified_totp"
        },
        "authenticated",
        json!({
            "event": "auth.mfa.verify",
            "org_id": result.org_id,
            "user_id": result.user_id,
            "email": result.email,
            "method": result.method,
            "recovery_code_used": result.recovery_code_used,
            "mfa_status": if result.recovery_code_used {
                "verified_recovery_code"
            } else {
                "verified_totp"
            },
            "result": "authenticated",
        }),
    )?;

    Ok(Json(json!({
        "status": "authenticated",
        "org_id": result.org_id,
        "email": result.email,
        "method": result.method,
        "recovery_code_used": result.recovery_code_used,
        "mfa_required": true,
        "mfa_status": if result.recovery_code_used {
            "verified_recovery_code"
        } else {
            "verified_totp"
        },
    })))
}

async fn post_mfa_enroll_start(
    State(state): State<SharedState>,
    ApiJson(request): ApiJson<MfaEnrollStartRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let result = {
        let storage = lock_storage(&state)?;
        storage
            .start_mfa_enrollment(&request.org_id, &request.email, &request.password)
            .map_err(map_auth_storage_error)?
    };

    append_auth_audit_event(
        &state,
        &result.org_id,
        &result.user_id,
        &result.email,
        "auth.mfa.enroll.start",
        "pending_enrollment",
        "pending",
        json!({
            "event": "auth.mfa.enroll.start",
            "org_id": result.org_id,
            "user_id": result.user_id,
            "email": result.email,
            "mfa_status": "pending_enrollment",
            "result": "pending",
        }),
    )?;

    Ok(Json(json!({
        "status": "pending_confirmation",
        "org_id": result.org_id,
        "email": result.email,
        "secret": result.secret,
        "provisioning_uri": result.provisioning_uri,
        "mfa_status": "pending_enrollment",
    })))
}

async fn post_mfa_enroll_confirm(
    State(state): State<SharedState>,
    ApiJson(request): ApiJson<MfaEnrollConfirmRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let result = {
        let storage = lock_storage(&state)?;
        storage
            .confirm_mfa_enrollment(
                &request.org_id,
                &request.email,
                &request.password,
                &request.code,
                current_time(),
            )
            .map_err(map_auth_storage_error)?
    };

    append_auth_audit_event(
        &state,
        &result.org_id,
        &result.user_id,
        &result.email,
        "auth.mfa.enroll.confirm",
        "enabled",
        "authenticated",
        json!({
            "event": "auth.mfa.enroll.confirm",
            "org_id": result.org_id,
            "user_id": result.user_id,
            "email": result.email,
            "recovery_codes_generated": result.recovery_codes.len(),
            "mfa_status": "enabled",
            "result": "authenticated",
        }),
    )?;

    Ok(Json(json!({
        "status": "enabled",
        "org_id": result.org_id,
        "email": result.email,
        "recovery_codes": result.recovery_codes,
        "mfa_status": "enabled",
    })))
}

async fn get_org_mfa_policy(
    State(state): State<SharedState>,
    auth: RequestAuth,
    AxumPath(org_id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    resolve_request_org_scope(&auth, Some(&org_id))?;
    let policy = {
        let storage = lock_storage(&state)?;
        storage
            .org_mfa_policy(&org_id)
            .map_err(ApiError::from_storage)?
    };

    Ok(Json(json!({
        "org_id": org_id,
        "policy": policy.as_str(),
    })))
}

async fn put_org_mfa_policy(
    State(state): State<SharedState>,
    auth: RequestAuth,
    AxumPath(org_id): AxumPath<String>,
    ApiJson(request): ApiJson<MfaPolicyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    resolve_request_org_scope(&auth, Some(&org_id))?;
    let policy = MfaPolicy::from_str(request.policy.trim()).map_err(ApiError::bad_request)?;
    {
        let storage = lock_storage(&state)?;
        storage
            .set_org_mfa_policy(&org_id, policy)
            .map_err(ApiError::from_storage)?;
    }

    append_policy_audit_event(&state, &org_id, policy)?;

    Ok(Json(json!({
        "org_id": org_id,
        "policy": policy.as_str(),
    })))
}

async fn get_auth_audit(
    State(state): State<SharedState>,
    auth: RequestAuth,
    ApiQuery(query): ApiQuery<AuthAuditListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let org_id = resolve_request_org_scope(&auth, query.org_id.as_deref())?;
    let events = run_auth_audit_query(
        &state,
        &AuthAuditQuery {
            org_id,
            event_type: query.event_type,
            actor_id: query.actor_id,
            subject_id: query.subject_id,
            from: query.from,
            to: query.to,
        },
    )
    .await?;
    let total = events.len();
    let limit = query
        .limit
        .unwrap_or(DEFAULT_ACTIONS_LIMIT)
        .min(MAX_ACTIONS_LIMIT);
    let offset = query.offset.unwrap_or(0);
    let paged_events = events
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    let count = paged_events.len();

    Ok(Json(PaginatedAuthAuditResponse {
        events: paged_events,
        total,
        pagination: PaginationMetadata {
            limit,
            offset,
            count,
            has_more: offset.saturating_add(count) < total,
        },
    }))
}

async fn post_oversight(
    State(state): State<SharedState>,
    auth: RequestAuth,
    Extension(_scope): Extension<ResolvedScope>,
    ApiJson(payload): ApiJson<Value>,
) -> Result<impl IntoResponse, ApiError> {
    ensure_oversight_allowed(&auth)?;
    let event = append_oversight_event(&state, &auth, payload).await?;
    Ok((StatusCode::CREATED, Json(event)))
}

async fn get_org_settings(
    State(state): State<SharedState>,
    auth: RequestAuth,
    AxumPath(org_id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    resolve_request_org_scope(&auth, Some(&org_id))?;
    let storage = lock_storage(&state)?;
    let settings = storage
        .get_org_settings(&org_id)
        .map_err(ApiError::from_storage)?
        .ok_or_else(|| {
            ApiError::not_found(format!("organization settings for {org_id} not found"))
        })?;

    Ok(Json(settings))
}

async fn get_retention_summary(
    State(state): State<SharedState>,
    Extension(scope): Extension<ResolvedScope>,
) -> Result<impl IntoResponse, ApiError> {
    let storage = lock_storage(&state)?;
    let storage_control = storage.control_settings().map_err(ApiError::from_storage)?;
    let org_settings = storage
        .get_org_settings(&scope.org_id)
        .map_err(ApiError::from_storage)?;
    let active_legal_holds = storage
        .legal_holds(None)
        .map_err(ApiError::from_storage)?
        .into_iter()
        .filter(|hold| hold.released_at.is_none())
        .filter(|hold| {
            hold.org_id.is_none() || hold.org_id.as_deref() == Some(scope.org_id.as_str())
        })
        .collect::<Vec<_>>();
    let entries = storage
        .entries_for_org(Some(&scope.org_id))
        .map_err(ApiError::from_storage)?;
    let effective_retention_days = org_settings
        .as_ref()
        .and_then(OrgSettings::min_retention_days)
        .unwrap_or(storage_control.min_retention_days)
        .max(0);
    let purge_cutoff = StoredActionEntry::canonical_timestamp(
        &(current_time() - chrono::Duration::days(effective_retention_days)),
    );
    let (age_distribution, oldest_record_at, newest_record_at) =
        build_retention_age_distribution(&entries);

    Ok(Json(RetentionSummaryResponse {
        org_id: scope.org_id,
        effective_retention_days,
        policy_source: if org_settings.is_some() {
            "organization".to_string()
        } else {
            "default".to_string()
        },
        purge_cutoff,
        purge_blocked: !active_legal_holds.is_empty(),
        storage_policy: RetentionStoragePolicySummary {
            allow_purge: storage_control.allow_purge,
            min_retention_days: storage_control.min_retention_days,
        },
        organization_policy: org_settings.map(|settings| {
            let min_retention_days = settings.min_retention_days();
            let legal_hold = settings.legal_hold();
            RetentionOrganizationPolicySummary {
                org_id: settings.org_id,
                min_retention_days,
                legal_hold,
                retention_policy: settings.retention_policy,
                updated_at: settings.updated_at,
            }
        }),
        active_legal_holds,
        age_distribution,
        total_records: entries.len(),
        oldest_record_at,
        newest_record_at,
    }))
}

async fn put_org_settings(
    State(state): State<SharedState>,
    auth: RequestAuth,
    AxumPath(org_id): AxumPath<String>,
    ApiJson(request): ApiJson<OrgSettingsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    resolve_request_org_scope(&auth, Some(&org_id))?;
    let storage = lock_storage(&state)?;
    let (settings, created) = storage
        .upsert_org_settings(
            &org_id,
            OrgSettingsInput {
                retention_policy: request.retention_policy,
                enabled_frameworks: request.enabled_frameworks,
                guardrail_settings: request.guardrail_settings,
            },
        )
        .map_err(ApiError::from_storage)?;

    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(settings),
    ))
}

async fn delete_org_settings(
    State(state): State<SharedState>,
    auth: RequestAuth,
    AxumPath(org_id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    resolve_request_org_scope(&auth, Some(&org_id))?;
    let storage = lock_storage(&state)?;
    let deleted = storage
        .delete_org_settings(&org_id)
        .map_err(ApiError::from_storage)?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!(
            "organization settings for {org_id} not found"
        )))
    }
}

async fn get_compliance(
    State(state): State<SharedState>,
    auth: RequestAuth,
    AxumPath(framework): AxumPath<String>,
    ApiQuery(query): ApiQuery<ComplianceQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let report = build_compliance_report(&state, &auth, framework, query).await?;
    Ok(Json(report))
}

async fn post_export_json(
    State(state): State<SharedState>,
    auth: RequestAuth,
    ApiJson(request): ApiJson<ExportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let package = build_export_json(&state, &auth, request.framework, request.org_id).await?;
    Ok(Json(package))
}

async fn post_export_pdf(
    State(state): State<SharedState>,
    auth: RequestAuth,
    ApiJson(request): ApiJson<ExportRequest>,
) -> Result<Response, ApiError> {
    let body = build_export_pdf(&state, &auth, request.framework, request.org_id).await?;
    Ok((StatusCode::OK, [("content-type", "application/pdf")], body).into_response())
}

async fn post_auth_audit_export(
    State(state): State<SharedState>,
    auth: RequestAuth,
    ApiJson(request): ApiJson<AuthAuditExportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let export = build_auth_audit_export(&state, &auth, &request).await?;
    Ok(Json(export))
}

async fn get_integrity(
    State(state): State<SharedState>,
    Extension(_scope): Extension<ResolvedScope>,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(verify_integrity(&state).await))
}

async fn get_checkpoints(State(state): State<SharedState>) -> Result<impl IntoResponse, ApiError> {
    let storage = lock_storage(&state)?;
    let checkpoints: Vec<SignedCheckpoint> = storage
        .signed_checkpoints()
        .map_err(ApiError::from_storage)?;
    Ok(Json(checkpoints))
}

async fn get_checkpoint(
    State(state): State<SharedState>,
    AxumPath(id): AxumPath<String>,
) -> Result<impl IntoResponse, ApiError> {
    let storage = lock_storage(&state)?;
    let checkpoint: VerifiedCheckpoint = storage
        .verify_signed_checkpoint(&id)
        .map_err(ApiError::from_storage)?
        .ok_or_else(|| ApiError::not_found(format!("checkpoint not found: {id}")))?;
    Ok(Json(checkpoint))
}

async fn get_health(
    State(state): State<SharedState>,
    Extension(scope): Extension<ResolvedScope>,
) -> Result<impl IntoResponse, ApiError> {
    let storage = lock_storage(&state)?;
    let storage_scope = StorageScope {
        org_id: scope.org_id.clone(),
        project_id: scope.project_id.clone(),
    };
    let entries = storage
        .entries_for_scope(&storage_scope)
        .map_err(ApiError::from_storage)?;
    let chain_valid = match storage.verify_chain_for_scope(&storage_scope) {
        Ok(violations) => violations.is_empty(),
        Err(StorageError::InvalidInput(_)) if storage.backend_name() == "postgres" => true,
        Err(error) => return Err(ApiError::from_storage(error)),
    };
    let db_size_bytes = storage
        .database_size_bytes()
        .map_err(ApiError::from_storage)?;
    let sso_available = validate_saml_dependencies().is_ok();

    Ok(Json(HealthReport {
        status: "ok",
        service: "trailing",
        version: TRAILING_VERSION,
        uptime_seconds: state.started_at.elapsed().as_secs(),
        total_actions: entries
            .iter()
            .filter(|entry| stored_kind(entry) == StoredKind::Action)
            .count(),
        db_size_bytes,
        chain_valid,
        sso_available,
    }))
}

fn require_sso_session(auth: &RequestAuth) -> Result<SessionIdentityResponse, ApiError> {
    let role = auth
        .roles
        .first()
        .cloned()
        .ok_or_else(|| ApiError::unauthorized("missing or invalid bearer session"))?;

    Ok(SessionIdentityResponse {
        session_id: auth
            .session_id
            .clone()
            .ok_or_else(|| ApiError::unauthorized("missing or invalid bearer session"))?,
        user_id: auth
            .user_id
            .clone()
            .ok_or_else(|| ApiError::unauthorized("missing or invalid bearer session"))?,
        org_id: auth
            .org_id
            .clone()
            .ok_or_else(|| ApiError::unauthorized("missing or invalid bearer session"))?,
        email: auth
            .email
            .clone()
            .ok_or_else(|| ApiError::unauthorized("missing or invalid bearer session"))?,
        display_name: auth
            .display_name
            .clone()
            .ok_or_else(|| ApiError::unauthorized("missing or invalid bearer session"))?,
        role,
        expires_at: auth
            .expires_at
            .clone()
            .ok_or_else(|| ApiError::unauthorized("missing or invalid bearer session"))?,
    })
}

fn ensure_saml_admin_access(
    state: &SharedState,
    auth: &RequestAuth,
    org_id: &str,
) -> Result<(), ApiError> {
    if !auth_required(state)? {
        return Ok(());
    }

    resolve_request_org_scope(auth, Some(org_id))?;

    if auth.key_id.is_some() && auth.is_admin {
        return Ok(());
    }

    if auth.session_id.is_some() && auth.is_admin && auth.org_id.as_deref() == Some(org_id) {
        return Ok(());
    }

    Err(ApiError::unauthorized(
        "admin role required for this organization",
    ))
}

fn ensure_trace_ingest_allowed(auth: &RequestAuth) -> Result<(), ApiError> {
    if auth.session_id.is_some() && !auth.is_admin {
        return Err(ApiError::unauthorized(
            "admin role required for trace ingestion",
        ));
    }
    Ok(())
}

fn ensure_oversight_allowed(auth: &RequestAuth) -> Result<(), ApiError> {
    if auth.session_id.is_some()
        && !matches!(
            auth.roles.first().map(String::as_str),
            Some("admin") | Some("auditor")
        )
    {
        return Err(ApiError::unauthorized(
            "admin or auditor role required for oversight events",
        ));
    }
    Ok(())
}

fn validate_saml_config_request(request: &SamlConfigRequest) -> Result<(), ApiError> {
    if request.idp_entity_id.trim().is_empty()
        || request.sso_url.trim().is_empty()
        || request.idp_certificate_pem.trim().is_empty()
        || request.sp_entity_id.trim().is_empty()
        || request.acs_url.trim().is_empty()
        || request.email_attribute.trim().is_empty()
        || request.default_role.trim().is_empty()
    {
        return Err(ApiError::missing_field(
            "SAML config requires entity ids, endpoints, certificate, email attribute, and default role",
        ));
    }

    if !is_valid_internal_role(&request.default_role) {
        return Err(ApiError::bad_request(format!(
            "unsupported internal role `{}`",
            request.default_role
        )));
    }

    for mapped_role in request.role_mappings.values() {
        if !is_valid_internal_role(mapped_role) {
            return Err(ApiError::bad_request(format!(
                "unsupported internal role `{mapped_role}`"
            )));
        }
    }

    Ok(())
}

fn resolve_internal_role(config: &SamlIdpConfig, saml_roles: &[String]) -> String {
    saml_roles
        .iter()
        .find_map(|value| config.role_mappings.get(value))
        .cloned()
        .unwrap_or_else(|| config.default_role.clone())
}

async fn parse_saml_acs_request(request: AxumRequest) -> Result<SamlAcsJsonRequest, ApiError> {
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| ApiError::invalid_json("failed to read request body"))?;

    if content_type.starts_with("application/json") {
        let payload: SamlAcsJsonRequest = serde_json::from_slice(&body)
            .map_err(|_| ApiError::invalid_json("request body must be valid JSON"))?;
        if payload.saml_response.trim().is_empty() {
            return Err(ApiError::missing_field(
                "missing required field `saml_response`",
            ));
        }
        return Ok(payload);
    }

    let form = std::str::from_utf8(&body)
        .map_err(|_| ApiError::invalid_json("form body must be valid UTF-8"))?;
    let mut saml_response = None;
    let mut relay_state = None;

    for pair in form.split('&').filter(|pair| !pair.is_empty()) {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(raw_key)?;
        let value = percent_decode(raw_value)?;
        match key.as_str() {
            "SAMLResponse" | "saml_response" => saml_response = Some(value),
            "RelayState" | "relay_state" => relay_state = Some(value),
            _ => {}
        }
    }

    let saml_response = saml_response
        .ok_or_else(|| ApiError::missing_field("missing required field `SAMLResponse`"))?;
    if saml_response.trim().is_empty() {
        return Err(ApiError::missing_field(
            "missing required field `SAMLResponse`",
        ));
    }

    Ok(SamlAcsJsonRequest {
        saml_response,
        relay_state,
    })
}

fn percent_decode(value: &str) -> Result<String, ApiError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1])?;
                let low = hex_value(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded)
        .map_err(|_| ApiError::invalid_json("form field contains invalid UTF-8"))
}

fn hex_value(value: u8) -> Result<u8, ApiError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ApiError::invalid_json("invalid percent-encoding")),
    }
}

async fn ingest_single_payload(
    state: &SharedState,
    auth: &RequestAuth,
    payload: Value,
    source: &str,
    request_idempotency_key: Option<String>,
) -> Result<PersistedActionOutcome, ApiError> {
    let prepared = prepare_sdk_action(state, payload, request_idempotency_key)?;
    append_action_record(
        state,
        auth,
        prepared.normalized,
        source,
        prepared.idempotency_key.as_deref(),
    )
}

async fn ingest_batch_payload(
    state: &SharedState,
    auth: &RequestAuth,
    payload: Value,
    source: &str,
    request_idempotency_key: Option<String>,
) -> Result<Response, ApiError> {
    let items = payload
        .get("actions")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| ApiError::missing_field("missing required field `actions`"))?;

    if items.is_empty() {
        return Err(ApiError::missing_field("missing required field `actions`"));
    }

    let mut action_ids = Vec::new();
    let mut results = Vec::with_capacity(items.len());
    let mut failed = 0usize;

    for (index, item) in items.into_iter().enumerate() {
        let per_item_idempotency_key = request_idempotency_key
            .as_ref()
            .map(|key| format!("{key}:{index}"));
        match prepare_sdk_action(state, item, per_item_idempotency_key) {
            Ok(prepared) => match append_action_record(
                state,
                auth,
                prepared.normalized,
                source,
                prepared.idempotency_key.as_deref(),
            ) {
                Ok(outcome) => {
                    let action_id = outcome.action_id().to_string();
                    action_ids.push(action_id.clone());
                    results.push(BatchIngestItemResult {
                        index,
                        status: if outcome.duplicate {
                            "duplicate"
                        } else {
                            "accepted"
                        },
                        action_id: Some(action_id),
                        error: None,
                    });
                }
                Err(error) => {
                    failed += 1;
                    results.push(batch_error_result(index, &error));
                }
            },
            Err(error) => {
                failed += 1;
                results.push(batch_error_result(index, &error));
            }
        }
    }

    let status = if failed == 0 {
        StatusCode::CREATED
    } else {
        StatusCode::MULTI_STATUS
    };

    Ok((
        status,
        Json(BatchIngestResponse {
            ingested: action_ids.len(),
            failed,
            action_ids,
            results,
        }),
    )
        .into_response())
}

async fn ingest_otlp_payload(
    state: &SharedState,
    auth: &RequestAuth,
    payload: Value,
    request_idempotency_key: Option<String>,
) -> Result<Vec<String>, ApiError> {
    let spans = extract_otlp_spans(&payload);
    if spans.is_empty() {
        return Err(ApiError::missing_field(
            "missing required OTLP spans in payload",
        ));
    }

    let mut action_ids = Vec::with_capacity(spans.len());
    for (index, span) in spans.into_iter().enumerate() {
        validate_otlp_span(&span)?;
        let mut redacted_span = span;
        redact_value(&mut redacted_span, &state.redact_fields);
        let normalized = normalize_otlp_span(redacted_span);
        let item_idempotency_key = request_idempotency_key
            .as_ref()
            .map(|key| format!("{key}:{index}"));
        let outcome = append_action_record(
            state,
            auth,
            normalized,
            "otlp",
            item_idempotency_key.as_deref(),
        )?;
        action_ids.push(outcome.action_id().to_string());
    }

    Ok(action_ids)
}

async fn run_action_query(
    state: &SharedState,
    auth: &RequestAuth,
    query: &ActionsQuery,
) -> Result<Vec<ActionRecord>, ApiError> {
    let from = parse_time(query.from.as_deref())?;
    let to = parse_time(query.to.as_deref())?;
    validate_time_window(from, to)?;
    let actions = load_action_records(state, auth, query.include_oversight.unwrap_or(false))?;

    Ok(actions
        .into_iter()
        .filter(|action| {
            query
                .session_id
                .as_deref()
                .is_none_or(|session_id| action.session_id == session_id)
        })
        .filter(|action| {
            query
                .agent
                .as_deref()
                .is_none_or(|agent| action.agent == agent)
        })
        .filter(|action| {
            query
                .action_type
                .as_deref()
                .is_none_or(|action_type| action.action_type == action_type)
        })
        .filter(|action| {
            let action_time = DateTime::parse_from_rfc3339(&action.timestamp)
                .map(|timestamp| timestamp.with_timezone(&Utc))
                .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
            from.is_none_or(|from| action_time >= from) && to.is_none_or(|to| action_time <= to)
        })
        .collect())
}

async fn run_auth_audit_query(
    state: &SharedState,
    query: &AuthAuditQuery,
) -> Result<Vec<AuthAuditRecord>, ApiError> {
    let from = parse_time(query.from.as_deref())?;
    let to = parse_time(query.to.as_deref())?;
    validate_time_window(from, to)?;
    let events = load_auth_audit_records(state)?;

    Ok(events
        .into_iter()
        .filter(|event| {
            query
                .org_id
                .as_deref()
                .is_none_or(|org_id| event.org_id.as_deref() == Some(org_id))
        })
        .filter(|event| {
            query
                .event_type
                .as_deref()
                .is_none_or(|event_type| event.event_type == event_type)
        })
        .filter(|event| {
            query
                .actor_id
                .as_deref()
                .is_none_or(|actor_id| event.actor_id.as_deref() == Some(actor_id))
        })
        .filter(|event| {
            query
                .subject_id
                .as_deref()
                .is_none_or(|subject_id| event.subject_id == subject_id)
        })
        .filter(|event| {
            let event_time = DateTime::parse_from_rfc3339(&event.timestamp)
                .map(|timestamp| timestamp.with_timezone(&Utc))
                .unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
            from.is_none_or(|from| event_time >= from) && to.is_none_or(|to| event_time <= to)
        })
        .collect())
}

async fn append_oversight_event(
    state: &SharedState,
    auth: &RequestAuth,
    payload: Value,
) -> Result<OversightEvent, ApiError> {
    let requested_org_id = normalize_payload_org_id(json_string_paths(
        &payload,
        &[
            &["org_id"],
            &["orgId"],
            &["organization_id"],
            &["organizationId"],
        ],
    ));
    let org_id = resolve_request_org_scope(auth, requested_org_id.as_deref())?;
    let severity = json_string(&payload, &["severity"]).unwrap_or_else(|| "info".to_string());
    let note = json_string(&payload, &["note", "message"])
        .unwrap_or_else(|| "oversight event".to_string());
    let framework = json_string(&payload, &["framework"]);
    let session_id = json_string(&payload, &["session_id", "sessionId"]);
    let (stored_timestamp, display_timestamp) =
        resolved_timestamp(json_string(&payload, &["timestamp"]));
    let stored_session_id = session_id
        .clone()
        .unwrap_or_else(|| "oversight-session".to_string());
    let context = json!({
        "trailing": {
            "kind": "oversight",
            "event_kind": "oversight",
            "org_id": org_id.clone(),
            "severity": severity,
            "note": note,
            "framework": framework,
            "session_id": session_id,
            "schema_version": json_string(&payload, &["schema_version", "schemaVersion"]),
            "trace_id": json_string_paths(&payload, &[&["trace_id"], &["traceId"]]),
            "span_id": json_string_paths(&payload, &[&["span_id"], &["spanId"]]),
            "idempotency_key": json_string(&payload, &["idempotency_key", "idempotencyKey"]),
            "request_metadata": json_value_paths(
                &payload,
                &[
                    &["request_metadata"],
                    &["requestMetadata"],
                    &["request", "metadata"],
                    &["metadata", "request"],
                ],
            ),
            "result_metadata": json_value_paths(
                &payload,
                &[
                    &["result_metadata"],
                    &["resultMetadata"],
                    &["result", "metadata"],
                    &["metadata", "result"],
                ],
            ),
            "display_timestamp": display_timestamp,
        }
    });

    let entry = {
        let storage = lock_storage(state)?;
        storage
            .append_action_at_for_tenant(
                org_id.as_deref().unwrap_or(&state.tenant_context.org_id),
                &state.tenant_context.project_id,
                stored_timestamp,
                "oversight",
                "api",
                stored_session_id,
                ActionType::HumanOverride,
                payload,
                context,
                "recorded",
            )
            .map_err(ApiError::from_storage)?
    };

    let event = map_oversight_event(&entry);
    publish_live_event(
        state,
        LiveEvent::Oversight {
            scope: state.default_scope.clone(),
            event: event.clone(),
        },
    );
    notify_webhook(
        state,
        WebhookNotification::new(
            WebhookEventKind::HumanOversightRecorded,
            json!({
                "org_id": &org_id,
                "framework": &event.framework,
                "severity": &event.severity,
                "oversight_event": &event,
            }),
        ),
    );

    Ok(event)
}

async fn build_compliance_report(
    state: &SharedState,
    auth: &RequestAuth,
    framework: String,
    query: ComplianceQuery,
) -> Result<ComplianceReport, ApiError> {
    let framework = parse_framework(&framework)?;
    let org_id = resolve_request_org_scope(auth, query.org_id.as_deref())?;
    let mut scoped_query = query;
    scoped_query.org_id = org_id.clone();
    let records = load_compliance_records(state, auth, &scoped_query)?;
    ensure_framework_enabled(records.org_settings.as_ref(), &framework, org_id.as_deref())?;
    let integrity = verify_integrity(state).await;
    let report = PolicyEngine::new()
        .evaluate(
            &framework,
            &derive_policy_evidence(
                &records.actions,
                &records.oversight_events,
                &records.storage_control,
                records.org_settings.as_ref(),
            ),
        )
        .map_err(|error| ApiError::unsupported_framework(error.to_string()))?;
    let controls_met = report
        .controls_met
        .iter()
        .map(map_policy_control_result)
        .collect::<Vec<_>>();
    let controls_gaps = report
        .controls_gaps
        .iter()
        .map(map_policy_control_result)
        .collect::<Vec<_>>();
    let total_controls = controls_met.len() + controls_gaps.len();
    let score = if total_controls == 0 {
        0
    } else {
        ((controls_met.len() as f64 / total_controls as f64) * 100.0).round() as u8
    };
    let report = ComplianceReport {
        framework: framework.name().to_string(),
        total_actions: records.actions.len(),
        oversight_events: records.oversight_events.len(),
        integrity_valid: integrity.valid,
        score,
        controls_met,
        controls_gaps,
        evidence_refs: report.evidence_refs,
    };

    if report.score < 100 || !report.controls_gaps.is_empty() {
        notify_webhook(
            state,
            WebhookNotification::new(
                WebhookEventKind::ComplianceThresholdBreached,
                json!({
                    "org_id": &org_id,
                    "framework": &report.framework,
                    "session_id": &scoped_query.session_id,
                    "score": report.score,
                    "threshold": 100,
                    "integrity_valid": report.integrity_valid,
                    "controls_gaps": &report.controls_gaps,
                    "evidence_refs": &report.evidence_refs,
                }),
            ),
        );
    }

    if !integrity.valid {
        notify_webhook(
            state,
            WebhookNotification::new(
                WebhookEventKind::ChainIntegrityFailure,
                json!({
                    "org_id": &org_id,
                    "framework": &report.framework,
                    "session_id": &scoped_query.session_id,
                    "score": report.score,
                    "integrity": &integrity,
                }),
            ),
        );
    }

    Ok(report)
}

async fn build_export_json(
    state: &SharedState,
    auth: &RequestAuth,
    framework: Option<String>,
    org_id: Option<String>,
) -> Result<Value, ApiError> {
    let org_id = resolve_request_org_scope(auth, org_id.as_deref())?;
    let integrity = verify_integrity(state).await;
    let records = load_records(state, auth, org_id.as_deref())?;
    let requested_framework = framework.as_deref().map(parse_framework).transpose()?;
    if let Some(framework) = requested_framework.as_ref() {
        ensure_framework_enabled(records.org_settings.as_ref(), framework, org_id.as_deref())?;
    }

    let framework = framework.unwrap_or_else(|| "generic".to_string());
    let package = build_evidence_package(
        &records,
        &integrity,
        Some(framework.clone()),
        org_id.as_deref(),
    );
    let export = evidence_export::json::JsonEvidenceExport::from_package(&package);

    Ok(json!({
        "framework": framework,
        "org_id": org_id,
        "org_settings": records.org_settings,
        "schema_version": export.schema_version,
        "exported_at": export.exported_at,
        "actions": records.actions,
        "oversight_events": records.oversight_events,
        "integrity": integrity,
        "integrity_proofs": export.integrity_proofs,
        "package": export.package,
    }))
}

async fn build_auth_audit_export(
    state: &SharedState,
    auth: &RequestAuth,
    request: &AuthAuditExportRequest,
) -> Result<Value, ApiError> {
    let org_id = resolve_request_org_scope(auth, request.org_id.as_deref())?;
    let events = run_auth_audit_query(
        state,
        &AuthAuditQuery {
            org_id,
            event_type: request.event_type.clone(),
            actor_id: request.actor_id.clone(),
            subject_id: request.subject_id.clone(),
            from: request.from.clone(),
            to: request.to.clone(),
        },
    )
    .await?;

    Ok(json!({
        "exported_at": current_time().to_rfc3339_opts(SecondsFormat::Nanos, true),
        "count": events.len(),
        "filters": request,
        "events": events,
    }))
}

async fn build_export_pdf(
    state: &SharedState,
    auth: &RequestAuth,
    framework: Option<String>,
    org_id: Option<String>,
) -> Result<Vec<u8>, ApiError> {
    let org_id = resolve_request_org_scope(auth, org_id.as_deref())?;
    let integrity = verify_integrity(state).await;
    let records = load_records(state, auth, org_id.as_deref())?;
    let requested_framework = framework.as_deref().map(parse_framework).transpose()?;
    if let Some(framework) = requested_framework.as_ref() {
        ensure_framework_enabled(records.org_settings.as_ref(), framework, org_id.as_deref())?;
    }
    let package = build_evidence_package(&records, &integrity, framework, org_id.as_deref());
    evidence_export::pdf::export_package(&package)
        .map_err(|_| ApiError::internal("failed to generate the PDF export"))
}

async fn verify_integrity(state: &SharedState) -> IntegrityReport {
    match verify_integrity_impl(state) {
        Ok(report) => report,
        Err(_) => IntegrityReport {
            valid: false,
            checked_entries: 0,
            latest_hash: None,
            root_anchor_hash: None,
            root_anchor_persisted: false,
            merkle_root_hash: evidence_export::sha256_hex(b"trailing-empty-ledger-merkle-root"),
            checkpoint_signature: evidence_export::sha256_hex(
                b"trailing-empty-integrity-checkpoint",
            ),
            proofs: Vec::new(),
        },
    }
}

fn map_auth_storage_error(error: StorageError) -> ApiError {
    match error {
        StorageError::AuthenticationFailed => {
            ApiError::unauthorized("invalid email, password, or organization")
        }
        StorageError::InvalidMfaCode => ApiError::unauthorized("invalid MFA or recovery code"),
        StorageError::AuthChallengeNotFound => {
            ApiError::unauthorized("authentication challenge was not found")
        }
        StorageError::AuthChallengeExpired => {
            ApiError::unauthorized("authentication challenge has expired")
        }
        StorageError::AuthChallengeUsed => {
            ApiError::unauthorized("authentication challenge has already been used")
        }
        StorageError::MfaAlreadyEnabled => {
            ApiError::bad_request("MFA is already enabled for this account")
        }
        StorageError::MfaEnrollmentRequired => {
            ApiError::bad_request("MFA enrollment is required before sign-in can complete")
        }
        StorageError::MfaNotEnabled => ApiError::bad_request("MFA is not enabled for this account"),
        StorageError::MfaPendingEnrollment => {
            ApiError::bad_request("MFA enrollment has not been started for this account")
        }
        StorageError::InvalidInput(message) => ApiError::bad_request(message),
        other => ApiError::from_storage(other),
    }
}

#[allow(clippy::too_many_arguments)]
fn append_auth_audit_event(
    state: &SharedState,
    org_id: &str,
    user_id: &str,
    email: &str,
    event_name: &str,
    mfa_status: &str,
    outcome: &str,
    payload: Value,
) -> Result<(), ApiError> {
    let session_id = format!("auth:{user_id}");
    {
        let storage = lock_storage(state)?;
        storage
            .append_action_for_org(
                Some(org_id),
                email,
                "human",
                session_id,
                ActionType::HumanOverride,
                payload,
                json!({
                    "trailing": {
                        "kind": "action",
                        "source": "auth",
                        "api_type": event_name,
                        "display_timestamp": current_time().to_rfc3339_opts(SecondsFormat::Nanos, true),
                        "mfa_status": mfa_status,
                    }
                }),
                outcome,
            )
            .map_err(ApiError::from_storage)?;
    }
    Ok(())
}

fn append_policy_audit_event(
    state: &SharedState,
    org_id: &str,
    policy: MfaPolicy,
) -> Result<(), ApiError> {
    {
        let storage = lock_storage(state)?;
        storage
            .append_action_for_org(
                Some(org_id),
                "mfa-policy",
                "system",
                format!("org-policy:{org_id}"),
                ActionType::PolicyCheck,
                json!({
                    "event": "auth.mfa.policy.update",
                    "org_id": org_id,
                    "policy": policy.as_str(),
                    "mfa_status": policy.as_str(),
                }),
                json!({
                    "trailing": {
                        "kind": "action",
                        "source": "auth",
                        "api_type": "auth.mfa.policy.update",
                        "display_timestamp": current_time().to_rfc3339_opts(SecondsFormat::Nanos, true),
                        "mfa_status": policy.as_str(),
                    }
                }),
                "recorded",
            )
            .map_err(ApiError::from_storage)?;
    }
    Ok(())
}

fn sse_json_event<T: Serialize>(event_name: &str, payload: &T) -> Option<Event> {
    serde_json::to_string(payload)
        .ok()
        .map(|data| Event::default().event(event_name).data(data))
}

fn publish_live_event(state: &SharedState, event: LiveEvent) {
    let _ = state.live_events.send(event);
}

fn notify_webhook(state: &SharedState, notification: WebhookNotification) {
    notify_in_background(state.webhook.clone(), notification);
}

fn verify_integrity_impl(state: &SharedState) -> Result<IntegrityReport, ApiError> {
    let storage = lock_storage(state)?;
    let entries = storage.entries().map_err(ApiError::from_storage)?;
    let root_anchor_hash = storage.root_anchor_hash().map_err(ApiError::from_storage)?;
    let root_anchor_persisted = storage
        .root_anchor_persisted()
        .map_err(ApiError::from_storage)?;
    let violations = storage
        .verify_chain(None, None)
        .map_err(ApiError::from_storage)?;
    let ledger_root_hash = entries.last().map(|entry| entry.entry_hash.clone());
    let merkle_root_hash = merkle_root_hash_for_entries(&entries);
    let checkpoint_signature = evidence_export::checkpoint_signature(
        &merkle_root_hash,
        ledger_root_hash.as_deref(),
        root_anchor_hash.as_deref(),
        entries.len(),
        violations.is_empty(),
    );
    let proofs = build_integrity_summary_proofs(
        &entries,
        violations.is_empty(),
        ledger_root_hash.as_deref(),
        root_anchor_hash.as_deref(),
        root_anchor_persisted,
        &merkle_root_hash,
        &checkpoint_signature,
    );

    Ok(IntegrityReport {
        valid: violations.is_empty(),
        checked_entries: entries.len(),
        latest_hash: ledger_root_hash,
        root_anchor_hash,
        root_anchor_persisted,
        merkle_root_hash,
        checkpoint_signature,
        proofs,
    })
}

fn prepare_sdk_action(
    state: &SharedState,
    mut payload: Value,
    request_idempotency_key: Option<String>,
) -> Result<PreparedSdkAction, ApiError> {
    validate_sdk_action(&payload)?;
    let item_idempotency_key = json_string(&payload, &["idempotency_key", "idempotencyKey"]);
    redact_value(&mut payload, &state.redact_fields);

    Ok(PreparedSdkAction {
        normalized: normalize_sdk_action(payload),
        idempotency_key: item_idempotency_key.or(request_idempotency_key),
    })
}

fn single_ingest_response(outcome: PersistedActionOutcome) -> (StatusCode, Json<IngestResponse>) {
    let status = if outcome.duplicate {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };

    (
        status,
        Json(IngestResponse {
            ingested: usize::from(!outcome.duplicate),
            action_ids: vec![outcome.action_id],
        }),
    )
}

fn batch_error_result(index: usize, error: &ApiError) -> BatchIngestItemResult {
    BatchIngestItemResult {
        index,
        status: "rejected",
        action_id: None,
        error: Some(BatchIngestItemError {
            code: error.code.as_str(),
            message: error.message.clone(),
        }),
    }
}

fn append_action_record(
    state: &SharedState,
    auth: &RequestAuth,
    action: NormalizedActionRecord,
    source: &str,
    idempotency_key: Option<&str>,
) -> Result<PersistedActionOutcome, ApiError> {
    let org_id = resolve_request_org_scope(auth, action.org_id.as_deref())?;
    let (stored_timestamp, display_timestamp) = resolved_timestamp(action.timestamp.clone());
    let log_action_type = resolve_action_type(&ActionTypeHints {
        action_name: &action.action_type,
        payload: &action.payload,
        tool_name: action.tool_name.as_deref(),
        target: action.target.as_deref(),
        has_data_accessed: false,
    });

    let entry = {
        let storage = lock_storage(state)?;
        let context = json!({
            "trailing": {
                "kind": "action",
                "event_kind": "action",
                "org_id": org_id.clone(),
                "source": source,
                "api_type": action.action_type,
                "tool_name": action.tool_name,
                "target": action.target,
                "schema_version": action.schema_version,
                "trace_id": action.trace_id,
                "span_id": action.span_id,
                "idempotency_key": action.idempotency_key,
                "request_metadata": action.request_metadata,
                "result_metadata": action.result_metadata,
                "display_timestamp": display_timestamp,
            }
        });

        match idempotency_key {
            Some(idempotency_key) => storage
                .append_action_with_dedup_at_for_org_detailed(
                    org_id.as_deref(),
                    &scoped_idempotency_key(org_id.as_deref(), source, idempotency_key),
                    stored_timestamp,
                    action.agent,
                    action.agent_type,
                    action.session_id,
                    log_action_type,
                    action.payload,
                    context,
                    action.outcome,
                )
                .map_err(ApiError::from_storage)?,
            None => DeduplicationOutcome::Inserted(
                storage
                    .append_action_at_for_org(
                        org_id.as_deref(),
                        stored_timestamp,
                        action.agent,
                        action.agent_type,
                        action.session_id,
                        log_action_type,
                        action.payload,
                        context,
                        action.outcome,
                    )
                    .map_err(ApiError::from_storage)?,
            ),
        }
    };

    match entry {
        DeduplicationOutcome::Inserted(entry) => {
            publish_live_event(
                state,
                LiveEvent::Action {
                    scope: state.default_scope.clone(),
                    action: map_action_record_with_kind(&entry, StoredKind::Action),
                },
            );
            Ok(PersistedActionOutcome {
                action_id: entry.id.to_string(),
                duplicate: false,
            })
        }
        DeduplicationOutcome::Duplicate { entry_id } => entry_id
            .map(|action_id| PersistedActionOutcome {
                action_id,
                duplicate: true,
            })
            .ok_or_else(|| ApiError::internal("failed to process the idempotent request")),
    }
}

fn scoped_idempotency_key(org_id: Option<&str>, source: &str, raw_key: &str) -> String {
    let org_scope = org_id.unwrap_or("global");
    format!("{org_scope}:{source}:{raw_key}")
}

fn load_entries_for_request(
    storage: &Storage,
    org_id: &str,
) -> Result<Vec<StoredActionEntry>, ApiError> {
    storage
        .entries_for_org(Some(org_id))
        .map_err(ApiError::from_storage)
}

fn require_org_scope(org_id: Option<&str>) -> Result<&str, ApiError> {
    org_id.ok_or_else(|| ApiError::bad_request("org scope required"))
}

fn resolve_request_org_scope(
    auth: &RequestAuth,
    requested_org_id: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let requested_org_id = normalize_query_org_id(requested_org_id)?;

    if let Some(auth_org_id) = auth.org_id.as_deref() {
        if requested_org_id
            .as_deref()
            .is_some_and(|requested_org_id| requested_org_id != auth_org_id)
        {
            return Err(ApiError::unauthorized(
                "credential cannot access another organization",
            ));
        }

        return Ok(Some(auth_org_id.to_string()));
    }

    Ok(requested_org_id)
}

fn load_records(
    state: &SharedState,
    auth: &RequestAuth,
    org_id: Option<&str>,
) -> Result<LoadedRecords, ApiError> {
    let storage = lock_storage(state)?;
    let authorized_org_id = resolve_request_org_scope(auth, org_id)?;
    let org_id = require_org_scope(authorized_org_id.as_deref())?;
    let entries = load_entries_for_request(&storage, org_id)?;
    let org_settings = storage
        .get_org_settings(org_id)
        .map_err(ApiError::from_storage)?;
    let mut actions = Vec::new();
    let mut oversight_events = Vec::new();
    let mut ledger_entries = Vec::new();

    for entry in entries {
        ledger_entries.push(entry.clone());
        match stored_kind(&entry) {
            StoredKind::Action => actions.push(map_action_record(&entry)),
            StoredKind::Oversight => oversight_events.push(map_oversight_event(&entry)),
        }
    }

    Ok(LoadedRecords {
        actions,
        oversight_events,
        org_settings,
        ledger_entries,
    })
}

fn load_auth_audit_records(state: &SharedState) -> Result<Vec<AuthAuditRecord>, ApiError> {
    let storage = lock_storage(state)?;
    let entries = storage
        .auth_audit_entries()
        .map_err(ApiError::from_storage)?;

    Ok(entries.iter().map(map_auth_audit_record).collect())
}

fn load_compliance_records(
    state: &SharedState,
    auth: &RequestAuth,
    query: &ComplianceQuery,
) -> Result<LoadedComplianceRecords, ApiError> {
    let from = parse_time(query.from.as_deref())?;
    let to = parse_time(query.to.as_deref())?;
    validate_time_window(from, to)?;

    let storage = lock_storage(state)?;
    let storage_control = storage.control_settings().map_err(ApiError::from_storage)?;
    let authorized_org_id = resolve_request_org_scope(auth, query.org_id.as_deref())?;
    let org_id = require_org_scope(authorized_org_id.as_deref())?;
    let entries = load_entries_for_request(&storage, org_id)?;
    let org_settings = storage
        .get_org_settings(org_id)
        .map_err(ApiError::from_storage)?;
    let mut actions = Vec::new();
    let mut oversight_events = Vec::new();

    for entry in entries
        .into_iter()
        .filter(|entry| compliance_scope_matches(entry, query.session_id.as_deref(), from, to))
    {
        match stored_kind(&entry) {
            StoredKind::Action => actions.push(entry),
            StoredKind::Oversight => oversight_events.push(entry),
        }
    }

    Ok(LoadedComplianceRecords {
        actions,
        oversight_events,
        storage_control,
        org_settings,
    })
}

fn load_action_records(
    state: &SharedState,
    auth: &RequestAuth,
    include_oversight: bool,
) -> Result<Vec<ActionRecord>, ApiError> {
    let storage = lock_storage(state)?;
    let org_id = require_org_scope(auth.org_id.as_deref())?;
    let entries = load_entries_for_request(&storage, org_id)?;

    Ok(entries
        .into_iter()
        .filter_map(|entry| {
            let kind = stored_kind(&entry);
            if kind == StoredKind::Oversight && !include_oversight {
                return None;
            }

            Some(map_action_record_with_kind(&entry, kind))
        })
        .collect())
}

fn build_retention_age_distribution(
    entries: &[StoredActionEntry],
) -> (Vec<RetentionAgeBucket>, Option<String>, Option<String>) {
    const AGE_BUCKETS: [(&str, i64, Option<i64>); 5] = [
        ("0-7 days", 0, Some(7)),
        ("8-30 days", 8, Some(30)),
        ("31-90 days", 31, Some(90)),
        ("91-180 days", 91, Some(180)),
        ("181+ days", 181, None),
    ];

    let mut buckets = AGE_BUCKETS
        .iter()
        .map(|(label, min_age_days, max_age_days)| RetentionAgeBucket {
            label: (*label).to_string(),
            min_age_days: *min_age_days,
            max_age_days: *max_age_days,
            count: 0,
            oldest_record_at: None,
            newest_record_at: None,
        })
        .collect::<Vec<_>>();
    let now = current_time();
    let mut oldest_record_at = None;
    let mut newest_record_at = None;

    for entry in entries {
        let age_days = ((now.timestamp() - entry.timestamp.timestamp()).max(0)) / 86_400;
        let Some(bucket) = buckets.iter_mut().find(|bucket| {
            age_days >= bucket.min_age_days
                && bucket
                    .max_age_days
                    .is_none_or(|max_age_days| age_days <= max_age_days)
        }) else {
            continue;
        };
        let timestamp = StoredActionEntry::canonical_timestamp(&entry.timestamp);

        bucket.count += 1;
        update_timestamp_bounds(
            &mut bucket.oldest_record_at,
            &mut bucket.newest_record_at,
            &timestamp,
        );
        update_timestamp_bounds(&mut oldest_record_at, &mut newest_record_at, &timestamp);
    }

    (buckets, oldest_record_at, newest_record_at)
}

fn update_timestamp_bounds(
    oldest: &mut Option<String>,
    newest: &mut Option<String>,
    candidate: &str,
) {
    if oldest
        .as_ref()
        .is_none_or(|value| candidate < value.as_str())
    {
        *oldest = Some(candidate.to_string());
    }
    if newest
        .as_ref()
        .is_none_or(|value| candidate > value.as_str())
    {
        *newest = Some(candidate.to_string());
    }
}

fn compliance_scope_matches(
    entry: &StoredActionEntry,
    session_id: Option<&str>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> bool {
    session_id.is_none_or(|expected| entry.session_id == expected)
        && from.is_none_or(|from| entry.timestamp >= from)
        && to.is_none_or(|to| entry.timestamp <= to)
}

fn lock_storage(state: &SharedState) -> Result<MutexGuard<'_, Storage>, ApiError> {
    state
        .storage
        .lock()
        .map_err(|_| ApiError::internal("failed to process the request"))
}

fn stored_kind(entry: &StoredActionEntry) -> StoredKind {
    match metadata_string(&entry.context, "kind").as_deref() {
        Some("oversight") => StoredKind::Oversight,
        _ => StoredKind::Action,
    }
}

fn map_action_record(entry: &StoredActionEntry) -> ActionRecord {
    map_action_record_with_kind(entry, stored_kind(entry))
}

fn map_action_record_with_kind(entry: &StoredActionEntry, kind: StoredKind) -> ActionRecord {
    let payload = entry.payload.clone();

    ActionRecord {
        id: entry.id.to_string(),
        session_id: entry.session_id.clone(),
        agent: entry.agent_id.clone(),
        agent_type: entry.agent_type.clone(),
        kind: kind.as_str().to_string(),
        action_type: metadata_string(&entry.context, "api_type")
            .or_else(|| {
                json_string_paths(
                    &payload,
                    &[
                        &["action", "type"],
                        &["action", "action_type"],
                        &["type"],
                        &["name"],
                        &["event_type"],
                    ],
                )
            })
            .unwrap_or_else(|| entry.action_type.to_string()),
        tool_name: metadata_string(&entry.context, "tool_name").or_else(|| {
            json_string_paths(
                &payload,
                &[
                    &["action", "tool_name"],
                    &["action", "toolName"],
                    &["tool_name"],
                    &["toolName"],
                    &["payload", "tool"],
                    &["attributes", "tool.name"],
                    &["attributes", "tool_name"],
                ],
            )
        }),
        target: metadata_string(&entry.context, "target").or_else(|| {
            json_string_paths(
                &payload,
                &[
                    &["action", "target"],
                    &["target"],
                    &["resource"],
                    &["resource", "name"],
                    &["attributes", "target"],
                    &["attributes", "target.id"],
                    &["attributes", "resource.name"],
                    &["attributes", "http.url"],
                ],
            )
        }),
        source: metadata_string(&entry.context, "source").unwrap_or_else(|| "sdk".to_string()),
        timestamp: display_timestamp(entry),
        payload,
        hash: entry.entry_hash.clone(),
        previous_hash: previous_hash_option(&entry.previous_hash),
    }
}

fn map_oversight_event(entry: &StoredActionEntry) -> OversightEvent {
    let payload = entry.payload.clone();

    OversightEvent {
        id: entry.id.to_string(),
        session_id: metadata_string(&entry.context, "session_id")
            .or_else(|| json_string(&payload, &["session_id", "sessionId"])),
        framework: metadata_string(&entry.context, "framework")
            .or_else(|| json_string(&payload, &["framework"])),
        severity: metadata_string(&entry.context, "severity")
            .or_else(|| json_string(&payload, &["severity"]))
            .unwrap_or_else(|| "info".to_string()),
        note: metadata_string(&entry.context, "note")
            .or_else(|| json_string(&payload, &["note", "message"]))
            .unwrap_or_else(|| "oversight event".to_string()),
        timestamp: display_timestamp(entry),
        payload,
        hash: entry.entry_hash.clone(),
        previous_hash: previous_hash_option(&entry.previous_hash),
    }
}

fn map_auth_audit_record(entry: &StoredAuthAuditEntry) -> AuthAuditRecord {
    AuthAuditRecord {
        id: entry.id.to_string(),
        timestamp: entry.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true),
        event_type: entry.event_type.to_string(),
        org_id: entry.org_id.clone(),
        actor_type: entry.actor_type.clone(),
        actor_id: entry.actor_id.clone(),
        subject_type: entry.subject_type.clone(),
        subject_id: entry.subject_id.clone(),
        payload: entry.payload.clone(),
        outcome: entry.outcome.clone(),
        hash: entry.entry_hash.clone(),
        previous_hash: previous_hash_option(&entry.previous_hash),
    }
}

fn display_timestamp(entry: &StoredActionEntry) -> String {
    metadata_string(&entry.context, "display_timestamp")
        .unwrap_or_else(|| entry.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

fn previous_hash_option(previous_hash: &str) -> Option<String> {
    (previous_hash != GENESIS_HASH).then(|| previous_hash.to_string())
}

fn metadata_string(context: &Value, key: &str) -> Option<String> {
    context
        .pointer(&format!("/trailing/{key}"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn resolved_timestamp(raw: Option<String>) -> (DateTime<Utc>, String) {
    match raw {
        Some(display_timestamp) => (
            parse_stored_timestamp(&display_timestamp).unwrap_or_else(current_time),
            display_timestamp,
        ),
        None => {
            let timestamp = current_time();
            (
                timestamp,
                timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true),
            )
        }
    }
}

fn parse_stored_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(timestamp) = DateTime::parse_from_rfc3339(raw) {
        return Some(timestamp.with_timezone(&Utc));
    }

    let nanos = raw.parse::<i64>().ok()?;
    let seconds = nanos.div_euclid(1_000_000_000);
    let subsec_nanos = nanos.rem_euclid(1_000_000_000) as u32;
    Utc.timestamp_opt(seconds, subsec_nanos).single()
}

fn build_evidence_package(
    records: &LoadedRecords,
    integrity: &IntegrityReport,
    framework: Option<String>,
    org_id: Option<&str>,
) -> ExportEvidencePackage {
    let generated_at = current_time();
    let framework = framework.unwrap_or_else(|| "generic".to_string());
    let oversight_count = records.oversight_events.len();
    let action_count = records.actions.len();
    let mut controls = vec![
        ExportComplianceControl {
            control_id: "AP-CHAIN".to_string(),
            title: "Evidence chain integrity verified".to_string(),
            status: if integrity.valid {
                ExportComplianceStatus::Compliant
            } else {
                ExportComplianceStatus::NonCompliant
            },
            evidence_refs: records
                .actions
                .iter()
                .take(3)
                .map(|action| action.id.clone())
                .collect(),
            notes: Some(format!(
                "Checked {} ledger entries; latest hash {}",
                integrity.checked_entries,
                integrity.latest_hash.as_deref().unwrap_or("none")
            )),
        },
        ExportComplianceControl {
            control_id: "AP-OVERSIGHT".to_string(),
            title: "Oversight events recorded".to_string(),
            status: if oversight_count > 0 {
                ExportComplianceStatus::Compliant
            } else {
                ExportComplianceStatus::Partial
            },
            evidence_refs: records
                .oversight_events
                .iter()
                .take(3)
                .map(|event| event.id.clone())
                .collect(),
            notes: Some(format!("{oversight_count} oversight events included")),
        },
        ExportComplianceControl {
            control_id: "AP-ACTIONS".to_string(),
            title: "Action log available for review".to_string(),
            status: if action_count > 0 {
                ExportComplianceStatus::Compliant
            } else {
                ExportComplianceStatus::Partial
            },
            evidence_refs: records
                .actions
                .iter()
                .take(3)
                .map(|action| action.id.clone())
                .collect(),
            notes: Some(format!("{action_count} actions included")),
        },
    ];
    let mut labels = std::collections::BTreeMap::from([
        ("framework".to_string(), framework.clone()),
        ("source".to_string(), "api-export".to_string()),
    ]);
    let mut legal_hold = false;

    if let Some(org_settings) = records.org_settings.as_ref() {
        legal_hold = org_settings.legal_hold();
        labels.insert("org_id".to_string(), org_settings.org_id.clone());
        if let Some(min_retention_days) = org_settings.min_retention_days() {
            labels.insert("retention_days".to_string(), min_retention_days.to_string());
        }
        if !org_settings.enabled_frameworks.is_empty() {
            labels.insert(
                "enabled_frameworks".to_string(),
                org_settings.enabled_frameworks.join(","),
            );
        }

        controls.push(ExportComplianceControl {
            control_id: "AP-ORG-RETENTION".to_string(),
            title: "Organization retention policy configured".to_string(),
            status: if org_settings.min_retention_days().unwrap_or_default() >= 180 {
                ExportComplianceStatus::Compliant
            } else {
                ExportComplianceStatus::Partial
            },
            evidence_refs: vec![format!(
                "org_settings:{}:retention_policy",
                org_settings.org_id
            )],
            notes: Some(format!(
                "Retention policy: {}",
                org_settings.retention_policy
            )),
        });

        controls.push(ExportComplianceControl {
            control_id: "AP-ORG-GUARDRAILS".to_string(),
            title: "Organization guardrails configured".to_string(),
            status: if org_settings.has_guardrails() {
                ExportComplianceStatus::Compliant
            } else {
                ExportComplianceStatus::Partial
            },
            evidence_refs: vec![format!(
                "org_settings:{}:guardrail_settings",
                org_settings.org_id
            )],
            notes: Some(format!("Guardrails: {}", org_settings.guardrail_settings)),
        });
    }

    let mut gaps = Vec::new();
    if !integrity.valid {
        gaps.push(ExportComplianceGap {
            gap_id: "gap-chain-integrity".to_string(),
            severity: GapSeverity::High,
            description: "Integrity verification reported a broken evidence chain".to_string(),
            remediation_owner: Some("compliance".to_string()),
        });
    }
    if oversight_count == 0 {
        gaps.push(ExportComplianceGap {
            gap_id: "gap-oversight-coverage".to_string(),
            severity: GapSeverity::Medium,
            description: "No oversight events were recorded for this package".to_string(),
            remediation_owner: Some("oversight".to_string()),
        });
    }

    let overall_status = if gaps.is_empty() {
        ExportComplianceStatus::Compliant
    } else if integrity.valid {
        ExportComplianceStatus::Partial
    } else {
        ExportComplianceStatus::NonCompliant
    };

    let mut package = ExportEvidencePackage::new(
        ExportEvidenceMetadata {
            package_id: Uuid::new_v4().to_string(),
            subject: format!("Compliance export for {framework}"),
            organization: org_id.unwrap_or("Trailing").to_string(),
            generated_at,
            generated_by: "trailing-api".to_string(),
            legal_hold,
            sessions: records
                .actions
                .iter()
                .map(|action| action.session_id.clone())
                .chain(
                    records
                        .oversight_events
                        .iter()
                        .filter_map(|event| event.session_id.clone()),
                )
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect(),
            agents: records
                .actions
                .iter()
                .map(|action| action.agent.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect(),
            labels,
        },
        ExportChainIntegrityStatus {
            status: if integrity.valid {
                IntegrityState::Verified
            } else {
                IntegrityState::Broken
            },
            last_verified_at: generated_at,
            ledger_root_hash: integrity
                .latest_hash
                .clone()
                .unwrap_or_else(|| "none".to_string()),
            broken_links: usize::from(!integrity.valid),
            proofs: Vec::new(),
        },
        records.actions.iter().map(map_export_action).collect(),
        records
            .oversight_events
            .iter()
            .map(map_export_oversight_event)
            .collect(),
        ExportComplianceReport {
            framework,
            status: overall_status,
            controls,
            gaps,
        },
    );

    package.chain_integrity_status.proofs =
        build_package_integrity_proofs(&package, records, integrity);

    if let Some(chain_control) = package
        .compliance_report
        .controls
        .iter_mut()
        .find(|control| control.control_id == "AP-CHAIN")
    {
        chain_control.evidence_refs = package
            .chain_integrity_status
            .proofs
            .iter()
            .filter(|proof| {
                matches!(
                    proof.scope.as_str(),
                    "chain_integrity" | "root_anchor_hash" | "merkle_root" | "checkpoint_signature"
                )
            })
            .map(|proof| proof.proof_id.clone())
            .collect();
    }

    package.refresh_hash();
    package
}

fn build_package_integrity_proofs(
    package: &ExportEvidencePackage,
    records: &LoadedRecords,
    integrity: &IntegrityReport,
) -> Vec<ExportIntegrityProof> {
    let merkle_artifacts = evidence_export::build_package_merkle_artifacts(package);
    let checkpoint_signature = evidence_export::checkpoint_signature(
        &merkle_artifacts.merkle_root_hash,
        integrity.latest_hash.as_deref(),
        integrity.root_anchor_hash.as_deref(),
        integrity.checked_entries,
        integrity.valid,
    );

    let mut proofs = build_integrity_summary_proofs(
        &records.ledger_entries,
        integrity.valid,
        integrity.latest_hash.as_deref(),
        integrity.root_anchor_hash.as_deref(),
        integrity.root_anchor_persisted,
        &merkle_artifacts.merkle_root_hash,
        &checkpoint_signature,
    );
    proofs.extend(merkle_artifacts.inclusion_proofs);
    proofs
}

fn build_integrity_summary_proofs(
    entries: &[StoredActionEntry],
    integrity_valid: bool,
    ledger_root_hash: Option<&str>,
    root_anchor_hash: Option<&str>,
    root_anchor_persisted: bool,
    merkle_root_hash: &str,
    checkpoint_signature: &str,
) -> Vec<ExportIntegrityProof> {
    let chain_verified = ledger_chain_verified(entries, ledger_root_hash);
    let root_anchor_verified = if root_anchor_persisted {
        root_anchor_hash == ledger_root_hash
    } else {
        true
    };

    vec![
        ExportIntegrityProof {
            proof_id: "chain-integrity".to_string(),
            scope: "chain_integrity".to_string(),
            algorithm: "sha256-chain".to_string(),
            value: serde_json::to_string(&json!({
                "checked_entries": entries.len(),
                "entries": entries
                    .iter()
                    .map(|entry| json!({
                        "entry_id": entry.id.to_string(),
                        "entry_kind": match stored_kind(entry) {
                            StoredKind::Action => "action",
                            StoredKind::Oversight => "oversight",
                        },
                        "previous_hash": entry.previous_hash,
                        "entry_hash": entry.entry_hash,
                    }))
                    .collect::<Vec<_>>(),
                "genesis_hash": GENESIS_HASH,
                "latest_hash": ledger_root_hash,
            }))
            .expect("chain integrity proof payload must serialize"),
            verified: chain_verified,
        },
        ExportIntegrityProof {
            proof_id: "root-anchor".to_string(),
            scope: "root_anchor_hash".to_string(),
            algorithm: "sha256-anchor".to_string(),
            value: serde_json::to_string(&json!({
                "persisted": root_anchor_persisted,
                "root_anchor_hash": root_anchor_hash,
                "ledger_root_hash": ledger_root_hash,
                "matches_ledger_root": root_anchor_verified,
            }))
            .expect("root anchor proof payload must serialize"),
            verified: root_anchor_verified,
        },
        ExportIntegrityProof {
            proof_id: "merkle-root".to_string(),
            scope: "merkle_root".to_string(),
            algorithm: "sha256-merkle".to_string(),
            value: serde_json::to_string(&json!({
                "leaf_count": entries.len(),
                "merkle_root_hash": merkle_root_hash,
            }))
            .expect("merkle root proof payload must serialize"),
            verified: true,
        },
        ExportIntegrityProof {
            proof_id: "checkpoint-signature".to_string(),
            scope: "checkpoint_signature".to_string(),
            algorithm: "sha256-checkpoint".to_string(),
            value: serde_json::to_string(&json!({
                "chain_verified": integrity_valid,
                "checked_entries": entries.len(),
                "checkpoint_signature": checkpoint_signature,
                "ledger_root_hash": ledger_root_hash,
                "merkle_root_hash": merkle_root_hash,
                "root_anchor_hash": root_anchor_hash,
            }))
            .expect("checkpoint signature payload must serialize"),
            verified: checkpoint_signature
                == evidence_export::checkpoint_signature(
                    merkle_root_hash,
                    ledger_root_hash,
                    root_anchor_hash,
                    entries.len(),
                    integrity_valid,
                ),
        },
    ]
}

fn ledger_chain_verified(entries: &[StoredActionEntry], ledger_root_hash: Option<&str>) -> bool {
    let mut expected_previous_hash = GENESIS_HASH.to_string();

    for entry in entries {
        if entry.previous_hash != expected_previous_hash {
            return false;
        }

        if entry.entry_hash != entry.calculate_hash() {
            return false;
        }

        expected_previous_hash = entry.entry_hash.clone();
    }

    match (entries.last(), ledger_root_hash) {
        (Some(entry), Some(ledger_root_hash)) => entry.entry_hash == ledger_root_hash,
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(_), None) => false,
    }
}

fn merkle_root_hash_for_entries(entries: &[StoredActionEntry]) -> String {
    if entries.is_empty() {
        return evidence_export::sha256_hex(b"trailing-empty-ledger-merkle-root");
    }

    let mut level = entries
        .iter()
        .map(|entry| {
            evidence_export::canonical_json_hash(&json!({
                "entry_hash": entry.entry_hash,
                "entry_id": entry.id.to_string(),
                "entry_kind": match stored_kind(entry) {
                    StoredKind::Action => "action",
                    StoredKind::Oversight => "oversight",
                },
                "previous_hash": entry.previous_hash,
                "timestamp": entry.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true),
            }))
        })
        .collect::<Vec<_>>();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));

        for chunk in level.chunks(2) {
            let left = &chunk[0];
            let right = chunk.get(1).unwrap_or(left);
            next.push(evidence_export::canonical_json_hash(&json!({
                "left": left,
                "right": right,
            })));
        }

        level = next;
    }

    level
        .into_iter()
        .next()
        .unwrap_or_else(|| evidence_export::sha256_hex(b"trailing-empty-ledger-merkle-root"))
}

fn map_export_action(action: &ActionRecord) -> ExportEvidenceAction {
    ExportEvidenceAction {
        action_id: action.id.clone(),
        timestamp: parse_stored_timestamp(&action.timestamp).unwrap_or(DateTime::<Utc>::UNIX_EPOCH),
        agent_id: action.agent.clone(),
        session_id: action.session_id.clone(),
        action_type: action.action_type.clone(),
        summary: action.payload.to_string(),
        input_hash: action
            .previous_hash
            .clone()
            .unwrap_or_else(|| GENESIS_HASH.to_string()),
        output_hash: action.hash.clone(),
        legal_hold: payload_legal_hold(&action.payload),
    }
}

fn map_export_oversight_event(event: &OversightEvent) -> ExportOversightEvent {
    ExportOversightEvent {
        event_id: event.id.clone(),
        timestamp: parse_stored_timestamp(&event.timestamp).unwrap_or(DateTime::<Utc>::UNIX_EPOCH),
        reviewer: json_string(&event.payload, &["approver", "reviewer", "actor"])
            .unwrap_or_else(|| "human-reviewer".to_string()),
        agent_id: None,
        session_id: event
            .session_id
            .clone()
            .unwrap_or_else(|| "oversight-session".to_string()),
        event_type: json_string(&event.payload, &["type", "event_type"])
            .unwrap_or_else(|| event.severity.clone()),
        details: event
            .framework
            .clone()
            .unwrap_or_else(|| event.note.clone()),
        disposition: event.severity.clone(),
        legal_hold: payload_legal_hold(&event.payload),
    }
}

fn payload_legal_hold(payload: &Value) -> bool {
    payload
        .get("legal_hold")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn empty_json_object() -> Value {
    json!({})
}

fn normalize_query_org_id(org_id: Option<&str>) -> Result<Option<String>, ApiError> {
    match org_id {
        None => Ok(None),
        Some(org_id) => {
            let org_id = org_id.trim();
            if org_id.is_empty() {
                Err(ApiError::bad_request("`org_id` must not be empty"))
            } else {
                Ok(Some(org_id.to_string()))
            }
        }
    }
}

fn normalize_payload_org_id(org_id: Option<String>) -> Option<String> {
    org_id.and_then(|org_id| {
        let org_id = org_id.trim();
        (!org_id.is_empty()).then(|| org_id.to_string())
    })
}

fn normalize_sdk_action(item: Value) -> NormalizedActionRecord {
    let org_id = normalize_payload_org_id(json_string_paths(
        &item,
        &[
            &["org_id"],
            &["orgId"],
            &["organization_id"],
            &["organizationId"],
        ],
    ));
    let session_id = json_string_paths(&item, &[&["session_id"], &["sessionId"]])
        .unwrap_or_else(|| "unknown-session".to_string());
    let trace_id = json_string_paths(
        &item,
        &[
            &["trace_id"],
            &["traceId"],
            &["context", "trace_id"],
            &["context", "traceId"],
        ],
    );
    let span_id = json_string_paths(
        &item,
        &[
            &["span_id"],
            &["spanId"],
            &["context", "span_id"],
            &["context", "spanId"],
        ],
    );
    let agent = json_string_paths(&item, &[&["agent_id"], &["agentId"], &["agent"], &["name"]])
        .unwrap_or_else(|| "unknown-agent".to_string());
    let agent_type = json_string_paths(&item, &[&["agent_type"], &["agentType"]])
        .unwrap_or_else(|| "unknown".to_string());
    let action_type = json_string_paths(
        &item,
        &[
            &["action", "type"],
            &["action", "action_type"],
            &["type"],
            &["name"],
            &["event_type"],
        ],
    )
    .unwrap_or_else(|| "event".to_string());
    let tool_name = json_string_paths(
        &item,
        &[
            &["action", "tool_name"],
            &["action", "toolName"],
            &["tool_name"],
            &["toolName"],
            &["payload", "tool"],
        ],
    );
    let target = json_string_paths(
        &item,
        &[
            &["action", "target"],
            &["target"],
            &["resource"],
            &["resource", "name"],
        ],
    );
    let outcome = json_string_paths(&item, &[&["status"], &["action", "status"], &["outcome"]])
        .unwrap_or_else(|| "ok".to_string());
    let timestamp = json_string_paths(&item, &[&["timestamp"]]);
    let schema_version = json_string_paths(&item, &[&["schema_version"], &["schemaVersion"]]);
    let idempotency_key = json_string_paths(&item, &[&["idempotency_key"], &["idempotencyKey"]]);
    let request_metadata = json_value_paths(
        &item,
        &[
            &["request_metadata"],
            &["requestMetadata"],
            &["request", "metadata"],
            &["action", "request_metadata"],
            &["action", "requestMetadata"],
            &["action", "request"],
            &["metadata", "request"],
        ],
    );
    let result_metadata = json_value_paths(
        &item,
        &[
            &["result_metadata"],
            &["resultMetadata"],
            &["result", "metadata"],
            &["action", "result_metadata"],
            &["action", "resultMetadata"],
            &["action", "result"],
            &["metadata", "result"],
        ],
    );

    NormalizedActionRecord {
        org_id,
        timestamp,
        session_id,
        trace_id,
        span_id,
        agent,
        agent_type,
        action_type,
        tool_name,
        target,
        schema_version,
        idempotency_key,
        request_metadata,
        result_metadata,
        outcome,
        payload: item,
    }
}

fn normalize_otlp_span(span: Value) -> NormalizedActionRecord {
    let org_id = normalize_payload_org_id(json_string_paths(
        &span,
        &[
            &["attributes", "org.id"],
            &["attributes", "org_id"],
            &["attributes", "organization.id"],
            &["org_id"],
            &["organization_id"],
        ],
    ));
    let session_id = json_string_paths(
        &span,
        &[
            &["attributes", "session.id"],
            &["attributes", "session_id"],
            &["parentSpanId"],
            &["parent_span_id"],
            &["traceId"],
            &["trace_id"],
        ],
    )
    .unwrap_or_else(|| "unknown-session".to_string());
    let trace_id = json_string_paths(&span, &[&["traceId"], &["trace_id"]]);
    let span_id = json_string_paths(&span, &[&["spanId"], &["span_id"]]);
    let agent = json_string_paths(
        &span,
        &[
            &["attributes", "agent.id"],
            &["attributes", "agent_id"],
            &["agent_id"],
            &["agent"],
            &["traceId"],
            &["trace_id"],
        ],
    )
    .unwrap_or_else(|| "unknown-agent".to_string());
    let agent_type = json_string_paths(
        &span,
        &[
            &["attributes", "agent.type"],
            &["attributes", "agent_type"],
            &["agent_type"],
        ],
    )
    .unwrap_or_else(|| "unknown".to_string());
    let action_type = json_string_paths(&span, &[&["name"]]).unwrap_or_else(|| "event".to_string());
    let tool_name = json_string_paths(
        &span,
        &[&["attributes", "tool.name"], &["attributes", "tool_name"]],
    );
    let target = json_string_paths(
        &span,
        &[
            &["attributes", "target"],
            &["attributes", "target.id"],
            &["attributes", "resource.name"],
            &["attributes", "http.url"],
        ],
    );
    let outcome = json_string_paths(
        &span,
        &[
            &["status"],
            &["status", "code"],
            &["status", "message"],
            &["outcome"],
        ],
    )
    .unwrap_or_else(|| "ok".to_string());
    let timestamp = json_string_paths(&span, &[&["timestamp"], &["startTimeUnixNano"]]);
    let schema_version = json_string_paths(&span, &[&["schema_version"], &["schemaVersion"]]);
    let idempotency_key = json_string_paths(&span, &[&["idempotency_key"], &["idempotencyKey"]]);
    let request_metadata = json_value_paths(
        &span,
        &[
            &["request_metadata"],
            &["requestMetadata"],
            &["request", "metadata"],
            &["metadata", "request"],
        ],
    );
    let result_metadata = json_value_paths(
        &span,
        &[
            &["result_metadata"],
            &["resultMetadata"],
            &["result", "metadata"],
            &["metadata", "result"],
        ],
    );

    NormalizedActionRecord {
        org_id,
        timestamp,
        session_id,
        trace_id,
        span_id,
        agent,
        agent_type,
        action_type,
        tool_name,
        target,
        schema_version,
        idempotency_key,
        request_metadata,
        result_metadata,
        outcome,
        payload: span,
    }
}

fn current_time() -> DateTime<Utc> {
    std::time::SystemTime::now().into()
}

fn normalize_redact_fields(fields: Vec<String>) -> Vec<String> {
    fields
        .into_iter()
        .map(|field| field.trim().to_ascii_lowercase())
        .filter(|field| !field.is_empty())
        .collect()
}

fn redact_value(value: &mut Value, redact_fields: &[String]) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object.iter_mut() {
                if redact_fields
                    .iter()
                    .any(|field| field.eq_ignore_ascii_case(key))
                {
                    *nested = Value::String(REDACTED_VALUE.to_string());
                } else {
                    redact_value(nested, redact_fields);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_value(item, redact_fields);
            }
        }
        _ => {}
    }
}

fn derive_policy_evidence(
    actions: &[StoredActionEntry],
    oversight_events: &[StoredActionEntry],
    storage_control: &StorageControl,
    org_settings: Option<&OrgSettings>,
) -> Vec<PolicyActionEntry> {
    let mut derived = Vec::new();

    if !actions.is_empty() {
        derived.push(PolicyActionEntry::from_owned(
            "persisted audit log evidence",
            vec![
                "logging".to_string(),
                "audit trail".to_string(),
                "audit controls".to_string(),
            ],
            action_refs(actions),
        ));
    }

    let transparency_refs = actions
        .iter()
        .filter(|entry| has_transparency_data(entry))
        .map(action_ref)
        .collect::<Vec<_>>();
    if !transparency_refs.is_empty() {
        derived.push(PolicyActionEntry::from_owned(
            "captured execution and context metadata",
            vec![
                "transparency notice".to_string(),
                "record context".to_string(),
            ],
            transparency_refs,
        ));
    }

    let governance_refs = actions
        .iter()
        .filter(|entry| has_governance_evidence(entry))
        .map(action_ref)
        .chain(oversight_events.iter().map(oversight_ref))
        .collect::<Vec<_>>();
    if !governance_refs.is_empty() {
        derived.push(PolicyActionEntry::from_owned(
            "recorded policy and governance evidence",
            vec![
                "governance policy".to_string(),
                "assigned responsibility".to_string(),
            ],
            governance_refs,
        ));
    }

    let risk_measurement_refs = actions
        .iter()
        .filter(|entry| has_risk_measurement_evidence(entry))
        .map(action_ref)
        .collect::<Vec<_>>();
    if !risk_measurement_refs.is_empty() {
        derived.push(PolicyActionEntry::from_owned(
            "measured and documented runtime activity",
            vec!["risk measurement".to_string()],
            risk_measurement_refs,
        ));
    }

    let risk_management_refs = actions
        .iter()
        .filter(|entry| has_risk_management_evidence(entry))
        .map(action_ref)
        .chain(oversight_events.iter().map(oversight_ref))
        .collect::<Vec<_>>();
    if !risk_management_refs.is_empty() {
        derived.push(PolicyActionEntry::from_owned(
            "recorded response and remediation activity",
            vec!["risk management process".to_string()],
            risk_management_refs,
        ));
    }

    if !actions.is_empty() && oversight_events.len() * 5 >= actions.len() {
        derived.push(PolicyActionEntry::from_owned(
            "human oversight coverage within expected ratio",
            vec!["human oversight".to_string()],
            oversight_events
                .iter()
                .map(oversight_ref)
                .chain(actions.iter().map(action_ref))
                .collect(),
        ));
    }

    if storage_control.min_retention_days >= 180 {
        let mut evidence = vec!["retention 6 months".to_string()];
        if storage_control.min_retention_days >= 365 * 6 {
            evidence.push("retention 6 years".to_string());
        }

        derived.push(PolicyActionEntry::from_owned(
            format!(
                "configured retention for {} days",
                storage_control.min_retention_days
            ),
            evidence,
            vec![format!(
                "storage_control:min_retention_days={}",
                storage_control.min_retention_days
            )],
        ));
    }

    if let Some(org_settings) = org_settings {
        if let Some(min_retention_days) = org_settings.min_retention_days()
            && min_retention_days >= 180
        {
            let mut evidence = vec!["retention 6 months".to_string()];
            if min_retention_days >= 365 * 6 {
                evidence.push("retention 6 years".to_string());
            }

            derived.push(PolicyActionEntry::from_owned(
                format!(
                    "configured organization retention for {} days",
                    min_retention_days
                ),
                evidence,
                vec![format!(
                    "org_settings:{}:retention_policy",
                    org_settings.org_id
                )],
            ));
        }

        if !org_settings.enabled_frameworks.is_empty() {
            derived.push(PolicyActionEntry::from_owned(
                format!(
                    "organization enabled frameworks: {}",
                    org_settings.enabled_frameworks.join(", ")
                ),
                vec![
                    "governance policy".to_string(),
                    "assigned responsibility".to_string(),
                ],
                vec![format!(
                    "org_settings:{}:enabled_frameworks",
                    org_settings.org_id
                )],
            ));
        }

        if org_settings.has_guardrails() {
            derived.push(PolicyActionEntry::from_owned(
                "configured organization guardrails",
                vec![
                    "risk management process".to_string(),
                    "governance policy".to_string(),
                    "human oversight".to_string(),
                ],
                vec![format!(
                    "org_settings:{}:guardrail_settings",
                    org_settings.org_id
                )],
            ));
        }
    }

    if let Some(latest_action) = actions.iter().max_by_key(|entry| entry.timestamp) {
        derived.push(PolicyActionEntry::from_owned(
            "ongoing monitoring and ingestion observed",
            vec![
                "post market monitoring".to_string(),
                "ongoing monitoring".to_string(),
                "information system activity review".to_string(),
            ],
            vec![
                action_ref(latest_action),
                format!(
                    "ingestion:last_action_at={}",
                    latest_action
                        .timestamp
                        .to_rfc3339_opts(SecondsFormat::Nanos, true)
                ),
            ],
        ));
    }

    derived
}

fn map_policy_control_result(result: &PolicyControlResult) -> ComplianceControlResult {
    ComplianceControlResult {
        id: result.control.id.clone(),
        article: result.control.article.clone(),
        requirement: result.control.requirement.clone(),
        matched_evidence: result.matched_evidence.clone(),
        missing_evidence: result.missing_evidence.clone(),
        evidence_refs: result.evidence_refs.clone(),
    }
}

fn action_refs(actions: &[StoredActionEntry]) -> Vec<String> {
    actions.iter().map(action_ref).collect()
}

fn action_ref(entry: &StoredActionEntry) -> String {
    format!("action:{}", entry.id)
}

fn oversight_ref(entry: &StoredActionEntry) -> String {
    format!("oversight:{}", entry.id)
}

fn has_transparency_data(entry: &StoredActionEntry) -> bool {
    metadata_string(&entry.context, "source").is_some()
        || metadata_string(&entry.context, "api_type").is_some()
        || payload_has_nonempty_object(&entry.payload)
}

fn has_governance_evidence(entry: &StoredActionEntry) -> bool {
    entry.action_type == ActionType::PolicyCheck
        || payload_has_key(&entry.payload, "policy")
        || payload_has_key(&entry.payload, "policy_refs")
        || payload_has_key(&entry.context, "policy_refs")
}

fn has_risk_measurement_evidence(entry: &StoredActionEntry) -> bool {
    !entry.outcome.is_empty()
        || payload_has_key(&entry.payload, "status")
        || payload_has_key(&entry.payload, "result")
        || payload_has_nonempty_object(&entry.payload)
}

fn has_risk_management_evidence(entry: &StoredActionEntry) -> bool {
    entry.action_type == ActionType::PolicyCheck
        || entry.action_type == ActionType::HumanOverride
        || !entry.outcome.eq_ignore_ascii_case("ok")
}

fn json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| json_scalar_to_string(value.get(*key)?))
}

fn json_string_paths(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| json_value_path(value, path))
        .and_then(json_scalar_to_string)
}

fn json_value_paths(value: &Value, paths: &[&[&str]]) -> Option<Value> {
    paths
        .iter()
        .find_map(|path| json_value_path(value, path))
        .cloned()
        .filter(value_has_content)
}

fn json_value_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
}

fn json_scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn value_has_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => !object.is_empty(),
        _ => true,
    }
}

fn json_strict_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        _ => None,
    }
}

fn payload_has_key(value: &Value, needle: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.keys().any(|key| key.eq_ignore_ascii_case(needle))
                || object
                    .values()
                    .any(|nested| payload_has_key(nested, needle))
        }
        Value::Array(items) => items.iter().any(|nested| payload_has_key(nested, needle)),
        _ => false,
    }
}

fn payload_has_nonempty_object(value: &Value) -> bool {
    matches!(value, Value::Object(object) if !object.is_empty())
}

fn validate_sdk_action(value: &Value) -> Result<(), ApiError> {
    let object = value
        .as_object()
        .ok_or_else(|| ApiError::invalid_json("trace event must be a JSON object"))?;

    require_string_field_paths(value, &[&["session_id"], &["sessionId"]], "session_id")?;
    require_string_field_paths(
        value,
        &[&["agent_id"], &["agentId"], &["agent"], &["name"]],
        "agent_id",
    )?;
    require_string_field_paths(
        value,
        &[
            &["action", "type"],
            &["action", "action_type"],
            &["type"],
            &["name"],
            &["event_type"],
        ],
        "type",
    )?;

    if object.contains_key("timestamp") {
        let timestamp = require_string_field_paths(value, &[&["timestamp"]], "timestamp")?;
        if parse_stored_timestamp(&timestamp).is_none() {
            return Err(ApiError::invalid_json(
                "field `timestamp` must be RFC3339 or unix timestamp in nanoseconds",
            ));
        }
    }

    validate_object_field(value, &["payload"], "payload")?;
    validate_object_field(value, &["action"], "action")?;
    validate_object_field(value, &["context"], "context")?;
    validate_string_field(value, &["tool_name"], "tool_name")?;
    validate_string_field(value, &["toolName"], "toolName")?;
    validate_string_field(value, &["agent_type"], "agent_type")?;
    validate_string_field(value, &["agentType"], "agentType")?;
    validate_string_field(value, &["target"], "target")?;
    validate_string_field(value, &["status"], "status")?;
    validate_string_field(value, &["outcome"], "outcome")?;
    validate_string_field(value, &["idempotency_key"], "idempotency_key")?;
    validate_string_field(value, &["idempotencyKey"], "idempotencyKey")?;
    validate_resource_field(value)?;

    if let Some(action) = value.get("action") {
        validate_string_field(action, &["type"], "action.type")?;
        validate_string_field(action, &["action_type"], "action.action_type")?;
        validate_string_field(action, &["tool_name"], "action.tool_name")?;
        validate_string_field(action, &["toolName"], "action.toolName")?;
        validate_string_field(action, &["target"], "action.target")?;
        validate_string_field(action, &["status"], "action.status")?;
    }

    Ok(())
}

fn require_string_field_paths(
    value: &Value,
    paths: &[&[&str]],
    field_name: &str,
) -> Result<String, ApiError> {
    match paths
        .iter()
        .find_map(|path| json_value_path(value, path))
        .map(json_strict_string)
    {
        Some(Some(text)) if !text.trim().is_empty() => Ok(text),
        Some(Some(_)) | Some(None) => Err(ApiError::invalid_json(format!(
            "field `{field_name}` must be a string"
        ))),
        None => Err(ApiError::missing_field(format!(
            "trace event is missing required field `{field_name}`"
        ))),
    }
}

fn validate_string_field(value: &Value, path: &[&str], field_name: &str) -> Result<(), ApiError> {
    if let Some(raw) = json_value_path(value, path)
        && json_strict_string(raw).is_none()
    {
        return Err(ApiError::invalid_json(format!(
            "field `{field_name}` must be a string"
        )));
    }

    Ok(())
}

fn validate_object_field(value: &Value, path: &[&str], field_name: &str) -> Result<(), ApiError> {
    if let Some(raw) = json_value_path(value, path)
        && !raw.is_object()
    {
        return Err(ApiError::invalid_json(format!(
            "field `{field_name}` must be an object"
        )));
    }

    Ok(())
}

fn validate_resource_field(value: &Value) -> Result<(), ApiError> {
    if let Some(resource) = value.get("resource")
        && !resource.is_string()
        && !resource.is_object()
    {
        return Err(ApiError::invalid_json(
            "field `resource` must be a string or object",
        ));
    }

    Ok(())
}

fn validate_otlp_span(span: &Value) -> Result<(), ApiError> {
    if !has_string_field(span, &["traceId", "trace_id"]) {
        return Err(ApiError::missing_field(
            "OTLP span is missing required field `traceId`",
        ));
    }
    if !has_string_field(span, &["spanId", "span_id"]) {
        return Err(ApiError::missing_field(
            "OTLP span is missing required field `spanId`",
        ));
    }
    if !has_string_field(span, &["name"]) {
        return Err(ApiError::missing_field(
            "OTLP span is missing required field `name`",
        ));
    }

    Ok(())
}

fn has_string_field(value: &Value, keys: &[&str]) -> bool {
    json_string(value, keys).is_some()
}

fn parse_framework(framework: &str) -> Result<PolicyFramework, ApiError> {
    match PolicyFramework::from_name(framework) {
        PolicyFramework::Custom(_) => Err(ApiError::unsupported_framework(format!(
            "framework `{framework}` is not supported"
        ))),
        supported => Ok(supported),
    }
}

fn ensure_framework_enabled(
    org_settings: Option<&OrgSettings>,
    framework: &PolicyFramework,
    org_id: Option<&str>,
) -> Result<(), ApiError> {
    let Some(org_settings) = org_settings else {
        return Ok(());
    };
    if org_settings.enabled_frameworks.is_empty()
        || org_settings
            .enabled_frameworks
            .iter()
            .any(|enabled| PolicyFramework::from_name(enabled).name() == framework.name())
    {
        return Ok(());
    }

    Err(ApiError::bad_request(format!(
        "framework `{}` is not enabled for organization `{}`",
        framework.name(),
        org_id.unwrap_or(org_settings.org_id.as_str())
    )))
}

fn validate_time_window(
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<(), ApiError> {
    if let (Some(from), Some(to)) = (from, to)
        && from > to
    {
        return Err(ApiError::bad_request(
            "`from` must be earlier than or equal to `to`",
        ));
    }

    Ok(())
}

fn parse_time(value: Option<&str>) -> Result<Option<DateTime<Utc>>, ApiError> {
    match value {
        None => Ok(None),
        Some(raw) => DateTime::parse_from_rfc3339(raw)
            .map(|timestamp| Some(timestamp.with_timezone(&Utc)))
            .map_err(|_| ApiError::bad_request(format!("invalid RFC3339 timestamp: {raw}"))),
    }
}

fn extract_otlp_spans(payload: &Value) -> Vec<Value> {
    if let Some(spans) = payload.get("spans").and_then(Value::as_array) {
        return spans.clone();
    }

    if payload.get("traceId").is_some() || payload.get("trace_id").is_some() {
        return vec![payload.clone()];
    }

    payload
        .get("resourceSpans")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|resource_span| {
            let resource_attributes = resource_span
                .get("resource")
                .and_then(|resource| resource.get("attributes"))
                .or_else(|| resource_span.get("attributes"));
            let resource_attributes = parse_otlp_attributes(resource_attributes);

            resource_span
                .get("scopeSpans")
                .or_else(|| resource_span.get("instrumentationLibrarySpans"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .flat_map(move |scope_span| {
                    let resource_attributes = resource_attributes.clone();
                    scope_span
                        .get("spans")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(move |span| enrich_otlp_span(span, &resource_attributes))
                })
        })
        .collect()
}

fn enrich_otlp_span(span: &Value, resource_attributes: &Map<String, Value>) -> Option<Value> {
    let mut span_object = span.as_object()?.clone();
    let mut span_attributes = parse_otlp_attributes(span_object.get("attributes"));

    for (key, value) in resource_attributes {
        span_attributes
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }

    if !span_attributes.is_empty() {
        span_object.insert("attributes".to_string(), Value::Object(span_attributes));
    }

    Some(Value::Object(span_object))
}

fn parse_otlp_attributes(value: Option<&Value>) -> Map<String, Value> {
    match value {
        Some(Value::Object(object)) => object.clone(),
        Some(Value::Array(attributes)) => attributes
            .iter()
            .filter_map(|attribute| {
                let object = attribute.as_object()?;
                let key = object.get("key")?.as_str()?.to_string();
                let value = object
                    .get("value")
                    .map(parse_otlp_any_value)
                    .unwrap_or(Value::Null);
                Some((key, value))
            })
            .collect(),
        _ => Map::new(),
    }
}

fn parse_otlp_any_value(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return value.clone();
    };

    if let Some(string_value) = object.get("stringValue").and_then(Value::as_str) {
        return Value::String(string_value.to_string());
    }
    if let Some(bool_value) = object.get("boolValue").and_then(Value::as_bool) {
        return Value::Bool(bool_value);
    }
    if let Some(int_value) = object.get("intValue") {
        return match int_value {
            Value::String(raw) => raw
                .parse::<i64>()
                .map(Into::into)
                .unwrap_or_else(|_| Value::String(raw.clone())),
            Value::Number(number) => Value::Number(number.clone()),
            _ => Value::Null,
        };
    }
    if let Some(double_value) = object.get("doubleValue").and_then(Value::as_f64) {
        return serde_json::Number::from_f64(double_value)
            .map(Value::Number)
            .unwrap_or(Value::Null);
    }
    if let Some(array_value) = object.get("arrayValue").and_then(Value::as_object) {
        let values = array_value
            .get("values")
            .and_then(Value::as_array)
            .map(|items| items.iter().map(parse_otlp_any_value).collect())
            .unwrap_or_default();
        return Value::Array(values);
    }
    if let Some(kvlist_value) = object.get("kvlistValue").and_then(Value::as_object) {
        let map = kvlist_value
            .get("values")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let object = item.as_object()?;
                        let key = object.get("key")?.as_str()?.to_string();
                        let value = object
                            .get("value")
                            .map(parse_otlp_any_value)
                            .unwrap_or(Value::Null);
                        Some((key, value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        return Value::Object(map);
    }
    if let Some(bytes_value) = object.get("bytesValue").and_then(Value::as_str) {
        return Value::String(bytes_value.to_string());
    }

    value.clone()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{
            Request, StatusCode,
            header::{AUTHORIZATION, CONTENT_TYPE},
        },
    };
    use serde_json::json;
    use tokio::time::{Duration, timeout};
    use tower::util::ServiceExt;

    use super::{LiveEvent, app, shared_state};

    const TEST_API_KEY: &str = "test-api-key";

    #[tokio::test]
    async fn root_route_serves_embedded_landing_page() {
        let response = app(shared_state(None))
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("Know what your AI"));
        assert!(html.contains("/dashboard"));
        assert!(html.contains("github.com/trailingai/trailing"));
    }

    #[tokio::test]
    async fn dashboard_route_serves_embedded_page() {
        let response = app(shared_state(None))
            .oneshot(
                Request::builder()
                    .uri("/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("Compliance Audit Dashboard"));
        assert!(html.contains("/v1/actions"));
        assert!(html.contains("Retention"));
        assert!(html.contains("retention-policy-list"));
    }

    #[tokio::test]
    async fn retention_summary_route_returns_dashboard_payload() {
        let response = app(shared_state(Some(TEST_API_KEY.to_string())))
            .oneshot(
                Request::builder()
                    .uri("/v1/retention/summary")
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload = String::from_utf8(body.to_vec()).unwrap();

        assert!(payload.contains("effective_retention_days"));
        assert!(payload.contains("active_legal_holds"));
        assert!(payload.contains("age_distribution"));
    }

    #[tokio::test]
    async fn events_route_serves_sse_stream() {
        let response = app(shared_state(Some(TEST_API_KEY.to_string())))
            .oneshot(
                Request::builder()
                    .uri("/v1/events")
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
    }

    #[tokio::test]
    async fn events_route_accepts_token_query_param() {
        let response = app(shared_state(Some(TEST_API_KEY.to_string())))
            .oneshot(
                Request::builder()
                    .uri("/v1/events?token=test-api-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
    }

    #[tokio::test]
    async fn integrity_route_accepts_bearer_api_key() {
        let response = app(shared_state(Some(TEST_API_KEY.to_string())))
            .oneshot(
                Request::builder()
                    .uri("/v1/integrity")
                    .header(AUTHORIZATION, format!("Bearer {TEST_API_KEY}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn posting_trace_broadcasts_live_action_event() {
        let state = shared_state(Some(TEST_API_KEY.to_string()));
        let mut receiver = state.live_events.subscribe();

        let response = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/traces")
                    .header("x-api-key", TEST_API_KEY)
                    .header("x-trailing-org-id", "org-1")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "session_id": "session-123",
                            "agent": "planner-agent",
                            "agent_type": "orchestrator",
                            "type": "tool_call",
                            "tool_name": "web.search",
                            "target": "https://example.com/policy",
                            "payload": {
                                "query": "policy evidence retention"
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let event = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();

        match event {
            LiveEvent::Action { action, .. } => {
                assert_eq!(action.session_id, "session-123");
                assert_eq!(action.agent, "planner-agent");
                assert_eq!(action.source, "sdk");
            }
            LiveEvent::Oversight { .. } => panic!("expected action event"),
        }
    }

    #[tokio::test]
    async fn openapi_route_serves_embedded_spec() {
        let response = app(shared_state(Some(TEST_API_KEY.to_string())))
            .oneshot(
                Request::builder()
                    .uri("/v1/openapi.yml")
                    .header("x-api-key", TEST_API_KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/yaml; charset=utf-8")
        );

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let spec = String::from_utf8(body.to_vec()).unwrap();

        assert!(spec.contains("openapi: 3.0.3"));
        assert!(spec.contains("/v1/actions:"));
        assert!(spec.contains("/v1/events:"));
        assert!(spec.contains("/v1/openapi.yml:"));
    }
}
