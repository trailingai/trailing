pub mod auth;
pub mod chain;
pub mod compliance_store;
pub mod merkle;
pub mod migration;
mod postgres;
pub mod retention;
pub mod tenant_store;

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::ledger::{
    ChainIntegrity, LedgerBackend as CoreLedgerBackend, LedgerEntry, LedgerFilter, LedgerProof,
    Range,
};
use crate::{
    checkpoint::{
        CheckpointError, CheckpointPayload, CheckpointSigner, CheckpointVerification,
        SigningKeyMetadata, checkpoint_hash, verify_signed_checkpoint,
    },
    log::{ActionEntry, ActionType, GENESIS_HASH},
    tenant::{self, Organization, Project, TenantContext},
};

use merkle::{MerkleCheckpoint, MerkleInclusionProof};

pub use auth::is_valid_internal_role;
pub use compliance_store::purge_expired;
pub use merkle::{
    MERKLE_BATCH_SIZE, MerkleProofStep, MerkleSiblingPosition, verify_inclusion_proof,
};
pub use postgres::PostgresStorage;
pub use retention::{LegalHoldEvent, LegalHoldRecord, OrgRetentionPolicy, RetentionPolicy};

pub(crate) use auth::{
    API_KEY_PREFIX, DUMMY_BCRYPT_HASH, bcrypt_hash, bcrypt_verify, normalize_internal_role,
    normalize_role_mappings, optional_trimmed, parse_api_key, require_non_empty,
};
pub use chain::verify_chain;
pub(crate) use chain::{
    RawStoredEntry, StoredEntry, build_merkle_root, calculate_checkpoint_hash,
    compute_merkle_root_from_batches, connection_path, load_entries_for_range, load_latest_hash,
    parse_stored_entry, record_integrity_check_details, validate_entry_hashes, write_root_anchor,
};

type StdResult<T, E> = std::result::Result<T, E>;

const SCHEMA_VERSION_LEGACY: i64 = 1;
const SCHEMA_VERSION_IMMUTABLE_LEDGER: i64 = 2;
const LEDGER_CHECKPOINT_INTERVAL: i64 = 1;

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Postgres(String),
    Command(String),
    SerdeJson(serde_json::Error),
    Uuid(uuid::Error),
    Chrono(chrono::ParseError),
    InvalidActionType(String),
    InvalidPrincipalRole(String),
    InvalidCredentialType(String),
    InvalidApiKeyFormat,
    InvalidInput(String),
    Checkpoint(String),
    MissingBoundary(Uuid),
    InvalidEntryHash { expected: String, actual: String },
    BrokenAppendChain { expected: String, actual: String },
    LegalHoldActive,
    AuthenticationFailed,
    MfaAlreadyEnabled,
    MfaEnrollmentRequired,
    MfaNotEnabled,
    MfaPendingEnrollment,
    InvalidMfaCode,
    AuthChallengeNotFound,
    AuthChallengeExpired,
    AuthChallengeUsed,
    ImmutableLedger,
}

impl Display for StorageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Sqlite(err) => write!(f, "{err}"),
            Self::Postgres(err) => write!(f, "{err}"),
            Self::Command(message) => write!(f, "{message}"),
            Self::SerdeJson(err) => write!(f, "{err}"),
            Self::Uuid(err) => write!(f, "{err}"),
            Self::Chrono(err) => write!(f, "{err}"),
            Self::InvalidActionType(value) => write!(f, "invalid action type: {value}"),
            Self::InvalidPrincipalRole(value) => write!(f, "invalid principal role: {value}"),
            Self::InvalidCredentialType(value) => {
                write!(f, "invalid credential type: {value}")
            }
            Self::InvalidApiKeyFormat => f.write_str("invalid API key format"),
            Self::InvalidInput(message) => write!(f, "{message}"),
            Self::Checkpoint(message) => write!(f, "{message}"),
            Self::MissingBoundary(id) => write!(f, "entry boundary not found: {id}"),
            Self::InvalidEntryHash { expected, actual } => {
                write!(
                    f,
                    "entry hash mismatch: expected {expected}, found {actual}"
                )
            }
            Self::BrokenAppendChain { expected, actual } => {
                write!(
                    f,
                    "append chain mismatch: expected {expected}, found {actual}"
                )
            }
            Self::LegalHoldActive => f.write_str("purge blocked by active legal hold"),
            Self::AuthenticationFailed => f.write_str("invalid email, password, or organization"),
            Self::MfaAlreadyEnabled => f.write_str("mfa is already enabled for this account"),
            Self::MfaEnrollmentRequired => {
                f.write_str("mfa enrollment is required before sign-in can complete")
            }
            Self::MfaNotEnabled => f.write_str("mfa is not enabled for this account"),
            Self::MfaPendingEnrollment => {
                f.write_str("mfa enrollment has not been started for this account")
            }
            Self::InvalidMfaCode => f.write_str("invalid mfa or recovery code"),
            Self::AuthChallengeNotFound => f.write_str("auth challenge not found"),
            Self::AuthChallengeExpired => f.write_str("auth challenge expired"),
            Self::AuthChallengeUsed => f.write_str("auth challenge has already been used"),
            Self::ImmutableLedger => f.write_str("purge is not supported for the immutable ledger"),
        }
    }
}

impl StdError for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(value: serde_json::Error) -> Self {
        Self::SerdeJson(value)
    }
}

impl From<uuid::Error> for StorageError {
    fn from(value: uuid::Error) -> Self {
        Self::Uuid(value)
    }
}

impl From<chrono::ParseError> for StorageError {
    fn from(value: chrono::ParseError) -> Self {
        Self::Chrono(value)
    }
}

impl From<CheckpointError> for StorageError {
    fn from(value: CheckpointError) -> Self {
        Self::Checkpoint(value.to_string())
    }
}

pub type Result<T> = StdResult<T, StorageError>;

#[derive(Debug, Clone)]
pub enum DeduplicationOutcome<T> {
    Inserted(T),
    Duplicate { entry_id: Option<String> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntegrityViolation {
    pub entry_id: Uuid,
    pub reason: String,
    pub expected_previous_hash: Option<String>,
    pub actual_previous_hash: String,
    pub expected_entry_hash: String,
    pub actual_entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageControl {
    pub allow_purge: bool,
    pub min_retention_days: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckpointCoverage {
    id: String,
    checkpointed_at: String,
    start_sequence: i64,
    end_sequence: i64,
    entry_count: i64,
    last_entry_id: String,
    last_entry_hash: String,
    previous_checkpoint_hash: String,
    checkpoint_hash: String,
}

pub struct StorageScope {
    pub org_id: String,
    pub project_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgSettings {
    pub org_id: String,
    pub retention_policy: Value,
    pub enabled_frameworks: Vec<String>,
    pub guardrail_settings: Value,
    pub created_at: String,
    pub updated_at: String,
}

impl OrgSettings {
    pub fn min_retention_days(&self) -> Option<i64> {
        self.retention_policy
            .get("min_retention_days")
            .and_then(Value::as_i64)
    }

    pub fn legal_hold(&self) -> bool {
        self.retention_policy
            .get("legal_hold")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    pub fn has_guardrails(&self) -> bool {
        matches!(&self.guardrail_settings, Value::Object(values) if !values.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgSettingsInput {
    pub retention_policy: Value,
    pub enabled_frameworks: Vec<String>,
    pub guardrail_settings: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiKeyRecord {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked: bool,
    pub is_admin: bool,
    pub roles: Vec<ApiKeyRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreatedApiKey {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub created_at: String,
    pub key: String,
    pub is_admin: bool,
    pub roles: Vec<ApiKeyRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedApiKey {
    pub id: String,
    pub org_id: String,
    pub is_admin: bool,
    pub revoked: bool,
    pub roles: Vec<ApiKeyRole>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MfaPolicy {
    Optional,
    Required,
}

impl MfaPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
}

impl FromStr for MfaPolicy {
    type Err = String;

    fn from_str(value: &str) -> StdResult<Self, Self::Err> {
        match value {
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            _ => Err(format!("invalid mfa policy: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyRole {
    Ingest,
    Query,
    Export,
    Configure,
    ManageKeys,
    Admin,
}

impl ApiKeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::Query => "query",
            Self::Export => "export",
            Self::Configure => "configure",
            Self::ManageKeys => "manage_keys",
            Self::Admin => "admin",
        }
    }

    pub fn default_service_roles() -> Vec<Self> {
        vec![Self::Ingest, Self::Query, Self::Export]
    }

    pub fn admin_roles() -> Vec<Self> {
        vec![Self::Admin]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalRole {
    Admin,
    ComplianceOfficer,
    Developer,
    Auditor,
    ReadOnly,
}

impl PrincipalRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::ComplianceOfficer => "compliance_officer",
            Self::Developer => "developer",
            Self::Auditor => "auditor",
            Self::ReadOnly => "read_only",
        }
    }
}

impl Display for PrincipalRole {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PrincipalRole {
    type Err = StorageError;

    fn from_str(value: &str) -> StdResult<Self, Self::Err> {
        match value {
            "admin" => Ok(Self::Admin),
            "compliance_officer" => Ok(Self::ComplianceOfficer),
            "developer" => Ok(Self::Developer),
            "auditor" => Ok(Self::Auditor),
            "read_only" => Ok(Self::ReadOnly),
            other => Err(StorageError::InvalidPrincipalRole(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthAuditEventType {
    Login,
    KeyCreation,
    KeyRevocation,
    RoleChange,
    PermissionGrant,
}

impl Display for AuthAuditEventType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Login => "login",
            Self::KeyCreation => "key_creation",
            Self::KeyRevocation => "key_revocation",
            Self::RoleChange => "role_change",
            Self::PermissionGrant => "permission_grant",
        };

        f.write_str(value)
    }
}

impl FromStr for AuthAuditEventType {
    type Err = String;

    fn from_str(value: &str) -> StdResult<Self, Self::Err> {
        match value {
            "login" => Ok(Self::Login),
            "key_creation" => Ok(Self::KeyCreation),
            "key_revocation" => Ok(Self::KeyRevocation),
            "role_change" => Ok(Self::RoleChange),
            "permission_grant" => Ok(Self::PermissionGrant),
            _ => Err(format!("unknown auth audit event type: {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrincipalUser {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrgMembership {
    pub org_id: String,
    pub user_id: String,
    pub role: PrincipalRole,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlIdpConfig {
    pub org_id: String,
    pub enabled: bool,
    pub idp_entity_id: String,
    pub sso_url: String,
    pub idp_certificate_pem: String,
    pub sp_entity_id: String,
    pub acs_url: String,
    pub email_attribute: String,
    pub first_name_attribute: Option<String>,
    pub last_name_attribute: Option<String>,
    pub role_attribute: Option<String>,
    pub role_mappings: HashMap<String, String>,
    pub default_role: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    ApiKey,
    ServiceAccount,
}

impl Display for CredentialType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey => f.write_str("api_key"),
            Self::ServiceAccount => f.write_str("service_account"),
        }
    }
}

impl FromStr for CredentialType {
    type Err = StorageError;

    fn from_str(value: &str) -> StdResult<Self, Self::Err> {
        match value {
            "api_key" => Ok(Self::ApiKey),
            "service_account" => Ok(Self::ServiceAccount),
            _ => Err(StorageError::InvalidCredentialType(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialCreator {
    pub actor_type: String,
    pub actor_id: String,
}

impl CredentialCreator {
    pub fn new(actor_type: impl Into<String>, actor_id: impl Into<String>) -> Self {
        Self {
            actor_type: actor_type.into(),
            actor_id: actor_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCredentialRequest {
    pub org_id: String,
    pub name: String,
    pub credential_type: CredentialType,
    pub project_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_by: Option<CredentialCreator>,
    pub previous_key_id: Option<String>,
    pub roles: Option<Vec<ApiKeyRole>>,
}

impl CreateCredentialRequest {
    pub fn api_key(org_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            org_id: org_id.into(),
            name: name.into(),
            credential_type: CredentialType::ApiKey,
            project_id: None,
            expires_at: None,
            created_by: None,
            previous_key_id: None,
            roles: None,
        }
    }

    pub fn service_account(org_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            org_id: org_id.into(),
            name: name.into(),
            credential_type: CredentialType::ServiceAccount,
            project_id: None,
            expires_at: None,
            created_by: None,
            previous_key_id: None,
            roles: None,
        }
    }

    pub fn with_project_id(mut self, project_id: impl Into<String>) -> Self {
        self.project_id = Some(project_id.into());
        self
    }

    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_creator(mut self, created_by: CredentialCreator) -> Self {
        self.created_by = Some(created_by);
        self
    }

    pub fn with_previous_key_id(mut self, previous_key_id: impl Into<String>) -> Self {
        self.previous_key_id = Some(previous_key_id.into());
        self
    }

    pub fn with_roles(mut self, roles: impl IntoIterator<Item = ApiKeyRole>) -> Self {
        self.roles = Some(roles.into_iter().collect());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthAuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuthAuditEventType,
    pub org_id: Option<String>,
    pub actor_type: String,
    pub actor_id: Option<String>,
    pub subject_type: String,
    pub subject_id: String,
    pub payload: Value,
    pub outcome: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpsertSamlIdpConfig {
    pub enabled: bool,
    pub idp_entity_id: String,
    pub sso_url: String,
    pub idp_certificate_pem: String,
    pub sp_entity_id: String,
    pub acs_url: String,
    pub email_attribute: String,
    pub first_name_attribute: Option<String>,
    pub last_name_attribute: Option<String>,
    pub role_attribute: Option<String>,
    pub role_mappings: HashMap<String, String>,
    pub default_role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRecord {
    pub id: String,
    pub org_id: String,
    pub external_subject: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: String,
    pub role: String,
    pub created_at: String,
    pub last_login_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreatedSession {
    pub id: String,
    pub org_id: String,
    pub token: String,
    pub created_at: String,
    pub expires_at: String,
    pub user: UserRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedSession {
    pub id: String,
    pub user_id: String,
    pub org_id: String,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HumanUserRecord {
    pub id: String,
    pub org_id: String,
    pub email: String,
    pub created_at: String,
    pub last_authenticated_at: Option<String>,
    pub mfa_enabled: bool,
    pub mfa_policy: MfaPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaEnrollmentStart {
    pub user_id: String,
    pub org_id: String,
    pub email: String,
    pub secret: String,
    pub provisioning_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaEnrollmentConfirm {
    pub user_id: String,
    pub org_id: String,
    pub email: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MfaChallengeStart {
    Authenticated {
        user_id: String,
        org_id: String,
        email: String,
    },
    ChallengeRequired {
        user_id: String,
        org_id: String,
        email: String,
        challenge_id: String,
        expires_at: String,
    },
    EnrollmentRequired {
        user_id: String,
        org_id: String,
        email: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MfaChallengeVerify {
    pub user_id: String,
    pub org_id: String,
    pub email: String,
    pub method: String,
    pub recovery_code_used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialRecord {
    pub id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub name: String,
    pub credential_type: CredentialType,
    pub created_at: String,
    pub created_by: Option<CredentialCreator>,
    pub expires_at: Option<String>,
    pub previous_key_id: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked: bool,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
    pub is_admin: bool,
    pub roles: Vec<ApiKeyRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreatedCredential {
    pub id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub name: String,
    pub credential_type: CredentialType,
    pub created_at: String,
    pub created_by: Option<CredentialCreator>,
    pub expires_at: Option<String>,
    pub previous_key_id: Option<String>,
    pub key: String,
    pub is_admin: bool,
    pub roles: Vec<ApiKeyRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedCredential {
    pub id: String,
    pub org_id: String,
    pub project_id: Option<String>,
    pub credential_type: CredentialType,
    pub expires_at: Option<String>,
    pub is_admin: bool,
    pub revoked: bool,
    pub roles: Vec<ApiKeyRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExternalAnchorInput {
    pub provider: String,
    pub reference: String,
    pub anchored_at: Option<String>,
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExternalAnchorRecord {
    pub anchor_id: String,
    pub provider: String,
    pub reference: String,
    pub anchored_at: String,
    pub anchored_hash: String,
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedCheckpoint {
    pub checkpoint_id: String,
    pub created_at: String,
    pub sequence: i64,
    pub entry_id: String,
    pub ledger_root_hash: String,
    pub checkpoint_hash: String,
    pub signature: String,
    pub key: SigningKeyMetadata,
    pub anchors: Vec<ExternalAnchorRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedCheckpoint {
    pub checkpoint: SignedCheckpoint,
    pub verification: CheckpointVerification,
    pub anchor_hashes_valid: bool,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LedgerCheckpoint {
    pub checkpoint_id: String,
    pub sequence: i64,
    pub entry_id: String,
    pub entry_hash: String,
    pub merkle_root: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MerkleBatch {
    pub batch_id: i64,
    pub start_sequence: i64,
    pub end_sequence: i64,
    pub leaf_count: i64,
    pub root_hash: String,
    pub created_at: String,
}

#[allow(clippy::too_many_arguments)]
pub trait LedgerBackend {
    fn backend_name(&self) -> &'static str;
    fn entries(&self) -> Result<Vec<ActionEntry>>;
    fn entries_for_org(&self, org_id: Option<&str>) -> Result<Vec<ActionEntry>>;
    fn append_entry(&self, entry: &ActionEntry) -> Result<()>;
    fn append_entry_for_org(&self, entry: &ActionEntry, org_id: Option<&str>) -> Result<()>;
    fn append_action_at(
        &self,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry>;
    fn append_action_at_for_org(
        &self,
        org_id: Option<&str>,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry>;
    fn append_action(
        &self,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry>;
    fn append_action_for_org(
        &self,
        org_id: Option<&str>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry>;
    fn append_action_with_dedup_at(
        &self,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<Option<ActionEntry>>;
    fn append_action_with_dedup_at_for_org(
        &self,
        org_id: Option<&str>,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<Option<ActionEntry>>;
    fn verify_chain(
        &self,
        from_id: Option<Uuid>,
        to_id: Option<Uuid>,
    ) -> Result<Vec<IntegrityViolation>>;
    fn create_checkpoint(&self) -> Result<LedgerCheckpoint>;
    fn latest_checkpoint(&self) -> Result<Option<LedgerCheckpoint>>;
    fn merkle_batches(&self) -> Result<Vec<MerkleBatch>>;
    fn purge_expired(&self, as_of: DateTime<Utc>) -> Result<usize>;
    fn control_settings(&self) -> Result<StorageControl>;
    fn database_size_bytes(&self) -> Result<u64>;
    fn create_api_key(&self, org_id: &str, name: &str) -> Result<CreatedApiKey>;
    fn list_api_keys(&self) -> Result<Vec<ApiKeyRecord>>;
    fn list_api_keys_for_org(&self, org_id: &str) -> Result<Vec<ApiKeyRecord>>;
    fn revoke_api_key(&self, key_id: &str) -> Result<bool>;
    fn revoke_api_key_for_org(&self, org_id: &str, key_id: &str) -> Result<bool>;
    fn authenticate_api_key(&self, raw_key: &str) -> Result<Option<AuthenticatedApiKey>>;
}

#[derive(Debug)]
pub enum Storage {
    Sqlite(SqliteStorage),
    Postgres(PostgresStorage),
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let raw = path.as_ref().as_os_str().to_string_lossy();
        if looks_like_postgres_dsn(raw.as_ref()) {
            PostgresStorage::open(raw.as_ref()).map(Self::Postgres)
        } else {
            SqliteStorage::open(path).map(Self::Sqlite)
        }
    }

    pub fn open_in_memory() -> Result<Self> {
        SqliteStorage::open_in_memory().map(Self::Sqlite)
    }

    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Sqlite(storage) => storage.backend_name(),
            Self::Postgres(storage) => storage.backend_name(),
        }
    }

    pub fn entries(&self) -> Result<Vec<ActionEntry>> {
        match self {
            Self::Sqlite(storage) => storage.entries(),
            Self::Postgres(storage) => storage.entries(),
        }
    }

    pub fn entries_for_org(&self, org_id: Option<&str>) -> Result<Vec<ActionEntry>> {
        match self {
            Self::Sqlite(storage) => storage.entries_for_org(org_id),
            Self::Postgres(storage) => storage.entries_for_org(org_id),
        }
    }

    pub fn root_anchor_hash(&self) -> Result<Option<String>> {
        match self {
            Self::Sqlite(storage) => chain::load_root_anchor(storage.connection()),
            Self::Postgres(storage) => Ok(storage
                .entries()?
                .last()
                .map(|entry| entry.entry_hash.clone())),
        }
    }

    pub fn root_anchor_persisted(&self) -> Result<bool> {
        match self {
            Self::Sqlite(storage) => Ok(chain::connection_path(storage.connection())?.is_some()),
            Self::Postgres(_) => Ok(true),
        }
    }

    pub fn append_entry(&self, entry: &ActionEntry) -> Result<()> {
        match self {
            Self::Sqlite(storage) => storage.append_entry(entry),
            Self::Postgres(storage) => storage.append_entry(entry),
        }
    }

    pub fn append_entry_for_org(&self, entry: &ActionEntry, org_id: Option<&str>) -> Result<()> {
        match self {
            Self::Sqlite(storage) => storage.append_entry_for_org(entry, org_id),
            Self::Postgres(storage) => storage.append_entry_for_org(entry, org_id),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_at(
        &self,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        let agent_id = agent_id.into();
        let agent_type = agent_type.into();
        let session_id = session_id.into();
        let outcome = outcome.into();
        match self {
            Self::Sqlite(storage) => storage.append_action_at(
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
            ),
            Self::Postgres(storage) => storage.append_action_at(
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_at_for_org(
        &self,
        org_id: Option<&str>,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        let agent_id = agent_id.into();
        let agent_type = agent_type.into();
        let session_id = session_id.into();
        let outcome = outcome.into();
        match self {
            Self::Sqlite(storage) => storage.append_action_at_for_org(
                org_id,
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
            ),
            Self::Postgres(storage) => storage.append_action_at_for_org(
                org_id,
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action(
        &self,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        self.append_action_for_org(
            None,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_for_org(
        &self,
        org_id: Option<&str>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        self.append_action_at_for_org(
            org_id,
            current_time(),
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_with_dedup_at(
        &self,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<Option<ActionEntry>> {
        self.append_action_with_dedup_at_for_org(
            None,
            dedup_key,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_with_dedup_at_for_org(
        &self,
        org_id: Option<&str>,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<Option<ActionEntry>> {
        let agent_id = agent_id.into();
        let agent_type = agent_type.into();
        let session_id = session_id.into();
        let outcome = outcome.into();
        match self {
            Self::Sqlite(storage) => storage.append_action_with_dedup_at_for_org(
                org_id,
                dedup_key,
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
            ),
            Self::Postgres(storage) => storage.append_action_with_dedup_at_for_org(
                org_id,
                dedup_key,
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
            ),
        }
    }

    pub fn verify_chain(
        &self,
        from_id: Option<Uuid>,
        to_id: Option<Uuid>,
    ) -> Result<Vec<IntegrityViolation>> {
        match self {
            Self::Sqlite(storage) => storage.verify_chain(from_id, to_id),
            Self::Postgres(storage) => storage.verify_chain(from_id, to_id),
        }
    }

    pub fn create_checkpoint(&self) -> Result<LedgerCheckpoint> {
        match self {
            Self::Sqlite(storage) => storage.create_checkpoint(),
            Self::Postgres(storage) => storage.create_checkpoint(),
        }
    }

    pub fn latest_checkpoint(&self) -> Result<Option<LedgerCheckpoint>> {
        match self {
            Self::Sqlite(storage) => storage.latest_checkpoint(),
            Self::Postgres(storage) => storage.latest_checkpoint(),
        }
    }

    pub fn merkle_batches(&self) -> Result<Vec<MerkleBatch>> {
        match self {
            Self::Sqlite(storage) => storage.merkle_batches(),
            Self::Postgres(storage) => storage.merkle_batches(),
        }
    }

    pub fn database_size_bytes(&self) -> Result<u64> {
        match self {
            Self::Sqlite(storage) => storage.database_size_bytes(),
            Self::Postgres(storage) => storage.database_size_bytes(),
        }
    }

    pub fn auth_audit_entries(&self) -> Result<Vec<AuthAuditEntry>> {
        match self {
            Self::Sqlite(storage) => storage.auth_audit_entries(),
            Self::Postgres(storage) => storage.auth_audit_entries(),
        }
    }

    pub fn create_human_user(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
    ) -> Result<HumanUserRecord> {
        match self {
            Self::Sqlite(storage) => storage.create_human_user(org_id, email, password),
            Self::Postgres(storage) => storage.create_human_user(org_id, email, password),
        }
    }

    pub fn human_user_record(&self, org_id: &str, email: &str) -> Result<Option<HumanUserRecord>> {
        match self {
            Self::Sqlite(storage) => storage.human_user_record(org_id, email),
            Self::Postgres(storage) => storage.human_user_record(org_id, email),
        }
    }

    pub fn org_mfa_policy(&self, org_id: &str) -> Result<MfaPolicy> {
        match self {
            Self::Sqlite(storage) => storage.org_mfa_policy(org_id),
            Self::Postgres(storage) => storage.org_mfa_policy(org_id),
        }
    }

    pub fn set_org_mfa_policy(&self, org_id: &str, policy: MfaPolicy) -> Result<MfaPolicy> {
        match self {
            Self::Sqlite(storage) => storage.set_org_mfa_policy(org_id, policy),
            Self::Postgres(storage) => storage.set_org_mfa_policy(org_id, policy),
        }
    }

    pub fn start_mfa_enrollment(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
    ) -> Result<MfaEnrollmentStart> {
        match self {
            Self::Sqlite(storage) => storage.start_mfa_enrollment(org_id, email, password),
            Self::Postgres(storage) => storage.start_mfa_enrollment(org_id, email, password),
        }
    }

    pub fn confirm_mfa_enrollment(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
        code: &str,
        as_of: DateTime<Utc>,
    ) -> Result<MfaEnrollmentConfirm> {
        match self {
            Self::Sqlite(storage) => {
                storage.confirm_mfa_enrollment(org_id, email, password, code, as_of)
            }
            Self::Postgres(storage) => {
                storage.confirm_mfa_enrollment(org_id, email, password, code, as_of)
            }
        }
    }

    pub fn create_mfa_challenge(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
        as_of: DateTime<Utc>,
    ) -> Result<MfaChallengeStart> {
        match self {
            Self::Sqlite(storage) => storage.create_mfa_challenge(org_id, email, password, as_of),
            Self::Postgres(storage) => storage.create_mfa_challenge(org_id, email, password, as_of),
        }
    }

    pub fn verify_mfa_challenge(
        &self,
        challenge_id: &str,
        code: &str,
        as_of: DateTime<Utc>,
    ) -> Result<MfaChallengeVerify> {
        match self {
            Self::Sqlite(storage) => storage.verify_mfa_challenge(challenge_id, code, as_of),
            Self::Postgres(storage) => storage.verify_mfa_challenge(challenge_id, code, as_of),
        }
    }

    pub fn create_api_key(&self, org_id: &str, name: &str) -> Result<CreatedApiKey> {
        match self {
            Self::Sqlite(storage) => storage.create_api_key(org_id, name),
            Self::Postgres(storage) => storage.create_api_key(org_id, name),
        }
    }

    pub fn create_api_key_with_roles(
        &self,
        org_id: &str,
        name: &str,
        roles: Option<&[ApiKeyRole]>,
    ) -> Result<CreatedApiKey> {
        match self {
            Self::Sqlite(storage) => storage.create_api_key_with_roles(org_id, name, roles),
            Self::Postgres(storage) => storage.create_api_key_with_roles(org_id, name, roles),
        }
    }

    pub fn list_api_keys(&self) -> Result<Vec<ApiKeyRecord>> {
        match self {
            Self::Sqlite(storage) => storage.list_api_keys(),
            Self::Postgres(storage) => storage.list_api_keys(),
        }
    }

    pub fn list_api_keys_for_org(&self, org_id: &str) -> Result<Vec<ApiKeyRecord>> {
        match self {
            Self::Sqlite(storage) => storage.list_api_keys_for_org(org_id),
            Self::Postgres(storage) => storage.list_api_keys_for_org(org_id),
        }
    }

    pub fn revoke_api_key(&self, key_id: &str) -> Result<bool> {
        match self {
            Self::Sqlite(storage) => storage.revoke_api_key(key_id),
            Self::Postgres(storage) => storage.revoke_api_key(key_id),
        }
    }

    pub fn revoke_api_key_for_org(&self, org_id: &str, key_id: &str) -> Result<bool> {
        match self {
            Self::Sqlite(storage) => storage.revoke_api_key_for_org(org_id, key_id),
            Self::Postgres(storage) => storage.revoke_api_key_for_org(org_id, key_id),
        }
    }

    pub fn authenticate_api_key(&self, raw_key: &str) -> Result<Option<AuthenticatedApiKey>> {
        match self {
            Self::Sqlite(storage) => storage.authenticate_api_key(raw_key),
            Self::Postgres(storage) => storage.authenticate_api_key(raw_key),
        }
    }

    pub fn provision_sso_user(
        &self,
        org_id: &str,
        external_subject: &str,
        email: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        role: &str,
    ) -> Result<UserRecord> {
        match self {
            Self::Sqlite(storage) => storage.provision_sso_user(
                org_id,
                external_subject,
                email,
                first_name,
                last_name,
                role,
            ),
            Self::Postgres(storage) => storage.provision_sso_user(
                org_id,
                external_subject,
                email,
                first_name,
                last_name,
                role,
            ),
        }
    }

    pub fn create_sso_session(&self, user: &UserRecord, ttl: Duration) -> Result<CreatedSession> {
        match self {
            Self::Sqlite(storage) => storage.create_sso_session(user, ttl),
            Self::Postgres(storage) => storage.create_sso_session(user, ttl),
        }
    }

    pub fn authenticate_session(&self, raw_token: &str) -> Result<Option<AuthenticatedSession>> {
        match self {
            Self::Sqlite(storage) => storage.authenticate_session(raw_token),
            Self::Postgres(storage) => storage.authenticate_session(raw_token),
        }
    }

    pub fn create_signed_checkpoint(
        &self,
        signer: &CheckpointSigner,
        anchors: &[ExternalAnchorInput],
    ) -> Result<SignedCheckpoint> {
        match self {
            Self::Sqlite(storage) => storage.create_signed_checkpoint(signer, anchors),
            Self::Postgres(storage) => storage.create_signed_checkpoint(signer, anchors),
        }
    }

    pub fn signed_checkpoints(&self) -> Result<Vec<SignedCheckpoint>> {
        match self {
            Self::Sqlite(storage) => storage.signed_checkpoints(),
            Self::Postgres(storage) => storage.signed_checkpoints(),
        }
    }

    pub fn verify_signed_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> Result<Option<VerifiedCheckpoint>> {
        match self {
            Self::Sqlite(storage) => storage.verify_signed_checkpoint(checkpoint_id),
            Self::Postgres(storage) => storage.verify_signed_checkpoint(checkpoint_id),
        }
    }

    pub fn verify_latest_signed_checkpoint(&self) -> Result<Option<VerifiedCheckpoint>> {
        match self {
            Self::Sqlite(storage) => storage.verify_latest_signed_checkpoint(),
            Self::Postgres(storage) => storage.verify_latest_signed_checkpoint(),
        }
    }

    pub fn verify_chain_for_scope(&self, scope: &StorageScope) -> Result<Vec<IntegrityViolation>> {
        match self {
            Self::Sqlite(storage) => storage.verify_chain_for_scope(scope),
            Self::Postgres(storage) => storage.verify_chain_for_scope(scope),
        }
    }

    pub fn entries_for_scope(&self, scope: &StorageScope) -> Result<Vec<ActionEntry>> {
        match self {
            Self::Sqlite(storage) => storage.entries_for_scope(scope),
            Self::Postgres(storage) => storage.entries_for_scope(scope),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_at_for_tenant(
        &self,
        org_id: &str,
        project_id: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        match self {
            Self::Sqlite(storage) => storage.append_action_at_for_tenant(
                org_id,
                project_id,
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
            ),
            Self::Postgres(storage) => storage.append_action_at_for_tenant(
                org_id,
                project_id,
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_with_dedup_at_for_org_detailed(
        &self,
        org_id: Option<&str>,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<DeduplicationOutcome<ActionEntry>> {
        match self {
            Self::Sqlite(storage) => storage.append_action_with_dedup_at_for_org_detailed(
                org_id,
                dedup_key,
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
            ),
            Self::Postgres(storage) => storage.append_action_with_dedup_at_for_org_detailed(
                org_id,
                dedup_key,
                timestamp,
                agent_id,
                agent_type,
                session_id,
                action_type,
                payload,
                context,
                outcome,
            ),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct ActionLogEnvelope {
    event_kind: Option<String>,
    schema_version: Option<String>,
    trace_id: Option<String>,
    span_id: Option<String>,
    idempotency_key: Option<String>,
    request_metadata: Option<String>,
    result_metadata: Option<String>,
}

#[derive(Debug)]
pub struct SqliteStorage {
    conn: Connection,
}

impl SqliteStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        initialize_schema(&conn)?;
        if !is_immutable_schema(&conn)? {
            chain::initialize_root_anchor(&conn)?;
        }
        if table_exists(&conn, "merkle_batches")? {
            chain::ensure_sqlite_merkle_batches(&conn)?;
        }
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        initialize_schema(&conn)?;
        if !is_immutable_schema(&conn)? {
            chain::initialize_root_anchor(&conn)?;
        }
        if table_exists(&conn, "merkle_batches")? {
            chain::ensure_sqlite_merkle_batches(&conn)?;
        }
        Ok(Self { conn })
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn backend_name(&self) -> &'static str {
        "sqlite"
    }

    pub fn entries(&self) -> Result<Vec<ActionEntry>> {
        self.entries_for_org(None)
    }

    pub fn entries_for_org(&self, org_id: Option<&str>) -> Result<Vec<ActionEntry>> {
        chain::entries_for_org(self, org_id)
    }

    pub fn entries_for_scope(&self, scope: &StorageScope) -> Result<Vec<ActionEntry>> {
        chain::entries_for_scope(self, scope)
    }

    pub fn append_entry(&self, entry: &ActionEntry) -> Result<()> {
        chain::append_entry(self, entry)
    }

    pub fn append_entry_for_org(&self, entry: &ActionEntry, org_id: Option<&str>) -> Result<()> {
        chain::append_entry_for_org(self, entry, org_id)
    }

    fn append_entry_for_org_with_proof(
        &self,
        entry: &ActionEntry,
        org_id: Option<&str>,
    ) -> Result<LedgerProof> {
        chain::append_entry_for_org_with_proof(self, entry, org_id)
    }

    pub fn append_entry_for_tenant(
        &self,
        entry: &ActionEntry,
        org_id: &str,
        project_id: &str,
    ) -> Result<()> {
        chain::append_entry_for_tenant(self, entry, org_id, project_id)
    }

    pub fn append_entry_for_scope(&self, entry: &ActionEntry, scope: &StorageScope) -> Result<()> {
        chain::append_entry_for_scope(self, entry, scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_at(
        &self,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        chain::append_action_at(
            self,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_at_for_org(
        &self,
        org_id: Option<&str>,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        chain::append_action_at_for_org(
            self,
            org_id,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_at_for_tenant(
        &self,
        org_id: &str,
        project_id: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        chain::append_action_at_for_tenant(
            self,
            org_id,
            project_id,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_at_for_scope(
        &self,
        scope: &StorageScope,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        chain::append_action_at_for_scope(
            self,
            scope,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action(
        &self,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        chain::append_action(
            self,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_for_org(
        &self,
        org_id: Option<&str>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        chain::append_action_for_org(
            self,
            org_id,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_for_tenant(
        &self,
        org_id: &str,
        project_id: &str,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        chain::append_action_for_tenant(
            self,
            org_id,
            project_id,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_for_scope(
        &self,
        scope: &StorageScope,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        chain::append_action_for_scope(
            self,
            scope,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_with_dedup_at(
        &self,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<Option<ActionEntry>> {
        chain::append_action_with_dedup_at(
            self,
            dedup_key,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_with_dedup_at_for_org(
        &self,
        org_id: Option<&str>,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<Option<ActionEntry>> {
        chain::append_action_with_dedup_at_for_org(
            self,
            org_id,
            dedup_key,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_with_dedup_at_for_org_detailed(
        &self,
        org_id: Option<&str>,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<DeduplicationOutcome<ActionEntry>> {
        chain::append_action_with_dedup_at_for_org_detailed(
            self,
            org_id,
            dedup_key,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_with_dedup_at_for_tenant(
        &self,
        org_id: &str,
        project_id: &str,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<Option<ActionEntry>> {
        chain::append_action_with_dedup_at_for_tenant(
            self,
            org_id,
            project_id,
            dedup_key,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_action_with_dedup_at_for_scope(
        &self,
        scope: &StorageScope,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<Option<ActionEntry>> {
        chain::append_action_with_dedup_at_for_scope(
            self,
            scope,
            dedup_key,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    pub fn verify_chain(
        &self,
        from_id: Option<Uuid>,
        to_id: Option<Uuid>,
    ) -> Result<Vec<IntegrityViolation>> {
        chain::verify_chain_for_storage(self, from_id, to_id)
    }

    pub fn verify_chain_for_scope(&self, scope: &StorageScope) -> Result<Vec<IntegrityViolation>> {
        chain::verify_chain_for_scope_for_storage(self, scope)
    }

    pub fn create_signed_checkpoint(
        &self,
        signer: &CheckpointSigner,
        anchors: &[ExternalAnchorInput],
    ) -> Result<SignedCheckpoint> {
        chain::create_signed_checkpoint(self, signer, anchors)
    }

    pub fn signed_checkpoints(&self) -> Result<Vec<SignedCheckpoint>> {
        chain::signed_checkpoints(self)
    }

    pub fn signed_checkpoint(&self, checkpoint_id: &str) -> Result<Option<SignedCheckpoint>> {
        chain::signed_checkpoint(self, checkpoint_id)
    }

    pub fn latest_signed_checkpoint(&self) -> Result<Option<SignedCheckpoint>> {
        chain::latest_signed_checkpoint(self)
    }

    pub fn verify_signed_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> Result<Option<VerifiedCheckpoint>> {
        chain::verify_signed_checkpoint_for_storage(self, checkpoint_id)
    }

    pub fn verify_latest_signed_checkpoint(&self) -> Result<Option<VerifiedCheckpoint>> {
        chain::verify_latest_signed_checkpoint(self)
    }

    pub fn merkle_checkpoints(&self) -> Result<Vec<MerkleCheckpoint>> {
        chain::merkle_checkpoints(self)
    }

    pub fn merkle_proof(&self, entry_id: Uuid) -> Result<Option<MerkleInclusionProof>> {
        chain::merkle_proof(self, entry_id)
    }

    pub fn create_checkpoint(&self) -> Result<LedgerCheckpoint> {
        chain::create_checkpoint(self)
    }

    pub fn latest_checkpoint(&self) -> Result<Option<LedgerCheckpoint>> {
        chain::latest_checkpoint(self)
    }

    pub fn merkle_batches(&self) -> Result<Vec<MerkleBatch>> {
        chain::merkle_batches(self)
    }

    pub fn database_size_bytes(&self) -> Result<u64> {
        let page_count = self
            .conn
            .query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))?;
        let page_size = self
            .conn
            .query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))?;

        Ok((page_count.max(0) as u64).saturating_mul(page_size.max(0) as u64))
    }

    pub fn auth_audit_entries(&self) -> Result<Vec<AuthAuditEntry>> {
        auth::auth_audit_entries(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_auth_audit_event_at(
        &self,
        timestamp: DateTime<Utc>,
        event_type: AuthAuditEventType,
        org_id: Option<&str>,
        actor_type: impl Into<String>,
        actor_id: Option<&str>,
        subject_type: impl Into<String>,
        subject_id: impl Into<String>,
        payload: Value,
        outcome: impl Into<String>,
    ) -> Result<AuthAuditEntry> {
        auth::append_auth_audit_event_at(
            self,
            timestamp,
            event_type,
            org_id,
            actor_type,
            actor_id,
            subject_type,
            subject_id,
            payload,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_auth_audit_event(
        &self,
        event_type: AuthAuditEventType,
        org_id: Option<&str>,
        actor_type: impl Into<String>,
        actor_id: Option<&str>,
        subject_type: impl Into<String>,
        subject_id: impl Into<String>,
        payload: Value,
        outcome: impl Into<String>,
    ) -> Result<AuthAuditEntry> {
        auth::append_auth_audit_event(
            self,
            event_type,
            org_id,
            actor_type,
            actor_id,
            subject_type,
            subject_id,
            payload,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_role_change(
        &self,
        org_id: Option<&str>,
        actor_type: &str,
        actor_id: Option<&str>,
        subject_type: &str,
        subject_id: &str,
        previous_role: Option<&str>,
        new_role: &str,
    ) -> Result<AuthAuditEntry> {
        auth::record_role_change(
            self,
            org_id,
            actor_type,
            actor_id,
            subject_type,
            subject_id,
            previous_role,
            new_role,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_permission_grant(
        &self,
        org_id: Option<&str>,
        actor_type: &str,
        actor_id: Option<&str>,
        subject_type: &str,
        subject_id: &str,
        permission: &str,
        scope: Option<&str>,
    ) -> Result<AuthAuditEntry> {
        auth::record_permission_grant(
            self,
            org_id,
            actor_type,
            actor_id,
            subject_type,
            subject_id,
            permission,
            scope,
        )
    }

    pub fn create_human_user(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
    ) -> Result<HumanUserRecord> {
        auth::create_human_user(self, org_id, email, password)
    }

    pub fn human_user_record(&self, org_id: &str, email: &str) -> Result<Option<HumanUserRecord>> {
        auth::load_human_user_record(self, org_id, email)
    }

    pub fn org_mfa_policy(&self, org_id: &str) -> Result<MfaPolicy> {
        auth::org_mfa_policy(self, org_id)
    }

    pub fn set_org_mfa_policy(&self, org_id: &str, policy: MfaPolicy) -> Result<MfaPolicy> {
        auth::set_org_mfa_policy(self, org_id, policy)
    }

    pub fn start_mfa_enrollment(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
    ) -> Result<MfaEnrollmentStart> {
        auth::start_mfa_enrollment(self, org_id, email, password)
    }

    pub fn confirm_mfa_enrollment(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
        code: &str,
        as_of: DateTime<Utc>,
    ) -> Result<MfaEnrollmentConfirm> {
        auth::confirm_mfa_enrollment(self, org_id, email, password, code, as_of)
    }

    pub fn create_mfa_challenge(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
        as_of: DateTime<Utc>,
    ) -> Result<MfaChallengeStart> {
        auth::create_mfa_challenge(self, org_id, email, password, as_of)
    }

    pub fn verify_mfa_challenge(
        &self,
        challenge_id: &str,
        code: &str,
        as_of: DateTime<Utc>,
    ) -> Result<MfaChallengeVerify> {
        auth::verify_mfa_challenge(self, challenge_id, code, as_of)
    }

    pub fn create_credential(&self, request: CreateCredentialRequest) -> Result<CreatedCredential> {
        auth::create_credential(self, request)
    }

    pub fn create_api_key(&self, org_id: &str, name: &str) -> Result<CreatedApiKey> {
        auth::create_api_key(self, org_id, name)
    }

    pub fn create_api_key_with_roles(
        &self,
        org_id: &str,
        name: &str,
        roles: Option<&[ApiKeyRole]>,
    ) -> Result<CreatedApiKey> {
        auth::create_api_key_with_roles(self, org_id, name, roles)
    }

    pub fn create_service_account(&self, org_id: &str, name: &str) -> Result<CreatedCredential> {
        auth::create_service_account(self, org_id, name)
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
        auth::list_credentials(self)
    }

    pub fn list_api_keys(&self) -> Result<Vec<ApiKeyRecord>> {
        auth::list_api_keys(self)
    }

    pub fn list_api_keys_for_org(&self, org_id: &str) -> Result<Vec<ApiKeyRecord>> {
        auth::list_api_keys_for_org(self, org_id)
    }

    pub fn list_service_accounts(&self) -> Result<Vec<CredentialRecord>> {
        auth::list_service_accounts(self)
    }

    pub fn revoke_credential(&self, credential_id: &str, reason: Option<&str>) -> Result<bool> {
        auth::revoke_credential(self, credential_id, reason)
    }

    pub fn revoke_api_key(&self, key_id: &str) -> Result<bool> {
        auth::revoke_api_key(self, key_id)
    }

    pub fn revoke_api_key_for_org(&self, org_id: &str, key_id: &str) -> Result<bool> {
        auth::revoke_api_key_for_org(self, org_id, key_id)
    }

    pub fn authenticate_credential(
        &self,
        raw_key: &str,
    ) -> Result<Option<AuthenticatedCredential>> {
        auth::authenticate_credential(self, raw_key)
    }

    pub fn authenticate_api_key(&self, raw_key: &str) -> Result<Option<AuthenticatedApiKey>> {
        auth::authenticate_api_key(self, raw_key)
    }

    pub fn provision_sso_user(
        &self,
        org_id: &str,
        external_subject: &str,
        email: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        role: &str,
    ) -> Result<UserRecord> {
        auth::provision_sso_user(
            self,
            org_id,
            external_subject,
            email,
            first_name,
            last_name,
            role,
        )
    }

    pub fn create_sso_session(&self, user: &UserRecord, ttl: Duration) -> Result<CreatedSession> {
        auth::create_sso_session(self, user, ttl)
    }

    pub fn authenticate_session(&self, raw_token: &str) -> Result<Option<AuthenticatedSession>> {
        auth::authenticate_session(self, raw_token)
    }

    pub fn create_user(&self, email: &str, display_name: Option<&str>) -> Result<PrincipalUser> {
        auth::create_user(self, email, display_name)
    }

    pub fn get_user(&self, user_id: &str) -> Result<Option<PrincipalUser>> {
        auth::get_user(self, user_id)
    }

    pub fn list_users(&self) -> Result<Vec<PrincipalUser>> {
        auth::list_users(self)
    }

    pub fn update_user(
        &self,
        user_id: &str,
        email: &str,
        display_name: Option<&str>,
    ) -> Result<Option<PrincipalUser>> {
        auth::update_user(self, user_id, email, display_name)
    }

    pub fn delete_user(&self, user_id: &str) -> Result<bool> {
        auth::delete_user(self, user_id)
    }

    pub fn create_org_membership(
        &self,
        org_id: &str,
        user_id: &str,
        role: PrincipalRole,
    ) -> Result<OrgMembership> {
        auth::create_org_membership(self, org_id, user_id, role)
    }

    pub fn get_org_membership(&self, org_id: &str, user_id: &str) -> Result<Option<OrgMembership>> {
        auth::get_org_membership(self, org_id, user_id)
    }

    pub fn list_org_memberships(&self, org_id: Option<&str>) -> Result<Vec<OrgMembership>> {
        auth::list_org_memberships(self, org_id)
    }

    pub fn update_org_membership(
        &self,
        org_id: &str,
        user_id: &str,
        role: PrincipalRole,
    ) -> Result<Option<OrgMembership>> {
        auth::update_org_membership(self, org_id, user_id, role)
    }

    pub fn delete_org_membership(&self, org_id: &str, user_id: &str) -> Result<bool> {
        auth::delete_org_membership(self, org_id, user_id)
    }
}

impl CoreLedgerBackend for SqliteStorage {
    fn append(&self, entry: LedgerEntry) -> Result<LedgerProof> {
        self.append_entry_for_org_with_proof(&entry, None)
    }

    fn verify_chain(&self, range: Option<Range>) -> Result<ChainIntegrity> {
        let (from_id, to_id) = chain::parse_range_bounds(range.as_ref())?;
        let violations = SqliteStorage::verify_chain(self, from_id, to_id)?;

        Ok(ChainIntegrity { range, violations })
    }

    fn get_entry(&self, id: &str) -> Result<Option<LedgerEntry>> {
        chain::load_entry_by_id(&self.conn, id)
            .map(|entry| entry.map(|stored_entry| stored_entry.entry))
    }

    fn get_entries(&self, filter: LedgerFilter) -> Result<Vec<LedgerEntry>> {
        chain::load_entries_with_filter(&self.conn, &filter).map(|entries| {
            entries
                .into_iter()
                .map(|stored_entry| stored_entry.entry)
                .collect()
        })
    }
}

impl LedgerBackend for SqliteStorage {
    fn backend_name(&self) -> &'static str {
        self.backend_name()
    }

    fn entries(&self) -> Result<Vec<ActionEntry>> {
        self.entries()
    }

    fn entries_for_org(&self, org_id: Option<&str>) -> Result<Vec<ActionEntry>> {
        self.entries_for_org(org_id)
    }

    fn append_entry(&self, entry: &ActionEntry) -> Result<()> {
        self.append_entry(entry)
    }

    fn append_entry_for_org(&self, entry: &ActionEntry, org_id: Option<&str>) -> Result<()> {
        self.append_entry_for_org(entry, org_id)
    }

    fn append_action_at(
        &self,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        self.append_action_at(
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    fn append_action_at_for_org(
        &self,
        org_id: Option<&str>,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        self.append_action_at_for_org(
            org_id,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    fn append_action(
        &self,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        self.append_action(
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    fn append_action_for_org(
        &self,
        org_id: Option<&str>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<ActionEntry> {
        self.append_action_for_org(
            org_id,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    fn append_action_with_dedup_at(
        &self,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<Option<ActionEntry>> {
        self.append_action_with_dedup_at(
            dedup_key,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    fn append_action_with_dedup_at_for_org(
        &self,
        org_id: Option<&str>,
        dedup_key: &str,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
    ) -> Result<Option<ActionEntry>> {
        self.append_action_with_dedup_at_for_org(
            org_id,
            dedup_key,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
        )
    }

    fn verify_chain(
        &self,
        from_id: Option<Uuid>,
        to_id: Option<Uuid>,
    ) -> Result<Vec<IntegrityViolation>> {
        self.verify_chain(from_id, to_id)
    }

    fn create_checkpoint(&self) -> Result<LedgerCheckpoint> {
        self.create_checkpoint()
    }

    fn latest_checkpoint(&self) -> Result<Option<LedgerCheckpoint>> {
        self.latest_checkpoint()
    }

    fn merkle_batches(&self) -> Result<Vec<MerkleBatch>> {
        self.merkle_batches()
    }

    fn purge_expired(&self, as_of: DateTime<Utc>) -> Result<usize> {
        self.purge_expired(as_of)
    }

    fn control_settings(&self) -> Result<StorageControl> {
        self.control_settings()
    }

    fn database_size_bytes(&self) -> Result<u64> {
        self.database_size_bytes()
    }

    fn create_api_key(&self, org_id: &str, name: &str) -> Result<CreatedApiKey> {
        self.create_api_key(org_id, name)
    }

    fn list_api_keys(&self) -> Result<Vec<ApiKeyRecord>> {
        self.list_api_keys()
    }

    fn list_api_keys_for_org(&self, org_id: &str) -> Result<Vec<ApiKeyRecord>> {
        self.list_api_keys_for_org(org_id)
    }

    fn revoke_api_key(&self, key_id: &str) -> Result<bool> {
        self.revoke_api_key(key_id)
    }

    fn revoke_api_key_for_org(&self, org_id: &str, key_id: &str) -> Result<bool> {
        self.revoke_api_key_for_org(org_id, key_id)
    }

    fn authenticate_api_key(&self, raw_key: &str) -> Result<Option<AuthenticatedApiKey>> {
        self.authenticate_api_key(raw_key)
    }
}

pub fn initialize_schema(conn: &Connection) -> Result<()> {
    let user_version = schema_user_version(conn).unwrap_or(0);
    let has_organizations = table_exists(conn, "organizations")?;
    let has_credentials = table_exists(conn, "credentials")?;
    let has_api_keys = table_exists(conn, "api_keys")?;

    if !has_organizations && user_version >= SCHEMA_VERSION_IMMUTABLE_LEDGER {
        initialize_immutable_schema(conn)?;
        set_schema_user_version(conn, SCHEMA_VERSION_IMMUTABLE_LEDGER)?;
        return Ok(());
    }

    if !has_organizations
        && (user_version == SCHEMA_VERSION_LEGACY || (has_api_keys && !has_credentials))
    {
        initialize_legacy_schema(conn)?;
        set_schema_user_version(conn, SCHEMA_VERSION_LEGACY)?;
        return Ok(());
    }

    tenant::initialize_schema(conn)?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS action_log (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            agent_type TEXT NOT NULL,
            session_id TEXT NOT NULL,
            trace_id TEXT,
            span_id TEXT,
            action_type TEXT NOT NULL,
            event_kind TEXT,
            schema_version TEXT,
            payload TEXT NOT NULL,
            context TEXT NOT NULL,
            outcome TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
            idempotency_key TEXT,
            request_metadata TEXT,
            result_metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            key_hash TEXT NOT NULL,
            org_id TEXT NOT NULL,
            project_id TEXT,
            name TEXT NOT NULL,
            credential_type TEXT NOT NULL DEFAULT 'api_key',
            created_at TEXT NOT NULL,
            created_by TEXT,
            expires_at TEXT,
            last_used_at TEXT,
            previous_key_id TEXT,
            revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
            revoked_at TEXT,
            revocation_reason TEXT,
            roles TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            admin_key_id TEXT
        );

        CREATE TABLE IF NOT EXISTS org_settings (
            org_id TEXT PRIMARY KEY,
            retention_policy TEXT NOT NULL,
            enabled_frameworks TEXT NOT NULL,
            guardrail_settings TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            display_name TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS org_memberships (
            org_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK (
                role IN (
                    'admin',
                    'compliance_officer',
                    'developer',
                    'auditor',
                    'read_only'
                )
            ),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (org_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS chain_integrity_checks (
            check_id TEXT PRIMARY KEY,
            checked_at TEXT NOT NULL,
            from_entry_id TEXT,
            to_entry_id TEXT,
            violation_count INTEGER NOT NULL,
            details TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ledger_checkpoints (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            checkpoint_id TEXT NOT NULL UNIQUE,
            checkpointed_at TEXT NOT NULL,
            start_sequence INTEGER NOT NULL,
            end_sequence INTEGER NOT NULL UNIQUE,
            entry_count INTEGER NOT NULL,
            last_entry_id TEXT NOT NULL,
            last_entry_hash TEXT NOT NULL,
            previous_checkpoint_hash TEXT NOT NULL,
            checkpoint_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS checkpoint_signing_keys (
            key_id TEXT PRIMARY KEY,
            algorithm TEXT NOT NULL,
            public_key TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            label TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS checkpoints (
            checkpoint_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            entry_id TEXT NOT NULL,
            ledger_root_hash TEXT NOT NULL,
            checkpoint_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            key_id TEXT NOT NULL,
            FOREIGN KEY (key_id) REFERENCES checkpoint_signing_keys(key_id)
        );

        CREATE TABLE IF NOT EXISTS checkpoint_anchors (
            anchor_id TEXT PRIMARY KEY,
            checkpoint_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            reference TEXT NOT NULL,
            anchored_at TEXT NOT NULL,
            anchored_hash TEXT NOT NULL,
            metadata TEXT NOT NULL,
            FOREIGN KEY (checkpoint_id) REFERENCES checkpoints(checkpoint_id)
        );

        CREATE TABLE IF NOT EXISTS merkle_checkpoints (
            batch_index INTEGER PRIMARY KEY,
            start_sequence INTEGER NOT NULL,
            end_sequence INTEGER NOT NULL,
            start_entry_id TEXT NOT NULL,
            end_entry_id TEXT NOT NULL,
            entry_count INTEGER NOT NULL,
            merkle_root TEXT NOT NULL,
            checkpointed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS merkle_batches (
            batch_id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_sequence INTEGER NOT NULL UNIQUE,
            end_sequence INTEGER NOT NULL UNIQUE,
            leaf_count INTEGER NOT NULL,
            root_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS storage_control (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            allow_purge INTEGER NOT NULL DEFAULT 0 CHECK (allow_purge IN (0, 1)),
            min_retention_days INTEGER NOT NULL DEFAULT 0,
            purge_through_sequence INTEGER
        );

        CREATE TABLE IF NOT EXISTS org_retention_policies (
            org_id TEXT PRIMARY KEY,
            min_retention_days INTEGER NOT NULL CHECK (min_retention_days >= 0),
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS legal_holds (
            id TEXT PRIMARY KEY,
            org_id TEXT,
            matter TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL,
            released_at TEXT,
            release_reason TEXT
        );

        CREATE TABLE IF NOT EXISTS legal_hold_events (
            id TEXT PRIMARY KEY,
            hold_id TEXT NOT NULL,
            org_id TEXT,
            event_type TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            detail TEXT NOT NULL,
            FOREIGN KEY (hold_id) REFERENCES legal_holds(id)
        );

        CREATE TABLE IF NOT EXISTS purge_events (
            id TEXT PRIMARY KEY,
            purged_at TEXT NOT NULL,
            as_of TEXT NOT NULL,
            deleted_rows INTEGER NOT NULL,
            through_sequence INTEGER NOT NULL,
            through_entry_hash TEXT NOT NULL,
            resume_previous_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS ingest_dedup (
            dedup_key TEXT PRIMARY KEY,
            entry_id TEXT,
            recorded_at TEXT NOT NULL
        );

        INSERT OR IGNORE INTO storage_control (
            id,
            allow_purge,
            min_retention_days,
            purge_through_sequence
        )
        VALUES (1, 0, 0, NULL);

        INSERT OR IGNORE INTO app_settings (id, admin_key_id)
        VALUES (1, NULL);

        CREATE INDEX IF NOT EXISTS idx_credentials_org_id
        ON credentials (org_id);

        CREATE INDEX IF NOT EXISTS idx_credentials_project_id
        ON credentials (project_id);

        CREATE INDEX IF NOT EXISTS idx_credentials_previous_key_id
        ON credentials (previous_key_id);

        CREATE INDEX IF NOT EXISTS idx_ledger_checkpoints_end_sequence
        ON ledger_checkpoints (end_sequence);

        CREATE INDEX IF NOT EXISTS idx_legal_holds_org_id
        ON legal_holds (org_id);

        CREATE INDEX IF NOT EXISTS idx_legal_holds_released_at
        ON legal_holds (released_at);

        CREATE INDEX IF NOT EXISTS idx_legal_hold_events_hold_id
        ON legal_hold_events (hold_id, occurred_at);

        CREATE INDEX IF NOT EXISTS idx_org_retention_policies_updated_at
        ON org_retention_policies (updated_at);

        CREATE INDEX IF NOT EXISTS idx_users_email
        ON users (email);

        CREATE INDEX IF NOT EXISTS idx_org_memberships_user_id
        ON org_memberships (user_id);

        CREATE INDEX IF NOT EXISTS idx_org_memberships_role
        ON org_memberships (role);

        CREATE INDEX IF NOT EXISTS idx_checkpoints_created_at
        ON checkpoints (created_at DESC, checkpoint_id DESC);

        CREATE INDEX IF NOT EXISTS idx_checkpoint_anchors_checkpoint_id
        ON checkpoint_anchors (checkpoint_id);

        CREATE INDEX IF NOT EXISTS idx_merkle_batches_range
        ON merkle_batches (start_sequence, end_sequence);
        CREATE TRIGGER IF NOT EXISTS action_log_reject_update
        BEFORE UPDATE ON action_log
        BEGIN
            SELECT RAISE(ABORT, 'action_log is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS action_log_reject_delete
        BEFORE DELETE ON action_log
        WHEN COALESCE((SELECT allow_purge FROM storage_control WHERE id = 1), 0) = 0
        BEGIN
            SELECT RAISE(ABORT, 'action_log deletes are blocked');
        END;

        CREATE TRIGGER IF NOT EXISTS chain_integrity_checks_reject_update
        BEFORE UPDATE ON chain_integrity_checks
        BEGIN
            SELECT RAISE(ABORT, 'chain_integrity_checks is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS chain_integrity_checks_reject_delete
        BEFORE DELETE ON chain_integrity_checks
        BEGIN
            SELECT RAISE(ABORT, 'chain_integrity_checks is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS ledger_checkpoints_reject_update
        BEFORE UPDATE ON ledger_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'ledger_checkpoints is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS ledger_checkpoints_reject_delete
        BEFORE DELETE ON ledger_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'ledger_checkpoints is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS merkle_batches_reject_update
        BEFORE UPDATE ON merkle_batches
        BEGIN
            SELECT RAISE(ABORT, 'merkle_batches is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS merkle_batches_reject_delete
        BEFORE DELETE ON merkle_batches
        BEGIN
            SELECT RAISE(ABORT, 'merkle_batches is append-only');
        END;
        ",
    )?;

    tenant::migrate_action_log_schema(conn)?;
    ensure_action_log_columns(conn)?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_action_log_org_id ON action_log (org_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_action_log_project_id ON action_log (project_id)",
        [],
    )?;

    conn.execute_batch(
        "
        DROP TRIGGER IF EXISTS action_log_reject_delete;

        CREATE TRIGGER IF NOT EXISTS action_log_reject_delete
        BEFORE DELETE ON action_log
        BEGIN
            SELECT RAISE(ABORT, 'action_log is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS ledger_checkpoints_reject_update
        BEFORE UPDATE ON ledger_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'ledger_checkpoints are append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS ledger_checkpoints_reject_delete
        BEFORE DELETE ON ledger_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'ledger_checkpoints are append-only');
        END;
        ",
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_action_log_scope ON action_log (org_id, project_id, sequence)",
        [],
    )?;
    ensure_storage_control_columns(conn)?;
    recreate_action_log_delete_trigger(conn)?;
    auth::ensure_users_table(conn)?;
    auth::ensure_org_memberships_table(conn)?;
    auth::ensure_credentials_columns(conn)?;
    auth::migrate_api_keys_to_credentials(conn)?;
    chain::rebuild_merkle_checkpoints(conn)?;

    Ok(())
}

fn initialize_legacy_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS action_log (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            agent_type TEXT NOT NULL,
            session_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            context TEXT NOT NULL,
            outcome TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            org_id TEXT
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            key_hash TEXT NOT NULL,
            org_id TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
        );

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

        CREATE TABLE IF NOT EXISTS app_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            admin_key_id TEXT
        );

        CREATE TABLE IF NOT EXISTS chain_integrity_checks (
            check_id TEXT PRIMARY KEY,
            checked_at TEXT NOT NULL,
            from_entry_id TEXT,
            to_entry_id TEXT,
            violation_count INTEGER NOT NULL,
            details TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS storage_control (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            allow_purge INTEGER NOT NULL DEFAULT 0 CHECK (allow_purge IN (0, 1)),
            min_retention_days INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS ingest_dedup (
            dedup_key TEXT PRIMARY KEY,
            entry_id TEXT,
            recorded_at TEXT NOT NULL
        );

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

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            external_subject TEXT NOT NULL,
            email TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login_at TEXT NOT NULL,
            UNIQUE(org_id, external_subject),
            UNIQUE(org_id, email)
        );

        CREATE TABLE IF NOT EXISTS auth_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT NOT NULL,
            session_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_used_at TEXT
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

        INSERT OR IGNORE INTO storage_control (id, allow_purge, min_retention_days)
        VALUES (1, 0, 0);

        INSERT OR IGNORE INTO app_settings (id, admin_key_id)
        VALUES (1, NULL);

        CREATE INDEX IF NOT EXISTS idx_api_keys_org_id
        ON api_keys (org_id);

        CREATE INDEX IF NOT EXISTS idx_auth_audit_log_org_id
        ON auth_audit_log (org_id);

        CREATE INDEX IF NOT EXISTS idx_auth_audit_log_event_type
        ON auth_audit_log (event_type);

        CREATE INDEX IF NOT EXISTS idx_users_org_id
        ON users (org_id);

        CREATE INDEX IF NOT EXISTS idx_users_subject
        ON users (org_id, external_subject);

        CREATE INDEX IF NOT EXISTS idx_auth_sessions_org_id
        ON auth_sessions (org_id);

        CREATE INDEX IF NOT EXISTS idx_human_users_org_id
        ON human_users (org_id);

        CREATE UNIQUE INDEX IF NOT EXISTS idx_human_users_org_email
        ON human_users (org_id, email);

        CREATE INDEX IF NOT EXISTS idx_auth_challenges_user_id
        ON auth_challenges (user_id);

        CREATE INDEX IF NOT EXISTS idx_human_recovery_codes_user_id
        ON human_recovery_codes (user_id);

        CREATE TRIGGER IF NOT EXISTS action_log_reject_update
        BEFORE UPDATE ON action_log
        BEGIN
            SELECT RAISE(ABORT, 'action_log is append-only');
        END;
        ",
    )?;

    conn.execute_batch(
        "
        DROP TRIGGER IF EXISTS ledger_checkpoints_reject_update;
        DROP TRIGGER IF EXISTS ledger_checkpoints_reject_delete;
        DROP TRIGGER IF EXISTS action_log_reject_delete;

        CREATE TRIGGER IF NOT EXISTS action_log_reject_delete
        BEFORE DELETE ON action_log
        WHEN COALESCE((SELECT allow_purge FROM storage_control WHERE id = 1), 0) = 0
        BEGIN
            SELECT RAISE(ABORT, 'action_log deletes are blocked');
        END;

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
    )?;

    ensure_action_log_org_column(conn)?;
    ensure_storage_control_columns(conn)?;

    Ok(())
}

fn initialize_immutable_schema(conn: &Connection) -> Result<()> {
    initialize_legacy_schema(conn)?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS ledger_checkpoints (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            checkpoint_id TEXT NOT NULL UNIQUE,
            checkpointed_at TEXT NOT NULL,
            start_sequence INTEGER NOT NULL,
            end_sequence INTEGER NOT NULL UNIQUE,
            entry_count INTEGER NOT NULL,
            last_entry_id TEXT NOT NULL,
            last_entry_hash TEXT NOT NULL,
            previous_checkpoint_hash TEXT NOT NULL,
            checkpoint_hash TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_ledger_checkpoints_end_sequence
        ON ledger_checkpoints (end_sequence);
        ",
    )?;

    conn.execute_batch(
        "
        DROP TRIGGER IF EXISTS action_log_reject_delete;

        CREATE TRIGGER IF NOT EXISTS action_log_reject_delete
        BEFORE DELETE ON action_log
        BEGIN
            SELECT RAISE(ABORT, 'action_log is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS ledger_checkpoints_reject_update
        BEFORE UPDATE ON ledger_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'ledger_checkpoints are append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS ledger_checkpoints_reject_delete
        BEFORE DELETE ON ledger_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'ledger_checkpoints are append-only');
        END;
        ",
    )?;

    Ok(())
}

fn schema_user_version(conn: &Connection) -> Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StorageError::from)
}

fn set_schema_user_version(conn: &Connection, version: i64) -> Result<()> {
    conn.execute_batch(&format!("PRAGMA user_version = {version}"))?;
    Ok(())
}

fn is_immutable_schema(conn: &Connection) -> Result<bool> {
    Ok(
        schema_user_version(conn).unwrap_or(0) >= SCHEMA_VERSION_IMMUTABLE_LEDGER
            && !table_exists(conn, "organizations")?,
    )
}

fn ensure_action_log_columns(conn: &Connection) -> Result<()> {
    ensure_action_log_column(conn, "org_id", "TEXT")?;
    ensure_action_log_column(conn, "event_kind", "TEXT")?;
    ensure_action_log_column(conn, "schema_version", "TEXT")?;
    ensure_action_log_column(conn, "trace_id", "TEXT")?;
    ensure_action_log_column(conn, "span_id", "TEXT")?;
    ensure_action_log_column(conn, "idempotency_key", "TEXT")?;
    ensure_action_log_column(conn, "request_metadata", "TEXT")?;
    ensure_action_log_column(conn, "result_metadata", "TEXT")?;
    Ok(())
}

fn ensure_action_log_column(conn: &Connection, column_name: &str, definition: &str) -> Result<()> {
    if !table_has_column(conn, "action_log", column_name)? {
        conn.execute(
            &format!("ALTER TABLE action_log ADD COLUMN {column_name} {definition}"),
            [],
        )?;
    }

    Ok(())
}

fn ensure_action_log_org_column(conn: &Connection) -> Result<()> {
    ensure_action_log_column(conn, "org_id", "TEXT")
}

fn ensure_storage_control_columns(conn: &Connection) -> Result<()> {
    if !table_has_column(conn, "storage_control", "allow_purge")? {
        conn.execute(
            "ALTER TABLE storage_control ADD COLUMN allow_purge INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }

    if !table_has_column(conn, "storage_control", "min_retention_days")? {
        conn.execute(
            "ALTER TABLE storage_control ADD COLUMN min_retention_days INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }

    if !table_has_column(conn, "storage_control", "purge_through_sequence")? {
        conn.execute(
            "ALTER TABLE storage_control ADD COLUMN purge_through_sequence INTEGER",
            [],
        )?;
    }

    Ok(())
}

fn recreate_action_log_delete_trigger(conn: &Connection) -> Result<()> {
    conn.execute("DROP TRIGGER IF EXISTS action_log_reject_delete", [])?;
    conn.execute_batch(
        "
        CREATE TRIGGER action_log_reject_delete
        BEFORE DELETE ON action_log
        WHEN COALESCE((SELECT allow_purge FROM storage_control WHERE id = 1), 0) = 0
          OR COALESCE(
                (SELECT purge_through_sequence FROM storage_control WHERE id = 1),
                -1
             ) < OLD.sequence
        BEGIN
            SELECT RAISE(ABORT, 'action_log deletes are blocked');
        END;
        ",
    )?;
    Ok(())
}

fn resolve_tenant_context(conn: &Connection, org_id: Option<&str>) -> Result<TenantContext> {
    match org_id.map(str::trim) {
        Some(org_id) if !org_id.is_empty() => {
            tenant::ensure_organization_id(conn, org_id)?;
            let project = tenant::ensure_default_project_for_org(conn, org_id)?;
            Ok(TenantContext {
                org_id: org_id.to_string(),
                project_id: project.id,
            })
        }
        _ => tenant::ensure_default_catalog(conn).map_err(StorageError::from),
    }
}

fn table_has_column(conn: &Connection, table_name: &str, column_name: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table_name})"))?;
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column_name {
            return Ok(true);
        }
    }

    Ok(false)
}

fn table_exists(conn: &Connection, table_name: &str) -> Result<bool> {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1",
        params![table_name],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map(|value| value.is_some())
    .map_err(StorageError::from)
}

fn current_time() -> DateTime<Utc> {
    std::time::SystemTime::now().into()
}

fn looks_like_postgres_dsn(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value.starts_with("postgres://") || value.starts_with("postgresql://")
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use rusqlite::Connection;
    use serde_json::json;
    use uuid::Uuid;

    use super::{
        IntegrityViolation, PrincipalRole, SqliteStorage, initialize_schema, verify_chain,
    };
    use crate::ledger::hashing::HashSpec;
    use crate::log::{ActionEntry, ActionType, GENESIS_HASH};

    fn fixed_timestamp() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 30, 12, 0, 0).unwrap()
    }

    fn legacy_entry(previous_hash: &str, id: &str) -> ActionEntry {
        let mut entry = ActionEntry {
            id: Uuid::parse_str(id).unwrap(),
            timestamp: fixed_timestamp(),
            agent_id: "agent".to_string(),
            agent_type: "orchestrator".to_string(),
            session_id: "session-1".to_string(),
            action_type: ActionType::Decision,
            payload: json!({"message":"legacy"}),
            context: json!({"scope":"audit"}),
            outcome: "ok".to_string(),
            previous_hash: previous_hash.to_string(),
            entry_hash: String::new(),
        };
        entry.entry_hash = HashSpec::legacy_v0().compute_entry_hash(&entry);
        entry
    }

    fn assert_no_hashing_violations(violations: &[IntegrityViolation]) {
        assert!(
            violations.iter().all(|violation| violation
                .reason
                .starts_with("missing merkle checkpoint for batch ")),
            "unexpected integrity violations: {violations:?}"
        );
    }

    #[test]
    fn verify_chain_accepts_legacy_entries_after_versioned_hashing_change() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let first = legacy_entry(GENESIS_HASH, "11111111-1111-4111-8111-111111111111");
        storage.append_entry(&first).unwrap();

        let second = legacy_entry(&first.entry_hash, "22222222-2222-4222-8222-222222222222");
        storage.append_entry(&second).unwrap();

        let violations = storage.verify_chain(None, None).unwrap();
        assert_no_hashing_violations(&violations);
    }

    #[test]
    fn verify_chain_accepts_legacy_to_versioned_upgrade_boundary() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let first = legacy_entry(GENESIS_HASH, "33333333-3333-4333-8333-333333333333");
        storage.append_entry(&first).unwrap();

        storage
            .append_action_at(
                fixed_timestamp(),
                "agent",
                "orchestrator",
                "session-2",
                ActionType::ToolCall,
                json!({"step":"upgrade"}),
                json!({"path":"mixed-chain"}),
                "ok",
            )
            .unwrap();

        let violations = verify_chain(storage.connection(), None, None).unwrap();
        assert_no_hashing_violations(&violations);
    }

    #[test]
    fn initialize_schema_creates_principal_tables() {
        let conn = Connection::open_in_memory().expect("in-memory connection");
        initialize_schema(&conn).expect("initialize schema");

        let users_exists: String = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'",
                [],
                |row| row.get(0),
            )
            .expect("users table exists");
        let memberships_exists: String = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'org_memberships'",
                [],
                |row| row.get(0),
            )
            .expect("org memberships table exists");

        assert_eq!(users_exists, "users");
        assert_eq!(memberships_exists, "org_memberships");
    }

    #[test]
    fn user_crud_round_trips() {
        let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
        let created = storage
            .create_user("alice@example.com", Some(" Alice Admin "))
            .expect("create user");

        assert_eq!(created.email, "alice@example.com");
        assert_eq!(created.display_name.as_deref(), Some("Alice Admin"));

        let loaded = storage
            .get_user(&created.id)
            .expect("load user")
            .expect("user exists");
        assert_eq!(loaded, created);

        let listed = storage.list_users().expect("list users");
        assert_eq!(listed, vec![created.clone()]);

        let updated = storage
            .update_user(
                &created.id,
                "alice+updated@example.com",
                Some("Alice Updated"),
            )
            .expect("update user")
            .expect("updated user exists");
        assert_eq!(updated.email, "alice+updated@example.com");
        assert_eq!(updated.display_name.as_deref(), Some("Alice Updated"));
        assert!(updated.updated_at >= created.updated_at);

        assert!(storage.delete_user(&created.id).expect("delete user"));
        assert!(
            storage
                .get_user(&created.id)
                .expect("reload user")
                .is_none()
        );
        assert!(
            !storage
                .delete_user(&created.id)
                .expect("delete missing user")
        );
    }

    #[test]
    fn org_membership_crud_round_trips() {
        let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
        let user = storage
            .create_user("auditor@example.com", Some("Audit User"))
            .expect("create user");

        let created = storage
            .create_org_membership("org-123", &user.id, PrincipalRole::Auditor)
            .expect("create membership");
        assert_eq!(created.org_id, "org-123");
        assert_eq!(created.user_id, user.id);
        assert_eq!(created.role, PrincipalRole::Auditor);

        let loaded = storage
            .get_org_membership("org-123", &user.id)
            .expect("load membership")
            .expect("membership exists");
        assert_eq!(loaded, created);

        let listed = storage
            .list_org_memberships(Some("org-123"))
            .expect("list memberships");
        assert_eq!(listed, vec![created.clone()]);

        let updated = storage
            .update_org_membership("org-123", &user.id, PrincipalRole::ComplianceOfficer)
            .expect("update membership")
            .expect("updated membership");
        assert_eq!(updated.role, PrincipalRole::ComplianceOfficer);
        assert!(updated.updated_at >= created.updated_at);

        assert!(
            storage
                .delete_org_membership("org-123", &user.id)
                .expect("delete membership")
        );
        assert!(
            storage
                .get_org_membership("org-123", &user.id)
                .expect("reload membership")
                .is_none()
        );
        assert!(
            !storage
                .delete_org_membership("org-123", &user.id)
                .expect("delete missing membership")
        );
    }

    #[test]
    fn membership_requires_existing_user_and_user_delete_cascades_memberships() {
        let storage = SqliteStorage::open_in_memory().expect("in-memory storage");
        let error = storage
            .create_org_membership("org-123", "missing-user", PrincipalRole::Developer)
            .expect_err("missing user should fail");
        assert!(error.to_string().contains("user not found"));

        let user = storage
            .create_user("dev@example.com", None)
            .expect("create user");
        storage
            .create_org_membership("org-456", &user.id, PrincipalRole::Developer)
            .expect("create membership");

        assert!(storage.delete_user(&user.id).expect("delete user"));
        let memberships = storage
            .list_org_memberships(None)
            .expect("list memberships");
        assert!(memberships.is_empty());
    }

    #[test]
    fn principal_role_rejects_unknown_values() {
        let error = "super_admin"
            .parse::<PrincipalRole>()
            .expect_err("unknown role should fail");
        assert_eq!(error.to_string(), "invalid principal role: super_admin");
    }
}
