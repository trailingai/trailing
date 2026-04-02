use std::collections::HashSet;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::Digest;
use tokio_postgres::{Client, GenericClient, NoTls, Row, error::SqlState, types::ToSql};
use uuid::Uuid;

use super::{
    API_KEY_PREFIX, ActionEntry, ActionType, ApiKeyRecord, ApiKeyRole, AuthAuditEntry,
    AuthAuditEventType, AuthenticatedApiKey, AuthenticatedSession, CreatedApiKey, CreatedSession,
    DUMMY_BCRYPT_HASH, DeduplicationOutcome, ExternalAnchorInput, ExternalAnchorRecord,
    GENESIS_HASH, HumanUserRecord, IntegrityViolation, LedgerBackend, LedgerCheckpoint,
    LegalHoldEvent, LegalHoldRecord, MERKLE_BATCH_SIZE, MerkleBatch, MerkleInclusionProof,
    MfaChallengeStart, MfaChallengeVerify, MfaEnrollmentConfirm, MfaEnrollmentStart, MfaPolicy,
    RawStoredEntry, Result, RetentionPolicy, SignedCheckpoint, SigningKeyMetadata, StorageControl,
    StorageError, StorageScope, StoredEntry, UserRecord, VerifiedCheckpoint, bcrypt_hash,
    bcrypt_verify, build_merkle_root, compute_merkle_root_from_batches, current_time,
    normalize_internal_role, optional_trimmed, parse_api_key, parse_stored_entry,
    record_integrity_check_details, require_non_empty, validate_entry_hashes,
};
use crate::auth::{
    RecoveryCodeCount, generate_recovery_codes, generate_totp_secret, provisioning_uri, verify_totp,
};
use crate::checkpoint::{
    CheckpointPayload, CheckpointSigner, SignatureAlgorithm, checkpoint_hash,
    verify_signed_checkpoint as verify_checkpoint_signature,
};
use crate::storage::merkle::build_inclusion_proof;

const POSTGRES_MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_ledger",
        include_str!("../../migrations/postgres/0001_ledger.sql"),
    ),
    (
        "0002_parity",
        include_str!("../../migrations/postgres/0002_parity.sql"),
    ),
    (
        "0003_least_privilege_role",
        include_str!("../../migrations/postgres/0003_least_privilege_role.sql"),
    ),
    (
        "0004_action_log_project_scope",
        include_str!("../../migrations/postgres/0004_action_log_project_scope.sql"),
    ),
    (
        "0004_auth_audit",
        include_str!("../../migrations/postgres/0004_auth_audit.sql"),
    ),
];
const SESSION_TOKEN_PREFIX: &str = "trailing_session_";

type Response<T> = mpsc::SyncSender<Result<T>>;

pub struct PostgresStorage {
    sender: mpsc::Sender<Command>,
}

impl std::fmt::Debug for PostgresStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresStorage").finish_non_exhaustive()
    }
}

enum Command {
    Entries {
        org_id: Option<String>,
        project_id: Option<String>,
        respond_to: Response<Vec<ActionEntry>>,
    },
    AppendEntry {
        entry: ActionEntry,
        org_id: Option<String>,
        project_id: Option<String>,
        respond_to: Response<()>,
    },
    AppendActionWithDedup {
        org_id: Option<String>,
        project_id: Option<String>,
        dedup_key: String,
        timestamp: DateTime<Utc>,
        agent_id: String,
        agent_type: String,
        session_id: String,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: String,
        respond_to: Response<DeduplicationOutcome<ActionEntry>>,
    },
    VerifyChain {
        from_id: Option<Uuid>,
        to_id: Option<Uuid>,
        respond_to: Response<Vec<IntegrityViolation>>,
    },
    VerifyChainForScope {
        org_id: String,
        project_id: String,
        respond_to: Response<Vec<IntegrityViolation>>,
    },
    CreateCheckpoint {
        respond_to: Response<LedgerCheckpoint>,
    },
    LatestCheckpoint {
        respond_to: Response<Option<LedgerCheckpoint>>,
    },
    MerkleBatches {
        respond_to: Response<Vec<MerkleBatch>>,
    },
    MerkleProof {
        entry_id: Uuid,
        respond_to: Response<Option<MerkleInclusionProof>>,
    },
    PurgeExpired {
        policy: RetentionPolicy,
        as_of: DateTime<Utc>,
        respond_to: Response<usize>,
    },
    ControlSettings {
        respond_to: Response<StorageControl>,
    },
    DatabaseSizeBytes {
        respond_to: Response<u64>,
    },
    AuthAuditEntries {
        respond_to: Response<Vec<AuthAuditEntry>>,
    },
    CreateApiKey {
        org_id: String,
        name: String,
        roles: Option<Vec<ApiKeyRole>>,
        respond_to: Response<CreatedApiKey>,
    },
    ListApiKeys {
        org_id: Option<String>,
        respond_to: Response<Vec<ApiKeyRecord>>,
    },
    RevokeApiKey {
        org_id: Option<String>,
        key_id: String,
        respond_to: Response<bool>,
    },
    AuthenticateApiKey {
        raw_key: String,
        respond_to: Response<Option<AuthenticatedApiKey>>,
    },
    CreateSignedCheckpoint {
        signer: CheckpointSigner,
        anchors: Vec<ExternalAnchorInput>,
        respond_to: Response<SignedCheckpoint>,
    },
    ListSignedCheckpoints {
        respond_to: Response<Vec<SignedCheckpoint>>,
    },
    VerifySignedCheckpoint {
        checkpoint_id: Option<String>,
        respond_to: Response<Option<VerifiedCheckpoint>>,
    },
    CreateLegalHold {
        org_id: Option<String>,
        matter: String,
        reason: String,
        created_at: DateTime<Utc>,
        respond_to: Response<LegalHoldRecord>,
    },
    ReleaseLegalHold {
        hold_id: String,
        released_at: DateTime<Utc>,
        release_reason: String,
        respond_to: Response<Option<LegalHoldRecord>>,
    },
    ListLegalHolds {
        org_id: Option<String>,
        respond_to: Response<Vec<LegalHoldRecord>>,
    },
    ListLegalHoldEvents {
        hold_id: String,
        respond_to: Response<Vec<LegalHoldEvent>>,
    },
    CreateHumanUser {
        org_id: String,
        email: String,
        password: String,
        respond_to: Response<HumanUserRecord>,
    },
    LoadHumanUserRecord {
        org_id: String,
        email: String,
        respond_to: Response<Option<HumanUserRecord>>,
    },
    OrgMfaPolicy {
        org_id: String,
        respond_to: Response<MfaPolicy>,
    },
    SetOrgMfaPolicy {
        org_id: String,
        policy: MfaPolicy,
        respond_to: Response<MfaPolicy>,
    },
    StartMfaEnrollment {
        org_id: String,
        email: String,
        password: String,
        respond_to: Response<MfaEnrollmentStart>,
    },
    ConfirmMfaEnrollment {
        org_id: String,
        email: String,
        password: String,
        code: String,
        as_of: DateTime<Utc>,
        respond_to: Response<MfaEnrollmentConfirm>,
    },
    CreateMfaChallenge {
        org_id: String,
        email: String,
        password: String,
        as_of: DateTime<Utc>,
        respond_to: Response<MfaChallengeStart>,
    },
    VerifyMfaChallenge {
        challenge_id: String,
        code: String,
        as_of: DateTime<Utc>,
        respond_to: Response<MfaChallengeVerify>,
    },
    ProvisionSsoUser {
        org_id: String,
        external_subject: String,
        email: String,
        first_name: Option<String>,
        last_name: Option<String>,
        role: String,
        respond_to: Response<UserRecord>,
    },
    CreateSsoSession {
        user: UserRecord,
        ttl: Duration,
        respond_to: Response<CreatedSession>,
    },
    AuthenticateSession {
        raw_token: String,
        respond_to: Response<Option<AuthenticatedSession>>,
    },
}

impl PostgresStorage {
    pub fn open(dsn: &str) -> Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let (init_tx, init_rx) = mpsc::sync_channel(1);
        let dsn = dsn.to_string();

        thread::spawn(move || worker_loop(dsn, receiver, init_tx));

        init_rx.recv().map_err(|_| {
            StorageError::Postgres("postgres worker failed to initialize".to_string())
        })??;

        Ok(Self { sender })
    }

    pub fn backend_name(&self) -> &'static str {
        "postgres"
    }

    pub fn entries(&self) -> Result<Vec<ActionEntry>> {
        self.entries_for_org(None)
    }

    pub fn entries_for_org(&self, org_id: Option<&str>) -> Result<Vec<ActionEntry>> {
        self.entries_with_scope(org_id, None)
    }

    pub fn entries_for_scope(&self, scope: &StorageScope) -> Result<Vec<ActionEntry>> {
        self.entries_with_scope(Some(scope.org_id.as_str()), Some(scope.project_id.as_str()))
    }

    fn entries_with_scope(
        &self,
        org_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<ActionEntry>> {
        self.rpc(|respond_to| Command::Entries {
            org_id: org_id.map(str::to_string),
            project_id: project_id.map(str::to_string),
            respond_to,
        })
    }

    pub fn append_entry(&self, entry: &ActionEntry) -> Result<()> {
        self.append_entry_for_org(entry, None)
    }

    pub fn append_entry_for_org(&self, entry: &ActionEntry, org_id: Option<&str>) -> Result<()> {
        self.append_entry_with_scope(entry, org_id, None)
    }

    pub fn append_entry_for_tenant(
        &self,
        entry: &ActionEntry,
        org_id: &str,
        project_id: &str,
    ) -> Result<()> {
        self.append_entry_with_scope(entry, Some(org_id), Some(project_id))
    }

    fn append_entry_with_scope(
        &self,
        entry: &ActionEntry,
        org_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<()> {
        self.rpc(|respond_to| Command::AppendEntry {
            entry: entry.clone(),
            org_id: org_id.map(str::to_string),
            project_id: project_id.map(str::to_string),
            respond_to,
        })
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
        self.append_action_at_for_org(
            None,
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
        let previous_hash = self
            .latest_hash()?
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let entry = ActionEntry::new_with_timestamp(
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
            previous_hash,
        );
        self.append_entry_for_org(&entry, org_id)?;
        Ok(entry)
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
        let previous_hash = self
            .latest_hash()?
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        let entry = ActionEntry::new_with_timestamp(
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
            previous_hash,
        );
        self.append_entry_for_tenant(&entry, org_id, project_id)?;
        Ok(entry)
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
        match self.append_action_with_dedup_at_for_org_detailed(
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
        )? {
            DeduplicationOutcome::Inserted(entry) => Ok(Some(entry)),
            DeduplicationOutcome::Duplicate { .. } => Ok(None),
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
        self.rpc(|respond_to| Command::AppendActionWithDedup {
            org_id: org_id.map(str::to_string),
            project_id: None,
            dedup_key: dedup_key.to_string(),
            timestamp,
            agent_id: agent_id.into(),
            agent_type: agent_type.into(),
            session_id: session_id.into(),
            action_type,
            payload,
            context,
            outcome: outcome.into(),
            respond_to,
        })
    }

    pub fn verify_chain(
        &self,
        from_id: Option<Uuid>,
        to_id: Option<Uuid>,
    ) -> Result<Vec<IntegrityViolation>> {
        self.rpc(|respond_to| Command::VerifyChain {
            from_id,
            to_id,
            respond_to,
        })
    }

    pub fn verify_chain_for_scope(&self, scope: &StorageScope) -> Result<Vec<IntegrityViolation>> {
        self.rpc(|respond_to| Command::VerifyChainForScope {
            org_id: scope.org_id.clone(),
            project_id: scope.project_id.clone(),
            respond_to,
        })
    }

    pub fn create_checkpoint(&self) -> Result<LedgerCheckpoint> {
        self.rpc(|respond_to| Command::CreateCheckpoint { respond_to })
    }

    pub fn latest_checkpoint(&self) -> Result<Option<LedgerCheckpoint>> {
        self.rpc(|respond_to| Command::LatestCheckpoint { respond_to })
    }

    pub fn merkle_batches(&self) -> Result<Vec<MerkleBatch>> {
        self.rpc(|respond_to| Command::MerkleBatches { respond_to })
    }

    pub fn merkle_proof(&self, entry_id: Uuid) -> Result<Option<MerkleInclusionProof>> {
        self.rpc(|respond_to| Command::MerkleProof {
            entry_id,
            respond_to,
        })
    }

    pub fn purge_expired(&self, policy: &RetentionPolicy, as_of: DateTime<Utc>) -> Result<usize> {
        self.rpc(|respond_to| Command::PurgeExpired {
            policy: policy.clone(),
            as_of,
            respond_to,
        })
    }

    pub fn control_settings(&self) -> Result<StorageControl> {
        self.rpc(|respond_to| Command::ControlSettings { respond_to })
    }

    pub fn database_size_bytes(&self) -> Result<u64> {
        self.rpc(|respond_to| Command::DatabaseSizeBytes { respond_to })
    }

    pub fn auth_audit_entries(&self) -> Result<Vec<AuthAuditEntry>> {
        self.rpc(|respond_to| Command::AuthAuditEntries { respond_to })
    }

    pub fn create_api_key(&self, org_id: &str, name: &str) -> Result<CreatedApiKey> {
        self.create_api_key_with_roles(org_id, name, None)
    }

    pub fn create_api_key_with_roles(
        &self,
        org_id: &str,
        name: &str,
        roles: Option<&[ApiKeyRole]>,
    ) -> Result<CreatedApiKey> {
        self.rpc(|respond_to| Command::CreateApiKey {
            org_id: org_id.to_string(),
            name: name.to_string(),
            roles: roles.map(|roles| roles.to_vec()),
            respond_to,
        })
    }

    pub fn list_api_keys(&self) -> Result<Vec<ApiKeyRecord>> {
        self.rpc(|respond_to| Command::ListApiKeys {
            org_id: None,
            respond_to,
        })
    }

    pub fn list_api_keys_for_org(&self, org_id: &str) -> Result<Vec<ApiKeyRecord>> {
        self.rpc(|respond_to| Command::ListApiKeys {
            org_id: Some(org_id.to_string()),
            respond_to,
        })
    }

    pub fn revoke_api_key(&self, key_id: &str) -> Result<bool> {
        self.rpc(|respond_to| Command::RevokeApiKey {
            org_id: None,
            key_id: key_id.to_string(),
            respond_to,
        })
    }

    pub fn revoke_api_key_for_org(&self, org_id: &str, key_id: &str) -> Result<bool> {
        self.rpc(|respond_to| Command::RevokeApiKey {
            org_id: Some(org_id.to_string()),
            key_id: key_id.to_string(),
            respond_to,
        })
    }

    pub fn authenticate_api_key(&self, raw_key: &str) -> Result<Option<AuthenticatedApiKey>> {
        self.rpc(|respond_to| Command::AuthenticateApiKey {
            raw_key: raw_key.to_string(),
            respond_to,
        })
    }

    pub fn create_signed_checkpoint(
        &self,
        signer: &CheckpointSigner,
        anchors: &[ExternalAnchorInput],
    ) -> Result<SignedCheckpoint> {
        self.rpc(|respond_to| Command::CreateSignedCheckpoint {
            signer: signer.clone(),
            anchors: anchors.to_vec(),
            respond_to,
        })
    }

    pub fn signed_checkpoints(&self) -> Result<Vec<SignedCheckpoint>> {
        self.rpc(|respond_to| Command::ListSignedCheckpoints { respond_to })
    }

    pub fn verify_signed_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> Result<Option<VerifiedCheckpoint>> {
        self.rpc(|respond_to| Command::VerifySignedCheckpoint {
            checkpoint_id: Some(checkpoint_id.to_string()),
            respond_to,
        })
    }

    pub fn verify_latest_signed_checkpoint(&self) -> Result<Option<VerifiedCheckpoint>> {
        self.rpc(|respond_to| Command::VerifySignedCheckpoint {
            checkpoint_id: None,
            respond_to,
        })
    }

    pub fn create_legal_hold(
        &self,
        org_id: Option<&str>,
        matter: &str,
        reason: &str,
        created_at: DateTime<Utc>,
    ) -> Result<LegalHoldRecord> {
        self.rpc(|respond_to| Command::CreateLegalHold {
            org_id: org_id.map(str::to_string),
            matter: matter.to_string(),
            reason: reason.to_string(),
            created_at,
            respond_to,
        })
    }

    pub fn release_legal_hold(
        &self,
        hold_id: &str,
        released_at: DateTime<Utc>,
        release_reason: &str,
    ) -> Result<Option<LegalHoldRecord>> {
        self.rpc(|respond_to| Command::ReleaseLegalHold {
            hold_id: hold_id.to_string(),
            released_at,
            release_reason: release_reason.to_string(),
            respond_to,
        })
    }

    pub fn legal_holds(&self, org_id: Option<&str>) -> Result<Vec<LegalHoldRecord>> {
        self.rpc(|respond_to| Command::ListLegalHolds {
            org_id: org_id.map(str::to_string),
            respond_to,
        })
    }

    pub fn legal_hold_events(&self, hold_id: &str) -> Result<Vec<LegalHoldEvent>> {
        self.rpc(|respond_to| Command::ListLegalHoldEvents {
            hold_id: hold_id.to_string(),
            respond_to,
        })
    }

    pub fn create_human_user(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
    ) -> Result<HumanUserRecord> {
        self.rpc(|respond_to| Command::CreateHumanUser {
            org_id: org_id.to_string(),
            email: email.to_string(),
            password: password.to_string(),
            respond_to,
        })
    }

    pub fn human_user_record(&self, org_id: &str, email: &str) -> Result<Option<HumanUserRecord>> {
        self.rpc(|respond_to| Command::LoadHumanUserRecord {
            org_id: org_id.to_string(),
            email: email.to_string(),
            respond_to,
        })
    }

    pub fn org_mfa_policy(&self, org_id: &str) -> Result<MfaPolicy> {
        self.rpc(|respond_to| Command::OrgMfaPolicy {
            org_id: org_id.to_string(),
            respond_to,
        })
    }

    pub fn set_org_mfa_policy(&self, org_id: &str, policy: MfaPolicy) -> Result<MfaPolicy> {
        self.rpc(|respond_to| Command::SetOrgMfaPolicy {
            org_id: org_id.to_string(),
            policy,
            respond_to,
        })
    }

    pub fn start_mfa_enrollment(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
    ) -> Result<MfaEnrollmentStart> {
        self.rpc(|respond_to| Command::StartMfaEnrollment {
            org_id: org_id.to_string(),
            email: email.to_string(),
            password: password.to_string(),
            respond_to,
        })
    }

    pub fn confirm_mfa_enrollment(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
        code: &str,
        as_of: DateTime<Utc>,
    ) -> Result<MfaEnrollmentConfirm> {
        self.rpc(|respond_to| Command::ConfirmMfaEnrollment {
            org_id: org_id.to_string(),
            email: email.to_string(),
            password: password.to_string(),
            code: code.to_string(),
            as_of,
            respond_to,
        })
    }

    pub fn create_mfa_challenge(
        &self,
        org_id: &str,
        email: &str,
        password: &str,
        as_of: DateTime<Utc>,
    ) -> Result<MfaChallengeStart> {
        self.rpc(|respond_to| Command::CreateMfaChallenge {
            org_id: org_id.to_string(),
            email: email.to_string(),
            password: password.to_string(),
            as_of,
            respond_to,
        })
    }

    pub fn verify_mfa_challenge(
        &self,
        challenge_id: &str,
        code: &str,
        as_of: DateTime<Utc>,
    ) -> Result<MfaChallengeVerify> {
        self.rpc(|respond_to| Command::VerifyMfaChallenge {
            challenge_id: challenge_id.to_string(),
            code: code.to_string(),
            as_of,
            respond_to,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn provision_sso_user(
        &self,
        org_id: &str,
        external_subject: &str,
        email: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
        role: &str,
    ) -> Result<UserRecord> {
        self.rpc(|respond_to| Command::ProvisionSsoUser {
            org_id: org_id.to_string(),
            external_subject: external_subject.to_string(),
            email: email.to_string(),
            first_name: first_name.map(str::to_string),
            last_name: last_name.map(str::to_string),
            role: role.to_string(),
            respond_to,
        })
    }

    pub fn create_sso_session(&self, user: &UserRecord, ttl: Duration) -> Result<CreatedSession> {
        self.rpc(|respond_to| Command::CreateSsoSession {
            user: user.clone(),
            ttl,
            respond_to,
        })
    }

    pub fn authenticate_session(&self, raw_token: &str) -> Result<Option<AuthenticatedSession>> {
        self.rpc(|respond_to| Command::AuthenticateSession {
            raw_token: raw_token.to_string(),
            respond_to,
        })
    }

    fn latest_hash(&self) -> Result<Option<String>> {
        let entries = self.entries()?;
        Ok(entries.last().map(|entry| entry.entry_hash.clone()))
    }

    fn rpc<T>(&self, build: impl FnOnce(Response<T>) -> Command) -> Result<T> {
        let (respond_to, receiver) = response_channel()?;
        self.sender
            .send(build(respond_to))
            .map_err(|_| StorageError::Postgres("postgres worker unavailable".to_string()))?;
        receiver
            .recv()
            .map_err(|_| StorageError::Postgres("postgres worker did not respond".to_string()))?
    }
}

impl LedgerBackend for PostgresStorage {
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
        let control = self.control_settings()?;
        let policy = RetentionPolicy {
            min_retention_days: control.min_retention_days,
            legal_hold: false,
        };
        self.purge_expired(&policy, as_of)
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

fn response_channel<T>() -> Result<(Response<T>, mpsc::Receiver<Result<T>>)> {
    let (tx, rx) = mpsc::sync_channel(1);
    Ok((tx, rx))
}

fn worker_loop(dsn: String, receiver: mpsc::Receiver<Command>, init_tx: Response<()>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = init_tx.send(Err(StorageError::Postgres(error.to_string())));
            return;
        }
    };

    let init_result = runtime.block_on(async {
        let (mut client, connection) = tokio_postgres::connect(&dsn, NoTls)
            .await
            .map_err(|error| StorageError::Postgres(error.to_string()))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        apply_migrations(&mut client).await?;
        materialize_merkle_batches(&mut client).await?;
        Ok(client)
    });

    let mut client = match init_result {
        Ok(client) => {
            let _ = init_tx.send(Ok(()));
            client
        }
        Err(error) => {
            let _ = init_tx.send(Err(error));
            return;
        }
    };

    for command in receiver {
        match command {
            Command::Entries {
                org_id,
                project_id,
                respond_to,
            } => {
                let _ = respond_to.send(
                    runtime
                        .block_on(load_entries(
                            &mut client,
                            None,
                            None,
                            org_id.as_deref(),
                            project_id.as_deref(),
                        ))
                        .map(|entries| entries.into_iter().map(|entry| entry.entry).collect()),
                );
            }
            Command::AppendEntry {
                entry,
                org_id,
                project_id,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(append_entry(
                    &mut client,
                    &entry,
                    org_id.as_deref(),
                    project_id.as_deref(),
                )));
            }
            Command::AppendActionWithDedup {
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
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(append_action_with_dedup(
                    &mut client,
                    org_id.as_deref(),
                    project_id.as_deref(),
                    &dedup_key,
                    timestamp,
                    &agent_id,
                    &agent_type,
                    &session_id,
                    action_type,
                    payload,
                    context,
                    &outcome,
                )));
            }
            Command::VerifyChain {
                from_id,
                to_id,
                respond_to,
            } => {
                let _ =
                    respond_to.send(runtime.block_on(verify_chain(&mut client, from_id, to_id)));
            }
            Command::VerifyChainForScope {
                org_id,
                project_id,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(verify_chain_for_scope(
                    &mut client,
                    &org_id,
                    &project_id,
                )));
            }
            Command::CreateCheckpoint { respond_to } => {
                let _ = respond_to.send(runtime.block_on(create_checkpoint(&mut client)));
            }
            Command::LatestCheckpoint { respond_to } => {
                let _ = respond_to.send(runtime.block_on(load_latest_checkpoint(&mut client)));
            }
            Command::MerkleBatches { respond_to } => {
                let _ = respond_to.send(runtime.block_on(load_merkle_batches(&mut client)));
            }
            Command::MerkleProof {
                entry_id,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(load_merkle_proof(&mut client, entry_id)));
            }
            Command::PurgeExpired {
                policy,
                as_of,
                respond_to,
            } => {
                let _ =
                    respond_to.send(runtime.block_on(purge_expired(&mut client, &policy, as_of)));
            }
            Command::ControlSettings { respond_to } => {
                let _ = respond_to.send(runtime.block_on(load_control_settings(&mut client)));
            }
            Command::DatabaseSizeBytes { respond_to } => {
                let _ = respond_to.send(runtime.block_on(database_size_bytes(&mut client)));
            }
            Command::AuthAuditEntries { respond_to } => {
                let _ = respond_to.send(runtime.block_on(load_auth_audit_entries(&client)));
            }
            Command::CreateApiKey {
                org_id,
                name,
                roles,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(create_api_key(
                    &mut client,
                    &org_id,
                    &name,
                    roles.as_deref(),
                )));
            }
            Command::ListApiKeys { org_id, respond_to } => {
                let _ = respond_to.send(runtime.block_on(list_api_keys(
                    &mut client,
                    org_id.as_deref(),
                )));
            }
            Command::RevokeApiKey {
                org_id,
                key_id,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(revoke_api_key(
                    &mut client,
                    org_id.as_deref(),
                    &key_id,
                )));
            }
            Command::AuthenticateApiKey {
                raw_key,
                respond_to,
            } => {
                let _ =
                    respond_to.send(runtime.block_on(authenticate_api_key(&mut client, &raw_key)));
            }
            Command::CreateSignedCheckpoint {
                signer,
                anchors,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(create_signed_checkpoint(
                    &mut client,
                    &signer,
                    &anchors,
                )));
            }
            Command::ListSignedCheckpoints { respond_to } => {
                let _ = respond_to.send(runtime.block_on(load_signed_checkpoints(&client)));
            }
            Command::VerifySignedCheckpoint {
                checkpoint_id,
                respond_to,
            } => {
                let _ = respond_to.send(
                    runtime.block_on(verify_signed_checkpoint(&client, checkpoint_id.as_deref())),
                );
            }
            Command::CreateLegalHold {
                org_id,
                matter,
                reason,
                created_at,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(create_legal_hold(
                    &mut client,
                    org_id.as_deref(),
                    &matter,
                    &reason,
                    created_at,
                )));
            }
            Command::ReleaseLegalHold {
                hold_id,
                released_at,
                release_reason,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(release_legal_hold(
                    &mut client,
                    &hold_id,
                    released_at,
                    &release_reason,
                )));
            }
            Command::ListLegalHolds { org_id, respond_to } => {
                let _ =
                    respond_to.send(runtime.block_on(load_legal_holds(&client, org_id.as_deref())));
            }
            Command::ListLegalHoldEvents {
                hold_id,
                respond_to,
            } => {
                let _ =
                    respond_to.send(runtime.block_on(load_legal_hold_events(&client, &hold_id)));
            }
            Command::CreateHumanUser {
                org_id,
                email,
                password,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(create_human_user(
                    &mut client,
                    &org_id,
                    &email,
                    &password,
                )));
            }
            Command::LoadHumanUserRecord {
                org_id,
                email,
                respond_to,
            } => {
                let _ = respond_to
                    .send(runtime.block_on(load_human_user_record(&client, &org_id, &email)));
            }
            Command::OrgMfaPolicy { org_id, respond_to } => {
                let _ = respond_to.send(runtime.block_on(load_org_mfa_policy(&client, &org_id)));
            }
            Command::SetOrgMfaPolicy {
                org_id,
                policy,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(set_org_mfa_policy(
                    &mut client,
                    &org_id,
                    policy,
                )));
            }
            Command::StartMfaEnrollment {
                org_id,
                email,
                password,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(start_mfa_enrollment(
                    &mut client,
                    &org_id,
                    &email,
                    &password,
                )));
            }
            Command::ConfirmMfaEnrollment {
                org_id,
                email,
                password,
                code,
                as_of,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(confirm_mfa_enrollment(
                    &mut client,
                    &org_id,
                    &email,
                    &password,
                    &code,
                    as_of,
                )));
            }
            Command::CreateMfaChallenge {
                org_id,
                email,
                password,
                as_of,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(create_mfa_challenge(
                    &mut client,
                    &org_id,
                    &email,
                    &password,
                    as_of,
                )));
            }
            Command::VerifyMfaChallenge {
                challenge_id,
                code,
                as_of,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(verify_mfa_challenge(
                    &mut client,
                    &challenge_id,
                    &code,
                    as_of,
                )));
            }
            Command::ProvisionSsoUser {
                org_id,
                external_subject,
                email,
                first_name,
                last_name,
                role,
                respond_to,
            } => {
                let _ = respond_to.send(runtime.block_on(provision_sso_user(
                    &mut client,
                    &org_id,
                    &external_subject,
                    &email,
                    first_name.as_deref(),
                    last_name.as_deref(),
                    &role,
                )));
            }
            Command::CreateSsoSession {
                user,
                ttl,
                respond_to,
            } => {
                let _ =
                    respond_to.send(runtime.block_on(create_sso_session(&mut client, &user, ttl)));
            }
            Command::AuthenticateSession {
                raw_token,
                respond_to,
            } => {
                let _ = respond_to
                    .send(runtime.block_on(authenticate_session(&mut client, &raw_token)));
            }
        }
    }
}

async fn apply_migrations(client: &mut Client) -> Result<()> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            )",
        )
        .await
        .map_err(pg_err)?;

    for (version, sql) in POSTGRES_MIGRATIONS {
        let already_applied = client
            .query_opt(
                "SELECT version FROM schema_migrations WHERE version = $1",
                &[version],
            )
            .await
            .map_err(pg_err)?
            .is_some();
        if already_applied {
            continue;
        }

        client.batch_execute(sql).await.map_err(pg_err)?;
        client
            .execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)",
                &[version, &ActionEntry::canonical_timestamp(&current_time())],
            )
            .await
            .map_err(pg_err)?;
    }

    Ok(())
}

async fn append_entry(
    client: &mut Client,
    entry: &ActionEntry,
    org_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<()> {
    let expected_previous_hash = load_latest_hash(client)
        .await?
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    validate_entry_hashes(entry, &expected_previous_hash)?;

    let tx = client.transaction().await.map_err(pg_err)?;
    let row = tx
        .query_one(
            "INSERT INTO action_log (
                id, timestamp, agent_id, agent_type, session_id, action_type, payload, context,
                outcome, previous_hash, entry_hash, org_id, project_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING sequence",
            &[
                &entry.id.to_string(),
                &ActionEntry::canonical_timestamp(&entry.timestamp),
                &entry.agent_id,
                &entry.agent_type,
                &entry.session_id,
                &entry.action_type.to_string(),
                &entry.payload.to_string(),
                &entry.context.to_string(),
                &entry.outcome,
                &entry.previous_hash,
                &entry.entry_hash,
                &org_id,
                &project_id,
            ],
        )
        .await
        .map_err(pg_err)?;
    let sequence: i64 = row.get(0);
    tx.execute(
        "INSERT INTO ledger_root_anchors (sequence, entry_id, entry_hash, recorded_at)
         VALUES ($1, $2, $3, $4)",
        &[
            &sequence,
            &entry.id.to_string(),
            &entry.entry_hash,
            &ActionEntry::canonical_timestamp(&current_time()),
        ],
    )
    .await
    .map_err(pg_err)?;
    tx.commit().await.map_err(pg_err)?;
    materialize_merkle_batches(client).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn append_action_with_dedup(
    client: &mut Client,
    org_id: Option<&str>,
    project_id: Option<&str>,
    dedup_key: &str,
    timestamp: DateTime<Utc>,
    agent_id: &str,
    agent_type: &str,
    session_id: &str,
    action_type: ActionType,
    payload: Value,
    context: Value,
    outcome: &str,
) -> Result<DeduplicationOutcome<ActionEntry>> {
    let tx = client.transaction().await.map_err(pg_err)?;
    let existing_entry_id = tx
        .query_opt(
            "SELECT entry_id FROM ingest_dedup WHERE dedup_key = $1",
            &[&dedup_key],
        )
        .await
        .map_err(pg_err)?
        .and_then(|row| row.get::<_, Option<String>>(0));

    if existing_entry_id.is_some() {
        tx.rollback().await.map_err(pg_err)?;
        return Ok(DeduplicationOutcome::Duplicate {
            entry_id: existing_entry_id,
        });
    }

    let previous_hash = load_latest_hash_tx(&tx)
        .await?
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    let entry = ActionEntry::new_with_timestamp(
        timestamp,
        agent_id,
        agent_type,
        session_id,
        action_type,
        payload,
        context,
        outcome,
        previous_hash,
    );

    let row = tx
        .query_one(
            "INSERT INTO action_log (
                id, timestamp, agent_id, agent_type, session_id, action_type, payload, context,
                outcome, previous_hash, entry_hash, org_id, project_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING sequence",
            &[
                &entry.id.to_string(),
                &ActionEntry::canonical_timestamp(&entry.timestamp),
                &entry.agent_id,
                &entry.agent_type,
                &entry.session_id,
                &entry.action_type.to_string(),
                &entry.payload.to_string(),
                &entry.context.to_string(),
                &entry.outcome,
                &entry.previous_hash,
                &entry.entry_hash,
                &org_id,
                &project_id,
            ],
        )
        .await
        .map_err(pg_err)?;
    let sequence: i64 = row.get(0);

    tx.execute(
        "INSERT INTO ingest_dedup (dedup_key, entry_id, recorded_at) VALUES ($1, $2, $3)",
        &[
            &dedup_key,
            &entry.id.to_string(),
            &ActionEntry::canonical_timestamp(&current_time()),
        ],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "INSERT INTO ledger_root_anchors (sequence, entry_id, entry_hash, recorded_at)
         VALUES ($1, $2, $3, $4)",
        &[
            &sequence,
            &entry.id.to_string(),
            &entry.entry_hash,
            &ActionEntry::canonical_timestamp(&current_time()),
        ],
    )
    .await
    .map_err(pg_err)?;

    tx.commit().await.map_err(pg_err)?;
    materialize_merkle_batches(client).await?;
    Ok(DeduplicationOutcome::Inserted(entry))
}

async fn load_entries(
    client: &mut Client,
    from_id: Option<Uuid>,
    to_id: Option<Uuid>,
    org_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<Vec<StoredEntry>> {
    let start_sequence = match from_id {
        Some(id) => Some(lookup_sequence(client, id).await?),
        None => None,
    };
    let end_sequence = match to_id {
        Some(id) => Some(lookup_sequence(client, id).await?),
        None => None,
    };

    if let (Some(start), Some(end)) = (start_sequence, end_sequence)
        && start > end
    {
        return Ok(Vec::new());
    }

    let mut sql = String::from(
        "SELECT sequence, id, timestamp, agent_id, agent_type, session_id, action_type,
                payload, context, outcome, previous_hash, entry_hash, org_id
         FROM action_log",
    );
    let mut clauses = Vec::new();
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
    let mut param_index = 1;

    if let Some(start) = start_sequence.as_ref() {
        clauses.push(format!("sequence >= ${param_index}"));
        params.push(start);
        param_index += 1;
    }

    if let Some(end) = end_sequence.as_ref() {
        clauses.push(format!("sequence <= ${param_index}"));
        params.push(end);
        param_index += 1;
    }

    if let Some(org) = org_id.as_ref() {
        clauses.push(format!("org_id = ${param_index}"));
        params.push(org);
        param_index += 1;
    }

    if let Some(project) = project_id.as_ref() {
        clauses.push(format!("project_id = ${param_index}"));
        params.push(project);
    }

    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY sequence ASC");

    let rows = client.query(&sql, &params).await.map_err(pg_err)?;

    rows.into_iter()
        .map(row_to_stored_entry)
        .collect::<Result<Vec<_>>>()
}

async fn load_entries_for_scope(
    client: &mut Client,
    org_id: &str,
    project_id: &str,
) -> Result<Vec<StoredEntry>> {
    let rows = match client
        .query(
            "SELECT sequence, id, timestamp, agent_id, agent_type, session_id, action_type,
                    payload, context, outcome, previous_hash, entry_hash, org_id
             FROM action_log
             WHERE org_id = $1 AND project_id = $2
             ORDER BY sequence ASC",
            &[&org_id, &project_id],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error) if error.code() == Some(&SqlState::UNDEFINED_COLUMN) => client
            .query(
                "SELECT sequence, id, timestamp, agent_id, agent_type, session_id, action_type,
                        payload, context, outcome, previous_hash, entry_hash, org_id
                 FROM action_log
                 WHERE org_id = $1
                 ORDER BY sequence ASC",
                &[&org_id],
            )
            .await
            .map_err(pg_err)?,
        Err(error) => return Err(pg_err(error)),
    };

    rows.into_iter()
        .map(row_to_stored_entry)
        .collect::<Result<Vec<_>>>()
}

async fn verify_chain(
    client: &mut Client,
    from_id: Option<Uuid>,
    to_id: Option<Uuid>,
) -> Result<Vec<IntegrityViolation>> {
    let entries = load_entries(client, from_id, to_id, None, None).await?;
    let mut violations = Vec::new();

    if entries.is_empty() {
        record_integrity_check_details(client, from_id, to_id, &violations).await?;
        return Ok(violations);
    }

    let mut expected_previous_hash = if entries[0].sequence > 1 {
        load_previous_hash(client, entries[0].sequence)
            .await?
            .or(load_purge_resume_previous_hash(client, entries[0].sequence).await?)
            .unwrap_or_else(|| GENESIS_HASH.to_string())
    } else {
        GENESIS_HASH.to_string()
    };

    for stored_entry in &entries {
        let entry = &stored_entry.entry;
        if entry.previous_hash != expected_previous_hash {
            violations.push(IntegrityViolation {
                entry_id: entry.id,
                reason: "previous hash mismatch".to_string(),
                expected_previous_hash: Some(expected_previous_hash.clone()),
                actual_previous_hash: entry.previous_hash.clone(),
                expected_entry_hash: entry.entry_hash.clone(),
                actual_entry_hash: entry.calculate_hash(),
            });
        }

        let recomputed_entry_hash = entry.calculate_hash();
        if entry.entry_hash != recomputed_entry_hash {
            violations.push(IntegrityViolation {
                entry_id: entry.id,
                reason: "entry hash mismatch".to_string(),
                expected_previous_hash: Some(entry.previous_hash.clone()),
                actual_previous_hash: entry.previous_hash.clone(),
                expected_entry_hash: recomputed_entry_hash,
                actual_entry_hash: entry.entry_hash.clone(),
            });
        }

        expected_previous_hash = entry.entry_hash.clone();
    }

    if from_id.is_none() && to_id.is_none() {
        let latest_entry = entries.last().expect("entries is not empty");
        match load_latest_root_anchor(client).await? {
            Some(expected_root_hash) => {
                let actual_root_hash = latest_entry.entry.entry_hash.clone();
                if expected_root_hash != actual_root_hash {
                    violations.push(IntegrityViolation {
                        entry_id: latest_entry.entry.id,
                        reason: "anchored root hash mismatch".to_string(),
                        expected_previous_hash: None,
                        actual_previous_hash: actual_root_hash.clone(),
                        expected_entry_hash: expected_root_hash,
                        actual_entry_hash: actual_root_hash,
                    });
                }
            }
            None => violations.push(IntegrityViolation {
                entry_id: latest_entry.entry.id,
                reason: "missing root anchor".to_string(),
                expected_previous_hash: None,
                actual_previous_hash: String::new(),
                expected_entry_hash: "root-anchor".to_string(),
                actual_entry_hash: String::new(),
            }),
        }
    }

    record_integrity_check_details(client, from_id, to_id, &violations).await?;
    Ok(violations)
}

async fn verify_chain_for_scope(
    client: &mut Client,
    org_id: &str,
    project_id: &str,
) -> Result<Vec<IntegrityViolation>> {
    let entries = load_entries_for_scope(client, org_id, project_id).await?;
    let mut violations = Vec::new();
    let mut expected_previous_hash = GENESIS_HASH.to_string();

    for stored_entry in &entries {
        let entry = &stored_entry.entry;
        if entry.previous_hash != expected_previous_hash {
            violations.push(IntegrityViolation {
                entry_id: entry.id,
                reason: "previous hash mismatch".to_string(),
                expected_previous_hash: Some(expected_previous_hash.clone()),
                actual_previous_hash: entry.previous_hash.clone(),
                expected_entry_hash: entry.entry_hash.clone(),
                actual_entry_hash: entry.calculate_hash(),
            });
        }

        let recomputed_entry_hash = entry.calculate_hash();
        if entry.entry_hash != recomputed_entry_hash {
            violations.push(IntegrityViolation {
                entry_id: entry.id,
                reason: "entry hash mismatch".to_string(),
                expected_previous_hash: Some(entry.previous_hash.clone()),
                actual_previous_hash: entry.previous_hash.clone(),
                expected_entry_hash: recomputed_entry_hash,
                actual_entry_hash: entry.entry_hash.clone(),
            });
        }

        expected_previous_hash = entry.entry_hash.clone();
    }

    Ok(violations)
}

async fn create_checkpoint(client: &mut Client) -> Result<LedgerCheckpoint> {
    materialize_merkle_batches(client).await?;
    let Some(head) = client
        .query_opt(
            "SELECT sequence, id, entry_hash FROM action_log ORDER BY sequence DESC LIMIT 1",
            &[],
        )
        .await
        .map_err(pg_err)?
    else {
        return Err(StorageError::InvalidInput(
            "cannot checkpoint an empty ledger".to_string(),
        ));
    };

    let sequence: i64 = head.get(0);
    let entry_id: String = head.get(1);
    let entry_hash: String = head.get(2);
    let merkle_root = compute_checkpoint_merkle_root(client, sequence).await?;
    let checkpoint_id = Uuid::new_v4().to_string();
    let created_at = ActionEntry::canonical_timestamp(&current_time());

    let inserted = client
        .query_opt(
            "INSERT INTO ledger_checkpoints (
                checkpoint_id, sequence, entry_id, entry_hash, merkle_root, created_at
             ) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (sequence) DO NOTHING
             RETURNING checkpoint_id, sequence, entry_id, entry_hash, merkle_root, created_at",
            &[
                &checkpoint_id,
                &sequence,
                &entry_id,
                &entry_hash,
                &merkle_root,
                &created_at,
            ],
        )
        .await
        .map_err(pg_err)?;

    match inserted {
        Some(row) => Ok(row_to_checkpoint(&row)),
        None => load_checkpoint_for_sequence(client, sequence)
            .await?
            .ok_or_else(|| {
                StorageError::Postgres("checkpoint insert lost on conflict".to_string())
            }),
    }
}

async fn load_latest_checkpoint(client: &mut Client) -> Result<Option<LedgerCheckpoint>> {
    client
        .query_opt(
            "SELECT checkpoint_id, sequence, entry_id, entry_hash, merkle_root, created_at
             FROM ledger_checkpoints
             ORDER BY sequence DESC
             LIMIT 1",
            &[],
        )
        .await
        .map(|row| row.map(|row| row_to_checkpoint(&row)))
        .map_err(pg_err)
}

async fn load_merkle_batches(client: &mut Client) -> Result<Vec<MerkleBatch>> {
    materialize_merkle_batches(client).await?;
    client
        .query(
            "SELECT batch_id, start_sequence, end_sequence, leaf_count, root_hash, created_at
             FROM merkle_batches
             ORDER BY start_sequence ASC",
            &[],
        )
        .await
        .map_err(pg_err)?
        .into_iter()
        .map(|row| {
            Ok(MerkleBatch {
                batch_id: row.get(0),
                start_sequence: row.get(1),
                end_sequence: row.get(2),
                leaf_count: row.get(3),
                root_hash: row.get(4),
                created_at: row.get(5),
            })
        })
        .collect()
}

async fn load_merkle_proof(
    client: &mut Client,
    entry_id: Uuid,
) -> Result<Option<MerkleInclusionProof>> {
    materialize_merkle_batches(client).await?;

    let target = client
        .query_opt(
            "SELECT sequence, entry_hash
             FROM action_log
             WHERE id = $1",
            &[&entry_id.to_string()],
        )
        .await
        .map_err(pg_err)?
        .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)));

    let Some((sequence, entry_hash)) = target else {
        return Ok(None);
    };

    let batch_index = (sequence - 1) / MERKLE_BATCH_SIZE;
    let batch = client
        .query_opt(
            "SELECT start_sequence, end_sequence, root_hash
             FROM merkle_batches
             WHERE start_sequence <= $1 AND end_sequence >= $1
             LIMIT 1",
            &[&sequence],
        )
        .await
        .map_err(pg_err)?
        .map(|row| {
            (
                row.get::<_, i64>(0),
                row.get::<_, i64>(1),
                row.get::<_, String>(2),
            )
        });

    let Some((batch_start_sequence, batch_end_sequence, batch_root)) = batch else {
        return Ok(None);
    };

    let leaves = client
        .query(
            "SELECT id, entry_hash
             FROM action_log
             WHERE sequence >= $1 AND sequence <= $2
             ORDER BY sequence ASC",
            &[&batch_start_sequence, &batch_end_sequence],
        )
        .await
        .map_err(pg_err)?
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
        .collect::<Vec<_>>();

    let leaf_index = leaves
        .iter()
        .position(|(stored_entry_id, _)| stored_entry_id == &entry_id.to_string())
        .ok_or_else(|| {
            StorageError::InvalidInput(format!(
                "entry {entry_id} missing from postgres merkle batch {batch_index}"
            ))
        })?;
    let leaf_hashes = leaves
        .iter()
        .map(|(_, stored_entry_hash)| stored_entry_hash.clone())
        .collect::<Vec<_>>();
    let (proof_leaf_hash, computed_root, proof) = build_inclusion_proof(&leaf_hashes, leaf_index)
        .ok_or_else(|| {
        StorageError::InvalidInput(format!(
            "failed to construct inclusion proof for entry {entry_id}"
        ))
    })?;

    if computed_root != batch_root {
        return Ok(None);
    }
    if leaves[leaf_index].1 != entry_hash {
        return Ok(None);
    }

    Ok(Some(MerkleInclusionProof {
        batch_index,
        batch_root,
        batch_start_sequence,
        batch_end_sequence,
        entry_id,
        leaf_index,
        leaf_hash: proof_leaf_hash,
        proof,
    }))
}

async fn purge_expired(
    client: &mut Client,
    policy: &RetentionPolicy,
    as_of: DateTime<Utc>,
) -> Result<usize> {
    if policy.legal_hold {
        return Err(StorageError::LegalHoldActive);
    }

    let active_holds = load_active_hold_scope(client).await?;
    let entries = load_entries(client, None, None, None, None).await?;

    let mut delete_through_sequence = None;
    let mut delete_through_hash = None;
    let mut hold_blocked = false;

    for stored_entry in entries {
        let held = active_holds.global
            || stored_entry
                .org_id
                .as_deref()
                .is_some_and(|org_id| active_holds.org_ids.contains(org_id));
        if held {
            hold_blocked = delete_through_sequence.is_none();
            break;
        }

        let cutoff = as_of - chrono::Duration::days(policy.min_retention_days.max(0));
        if stored_entry.entry.timestamp >= cutoff {
            break;
        }

        delete_through_sequence = Some(stored_entry.sequence);
        delete_through_hash = Some(stored_entry.entry.entry_hash.clone());
    }

    let Some(delete_through_sequence) = delete_through_sequence else {
        if hold_blocked {
            return Err(StorageError::LegalHoldActive);
        }
        return Ok(0);
    };
    let Some(delete_through_hash) = delete_through_hash else {
        return Err(StorageError::InvalidInput(
            "purge state missing terminal hash".to_string(),
        ));
    };

    let tx = client.transaction().await.map_err(pg_err)?;
    tx.execute(
        "UPDATE storage_control
         SET allow_purge = TRUE,
             purge_through_sequence = $1
         WHERE id = 1",
        &[&delete_through_sequence],
    )
    .await
    .map_err(pg_err)?;
    let deleted = tx
        .execute(
            "DELETE FROM action_log WHERE sequence <= $1",
            &[&delete_through_sequence],
        )
        .await
        .map_err(pg_err)?;
    let remaining_rows = tx
        .query_one("SELECT COUNT(*) FROM action_log", &[])
        .await
        .map_err(pg_err)?
        .get::<_, i64>(0);
    let resume_previous_hash = (remaining_rows > 0).then_some(delete_through_hash.clone());
    tx.execute(
        "INSERT INTO purge_events (
            id,
            purged_at,
            as_of,
            deleted_rows,
            through_sequence,
            through_entry_hash,
            resume_previous_hash
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[
            &Uuid::new_v4().to_string(),
            &ActionEntry::canonical_timestamp(&current_time()),
            &ActionEntry::canonical_timestamp(&as_of),
            &(deleted as i64),
            &delete_through_sequence,
            &delete_through_hash,
            &resume_previous_hash,
        ],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "UPDATE storage_control
         SET allow_purge = FALSE,
             purge_through_sequence = NULL
         WHERE id = 1",
        &[],
    )
    .await
    .map_err(pg_err)?;
    tx.commit().await.map_err(pg_err)?;
    Ok(deleted as usize)
}

async fn load_control_settings(client: &mut Client) -> Result<StorageControl> {
    client
        .query_one(
            "SELECT allow_purge, min_retention_days FROM storage_control WHERE id = 1",
            &[],
        )
        .await
        .map(|row| StorageControl {
            allow_purge: row.get::<_, bool>(0),
            min_retention_days: row.get(1),
        })
        .map_err(pg_err)
}

async fn database_size_bytes(client: &mut Client) -> Result<u64> {
    client
        .query_one("SELECT pg_database_size(current_database())", &[])
        .await
        .map(|row| row.get::<_, i64>(0).max(0) as u64)
        .map_err(pg_err)
}

#[allow(clippy::too_many_arguments)]
async fn record_auth_event(
    client: &impl GenericClient,
    timestamp: DateTime<Utc>,
    event_type: AuthAuditEventType,
    org_id: Option<&str>,
    actor_type: String,
    actor_id: Option<String>,
    subject_type: String,
    subject_id: String,
    payload: Value,
    outcome: String,
) -> Result<AuthAuditEntry> {
    let id = Uuid::new_v4();
    let previous_hash = load_latest_auth_audit_hash(client)
        .await?
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    let entry_hash = calculate_auth_audit_hash_parts(
        &id,
        &previous_hash,
        &timestamp,
        event_type,
        org_id,
        &actor_type,
        actor_id.as_deref(),
        &subject_type,
        &subject_id,
        &payload,
        &outcome,
    );
    let id_str = id.to_string();
    let timestamp_str = ActionEntry::canonical_timestamp(&timestamp);
    let event_type_str = event_type.to_string();
    let payload_str = payload.to_string();
    let actor_id_ref = actor_id.as_deref();

    client
        .execute(
            "INSERT INTO auth_audit_log (
                id,
                timestamp,
                event_type,
                org_id,
                actor_type,
                actor_id,
                subject_type,
                subject_id,
                payload,
                outcome,
                previous_hash,
                entry_hash
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                &id_str,
                &timestamp_str,
                &event_type_str,
                &org_id,
                &actor_type,
                &actor_id_ref,
                &subject_type,
                &subject_id,
                &payload_str,
                &outcome,
                &previous_hash,
                &entry_hash,
            ],
        )
        .await
        .map_err(pg_err)?;

    Ok(AuthAuditEntry {
        id,
        timestamp,
        event_type,
        org_id: org_id.map(ToString::to_string),
        actor_type,
        actor_id,
        subject_type,
        subject_id,
        payload,
        outcome,
        previous_hash,
        entry_hash,
    })
}

async fn load_auth_audit_entries(client: &impl GenericClient) -> Result<Vec<AuthAuditEntry>> {
    client
        .query(
            "SELECT
                id,
                timestamp,
                event_type,
                org_id,
                actor_type,
                actor_id,
                subject_type,
                subject_id,
                payload,
                outcome,
                previous_hash,
                entry_hash
             FROM auth_audit_log
             ORDER BY sequence ASC",
            &[],
        )
        .await
        .map_err(pg_err)?
        .into_iter()
        .map(|row| {
            parse_auth_audit_entry(RawStoredAuthAuditEntry {
                id: row.get(0),
                timestamp: row.get(1),
                event_type: row.get(2),
                org_id: row.get(3),
                actor_type: row.get(4),
                actor_id: row.get(5),
                subject_type: row.get(6),
                subject_id: row.get(7),
                payload: row.get(8),
                outcome: row.get(9),
                previous_hash: row.get(10),
                entry_hash: row.get(11),
            })
        })
        .collect()
}

async fn load_latest_auth_audit_hash(client: &impl GenericClient) -> Result<Option<String>> {
    client
        .query_opt(
            "SELECT entry_hash FROM auth_audit_log ORDER BY sequence DESC LIMIT 1",
            &[],
        )
        .await
        .map(|row| row.map(|row| row.get::<_, String>(0)))
        .map_err(pg_err)
}

async fn create_api_key(
    client: &mut Client,
    org_id: &str,
    name: &str,
    requested_roles: Option<&[ApiKeyRole]>,
) -> Result<CreatedApiKey> {
    let org_id = org_id.trim();
    let name = name.trim();
    if org_id.is_empty() {
        return Err(StorageError::InvalidInput(
            "organization id must not be empty".to_string(),
        ));
    }
    if name.is_empty() {
        return Err(StorageError::InvalidInput(
            "key name must not be empty".to_string(),
        ));
    }

    let created_at_time = current_time();
    let id = Uuid::new_v4().to_string();
    let secret = format!(
        "{}{}",
        Uuid::new_v4().to_string().replace('-', ""),
        Uuid::new_v4().to_string().replace('-', "")
    );
    let key_hash = bcrypt_hash(&secret)?;
    let created_at = ActionEntry::canonical_timestamp(&created_at_time);
    let tx = client.transaction().await.map_err(pg_err)?;
    tx.execute(
        "INSERT INTO credentials (
            id,
            key_hash,
            org_id,
            project_id,
            name,
            credential_type,
            created_at,
            created_by,
            expires_at,
            last_used_at,
            previous_key_id,
            revoked,
            revoked_at,
            revocation_reason,
            roles
         ) VALUES ($1, $2, $3, NULL, $4, 'api_key', $5, NULL, NULL, NULL, NULL, FALSE, NULL, NULL, $6)",
        &[
            &id,
            &key_hash,
            &org_id,
            &name,
            &created_at,
            &serialize_api_key_roles(requested_roles.unwrap_or(&[]))?,
        ],
    )
    .await
    .map_err(pg_err)?;
    let current_admin_key_id = load_admin_key_id(&tx).await?;
    let is_admin = match current_admin_key_id {
        Some(_) => false,
        None => {
            tx.execute(
                "UPDATE app_settings SET admin_key_id = $1 WHERE id = 1",
                &[&id],
            )
            .await
            .map_err(pg_err)?;
            true
        }
    };
    let roles = if is_admin {
        ApiKeyRole::admin_roles()
    } else if let Some(roles) = requested_roles {
        roles.to_vec()
    } else {
        ApiKeyRole::default_service_roles()
    };
    let grants_admin_access = is_admin || roles.contains(&ApiKeyRole::Admin);
    tx.execute(
        "UPDATE credentials SET roles = $2 WHERE id = $1",
        &[&id, &serialize_api_key_roles(&roles)?],
    )
    .await
    .map_err(pg_err)?;
    let role_names = roles.iter().map(|role| role.as_str()).collect::<Vec<_>>();
    record_auth_event(
        &tx,
        created_at_time,
        AuthAuditEventType::KeyCreation,
        Some(org_id),
        "system".to_string(),
        None,
        CredentialKind::ApiKey.as_str().to_string(),
        id.clone(),
        json!({
            "name": name,
            "credential_type": CredentialKind::ApiKey.as_str(),
            "project_id": Option::<String>::None,
            "is_admin": grants_admin_access,
            "previous_key_id": Option::<String>::None,
            "roles": role_names,
        }),
        "created".to_string(),
    )
    .await?;
    tx.commit().await.map_err(pg_err)?;

    Ok(CreatedApiKey {
        id: id.clone(),
        org_id: org_id.to_string(),
        name: name.to_string(),
        created_at: created_at.clone(),
        key: format!("{API_KEY_PREFIX}{id}_{secret}"),
        is_admin: grants_admin_access,
        roles,
    })
}

async fn list_api_keys(client: &mut Client, org_id: Option<&str>) -> Result<Vec<ApiKeyRecord>> {
    let admin_key_id = load_admin_key_id(client).await?;
    let rows = if let Some(org_id) = org_id {
        client
            .query(
                "SELECT id, org_id, name, created_at, last_used_at, revoked, roles
                 FROM credentials
                 WHERE credential_type = 'api_key' AND org_id = $1
                 ORDER BY created_at ASC, id ASC",
                &[&org_id],
            )
            .await
            .map_err(pg_err)?
    } else {
        client
            .query(
                "SELECT id, org_id, name, created_at, last_used_at, revoked, roles
                 FROM credentials
                 WHERE credential_type = 'api_key'
                 ORDER BY created_at ASC, id ASC",
                &[],
            )
            .await
            .map_err(pg_err)?
    };
    rows
        .into_iter()
        .map(|row| {
            let id: String = row.get(0);
            let is_bootstrap_admin = admin_key_id.as_deref() == Some(id.as_str());
            let roles = if is_bootstrap_admin {
                ApiKeyRole::admin_roles()
            } else {
                deserialize_api_key_roles(row.get::<_, String>(6))?
            };
            let is_admin = is_bootstrap_admin || roles.contains(&ApiKeyRole::Admin);
            Ok(ApiKeyRecord {
                is_admin,
                id,
                org_id: row.get(1),
                name: row.get(2),
                created_at: row.get(3),
                last_used_at: row.get(4),
                revoked: row.get::<_, bool>(5),
                roles,
            })
        })
        .collect()
}

async fn revoke_api_key(client: &mut Client, org_id: Option<&str>, key_id: &str) -> Result<bool> {
    let revoked_at = current_time();
    let revoked_at_str = ActionEntry::canonical_timestamp(&revoked_at);
    let tx = client.transaction().await.map_err(pg_err)?;
    let current_admin_key_id = load_admin_key_id(&tx).await?;
    let credential = load_credential(&tx, key_id).await?;
    let Some(credential) = credential else {
        tx.rollback().await.map_err(pg_err)?;
        return Ok(false);
    };
    if credential.revoked
        || credential.credential_type != CredentialKind::ApiKey
        || org_id.is_some_and(|org_id| credential.org_id != org_id)
    {
        tx.rollback().await.map_err(pg_err)?;
        return Ok(false);
    }
    let affected = tx
        .execute(
            "UPDATE credentials
             SET revoked = TRUE, revoked_at = $2
             WHERE id = $1 AND revoked = FALSE",
            &[&key_id, &revoked_at_str],
        )
        .await
        .map_err(pg_err)?;
    if affected == 0 {
        tx.rollback().await.map_err(pg_err)?;
        return Ok(false);
    }

    let next_admin_key_id = if current_admin_key_id.as_deref() == Some(key_id) {
        let next_admin_key_id = next_active_credential_id(&tx).await?;
        tx.execute(
            "UPDATE app_settings SET admin_key_id = $1 WHERE id = 1",
            &[&next_admin_key_id],
        )
        .await
        .map_err(pg_err)?;
        next_admin_key_id
    } else {
        None
    };

    record_auth_event(
        &tx,
        revoked_at,
        AuthAuditEventType::KeyRevocation,
        Some(credential.org_id.as_str()),
        "system".to_string(),
        None,
        credential.credential_type.as_str().to_string(),
        credential.id.clone(),
        json!({
            "credential_type": credential.credential_type.as_str(),
            "project_id": Option::<String>::None,
            "reason": Option::<String>::None,
            "was_admin": current_admin_key_id.as_deref() == Some(key_id),
            "next_admin_key_id": next_admin_key_id,
        }),
        "revoked".to_string(),
    )
    .await?;

    tx.commit().await.map_err(pg_err)?;
    Ok(true)
}

async fn authenticate_api_key(
    client: &mut Client,
    raw_key: &str,
) -> Result<Option<AuthenticatedApiKey>> {
    let maybe_parts = parse_api_key(raw_key);
    let stored_key = match maybe_parts.as_ref() {
        Some((key_id, _)) => load_credential(client, key_id).await?,
        None => None,
    };

    let provided_secret = maybe_parts
        .as_ref()
        .map(|(_, secret)| secret.as_str())
        .unwrap_or(raw_key);
    let hash_to_check = stored_key
        .as_ref()
        .map(|stored_key| stored_key.key_hash.as_str())
        .unwrap_or(DUMMY_BCRYPT_HASH);
    let verified = bcrypt_verify(provided_secret, hash_to_check)?;

    let Some(stored_key) = stored_key else {
        return Ok(None);
    };
    if !verified
        || stored_key.revoked
        || credential_is_expired(stored_key.expires_at.as_deref())?
        || stored_key.credential_type != CredentialKind::ApiKey
    {
        return Ok(None);
    }

    let authenticated_at = current_time();
    let last_used_at = ActionEntry::canonical_timestamp(&authenticated_at);
    let tx = client.transaction().await.map_err(pg_err)?;
    tx.execute(
        "UPDATE credentials SET last_used_at = $2 WHERE id = $1",
        &[&stored_key.id, &last_used_at],
    )
    .await
    .map_err(pg_err)?;
    record_auth_event(
        &tx,
        authenticated_at,
        AuthAuditEventType::Login,
        Some(stored_key.org_id.as_str()),
        stored_key.credential_type.as_str().to_string(),
        Some(stored_key.id.clone()),
        stored_key.credential_type.as_str().to_string(),
        stored_key.id.clone(),
        json!({
            "credential_type": stored_key.credential_type.as_str(),
            "project_id": Option::<String>::None,
            "is_admin": stored_key.is_admin || stored_key.roles.contains(&ApiKeyRole::Admin),
            "auth_method": stored_key.credential_type.as_str(),
        }),
        "authenticated".to_string(),
    )
    .await?;
    tx.commit().await.map_err(pg_err)?;

    let is_admin = stored_key.is_admin || stored_key.roles.contains(&ApiKeyRole::Admin);
    Ok(Some(AuthenticatedApiKey {
        id: stored_key.id,
        org_id: stored_key.org_id,
        is_admin,
        revoked: false,
        roles: stored_key.roles,
    }))
}

async fn materialize_merkle_batches(client: &mut Client) -> Result<()> {
    let next_start = client
        .query_opt(
            "SELECT end_sequence FROM merkle_batches ORDER BY end_sequence DESC LIMIT 1",
            &[],
        )
        .await
        .map_err(pg_err)?
        .map(|row| row.get::<_, i64>(0) + 1)
        .unwrap_or(1);

    let latest_sequence = client
        .query_opt(
            "SELECT sequence FROM action_log ORDER BY sequence DESC LIMIT 1",
            &[],
        )
        .await
        .map_err(pg_err)?
        .map(|row| row.get::<_, i64>(0))
        .unwrap_or(0);

    if latest_sequence < next_start {
        return Ok(());
    }

    let mut batch_start = next_start;
    while batch_start + MERKLE_BATCH_SIZE - 1 <= latest_sequence {
        let batch_end = batch_start + MERKLE_BATCH_SIZE - 1;
        let rows = client
            .query(
                "SELECT entry_hash FROM action_log
                 WHERE sequence >= $1 AND sequence <= $2
                 ORDER BY sequence ASC",
                &[&batch_start, &batch_end],
            )
            .await
            .map_err(pg_err)?;
        let hashes = rows
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>();
        let batch_root_hash = build_merkle_root(&hashes);
        client
            .execute(
                "INSERT INTO merkle_batches (
                    start_sequence, end_sequence, leaf_count, root_hash, created_at
                 ) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (start_sequence) DO NOTHING",
                &[
                    &batch_start,
                    &batch_end,
                    &MERKLE_BATCH_SIZE,
                    &batch_root_hash,
                    &ActionEntry::canonical_timestamp(&current_time()),
                ],
            )
            .await
            .map_err(pg_err)?;
        batch_start += MERKLE_BATCH_SIZE;
    }

    Ok(())
}

async fn compute_checkpoint_merkle_root(client: &mut Client, sequence: i64) -> Result<String> {
    let stored_batches = client
        .query(
            "SELECT root_hash FROM merkle_batches WHERE end_sequence <= $1 ORDER BY start_sequence ASC",
            &[&sequence],
        )
        .await
        .map_err(pg_err)?
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    let covered = stored_batches.len() as i64 * MERKLE_BATCH_SIZE;
    let partial_hashes = if covered < sequence {
        client
            .query(
                "SELECT entry_hash FROM action_log
                 WHERE sequence > $1 AND sequence <= $2
                 ORDER BY sequence ASC",
                &[&covered, &sequence],
            )
            .await
            .map_err(pg_err)?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    compute_merkle_root_from_batches(stored_batches, partial_hashes)
}

async fn load_checkpoint_for_sequence(
    client: &mut Client,
    sequence: i64,
) -> Result<Option<LedgerCheckpoint>> {
    client
        .query_opt(
            "SELECT checkpoint_id, sequence, entry_id, entry_hash, merkle_root, created_at
             FROM ledger_checkpoints
             WHERE sequence = $1",
            &[&sequence],
        )
        .await
        .map(|row| row.map(|row| row_to_checkpoint(&row)))
        .map_err(pg_err)
}

async fn lookup_sequence(client: &mut Client, id: Uuid) -> Result<i64> {
    client
        .query_opt(
            "SELECT sequence FROM action_log WHERE id = $1",
            &[&id.to_string()],
        )
        .await
        .map_err(pg_err)?
        .map(|row| row.get::<_, i64>(0))
        .ok_or(StorageError::MissingBoundary(id))
}

async fn load_previous_hash(client: &mut Client, sequence: i64) -> Result<Option<String>> {
    client
        .query_opt(
            "SELECT entry_hash FROM action_log
             WHERE sequence < $1
             ORDER BY sequence DESC
             LIMIT 1",
            &[&sequence],
        )
        .await
        .map(|row| row.map(|row| row.get::<_, String>(0)))
        .map_err(pg_err)
}

async fn load_purge_resume_previous_hash(
    client: &mut Client,
    sequence: i64,
) -> Result<Option<String>> {
    client
        .query_opt(
            "SELECT resume_previous_hash
             FROM purge_events
             WHERE through_sequence < $1
               AND resume_previous_hash IS NOT NULL
             ORDER BY through_sequence DESC
             LIMIT 1",
            &[&sequence],
        )
        .await
        .map(|row| row.map(|row| row.get::<_, String>(0)))
        .map_err(pg_err)
}

async fn load_latest_root_anchor(client: &mut Client) -> Result<Option<String>> {
    client
        .query_opt(
            "SELECT entry_hash FROM ledger_root_anchors ORDER BY sequence DESC LIMIT 1",
            &[],
        )
        .await
        .map(|row| row.map(|row| row.get::<_, String>(0)))
        .map_err(pg_err)
}

async fn load_latest_hash(client: &impl GenericClient) -> Result<Option<String>> {
    client
        .query_opt(
            "SELECT entry_hash FROM action_log ORDER BY sequence DESC LIMIT 1",
            &[],
        )
        .await
        .map(|row| row.map(|row| row.get::<_, String>(0)))
        .map_err(pg_err)
}

async fn load_latest_hash_tx(tx: &tokio_postgres::Transaction<'_>) -> Result<Option<String>> {
    tx.query_opt(
        "SELECT entry_hash FROM action_log ORDER BY sequence DESC LIMIT 1",
        &[],
    )
    .await
    .map(|row| row.map(|row| row.get::<_, String>(0)))
    .map_err(pg_err)
}

async fn load_admin_key_id(client: &impl GenericClient) -> Result<Option<String>> {
    client
        .query_opt("SELECT admin_key_id FROM app_settings WHERE id = 1", &[])
        .await
        .map(|row| row.and_then(|row| row.get::<_, Option<String>>(0)))
        .map_err(pg_err)
}

async fn load_credential(
    client: &impl GenericClient,
    credential_id: &str,
) -> Result<Option<StoredCredential>> {
    let admin_key_id = load_admin_key_id(client).await?;
    let row = client
        .query_opt(
            "SELECT id, org_id, credential_type, key_hash, expires_at, revoked, roles
             FROM credentials
             WHERE id = $1",
            &[&credential_id],
        )
        .await
        .map_err(pg_err)?;

    let Some(row) = row else {
        return Ok(None);
    };
    let id: String = row.get(0);
    let is_admin = admin_key_id.as_deref() == Some(id.as_str());
    let mut roles = deserialize_api_key_roles(row.get::<_, String>(6))?;
    if is_admin && !roles.contains(&ApiKeyRole::Admin) {
        roles = ApiKeyRole::admin_roles();
    }

    Ok(Some(StoredCredential {
        is_admin,
        id,
        org_id: row.get(1),
        credential_type: CredentialKind::from_str(row.get::<_, String>(2).as_str())?,
        key_hash: row.get(3),
        expires_at: row.get(4),
        revoked: row.get::<_, bool>(5),
        roles,
    }))
}

#[derive(Debug)]
struct LatestEntrySummary {
    sequence: i64,
    entry_id: String,
    ledger_root_hash: String,
}

#[derive(Debug)]
struct RawSignedCheckpointRow {
    checkpoint_id: String,
    created_at: String,
    sequence: i64,
    entry_id: String,
    ledger_root_hash: String,
    checkpoint_hash: String,
    signature: String,
    key_id: String,
    algorithm: String,
    public_key: String,
    fingerprint: String,
    label: Option<String>,
    key_created_at: String,
}

#[derive(Debug, Default)]
struct ActiveHoldScope {
    global: bool,
    org_ids: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialKind {
    ApiKey,
    ServiceAccount,
}

impl FromStr for CredentialKind {
    type Err = StorageError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "api_key" => Ok(Self::ApiKey),
            "service_account" => Ok(Self::ServiceAccount),
            other => Err(StorageError::InvalidCredentialType(other.to_string())),
        }
    }
}

impl CredentialKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::ServiceAccount => "service_account",
        }
    }
}

#[derive(Debug, Clone)]
struct StoredCredential {
    id: String,
    org_id: String,
    credential_type: CredentialKind,
    key_hash: String,
    expires_at: Option<String>,
    revoked: bool,
    is_admin: bool,
    roles: Vec<ApiKeyRole>,
}

#[derive(Debug, Clone)]
struct StoredHumanUser {
    id: String,
    org_id: String,
    email: String,
    password_hash: String,
    created_at: String,
    last_authenticated_at: Option<String>,
    pending_mfa_secret: Option<String>,
    mfa_secret: Option<String>,
    mfa_enabled: bool,
}

#[derive(Debug, Clone)]
struct StoredAuthChallenge {
    id: String,
    user_id: String,
    org_id: String,
    expires_at: String,
    used_at: Option<String>,
}

#[derive(Debug, Clone)]
struct StoredSession {
    id: String,
    session_hash: String,
    expires_at: String,
}

#[derive(Debug)]
struct RawStoredAuthAuditEntry {
    id: String,
    timestamp: String,
    event_type: String,
    org_id: Option<String>,
    actor_type: String,
    actor_id: Option<String>,
    subject_type: String,
    subject_id: String,
    payload: String,
    outcome: String,
    previous_hash: String,
    entry_hash: String,
}

async fn load_latest_entry_summary(
    client: &impl GenericClient,
) -> Result<Option<LatestEntrySummary>> {
    client
        .query_opt(
            "SELECT sequence, id, entry_hash
             FROM action_log
             ORDER BY sequence DESC
             LIMIT 1",
            &[],
        )
        .await
        .map_err(pg_err)?
        .map(|row| {
            Ok(LatestEntrySummary {
                sequence: row.get(0),
                entry_id: row.get(1),
                ledger_root_hash: row.get(2),
            })
        })
        .transpose()
}

async fn create_signed_checkpoint(
    client: &mut Client,
    signer: &CheckpointSigner,
    anchors: &[ExternalAnchorInput],
) -> Result<SignedCheckpoint> {
    let latest = load_latest_entry_summary(client).await?.ok_or_else(|| {
        StorageError::InvalidInput("cannot create checkpoint for an empty ledger".to_string())
    })?;
    let created_at = ActionEntry::canonical_timestamp(&current_time());
    let checkpoint_id = Uuid::new_v4().to_string();
    let payload = CheckpointPayload {
        checkpoint_id: checkpoint_id.clone(),
        created_at: created_at.clone(),
        sequence: latest.sequence,
        entry_id: latest.entry_id.clone(),
        ledger_root_hash: latest.ledger_root_hash.clone(),
    };
    let checkpoint_hash_value = checkpoint_hash(&payload);
    let signature = signer.sign_checkpoint_hash(&checkpoint_hash_value);

    let tx = client.transaction().await.map_err(pg_err)?;
    upsert_checkpoint_signing_key(&tx, signer.metadata()).await?;
    tx.execute(
        "INSERT INTO signed_checkpoints (
            checkpoint_id,
            created_at,
            sequence,
            entry_id,
            ledger_root_hash,
            checkpoint_hash,
            signature,
            key_id
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &[
            &checkpoint_id,
            &created_at,
            &latest.sequence,
            &latest.entry_id,
            &latest.ledger_root_hash,
            &checkpoint_hash_value,
            &signature,
            &signer.metadata().key_id,
        ],
    )
    .await
    .map_err(pg_err)?;

    for anchor in anchors {
        let provider = anchor.provider.trim();
        let reference = anchor.reference.trim();
        if provider.is_empty() || reference.is_empty() {
            return Err(StorageError::InvalidInput(
                "external anchors require non-empty provider and reference".to_string(),
            ));
        }
        let anchored_at = anchor
            .anchored_at
            .clone()
            .unwrap_or_else(|| ActionEntry::canonical_timestamp(&current_time()));
        tx.execute(
            "INSERT INTO checkpoint_anchors (
                anchor_id,
                checkpoint_id,
                provider,
                reference,
                anchored_at,
                anchored_hash,
                metadata
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &Uuid::new_v4().to_string(),
                &payload.checkpoint_id,
                &provider,
                &reference,
                &anchored_at,
                &checkpoint_hash_value,
                &anchor.metadata.to_string(),
            ],
        )
        .await
        .map_err(pg_err)?;
    }

    tx.commit().await.map_err(pg_err)?;
    load_signed_checkpoint(client, &payload.checkpoint_id)
        .await?
        .ok_or_else(|| StorageError::Checkpoint("checkpoint was not persisted".to_string()))
}

async fn upsert_checkpoint_signing_key(
    client: &impl GenericClient,
    metadata: &SigningKeyMetadata,
) -> Result<()> {
    let existing = client
        .query_opt(
            "SELECT algorithm, public_key, fingerprint, label, created_at
             FROM checkpoint_signing_keys
             WHERE key_id = $1",
            &[&metadata.key_id],
        )
        .await
        .map_err(pg_err)?;

    if let Some(row) = existing {
        let existing = SigningKeyMetadata {
            key_id: metadata.key_id.clone(),
            algorithm: parse_signature_algorithm(row.get::<_, String>(0).as_str())?,
            public_key: row.get(1),
            fingerprint: row.get(2),
            label: row.get(3),
            created_at: row.get(4),
        };
        if existing != *metadata {
            return Err(StorageError::Checkpoint(format!(
                "checkpoint signing key '{}' metadata does not match existing record",
                metadata.key_id
            )));
        }
        return Ok(());
    }

    client
        .execute(
            "INSERT INTO checkpoint_signing_keys (
                key_id,
                algorithm,
                public_key,
                fingerprint,
                label,
                created_at
             ) VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &metadata.key_id,
                &metadata.algorithm.to_string(),
                &metadata.public_key,
                &metadata.fingerprint,
                &metadata.label,
                &metadata.created_at,
            ],
        )
        .await
        .map_err(pg_err)?;

    Ok(())
}

async fn load_signed_checkpoints(client: &impl GenericClient) -> Result<Vec<SignedCheckpoint>> {
    let rows = client
        .query(
            "SELECT
                c.checkpoint_id,
                c.created_at,
                c.sequence,
                c.entry_id,
                c.ledger_root_hash,
                c.checkpoint_hash,
                c.signature,
                c.key_id,
                k.algorithm,
                k.public_key,
                k.fingerprint,
                k.label,
                k.created_at
             FROM signed_checkpoints c
             JOIN checkpoint_signing_keys k ON k.key_id = c.key_id
             ORDER BY c.created_at DESC, c.checkpoint_id DESC",
            &[],
        )
        .await
        .map_err(pg_err)?;

    let mut checkpoints = Vec::with_capacity(rows.len());
    for row in rows {
        checkpoints.push(parse_signed_checkpoint(client, &row).await?);
    }
    Ok(checkpoints)
}

async fn load_signed_checkpoint(
    client: &impl GenericClient,
    checkpoint_id: &str,
) -> Result<Option<SignedCheckpoint>> {
    let row = client
        .query_opt(
            "SELECT
                c.checkpoint_id,
                c.created_at,
                c.sequence,
                c.entry_id,
                c.ledger_root_hash,
                c.checkpoint_hash,
                c.signature,
                c.key_id,
                k.algorithm,
                k.public_key,
                k.fingerprint,
                k.label,
                k.created_at
             FROM signed_checkpoints c
             JOIN checkpoint_signing_keys k ON k.key_id = c.key_id
             WHERE c.checkpoint_id = $1",
            &[&checkpoint_id],
        )
        .await
        .map_err(pg_err)?;

    match row {
        Some(row) => Ok(Some(parse_signed_checkpoint(client, &row).await?)),
        None => Ok(None),
    }
}

async fn load_latest_signed_checkpoint(
    client: &impl GenericClient,
) -> Result<Option<SignedCheckpoint>> {
    let checkpoint_id = client
        .query_opt(
            "SELECT checkpoint_id
             FROM signed_checkpoints
             ORDER BY created_at DESC, checkpoint_id DESC
             LIMIT 1",
            &[],
        )
        .await
        .map_err(pg_err)?
        .map(|row| row.get::<_, String>(0));

    match checkpoint_id {
        Some(checkpoint_id) => load_signed_checkpoint(client, &checkpoint_id).await,
        None => Ok(None),
    }
}

async fn parse_signed_checkpoint(
    client: &impl GenericClient,
    row: &Row,
) -> Result<SignedCheckpoint> {
    let raw = RawSignedCheckpointRow {
        checkpoint_id: row.get(0),
        created_at: row.get(1),
        sequence: row.get(2),
        entry_id: row.get(3),
        ledger_root_hash: row.get(4),
        checkpoint_hash: row.get(5),
        signature: row.get(6),
        key_id: row.get(7),
        algorithm: row.get(8),
        public_key: row.get(9),
        fingerprint: row.get(10),
        label: row.get(11),
        key_created_at: row.get(12),
    };

    Ok(SignedCheckpoint {
        checkpoint_id: raw.checkpoint_id.clone(),
        created_at: raw.created_at,
        sequence: raw.sequence,
        entry_id: raw.entry_id,
        ledger_root_hash: raw.ledger_root_hash,
        checkpoint_hash: raw.checkpoint_hash,
        signature: raw.signature,
        key: SigningKeyMetadata {
            key_id: raw.key_id,
            algorithm: parse_signature_algorithm(&raw.algorithm)?,
            public_key: raw.public_key,
            fingerprint: raw.fingerprint,
            label: raw.label,
            created_at: raw.key_created_at,
        },
        anchors: load_checkpoint_anchors(client, &raw.checkpoint_id).await?,
    })
}

async fn load_checkpoint_anchors(
    client: &impl GenericClient,
    checkpoint_id: &str,
) -> Result<Vec<ExternalAnchorRecord>> {
    client
        .query(
            "SELECT anchor_id, provider, reference, anchored_at, anchored_hash, metadata
             FROM checkpoint_anchors
             WHERE checkpoint_id = $1
             ORDER BY anchored_at ASC, anchor_id ASC",
            &[&checkpoint_id],
        )
        .await
        .map_err(pg_err)?
        .into_iter()
        .map(|row| {
            Ok(ExternalAnchorRecord {
                anchor_id: row.get(0),
                provider: row.get(1),
                reference: row.get(2),
                anchored_at: row.get(3),
                anchored_hash: row.get(4),
                metadata: serde_json::from_str(row.get::<_, String>(5).as_str())?,
            })
        })
        .collect()
}

async fn verify_signed_checkpoint(
    client: &impl GenericClient,
    checkpoint_id: Option<&str>,
) -> Result<Option<VerifiedCheckpoint>> {
    let checkpoint = match checkpoint_id {
        Some(checkpoint_id) => load_signed_checkpoint(client, checkpoint_id).await?,
        None => load_latest_signed_checkpoint(client).await?,
    };
    checkpoint.map(verify_loaded_checkpoint).transpose()
}

fn verify_loaded_checkpoint(checkpoint: SignedCheckpoint) -> Result<VerifiedCheckpoint> {
    let payload = CheckpointPayload {
        checkpoint_id: checkpoint.checkpoint_id.clone(),
        created_at: checkpoint.created_at.clone(),
        sequence: checkpoint.sequence,
        entry_id: checkpoint.entry_id.clone(),
        ledger_root_hash: checkpoint.ledger_root_hash.clone(),
    };
    let verification = verify_checkpoint_signature(
        &payload,
        &checkpoint.checkpoint_hash,
        &checkpoint.signature,
        &checkpoint.key,
    )?;
    let anchor_hashes_valid = checkpoint
        .anchors
        .iter()
        .all(|anchor| anchor.anchored_hash == checkpoint.checkpoint_hash);
    Ok(VerifiedCheckpoint {
        verified: verification.verified && anchor_hashes_valid,
        checkpoint,
        verification,
        anchor_hashes_valid,
    })
}

fn parse_signature_algorithm(value: &str) -> Result<SignatureAlgorithm> {
    match value {
        "ed25519" => Ok(SignatureAlgorithm::Ed25519),
        "ecdsa_p256_sha256" => Ok(SignatureAlgorithm::EcdsaP256Sha256),
        other => Err(StorageError::Checkpoint(format!(
            "unknown checkpoint signature algorithm: {other}"
        ))),
    }
}

async fn create_legal_hold(
    client: &mut Client,
    org_id: Option<&str>,
    matter: &str,
    reason: &str,
    created_at: DateTime<Utc>,
) -> Result<LegalHoldRecord> {
    let matter = matter.trim();
    let reason = reason.trim();
    if matter.is_empty() {
        return Err(StorageError::InvalidInput(
            "legal hold matter must not be empty".to_string(),
        ));
    }
    if reason.is_empty() {
        return Err(StorageError::InvalidInput(
            "legal hold reason must not be empty".to_string(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let created_at = ActionEntry::canonical_timestamp(&created_at);
    let org_id = org_id
        .map(str::trim)
        .filter(|org_id| !org_id.is_empty())
        .map(ToString::to_string);

    let tx = client.transaction().await.map_err(pg_err)?;
    tx.execute(
        "INSERT INTO legal_holds (
            id,
            org_id,
            matter,
            reason,
            created_at,
            released_at,
            release_reason
         ) VALUES ($1, $2, $3, $4, $5, NULL, NULL)",
        &[&id, &org_id, &matter, &reason, &created_at],
    )
    .await
    .map_err(pg_err)?;
    insert_legal_hold_event(
        &tx,
        &id,
        org_id.as_deref(),
        "created",
        &created_at,
        &format!("created legal hold for {matter}"),
    )
    .await?;
    tx.commit().await.map_err(pg_err)?;

    Ok(LegalHoldRecord {
        id,
        org_id,
        matter: matter.to_string(),
        reason: reason.to_string(),
        created_at,
        released_at: None,
        release_reason: None,
    })
}

async fn release_legal_hold(
    client: &mut Client,
    hold_id: &str,
    released_at: DateTime<Utc>,
    release_reason: &str,
) -> Result<Option<LegalHoldRecord>> {
    let release_reason = release_reason.trim();
    if release_reason.is_empty() {
        return Err(StorageError::InvalidInput(
            "legal hold release reason must not be empty".to_string(),
        ));
    }

    let tx = client.transaction().await.map_err(pg_err)?;
    let Some(mut hold) = load_legal_hold(&tx, hold_id).await? else {
        tx.rollback().await.map_err(pg_err)?;
        return Ok(None);
    };
    if hold.released_at.is_some() {
        tx.rollback().await.map_err(pg_err)?;
        return Ok(Some(hold));
    }

    let released_at = ActionEntry::canonical_timestamp(&released_at);
    tx.execute(
        "UPDATE legal_holds
         SET released_at = $2,
             release_reason = $3
         WHERE id = $1",
        &[&hold_id, &released_at, &release_reason],
    )
    .await
    .map_err(pg_err)?;
    insert_legal_hold_event(
        &tx,
        hold_id,
        hold.org_id.as_deref(),
        "released",
        &released_at,
        release_reason,
    )
    .await?;
    tx.commit().await.map_err(pg_err)?;

    hold.released_at = Some(released_at);
    hold.release_reason = Some(release_reason.to_string());
    Ok(Some(hold))
}

async fn load_legal_holds(
    client: &impl GenericClient,
    org_id: Option<&str>,
) -> Result<Vec<LegalHoldRecord>> {
    let rows = match org_id {
        Some(org_id) => client
            .query(
                "SELECT id, org_id, matter, reason, created_at, released_at, release_reason
                 FROM legal_holds
                 WHERE org_id = $1
                 ORDER BY created_at ASC, id ASC",
                &[&org_id],
            )
            .await
            .map_err(pg_err)?,
        None => client
            .query(
                "SELECT id, org_id, matter, reason, created_at, released_at, release_reason
                 FROM legal_holds
                 ORDER BY created_at ASC, id ASC",
                &[],
            )
            .await
            .map_err(pg_err)?,
    };

    Ok(rows
        .into_iter()
        .map(|row| LegalHoldRecord {
            id: row.get(0),
            org_id: row.get(1),
            matter: row.get(2),
            reason: row.get(3),
            created_at: row.get(4),
            released_at: row.get(5),
            release_reason: row.get(6),
        })
        .collect())
}

async fn load_legal_hold_events(
    client: &impl GenericClient,
    hold_id: &str,
) -> Result<Vec<LegalHoldEvent>> {
    let events = client
        .query(
            "SELECT id, hold_id, org_id, event_type, occurred_at, detail
             FROM legal_hold_events
             WHERE hold_id = $1
             ORDER BY occurred_at ASC, id ASC",
            &[&hold_id],
        )
        .await
        .map_err(pg_err)?
        .into_iter()
        .map(|row| LegalHoldEvent {
            id: row.get(0),
            hold_id: row.get(1),
            org_id: row.get(2),
            event_type: row.get(3),
            occurred_at: row.get(4),
            detail: row.get(5),
        })
        .collect::<Vec<_>>();
    Ok(events)
}

async fn load_legal_hold(
    client: &impl GenericClient,
    hold_id: &str,
) -> Result<Option<LegalHoldRecord>> {
    client
        .query_opt(
            "SELECT id, org_id, matter, reason, created_at, released_at, release_reason
             FROM legal_holds
             WHERE id = $1",
            &[&hold_id],
        )
        .await
        .map_err(pg_err)?
        .map(|row| {
            Ok(LegalHoldRecord {
                id: row.get(0),
                org_id: row.get(1),
                matter: row.get(2),
                reason: row.get(3),
                created_at: row.get(4),
                released_at: row.get(5),
                release_reason: row.get(6),
            })
        })
        .transpose()
}

async fn insert_legal_hold_event(
    client: &impl GenericClient,
    hold_id: &str,
    org_id: Option<&str>,
    event_type: &str,
    occurred_at: &str,
    detail: &str,
) -> Result<()> {
    client
        .execute(
            "INSERT INTO legal_hold_events (
                id,
                hold_id,
                org_id,
                event_type,
                occurred_at,
                detail
             ) VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &Uuid::new_v4().to_string(),
                &hold_id,
                &org_id,
                &event_type,
                &occurred_at,
                &detail,
            ],
        )
        .await
        .map_err(pg_err)?;
    Ok(())
}

async fn load_active_hold_scope(client: &impl GenericClient) -> Result<ActiveHoldScope> {
    let rows = client
        .query(
            "SELECT org_id
             FROM legal_holds
             WHERE released_at IS NULL",
            &[],
        )
        .await
        .map_err(pg_err)?;
    let mut scope = ActiveHoldScope::default();
    for row in rows {
        match row.get::<_, Option<String>>(0) {
            Some(org_id) => {
                scope.org_ids.insert(org_id);
            }
            None => scope.global = true,
        }
    }
    Ok(scope)
}

async fn create_human_user(
    client: &mut Client,
    org_id: &str,
    email: &str,
    password: &str,
) -> Result<HumanUserRecord> {
    let org_id = org_id.trim();
    let email = normalize_email(email)?;
    let password = password.trim();

    if org_id.is_empty() {
        return Err(StorageError::InvalidInput(
            "organization id must not be empty".to_string(),
        ));
    }
    if password.is_empty() {
        return Err(StorageError::InvalidInput(
            "password must not be empty".to_string(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let created_at = ActionEntry::canonical_timestamp(&current_time());
    let password_hash = bcrypt_hash(password)?;
    client
        .execute(
            "INSERT INTO human_users (
                id,
                org_id,
                email,
                password_hash,
                created_at,
                last_authenticated_at,
                pending_mfa_secret,
                mfa_secret,
                mfa_enabled,
                mfa_enrolled_at
             ) VALUES ($1, $2, $3, $4, $5, NULL, NULL, NULL, FALSE, NULL)",
            &[&id, &org_id, &email, &password_hash, &created_at],
        )
        .await
        .map_err(pg_err)?;

    load_human_user_record(client, org_id, &email)
        .await?
        .ok_or_else(|| StorageError::InvalidInput("created user could not be reloaded".to_string()))
}

async fn load_human_user_record(
    client: &impl GenericClient,
    org_id: &str,
    email: &str,
) -> Result<Option<HumanUserRecord>> {
    let email = normalize_email(email)?;
    let user = load_human_user(client, org_id.trim(), &email).await?;
    match user {
        Some(user) => Ok(Some(human_user_record(client, user).await?)),
        None => Ok(None),
    }
}

async fn human_user_record(
    client: &impl GenericClient,
    user: StoredHumanUser,
) -> Result<HumanUserRecord> {
    Ok(HumanUserRecord {
        id: user.id,
        org_id: user.org_id.clone(),
        email: user.email,
        created_at: user.created_at,
        last_authenticated_at: user.last_authenticated_at,
        mfa_enabled: user.mfa_enabled,
        mfa_policy: load_org_mfa_policy(client, &user.org_id).await?,
    })
}

async fn load_org_mfa_policy(client: &impl GenericClient, org_id: &str) -> Result<MfaPolicy> {
    let value = client
        .query_opt(
            "SELECT policy FROM org_mfa_policies WHERE org_id = $1",
            &[&org_id],
        )
        .await
        .map_err(pg_err)?
        .map(|row| row.get::<_, String>(0));

    match value.as_deref() {
        None => Ok(MfaPolicy::Optional),
        Some("optional") => Ok(MfaPolicy::Optional),
        Some("required") => Ok(MfaPolicy::Required),
        Some(other) => Err(StorageError::InvalidInput(format!(
            "invalid mfa policy: {other}"
        ))),
    }
}

async fn set_org_mfa_policy(
    client: &mut Client,
    org_id: &str,
    policy: MfaPolicy,
) -> Result<MfaPolicy> {
    let org_id = org_id.trim();
    if org_id.is_empty() {
        return Err(StorageError::InvalidInput(
            "organization id must not be empty".to_string(),
        ));
    }

    client
        .execute(
            "INSERT INTO org_mfa_policies (org_id, policy, updated_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (org_id) DO UPDATE
             SET policy = EXCLUDED.policy, updated_at = EXCLUDED.updated_at",
            &[
                &org_id,
                &policy.as_str(),
                &ActionEntry::canonical_timestamp(&current_time()),
            ],
        )
        .await
        .map_err(pg_err)?;

    Ok(policy)
}

async fn start_mfa_enrollment(
    client: &mut Client,
    org_id: &str,
    email: &str,
    password: &str,
) -> Result<MfaEnrollmentStart> {
    let user = authenticate_human_user(client, org_id.trim(), email, password).await?;
    if user.mfa_enabled {
        return Err(StorageError::MfaAlreadyEnabled);
    }

    let secret = generate_totp_secret().map_err(StorageError::Command)?;
    client
        .execute(
            "UPDATE human_users SET pending_mfa_secret = $2 WHERE id = $1",
            &[&user.id, &secret],
        )
        .await
        .map_err(pg_err)?;

    Ok(MfaEnrollmentStart {
        user_id: user.id,
        org_id: user.org_id,
        email: user.email.clone(),
        provisioning_uri: provisioning_uri(&user.email, &secret),
        secret,
    })
}

async fn confirm_mfa_enrollment(
    client: &mut Client,
    org_id: &str,
    email: &str,
    password: &str,
    code: &str,
    as_of: DateTime<Utc>,
) -> Result<MfaEnrollmentConfirm> {
    let user = authenticate_human_user(client, org_id.trim(), email, password).await?;
    if user.mfa_enabled {
        return Err(StorageError::MfaAlreadyEnabled);
    }
    let Some(secret) = user.pending_mfa_secret.clone() else {
        return Err(StorageError::MfaPendingEnrollment);
    };
    if !verify_totp(&secret, code, as_of).map_err(StorageError::Command)? {
        return Err(StorageError::InvalidMfaCode);
    }

    let recovery_codes = generate_recovery_codes(RecoveryCodeCount::Default);
    let tx = client.transaction().await.map_err(pg_err)?;
    let authenticated_at = ActionEntry::canonical_timestamp(&as_of);
    tx.execute(
        "UPDATE human_users
         SET pending_mfa_secret = NULL,
             mfa_secret = $2,
             mfa_enabled = TRUE,
             mfa_enrolled_at = $3,
             last_authenticated_at = $3
         WHERE id = $1",
        &[&user.id, &secret, &authenticated_at],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "DELETE FROM human_recovery_codes WHERE user_id = $1",
        &[&user.id],
    )
    .await
    .map_err(pg_err)?;

    for code in &recovery_codes {
        tx.execute(
            "INSERT INTO human_recovery_codes (
                id,
                user_id,
                code_hash,
                created_at,
                used_at
             ) VALUES ($1, $2, $3, $4, NULL)",
            &[
                &Uuid::new_v4().to_string(),
                &user.id,
                &bcrypt_hash(code)?,
                &authenticated_at,
            ],
        )
        .await
        .map_err(pg_err)?;
    }

    tx.commit().await.map_err(pg_err)?;

    Ok(MfaEnrollmentConfirm {
        user_id: user.id,
        org_id: user.org_id,
        email: user.email,
        recovery_codes,
    })
}

async fn create_mfa_challenge(
    client: &mut Client,
    org_id: &str,
    email: &str,
    password: &str,
    as_of: DateTime<Utc>,
) -> Result<MfaChallengeStart> {
    let user = authenticate_human_user(client, org_id.trim(), email, password).await?;
    let policy = load_org_mfa_policy(client, &user.org_id).await?;

    if user.mfa_enabled {
        let challenge_id = Uuid::new_v4().to_string();
        let created_at = ActionEntry::canonical_timestamp(&as_of);
        let expires_at = ActionEntry::canonical_timestamp(&(as_of + chrono::Duration::minutes(10)));
        client
            .execute(
                "INSERT INTO auth_challenges (
                    id,
                    user_id,
                    org_id,
                    created_at,
                    expires_at,
                    used_at
                 ) VALUES ($1, $2, $3, $4, $5, NULL)",
                &[
                    &challenge_id,
                    &user.id,
                    &user.org_id,
                    &created_at,
                    &expires_at,
                ],
            )
            .await
            .map_err(pg_err)?;

        return Ok(MfaChallengeStart::ChallengeRequired {
            user_id: user.id,
            org_id: user.org_id,
            email: user.email,
            challenge_id,
            expires_at,
        });
    }

    if policy == MfaPolicy::Required {
        return Ok(MfaChallengeStart::EnrollmentRequired {
            user_id: user.id,
            org_id: user.org_id,
            email: user.email,
        });
    }

    client
        .execute(
            "UPDATE human_users SET last_authenticated_at = $2 WHERE id = $1",
            &[&user.id, &ActionEntry::canonical_timestamp(&as_of)],
        )
        .await
        .map_err(pg_err)?;

    Ok(MfaChallengeStart::Authenticated {
        user_id: user.id,
        org_id: user.org_id,
        email: user.email,
    })
}

async fn verify_mfa_challenge(
    client: &mut Client,
    challenge_id: &str,
    code: &str,
    as_of: DateTime<Utc>,
) -> Result<MfaChallengeVerify> {
    let challenge = load_auth_challenge(client, challenge_id.trim())
        .await?
        .ok_or(StorageError::AuthChallengeNotFound)?;
    if challenge.used_at.is_some() {
        return Err(StorageError::AuthChallengeUsed);
    }

    let expires_at = DateTime::parse_from_rfc3339(&challenge.expires_at)?.with_timezone(&Utc);
    if as_of > expires_at {
        return Err(StorageError::AuthChallengeExpired);
    }

    let user = load_human_user_by_id(client, &challenge.user_id)
        .await?
        .ok_or(StorageError::AuthChallengeNotFound)?;
    if !user.mfa_enabled {
        return Err(StorageError::MfaNotEnabled);
    }
    let Some(secret) = user.mfa_secret.clone() else {
        return Err(StorageError::MfaNotEnabled);
    };

    let verified_method = if verify_totp(&secret, code, as_of).map_err(StorageError::Command)? {
        ("totp".to_string(), false)
    } else if consume_recovery_code(client, &user.id, code, as_of).await? {
        ("recovery_code".to_string(), true)
    } else {
        return Err(StorageError::InvalidMfaCode);
    };

    let authenticated_at = ActionEntry::canonical_timestamp(&as_of);
    client
        .execute(
            "UPDATE auth_challenges SET used_at = $2 WHERE id = $1",
            &[&challenge.id, &authenticated_at],
        )
        .await
        .map_err(pg_err)?;
    client
        .execute(
            "UPDATE human_users SET last_authenticated_at = $2 WHERE id = $1",
            &[&user.id, &authenticated_at],
        )
        .await
        .map_err(pg_err)?;

    Ok(MfaChallengeVerify {
        user_id: user.id,
        org_id: challenge.org_id,
        email: user.email,
        method: verified_method.0,
        recovery_code_used: verified_method.1,
    })
}

async fn provision_sso_user(
    client: &mut Client,
    org_id: &str,
    external_subject: &str,
    email: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    role: &str,
) -> Result<UserRecord> {
    let org_id = require_non_empty(org_id, "organization id")?;
    let external_subject = require_non_empty(external_subject, "external subject")?;
    let email = require_non_empty(email, "email")?;
    let role = normalize_internal_role(role)?;
    let first_name = optional_trimmed(first_name.map(ToString::to_string));
    let last_name = optional_trimmed(last_name.map(ToString::to_string));
    let display_name = user_display_name(&email, first_name.as_deref(), last_name.as_deref());
    let now = ActionEntry::canonical_timestamp(&current_time());

    let existing =
        load_user_for_subject_or_email(client, &org_id, &external_subject, &email).await?;
    let user_id = existing
        .as_ref()
        .map(|user| user.id.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let created_at = existing
        .as_ref()
        .map(|user| user.created_at.clone())
        .unwrap_or_else(|| now.clone());

    client
        .execute(
            "INSERT INTO users (
                id,
                org_id,
                external_subject,
                email,
                first_name,
                last_name,
                display_name,
                role,
                created_at,
                last_login_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (id) DO UPDATE SET
                external_subject = EXCLUDED.external_subject,
                email = EXCLUDED.email,
                first_name = EXCLUDED.first_name,
                last_name = EXCLUDED.last_name,
                display_name = EXCLUDED.display_name,
                role = EXCLUDED.role,
                last_login_at = EXCLUDED.last_login_at",
            &[
                &user_id,
                &org_id,
                &external_subject,
                &email,
                &first_name,
                &last_name,
                &display_name,
                &role,
                &created_at,
                &now,
            ],
        )
        .await
        .map_err(pg_err)?;

    load_user_by_id(client, &user_id).await?.ok_or_else(|| {
        StorageError::InvalidInput("failed to load provisioned SSO user".to_string())
    })
}

async fn create_sso_session(
    client: &mut Client,
    user: &UserRecord,
    ttl: Duration,
) -> Result<CreatedSession> {
    let created_at = ActionEntry::canonical_timestamp(&current_time());
    let expires_at = ActionEntry::canonical_timestamp(
        &(current_time()
            + chrono::Duration::from_std(ttl).map_err(|error| {
                StorageError::InvalidInput(format!("invalid session ttl: {error}"))
            })?),
    );
    let id = Uuid::new_v4().to_string();
    let secret = format!(
        "{}{}",
        Uuid::new_v4().to_string().replace('-', ""),
        Uuid::new_v4().to_string().replace('-', "")
    );
    let token = format!("{SESSION_TOKEN_PREFIX}{id}_{secret}");
    let session_hash = hash_session_secret(&secret);

    client
        .execute(
            "INSERT INTO auth_sessions (
                id,
                user_id,
                org_id,
                session_hash,
                created_at,
                expires_at,
                last_used_at
             ) VALUES ($1, $2, $3, $4, $5, $6, NULL)",
            &[
                &id,
                &user.id,
                &user.org_id,
                &session_hash,
                &created_at,
                &expires_at,
            ],
        )
        .await
        .map_err(pg_err)?;

    Ok(CreatedSession {
        id,
        org_id: user.org_id.clone(),
        token,
        created_at,
        expires_at,
        user: user.clone(),
    })
}

async fn authenticate_session(
    client: &mut Client,
    raw_token: &str,
) -> Result<Option<AuthenticatedSession>> {
    let Some((session_id, secret)) = parse_session_token(raw_token) else {
        return Ok(None);
    };

    let Some(stored_session) = load_session(client, &session_id).await? else {
        return Ok(None);
    };
    let provided_hash = hash_session_secret(&secret);
    if !constant_time_eq(
        provided_hash.as_bytes(),
        stored_session.session_hash.as_bytes(),
    ) {
        return Ok(None);
    }

    let expires_at = DateTime::parse_from_rfc3339(&stored_session.expires_at)?.with_timezone(&Utc);
    if expires_at <= current_time() {
        return Ok(None);
    }

    client
        .execute(
            "UPDATE auth_sessions SET last_used_at = $2 WHERE id = $1",
            &[
                &stored_session.id,
                &ActionEntry::canonical_timestamp(&current_time()),
            ],
        )
        .await
        .map_err(pg_err)?;

    load_authenticated_session(client, &stored_session.id).await
}

async fn authenticate_human_user(
    client: &impl GenericClient,
    org_id: &str,
    email: &str,
    password: &str,
) -> Result<StoredHumanUser> {
    let email = normalize_email(email)?;
    let stored_user = load_human_user(client, org_id, &email).await?;
    let hash_to_check = stored_user
        .as_ref()
        .map(|user| user.password_hash.as_str())
        .unwrap_or(DUMMY_BCRYPT_HASH);
    let verified = bcrypt_verify(password.trim(), hash_to_check)?;

    match (stored_user, verified) {
        (Some(user), true) => Ok(user),
        _ => Err(StorageError::AuthenticationFailed),
    }
}

async fn load_human_user(
    client: &impl GenericClient,
    org_id: &str,
    email: &str,
) -> Result<Option<StoredHumanUser>> {
    client
        .query_opt(
            "SELECT id, org_id, email, password_hash, created_at, last_authenticated_at,
                    pending_mfa_secret, mfa_secret, mfa_enabled
             FROM human_users
             WHERE org_id = $1 AND email = $2",
            &[&org_id, &email],
        )
        .await
        .map_err(pg_err)?
        .map(|row| {
            Ok(StoredHumanUser {
                id: row.get(0),
                org_id: row.get(1),
                email: row.get(2),
                password_hash: row.get(3),
                created_at: row.get(4),
                last_authenticated_at: row.get(5),
                pending_mfa_secret: row.get(6),
                mfa_secret: row.get(7),
                mfa_enabled: row.get::<_, bool>(8),
            })
        })
        .transpose()
}

async fn load_human_user_by_id(
    client: &impl GenericClient,
    user_id: &str,
) -> Result<Option<StoredHumanUser>> {
    client
        .query_opt(
            "SELECT id, org_id, email, password_hash, created_at, last_authenticated_at,
                    pending_mfa_secret, mfa_secret, mfa_enabled
             FROM human_users
             WHERE id = $1",
            &[&user_id],
        )
        .await
        .map_err(pg_err)?
        .map(|row| {
            Ok(StoredHumanUser {
                id: row.get(0),
                org_id: row.get(1),
                email: row.get(2),
                password_hash: row.get(3),
                created_at: row.get(4),
                last_authenticated_at: row.get(5),
                pending_mfa_secret: row.get(6),
                mfa_secret: row.get(7),
                mfa_enabled: row.get::<_, bool>(8),
            })
        })
        .transpose()
}

async fn load_auth_challenge(
    client: &impl GenericClient,
    challenge_id: &str,
) -> Result<Option<StoredAuthChallenge>> {
    client
        .query_opt(
            "SELECT id, user_id, org_id, expires_at, used_at
             FROM auth_challenges
             WHERE id = $1",
            &[&challenge_id],
        )
        .await
        .map_err(pg_err)?
        .map(|row| {
            Ok(StoredAuthChallenge {
                id: row.get(0),
                user_id: row.get(1),
                org_id: row.get(2),
                expires_at: row.get(3),
                used_at: row.get(4),
            })
        })
        .transpose()
}

async fn consume_recovery_code(
    client: &impl GenericClient,
    user_id: &str,
    code: &str,
    as_of: DateTime<Utc>,
) -> Result<bool> {
    let rows = client
        .query(
            "SELECT id, code_hash
             FROM human_recovery_codes
             WHERE user_id = $1 AND used_at IS NULL
             ORDER BY created_at ASC, id ASC",
            &[&user_id],
        )
        .await
        .map_err(pg_err)?;

    for row in rows {
        let id: String = row.get(0);
        let code_hash: String = row.get(1);
        if bcrypt_verify(code.trim(), &code_hash)? {
            client
                .execute(
                    "UPDATE human_recovery_codes SET used_at = $2 WHERE id = $1",
                    &[&id, &ActionEntry::canonical_timestamp(&as_of)],
                )
                .await
                .map_err(pg_err)?;
            return Ok(true);
        }
    }

    Ok(false)
}

async fn load_user_by_id(client: &impl GenericClient, user_id: &str) -> Result<Option<UserRecord>> {
    let row = client
        .query_opt(
            "SELECT id, org_id, external_subject, email, first_name, last_name, display_name, role,
                    created_at, last_login_at
             FROM users
             WHERE id = $1",
            &[&user_id],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.map(|row| UserRecord {
        id: row.get(0),
        org_id: row.get(1),
        external_subject: row.get(2),
        email: row.get(3),
        first_name: row.get(4),
        last_name: row.get(5),
        display_name: row.get(6),
        role: row.get(7),
        created_at: row.get(8),
        last_login_at: row.get(9),
    }))
}

async fn load_user_for_subject_or_email(
    client: &impl GenericClient,
    org_id: &str,
    external_subject: &str,
    email: &str,
) -> Result<Option<UserRecord>> {
    let row = client
        .query_opt(
            "SELECT id, org_id, external_subject, email, first_name, last_name, display_name, role,
                    created_at, last_login_at
             FROM users
             WHERE org_id = $1 AND (external_subject = $2 OR email = $3)
             ORDER BY CASE WHEN external_subject = $2 THEN 0 ELSE 1 END
             LIMIT 1",
            &[&org_id, &external_subject, &email],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.map(|row| UserRecord {
        id: row.get(0),
        org_id: row.get(1),
        external_subject: row.get(2),
        email: row.get(3),
        first_name: row.get(4),
        last_name: row.get(5),
        display_name: row.get(6),
        role: row.get(7),
        created_at: row.get(8),
        last_login_at: row.get(9),
    }))
}

async fn load_session(
    client: &impl GenericClient,
    session_id: &str,
) -> Result<Option<StoredSession>> {
    let row = client
        .query_opt(
            "SELECT id, user_id, org_id, session_hash, created_at, expires_at
             FROM auth_sessions
             WHERE id = $1",
            &[&session_id],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.map(|row| StoredSession {
        id: row.get(0),
        session_hash: row.get(3),
        expires_at: row.get(5),
    }))
}

async fn load_authenticated_session(
    client: &impl GenericClient,
    session_id: &str,
) -> Result<Option<AuthenticatedSession>> {
    let row = client
        .query_opt(
            "SELECT s.id, s.user_id, s.org_id, u.email, u.display_name, u.role, s.created_at, s.expires_at
             FROM auth_sessions s
             INNER JOIN users u ON u.id = s.user_id
             WHERE s.id = $1",
            &[&session_id],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.map(|row| AuthenticatedSession {
        id: row.get(0),
        user_id: row.get(1),
        org_id: row.get(2),
        email: row.get(3),
        display_name: row.get(4),
        role: row.get(5),
        created_at: row.get(6),
        expires_at: row.get(7),
    }))
}

async fn next_active_credential_id(client: &impl GenericClient) -> Result<Option<String>> {
    let now = ActionEntry::canonical_timestamp(&current_time());
    let row = client
        .query_opt(
            "SELECT id FROM credentials
             WHERE revoked = FALSE
               AND (expires_at IS NULL OR expires_at > $1)
             ORDER BY created_at ASC, id ASC
             LIMIT 1",
            &[&now],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.map(|row| row.get::<_, String>(0)))
}

fn serialize_api_key_roles(roles: &[ApiKeyRole]) -> Result<String> {
    serde_json::to_string(roles).map_err(StorageError::from)
}

fn deserialize_api_key_roles(value: String) -> Result<Vec<ApiKeyRole>> {
    serde_json::from_str(&value).map_err(StorageError::from)
}

#[allow(clippy::too_many_arguments)]
fn calculate_auth_audit_hash_parts(
    id: &Uuid,
    previous_hash: &str,
    timestamp: &DateTime<Utc>,
    event_type: AuthAuditEventType,
    org_id: Option<&str>,
    actor_type: &str,
    actor_id: Option<&str>,
    subject_type: &str,
    subject_id: &str,
    payload: &Value,
    outcome: &str,
) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(id.to_string().as_bytes());
    hasher.update(previous_hash.as_bytes());
    hasher.update(ActionEntry::canonical_timestamp(timestamp).as_bytes());
    hasher.update(event_type.to_string().as_bytes());
    hasher.update(org_id.unwrap_or_default().as_bytes());
    hasher.update(actor_type.as_bytes());
    hasher.update(actor_id.unwrap_or_default().as_bytes());
    hasher.update(subject_type.as_bytes());
    hasher.update(subject_id.as_bytes());
    hasher.update(payload.to_string().as_bytes());
    hasher.update(outcome.as_bytes());

    format!("{:x}", hasher.finalize())
}

fn parse_auth_audit_entry(raw: RawStoredAuthAuditEntry) -> Result<AuthAuditEntry> {
    let timestamp = DateTime::parse_from_rfc3339(&raw.timestamp)?.with_timezone(&Utc);
    let event_type =
        AuthAuditEventType::from_str(&raw.event_type).map_err(StorageError::InvalidInput)?;
    let payload = serde_json::from_str(&raw.payload)?;
    let id = Uuid::parse_str(&raw.id)?;
    let entry_hash = calculate_auth_audit_hash_parts(
        &id,
        &raw.previous_hash,
        &timestamp,
        event_type,
        raw.org_id.as_deref(),
        &raw.actor_type,
        raw.actor_id.as_deref(),
        &raw.subject_type,
        &raw.subject_id,
        &payload,
        &raw.outcome,
    );

    Ok(AuthAuditEntry {
        id,
        timestamp,
        event_type,
        org_id: raw.org_id,
        actor_type: raw.actor_type,
        actor_id: raw.actor_id,
        subject_type: raw.subject_type,
        subject_id: raw.subject_id,
        payload,
        outcome: raw.outcome,
        previous_hash: raw.previous_hash,
        entry_hash: if raw.entry_hash.is_empty() {
            entry_hash
        } else {
            raw.entry_hash
        },
    })
}

fn normalize_email(email: &str) -> Result<String> {
    let normalized = email.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(StorageError::InvalidInput(
            "email must not be empty".to_string(),
        ));
    }
    Ok(normalized)
}

fn credential_is_expired(expires_at: Option<&str>) -> Result<bool> {
    let Some(expires_at) = expires_at else {
        return Ok(false);
    };
    Ok(DateTime::parse_from_rfc3339(expires_at)?.with_timezone(&Utc) <= current_time())
}

fn user_display_name(email: &str, first_name: Option<&str>, last_name: Option<&str>) -> String {
    match (first_name, last_name) {
        (Some(first), Some(last)) => format!("{first} {last}"),
        (Some(first), None) => first.to_string(),
        (None, Some(last)) => last.to_string(),
        (None, None) => email.to_string(),
    }
}

fn hash_session_secret(secret: &str) -> String {
    hex::encode(sha2::Sha256::digest(secret.as_bytes()))
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

fn parse_session_token(raw_token: &str) -> Option<(String, String)> {
    let raw_token = raw_token.trim();
    let suffix = raw_token.strip_prefix(SESSION_TOKEN_PREFIX)?;
    let (id, secret) = suffix.split_once('_')?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((id.to_string(), secret.to_string()))
}

fn row_to_stored_entry(row: Row) -> Result<StoredEntry> {
    parse_stored_entry(RawStoredEntry {
        sequence: row.get(0),
        id: row.get(1),
        timestamp: row.get(2),
        agent_id: row.get(3),
        agent_type: row.get(4),
        session_id: row.get(5),
        action_type: row.get(6),
        payload: row.get(7),
        context: row.get(8),
        outcome: row.get(9),
        previous_hash: row.get(10),
        entry_hash: row.get(11),
        org_id: row.get(12),
    })
}

fn row_to_checkpoint(row: &Row) -> LedgerCheckpoint {
    LedgerCheckpoint {
        checkpoint_id: row.get(0),
        sequence: row.get(1),
        entry_id: row.get(2),
        entry_hash: row.get(3),
        merkle_root: row.get(4),
        created_at: row.get(5),
    }
}

fn pg_err(error: tokio_postgres::Error) -> StorageError {
    StorageError::Postgres(error.to_string())
}
