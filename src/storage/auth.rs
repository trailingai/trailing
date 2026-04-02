use std::collections::HashMap;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rusqlite::types::{Type as SqlType, Value as SqlValue};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::*;
use crate::auth::{
    RecoveryCodeCount, generate_recovery_codes, generate_totp_secret, provisioning_uri, verify_totp,
};

pub(crate) const API_KEY_PREFIX: &str = "trailing_";
const SESSION_TOKEN_PREFIX: &str = "trailing_session_";
const BCRYPT_PYTHON_SCRIPT: &str = r#"
import bcrypt
import sys

mode = sys.argv[1]

if mode == "hash":
    print(bcrypt.hashpw(sys.argv[2].encode(), bcrypt.gensalt()).decode())
elif mode == "verify":
    try:
        print("true" if bcrypt.checkpw(sys.argv[2].encode(), sys.argv[3].encode()) else "false")
    except ValueError:
        print("false")
"#;
pub(crate) const DUMMY_BCRYPT_HASH: &str =
    "$2b$12$3Tpu7THQYYnM.n3fEI9Q..HC4xAt2dLs5MlM2N0U1Q6ttuPAHyxEm";

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedCredentialRequest {
    org_id: String,
    name: String,
    credential_type: CredentialType,
    project_id: Option<String>,
    expires_at: Option<String>,
    created_by: Option<String>,
    previous_key_id: Option<String>,
    roles: Option<Vec<ApiKeyRole>>,
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
struct StoredCredential {
    id: String,
    org_id: String,
    project_id: Option<String>,
    credential_type: CredentialType,
    key_hash: String,
    expires_at: Option<String>,
    revoked: bool,
    is_admin: bool,
    roles: Vec<ApiKeyRole>,
}

pub(super) fn auth_audit_entries(storage: &SqliteStorage) -> Result<Vec<AuthAuditEntry>> {
    load_auth_audit_entries(&storage.conn)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_auth_audit_event_at(
    storage: &SqliteStorage,
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
    append_auth_audit_event_to_conn(
        &storage.conn,
        timestamp,
        event_type,
        org_id,
        actor_type.into(),
        actor_id.map(ToString::to_string),
        subject_type.into(),
        subject_id.into(),
        payload,
        outcome.into(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_auth_audit_event(
    storage: &SqliteStorage,
    event_type: AuthAuditEventType,
    org_id: Option<&str>,
    actor_type: impl Into<String>,
    actor_id: Option<&str>,
    subject_type: impl Into<String>,
    subject_id: impl Into<String>,
    payload: Value,
    outcome: impl Into<String>,
) -> Result<AuthAuditEntry> {
    append_auth_audit_event_at(
        storage,
        current_time(),
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
pub(super) fn record_role_change(
    storage: &SqliteStorage,
    org_id: Option<&str>,
    actor_type: &str,
    actor_id: Option<&str>,
    subject_type: &str,
    subject_id: &str,
    previous_role: Option<&str>,
    new_role: &str,
) -> Result<AuthAuditEntry> {
    append_auth_audit_event(
        storage,
        AuthAuditEventType::RoleChange,
        org_id,
        actor_type,
        actor_id,
        subject_type,
        subject_id,
        json!({
            "previous_role": previous_role,
            "new_role": new_role,
        }),
        "recorded",
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record_permission_grant(
    storage: &SqliteStorage,
    org_id: Option<&str>,
    actor_type: &str,
    actor_id: Option<&str>,
    subject_type: &str,
    subject_id: &str,
    permission: &str,
    scope: Option<&str>,
) -> Result<AuthAuditEntry> {
    append_auth_audit_event(
        storage,
        AuthAuditEventType::PermissionGrant,
        org_id,
        actor_type,
        actor_id,
        subject_type,
        subject_id,
        json!({
            "permission": permission,
            "scope": scope,
        }),
        "granted",
    )
}

pub(super) fn create_human_user(
    storage: &SqliteStorage,
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
    storage.conn.execute(
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
        ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL, 0, NULL)",
        params![id, org_id, email, password_hash, created_at],
    )?;

    load_human_user_record(storage, org_id, &email)?
        .ok_or_else(|| StorageError::InvalidInput("created user could not be reloaded".to_string()))
}

pub(super) fn load_human_user_record(
    storage: &SqliteStorage,
    org_id: &str,
    email: &str,
) -> Result<Option<HumanUserRecord>> {
    let email = normalize_email(email)?;
    let user = load_human_user(&storage.conn, org_id.trim(), &email)?;
    user.map(|user| human_user_record(&storage.conn, user))
        .transpose()
}

pub(super) fn org_mfa_policy(storage: &SqliteStorage, org_id: &str) -> Result<MfaPolicy> {
    load_org_mfa_policy(&storage.conn, org_id.trim())
}

pub(super) fn set_org_mfa_policy(
    storage: &SqliteStorage,
    org_id: &str,
    policy: MfaPolicy,
) -> Result<MfaPolicy> {
    let org_id = org_id.trim();
    if org_id.is_empty() {
        return Err(StorageError::InvalidInput(
            "organization id must not be empty".to_string(),
        ));
    }

    storage.conn.execute(
        "INSERT INTO org_mfa_policies (org_id, policy, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(org_id) DO UPDATE
         SET policy = excluded.policy, updated_at = excluded.updated_at",
        params![
            org_id,
            policy.as_str(),
            ActionEntry::canonical_timestamp(&current_time()),
        ],
    )?;

    Ok(policy)
}

pub(super) fn start_mfa_enrollment(
    storage: &SqliteStorage,
    org_id: &str,
    email: &str,
    password: &str,
) -> Result<MfaEnrollmentStart> {
    let user = authenticate_human_user(&storage.conn, org_id.trim(), email, password)?;
    if user.mfa_enabled {
        return Err(StorageError::MfaAlreadyEnabled);
    }

    let secret = generate_totp_secret().map_err(StorageError::Command)?;
    storage.conn.execute(
        "UPDATE human_users SET pending_mfa_secret = ?2 WHERE id = ?1",
        params![user.id, secret.clone()],
    )?;

    Ok(MfaEnrollmentStart {
        user_id: user.id,
        org_id: user.org_id,
        email: user.email.clone(),
        provisioning_uri: provisioning_uri(&user.email, &secret),
        secret,
    })
}

pub(super) fn confirm_mfa_enrollment(
    storage: &SqliteStorage,
    org_id: &str,
    email: &str,
    password: &str,
    code: &str,
    as_of: DateTime<Utc>,
) -> Result<MfaEnrollmentConfirm> {
    let user = authenticate_human_user(&storage.conn, org_id.trim(), email, password)?;
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
    let transaction = storage.conn.unchecked_transaction()?;
    let authenticated_at = ActionEntry::canonical_timestamp(&as_of);

    transaction.execute(
        "UPDATE human_users
         SET pending_mfa_secret = NULL,
             mfa_secret = ?2,
             mfa_enabled = 1,
             mfa_enrolled_at = ?3,
             last_authenticated_at = ?3
         WHERE id = ?1",
        params![user.id, secret, authenticated_at.clone()],
    )?;
    transaction.execute(
        "DELETE FROM human_recovery_codes WHERE user_id = ?1",
        params![user.id.clone()],
    )?;

    for code in &recovery_codes {
        transaction.execute(
            "INSERT INTO human_recovery_codes (
                id,
                user_id,
                code_hash,
                created_at,
                used_at
            ) VALUES (?1, ?2, ?3, ?4, NULL)",
            params![
                Uuid::new_v4().to_string(),
                user.id.clone(),
                bcrypt_hash(code)?,
                authenticated_at.clone(),
            ],
        )?;
    }

    transaction.commit()?;

    Ok(MfaEnrollmentConfirm {
        user_id: user.id,
        org_id: user.org_id,
        email: user.email,
        recovery_codes,
    })
}

pub(super) fn create_mfa_challenge(
    storage: &SqliteStorage,
    org_id: &str,
    email: &str,
    password: &str,
    as_of: DateTime<Utc>,
) -> Result<MfaChallengeStart> {
    let user = authenticate_human_user(&storage.conn, org_id.trim(), email, password)?;
    let policy = load_org_mfa_policy(&storage.conn, &user.org_id)?;

    if user.mfa_enabled {
        let challenge_id = Uuid::new_v4().to_string();
        let created_at = ActionEntry::canonical_timestamp(&as_of);
        let expires_at = ActionEntry::canonical_timestamp(&(as_of + chrono::Duration::minutes(10)));
        storage.conn.execute(
            "INSERT INTO auth_challenges (
                id,
                user_id,
                org_id,
                created_at,
                expires_at,
                used_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![
                challenge_id.clone(),
                user.id.clone(),
                user.org_id.clone(),
                created_at,
                expires_at.clone(),
            ],
        )?;

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

    storage.conn.execute(
        "UPDATE human_users SET last_authenticated_at = ?2 WHERE id = ?1",
        params![user.id.clone(), ActionEntry::canonical_timestamp(&as_of)],
    )?;

    Ok(MfaChallengeStart::Authenticated {
        user_id: user.id,
        org_id: user.org_id,
        email: user.email,
    })
}

pub(super) fn verify_mfa_challenge(
    storage: &SqliteStorage,
    challenge_id: &str,
    code: &str,
    as_of: DateTime<Utc>,
) -> Result<MfaChallengeVerify> {
    let challenge = load_auth_challenge(&storage.conn, challenge_id.trim())?
        .ok_or(StorageError::AuthChallengeNotFound)?;
    if challenge.used_at.is_some() {
        return Err(StorageError::AuthChallengeUsed);
    }

    let expires_at = DateTime::parse_from_rfc3339(&challenge.expires_at)?.with_timezone(&Utc);
    if as_of > expires_at {
        return Err(StorageError::AuthChallengeExpired);
    }

    let user = load_human_user_by_id(&storage.conn, &challenge.user_id)?
        .ok_or(StorageError::AuthChallengeNotFound)?;
    if !user.mfa_enabled {
        return Err(StorageError::MfaNotEnabled);
    }

    let Some(secret) = user.mfa_secret.clone() else {
        return Err(StorageError::MfaNotEnabled);
    };

    let verified_method = if verify_totp(&secret, code, as_of).map_err(StorageError::Command)? {
        ("totp".to_string(), false)
    } else if consume_recovery_code(&storage.conn, &user.id, code, as_of)? {
        ("recovery_code".to_string(), true)
    } else {
        return Err(StorageError::InvalidMfaCode);
    };

    let authenticated_at = ActionEntry::canonical_timestamp(&as_of);
    storage.conn.execute(
        "UPDATE auth_challenges SET used_at = ?2 WHERE id = ?1",
        params![challenge.id, authenticated_at.clone()],
    )?;
    storage.conn.execute(
        "UPDATE human_users SET last_authenticated_at = ?2 WHERE id = ?1",
        params![user.id.clone(), authenticated_at],
    )?;

    Ok(MfaChallengeVerify {
        user_id: user.id,
        org_id: challenge.org_id,
        email: user.email,
        method: verified_method.0,
        recovery_code_used: verified_method.1,
    })
}

pub(super) fn create_credential(
    storage: &SqliteStorage,
    request: CreateCredentialRequest,
) -> Result<CreatedCredential> {
    let request = normalize_credential_request(request)?;
    let transaction = storage.conn.unchecked_transaction()?;
    let created = insert_credential(&transaction, &request)?;

    let current_admin_key_id = load_admin_key_id(&transaction)?;
    let is_admin = match current_admin_key_id {
        Some(_) => false,
        None => {
            transaction.execute(
                "UPDATE app_settings SET admin_key_id = ?1 WHERE id = 1",
                params![created.id.clone()],
            )?;
            true
        }
    };

    let roles = match request.credential_type {
        CredentialType::ApiKey if is_admin => ApiKeyRole::admin_roles(),
        CredentialType::ApiKey => request
            .roles
            .clone()
            .unwrap_or_else(ApiKeyRole::default_service_roles),
        CredentialType::ServiceAccount => request.roles.clone().unwrap_or_default(),
    };
    transaction.execute(
        "UPDATE credentials SET roles = ?2 WHERE id = ?1",
        params![created.id.clone(), serialize_api_key_roles(&roles)?],
    )?;

    let actor_type = created
        .created_by
        .as_ref()
        .map(|creator| creator.actor_type.clone())
        .unwrap_or_else(|| "system".to_string());
    let actor_id = created
        .created_by
        .as_ref()
        .map(|creator| creator.actor_id.clone());
    let credential_type = created.credential_type.to_string();
    let role_names = roles.iter().map(|role| role.as_str()).collect::<Vec<_>>();
    let grants_admin_access = is_admin || roles.contains(&ApiKeyRole::Admin);

    append_auth_audit_event_to_conn(
        &transaction,
        current_time(),
        AuthAuditEventType::KeyCreation,
        Some(created.org_id.as_str()),
        actor_type,
        actor_id,
        credential_type.clone(),
        created.id.clone(),
        json!({
            "name": created.name,
            "credential_type": credential_type,
            "project_id": created.project_id,
            "is_admin": grants_admin_access,
            "previous_key_id": created.previous_key_id,
            "roles": role_names,
        }),
        "created".to_string(),
    )?;

    transaction.commit()?;

    Ok(CreatedCredential {
        is_admin: grants_admin_access,
        roles,
        ..created
    })
}

pub(super) fn create_api_key(
    storage: &SqliteStorage,
    org_id: &str,
    name: &str,
) -> Result<CreatedApiKey> {
    create_credential(storage, CreateCredentialRequest::api_key(org_id, name))
        .map(created_api_key_from_credential)
}

pub(super) fn create_api_key_with_roles(
    storage: &SqliteStorage,
    org_id: &str,
    name: &str,
    roles: Option<&[ApiKeyRole]>,
) -> Result<CreatedApiKey> {
    let request = match roles {
        Some(roles) => {
            CreateCredentialRequest::api_key(org_id, name).with_roles(roles.iter().copied())
        }
        None => CreateCredentialRequest::api_key(org_id, name),
    };
    create_credential(storage, request).map(created_api_key_from_credential)
}

pub(super) fn create_service_account(
    storage: &SqliteStorage,
    org_id: &str,
    name: &str,
) -> Result<CreatedCredential> {
    create_credential(
        storage,
        CreateCredentialRequest::service_account(org_id, name),
    )
}

pub(super) fn list_credentials(storage: &SqliteStorage) -> Result<Vec<CredentialRecord>> {
    let admin_key_id = load_admin_key_id(&storage.conn)?;
    let mut statement = storage.conn.prepare(
        "SELECT id, org_id, project_id, name, credential_type, created_at, created_by,
                expires_at, previous_key_id, last_used_at, revoked, revoked_at,
                revocation_reason, roles
         FROM credentials
         ORDER BY created_at ASC, id ASC",
    )?;
    let rows = statement.query_map([], |row| {
        let id = row.get::<_, String>(0)?;
        let created_by = row.get::<_, Option<String>>(6)?;
        Ok(CredentialRecord {
            is_admin: admin_key_id.as_deref() == Some(id.as_str()),
            id,
            org_id: row.get(1)?,
            project_id: row.get(2)?,
            name: row.get(3)?,
            credential_type: parse_credential_type_column(row.get::<_, String>(4)?, 4)?,
            created_at: row.get(5)?,
            created_by: deserialize_creator_column(created_by, 6)?,
            expires_at: row.get(7)?,
            previous_key_id: row.get(8)?,
            last_used_at: row.get(9)?,
            revoked: row.get::<_, i64>(10)? != 0,
            revoked_at: row.get(11)?,
            revocation_reason: row.get(12)?,
            roles: deserialize_api_key_roles_column(row.get::<_, String>(13)?, 13)?,
        })
    })?;

    let mut credentials = Vec::new();
    for row in rows {
        credentials.push(row?);
    }
    Ok(credentials)
}

pub(super) fn list_api_keys(storage: &SqliteStorage) -> Result<Vec<ApiKeyRecord>> {
    list_credentials(storage).map(|credentials| {
        credentials
            .into_iter()
            .filter(|credential| credential.credential_type == CredentialType::ApiKey)
            .map(api_key_record_from_credential)
            .collect()
    })
}

pub(super) fn list_api_keys_for_org(
    storage: &SqliteStorage,
    org_id: &str,
) -> Result<Vec<ApiKeyRecord>> {
    let org_id = require_non_empty(org_id, "organization id")?;
    list_api_keys(storage).map(|keys| {
        keys.into_iter()
            .filter(|key| key.org_id == org_id)
            .collect::<Vec<_>>()
    })
}

pub(super) fn list_service_accounts(storage: &SqliteStorage) -> Result<Vec<CredentialRecord>> {
    list_credentials(storage).map(|credentials| {
        credentials
            .into_iter()
            .filter(|credential| credential.credential_type == CredentialType::ServiceAccount)
            .collect()
    })
}

pub(super) fn revoke_credential(
    storage: &SqliteStorage,
    credential_id: &str,
    reason: Option<&str>,
) -> Result<bool> {
    let credential_id = credential_id.trim();
    if credential_id.is_empty() {
        return Err(StorageError::InvalidInput(
            "credential id must not be empty".to_string(),
        ));
    }
    let reason = normalize_optional_string(reason)?;
    let revoked_at = ActionEntry::canonical_timestamp(&current_time());
    let transaction = storage.conn.unchecked_transaction()?;
    let Some(stored_credential) = load_credential(&transaction, credential_id)? else {
        transaction.rollback()?;
        return Ok(false);
    };
    if stored_credential.revoked {
        transaction.rollback()?;
        return Ok(false);
    }

    let current_admin_key_id = load_admin_key_id(&transaction)?;
    transaction.execute(
        "UPDATE credentials
         SET revoked = 1, revoked_at = ?2, revocation_reason = ?3
         WHERE id = ?1 AND revoked = 0",
        params![credential_id, revoked_at, reason.clone()],
    )?;

    let mut next_admin_key_id = None;
    if current_admin_key_id.as_deref() == Some(credential_id) {
        next_admin_key_id = next_active_credential_id(&transaction)?;
        transaction.execute(
            "UPDATE app_settings SET admin_key_id = ?1 WHERE id = 1",
            params![next_admin_key_id.as_deref()],
        )?;
    }

    append_auth_audit_event_to_conn(
        &transaction,
        current_time(),
        AuthAuditEventType::KeyRevocation,
        Some(stored_credential.org_id.as_str()),
        "system".to_string(),
        None,
        stored_credential.credential_type.to_string(),
        stored_credential.id.clone(),
        json!({
            "credential_type": stored_credential.credential_type.to_string(),
            "project_id": stored_credential.project_id,
            "reason": reason,
            "was_admin": current_admin_key_id.as_deref() == Some(credential_id),
            "next_admin_key_id": next_admin_key_id,
        }),
        "revoked".to_string(),
    )?;

    transaction.commit()?;
    Ok(true)
}

pub(super) fn revoke_api_key(storage: &SqliteStorage, key_id: &str) -> Result<bool> {
    revoke_credential(storage, key_id, None)
}

pub(super) fn revoke_api_key_for_org(
    storage: &SqliteStorage,
    org_id: &str,
    key_id: &str,
) -> Result<bool> {
    let org_id = require_non_empty(org_id, "organization id")?;
    let key_id = require_non_empty(key_id, "credential id")?;
    let Some(credential) = load_credential(&storage.conn, &key_id)? else {
        return Ok(false);
    };
    if credential.org_id != org_id || credential.credential_type != CredentialType::ApiKey {
        return Ok(false);
    }

    revoke_api_key(storage, &key_id)
}

pub(super) fn authenticate_credential(
    storage: &SqliteStorage,
    raw_key: &str,
) -> Result<Option<AuthenticatedCredential>> {
    let maybe_parts = parse_api_key(raw_key);
    let stored_credential = match maybe_parts.as_ref() {
        Some((key_id, _)) => load_credential(&storage.conn, key_id)?,
        None => None,
    };

    let provided_secret = maybe_parts
        .as_ref()
        .map(|(_, secret)| secret.as_str())
        .unwrap_or(raw_key);
    let hash_to_check = stored_credential
        .as_ref()
        .map(|credential| credential.key_hash.as_str())
        .unwrap_or(DUMMY_BCRYPT_HASH);
    let verified = bcrypt_verify(provided_secret, hash_to_check)?;

    let Some(stored_credential) = stored_credential else {
        return Ok(None);
    };
    if !verified
        || stored_credential.revoked
        || credential_is_expired(stored_credential.expires_at.as_deref())?
    {
        return Ok(None);
    }

    let transaction = storage.conn.unchecked_transaction()?;
    let authenticated_at = current_time();
    let last_used_at = ActionEntry::canonical_timestamp(&authenticated_at);
    transaction.execute(
        "UPDATE credentials SET last_used_at = ?2 WHERE id = ?1",
        params![&stored_credential.id, last_used_at],
    )?;

    let credential_type = stored_credential.credential_type.to_string();
    append_auth_audit_event_to_conn(
        &transaction,
        authenticated_at,
        AuthAuditEventType::Login,
        Some(stored_credential.org_id.as_str()),
        credential_type.clone(),
        Some(stored_credential.id.clone()),
        credential_type.clone(),
        stored_credential.id.clone(),
        json!({
            "credential_type": credential_type,
            "project_id": stored_credential.project_id,
            "is_admin": stored_credential.is_admin
                || stored_credential.roles.contains(&ApiKeyRole::Admin),
            "auth_method": stored_credential.credential_type.to_string(),
        }),
        "authenticated".to_string(),
    )?;
    transaction.commit()?;

    let is_admin = stored_credential.is_admin || stored_credential.roles.contains(&ApiKeyRole::Admin);
    Ok(Some(AuthenticatedCredential {
        id: stored_credential.id,
        org_id: stored_credential.org_id,
        project_id: stored_credential.project_id,
        credential_type: stored_credential.credential_type,
        expires_at: stored_credential.expires_at,
        is_admin,
        revoked: false,
        roles: stored_credential.roles,
    }))
}

pub(super) fn authenticate_api_key(
    storage: &SqliteStorage,
    raw_key: &str,
) -> Result<Option<AuthenticatedApiKey>> {
    authenticate_credential(storage, raw_key)
        .map(|credential| credential.map(authenticated_api_key_from_credential))
}

pub(super) fn provision_sso_user(
    storage: &SqliteStorage,
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
        load_user_for_subject_or_email(&storage.conn, &org_id, &external_subject, &email)?;
    let user_id = existing
        .as_ref()
        .map(|user| user.id.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let created_at = existing
        .as_ref()
        .map(|user| user.created_at.clone())
        .unwrap_or_else(|| now.clone());

    storage.conn.execute(
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
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT(id) DO UPDATE SET
            external_subject = excluded.external_subject,
            email = excluded.email,
            first_name = excluded.first_name,
            last_name = excluded.last_name,
            display_name = excluded.display_name,
            role = excluded.role,
            last_login_at = excluded.last_login_at",
        params![
            &user_id,
            org_id,
            external_subject,
            &email,
            &first_name,
            &last_name,
            &display_name,
            &role,
            &created_at,
            &now,
        ],
    )?;

    load_user_by_id(&storage.conn, &user_id)?.ok_or_else(|| {
        StorageError::InvalidInput("failed to load provisioned SSO user".to_string())
    })
}

pub(super) fn create_sso_session(
    storage: &SqliteStorage,
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

    storage.conn.execute(
        "INSERT INTO auth_sessions (
            id,
            user_id,
            org_id,
            session_hash,
            created_at,
            expires_at,
            last_used_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        params![
            &id,
            &user.id,
            &user.org_id,
            &session_hash,
            &created_at,
            &expires_at,
        ],
    )?;

    Ok(CreatedSession {
        id,
        org_id: user.org_id.clone(),
        token,
        created_at,
        expires_at,
        user: user.clone(),
    })
}

pub(super) fn authenticate_session(
    storage: &SqliteStorage,
    raw_token: &str,
) -> Result<Option<AuthenticatedSession>> {
    let Some((session_id, secret)) = parse_session_token(raw_token) else {
        return Ok(None);
    };

    let Some(stored_session) = load_session(&storage.conn, &session_id)? else {
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

    storage.conn.execute(
        "UPDATE auth_sessions SET last_used_at = ?2 WHERE id = ?1",
        params![
            &stored_session.id,
            ActionEntry::canonical_timestamp(&current_time()),
        ],
    )?;

    load_authenticated_session(&storage.conn, &stored_session.id)
}

pub(super) fn create_user(
    storage: &SqliteStorage,
    email: &str,
    display_name: Option<&str>,
) -> Result<PrincipalUser> {
    let email = normalize_required_field(email, "user email")?;
    let display_name = normalize_optional_field(display_name);
    let id = Uuid::new_v4().to_string();
    let timestamp = ActionEntry::canonical_timestamp(&current_time());

    storage.conn.execute(
        "INSERT INTO users (
            id,
            email,
            display_name,
            created_at,
            updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id,
            email,
            display_name,
            timestamp.clone(),
            timestamp.clone(),
        ],
    )?;

    Ok(PrincipalUser {
        id,
        email,
        display_name,
        created_at: timestamp.clone(),
        updated_at: timestamp,
    })
}

pub(super) fn get_user(storage: &SqliteStorage, user_id: &str) -> Result<Option<PrincipalUser>> {
    load_user(&storage.conn, user_id)
}

pub(super) fn list_users(storage: &SqliteStorage) -> Result<Vec<PrincipalUser>> {
    let mut statement = storage.conn.prepare(
        "SELECT id, email, display_name, created_at, updated_at
         FROM users
         ORDER BY created_at ASC, id ASC",
    )?;
    let rows = statement.query_map([], parse_user_row)?;

    let mut users = Vec::new();
    for row in rows {
        users.push(row?);
    }
    Ok(users)
}

pub(super) fn update_user(
    storage: &SqliteStorage,
    user_id: &str,
    email: &str,
    display_name: Option<&str>,
) -> Result<Option<PrincipalUser>> {
    let email = normalize_required_field(email, "user email")?;
    let display_name = normalize_optional_field(display_name);
    let updated_at = ActionEntry::canonical_timestamp(&current_time());
    let affected = storage.conn.execute(
        "UPDATE users
         SET email = ?2, display_name = ?3, updated_at = ?4
         WHERE id = ?1",
        params![user_id, email, display_name, updated_at],
    )?;

    if affected == 0 {
        return Ok(None);
    }

    load_user(&storage.conn, user_id)
}

pub(super) fn delete_user(storage: &SqliteStorage, user_id: &str) -> Result<bool> {
    let transaction = storage.conn.unchecked_transaction()?;
    transaction.execute(
        "DELETE FROM org_memberships WHERE user_id = ?1",
        params![user_id],
    )?;
    let affected = transaction.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
    transaction.commit()?;
    Ok(affected > 0)
}

pub(super) fn create_org_membership(
    storage: &SqliteStorage,
    org_id: &str,
    user_id: &str,
    role: PrincipalRole,
) -> Result<OrgMembership> {
    let org_id = normalize_required_field(org_id, "organization id")?;
    ensure_user_exists(&storage.conn, user_id)?;
    let timestamp = ActionEntry::canonical_timestamp(&current_time());

    storage.conn.execute(
        "INSERT INTO org_memberships (
            org_id,
            user_id,
            role,
            created_at,
            updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            org_id,
            user_id,
            role.as_str(),
            timestamp.clone(),
            timestamp.clone(),
        ],
    )?;

    Ok(OrgMembership {
        org_id,
        user_id: user_id.to_string(),
        role,
        created_at: timestamp.clone(),
        updated_at: timestamp,
    })
}

pub(super) fn get_org_membership(
    storage: &SqliteStorage,
    org_id: &str,
    user_id: &str,
) -> Result<Option<OrgMembership>> {
    load_org_membership(&storage.conn, org_id, user_id)
}

pub(super) fn list_org_memberships(
    storage: &SqliteStorage,
    org_id: Option<&str>,
) -> Result<Vec<OrgMembership>> {
    let (sql, values): (&str, Vec<SqlValue>) = match org_id {
        Some(org_id) => (
            "SELECT org_id, user_id, role, created_at, updated_at
             FROM org_memberships
             WHERE org_id = ?
             ORDER BY created_at ASC, user_id ASC",
            vec![SqlValue::Text(org_id.to_string())],
        ),
        None => (
            "SELECT org_id, user_id, role, created_at, updated_at
             FROM org_memberships
             ORDER BY created_at ASC, org_id ASC, user_id ASC",
            Vec::new(),
        ),
    };

    let mut statement = storage.conn.prepare(sql)?;
    let rows = statement.query_map(rusqlite::params_from_iter(values.iter()), |row| {
        parse_org_membership_row(row)
    })?;

    let mut memberships = Vec::new();
    for row in rows {
        memberships.push(row?);
    }
    Ok(memberships)
}

pub(super) fn update_org_membership(
    storage: &SqliteStorage,
    org_id: &str,
    user_id: &str,
    role: PrincipalRole,
) -> Result<Option<OrgMembership>> {
    ensure_user_exists(&storage.conn, user_id)?;
    let updated_at = ActionEntry::canonical_timestamp(&current_time());
    let affected = storage.conn.execute(
        "UPDATE org_memberships
         SET role = ?3, updated_at = ?4
         WHERE org_id = ?1 AND user_id = ?2",
        params![org_id, user_id, role.as_str(), updated_at],
    )?;

    if affected == 0 {
        return Ok(None);
    }

    load_org_membership(&storage.conn, org_id, user_id)
}

pub(super) fn delete_org_membership(
    storage: &SqliteStorage,
    org_id: &str,
    user_id: &str,
) -> Result<bool> {
    let affected = storage.conn.execute(
        "DELETE FROM org_memberships WHERE org_id = ?1 AND user_id = ?2",
        params![org_id, user_id],
    )?;
    Ok(affected > 0)
}

#[allow(clippy::too_many_arguments)]
fn append_auth_audit_event_to_conn(
    conn: &Connection,
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
    let previous_hash =
        load_latest_auth_audit_hash(conn)?.unwrap_or_else(|| GENESIS_HASH.to_string());
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

    conn.execute(
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
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            id.to_string(),
            ActionEntry::canonical_timestamp(&timestamp),
            event_type.to_string(),
            org_id,
            &actor_type,
            actor_id.as_deref(),
            &subject_type,
            &subject_id,
            payload.to_string(),
            &outcome,
            &previous_hash,
            &entry_hash,
        ],
    )?;

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
    let mut hasher = Sha256::new();
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

fn load_auth_audit_entries(conn: &Connection) -> Result<Vec<AuthAuditEntry>> {
    let mut statement = conn.prepare(
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
    )?;
    let rows = statement.query_map([], |row| {
        Ok(RawStoredAuthAuditEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            event_type: row.get(2)?,
            org_id: row.get(3)?,
            actor_type: row.get(4)?,
            actor_id: row.get(5)?,
            subject_type: row.get(6)?,
            subject_id: row.get(7)?,
            payload: row.get(8)?,
            outcome: row.get(9)?,
            previous_hash: row.get(10)?,
            entry_hash: row.get(11)?,
        })
    })?;

    let mut entries = Vec::new();
    for row in rows {
        entries.push(parse_auth_audit_entry(row?)?);
    }

    Ok(entries)
}

fn load_latest_auth_audit_hash(conn: &Connection) -> Result<Option<String>> {
    conn.query_row(
        "SELECT entry_hash FROM auth_audit_log ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(StorageError::from)
}

fn parse_auth_audit_entry(raw: RawStoredAuthAuditEntry) -> Result<AuthAuditEntry> {
    let timestamp = DateTime::parse_from_rfc3339(&raw.timestamp)?.with_timezone(&Utc);
    let event_type =
        AuthAuditEventType::from_str(&raw.event_type).map_err(StorageError::InvalidInput)?;
    let payload = serde_json::from_str(&raw.payload)?;
    let entry_hash = calculate_auth_audit_hash_parts(
        &Uuid::parse_str(&raw.id)?,
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
        id: Uuid::parse_str(&raw.id)?,
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

pub(super) fn ensure_credentials_columns(conn: &Connection) -> Result<()> {
    if !table_has_column(conn, "credentials", "project_id")? {
        conn.execute("ALTER TABLE credentials ADD COLUMN project_id TEXT", [])?;
    }
    if !table_has_column(conn, "credentials", "credential_type")? {
        conn.execute(
            "ALTER TABLE credentials ADD COLUMN credential_type TEXT NOT NULL DEFAULT 'api_key'",
            [],
        )?;
    }
    if !table_has_column(conn, "credentials", "created_by")? {
        conn.execute("ALTER TABLE credentials ADD COLUMN created_by TEXT", [])?;
    }
    if !table_has_column(conn, "credentials", "expires_at")? {
        conn.execute("ALTER TABLE credentials ADD COLUMN expires_at TEXT", [])?;
    }
    if !table_has_column(conn, "credentials", "previous_key_id")? {
        conn.execute(
            "ALTER TABLE credentials ADD COLUMN previous_key_id TEXT",
            [],
        )?;
    }
    if !table_has_column(conn, "credentials", "revoked")? {
        conn.execute(
            "ALTER TABLE credentials ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !table_has_column(conn, "credentials", "revoked_at")? {
        conn.execute("ALTER TABLE credentials ADD COLUMN revoked_at TEXT", [])?;
    }
    if !table_has_column(conn, "credentials", "revocation_reason")? {
        conn.execute(
            "ALTER TABLE credentials ADD COLUMN revocation_reason TEXT",
            [],
        )?;
    }
    let added_roles_column = if !table_has_column(conn, "credentials", "roles")? {
        conn.execute(
            "ALTER TABLE credentials ADD COLUMN roles TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
        true
    } else {
        false
    };

    if added_roles_column {
        backfill_credential_roles(conn)?;
    }

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_credentials_org_id ON credentials (org_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_credentials_project_id ON credentials (project_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_credentials_previous_key_id ON credentials (previous_key_id)",
        [],
    )?;

    Ok(())
}

pub(super) fn migrate_api_keys_to_credentials(conn: &Connection) -> Result<()> {
    if !table_exists(conn, "api_keys")? {
        return Ok(());
    }

    let has_roles = table_has_column(conn, "api_keys", "roles")?;
    if has_roles {
        conn.execute(
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
            )
            SELECT
                legacy.id,
                legacy.key_hash,
                legacy.org_id,
                NULL,
                legacy.name,
                'api_key',
                legacy.created_at,
                NULL,
                NULL,
                legacy.last_used_at,
                NULL,
                legacy.revoked,
                NULL,
                NULL,
                legacy.roles
            FROM api_keys AS legacy
            WHERE NOT EXISTS (
                SELECT 1 FROM credentials WHERE credentials.id = legacy.id
            )",
            [],
        )?;
    } else {
        conn.execute(
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
            )
            SELECT
                legacy.id,
                legacy.key_hash,
                legacy.org_id,
                NULL,
                legacy.name,
                'api_key',
                legacy.created_at,
                NULL,
                NULL,
                legacy.last_used_at,
                NULL,
                legacy.revoked,
                NULL,
                NULL,
                '[]'
            FROM api_keys AS legacy
            WHERE NOT EXISTS (
                SELECT 1 FROM credentials WHERE credentials.id = legacy.id
            )",
            [],
        )?;
    }

    backfill_credential_roles(conn)?;
    Ok(())
}

pub(super) fn ensure_users_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            display_name TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_users_email
        ON users (email);
        ",
    )?;

    Ok(())
}

pub(super) fn ensure_org_memberships_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
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

        CREATE INDEX IF NOT EXISTS idx_org_memberships_user_id
        ON org_memberships (user_id);

        CREATE INDEX IF NOT EXISTS idx_org_memberships_role
        ON org_memberships (role);
        ",
    )?;

    Ok(())
}

fn load_admin_key_id(conn: &Connection) -> Result<Option<String>> {
    conn.query_row(
        "SELECT admin_key_id FROM app_settings WHERE id = 1",
        [],
        |row| row.get::<_, Option<String>>(0),
    )
    .optional()
    .map(|value| value.flatten())
    .map_err(StorageError::from)
}

fn load_credential(conn: &Connection, credential_id: &str) -> Result<Option<StoredCredential>> {
    let admin_key_id = load_admin_key_id(conn)?;
    conn.query_row(
        "SELECT id, org_id, project_id, credential_type, key_hash, expires_at, revoked, roles
         FROM credentials
         WHERE id = ?1",
        params![credential_id],
        |row| {
            let id = row.get::<_, String>(0)?;
            let is_admin = admin_key_id.as_deref() == Some(id.as_str());
            let mut roles = deserialize_api_key_roles_column(row.get::<_, String>(7)?, 7)?;
            if is_admin && !roles.contains(&ApiKeyRole::Admin) {
                roles = ApiKeyRole::admin_roles();
            }
            Ok(StoredCredential {
                is_admin,
                id,
                org_id: row.get(1)?,
                project_id: row.get(2)?,
                credential_type: parse_credential_type_column(row.get::<_, String>(3)?, 3)?,
                key_hash: row.get(4)?,
                expires_at: row.get(5)?,
                revoked: row.get::<_, i64>(6)? != 0,
                roles,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

fn human_user_record(conn: &Connection, user: StoredHumanUser) -> Result<HumanUserRecord> {
    Ok(HumanUserRecord {
        id: user.id,
        org_id: user.org_id.clone(),
        email: user.email,
        created_at: user.created_at,
        last_authenticated_at: user.last_authenticated_at,
        mfa_enabled: user.mfa_enabled,
        mfa_policy: load_org_mfa_policy(conn, &user.org_id)?,
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

fn authenticate_human_user(
    conn: &Connection,
    org_id: &str,
    email: &str,
    password: &str,
) -> Result<StoredHumanUser> {
    let email = normalize_email(email)?;
    let stored_user = load_human_user(conn, org_id, &email)?;
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

fn load_human_user(
    conn: &Connection,
    org_id: &str,
    email: &str,
) -> Result<Option<StoredHumanUser>> {
    conn.query_row(
        "SELECT id, org_id, email, password_hash, created_at, last_authenticated_at,
                pending_mfa_secret, mfa_secret, mfa_enabled
         FROM human_users
         WHERE org_id = ?1 AND email = ?2",
        params![org_id, email],
        |row| {
            Ok(StoredHumanUser {
                id: row.get(0)?,
                org_id: row.get(1)?,
                email: row.get(2)?,
                password_hash: row.get(3)?,
                created_at: row.get(4)?,
                last_authenticated_at: row.get(5)?,
                pending_mfa_secret: row.get(6)?,
                mfa_secret: row.get(7)?,
                mfa_enabled: row.get::<_, i64>(8)? != 0,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

fn load_human_user_by_id(conn: &Connection, user_id: &str) -> Result<Option<StoredHumanUser>> {
    conn.query_row(
        "SELECT id, org_id, email, password_hash, created_at, last_authenticated_at,
                pending_mfa_secret, mfa_secret, mfa_enabled
         FROM human_users
         WHERE id = ?1",
        params![user_id],
        |row| {
            Ok(StoredHumanUser {
                id: row.get(0)?,
                org_id: row.get(1)?,
                email: row.get(2)?,
                password_hash: row.get(3)?,
                created_at: row.get(4)?,
                last_authenticated_at: row.get(5)?,
                pending_mfa_secret: row.get(6)?,
                mfa_secret: row.get(7)?,
                mfa_enabled: row.get::<_, i64>(8)? != 0,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

fn load_org_mfa_policy(conn: &Connection, org_id: &str) -> Result<MfaPolicy> {
    conn.query_row(
        "SELECT policy FROM org_mfa_policies WHERE org_id = ?1",
        params![org_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map(|value| {
        value
            .as_deref()
            .map(MfaPolicy::from_str)
            .transpose()
            .map(|policy| policy.unwrap_or(MfaPolicy::Optional))
    })
    .map_err(StorageError::from)?
    .map_err(StorageError::InvalidInput)
}

fn load_auth_challenge(
    conn: &Connection,
    challenge_id: &str,
) -> Result<Option<StoredAuthChallenge>> {
    conn.query_row(
        "SELECT id, user_id, org_id, expires_at, used_at
         FROM auth_challenges
         WHERE id = ?1",
        params![challenge_id],
        |row| {
            Ok(StoredAuthChallenge {
                id: row.get(0)?,
                user_id: row.get(1)?,
                org_id: row.get(2)?,
                expires_at: row.get(3)?,
                used_at: row.get(4)?,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

fn consume_recovery_code(
    conn: &Connection,
    user_id: &str,
    code: &str,
    as_of: DateTime<Utc>,
) -> Result<bool> {
    let mut statement = conn.prepare(
        "SELECT id, code_hash
         FROM human_recovery_codes
         WHERE user_id = ?1 AND used_at IS NULL
         ORDER BY created_at ASC, id ASC",
    )?;
    let rows = statement.query_map(params![user_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    for row in rows {
        let (id, code_hash) = row?;
        if bcrypt_verify(code.trim(), &code_hash)? {
            conn.execute(
                "UPDATE human_recovery_codes SET used_at = ?2 WHERE id = ?1",
                params![id, ActionEntry::canonical_timestamp(&as_of)],
            )?;
            return Ok(true);
        }
    }

    Ok(false)
}

fn load_user(conn: &Connection, user_id: &str) -> Result<Option<PrincipalUser>> {
    conn.query_row(
        "SELECT id, email, display_name, created_at, updated_at
         FROM users
         WHERE id = ?1",
        params![user_id],
        parse_user_row,
    )
    .optional()
    .map_err(StorageError::from)
}

fn load_user_by_id(conn: &Connection, user_id: &str) -> Result<Option<UserRecord>> {
    conn.query_row(
        "SELECT id, org_id, external_subject, email, first_name, last_name, display_name, role,
                created_at, last_login_at
         FROM users
         WHERE id = ?1",
        params![user_id],
        |row| {
            Ok(UserRecord {
                id: row.get(0)?,
                org_id: row.get(1)?,
                external_subject: row.get(2)?,
                email: row.get(3)?,
                first_name: row.get(4)?,
                last_name: row.get(5)?,
                display_name: row.get(6)?,
                role: row.get(7)?,
                created_at: row.get(8)?,
                last_login_at: row.get(9)?,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

fn load_org_membership(
    conn: &Connection,
    org_id: &str,
    user_id: &str,
) -> Result<Option<OrgMembership>> {
    conn.query_row(
        "SELECT org_id, user_id, role, created_at, updated_at
         FROM org_memberships
         WHERE org_id = ?1 AND user_id = ?2",
        params![org_id, user_id],
        parse_org_membership_row,
    )
    .optional()
    .map_err(StorageError::from)
}

fn load_user_for_subject_or_email(
    conn: &Connection,
    org_id: &str,
    external_subject: &str,
    email: &str,
) -> Result<Option<UserRecord>> {
    conn.query_row(
        "SELECT id, org_id, external_subject, email, first_name, last_name, display_name, role,
                created_at, last_login_at
         FROM users
         WHERE org_id = ?1 AND (external_subject = ?2 OR email = ?3)
         ORDER BY CASE WHEN external_subject = ?2 THEN 0 ELSE 1 END
         LIMIT 1",
        params![org_id, external_subject, email],
        |row| {
            Ok(UserRecord {
                id: row.get(0)?,
                org_id: row.get(1)?,
                external_subject: row.get(2)?,
                email: row.get(3)?,
                first_name: row.get(4)?,
                last_name: row.get(5)?,
                display_name: row.get(6)?,
                role: row.get(7)?,
                created_at: row.get(8)?,
                last_login_at: row.get(9)?,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

fn ensure_user_exists(conn: &Connection, user_id: &str) -> Result<()> {
    let user_exists = conn
        .query_row(
            "SELECT 1 FROM users WHERE id = ?1 LIMIT 1",
            params![user_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();

    if user_exists {
        Ok(())
    } else {
        Err(StorageError::InvalidInput(format!(
            "user not found: {user_id}"
        )))
    }
}

fn parse_user_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PrincipalUser> {
    Ok(PrincipalUser {
        id: row.get(0)?,
        email: row.get(1)?,
        display_name: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn parse_org_membership_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OrgMembership> {
    let role: String = row.get(2)?;
    let role = PrincipalRole::from_str(&role).map_err(|error| match error {
        StorageError::InvalidPrincipalRole(value) => rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(StorageError::InvalidPrincipalRole(value)),
        ),
        other => rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(other),
        ),
    })?;

    Ok(OrgMembership {
        org_id: row.get(0)?,
        user_id: row.get(1)?,
        role,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn normalize_required_field(value: &str, field_name: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(StorageError::InvalidInput(format!(
            "{field_name} must not be empty"
        )));
    }

    Ok(value.to_string())
}

fn normalize_optional_field(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn next_active_credential_id(transaction: &rusqlite::Transaction<'_>) -> Result<Option<String>> {
    let now = ActionEntry::canonical_timestamp(&current_time());
    transaction
        .query_row(
            "SELECT id FROM credentials
             WHERE revoked = 0
               AND (expires_at IS NULL OR expires_at > ?1)
             ORDER BY created_at ASC, id ASC
             LIMIT 1",
            params![now],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(StorageError::from)
}

fn normalize_credential_request(
    request: CreateCredentialRequest,
) -> Result<NormalizedCredentialRequest> {
    let org_id = request.org_id.trim().to_string();
    if org_id.is_empty() {
        return Err(StorageError::InvalidInput(
            "organization id must not be empty".to_string(),
        ));
    }

    let name = request.name.trim().to_string();
    if name.is_empty() {
        return Err(StorageError::InvalidInput(
            "credential name must not be empty".to_string(),
        ));
    }

    let project_id = normalize_optional_string(request.project_id.as_deref())?;
    let previous_key_id = normalize_optional_string(request.previous_key_id.as_deref())?;
    let created_by = match request.created_by {
        Some(created_by) => {
            let actor_type = created_by.actor_type.trim();
            let actor_id = created_by.actor_id.trim();
            if actor_type.is_empty() || actor_id.is_empty() {
                return Err(StorageError::InvalidInput(
                    "credential creator metadata must include actor_type and actor_id".to_string(),
                ));
            }
            Some(serde_json::to_string(&CredentialCreator {
                actor_type: actor_type.to_string(),
                actor_id: actor_id.to_string(),
            })?)
        }
        None => None,
    };

    Ok(NormalizedCredentialRequest {
        org_id,
        name,
        credential_type: request.credential_type,
        project_id,
        expires_at: request
            .expires_at
            .map(|value| ActionEntry::canonical_timestamp(&value)),
        created_by,
        previous_key_id,
        roles: request.roles,
    })
}

fn normalize_optional_string(value: Option<&str>) -> Result<Option<String>> {
    match value.map(str::trim) {
        Some("") => Err(StorageError::InvalidInput(
            "optional string values must not be empty when provided".to_string(),
        )),
        Some(value) => Ok(Some(value.to_string())),
        None => Ok(None),
    }
}

fn insert_credential(
    transaction: &rusqlite::Transaction<'_>,
    request: &NormalizedCredentialRequest,
) -> Result<CreatedCredential> {
    if let Some(previous_key_id) = request.previous_key_id.as_deref() {
        let previous = load_credential(transaction, previous_key_id)?.ok_or_else(|| {
            StorageError::InvalidInput(
                "previous_key_id must reference an existing credential".to_string(),
            )
        })?;
        if previous.org_id != request.org_id
            || previous.credential_type != request.credential_type
            || previous.project_id != request.project_id
        {
            return Err(StorageError::InvalidInput(
                "rotated credentials must keep the same org, project, and credential type"
                    .to_string(),
            ));
        }
    }

    let id = Uuid::new_v4().to_string();
    let secret = format!(
        "{}{}",
        Uuid::new_v4().to_string().replace('-', ""),
        Uuid::new_v4().to_string().replace('-', "")
    );
    let key_hash = bcrypt_hash(&secret)?;
    let created_at = ActionEntry::canonical_timestamp(&current_time());

    transaction.execute(
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
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, 0, NULL, NULL, ?11)",
        params![
            id.clone(),
            key_hash,
            request.org_id,
            request.project_id,
            request.name,
            request.credential_type.to_string(),
            created_at.clone(),
            request.created_by,
            request.expires_at,
            request.previous_key_id,
            serialize_api_key_roles(request.roles.as_deref().unwrap_or(&[]))?,
        ],
    )?;

    Ok(CreatedCredential {
        id: id.clone(),
        org_id: request.org_id.clone(),
        project_id: request.project_id.clone(),
        name: request.name.clone(),
        credential_type: request.credential_type,
        created_at,
        created_by: deserialize_creator(request.created_by.clone())?,
        expires_at: request.expires_at.clone(),
        previous_key_id: request.previous_key_id.clone(),
        key: format!("{API_KEY_PREFIX}{id}_{secret}"),
        is_admin: false,
        roles: request.roles.clone().unwrap_or_default(),
    })
}

fn deserialize_creator(value: Option<String>) -> Result<Option<CredentialCreator>> {
    value
        .map(|value| serde_json::from_str::<CredentialCreator>(&value).map_err(StorageError::from))
        .transpose()
}

fn parse_credential_type_column(value: String, column: usize) -> rusqlite::Result<CredentialType> {
    CredentialType::from_str(&value).map_err(|err| sqlite_column_conversion_error(column, err))
}

fn deserialize_creator_column(
    value: Option<String>,
    column: usize,
) -> rusqlite::Result<Option<CredentialCreator>> {
    deserialize_creator(value).map_err(|err| sqlite_column_conversion_error(column, err))
}

fn deserialize_api_key_roles_column(
    value: String,
    column: usize,
) -> rusqlite::Result<Vec<ApiKeyRole>> {
    serde_json::from_str::<Vec<ApiKeyRole>>(&value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(column, SqlType::Text, Box::new(err))
    })
}

fn sqlite_column_conversion_error(column: usize, err: StorageError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, SqlType::Text, Box::new(err))
}

fn credential_is_expired(expires_at: Option<&str>) -> Result<bool> {
    let Some(expires_at) = expires_at else {
        return Ok(false);
    };

    Ok(DateTime::parse_from_rfc3339(expires_at)?.with_timezone(&Utc) <= current_time())
}

fn api_key_record_from_credential(record: CredentialRecord) -> ApiKeyRecord {
    let roles = if record.is_admin {
        ApiKeyRole::admin_roles()
    } else {
        record.roles
    };
    let is_admin = record.is_admin || roles.contains(&ApiKeyRole::Admin);
    ApiKeyRecord {
        id: record.id,
        org_id: record.org_id,
        name: record.name,
        created_at: record.created_at,
        last_used_at: record.last_used_at,
        revoked: record.revoked,
        is_admin,
        roles,
    }
}

fn created_api_key_from_credential(created: CreatedCredential) -> CreatedApiKey {
    let is_admin = created.is_admin || created.roles.contains(&ApiKeyRole::Admin);
    CreatedApiKey {
        id: created.id,
        org_id: created.org_id,
        name: created.name,
        created_at: created.created_at,
        key: created.key,
        is_admin,
        roles: if is_admin {
            ApiKeyRole::admin_roles()
        } else {
            created.roles
        },
    }
}

fn authenticated_api_key_from_credential(
    authenticated: AuthenticatedCredential,
) -> AuthenticatedApiKey {
    let is_admin = authenticated.is_admin || authenticated.roles.contains(&ApiKeyRole::Admin);
    AuthenticatedApiKey {
        id: authenticated.id,
        org_id: authenticated.org_id,
        is_admin,
        revoked: authenticated.revoked,
        roles: if is_admin {
            ApiKeyRole::admin_roles()
        } else {
            authenticated.roles
        },
    }
}

fn serialize_api_key_roles(roles: &[ApiKeyRole]) -> Result<String> {
    serde_json::to_string(roles).map_err(StorageError::from)
}

fn backfill_credential_roles(conn: &Connection) -> Result<()> {
    let default_roles = serialize_api_key_roles(&ApiKeyRole::default_service_roles())?;
    conn.execute(
        "UPDATE credentials
         SET roles = ?1
         WHERE credential_type = 'api_key'
           AND (roles IS NULL OR roles = '' OR roles = '[]')",
        params![default_roles],
    )?;

    if let Some(admin_key_id) = load_admin_key_id(conn)? {
        conn.execute(
            "UPDATE credentials SET roles = ?2 WHERE id = ?1",
            params![
                admin_key_id,
                serialize_api_key_roles(&ApiKeyRole::admin_roles())?
            ],
        )?;
    }

    Ok(())
}

fn load_session(conn: &Connection, session_id: &str) -> Result<Option<StoredSession>> {
    conn.query_row(
        "SELECT id, user_id, org_id, session_hash, created_at, expires_at
         FROM auth_sessions
         WHERE id = ?1",
        params![session_id],
        |row| {
            Ok(StoredSession {
                id: row.get(0)?,
                session_hash: row.get(3)?,
                expires_at: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

fn load_authenticated_session(
    conn: &Connection,
    session_id: &str,
) -> Result<Option<AuthenticatedSession>> {
    conn.query_row(
        "SELECT s.id, s.user_id, s.org_id, u.email, u.display_name, u.role, s.created_at, s.expires_at
         FROM auth_sessions s
         INNER JOIN users u ON u.id = s.user_id
         WHERE s.id = ?1",
        params![session_id],
        |row| {
            Ok(AuthenticatedSession {
                id: row.get(0)?,
                user_id: row.get(1)?,
                org_id: row.get(2)?,
                email: row.get(3)?,
                display_name: row.get(4)?,
                role: row.get(5)?,
                created_at: row.get(6)?,
                expires_at: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

pub(crate) fn parse_api_key(raw_key: &str) -> Option<(String, String)> {
    let raw_key = raw_key.trim();
    let suffix = raw_key.strip_prefix(API_KEY_PREFIX)?;
    let (id, secret) = suffix.split_once('_')?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }

    Some((id.to_string(), secret.to_string()))
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

pub(crate) fn require_non_empty(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(StorageError::InvalidInput(format!(
            "{label} must not be empty"
        )));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn optional_trimmed(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

pub fn is_valid_internal_role(role: &str) -> bool {
    matches!(role.trim(), "admin" | "auditor" | "viewer")
}

pub(crate) fn normalize_internal_role(role: &str) -> Result<String> {
    let role = require_non_empty(role, "internal role")?;
    if !is_valid_internal_role(&role) {
        return Err(StorageError::InvalidInput(format!(
            "unsupported internal role `{role}`"
        )));
    }
    Ok(role)
}

pub(crate) fn normalize_role_mappings(
    mappings: HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let mut normalized = HashMap::new();
    for (raw_external, raw_internal) in mappings {
        let external = require_non_empty(&raw_external, "SAML role mapping key")?;
        let internal = normalize_internal_role(&raw_internal)?;
        normalized.insert(external, internal);
    }
    Ok(normalized)
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
    hex::encode(Sha256::digest(secret.as_bytes()))
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

pub(crate) fn bcrypt_hash(secret: &str) -> Result<String> {
    let output = Command::new("python3")
        .args(["-c", BCRYPT_PYTHON_SCRIPT, "hash", secret])
        .output()
        .map_err(StorageError::Io)?;
    if !output.status.success() {
        return Err(StorageError::Command(format!(
            "python bcrypt hash failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) fn bcrypt_verify(secret: &str, hash: &str) -> Result<bool> {
    let output = Command::new("python3")
        .args(["-c", BCRYPT_PYTHON_SCRIPT, "verify", secret, hash])
        .output()
        .map_err(StorageError::Io)?;
    if !output.status.success() {
        return Err(StorageError::Command(format!(
            "python bcrypt verify failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
}
