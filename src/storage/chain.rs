use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::merkle::{batch_bounds, batch_index_for_sequence, build_inclusion_proof, compute_root};
use super::*;
use crate::ledger::hashing;

pub(super) fn entries_for_org(
    storage: &SqliteStorage,
    org_id: Option<&str>,
) -> Result<Vec<ActionEntry>> {
    load_entries_for_range(&storage.conn, None, None, org_id, None).map(|entries| {
        entries
            .into_iter()
            .map(|stored_entry| stored_entry.entry)
            .collect()
    })
}

pub(super) fn entries_for_scope(
    storage: &SqliteStorage,
    scope: &StorageScope,
) -> Result<Vec<ActionEntry>> {
    load_entries_for_range(
        &storage.conn,
        None,
        None,
        Some(scope.org_id.as_str()),
        Some(scope.project_id.as_str()),
    )
    .map(|entries| {
        entries
            .into_iter()
            .map(|stored_entry| stored_entry.entry)
            .collect()
    })
}

pub(super) fn append_entry(storage: &SqliteStorage, entry: &ActionEntry) -> Result<()> {
    let context = storage.tenant_context()?;
    append_entry_for_tenant(storage, entry, &context.org_id, &context.project_id)
}

pub(super) fn append_entry_for_org(
    storage: &SqliteStorage,
    entry: &ActionEntry,
    org_id: Option<&str>,
) -> Result<()> {
    append_entry_for_org_with_proof(storage, entry, org_id).map(|_| ())
}

pub(super) fn append_entry_for_org_with_proof(
    storage: &SqliteStorage,
    entry: &ActionEntry,
    org_id: Option<&str>,
) -> Result<LedgerProof> {
    let context = resolve_tenant_context(&storage.conn, org_id)?;
    append_entry_for_tenant_with_proof(storage, entry, &context.org_id, &context.project_id)
}

pub(super) fn append_entry_for_tenant(
    storage: &SqliteStorage,
    entry: &ActionEntry,
    org_id: &str,
    project_id: &str,
) -> Result<()> {
    append_entry_for_tenant_with_proof(storage, entry, org_id, project_id).map(|_| ())
}

pub(super) fn append_entry_for_tenant_with_proof(
    storage: &SqliteStorage,
    entry: &ActionEntry,
    org_id: &str,
    project_id: &str,
) -> Result<LedgerProof> {
    let transaction = storage.conn.unchecked_transaction()?;
    let expected_previous_hash = transaction
        .query_row(
            "SELECT entry_hash FROM action_log ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    if entry.previous_hash != expected_previous_hash {
        return Err(StorageError::BrokenAppendChain {
            expected: expected_previous_hash,
            actual: entry.previous_hash.clone(),
        });
    }

    let expected_entry_hash = entry.calculate_hash();
    if entry.entry_hash != expected_entry_hash {
        return Err(StorageError::InvalidEntryHash {
            expected: expected_entry_hash,
            actual: entry.entry_hash.clone(),
        });
    }

    let envelope = action_log_envelope(entry, None);
    transaction.execute(
        "INSERT INTO action_log (
            id,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            trace_id,
            span_id,
            action_type,
            event_kind,
            schema_version,
            payload,
            context,
            outcome,
            previous_hash,
            entry_hash,
            org_id,
            project_id,
            idempotency_key,
            request_metadata,
            result_metadata
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            entry.id.to_string(),
            ActionEntry::canonical_timestamp(&entry.timestamp),
            &entry.agent_id,
            &entry.agent_type,
            &entry.session_id,
            &envelope.trace_id,
            &envelope.span_id,
            entry.action_type.to_string(),
            &envelope.event_kind,
            &envelope.schema_version,
            entry.payload.to_string(),
            entry.context.to_string(),
            &entry.outcome,
            &entry.previous_hash,
            &entry.entry_hash,
            org_id,
            project_id,
            &envelope.idempotency_key,
            &envelope.request_metadata,
            &envelope.result_metadata,
        ],
    )?;
    let action_sequence = transaction.last_insert_rowid();
    append_checkpoint_if_due(&transaction, action_sequence, entry.id, &entry.entry_hash)?;
    transaction.commit()?;
    persist_root_anchor(&storage.conn, Some(&entry.entry_hash))?;

    let chain_position = lookup_sequence(&storage.conn, entry.id)? as u64;

    Ok(LedgerProof {
        hash: entry.entry_hash.clone(),
        previous_hash: entry.previous_hash.clone(),
        chain_position,
    })
}

pub(super) fn append_entry_for_scope(
    storage: &SqliteStorage,
    entry: &ActionEntry,
    scope: &StorageScope,
) -> Result<()> {
    let expected_previous_hash =
        load_latest_hash_for_scope(&storage.conn, &scope.org_id, &scope.project_id)?
            .unwrap_or_else(|| GENESIS_HASH.to_string());
    if entry.previous_hash != expected_previous_hash {
        return Err(StorageError::BrokenAppendChain {
            expected: expected_previous_hash,
            actual: entry.previous_hash.clone(),
        });
    }

    let expected_entry_hash = entry.calculate_hash();
    if entry.entry_hash != expected_entry_hash {
        return Err(StorageError::InvalidEntryHash {
            expected: expected_entry_hash,
            actual: entry.entry_hash.clone(),
        });
    }

    storage.conn.execute(
        "INSERT INTO action_log (
            id,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
            previous_hash,
            entry_hash,
            org_id,
            project_id
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            entry.id.to_string(),
            ActionEntry::canonical_timestamp(&entry.timestamp),
            &entry.agent_id,
            &entry.agent_type,
            &entry.session_id,
            entry.action_type.to_string(),
            entry.payload.to_string(),
            entry.context.to_string(),
            &entry.outcome,
            &entry.previous_hash,
            &entry.entry_hash,
            &scope.org_id,
            &scope.project_id,
        ],
    )?;
    upsert_merkle_checkpoint_for_sequence(&storage.conn, storage.conn.last_insert_rowid())?;
    persist_root_anchor(&storage.conn, Some(&entry.entry_hash))?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_action_at(
    storage: &SqliteStorage,
    timestamp: DateTime<Utc>,
    agent_id: impl Into<String>,
    agent_type: impl Into<String>,
    session_id: impl Into<String>,
    action_type: ActionType,
    payload: Value,
    context: Value,
    outcome: impl Into<String>,
) -> Result<ActionEntry> {
    let tenant_context = storage.tenant_context()?;
    append_action_at_for_tenant(
        storage,
        &tenant_context.org_id,
        &tenant_context.project_id,
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
pub(super) fn append_action_at_for_org(
    storage: &SqliteStorage,
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
    let tenant_context = resolve_tenant_context(&storage.conn, org_id)?;
    append_action_at_for_tenant(
        storage,
        &tenant_context.org_id,
        &tenant_context.project_id,
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
pub(super) fn append_action_at_for_tenant(
    storage: &SqliteStorage,
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
    let previous_hash =
        load_latest_hash(&storage.conn)?.unwrap_or_else(|| GENESIS_HASH.to_string());
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
    append_entry_for_tenant(storage, &entry, org_id, project_id)?;
    Ok(entry)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_action_at_for_scope(
    storage: &SqliteStorage,
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
    let previous_hash =
        load_latest_hash_for_scope(&storage.conn, &scope.org_id, &scope.project_id)?
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
    append_entry_for_scope(storage, &entry, scope)?;
    Ok(entry)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_action(
    storage: &SqliteStorage,
    agent_id: impl Into<String>,
    agent_type: impl Into<String>,
    session_id: impl Into<String>,
    action_type: ActionType,
    payload: Value,
    context: Value,
    outcome: impl Into<String>,
) -> Result<ActionEntry> {
    let tenant_context = storage.tenant_context()?;
    append_action_for_tenant(
        storage,
        &tenant_context.org_id,
        &tenant_context.project_id,
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
pub(super) fn append_action_for_org(
    storage: &SqliteStorage,
    org_id: Option<&str>,
    agent_id: impl Into<String>,
    agent_type: impl Into<String>,
    session_id: impl Into<String>,
    action_type: ActionType,
    payload: Value,
    context: Value,
    outcome: impl Into<String>,
) -> Result<ActionEntry> {
    let tenant_context = resolve_tenant_context(&storage.conn, org_id)?;
    append_action_for_tenant(
        storage,
        &tenant_context.org_id,
        &tenant_context.project_id,
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
pub(super) fn append_action_for_tenant(
    storage: &SqliteStorage,
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
    append_action_at_for_tenant(
        storage,
        org_id,
        project_id,
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
pub(super) fn append_action_for_scope(
    storage: &SqliteStorage,
    scope: &StorageScope,
    agent_id: impl Into<String>,
    agent_type: impl Into<String>,
    session_id: impl Into<String>,
    action_type: ActionType,
    payload: Value,
    context: Value,
    outcome: impl Into<String>,
) -> Result<ActionEntry> {
    append_action_at_for_scope(
        storage,
        scope,
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
pub(super) fn append_action_with_dedup_at(
    storage: &SqliteStorage,
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
    let tenant_context = storage.tenant_context()?;
    append_action_with_dedup_at_for_tenant(
        storage,
        &tenant_context.org_id,
        &tenant_context.project_id,
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
pub(super) fn append_action_with_dedup_at_for_org(
    storage: &SqliteStorage,
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
    match append_action_with_dedup_at_for_org_detailed(
        storage,
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
pub(super) fn append_action_with_dedup_at_for_org_detailed(
    storage: &SqliteStorage,
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
    let tenant_context = resolve_tenant_context(&storage.conn, org_id)?;
    append_action_with_dedup_at_for_tenant_detailed(
        storage,
        &tenant_context.org_id,
        &tenant_context.project_id,
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
pub(super) fn append_action_with_dedup_at_for_tenant(
    storage: &SqliteStorage,
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
    match append_action_with_dedup_at_for_tenant_detailed(
        storage,
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
    )? {
        DeduplicationOutcome::Inserted(entry) => Ok(Some(entry)),
        DeduplicationOutcome::Duplicate { .. } => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn append_action_with_dedup_at_for_tenant_detailed(
    storage: &SqliteStorage,
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
) -> Result<DeduplicationOutcome<ActionEntry>> {
    let transaction = storage.conn.unchecked_transaction()?;
    let existing_entry_id = transaction
        .query_row(
            "SELECT entry_id FROM ingest_dedup WHERE dedup_key = ?1 LIMIT 1",
            params![dedup_key],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();

    if existing_entry_id.is_some() {
        transaction.rollback()?;
        return Ok(DeduplicationOutcome::Duplicate {
            entry_id: existing_entry_id,
        });
    }

    let agent_id = agent_id.into();
    let agent_type = agent_type.into();
    let session_id = session_id.into();
    let outcome = outcome.into();
    let previous_hash = transaction
        .query_row(
            "SELECT entry_hash FROM action_log ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
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

    let envelope = action_log_envelope(&entry, Some(dedup_key));
    transaction.execute(
        "INSERT INTO action_log (
            id,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            trace_id,
            span_id,
            action_type,
            event_kind,
            schema_version,
            payload,
            context,
            outcome,
            previous_hash,
            entry_hash,
            org_id,
            project_id,
            idempotency_key,
            request_metadata,
            result_metadata
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            entry.id.to_string(),
            ActionEntry::canonical_timestamp(&entry.timestamp),
            &entry.agent_id,
            &entry.agent_type,
            &entry.session_id,
            &envelope.trace_id,
            &envelope.span_id,
            entry.action_type.to_string(),
            &envelope.event_kind,
            &envelope.schema_version,
            entry.payload.to_string(),
            entry.context.to_string(),
            &entry.outcome,
            &entry.previous_hash,
            &entry.entry_hash,
            org_id,
            project_id,
            &envelope.idempotency_key,
            &envelope.request_metadata,
            &envelope.result_metadata,
        ],
    )?;
    let action_sequence = transaction.last_insert_rowid();
    transaction.execute(
        "INSERT INTO ingest_dedup (
            dedup_key,
            entry_id,
            recorded_at
        ) VALUES (?1, ?2, ?3)",
        params![
            dedup_key,
            entry.id.to_string(),
            ActionEntry::canonical_timestamp(&current_time()),
        ],
    )?;
    append_checkpoint_if_due(&transaction, action_sequence, entry.id, &entry.entry_hash)?;
    transaction.commit()?;
    persist_root_anchor(&storage.conn, Some(&entry.entry_hash))?;

    Ok(DeduplicationOutcome::Inserted(entry))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_action_with_dedup_at_for_scope(
    storage: &SqliteStorage,
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
    let transaction = storage.conn.unchecked_transaction()?;
    let existing_entry_id = transaction
        .query_row(
            "SELECT entry_id FROM ingest_dedup WHERE dedup_key = ?1 LIMIT 1",
            params![dedup_key],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();

    if existing_entry_id.is_some() {
        transaction.rollback()?;
        return Ok(None);
    }

    let agent_id = agent_id.into();
    let agent_type = agent_type.into();
    let session_id = session_id.into();
    let outcome = outcome.into();
    let previous_hash = load_latest_hash_for_scope(&transaction, &scope.org_id, &scope.project_id)?
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

    transaction.execute(
        "INSERT INTO action_log (
            id,
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
            previous_hash,
            entry_hash,
            org_id,
            project_id
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            entry.id.to_string(),
            ActionEntry::canonical_timestamp(&entry.timestamp),
            &entry.agent_id,
            &entry.agent_type,
            &entry.session_id,
            entry.action_type.to_string(),
            entry.payload.to_string(),
            entry.context.to_string(),
            &entry.outcome,
            &entry.previous_hash,
            &entry.entry_hash,
            &scope.org_id,
            &scope.project_id,
        ],
    )?;
    transaction.execute(
        "INSERT INTO ingest_dedup (
            dedup_key,
            entry_id,
            recorded_at
        ) VALUES (?1, ?2, ?3)",
        params![
            dedup_key,
            entry.id.to_string(),
            ActionEntry::canonical_timestamp(&current_time()),
        ],
    )?;
    upsert_merkle_checkpoint_for_sequence(&transaction, transaction.last_insert_rowid())?;
    transaction.commit()?;
    persist_root_anchor(&storage.conn, Some(&entry.entry_hash))?;

    Ok(Some(entry))
}

pub(super) fn verify_chain_for_storage(
    storage: &SqliteStorage,
    from_id: Option<Uuid>,
    to_id: Option<Uuid>,
) -> Result<Vec<IntegrityViolation>> {
    verify_chain(&storage.conn, from_id, to_id)
}

pub(super) fn verify_chain_for_scope_for_storage(
    storage: &SqliteStorage,
    scope: &StorageScope,
) -> Result<Vec<IntegrityViolation>> {
    verify_chain_for_scope(&storage.conn, scope)
}

pub(super) fn create_signed_checkpoint(
    storage: &SqliteStorage,
    signer: &CheckpointSigner,
    anchors: &[ExternalAnchorInput],
) -> Result<SignedCheckpoint> {
    let latest = load_latest_entry_summary(&storage.conn)?.ok_or_else(|| {
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
    let transaction = storage.conn.unchecked_transaction()?;

    upsert_checkpoint_signing_key(&transaction, signer.metadata())?;
    transaction.execute(
        "INSERT INTO checkpoints (
            checkpoint_id,
            created_at,
            sequence,
            entry_id,
            ledger_root_hash,
            checkpoint_hash,
            signature,
            key_id
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            checkpoint_id,
            created_at,
            latest.sequence,
            latest.entry_id,
            latest.ledger_root_hash,
            checkpoint_hash_value,
            signature,
            signer.metadata().key_id,
        ],
    )?;

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
        transaction.execute(
            "INSERT INTO checkpoint_anchors (
                anchor_id,
                checkpoint_id,
                provider,
                reference,
                anchored_at,
                anchored_hash,
                metadata
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                Uuid::new_v4().to_string(),
                payload.checkpoint_id,
                provider,
                reference,
                anchored_at,
                checkpoint_hash(&payload),
                anchor.metadata.to_string(),
            ],
        )?;
    }

    transaction.commit()?;
    load_signed_checkpoint(&storage.conn, &payload.checkpoint_id)?
        .ok_or_else(|| StorageError::Checkpoint("checkpoint was not persisted".to_string()))
}

pub(super) fn signed_checkpoints(storage: &SqliteStorage) -> Result<Vec<SignedCheckpoint>> {
    load_signed_checkpoints(&storage.conn)
}

pub(super) fn signed_checkpoint(
    storage: &SqliteStorage,
    checkpoint_id: &str,
) -> Result<Option<SignedCheckpoint>> {
    load_signed_checkpoint(&storage.conn, checkpoint_id)
}

pub(super) fn latest_signed_checkpoint(
    storage: &SqliteStorage,
) -> Result<Option<SignedCheckpoint>> {
    load_latest_signed_checkpoint(&storage.conn)
}

pub(super) fn verify_signed_checkpoint_for_storage(
    storage: &SqliteStorage,
    checkpoint_id: &str,
) -> Result<Option<VerifiedCheckpoint>> {
    load_signed_checkpoint(&storage.conn, checkpoint_id)?
        .map(verify_loaded_checkpoint)
        .transpose()
}

pub(super) fn verify_latest_signed_checkpoint(
    storage: &SqliteStorage,
) -> Result<Option<VerifiedCheckpoint>> {
    load_latest_signed_checkpoint(&storage.conn)?
        .map(verify_loaded_checkpoint)
        .transpose()
}

pub(super) fn merkle_checkpoints(storage: &SqliteStorage) -> Result<Vec<MerkleCheckpoint>> {
    load_merkle_checkpoints(&storage.conn)
}

pub(super) fn merkle_proof(
    storage: &SqliteStorage,
    entry_id: Uuid,
) -> Result<Option<MerkleInclusionProof>> {
    load_merkle_proof(&storage.conn, entry_id)
}

pub(super) fn create_checkpoint(storage: &SqliteStorage) -> Result<LedgerCheckpoint> {
    ensure_sqlite_merkle_batches(&storage.conn)?;
    create_sqlite_checkpoint(&storage.conn)
}

pub(super) fn latest_checkpoint(storage: &SqliteStorage) -> Result<Option<LedgerCheckpoint>> {
    load_latest_sqlite_checkpoint(&storage.conn)
}

pub(super) fn merkle_batches(storage: &SqliteStorage) -> Result<Vec<MerkleBatch>> {
    ensure_sqlite_merkle_batches(&storage.conn)?;
    load_sqlite_merkle_batches(&storage.conn)
}

pub fn verify_chain(
    conn: &Connection,
    from_id: Option<Uuid>,
    to_id: Option<Uuid>,
) -> Result<Vec<IntegrityViolation>> {
    let entries = load_entries_for_range(conn, from_id, to_id, None, None)?;
    let mut violations = Vec::new();

    if entries.is_empty() {
        record_integrity_check(conn, from_id, to_id, &violations)?;
        return Ok(violations);
    }

    let expected_previous_hash = if entries[0].sequence > 1 {
        load_previous_stored_hash(conn, entries[0].sequence)?
            .or(load_purge_resume_previous_hash(conn, entries[0].sequence)?)
            .unwrap_or_else(|| GENESIS_HASH.to_string())
    } else {
        GENESIS_HASH.to_string()
    };
    let chain_entries: Vec<_> = entries
        .iter()
        .map(|stored_entry| stored_entry.entry.clone())
        .collect();
    violations.extend(
        hashing::verify_chain(&chain_entries, &expected_previous_hash)
            .into_iter()
            .map(|violation| IntegrityViolation {
                entry_id: violation.entry_id,
                reason: violation.reason,
                expected_previous_hash: violation.expected_previous_hash,
                actual_previous_hash: violation.actual_previous_hash,
                expected_entry_hash: violation.expected_entry_hash,
                actual_entry_hash: violation.actual_entry_hash,
            }),
    );

    if from_id.is_none() && to_id.is_none() {
        if table_exists(conn, "ledger_checkpoints")? {
            verify_checkpoints(conn, &entries, &mut violations)?;
        }

        if !is_immutable_schema(conn)? {
            let Some(latest_entry_id) = entries.last().map(|stored_entry| stored_entry.entry.id)
            else {
                record_integrity_check(conn, from_id, to_id, &violations)?;
                return Ok(violations);
            };
            match load_root_anchor(conn)? {
                Some(expected_root_hash) => {
                    let actual_root_hash = entries
                        .last()
                        .map(|stored_entry| stored_entry.entry.entry_hash.clone())
                        .unwrap_or_else(|| GENESIS_HASH.to_string());
                    if expected_root_hash != actual_root_hash {
                        violations.push(IntegrityViolation {
                            entry_id: latest_entry_id,
                            reason: "anchored root hash mismatch".to_string(),
                            expected_previous_hash: None,
                            actual_previous_hash: actual_root_hash.clone(),
                            expected_entry_hash: expected_root_hash,
                            actual_entry_hash: actual_root_hash,
                        });
                    }
                }
                None if connection_path(conn)?.is_some() => {
                    violations.push(IntegrityViolation {
                        entry_id: latest_entry_id,
                        reason: "missing root anchor".to_string(),
                        expected_previous_hash: None,
                        actual_previous_hash: String::new(),
                        expected_entry_hash: "root-anchor".to_string(),
                        actual_entry_hash: String::new(),
                    });
                }
                None => {}
            }

            if table_exists(conn, "merkle_checkpoints")? {
                verify_merkle_checkpoints(conn, &entries, &mut violations)?;
            }
        }
    }

    record_integrity_check(conn, from_id, to_id, &violations)?;
    Ok(violations)
}

#[derive(Debug)]
pub(crate) struct RawStoredEntry {
    pub(crate) sequence: i64,
    pub(crate) id: String,
    pub(crate) timestamp: String,
    pub(crate) agent_id: String,
    pub(crate) agent_type: String,
    pub(crate) session_id: String,
    pub(crate) action_type: String,
    pub(crate) payload: String,
    pub(crate) context: String,
    pub(crate) outcome: String,
    pub(crate) previous_hash: String,
    pub(crate) entry_hash: String,
    pub(crate) org_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct StoredEntry {
    pub(crate) sequence: i64,
    pub(crate) entry: ActionEntry,
    pub(crate) org_id: Option<String>,
}

pub(crate) fn load_entries_for_range(
    conn: &Connection,
    from_id: Option<Uuid>,
    to_id: Option<Uuid>,
    org_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<Vec<StoredEntry>> {
    let start_sequence = match from_id {
        Some(id) => Some(lookup_sequence(conn, id)?),
        None => None,
    };
    let end_sequence = match to_id {
        Some(id) => Some(lookup_sequence(conn, id)?),
        None => None,
    };

    load_entries_for_sequence_range(conn, start_sequence, end_sequence, org_id, project_id)
}

fn load_entries_for_sequence_range(
    conn: &Connection,
    start_sequence: Option<i64>,
    end_sequence: Option<i64>,
    org_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<Vec<StoredEntry>> {
    if let (Some(start), Some(end)) = (start_sequence, end_sequence)
        && start > end
    {
        return Ok(Vec::new());
    }

    let mut sql = String::from(
        "SELECT sequence, id, timestamp, agent_id, agent_type, session_id, action_type, payload, context, outcome, previous_hash, entry_hash, org_id FROM action_log",
    );
    let mut clauses = Vec::new();
    let mut values: Vec<SqlValue> = Vec::new();

    if let Some(start) = start_sequence {
        clauses.push("sequence >= ?".to_string());
        values.push(SqlValue::Integer(start));
    }

    if let Some(end) = end_sequence {
        clauses.push("sequence <= ?".to_string());
        values.push(SqlValue::Integer(end));
    }

    if let Some(org_id) = org_id {
        clauses.push("org_id = ?".to_string());
        values.push(SqlValue::Text(org_id.to_string()));
    }

    if let Some(project_id) = project_id {
        clauses.push("project_id = ?".to_string());
        values.push(SqlValue::Text(project_id.to_string()));
    }

    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY sequence ASC");

    let mut statement = conn.prepare(&sql)?;
    let rows = statement.query_map(rusqlite::params_from_iter(values.iter()), |row| {
        Ok(RawStoredEntry {
            sequence: row.get(0)?,
            id: row.get(1)?,
            timestamp: row.get(2)?,
            agent_id: row.get(3)?,
            agent_type: row.get(4)?,
            session_id: row.get(5)?,
            action_type: row.get(6)?,
            payload: row.get(7)?,
            context: row.get(8)?,
            outcome: row.get(9)?,
            previous_hash: row.get(10)?,
            entry_hash: row.get(11)?,
            org_id: row.get(12)?,
        })
    })?;

    let mut entries = Vec::new();
    for raw_row in rows {
        entries.push(parse_stored_entry(raw_row?)?);
    }

    Ok(entries)
}

pub(crate) fn load_entry_by_id(conn: &Connection, id: &str) -> Result<Option<StoredEntry>> {
    let mut statement = conn.prepare(
        "SELECT sequence, id, timestamp, agent_id, agent_type, session_id, action_type, payload, context, outcome, previous_hash, entry_hash, org_id
         FROM action_log
         WHERE id = ?1
         LIMIT 1",
    )?;
    let raw_entry = statement
        .query_row(params![id], |row| {
            Ok(RawStoredEntry {
                sequence: row.get(0)?,
                id: row.get(1)?,
                timestamp: row.get(2)?,
                agent_id: row.get(3)?,
                agent_type: row.get(4)?,
                session_id: row.get(5)?,
                action_type: row.get(6)?,
                payload: row.get(7)?,
                context: row.get(8)?,
                outcome: row.get(9)?,
                previous_hash: row.get(10)?,
                entry_hash: row.get(11)?,
                org_id: row.get(12)?,
            })
        })
        .optional()?;

    raw_entry.map(parse_stored_entry).transpose()
}

pub(crate) fn load_entries_with_filter(
    conn: &Connection,
    filter: &LedgerFilter,
) -> Result<Vec<StoredEntry>> {
    let (start_sequence, end_sequence) = resolve_filter_range(conn, filter.range.as_ref())?;
    if let (Some(start), Some(end)) = (start_sequence, end_sequence)
        && start > end
    {
        return Ok(Vec::new());
    }

    let mut sql = String::from(
        "SELECT sequence, id, timestamp, agent_id, agent_type, session_id, action_type, payload, context, outcome, previous_hash, entry_hash, org_id FROM action_log",
    );
    let mut clauses = Vec::new();
    let mut values: Vec<SqlValue> = Vec::new();

    if let Some(start) = start_sequence {
        clauses.push("sequence >= ?".to_string());
        values.push(SqlValue::Integer(start));
    }

    if let Some(end) = end_sequence {
        clauses.push("sequence <= ?".to_string());
        values.push(SqlValue::Integer(end));
    }

    if let Some(agent_id) = filter.agent_id.as_deref() {
        clauses.push("agent_id = ?".to_string());
        values.push(SqlValue::Text(agent_id.to_string()));
    }

    if let Some(agent_type) = filter.agent_type.as_deref() {
        clauses.push("agent_type = ?".to_string());
        values.push(SqlValue::Text(agent_type.to_string()));
    }

    if let Some(session_id) = filter.session_id.as_deref() {
        clauses.push("session_id = ?".to_string());
        values.push(SqlValue::Text(session_id.to_string()));
    }

    if let Some(action_type) = filter.action_type {
        clauses.push("action_type = ?".to_string());
        values.push(SqlValue::Text(action_type.to_string()));
    }

    if let Some(outcome) = filter.outcome.as_deref() {
        clauses.push("outcome = ?".to_string());
        values.push(SqlValue::Text(outcome.to_string()));
    }

    if let Some(from_timestamp) = filter.from_timestamp.as_ref() {
        clauses.push("timestamp >= ?".to_string());
        values.push(SqlValue::Text(ActionEntry::canonical_timestamp(
            from_timestamp,
        )));
    }

    if let Some(to_timestamp) = filter.to_timestamp.as_ref() {
        clauses.push("timestamp <= ?".to_string());
        values.push(SqlValue::Text(ActionEntry::canonical_timestamp(
            to_timestamp,
        )));
    }

    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY sequence ASC");

    let mut statement = conn.prepare(&sql)?;
    let rows = statement.query_map(rusqlite::params_from_iter(values.iter()), |row| {
        Ok(RawStoredEntry {
            sequence: row.get(0)?,
            id: row.get(1)?,
            timestamp: row.get(2)?,
            agent_id: row.get(3)?,
            agent_type: row.get(4)?,
            session_id: row.get(5)?,
            action_type: row.get(6)?,
            payload: row.get(7)?,
            context: row.get(8)?,
            outcome: row.get(9)?,
            previous_hash: row.get(10)?,
            entry_hash: row.get(11)?,
            org_id: row.get(12)?,
        })
    })?;

    let mut entries = Vec::new();
    for raw_row in rows {
        entries.push(parse_stored_entry(raw_row?)?);
    }

    Ok(entries)
}

fn lookup_sequence(conn: &Connection, id: Uuid) -> Result<i64> {
    let sequence = conn
        .query_row(
            "SELECT sequence FROM action_log WHERE id = ?1",
            params![id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;

    sequence.ok_or(StorageError::MissingBoundary(id))
}

fn resolve_filter_range(
    conn: &Connection,
    range: Option<&Range>,
) -> Result<(Option<i64>, Option<i64>)> {
    let start_sequence = match range.and_then(|range| range.from_id.as_deref()) {
        Some(id) => Some(lookup_sequence(conn, Uuid::parse_str(id)?)?),
        None => None,
    };
    let end_sequence = match range.and_then(|range| range.to_id.as_deref()) {
        Some(id) => Some(lookup_sequence(conn, Uuid::parse_str(id)?)?),
        None => None,
    };

    Ok((start_sequence, end_sequence))
}

pub(crate) fn parse_range_bounds(range: Option<&Range>) -> Result<(Option<Uuid>, Option<Uuid>)> {
    let from_id = range
        .and_then(|range| range.from_id.as_deref())
        .map(Uuid::parse_str)
        .transpose()?;
    let to_id = range
        .and_then(|range| range.to_id.as_deref())
        .map(Uuid::parse_str)
        .transpose()?;

    Ok((from_id, to_id))
}

fn load_previous_stored_hash(conn: &Connection, sequence: i64) -> Result<Option<String>> {
    let hash = conn
        .query_row(
            "SELECT entry_hash FROM action_log WHERE sequence < ?1 ORDER BY sequence DESC LIMIT 1",
            params![sequence],
            |row| row.get::<_, String>(0),
        )
        .optional()?;

    Ok(hash)
}

fn load_purge_resume_previous_hash(conn: &Connection, sequence: i64) -> Result<Option<String>> {
    let hash = conn
        .query_row(
            "SELECT resume_previous_hash
             FROM purge_events
             WHERE through_sequence < ?1
               AND resume_previous_hash IS NOT NULL
             ORDER BY through_sequence DESC
             LIMIT 1",
            params![sequence],
            |row| row.get::<_, String>(0),
        )
        .optional()?;

    Ok(hash)
}

fn append_checkpoint_if_due(
    transaction: &rusqlite::Transaction<'_>,
    end_sequence: i64,
    entry_id: Uuid,
    entry_hash: &str,
) -> Result<()> {
    let latest_checkpoint = load_latest_checkpoint(transaction)?;
    let last_checkpoint_end = latest_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.end_sequence)
        .unwrap_or(0);

    if end_sequence - last_checkpoint_end < LEDGER_CHECKPOINT_INTERVAL {
        return Ok(());
    }

    let start_sequence = last_checkpoint_end + 1;
    let previous_checkpoint_hash = latest_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.checkpoint_hash.clone())
        .unwrap_or_else(|| GENESIS_HASH.to_string());
    let checkpointed_at = ActionEntry::canonical_timestamp(&current_time());
    let entry_count = end_sequence - start_sequence + 1;
    let checkpoint_hash = calculate_checkpoint_hash(
        start_sequence,
        end_sequence,
        entry_count,
        &entry_id.to_string(),
        entry_hash,
        &previous_checkpoint_hash,
    );

    transaction.execute(
        "INSERT INTO ledger_checkpoints (
            checkpoint_id,
            checkpointed_at,
            start_sequence,
            end_sequence,
            entry_count,
            last_entry_id,
            last_entry_hash,
            previous_checkpoint_hash,
            checkpoint_hash
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            Uuid::new_v4().to_string(),
            checkpointed_at,
            start_sequence,
            end_sequence,
            entry_count,
            entry_id.to_string(),
            entry_hash,
            previous_checkpoint_hash,
            checkpoint_hash,
        ],
    )?;

    Ok(())
}

fn verify_checkpoints(
    conn: &Connection,
    entries: &[StoredEntry],
    violations: &mut Vec<IntegrityViolation>,
) -> Result<()> {
    let all_checkpoints = load_checkpoints(conn)?;
    let Some(first_entry) = entries.first() else {
        return Ok(());
    };
    let Some(latest_entry) = entries.last() else {
        return Ok(());
    };
    let first_sequence = first_entry.sequence;
    let checkpoints = all_checkpoints
        .iter()
        .filter(|checkpoint| checkpoint.end_sequence >= first_sequence)
        .cloned()
        .collect::<Vec<_>>();
    let mut expected_previous_checkpoint_hash = all_checkpoints
        .iter()
        .rev()
        .find(|checkpoint| checkpoint.end_sequence < first_sequence)
        .map(|checkpoint| checkpoint.checkpoint_hash.clone())
        .unwrap_or_else(|| GENESIS_HASH.to_string());

    if checkpoints.is_empty() {
        violations.push(IntegrityViolation {
            entry_id: latest_entry.entry.id,
            reason: "missing checkpoint coverage".to_string(),
            expected_previous_hash: None,
            actual_previous_hash: String::new(),
            expected_entry_hash: "checkpoint".to_string(),
            actual_entry_hash: String::new(),
        });
        return Ok(());
    }

    let mut expected_start_sequence = first_sequence;

    for checkpoint in checkpoints {
        if checkpoint.start_sequence != expected_start_sequence {
            violations.push(IntegrityViolation {
                entry_id: Uuid::parse_str(&checkpoint.last_entry_id)?,
                reason: "checkpoint coverage gap".to_string(),
                expected_previous_hash: Some(expected_start_sequence.to_string()),
                actual_previous_hash: checkpoint.start_sequence.to_string(),
                expected_entry_hash: checkpoint.checkpoint_hash.clone(),
                actual_entry_hash: checkpoint.checkpoint_hash.clone(),
            });
        }

        if checkpoint.previous_checkpoint_hash != expected_previous_checkpoint_hash {
            violations.push(IntegrityViolation {
                entry_id: Uuid::parse_str(&checkpoint.last_entry_id)?,
                reason: "checkpoint chain mismatch".to_string(),
                expected_previous_hash: Some(expected_previous_checkpoint_hash.clone()),
                actual_previous_hash: checkpoint.previous_checkpoint_hash.clone(),
                expected_entry_hash: checkpoint.checkpoint_hash.clone(),
                actual_entry_hash: checkpoint.checkpoint_hash.clone(),
            });
        }

        let expected_entry = entries
            .iter()
            .find(|entry| entry.sequence == checkpoint.end_sequence);
        match expected_entry {
            Some(stored_entry) => {
                if stored_entry.entry.id.to_string() != checkpoint.last_entry_id
                    || stored_entry.entry.entry_hash != checkpoint.last_entry_hash
                {
                    violations.push(IntegrityViolation {
                        entry_id: stored_entry.entry.id,
                        reason: "checkpoint entry mismatch".to_string(),
                        expected_previous_hash: Some(stored_entry.entry.id.to_string()),
                        actual_previous_hash: checkpoint.last_entry_id.clone(),
                        expected_entry_hash: stored_entry.entry.entry_hash.clone(),
                        actual_entry_hash: checkpoint.last_entry_hash.clone(),
                    });
                }
            }
            None => {
                violations.push(IntegrityViolation {
                    entry_id: latest_entry.entry.id,
                    reason: "checkpoint points past ledger".to_string(),
                    expected_previous_hash: Some(latest_entry.sequence.to_string()),
                    actual_previous_hash: checkpoint.end_sequence.to_string(),
                    expected_entry_hash: latest_entry.entry.entry_hash.clone(),
                    actual_entry_hash: checkpoint.last_entry_hash.clone(),
                });
            }
        }

        let expected_entry_count = checkpoint.end_sequence - checkpoint.start_sequence + 1;
        if checkpoint.entry_count != expected_entry_count {
            violations.push(IntegrityViolation {
                entry_id: Uuid::parse_str(&checkpoint.last_entry_id)?,
                reason: "checkpoint entry count mismatch".to_string(),
                expected_previous_hash: Some(expected_entry_count.to_string()),
                actual_previous_hash: checkpoint.entry_count.to_string(),
                expected_entry_hash: checkpoint.checkpoint_hash.clone(),
                actual_entry_hash: checkpoint.checkpoint_hash.clone(),
            });
        }

        let recomputed_hash = calculate_checkpoint_hash(
            checkpoint.start_sequence,
            checkpoint.end_sequence,
            checkpoint.entry_count,
            &checkpoint.last_entry_id,
            &checkpoint.last_entry_hash,
            &checkpoint.previous_checkpoint_hash,
        );
        if checkpoint.checkpoint_hash != recomputed_hash {
            violations.push(IntegrityViolation {
                entry_id: Uuid::parse_str(&checkpoint.last_entry_id)?,
                reason: "checkpoint hash mismatch".to_string(),
                expected_previous_hash: Some(checkpoint.previous_checkpoint_hash.clone()),
                actual_previous_hash: checkpoint.previous_checkpoint_hash.clone(),
                expected_entry_hash: recomputed_hash,
                actual_entry_hash: checkpoint.checkpoint_hash.clone(),
            });
        }

        expected_start_sequence = checkpoint.end_sequence + 1;
        expected_previous_checkpoint_hash = checkpoint.checkpoint_hash;
    }

    if expected_start_sequence - 1 != latest_entry.sequence {
        violations.push(IntegrityViolation {
            entry_id: latest_entry.entry.id,
            reason: "missing checkpoint coverage".to_string(),
            expected_previous_hash: Some(latest_entry.sequence.to_string()),
            actual_previous_hash: (expected_start_sequence - 1).to_string(),
            expected_entry_hash: latest_entry.entry.entry_hash.clone(),
            actual_entry_hash: latest_entry.entry.entry_hash.clone(),
        });
    }

    Ok(())
}

fn load_checkpoints(conn: &Connection) -> Result<Vec<CheckpointCoverage>> {
    let mut statement = conn.prepare(
        "SELECT checkpoint_id, checkpointed_at, start_sequence, end_sequence, entry_count,
                last_entry_id, last_entry_hash, previous_checkpoint_hash, checkpoint_hash
         FROM ledger_checkpoints
         ORDER BY end_sequence ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(CheckpointCoverage {
            id: row.get(0)?,
            checkpointed_at: row.get(1)?,
            start_sequence: row.get(2)?,
            end_sequence: row.get(3)?,
            entry_count: row.get(4)?,
            last_entry_id: row.get(5)?,
            last_entry_hash: row.get(6)?,
            previous_checkpoint_hash: row.get(7)?,
            checkpoint_hash: row.get(8)?,
        })
    })?;

    let mut checkpoints = Vec::new();
    for row in rows {
        checkpoints.push(row?);
    }
    Ok(checkpoints)
}

fn load_latest_checkpoint(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<Option<CheckpointCoverage>> {
    transaction
        .query_row(
            "SELECT checkpoint_id, checkpointed_at, start_sequence, end_sequence, entry_count,
                    last_entry_id, last_entry_hash, previous_checkpoint_hash, checkpoint_hash
             FROM ledger_checkpoints
             ORDER BY end_sequence DESC
             LIMIT 1",
            [],
            |row| {
                Ok(CheckpointCoverage {
                    id: row.get(0)?,
                    checkpointed_at: row.get(1)?,
                    start_sequence: row.get(2)?,
                    end_sequence: row.get(3)?,
                    entry_count: row.get(4)?,
                    last_entry_id: row.get(5)?,
                    last_entry_hash: row.get(6)?,
                    previous_checkpoint_hash: row.get(7)?,
                    checkpoint_hash: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(StorageError::from)
}

pub(crate) fn calculate_checkpoint_hash(
    start_sequence: i64,
    end_sequence: i64,
    entry_count: i64,
    last_entry_id: &str,
    last_entry_hash: &str,
    previous_checkpoint_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(start_sequence.to_string().as_bytes());
    hasher.update(end_sequence.to_string().as_bytes());
    hasher.update(entry_count.to_string().as_bytes());
    hasher.update(last_entry_id.as_bytes());
    hasher.update(last_entry_hash.as_bytes());
    hasher.update(previous_checkpoint_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(crate) fn load_latest_hash(conn: &Connection) -> Result<Option<String>> {
    conn.query_row(
        "SELECT entry_hash FROM action_log ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(StorageError::from)
}

fn load_latest_hash_for_scope(
    conn: &Connection,
    org_id: &str,
    project_id: &str,
) -> Result<Option<String>> {
    conn.query_row(
        "SELECT entry_hash
         FROM action_log
         WHERE org_id = ?1 AND project_id = ?2
         ORDER BY sequence DESC
         LIMIT 1",
        params![org_id, project_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(StorageError::from)
}

fn verify_chain_for_scope(
    conn: &Connection,
    scope: &StorageScope,
) -> Result<Vec<IntegrityViolation>> {
    let entries = load_entries_for_range(
        conn,
        None,
        None,
        Some(scope.org_id.as_str()),
        Some(scope.project_id.as_str()),
    )?;
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

#[derive(Debug)]
struct LatestEntrySummary {
    sequence: i64,
    entry_id: String,
    ledger_root_hash: String,
}

#[derive(Debug)]
struct RawCheckpointRow {
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

#[derive(Debug)]
struct MerkleLeafRow {
    sequence: i64,
    entry_id: Uuid,
    entry_hash: String,
}

fn load_latest_entry_summary(conn: &Connection) -> Result<Option<LatestEntrySummary>> {
    conn.query_row(
        "SELECT sequence, id, entry_hash
         FROM action_log
         ORDER BY sequence DESC
         LIMIT 1",
        [],
        |row| {
            Ok(LatestEntrySummary {
                sequence: row.get(0)?,
                entry_id: row.get(1)?,
                ledger_root_hash: row.get(2)?,
            })
        },
    )
    .optional()
    .map_err(StorageError::from)
}

pub(crate) fn rebuild_merkle_checkpoints(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM merkle_checkpoints", [])?;

    let max_sequence = conn
        .query_row("SELECT MAX(sequence) FROM action_log", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .optional()?
        .flatten();

    let Some(max_sequence) = max_sequence else {
        return Ok(());
    };

    for batch_index in 0..=batch_index_for_sequence(max_sequence) {
        upsert_merkle_checkpoint_for_batch(conn, batch_index)?;
    }

    Ok(())
}

fn upsert_merkle_checkpoint_for_sequence(conn: &Connection, sequence: i64) -> Result<()> {
    upsert_merkle_checkpoint_for_batch(conn, batch_index_for_sequence(sequence))
}

fn upsert_merkle_checkpoint_for_batch(conn: &Connection, batch_index: i64) -> Result<()> {
    let (start_sequence, end_sequence) = batch_bounds(batch_index);
    let leaves = load_merkle_leaves_for_batch(conn, batch_index)?;

    if leaves.is_empty() {
        conn.execute(
            "DELETE FROM merkle_checkpoints WHERE batch_index = ?1",
            params![batch_index],
        )?;
        return Ok(());
    }

    let merkle_root = compute_root(
        &leaves
            .iter()
            .map(|leaf| leaf.entry_hash.clone())
            .collect::<Vec<_>>(),
    )
    .ok_or_else(|| {
        StorageError::InvalidInput("cannot checkpoint empty merkle batch".to_string())
    })?;
    let first = &leaves[0];
    let last = leaves.last().ok_or_else(|| {
        StorageError::InvalidInput("cannot checkpoint empty merkle batch".to_string())
    })?;
    let checkpointed_at = ActionEntry::canonical_timestamp(&current_time());

    conn.execute(
        "INSERT INTO merkle_checkpoints (
            batch_index,
            start_sequence,
            end_sequence,
            start_entry_id,
            end_entry_id,
            entry_count,
            merkle_root,
            checkpointed_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(batch_index) DO UPDATE SET
            start_sequence = excluded.start_sequence,
            end_sequence = excluded.end_sequence,
            start_entry_id = excluded.start_entry_id,
            end_entry_id = excluded.end_entry_id,
            entry_count = excluded.entry_count,
            merkle_root = excluded.merkle_root,
            checkpointed_at = excluded.checkpointed_at",
        params![
            batch_index,
            first.sequence.max(start_sequence),
            last.sequence.min(end_sequence),
            first.entry_id.to_string(),
            last.entry_id.to_string(),
            leaves.len() as i64,
            merkle_root,
            checkpointed_at,
        ],
    )?;

    Ok(())
}

fn load_merkle_leaves_for_batch(conn: &Connection, batch_index: i64) -> Result<Vec<MerkleLeafRow>> {
    let (start_sequence, end_sequence) = batch_bounds(batch_index);
    let mut statement = conn.prepare(
        "SELECT sequence, id, entry_hash
         FROM action_log
         WHERE sequence >= ?1 AND sequence <= ?2
         ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map(params![start_sequence, end_sequence], |row| {
        let entry_id = row.get::<_, String>(1)?;
        Ok(MerkleLeafRow {
            sequence: row.get(0)?,
            entry_id: Uuid::parse_str(&entry_id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
            entry_hash: row.get(2)?,
        })
    })?;

    let mut leaves = Vec::new();
    for row in rows {
        leaves.push(row?);
    }

    Ok(leaves)
}

fn load_merkle_checkpoints(conn: &Connection) -> Result<Vec<MerkleCheckpoint>> {
    let mut statement = conn.prepare(
        "SELECT batch_index, start_sequence, end_sequence, start_entry_id, end_entry_id,
                entry_count, merkle_root, checkpointed_at
         FROM merkle_checkpoints
         ORDER BY batch_index ASC",
    )?;
    let rows = statement.query_map([], |row| {
        let start_entry_id = row.get::<_, String>(3)?;
        let end_entry_id = row.get::<_, String>(4)?;
        let checkpointed_at = row.get::<_, String>(7)?;
        Ok(MerkleCheckpoint {
            batch_index: row.get(0)?,
            start_sequence: row.get(1)?,
            end_sequence: row.get(2)?,
            start_entry_id: Uuid::parse_str(&start_entry_id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
            end_entry_id: Uuid::parse_str(&end_entry_id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
            entry_count: row.get::<_, i64>(5)? as usize,
            merkle_root: row.get(6)?,
            checkpointed_at: DateTime::parse_from_rfc3339(&checkpointed_at)
                .map(|timestamp| timestamp.with_timezone(&Utc))
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
        })
    })?;

    let mut checkpoints = Vec::new();
    for row in rows {
        checkpoints.push(row?);
    }

    Ok(checkpoints)
}

fn load_merkle_proof(conn: &Connection, entry_id: Uuid) -> Result<Option<MerkleInclusionProof>> {
    let target = conn
        .query_row(
            "SELECT sequence, entry_hash FROM action_log WHERE id = ?1",
            params![entry_id.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;

    let Some((sequence, entry_hash)) = target else {
        return Ok(None);
    };

    let batch_index = batch_index_for_sequence(sequence);
    let leaves = load_merkle_leaves_for_batch(conn, batch_index)?;
    let leaf_index = leaves
        .iter()
        .position(|leaf| leaf.entry_id == entry_id)
        .ok_or_else(|| {
            StorageError::InvalidInput(format!(
                "entry {entry_id} missing from merkle batch {batch_index}"
            ))
        })?;
    let checkpoint = conn
        .query_row(
            "SELECT start_sequence, end_sequence, merkle_root
             FROM merkle_checkpoints
             WHERE batch_index = ?1",
            params![batch_index],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((batch_start_sequence, batch_end_sequence, batch_root)) = checkpoint else {
        return Ok(None);
    };

    let leaf_hashes = leaves
        .iter()
        .map(|leaf| leaf.entry_hash.clone())
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
    if leaves[leaf_index].entry_hash != entry_hash {
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

fn verify_merkle_checkpoints(
    conn: &Connection,
    entries: &[StoredEntry],
    violations: &mut Vec<IntegrityViolation>,
) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    for batch in entries.chunk_by(|left, right| {
        batch_index_for_sequence(left.sequence) == batch_index_for_sequence(right.sequence)
    }) {
        let batch_index = batch_index_for_sequence(batch[0].sequence);
        let checkpoint = conn
            .query_row(
                "SELECT start_sequence, end_sequence, start_entry_id, end_entry_id, entry_count, merkle_root
                 FROM merkle_checkpoints
                 WHERE batch_index = ?1",
                params![batch_index],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            start_sequence,
            end_sequence,
            start_entry_id,
            end_entry_id,
            entry_count,
            merkle_root,
        )) = checkpoint
        else {
            violations.push(IntegrityViolation {
                entry_id: batch[0].entry.id,
                reason: format!("missing merkle checkpoint for batch {batch_index}"),
                expected_previous_hash: None,
                actual_previous_hash: String::new(),
                expected_entry_hash: "checkpoint".to_string(),
                actual_entry_hash: String::new(),
            });
            continue;
        };

        let computed_root = compute_root(
            &batch
                .iter()
                .map(|stored_entry| stored_entry.entry.entry_hash.clone())
                .collect::<Vec<_>>(),
        )
        .ok_or_else(|| {
            StorageError::InvalidInput("cannot verify empty merkle batch".to_string())
        })?;
        let metadata_mismatch = start_sequence != batch[0].sequence
            || end_sequence
                != batch
                    .last()
                    .map(|stored_entry| stored_entry.sequence)
                    .unwrap_or(batch[0].sequence)
            || start_entry_id != batch[0].entry.id.to_string()
            || end_entry_id
                != batch
                    .last()
                    .map(|stored_entry| stored_entry.entry.id.to_string())
                    .unwrap_or_else(|| batch[0].entry.id.to_string())
            || entry_count != batch.len() as i64;

        if metadata_mismatch {
            violations.push(IntegrityViolation {
                entry_id: batch[0].entry.id,
                reason: format!("merkle checkpoint metadata mismatch for batch {batch_index}"),
                expected_previous_hash: None,
                actual_previous_hash: merkle_root.clone(),
                expected_entry_hash: format!(
                    "{}:{}:{}:{}:{}",
                    batch[0].sequence,
                    batch
                        .last()
                        .map(|stored_entry| stored_entry.sequence)
                        .unwrap_or(batch[0].sequence),
                    batch[0].entry.id,
                    batch
                        .last()
                        .map(|stored_entry| stored_entry.entry.id)
                        .unwrap_or(batch[0].entry.id),
                    batch.len()
                ),
                actual_entry_hash: format!(
                    "{start_sequence}:{end_sequence}:{start_entry_id}:{end_entry_id}:{entry_count}"
                ),
            });
        }

        if computed_root != merkle_root {
            violations.push(IntegrityViolation {
                entry_id: batch[0].entry.id,
                reason: format!("merkle root mismatch for batch {batch_index}"),
                expected_previous_hash: None,
                actual_previous_hash: merkle_root,
                expected_entry_hash: computed_root,
                actual_entry_hash: batch[0].entry.entry_hash.clone(),
            });
        }
    }

    Ok(())
}

pub(crate) fn initialize_root_anchor(conn: &Connection) -> Result<()> {
    let latest_hash = load_latest_hash(conn)?;
    if let Some(path) = connection_path(conn)?
        && !path.exists()
    {
        write_root_anchor(&path, latest_hash.as_deref())?;
    }

    Ok(())
}

pub(crate) fn persist_root_anchor(conn: &Connection, latest_hash: Option<&str>) -> Result<()> {
    if let Some(path) = connection_path(conn)? {
        write_root_anchor(&path, latest_hash)?;
    }

    Ok(())
}

pub(crate) fn load_root_anchor(conn: &Connection) -> Result<Option<String>> {
    let Some(path) = connection_path(conn)? else {
        return Ok(None);
    };

    if !path.exists() {
        return Ok(None);
    }

    let value = fs::read_to_string(path)?;
    let value = value.trim().to_string();
    Ok((!value.is_empty()).then_some(value))
}

pub(crate) fn write_root_anchor(path: &Path, latest_hash: Option<&str>) -> Result<()> {
    if let Some(latest_hash) = latest_hash {
        let mut temp_path = path.as_os_str().to_os_string();
        temp_path.push(".tmp");
        let temp_path = PathBuf::from(temp_path);
        fs::write(&temp_path, latest_hash)?;
        fs::rename(temp_path, path)?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }

    Ok(())
}

pub(crate) fn connection_path(conn: &Connection) -> Result<Option<PathBuf>> {
    let database_path = conn
        .query_row("PRAGMA database_list", [], |row| row.get::<_, String>(2))
        .optional()?;

    Ok(database_path.and_then(|path| {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(root_anchor_path(Path::new(trimmed)))
        }
    }))
}

fn root_anchor_path(path: &Path) -> PathBuf {
    let mut anchor_path = path.as_os_str().to_os_string();
    anchor_path.push(".root");
    PathBuf::from(anchor_path)
}

fn upsert_checkpoint_signing_key(conn: &Connection, metadata: &SigningKeyMetadata) -> Result<()> {
    let existing = conn
        .query_row(
            "SELECT algorithm, public_key, fingerprint, label, created_at
             FROM checkpoint_signing_keys
             WHERE key_id = ?1",
            params![&metadata.key_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;

    if let Some((algorithm, public_key, fingerprint, label, created_at)) = existing {
        let existing = SigningKeyMetadata {
            key_id: metadata.key_id.clone(),
            algorithm: parse_signature_algorithm(&algorithm)?,
            public_key,
            fingerprint,
            label,
            created_at,
        };
        if existing != *metadata {
            return Err(StorageError::Checkpoint(format!(
                "checkpoint signing key '{}' metadata does not match existing record",
                metadata.key_id
            )));
        }
        return Ok(());
    }

    conn.execute(
        "INSERT INTO checkpoint_signing_keys (
            key_id,
            algorithm,
            public_key,
            fingerprint,
            label,
            created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            &metadata.key_id,
            metadata.algorithm.to_string(),
            &metadata.public_key,
            &metadata.fingerprint,
            &metadata.label,
            &metadata.created_at,
        ],
    )?;

    Ok(())
}

fn load_signed_checkpoints(conn: &Connection) -> Result<Vec<SignedCheckpoint>> {
    let mut statement = conn.prepare(
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
         FROM checkpoints c
         JOIN checkpoint_signing_keys k ON k.key_id = c.key_id
         ORDER BY c.created_at DESC, c.checkpoint_id DESC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(RawCheckpointRow {
            checkpoint_id: row.get(0)?,
            created_at: row.get(1)?,
            sequence: row.get(2)?,
            entry_id: row.get(3)?,
            ledger_root_hash: row.get(4)?,
            checkpoint_hash: row.get(5)?,
            signature: row.get(6)?,
            key_id: row.get(7)?,
            algorithm: row.get(8)?,
            public_key: row.get(9)?,
            fingerprint: row.get(10)?,
            label: row.get(11)?,
            key_created_at: row.get(12)?,
        })
    })?;

    let mut checkpoints = Vec::new();
    for row in rows {
        checkpoints.push(parse_signed_checkpoint(conn, row?)?);
    }

    Ok(checkpoints)
}

fn load_signed_checkpoint(
    conn: &Connection,
    checkpoint_id: &str,
) -> Result<Option<SignedCheckpoint>> {
    let row = conn
        .query_row(
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
             FROM checkpoints c
             JOIN checkpoint_signing_keys k ON k.key_id = c.key_id
             WHERE c.checkpoint_id = ?1",
            params![checkpoint_id],
            |row| {
                Ok(RawCheckpointRow {
                    checkpoint_id: row.get(0)?,
                    created_at: row.get(1)?,
                    sequence: row.get(2)?,
                    entry_id: row.get(3)?,
                    ledger_root_hash: row.get(4)?,
                    checkpoint_hash: row.get(5)?,
                    signature: row.get(6)?,
                    key_id: row.get(7)?,
                    algorithm: row.get(8)?,
                    public_key: row.get(9)?,
                    fingerprint: row.get(10)?,
                    label: row.get(11)?,
                    key_created_at: row.get(12)?,
                })
            },
        )
        .optional()?;

    row.map(|row| parse_signed_checkpoint(conn, row))
        .transpose()
}

fn load_latest_signed_checkpoint(conn: &Connection) -> Result<Option<SignedCheckpoint>> {
    let checkpoint_id = conn
        .query_row(
            "SELECT checkpoint_id
             FROM checkpoints
             ORDER BY created_at DESC, checkpoint_id DESC
             LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;

    checkpoint_id
        .as_deref()
        .map(|checkpoint_id| load_signed_checkpoint(conn, checkpoint_id))
        .transpose()
        .map(|value| value.flatten())
}

fn parse_signed_checkpoint(conn: &Connection, row: RawCheckpointRow) -> Result<SignedCheckpoint> {
    let anchors = load_checkpoint_anchors(conn, &row.checkpoint_id)?;
    Ok(SignedCheckpoint {
        checkpoint_id: row.checkpoint_id,
        created_at: row.created_at,
        sequence: row.sequence,
        entry_id: row.entry_id,
        ledger_root_hash: row.ledger_root_hash,
        checkpoint_hash: row.checkpoint_hash,
        signature: row.signature,
        key: SigningKeyMetadata {
            key_id: row.key_id,
            algorithm: parse_signature_algorithm(&row.algorithm)?,
            public_key: row.public_key,
            fingerprint: row.fingerprint,
            label: row.label,
            created_at: row.key_created_at,
        },
        anchors,
    })
}

fn load_checkpoint_anchors(
    conn: &Connection,
    checkpoint_id: &str,
) -> Result<Vec<ExternalAnchorRecord>> {
    let mut statement = conn.prepare(
        "SELECT anchor_id, provider, reference, anchored_at, anchored_hash, metadata
         FROM checkpoint_anchors
         WHERE checkpoint_id = ?1
         ORDER BY anchored_at ASC, anchor_id ASC",
    )?;
    let rows = statement.query_map(params![checkpoint_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;

    let mut anchors = Vec::new();
    for row in rows {
        let (anchor_id, provider, reference, anchored_at, anchored_hash, metadata) = row?;
        anchors.push(ExternalAnchorRecord {
            anchor_id,
            provider,
            reference,
            anchored_at,
            anchored_hash,
            metadata: serde_json::from_str(&metadata)?,
        });
    }
    Ok(anchors)
}

fn verify_loaded_checkpoint(checkpoint: SignedCheckpoint) -> Result<VerifiedCheckpoint> {
    let payload = CheckpointPayload {
        checkpoint_id: checkpoint.checkpoint_id.clone(),
        created_at: checkpoint.created_at.clone(),
        sequence: checkpoint.sequence,
        entry_id: checkpoint.entry_id.clone(),
        ledger_root_hash: checkpoint.ledger_root_hash.clone(),
    };
    let verification = verify_signed_checkpoint(
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

fn parse_signature_algorithm(value: &str) -> Result<crate::checkpoint::SignatureAlgorithm> {
    match value {
        "ed25519" => Ok(crate::checkpoint::SignatureAlgorithm::Ed25519),
        "ecdsa_p256_sha256" => Ok(crate::checkpoint::SignatureAlgorithm::EcdsaP256Sha256),
        other => Err(StorageError::Checkpoint(format!(
            "unknown checkpoint signature algorithm: {other}"
        ))),
    }
}

pub(crate) fn parse_stored_entry(raw: RawStoredEntry) -> Result<StoredEntry> {
    let timestamp = DateTime::parse_from_rfc3339(&raw.timestamp)?.with_timezone(&Utc);
    let action_type =
        ActionType::from_str(&raw.action_type).map_err(StorageError::InvalidActionType)?;
    let payload = serde_json::from_str(&raw.payload)?;
    let context = serde_json::from_str(&raw.context)?;

    Ok(StoredEntry {
        sequence: raw.sequence,
        entry: ActionEntry {
            id: Uuid::parse_str(&raw.id)?,
            timestamp,
            agent_id: raw.agent_id,
            agent_type: raw.agent_type,
            session_id: raw.session_id,
            action_type,
            payload,
            context,
            outcome: raw.outcome,
            previous_hash: raw.previous_hash,
            entry_hash: raw.entry_hash,
        },
        org_id: raw.org_id,
    })
}

fn record_integrity_check(
    conn: &Connection,
    from_id: Option<Uuid>,
    to_id: Option<Uuid>,
    violations: &[IntegrityViolation],
) -> Result<()> {
    let details = Value::Array(
        violations
            .iter()
            .map(|violation| {
                json!({
                    "entry_id": violation.entry_id.to_string(),
                    "reason": violation.reason,
                    "expected_previous_hash": violation.expected_previous_hash,
                    "actual_previous_hash": violation.actual_previous_hash,
                    "expected_entry_hash": violation.expected_entry_hash,
                    "actual_entry_hash": violation.actual_entry_hash,
                })
            })
            .collect(),
    );

    conn.execute(
        "INSERT INTO chain_integrity_checks (
            check_id,
            checked_at,
            from_entry_id,
            to_entry_id,
            violation_count,
            details
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            Uuid::new_v4().to_string(),
            ActionEntry::canonical_timestamp(&current_time()),
            from_id.map(|id| id.to_string()),
            to_id.map(|id| id.to_string()),
            violations.len() as i64,
            details.to_string(),
        ],
    )?;

    Ok(())
}

fn action_log_envelope(entry: &ActionEntry, idempotency_key: Option<&str>) -> ActionLogEnvelope {
    ActionLogEnvelope {
        event_kind: metadata_string(&entry.context, &["trailing", "event_kind"])
            .or_else(|| metadata_string(&entry.context, &["trailing", "kind"]))
            .or_else(|| json_string_paths(&entry.payload, &[&["event_kind"], &["kind"]])),
        schema_version: metadata_string(&entry.context, &["trailing", "schema_version"]).or_else(
            || json_string_paths(&entry.payload, &[&["schema_version"], &["schemaVersion"]]),
        ),
        trace_id: metadata_string(&entry.context, &["trailing", "trace_id"])
            .or_else(|| json_string_paths(&entry.context, &[&["trace_id"]]))
            .or_else(|| {
                json_string_paths(
                    &entry.payload,
                    &[
                        &["trace_id"],
                        &["traceId"],
                        &["attributes", "trace_id"],
                        &["attributes", "traceId"],
                    ],
                )
            }),
        span_id: metadata_string(&entry.context, &["trailing", "span_id"])
            .or_else(|| json_string_paths(&entry.context, &[&["span_id"]]))
            .or_else(|| {
                json_string_paths(
                    &entry.payload,
                    &[
                        &["span_id"],
                        &["spanId"],
                        &["attributes", "span_id"],
                        &["attributes", "spanId"],
                    ],
                )
            }),
        idempotency_key: idempotency_key
            .map(ToString::to_string)
            .or_else(|| metadata_string(&entry.context, &["trailing", "idempotency_key"]))
            .or_else(|| {
                json_string_paths(&entry.payload, &[&["idempotency_key"], &["idempotencyKey"]])
            }),
        request_metadata: metadata_json(&entry.context, &["trailing", "request_metadata"])
            .or_else(|| {
                json_value_paths(
                    &entry.payload,
                    &[
                        &["request_metadata"],
                        &["requestMetadata"],
                        &["request", "metadata"],
                        &["action", "request_metadata"],
                        &["action", "requestMetadata"],
                        &["action", "request"],
                        &["metadata", "request"],
                    ],
                )
            })
            .map(|value| value.to_string()),
        result_metadata: metadata_json(&entry.context, &["trailing", "result_metadata"])
            .or_else(|| {
                json_value_paths(
                    &entry.payload,
                    &[
                        &["result_metadata"],
                        &["resultMetadata"],
                        &["result", "metadata"],
                        &["action", "result_metadata"],
                        &["action", "resultMetadata"],
                        &["action", "result"],
                        &["metadata", "result"],
                    ],
                )
            })
            .or_else(|| json_value_paths(&entry.context, &[&["result"]]))
            .map(|value| value.to_string()),
    }
}

fn metadata_string(context: &Value, path: &[&str]) -> Option<String> {
    json_value_path(context, path).and_then(json_scalar_to_string)
}

fn metadata_json(context: &Value, path: &[&str]) -> Option<Value> {
    json_value_path(context, path)
        .cloned()
        .filter(value_has_content)
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

pub(crate) fn validate_entry_hashes(
    entry: &ActionEntry,
    expected_previous_hash: &str,
) -> Result<()> {
    if entry.previous_hash != expected_previous_hash {
        return Err(StorageError::BrokenAppendChain {
            expected: expected_previous_hash.to_string(),
            actual: entry.previous_hash.clone(),
        });
    }

    let expected_entry_hash = entry.calculate_hash();
    if entry.entry_hash != expected_entry_hash {
        return Err(StorageError::InvalidEntryHash {
            expected: expected_entry_hash,
            actual: entry.entry_hash.clone(),
        });
    }

    Ok(())
}

pub(crate) fn build_merkle_root(hashes: &[String]) -> String {
    match hashes.len() {
        0 => GENESIS_HASH.to_string(),
        1 => hashes[0].clone(),
        _ => {
            let mut level = hashes.to_vec();
            while level.len() > 1 {
                let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
                let mut index = 0usize;
                while index < level.len() {
                    let left = &level[index];
                    let right = level.get(index + 1).unwrap_or(left);
                    let mut hasher = Sha256::new();
                    hasher.update(left.as_bytes());
                    hasher.update(right.as_bytes());
                    next_level.push(format!("{:x}", hasher.finalize()));
                    index += 2;
                }
                level = next_level;
            }

            level.pop().unwrap_or_else(|| GENESIS_HASH.to_string())
        }
    }
}

pub(crate) fn compute_merkle_root_from_batches(
    batch_roots: Vec<String>,
    partial_hashes: Vec<String>,
) -> Result<String> {
    let mut layer = batch_roots;
    if !partial_hashes.is_empty() {
        layer.push(build_merkle_root(&partial_hashes));
    }

    if layer.is_empty() {
        return Err(StorageError::InvalidInput(
            "cannot checkpoint an empty ledger".to_string(),
        ));
    }

    Ok(build_merkle_root(&layer))
}

pub(crate) fn ensure_sqlite_merkle_batches(conn: &Connection) -> Result<()> {
    let next_start = conn
        .query_row(
            "SELECT COALESCE(MAX(end_sequence), 0) + 1 FROM merkle_batches",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(1);
    let latest_sequence = conn
        .query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM action_log",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0);

    if latest_sequence < next_start {
        return Ok(());
    }

    let mut batch_start = next_start;
    while batch_start + MERKLE_BATCH_SIZE - 1 <= latest_sequence {
        let batch_end = batch_start + MERKLE_BATCH_SIZE - 1;
        let mut statement = conn.prepare(
            "SELECT entry_hash FROM action_log
             WHERE sequence >= ?1 AND sequence <= ?2
             ORDER BY sequence ASC",
        )?;
        let rows = statement.query_map(params![batch_start, batch_end], |row| {
            row.get::<_, String>(0)
        })?;
        let mut hashes = Vec::new();
        for row in rows {
            hashes.push(row?);
        }
        conn.execute(
            "INSERT OR IGNORE INTO merkle_batches (
                start_sequence,
                end_sequence,
                leaf_count,
                root_hash,
                created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                batch_start,
                batch_end,
                MERKLE_BATCH_SIZE,
                build_merkle_root(&hashes),
                ActionEntry::canonical_timestamp(&current_time()),
            ],
        )?;
        batch_start += MERKLE_BATCH_SIZE;
    }

    Ok(())
}

fn load_sqlite_merkle_batches(conn: &Connection) -> Result<Vec<MerkleBatch>> {
    let mut statement = conn.prepare(
        "SELECT batch_id, start_sequence, end_sequence, leaf_count, root_hash, created_at
         FROM merkle_batches
         ORDER BY start_sequence ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(MerkleBatch {
            batch_id: row.get(0)?,
            start_sequence: row.get(1)?,
            end_sequence: row.get(2)?,
            leaf_count: row.get(3)?,
            root_hash: row.get(4)?,
            created_at: row.get(5)?,
        })
    })?;
    let mut batches = Vec::new();
    for row in rows {
        batches.push(row?);
    }
    Ok(batches)
}

fn create_sqlite_checkpoint(conn: &Connection) -> Result<LedgerCheckpoint> {
    let head = conn
        .query_row(
            "SELECT sequence, id, entry_hash FROM action_log ORDER BY sequence DESC LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((sequence, entry_id, entry_hash)) = head else {
        return Err(StorageError::InvalidInput(
            "cannot checkpoint an empty ledger".to_string(),
        ));
    };

    let transaction = conn.unchecked_transaction()?;
    append_checkpoint_if_due(
        &transaction,
        sequence,
        Uuid::parse_str(&entry_id)?,
        &entry_hash,
    )?;
    transaction.commit()?;

    load_sqlite_checkpoint_for_sequence(conn, sequence)?.ok_or_else(|| {
        StorageError::InvalidInput("failed to materialize sqlite checkpoint".to_string())
    })
}

fn load_latest_sqlite_checkpoint(conn: &Connection) -> Result<Option<LedgerCheckpoint>> {
    let checkpoint = conn
        .query_row(
            "SELECT checkpoint_id, checkpointed_at, end_sequence, last_entry_id, last_entry_hash
             FROM ledger_checkpoints
             ORDER BY end_sequence DESC
             LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;

    checkpoint
        .map(
            |(checkpoint_id, created_at, sequence, entry_id, entry_hash)| -> Result<_> {
                Ok(LedgerCheckpoint {
                    checkpoint_id,
                    sequence,
                    entry_id,
                    entry_hash,
                    merkle_root: compute_sqlite_checkpoint_merkle_root(conn, sequence)?,
                    created_at,
                })
            },
        )
        .transpose()
}

fn load_sqlite_checkpoint_for_sequence(
    conn: &Connection,
    sequence: i64,
) -> Result<Option<LedgerCheckpoint>> {
    let checkpoint = conn
        .query_row(
            "SELECT checkpoint_id, checkpointed_at, end_sequence, last_entry_id, last_entry_hash
             FROM ledger_checkpoints
             WHERE end_sequence = ?1",
            params![sequence],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;

    checkpoint
        .map(
            |(checkpoint_id, created_at, end_sequence, entry_id, entry_hash)| -> Result<_> {
                Ok(LedgerCheckpoint {
                    checkpoint_id,
                    sequence: end_sequence,
                    entry_id,
                    entry_hash,
                    merkle_root: compute_sqlite_checkpoint_merkle_root(conn, end_sequence)?,
                    created_at,
                })
            },
        )
        .transpose()
}

fn compute_sqlite_checkpoint_merkle_root(conn: &Connection, sequence: i64) -> Result<String> {
    let batch_roots = {
        let mut statement = conn.prepare(
            "SELECT root_hash FROM merkle_batches
             WHERE end_sequence <= ?1
             ORDER BY start_sequence ASC",
        )?;
        let rows = statement.query_map(params![sequence], |row| row.get::<_, String>(0))?;
        let mut roots = Vec::new();
        for row in rows {
            roots.push(row?);
        }
        roots
    };

    let covered = batch_roots.len() as i64 * MERKLE_BATCH_SIZE;
    let partial_hashes = if covered < sequence {
        let mut statement = conn.prepare(
            "SELECT entry_hash FROM action_log
             WHERE sequence > ?1 AND sequence <= ?2
             ORDER BY sequence ASC",
        )?;
        let rows =
            statement.query_map(params![covered, sequence], |row| row.get::<_, String>(0))?;
        let mut hashes = Vec::new();
        for row in rows {
            hashes.push(row?);
        }
        hashes
    } else {
        Vec::new()
    };

    compute_merkle_root_from_batches(batch_roots, partial_hashes)
}

pub(crate) async fn record_integrity_check_details(
    client: &tokio_postgres::Client,
    from_id: Option<Uuid>,
    to_id: Option<Uuid>,
    violations: &[IntegrityViolation],
) -> Result<()> {
    let details = Value::Array(
        violations
            .iter()
            .map(|violation| {
                json!({
                    "entry_id": violation.entry_id.to_string(),
                    "reason": violation.reason,
                    "expected_previous_hash": violation.expected_previous_hash,
                    "actual_previous_hash": violation.actual_previous_hash,
                    "expected_entry_hash": violation.expected_entry_hash,
                    "actual_entry_hash": violation.actual_entry_hash,
                })
            })
            .collect(),
    );

    client
        .execute(
            "INSERT INTO chain_integrity_checks (
                check_id,
                checked_at,
                from_entry_id,
                to_entry_id,
                violation_count,
                details
             ) VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &Uuid::new_v4().to_string(),
                &ActionEntry::canonical_timestamp(&current_time()),
                &from_id.map(|id| id.to_string()),
                &to_id.map(|id| id.to_string()),
                &(violations.len() as i64),
                &details.to_string(),
            ],
        )
        .await
        .map(|_| ())
        .map_err(|error| StorageError::Postgres(error.to_string()))
}
