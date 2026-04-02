pub mod hashing;

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::ledger::hashing::{HashSpec, canonical_timestamp};
use crate::storage::{IntegrityViolation, Result as StorageResult};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub type Result<T> = StorageResult<T>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    ToolCall,
    SystemWrite,
    DataAccess,
    HumanOverride,
    PolicyCheck,
    Decision,
}

impl Display for ActionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::ToolCall => "ToolCall",
            Self::SystemWrite => "SystemWrite",
            Self::DataAccess => "DataAccess",
            Self::HumanOverride => "HumanOverride",
            Self::PolicyCheck => "PolicyCheck",
            Self::Decision => "Decision",
        };

        f.write_str(value)
    }
}

impl FromStr for ActionType {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "ToolCall" => Ok(Self::ToolCall),
            "SystemWrite" => Ok(Self::SystemWrite),
            "DataAccess" => Ok(Self::DataAccess),
            "HumanOverride" => Ok(Self::HumanOverride),
            "PolicyCheck" => Ok(Self::PolicyCheck),
            "Decision" => Ok(Self::Decision),
            _ => Err(format!("unknown action type: {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LedgerEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub agent_type: String,
    pub session_id: String,
    pub action_type: ActionType,
    pub payload: Value,
    pub context: Value,
    pub outcome: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

impl LedgerEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
        previous_hash: impl Into<String>,
    ) -> Self {
        Self::new_with_timestamp(
            current_time(),
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
            previous_hash,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_timestamp(
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
        previous_hash: impl Into<String>,
    ) -> Self {
        Self::new_with_id_and_timestamp(
            Uuid::new_v4(),
            timestamp,
            agent_id,
            agent_type,
            session_id,
            action_type,
            payload,
            context,
            outcome,
            previous_hash,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_id_and_timestamp(
        id: Uuid,
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        action_type: ActionType,
        payload: Value,
        context: Value,
        outcome: impl Into<String>,
        previous_hash: impl Into<String>,
    ) -> Self {
        let agent_id = agent_id.into();
        let agent_type = agent_type.into();
        let session_id = session_id.into();
        let outcome = outcome.into();
        let previous_hash = previous_hash.into();
        let mut entry = Self {
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
            entry_hash: String::new(),
        };
        entry.entry_hash = HashSpec::current().compute_entry_hash(&entry);
        entry
    }

    pub fn calculate_hash(&self) -> String {
        let spec = HashSpec::from_stored_hash(&self.entry_hash).unwrap_or_else(HashSpec::current);
        spec.compute_entry_hash(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn calculate_hash_parts(
        id: &Uuid,
        previous_hash: &str,
        timestamp: &DateTime<Utc>,
        agent_id: &str,
        agent_type: &str,
        session_id: &str,
        action_type: ActionType,
        payload: &Value,
        context: &Value,
        outcome: &str,
    ) -> String {
        HashSpec::current().compute_entry_hash(&Self {
            id: *id,
            timestamp: *timestamp,
            agent_id: agent_id.to_string(),
            agent_type: agent_type.to_string(),
            session_id: session_id.to_string(),
            action_type,
            payload: payload.clone(),
            context: context.clone(),
            outcome: outcome.to_string(),
            previous_hash: previous_hash.to_string(),
            entry_hash: String::new(),
        })
    }

    pub fn canonical_timestamp(timestamp: &DateTime<Utc>) -> String {
        canonical_timestamp(timestamp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerProof {
    pub hash: String,
    pub previous_hash: String,
    pub chain_position: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Range {
    pub from_id: Option<String>,
    pub to_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerFilter {
    pub range: Option<Range>,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub session_id: Option<String>,
    pub action_type: Option<ActionType>,
    pub outcome: Option<String>,
    pub from_timestamp: Option<DateTime<Utc>>,
    pub to_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainIntegrity {
    pub range: Option<Range>,
    pub violations: Vec<IntegrityViolation>,
}

impl ChainIntegrity {
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }
}

pub trait LedgerBackend {
    fn append(&self, entry: LedgerEntry) -> Result<LedgerProof>;
    fn verify_chain(&self, range: Option<Range>) -> Result<ChainIntegrity>;
    fn get_entry(&self, id: &str) -> Result<Option<LedgerEntry>>;
    fn get_entries(&self, filter: LedgerFilter) -> Result<Vec<LedgerEntry>>;
}

fn current_time() -> DateTime<Utc> {
    std::time::SystemTime::now().into()
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};
    use serde_json::json;

    use super::{
        ActionType, ChainIntegrity, GENESIS_HASH, LedgerBackend, LedgerEntry, LedgerFilter, Range,
    };
    use crate::storage::SqliteStorage;

    fn make_entry(
        sequence: i64,
        previous_hash: impl Into<String>,
        action_type: ActionType,
    ) -> LedgerEntry {
        let timestamp =
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap() + Duration::seconds(sequence);
        LedgerEntry::new_with_timestamp(
            timestamp,
            format!("agent-{sequence}"),
            "worker",
            format!("session-{}", sequence.rem_euclid(2)),
            action_type,
            json!({ "sequence": sequence }),
            json!({ "origin": "ledger-test" }),
            "ok",
            previous_hash,
        )
    }

    fn assert_backend_contract<B: LedgerBackend>(backend: &B) {
        let first_entry = make_entry(0, GENESIS_HASH.to_string(), ActionType::Decision);
        let first_id = first_entry.id.to_string();
        let first_proof = backend
            .append(first_entry.clone())
            .expect("append first entry");
        assert_eq!(first_proof.previous_hash, GENESIS_HASH);
        assert_eq!(first_proof.hash, first_entry.entry_hash);
        assert_eq!(first_proof.chain_position, 1);

        let second_entry = make_entry(1, first_proof.hash.clone(), ActionType::ToolCall);
        let second_id = second_entry.id.to_string();
        backend
            .append(second_entry.clone())
            .expect("append second entry");

        let stored_first = backend
            .get_entry(&first_id)
            .expect("load first entry")
            .expect("first entry exists");
        assert_eq!(stored_first, first_entry);

        let stored_second = backend
            .get_entry(&second_id)
            .expect("load second entry")
            .expect("second entry exists");
        assert_eq!(stored_second, second_entry);

        let tool_calls = backend
            .get_entries(LedgerFilter {
                action_type: Some(ActionType::ToolCall),
                ..LedgerFilter::default()
            })
            .expect("query tool calls");
        assert_eq!(tool_calls, vec![second_entry.clone()]);

        let integrity = backend.verify_chain(None).expect("verify full chain");
        assert!(
            integrity.is_valid() || only_missing_merkle_checkpoints(&integrity),
            "expected valid chain: {integrity:?}"
        );

        let ranged_integrity = backend
            .verify_chain(Some(Range {
                from_id: Some(first_id),
                to_id: Some(second_id),
            }))
            .expect("verify ranged chain");
        assert!(ranged_integrity.is_valid() || only_missing_merkle_checkpoints(&ranged_integrity));
    }

    fn only_missing_merkle_checkpoints(integrity: &ChainIntegrity) -> bool {
        !integrity.violations.is_empty()
            && integrity.violations.iter().all(|violation| {
                violation
                    .reason
                    .starts_with("missing merkle checkpoint for batch ")
            })
    }

    #[test]
    fn sqlite_backend_satisfies_ledger_trait_contract() {
        let storage = SqliteStorage::open_in_memory().expect("open storage");
        assert_backend_contract(&storage);
    }

    #[test]
    fn sqlite_backend_returns_chain_positions_in_append_proofs() {
        let storage = SqliteStorage::open_in_memory().expect("open storage");

        let first = make_entry(0, GENESIS_HASH.to_string(), ActionType::Decision);
        let first_proof = storage.append(first.clone()).expect("append first");
        let second = make_entry(1, first_proof.hash.clone(), ActionType::PolicyCheck);
        let second_proof = storage.append(second).expect("append second");

        assert_eq!(first_proof.chain_position, 1);
        assert_eq!(second_proof.chain_position, 2);
        assert_eq!(second_proof.previous_hash, first.entry_hash);
    }
}
