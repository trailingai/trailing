use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ledger::LedgerEntry as ActionEntry;

pub const LEGACY_HASH_VERSION: &str = "legacy-v0";
pub const CURRENT_HASH_VERSION: &str = "trailing-v1";

const SHA256_HEX_LEN: usize = 64;
const SHA256_PREFIX: &str = "sha256:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashSpec {
    pub version: &'static str,
    pub algorithm: &'static str,
    layout: HashLayout,
    output: HashOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashLayout {
    LegacyV0,
    CanonicalJsonV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashOutput {
    BareHex,
    AlgorithmPrefixed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashChainViolation {
    pub entry_id: Uuid,
    pub reason: String,
    pub expected_previous_hash: Option<String>,
    pub actual_previous_hash: String,
    pub expected_entry_hash: String,
    pub actual_entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashVerificationError {
    UnsupportedHashFormat(String),
    UnsupportedHashVersion(String),
    HashMismatch { expected: String, actual: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHash {
    pub spec: HashSpec,
    pub expected_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointHash {
    pub spec_version: String,
    pub algorithm: String,
    pub previous_hash: String,
    pub first_sequence: i64,
    pub last_sequence: i64,
    pub entry_count: usize,
    pub first_entry_hash: String,
    pub last_entry_hash: String,
    pub checkpoint_hash: String,
}

impl HashSpec {
    pub const fn legacy_v0() -> Self {
        Self {
            version: LEGACY_HASH_VERSION,
            algorithm: "sha256",
            layout: HashLayout::LegacyV0,
            output: HashOutput::BareHex,
        }
    }

    pub const fn trailing_v1() -> Self {
        Self {
            version: CURRENT_HASH_VERSION,
            algorithm: "sha256",
            layout: HashLayout::CanonicalJsonV1,
            output: HashOutput::AlgorithmPrefixed,
        }
    }

    pub const fn current() -> Self {
        Self::trailing_v1()
    }

    pub fn from_version(version: &str) -> Option<Self> {
        match version {
            LEGACY_HASH_VERSION => Some(Self::legacy_v0()),
            CURRENT_HASH_VERSION => Some(Self::trailing_v1()),
            _ => None,
        }
    }

    pub fn from_stored_hash(stored_hash: &str) -> Option<Self> {
        if is_sha256_hex(stored_hash) {
            return Some(Self::legacy_v0());
        }

        let digest = stored_hash.strip_prefix(SHA256_PREFIX)?;
        if is_sha256_hex(digest) {
            Some(Self::trailing_v1())
        } else {
            None
        }
    }

    pub fn compute_entry_hash(self, entry: &ActionEntry) -> String {
        match self.layout {
            HashLayout::LegacyV0 => self.compute_legacy_entry_hash(entry),
            HashLayout::CanonicalJsonV1 => {
                let canonical_entry = canonical_action_entry_json(entry);
                self.hash_canonical_payload(&entry.previous_hash, &canonical_entry)
            }
        }
    }

    pub fn compute_checkpoint_hash(self, checkpoint: &CheckpointHash) -> String {
        let canonical_checkpoint = canonical_checkpoint_json(checkpoint);
        self.hash_canonical_payload(&checkpoint.previous_hash, &canonical_checkpoint)
    }

    fn compute_legacy_entry_hash(self, entry: &ActionEntry) -> String {
        let mut hasher = Sha256::new();
        hasher.update(entry.id.to_string().as_bytes());
        hasher.update(entry.previous_hash.as_bytes());
        hasher.update(canonical_timestamp(&entry.timestamp).as_bytes());
        hasher.update(entry.agent_id.as_bytes());
        hasher.update(entry.agent_type.as_bytes());
        hasher.update(entry.session_id.as_bytes());
        hasher.update(entry.action_type.to_string().as_bytes());
        hasher.update(entry.payload.to_string().as_bytes());
        hasher.update(entry.context.to_string().as_bytes());
        hasher.update(entry.outcome.as_bytes());

        self.format_digest(hasher.finalize())
    }

    fn hash_canonical_payload(self, previous_hash: &str, canonical_payload: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.version.as_bytes());
        hasher.update(previous_hash.as_bytes());
        hasher.update(canonical_payload.as_bytes());

        self.format_digest(hasher.finalize())
    }

    fn format_digest(self, digest: impl AsRef<[u8]>) -> String {
        let digest = hex::encode(digest.as_ref());

        match self.output {
            HashOutput::BareHex => digest,
            HashOutput::AlgorithmPrefixed => format!("{SHA256_PREFIX}{digest}"),
        }
    }
}

impl CheckpointHash {
    pub fn new(
        previous_hash: impl Into<String>,
        first_sequence: i64,
        last_sequence: i64,
        entry_count: usize,
        first_entry_hash: impl Into<String>,
        last_entry_hash: impl Into<String>,
    ) -> Self {
        let spec = HashSpec::current();
        let mut checkpoint = Self {
            spec_version: spec.version.to_string(),
            algorithm: spec.algorithm.to_string(),
            previous_hash: previous_hash.into(),
            first_sequence,
            last_sequence,
            entry_count,
            first_entry_hash: first_entry_hash.into(),
            last_entry_hash: last_entry_hash.into(),
            checkpoint_hash: String::new(),
        };
        checkpoint.checkpoint_hash = spec.compute_checkpoint_hash(&checkpoint);
        checkpoint
    }

    pub fn calculate_hash(&self) -> Result<String, HashVerificationError> {
        let spec = HashSpec::from_version(&self.spec_version).ok_or_else(|| {
            HashVerificationError::UnsupportedHashVersion(self.spec_version.clone())
        })?;
        Ok(spec.compute_checkpoint_hash(self))
    }

    pub fn verify(&self) -> Result<(), HashVerificationError> {
        let expected_hash = self.calculate_hash()?;
        if self.checkpoint_hash == expected_hash {
            Ok(())
        } else {
            Err(HashVerificationError::HashMismatch {
                expected: expected_hash,
                actual: self.checkpoint_hash.clone(),
            })
        }
    }
}

pub fn verify_entry_hash(entry: &ActionEntry) -> Result<VerifiedHash, HashVerificationError> {
    let spec = HashSpec::from_stored_hash(&entry.entry_hash)
        .ok_or_else(|| HashVerificationError::UnsupportedHashFormat(entry.entry_hash.clone()))?;

    Ok(VerifiedHash {
        spec,
        expected_hash: spec.compute_entry_hash(entry),
    })
}

pub fn verify_chain(
    entries: &[ActionEntry],
    initial_previous_hash: &str,
) -> Vec<HashChainViolation> {
    let mut violations = Vec::new();
    let mut expected_previous_hash = initial_previous_hash.to_string();

    for entry in entries {
        if entry.previous_hash != expected_previous_hash {
            let expected_entry_hash = verify_entry_hash(entry)
                .map(|verified| verified.expected_hash)
                .unwrap_or_else(|_| String::new());
            violations.push(HashChainViolation {
                entry_id: entry.id,
                reason: "previous hash mismatch".to_string(),
                expected_previous_hash: Some(expected_previous_hash.clone()),
                actual_previous_hash: entry.previous_hash.clone(),
                expected_entry_hash,
                actual_entry_hash: entry.entry_hash.clone(),
            });
        }

        match verify_entry_hash(entry) {
            Ok(verified) if entry.entry_hash != verified.expected_hash => {
                violations.push(HashChainViolation {
                    entry_id: entry.id,
                    reason: "entry hash mismatch".to_string(),
                    expected_previous_hash: Some(entry.previous_hash.clone()),
                    actual_previous_hash: entry.previous_hash.clone(),
                    expected_entry_hash: verified.expected_hash,
                    actual_entry_hash: entry.entry_hash.clone(),
                });
            }
            Ok(_) => {}
            Err(HashVerificationError::UnsupportedHashFormat(actual_hash)) => {
                violations.push(HashChainViolation {
                    entry_id: entry.id,
                    reason: "unsupported hash format".to_string(),
                    expected_previous_hash: Some(entry.previous_hash.clone()),
                    actual_previous_hash: entry.previous_hash.clone(),
                    expected_entry_hash: "legacy bare hex or sha256:<digest>".to_string(),
                    actual_entry_hash: actual_hash,
                });
            }
            Err(HashVerificationError::UnsupportedHashVersion(version)) => {
                violations.push(HashChainViolation {
                    entry_id: entry.id,
                    reason: "unsupported hash version".to_string(),
                    expected_previous_hash: Some(entry.previous_hash.clone()),
                    actual_previous_hash: entry.previous_hash.clone(),
                    expected_entry_hash: "registered hash spec".to_string(),
                    actual_entry_hash: version,
                });
            }
            Err(HashVerificationError::HashMismatch { .. }) => {}
        }

        expected_previous_hash = entry.entry_hash.clone();
    }

    violations
}

pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical_json(value, &mut out);
    out
}

pub fn canonical_timestamp(timestamp: &DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn canonical_action_entry_json(entry: &ActionEntry) -> String {
    let mut object = Map::new();
    object.insert(
        "action_type".to_string(),
        Value::String(entry.action_type.to_string()),
    );
    object.insert(
        "agent_id".to_string(),
        Value::String(entry.agent_id.clone()),
    );
    object.insert(
        "agent_type".to_string(),
        Value::String(entry.agent_type.clone()),
    );
    object.insert("context".to_string(), entry.context.clone());
    object.insert("id".to_string(), Value::String(entry.id.to_string()));
    object.insert("outcome".to_string(), Value::String(entry.outcome.clone()));
    object.insert("payload".to_string(), entry.payload.clone());
    object.insert(
        "session_id".to_string(),
        Value::String(entry.session_id.clone()),
    );
    object.insert(
        "timestamp".to_string(),
        Value::String(canonical_timestamp(&entry.timestamp)),
    );

    canonical_json(&Value::Object(object))
}

fn canonical_checkpoint_json(checkpoint: &CheckpointHash) -> String {
    let mut object = Map::new();
    object.insert(
        "entry_count".to_string(),
        Value::Number(checkpoint.entry_count.into()),
    );
    object.insert(
        "first_entry_hash".to_string(),
        Value::String(checkpoint.first_entry_hash.clone()),
    );
    object.insert(
        "first_sequence".to_string(),
        Value::Number(checkpoint.first_sequence.into()),
    );
    object.insert(
        "last_entry_hash".to_string(),
        Value::String(checkpoint.last_entry_hash.clone()),
    );
    object.insert(
        "last_sequence".to_string(),
        Value::Number(checkpoint.last_sequence.into()),
    );

    canonical_json(&Value::Object(object))
}

fn write_canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => {
            if *value {
                out.push_str("true");
            } else {
                out.push_str("false");
            }
        }
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(value) => {
            out.push_str(
                &serde_json::to_string(value)
                    .expect("serializing JSON string to canonical form must succeed"),
            );
        }
        Value::Array(values) => {
            out.push('[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        Value::Object(values) => {
            let mut items: Vec<_> = values.iter().collect();
            items.sort_by(|left, right| left.0.cmp(right.0));

            out.push('{');
            for (index, (key, item)) in items.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(key)
                        .expect("serializing JSON object key to canonical form must succeed"),
                );
                out.push(':');
                write_canonical_json(item, out);
            }
            out.push('}');
        }
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::json;
    use uuid::Uuid;

    use super::{CheckpointHash, HashSpec, canonical_json, verify_chain};
    use crate::log::{ActionEntry, ActionType, GENESIS_HASH};

    fn sample_entry(previous_hash: &str) -> ActionEntry {
        ActionEntry {
            id: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            timestamp: Utc.with_ymd_and_hms(2026, 3, 30, 15, 4, 5).unwrap(),
            agent_id: "agent-42".to_string(),
            agent_type: "planner".to_string(),
            session_id: "session-9".to_string(),
            action_type: ActionType::ToolCall,
            payload: json!({
                "zebra": 2,
                "alpha": {
                    "beta": true,
                    "aardvark": [3, 2, 1]
                }
            }),
            context: json!({
                "env": "prod",
                "request": {
                    "id": 7,
                    "trace": "abc"
                }
            }),
            outcome: "allowed".to_string(),
            previous_hash: previous_hash.to_string(),
            entry_hash: String::new(),
        }
    }

    #[test]
    fn canonical_json_sorts_nested_keys_without_whitespace() {
        let value = json!({
            "zebra": 1,
            "alpha": {
                "delta": 4,
                "beta": 2
            },
            "items": [
                {"b": 2, "a": 1},
                null
            ]
        });

        assert_eq!(
            canonical_json(&value),
            "{\"alpha\":{\"beta\":2,\"delta\":4},\"items\":[{\"a\":1,\"b\":2},null],\"zebra\":1}"
        );
    }

    #[test]
    fn legacy_hash_known_answer_matches_expected_digest() {
        let mut entry = sample_entry(GENESIS_HASH);
        entry.entry_hash = HashSpec::legacy_v0().compute_entry_hash(&entry);

        assert_eq!(
            entry.entry_hash,
            "9cde86509ab272dc9ac21e8a56fd1beaf23b30b48bc51b3ab7cbea2085d38549"
        );
    }

    #[test]
    fn trailing_v1_hash_known_answer_matches_expected_digest() {
        let mut entry = sample_entry(GENESIS_HASH);
        entry.entry_hash = HashSpec::trailing_v1().compute_entry_hash(&entry);

        assert_eq!(
            entry.entry_hash,
            "sha256:2328ade6848e4677d783774f40bcf634622576a2449295a51f16547bd6ca7791"
        );
    }

    #[test]
    fn checkpoint_hash_known_answer_matches_expected_digest() {
        let checkpoint = CheckpointHash::new(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            100,
            199,
            100,
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        );

        assert_eq!(
            checkpoint.checkpoint_hash,
            "sha256:0a1999997f982fdafe55f99a614d520f38e486d6c12ff307e76a2c6b3f43e98e"
        );
        assert!(checkpoint.verify().is_ok());
    }

    #[test]
    fn mixed_legacy_and_versioned_chain_verifies_cleanly() {
        let mut legacy_entry = sample_entry(GENESIS_HASH);
        legacy_entry.entry_hash = HashSpec::legacy_v0().compute_entry_hash(&legacy_entry);

        let mut versioned_entry = sample_entry(&legacy_entry.entry_hash);
        versioned_entry.id = Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap();
        versioned_entry.entry_hash = HashSpec::trailing_v1().compute_entry_hash(&versioned_entry);

        assert!(verify_chain(&[legacy_entry, versioned_entry], GENESIS_HASH).is_empty());
    }

    #[test]
    fn invalid_hash_format_is_reported_during_verification() {
        let mut entry = sample_entry(GENESIS_HASH);
        entry.entry_hash = "md5:not-supported".to_string();

        let violations = verify_chain(&[entry], GENESIS_HASH);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].reason, "unsupported hash format");
    }
}
