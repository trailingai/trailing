use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::log::ActionEntry;

pub const MERKLE_BATCH_SIZE: i64 = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MerkleCheckpoint {
    pub batch_index: i64,
    pub start_sequence: i64,
    pub end_sequence: i64,
    #[serde(serialize_with = "serialize_uuid")]
    pub start_entry_id: Uuid,
    #[serde(serialize_with = "serialize_uuid")]
    pub end_entry_id: Uuid,
    pub entry_count: usize,
    pub merkle_root: String,
    pub checkpointed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MerkleSiblingPosition {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MerkleProofStep {
    pub sibling_hash: String,
    pub position: MerkleSiblingPosition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MerkleInclusionProof {
    pub batch_index: i64,
    pub batch_root: String,
    pub batch_start_sequence: i64,
    pub batch_end_sequence: i64,
    #[serde(serialize_with = "serialize_uuid")]
    pub entry_id: Uuid,
    pub leaf_index: usize,
    pub leaf_hash: String,
    pub proof: Vec<MerkleProofStep>,
}

pub fn batch_index_for_sequence(sequence: i64) -> i64 {
    (sequence - 1) / MERKLE_BATCH_SIZE
}

pub fn batch_bounds(batch_index: i64) -> (i64, i64) {
    let start_sequence = batch_index * MERKLE_BATCH_SIZE + 1;
    let end_sequence = start_sequence + MERKLE_BATCH_SIZE - 1;
    (start_sequence, end_sequence)
}

pub fn compute_root(entry_hashes: &[String]) -> Option<String> {
    if entry_hashes.is_empty() {
        return None;
    }

    let mut level = entry_hashes
        .iter()
        .map(|hash| leaf_hash(hash))
        .collect::<Vec<_>>();

    while level.len() > 1 {
        level = next_level(&level);
    }

    level.into_iter().next()
}

pub fn build_inclusion_proof(
    entry_hashes: &[String],
    leaf_index: usize,
) -> Option<(String, String, Vec<MerkleProofStep>)> {
    if entry_hashes.is_empty() || leaf_index >= entry_hashes.len() {
        return None;
    }

    let mut proof = Vec::new();
    let mut level = entry_hashes
        .iter()
        .map(|hash| leaf_hash(hash))
        .collect::<Vec<_>>();
    let mut index = leaf_index;
    let leaf_hash = level[index].clone();

    while level.len() > 1 {
        let sibling_index = if index.is_multiple_of(2) {
            (index + 1).min(level.len() - 1)
        } else {
            index - 1
        };
        proof.push(MerkleProofStep {
            sibling_hash: level[sibling_index].clone(),
            position: if index.is_multiple_of(2) {
                MerkleSiblingPosition::Right
            } else {
                MerkleSiblingPosition::Left
            },
        });

        level = next_level(&level);
        index /= 2;
    }

    let root = level.into_iter().next()?;
    Some((leaf_hash, root, proof))
}

pub fn verify_inclusion_proof(entry: &ActionEntry, proof: &MerkleInclusionProof) -> bool {
    if entry.id != proof.entry_id {
        return false;
    }

    let entry_hash = entry.calculate_hash();
    let mut current = leaf_hash(&entry_hash);
    if current != proof.leaf_hash {
        return false;
    }

    for step in &proof.proof {
        current = match step.position {
            MerkleSiblingPosition::Left => parent_hash(&step.sibling_hash, &current),
            MerkleSiblingPosition::Right => parent_hash(&current, &step.sibling_hash),
        };
    }

    current == proof.batch_root
}

fn serialize_uuid<S>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&uuid.to_string())
}

fn leaf_hash(entry_hash: &str) -> String {
    tagged_hash("leaf", entry_hash, "")
}

fn parent_hash(left: &str, right: &str) -> String {
    tagged_hash("node", left, right)
}

fn tagged_hash(tag: &str, left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0]);
    hasher.update(left.as_bytes());
    hasher.update([0]);
    hasher.update(right.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn next_level(level: &[String]) -> Vec<String> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    for pair in level.chunks(2) {
        let left = &pair[0];
        let right = pair.get(1).unwrap_or(left);
        next.push(parent_hash(left, right));
    }
    next
}
