use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

pub mod filter;
pub mod json;
pub mod pdf;

pub const EXPORT_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidencePackage {
    pub metadata: EvidenceMetadata,
    pub chain_integrity_status: ChainIntegrityStatus,
    pub actions: Vec<EvidenceAction>,
    pub oversight_events: Vec<OversightEvent>,
    pub compliance_report: ComplianceReport,
    pub package_hash: String,
}

impl EvidencePackage {
    pub fn new(
        metadata: EvidenceMetadata,
        chain_integrity_status: ChainIntegrityStatus,
        actions: Vec<EvidenceAction>,
        oversight_events: Vec<OversightEvent>,
        compliance_report: ComplianceReport,
    ) -> Self {
        let mut package = Self {
            metadata,
            chain_integrity_status,
            actions,
            oversight_events,
            compliance_report,
            package_hash: String::new(),
        };
        package.refresh_hash();
        package
    }

    pub fn refresh_hash(&mut self) {
        self.package_hash = self.compute_hash();
    }

    pub fn compute_hash(&self) -> String {
        let payload = HashableEvidencePackage::from(self);
        let bytes = serde_json::to_vec(&payload)
            .expect("evidence package payload must serialize for hashing");
        sha256_hex(&bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceMetadata {
    pub package_id: String,
    pub subject: String,
    pub organization: String,
    pub generated_at: DateTime<Utc>,
    pub generated_by: String,
    pub legal_hold: bool,
    pub sessions: Vec<String>,
    pub agents: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainIntegrityStatus {
    pub status: IntegrityState,
    pub last_verified_at: DateTime<Utc>,
    pub ledger_root_hash: String,
    pub broken_links: usize,
    pub proofs: Vec<IntegrityProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityProof {
    pub proof_id: String,
    pub scope: String,
    pub algorithm: String,
    pub value: String,
    pub verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceAction {
    pub action_id: String,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub session_id: String,
    pub action_type: String,
    pub summary: String,
    pub input_hash: String,
    pub output_hash: String,
    pub legal_hold: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OversightEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub reviewer: String,
    pub agent_id: Option<String>,
    pub session_id: String,
    pub event_type: String,
    pub details: String,
    pub disposition: String,
    pub legal_hold: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceReport {
    pub framework: String,
    pub status: ComplianceStatus,
    pub controls: Vec<ComplianceControl>,
    pub gaps: Vec<ComplianceGap>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceControl {
    pub control_id: String,
    pub title: String,
    pub status: ComplianceStatus,
    pub evidence_refs: Vec<String>,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceGap {
    pub gap_id: String,
    pub severity: GapSeverity,
    pub description: String,
    pub remediation_owner: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityState {
    Verified,
    Warning,
    Broken,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Compliant,
    Partial,
    NonCompliant,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GapSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize)]
struct HashableEvidencePackage<'a> {
    metadata: &'a EvidenceMetadata,
    chain_integrity_status: &'a ChainIntegrityStatus,
    actions: &'a [EvidenceAction],
    oversight_events: &'a [OversightEvent],
    compliance_report: &'a ComplianceReport,
}

impl<'a> From<&'a EvidencePackage> for HashableEvidencePackage<'a> {
    fn from(package: &'a EvidencePackage) -> Self {
        Self {
            metadata: &package.metadata,
            chain_integrity_status: &package.chain_integrity_status,
            actions: &package.actions,
            oversight_events: &package.oversight_events,
            compliance_report: &package.compliance_report,
        }
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);

    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }

    encoded
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PackageMerkleArtifacts {
    pub merkle_root_hash: String,
    pub inclusion_proofs: Vec<IntegrityProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct MerkleProofNode {
    position: String,
    hash: String,
}

#[derive(Clone, Debug)]
struct MerkleLeaf {
    proof_id: String,
    scope: String,
    leaf_id: String,
    leaf_kind: String,
    leaf_hash: String,
}

pub(crate) fn canonical_json_hash<T: Serialize>(value: &T) -> String {
    sha256_hex(
        &serde_json::to_vec(value).expect("value must serialize for canonical cryptographic hash"),
    )
}

pub(crate) fn build_package_merkle_artifacts(package: &EvidencePackage) -> PackageMerkleArtifacts {
    let leaves = merkle_leaves(package);

    if leaves.is_empty() {
        return PackageMerkleArtifacts {
            merkle_root_hash: sha256_hex(b"trailing-empty-merkle-root"),
            inclusion_proofs: Vec::new(),
        };
    }

    let leaf_hashes = leaves
        .iter()
        .map(|leaf| leaf.leaf_hash.clone())
        .collect::<Vec<_>>();
    let levels = merkle_levels(&leaf_hashes);
    let merkle_root_hash = levels
        .last()
        .and_then(|level| level.first())
        .cloned()
        .unwrap_or_else(|| sha256_hex(b"trailing-empty-merkle-root"));

    let inclusion_proofs = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            let path = merkle_path(&levels, index);
            let verified = verify_merkle_path(&leaf.leaf_hash, &path, &merkle_root_hash);
            let value = serde_json::to_string(&json!({
                "leaf_id": leaf.leaf_id,
                "leaf_kind": leaf.leaf_kind,
                "leaf_hash": leaf.leaf_hash,
                "leaf_index": index,
                "merkle_root_hash": merkle_root_hash,
                "path": path,
            }))
            .expect("merkle inclusion proof payload must serialize");

            IntegrityProof {
                proof_id: leaf.proof_id.clone(),
                scope: leaf.scope.clone(),
                algorithm: "sha256-merkle".to_string(),
                value,
                verified,
            }
        })
        .collect();

    PackageMerkleArtifacts {
        merkle_root_hash,
        inclusion_proofs,
    }
}

pub(crate) fn checkpoint_signature(
    merkle_root_hash: &str,
    ledger_root_hash: Option<&str>,
    root_anchor_hash: Option<&str>,
    checked_entries: usize,
    chain_verified: bool,
) -> String {
    canonical_json_hash(&json!({
        "chain_verified": chain_verified,
        "checked_entries": checked_entries,
        "checkpoint_version": 1,
        "ledger_root_hash": ledger_root_hash,
        "merkle_root_hash": merkle_root_hash,
        "root_anchor_hash": root_anchor_hash,
    }))
}

fn merkle_leaves(package: &EvidencePackage) -> Vec<MerkleLeaf> {
    let mut leaves = package
        .actions
        .iter()
        .map(|action| MerkleLeaf {
            proof_id: format!("merkle-action-{}", action.action_id),
            scope: "merkle_inclusion".to_string(),
            leaf_id: action.action_id.clone(),
            leaf_kind: "action".to_string(),
            leaf_hash: canonical_json_hash(&json!({
                "kind": "action",
                "payload": action,
            })),
        })
        .collect::<Vec<_>>();

    leaves.extend(package.oversight_events.iter().map(|event| MerkleLeaf {
        proof_id: format!("merkle-oversight-{}", event.event_id),
        scope: "merkle_inclusion".to_string(),
        leaf_id: event.event_id.clone(),
        leaf_kind: "oversight_event".to_string(),
        leaf_hash: canonical_json_hash(&json!({
            "kind": "oversight_event",
            "payload": event,
        })),
    }));

    leaves.push(MerkleLeaf {
        proof_id: format!("merkle-compliance-{}", package.compliance_report.framework),
        scope: "merkle_inclusion".to_string(),
        leaf_id: package.compliance_report.framework.clone(),
        leaf_kind: "compliance_report".to_string(),
        leaf_hash: canonical_json_hash(&json!({
            "kind": "compliance_report",
            "payload": &package.compliance_report,
        })),
    });

    leaves
}

fn merkle_levels(leaves: &[String]) -> Vec<Vec<String>> {
    let mut levels = vec![leaves.to_vec()];

    while levels.last().is_some_and(|level| level.len() > 1) {
        let previous = levels
            .last()
            .expect("merkle levels must contain at least one level");
        let mut next = Vec::with_capacity(previous.len().div_ceil(2));

        for chunk in previous.chunks(2) {
            let left = &chunk[0];
            let right = chunk.get(1).unwrap_or(left);
            next.push(canonical_json_hash(&json!({
                "left": left,
                "right": right,
            })));
        }

        levels.push(next);
    }

    levels
}

fn merkle_path(levels: &[Vec<String>], leaf_index: usize) -> Vec<MerkleProofNode> {
    let mut index = leaf_index;
    let mut path = Vec::new();

    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        let sibling_index = if index.is_multiple_of(2) {
            index + 1
        } else {
            index - 1
        };
        let sibling_hash = level
            .get(sibling_index)
            .cloned()
            .unwrap_or_else(|| level[index].clone());
        let position = if index.is_multiple_of(2) {
            "right"
        } else {
            "left"
        };

        path.push(MerkleProofNode {
            position: position.to_string(),
            hash: sibling_hash,
        });
        index /= 2;
    }

    path
}

fn verify_merkle_path(leaf_hash: &str, path: &[MerkleProofNode], merkle_root_hash: &str) -> bool {
    let mut current = leaf_hash.to_string();

    for node in path {
        current = match node.position.as_str() {
            "left" => canonical_json_hash(&json!({
                "left": node.hash,
                "right": current,
            })),
            "right" => canonical_json_hash(&json!({
                "left": current,
                "right": node.hash,
            })),
            _ => return false,
        };
    }

    current == merkle_root_hash
}
