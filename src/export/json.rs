use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    EXPORT_SCHEMA_VERSION, EvidencePackage, build_package_merkle_artifacts, checkpoint_signature,
    sha256_hex,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonEvidenceExport {
    pub schema_version: String,
    pub exported_at: DateTime<Utc>,
    pub integrity_proofs: ExportIntegrityProofs,
    pub package: EvidencePackage,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportIntegrityProofs {
    pub package_hash: String,
    pub actions_hash: String,
    pub oversight_hash: String,
    pub compliance_hash: String,
    pub merkle_root_hash: String,
    pub root_anchor_hash: Option<String>,
    pub checkpoint_signature: String,
    pub proof_count: usize,
    pub chain_verified: bool,
}

impl JsonEvidenceExport {
    pub fn from_package(package: &EvidencePackage) -> Self {
        let mut normalized = package.clone();
        normalized.refresh_hash();
        let merkle_artifacts = build_package_merkle_artifacts(&normalized);
        let root_anchor_hash = root_anchor_hash(&normalized);

        Self {
            schema_version: EXPORT_SCHEMA_VERSION.to_string(),
            exported_at: current_time(),
            integrity_proofs: ExportIntegrityProofs {
                package_hash: normalized.package_hash.clone(),
                actions_hash: sha256_hex(
                    &serde_json::to_vec(&normalized.actions)
                        .expect("actions must serialize for integrity proofs"),
                ),
                oversight_hash: sha256_hex(
                    &serde_json::to_vec(&normalized.oversight_events)
                        .expect("oversight events must serialize for integrity proofs"),
                ),
                compliance_hash: sha256_hex(
                    &serde_json::to_vec(&normalized.compliance_report)
                        .expect("compliance report must serialize for integrity proofs"),
                ),
                merkle_root_hash: merkle_artifacts.merkle_root_hash.clone(),
                root_anchor_hash: root_anchor_hash.clone(),
                checkpoint_signature: checkpoint_signature(
                    &merkle_artifacts.merkle_root_hash,
                    Some(&normalized.chain_integrity_status.ledger_root_hash),
                    root_anchor_hash.as_deref(),
                    normalized.actions.len() + normalized.oversight_events.len(),
                    normalized.chain_integrity_status.broken_links == 0,
                ),
                proof_count: normalized.chain_integrity_status.proofs.len(),
                chain_verified: normalized.chain_integrity_status.broken_links == 0,
            },
            package: normalized,
        }
    }
}

pub fn export_package(package: &EvidencePackage) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&JsonEvidenceExport::from_package(package))
}

fn current_time() -> DateTime<Utc> {
    Utc::now()
}

fn root_anchor_hash(package: &EvidencePackage) -> Option<String> {
    package
        .chain_integrity_status
        .proofs
        .iter()
        .find(|proof| proof.scope == "root_anchor_hash")
        .and_then(|proof| serde_json::from_str::<Value>(&proof.value).ok())
        .and_then(|payload| {
            payload
                .get("root_anchor_hash")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
}
