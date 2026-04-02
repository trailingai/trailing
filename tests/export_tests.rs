use std::collections::BTreeMap;

use chrono::{Duration, TimeZone, Utc};
use trailing::export::filter::{ExportFilter, TimeRange};
use trailing::export::json::{JsonEvidenceExport, export_package as export_json};
use trailing::export::pdf::export_package as export_pdf;
use trailing::export::{
    ChainIntegrityStatus, ComplianceControl, ComplianceGap, ComplianceReport, ComplianceStatus,
    EXPORT_SCHEMA_VERSION, EvidenceAction, EvidenceMetadata, EvidencePackage, GapSeverity,
    IntegrityProof, IntegrityState, OversightEvent,
};

fn sample_package() -> EvidencePackage {
    let generated_at = Utc.timestamp_opt(1_774_716_800, 0).single().unwrap();
    let action_time = generated_at - Duration::hours(2);
    let later_action_time = generated_at - Duration::hours(1);

    EvidencePackage::new(
        EvidenceMetadata {
            package_id: "pkg-001".to_string(),
            subject: "Quarterly agent audit".to_string(),
            organization: "Trailing".to_string(),
            generated_at,
            generated_by: "auditor@trailing".to_string(),
            legal_hold: true,
            sessions: vec!["session-a".to_string(), "session-b".to_string()],
            agents: vec!["agent-1".to_string(), "agent-2".to_string()],
            labels: BTreeMap::from([
                ("case_id".to_string(), "case-77".to_string()),
                ("region".to_string(), "us-east".to_string()),
            ]),
        },
        ChainIntegrityStatus {
            status: IntegrityState::Verified,
            last_verified_at: generated_at,
            ledger_root_hash: "ledger-root-123".to_string(),
            broken_links: 0,
            proofs: vec![
                IntegrityProof {
                    proof_id: "proof-1".to_string(),
                    scope: "actions".to_string(),
                    algorithm: "sha256".to_string(),
                    value: "abc123".to_string(),
                    verified: true,
                },
                IntegrityProof {
                    proof_id: "proof-2".to_string(),
                    scope: "oversight".to_string(),
                    algorithm: "sha256".to_string(),
                    value: "def456".to_string(),
                    verified: true,
                },
            ],
        },
        vec![
            EvidenceAction {
                action_id: "action-1".to_string(),
                timestamp: action_time,
                agent_id: "agent-1".to_string(),
                session_id: "session-a".to_string(),
                action_type: "prompt".to_string(),
                summary: "Opened investigation".to_string(),
                input_hash: "in-1".to_string(),
                output_hash: "out-1".to_string(),
                legal_hold: true,
            },
            EvidenceAction {
                action_id: "action-2".to_string(),
                timestamp: later_action_time,
                agent_id: "agent-2".to_string(),
                session_id: "session-b".to_string(),
                action_type: "tool_call".to_string(),
                summary: "Pulled evidence logs".to_string(),
                input_hash: "in-2".to_string(),
                output_hash: "out-2".to_string(),
                legal_hold: false,
            },
        ],
        vec![
            OversightEvent {
                event_id: "event-1".to_string(),
                timestamp: action_time,
                reviewer: "reviewer-1".to_string(),
                agent_id: Some("agent-1".to_string()),
                session_id: "session-a".to_string(),
                event_type: "approval".to_string(),
                details: "Approved initial evidence scope".to_string(),
                disposition: "accepted".to_string(),
                legal_hold: true,
            },
            OversightEvent {
                event_id: "event-2".to_string(),
                timestamp: later_action_time,
                reviewer: "reviewer-2".to_string(),
                agent_id: Some("agent-2".to_string()),
                session_id: "session-b".to_string(),
                event_type: "exception".to_string(),
                details: "Requested additional attestations".to_string(),
                disposition: "follow_up".to_string(),
                legal_hold: false,
            },
        ],
        ComplianceReport {
            framework: "SOC 2".to_string(),
            status: ComplianceStatus::Partial,
            controls: vec![
                ComplianceControl {
                    control_id: "CC1.1".to_string(),
                    title: "Governance oversight".to_string(),
                    status: ComplianceStatus::Compliant,
                    evidence_refs: vec!["event-1".to_string()],
                    notes: Some("Oversight completed".to_string()),
                },
                ComplianceControl {
                    control_id: "CC7.2".to_string(),
                    title: "Integrity monitoring".to_string(),
                    status: ComplianceStatus::Partial,
                    evidence_refs: vec!["proof-1".to_string(), "proof-2".to_string()],
                    notes: Some("Manual follow-up pending".to_string()),
                },
            ],
            gaps: vec![ComplianceGap {
                gap_id: "gap-1".to_string(),
                severity: GapSeverity::Medium,
                description: "Exception review lacks final sign-off".to_string(),
                remediation_owner: Some("ops@example.com".to_string()),
            }],
        },
    )
}

#[test]
fn package_hash_changes_when_contents_change() {
    let package = sample_package();
    let original_hash = package.package_hash.clone();

    let mut modified = package.clone();
    modified.actions[0].summary = "Updated summary".to_string();
    modified.refresh_hash();

    assert_ne!(original_hash, modified.package_hash);
}

#[test]
fn filter_applies_time_agent_session_action_and_legal_hold_constraints() {
    let package = sample_package();
    let generated_at = package.metadata.generated_at;

    let filter = ExportFilter {
        time_range: Some(TimeRange {
            start: Some(generated_at - Duration::hours(2)),
            end: Some(generated_at - Duration::minutes(90)),
        }),
        agent_id: Some("agent-1".to_string()),
        session_id: Some("session-a".to_string()),
        action_type: Some("prompt".to_string()),
        legal_hold: Some(true),
    };

    let filtered = filter.apply(&package);

    assert_eq!(filtered.actions.len(), 1);
    assert_eq!(filtered.actions[0].action_id, "action-1");
    assert_eq!(filtered.oversight_events.len(), 1);
    assert_eq!(filtered.oversight_events[0].event_id, "event-1");
    assert_ne!(filtered.package_hash, package.package_hash);
}

#[test]
fn json_export_includes_schema_version_and_integrity_proofs() {
    let package = sample_package();
    let json = export_json(&package).expect("json export should succeed");
    let export: JsonEvidenceExport =
        serde_json::from_str(&json).expect("json export should deserialize");

    assert_eq!(export.schema_version, EXPORT_SCHEMA_VERSION);
    assert_eq!(
        export.integrity_proofs.package_hash,
        export.package.package_hash
    );
    assert!(!export.integrity_proofs.actions_hash.is_empty());
    assert!(!export.integrity_proofs.merkle_root_hash.is_empty());
    assert!(!export.integrity_proofs.checkpoint_signature.is_empty());
    assert_eq!(
        export.integrity_proofs.proof_count,
        export.package.chain_integrity_status.proofs.len()
    );
    assert!(export.integrity_proofs.chain_verified);
}

#[test]
fn pdf_export_contains_required_sections() {
    let package = sample_package();
    let pdf = export_pdf(&package).expect("pdf export should succeed");
    let pdf_text = String::from_utf8_lossy(&pdf);

    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(pdf_text.contains("TRAILING AUDIT EVIDENCE REPORT"));
    assert!(pdf_text.contains("Table of Contents"));
    assert!(pdf_text.contains("/Helvetica-Bold"));
    assert!(pdf_text.contains("Page 1 of"));
    assert!(pdf_text.contains("Summary Statistics"));
    assert!(pdf_text.contains("Report Overview"));
    assert!(pdf_text.contains("Chain Integrity"));
    assert!(pdf_text.contains("Action Timeline"));
    assert!(pdf_text.contains("Oversight Log"));
    assert!(pdf_text.contains("Compliance Matrix"));
    assert!(pdf_text.contains("Gaps"));
}
