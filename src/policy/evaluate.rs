use std::collections::BTreeSet;

use super::framework::{Control, Framework};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionEntry {
    pub action: String,
    pub evidence: Vec<String>,
    pub evidence_refs: Vec<String>,
}

impl ActionEntry {
    pub fn new(action: impl Into<String>, evidence: Vec<&str>, evidence_refs: Vec<&str>) -> Self {
        Self {
            action: action.into(),
            evidence: evidence.into_iter().map(str::to_string).collect(),
            evidence_refs: evidence_refs.into_iter().map(str::to_string).collect(),
        }
    }

    pub fn from_owned(
        action: impl Into<String>,
        evidence: Vec<String>,
        evidence_refs: Vec<String>,
    ) -> Self {
        Self {
            action: action.into(),
            evidence,
            evidence_refs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlResult {
    pub control: Control,
    pub matched_evidence: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceReport {
    pub framework: Framework,
    pub controls_met: Vec<ControlResult>,
    pub controls_gaps: Vec<ControlResult>,
    pub evidence_refs: Vec<String>,
}

pub fn evaluate_actions(
    framework: &Framework,
    controls: &[Control],
    actions: &[ActionEntry],
) -> ComplianceReport {
    let mut controls_met = Vec::new();
    let mut controls_gaps = Vec::new();

    for control in controls {
        let mut matched_evidence = Vec::new();
        let mut missing_evidence = Vec::new();
        let mut evidence_refs = BTreeSet::new();

        for requirement in &control.evidence_requirements {
            if let Some(matched) = match_requirement(actions, requirement) {
                matched_evidence.push(matched.value);
                evidence_refs.extend(matched.refs);
            } else {
                missing_evidence.push(requirement.clone());
            }
        }

        let result = ControlResult {
            control: control.clone(),
            matched_evidence,
            missing_evidence,
            evidence_refs: evidence_refs.into_iter().collect(),
        };

        if result.missing_evidence.is_empty() {
            controls_met.push(result);
        } else {
            controls_gaps.push(result);
        }
    }

    let evidence_refs = actions
        .iter()
        .flat_map(|action| action.evidence_refs.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    ComplianceReport {
        framework: framework.clone(),
        controls_met,
        controls_gaps,
        evidence_refs,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MatchedEvidence {
    value: String,
    refs: Vec<String>,
}

fn match_requirement(actions: &[ActionEntry], requirement: &str) -> Option<MatchedEvidence> {
    let requirement = normalize(requirement);

    for action in actions {
        if matches_text(&action.action, &requirement) {
            return Some(MatchedEvidence {
                value: action.action.clone(),
                refs: action.evidence_refs.clone(),
            });
        }

        for evidence in &action.evidence {
            if matches_text(evidence, &requirement) {
                return Some(MatchedEvidence {
                    value: evidence.clone(),
                    refs: action.evidence_refs.clone(),
                });
            }
        }
    }

    None
}

fn matches_text(candidate: &str, requirement: &str) -> bool {
    let candidate = normalize(candidate);
    candidate.contains(requirement) || requirement.contains(&candidate)
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
