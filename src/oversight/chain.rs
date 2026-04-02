use crate::collector::ActionEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OversightChain {
    pub oversight_entry_id: String,
    pub target_entry_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OversightChainError {
    MissingOversightEntry(String),
    MissingTargetEntry(String),
    NotOversightEntry(String),
    UnlinkedOversightEntry(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Art14Threshold {
    pub max_actions_without_oversight: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Art14ComplianceError {
    InvalidThreshold,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Art14ComplianceReport {
    pub threshold: usize,
    pub is_compliant: bool,
    pub actions_since_last_oversight: usize,
    pub last_oversight_entry_id: Option<String>,
    pub violating_entry_id: Option<String>,
}

pub fn link_oversight_event(
    entries: &[ActionEntry],
    oversight_entry_id: &str,
) -> Result<OversightChain, OversightChainError> {
    let oversight_entry = entries
        .iter()
        .find(|entry| entry.entry_id == oversight_entry_id)
        .ok_or_else(|| {
            OversightChainError::MissingOversightEntry(oversight_entry_id.to_string())
        })?;

    if !oversight_entry.is_human_oversight() {
        return Err(OversightChainError::NotOversightEntry(
            oversight_entry_id.to_string(),
        ));
    }

    let target_entry_id = oversight_entry.modified_entry_id.clone().ok_or_else(|| {
        OversightChainError::UnlinkedOversightEntry(oversight_entry_id.to_string())
    })?;

    if !entries
        .iter()
        .any(|entry| entry.entry_id == target_entry_id)
    {
        return Err(OversightChainError::MissingTargetEntry(target_entry_id));
    }

    Ok(OversightChain {
        oversight_entry_id: oversight_entry_id.to_string(),
        target_entry_id,
    })
}

pub fn linked_action<'a>(
    entries: &'a [ActionEntry],
    oversight_entry_id: &str,
) -> Result<&'a ActionEntry, OversightChainError> {
    let chain = link_oversight_event(entries, oversight_entry_id)?;

    entries
        .iter()
        .find(|entry| entry.entry_id == chain.target_entry_id)
        .ok_or(OversightChainError::MissingTargetEntry(
            chain.target_entry_id,
        ))
}

pub fn verify_human_oversight(
    entries: &[ActionEntry],
    threshold: Art14Threshold,
) -> Result<Art14ComplianceReport, Art14ComplianceError> {
    if threshold.max_actions_without_oversight == 0 {
        return Err(Art14ComplianceError::InvalidThreshold);
    }

    let mut actions_since_last_oversight = 0usize;
    let mut last_oversight_entry_id = None;

    for entry in entries {
        if entry.is_human_oversight() {
            actions_since_last_oversight = 0;
            last_oversight_entry_id = Some(entry.entry_id.clone());
            continue;
        }

        actions_since_last_oversight += 1;

        if actions_since_last_oversight > threshold.max_actions_without_oversight {
            return Ok(Art14ComplianceReport {
                threshold: threshold.max_actions_without_oversight,
                is_compliant: false,
                actions_since_last_oversight,
                last_oversight_entry_id,
                violating_entry_id: Some(entry.entry_id.clone()),
            });
        }
    }

    Ok(Art14ComplianceReport {
        threshold: threshold.max_actions_without_oversight,
        is_compliant: true,
        actions_since_last_oversight,
        last_oversight_entry_id,
        violating_entry_id: None,
    })
}
