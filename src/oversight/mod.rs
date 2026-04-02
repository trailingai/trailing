pub mod capture;
pub mod chain;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OversightActor {
    pub agent_id: String,
    pub agent_type: String,
    pub session_id: String,
}

impl OversightActor {
    pub fn new(
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            agent_type: agent_type.into(),
            session_id: session_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum OversightEvent {
    Approval {
        reviewer: String,
        approved_entry_id: String,
        notes: Option<String>,
    },
    Override {
        reviewer: String,
        overridden_entry_id: String,
        previous_outcome: Option<String>,
        new_outcome: String,
        reason: String,
    },
    Escalation {
        reviewer: String,
        escalated_entry_id: String,
        escalation_target: String,
        reason: String,
    },
    KillSwitch {
        reviewer: String,
        halted_entry_id: Option<String>,
        scope: String,
        reason: String,
    },
}

impl OversightEvent {
    pub fn modified_entry_id(&self) -> Option<&str> {
        match self {
            Self::Approval {
                approved_entry_id, ..
            } => Some(approved_entry_id.as_str()),
            Self::Override {
                overridden_entry_id,
                ..
            } => Some(overridden_entry_id.as_str()),
            Self::Escalation {
                escalated_entry_id, ..
            } => Some(escalated_entry_id.as_str()),
            Self::KillSwitch {
                halted_entry_id, ..
            } => halted_entry_id.as_deref(),
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Approval {
                reviewer,
                approved_entry_id,
                ..
            } => format!("{reviewer} approved action {approved_entry_id}"),
            Self::Override {
                reviewer,
                overridden_entry_id,
                new_outcome,
                ..
            } => format!(
                "{reviewer} overrode action {overridden_entry_id} with outcome {new_outcome}"
            ),
            Self::Escalation {
                reviewer,
                escalated_entry_id,
                escalation_target,
                ..
            } => format!("{reviewer} escalated action {escalated_entry_id} to {escalation_target}"),
            Self::KillSwitch {
                reviewer,
                halted_entry_id,
                scope,
                ..
            } => match halted_entry_id {
                Some(entry_id) => {
                    format!("{reviewer} triggered kill switch for action {entry_id} in {scope}")
                }
                None => format!("{reviewer} triggered system-wide kill switch in {scope}"),
            },
        }
    }

    pub fn payload(&self) -> Value {
        match self {
            Self::Approval {
                reviewer,
                approved_entry_id,
                notes,
            } => json!({
                "event_type": "Approval",
                "reviewer": reviewer,
                "modified_entry_id": approved_entry_id,
                "notes": notes,
                "summary": self.summary(),
            }),
            Self::Override {
                reviewer,
                overridden_entry_id,
                previous_outcome,
                new_outcome,
                reason,
            } => json!({
                "event_type": "Override",
                "reviewer": reviewer,
                "modified_entry_id": overridden_entry_id,
                "previous_outcome": previous_outcome,
                "new_outcome": new_outcome,
                "reason": reason,
                "summary": self.summary(),
            }),
            Self::Escalation {
                reviewer,
                escalated_entry_id,
                escalation_target,
                reason,
            } => json!({
                "event_type": "Escalation",
                "reviewer": reviewer,
                "modified_entry_id": escalated_entry_id,
                "escalation_target": escalation_target,
                "reason": reason,
                "summary": self.summary(),
            }),
            Self::KillSwitch {
                reviewer,
                halted_entry_id,
                scope,
                reason,
            } => json!({
                "event_type": "KillSwitch",
                "reviewer": reviewer,
                "modified_entry_id": halted_entry_id,
                "scope": scope,
                "reason": reason,
                "summary": self.summary(),
            }),
        }
    }
}
