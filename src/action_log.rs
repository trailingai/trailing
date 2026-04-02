use chrono::{TimeZone, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::ledger::{ActionType as LedgerActionType, GENESIS_HASH, LedgerEntry};
use crate::oversight::OversightEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionType {
    AgentAction,
    HumanOverride,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionEntry {
    pub entry_id: u64,
    pub action_type: ActionType,
    pub description: String,
    pub related_entry_id: Option<u64>,
    pub oversight: Option<OversightEvent>,
}

#[derive(Debug, Clone, Default)]
pub struct ActionLog {
    entries: Vec<ActionEntry>,
    next_entry_id: u64,
}

impl ActionLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_entry_id: 1,
        }
    }

    pub fn record_action(&mut self, description: impl Into<String>) -> ActionEntry {
        self.push_entry(ActionType::AgentAction, description, None, None)
    }

    pub fn push_entry(
        &mut self,
        action_type: ActionType,
        description: impl Into<String>,
        related_entry_id: Option<u64>,
        oversight: Option<OversightEvent>,
    ) -> ActionEntry {
        let entry = ActionEntry {
            entry_id: self.next_entry_id,
            action_type,
            description: description.into(),
            related_entry_id,
            oversight,
        };
        self.next_entry_id += 1;
        self.entries.push(entry.clone());
        entry
    }

    pub fn entries(&self) -> &[ActionEntry] {
        &self.entries
    }

    pub fn get(&self, entry_id: u64) -> Option<&ActionEntry> {
        self.entries.iter().find(|entry| entry.entry_id == entry_id)
    }
}

impl From<ActionType> for LedgerActionType {
    fn from(value: ActionType) -> Self {
        match value {
            ActionType::AgentAction => Self::Decision,
            ActionType::HumanOverride => Self::HumanOverride,
        }
    }
}

impl From<&ActionEntry> for LedgerEntry {
    fn from(value: &ActionEntry) -> Self {
        let id = legacy_entry_uuid(value.entry_id);
        let timestamp = legacy_entry_timestamp(value.entry_id);
        let payload = json!({
            "legacy_entry_id": value.entry_id,
            "description": value.description,
            "related_entry_id": value.related_entry_id,
            "oversight": value.oversight.as_ref().map(OversightEvent::payload),
        });
        let context = json!({
            "source": "legacy_action_log",
        });

        LedgerEntry::new_with_id_and_timestamp(
            id,
            timestamp,
            "legacy-action-log",
            "legacy",
            "legacy-action-log",
            value.action_type.clone().into(),
            payload,
            context,
            "recorded",
            GENESIS_HASH,
        )
    }
}

impl From<ActionEntry> for LedgerEntry {
    fn from(value: ActionEntry) -> Self {
        Self::from(&value)
    }
}

fn legacy_entry_uuid(entry_id: u64) -> Uuid {
    let high = ((entry_id >> 48) & 0xffff) as u16;
    let low = entry_id & 0x0000_ffff_ffff_ffff;
    let value = format!("00000000-0000-0000-{high:04x}-{low:012x}");
    Uuid::parse_str(&value).expect("valid legacy UUID")
}

fn legacy_entry_timestamp(entry_id: u64) -> chrono::DateTime<Utc> {
    let seconds = i64::try_from(entry_id).unwrap_or(i64::MAX);
    Utc.timestamp_opt(seconds, 0)
        .single()
        .unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    use super::{ActionEntry, ActionType};
    use crate::ledger::{ActionType as LedgerActionType, LedgerEntry};

    #[test]
    fn legacy_action_entry_bridges_to_canonical_ledger_entry() {
        let legacy = ActionEntry {
            entry_id: 7,
            action_type: ActionType::HumanOverride,
            description: "override".to_string(),
            related_entry_id: Some(3),
            oversight: None,
        };

        let ledger = LedgerEntry::from(&legacy);

        assert_eq!(ledger.action_type, LedgerActionType::HumanOverride);
        assert_eq!(ledger.payload["legacy_entry_id"], 7);
        assert_eq!(ledger.payload["related_entry_id"], 3);
        assert_eq!(ledger.payload["description"], "override");
    }
}
