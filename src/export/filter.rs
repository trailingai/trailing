use chrono::{DateTime, Utc};

use super::{EvidenceAction, EvidencePackage, OversightEvent};

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExportFilter {
    pub time_range: Option<TimeRange>,
    pub agent_id: Option<String>,
    pub session_id: Option<String>,
    pub action_type: Option<String>,
    pub legal_hold: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeRange {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

impl TimeRange {
    pub fn contains(&self, value: DateTime<Utc>) -> bool {
        let after_start = self.start.is_none_or(|start| value >= start);
        let before_end = self.end.is_none_or(|end| value <= end);
        after_start && before_end
    }
}

impl ExportFilter {
    pub fn apply(&self, package: &EvidencePackage) -> EvidencePackage {
        let mut filtered = package.clone();
        filtered.actions = package
            .actions
            .iter()
            .filter(|action| self.matches_action(action))
            .cloned()
            .collect();
        filtered.oversight_events = package
            .oversight_events
            .iter()
            .filter(|event| self.matches_event(event))
            .cloned()
            .collect();
        filtered.refresh_hash();
        filtered
    }

    fn matches_action(&self, action: &EvidenceAction) -> bool {
        self.matches_time(action.timestamp)
            && self
                .agent_id
                .as_ref()
                .is_none_or(|agent_id| action.agent_id == *agent_id)
            && self
                .session_id
                .as_ref()
                .is_none_or(|session_id| action.session_id == *session_id)
            && self
                .action_type
                .as_ref()
                .is_none_or(|action_type| action.action_type == *action_type)
            && self
                .legal_hold
                .is_none_or(|legal_hold| action.legal_hold == legal_hold)
    }

    fn matches_event(&self, event: &OversightEvent) -> bool {
        self.matches_time(event.timestamp)
            && self
                .session_id
                .as_ref()
                .is_none_or(|session_id| event.session_id == *session_id)
            && self.agent_id.as_ref().is_none_or(|agent_id| {
                event
                    .agent_id
                    .as_ref()
                    .is_some_and(|event_agent| event_agent == agent_id)
            })
            && self
                .legal_hold
                .is_none_or(|legal_hold| event.legal_hold == legal_hold)
    }

    fn matches_time(&self, value: DateTime<Utc>) -> bool {
        self.time_range
            .as_ref()
            .is_none_or(|time_range| time_range.contains(value))
    }
}
