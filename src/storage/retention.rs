use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub min_retention_days: i64,
    pub legal_hold: bool,
}

impl RetentionPolicy {
    pub fn cutoff(&self, as_of: DateTime<Utc>) -> DateTime<Utc> {
        as_of - Duration::days(self.min_retention_days.max(0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrgRetentionPolicy {
    pub org_id: String,
    pub min_retention_days: i64,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LegalHoldRecord {
    pub id: String,
    pub org_id: Option<String>,
    pub matter: String,
    pub reason: String,
    pub created_at: String,
    pub released_at: Option<String>,
    pub release_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LegalHoldEvent {
    pub id: String,
    pub hold_id: String,
    pub org_id: Option<String>,
    pub event_type: String,
    pub occurred_at: String,
    pub detail: String,
}
