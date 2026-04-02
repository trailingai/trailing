pub mod normalize;
pub mod otel;
pub mod sdk;

use std::error::Error;
use std::fmt;

use serde_json::json;

use crate::storage::SqliteStorage;
use crate::{
    ingest::helpers::{ActionTypeHints, resolve_action_type},
    log::ActionType as LogActionType,
};

pub use normalize::{
    ActionContext, ActionEntry, AgentType, normalize_otel_span, normalize_sdk_event,
};
pub use otel::{OtelSpan, parse_otlp_http_json};
pub use sdk::{SdkAction, SdkContext, SdkEvent};

#[derive(Debug)]
pub enum CollectorError {
    Json(serde_json::Error),
    MissingField(&'static str),
    InvalidOtelPayload(String),
    Storage(String),
}

impl fmt::Display for CollectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::InvalidOtelPayload(message) => write!(f, "invalid otel payload: {message}"),
            Self::Storage(message) => write!(f, "storage error: {message}"),
        }
    }
}

impl Error for CollectorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for CollectorError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub trait ActionStorage {
    fn write_action(&mut self, entry: ActionEntry) -> Result<(), CollectorError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryStorage {
    entries: Vec<ActionEntry>,
}

impl InMemoryStorage {
    pub fn entries(&self) -> &[ActionEntry] {
        &self.entries
    }
}

impl ActionStorage for InMemoryStorage {
    fn write_action(&mut self, entry: ActionEntry) -> Result<(), CollectorError> {
        self.entries.push(entry);
        Ok(())
    }
}

impl ActionStorage for SqliteStorage {
    fn write_action(&mut self, entry: ActionEntry) -> Result<(), CollectorError> {
        let outcome = entry.status.clone().unwrap_or_else(|| "ok".to_string());
        let action_type = classify_action_type(&entry);
        let schema_version =
            json_string_paths(&entry.payload, &[&["schema_version"], &["schemaVersion"]]);
        let idempotency_key =
            json_string_paths(&entry.payload, &[&["idempotency_key"], &["idempotencyKey"]]);
        let request_metadata = json_value_paths(
            &entry.payload,
            &[
                &["request_metadata"],
                &["requestMetadata"],
                &["request", "metadata"],
                &["metadata", "request"],
            ],
        );
        let context = json!({
            "trace_id": entry.trace_id,
            "span_id": entry.span_id,
            "tool_name": entry.tool_name,
            "target": entry.target,
            "result": entry.result,
            "started_at": entry.started_at,
            "ended_at": entry.ended_at,
            "parent_span_id": entry.context.parent_span_id,
            "data_accessed": entry.context.data_accessed,
            "permissions_used": entry.context.permissions_used,
            "policy_refs": entry.context.policy_refs,
            "trailing": {
                "kind": "action",
                "event_kind": "action",
                "schema_version": schema_version,
                "trace_id": entry.trace_id,
                "span_id": entry.span_id,
                "idempotency_key": idempotency_key,
                "request_metadata": request_metadata,
                "result_metadata": entry.result,
            }
        });

        self.append_action(
            entry.agent_id,
            entry.agent_type.as_str(),
            entry.session_id,
            action_type,
            entry.payload,
            context,
            outcome,
        )
        .map(|_| ())
        .map_err(|error| CollectorError::Storage(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub enum TraceEvent {
    Otel(OtelSpan),
    Sdk(SdkEvent),
}

pub struct TraceCollector<S> {
    storage: S,
}

impl<S> TraceCollector<S>
where
    S: ActionStorage,
{
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    pub fn ingest_event(&mut self, event: TraceEvent) -> Result<ActionEntry, CollectorError> {
        match event {
            TraceEvent::Otel(span) => self.ingest_otel_span(span),
            TraceEvent::Sdk(event) => self.ingest_sdk_event(event),
        }
    }

    pub fn ingest_otel_json(&mut self, payload: &str) -> Result<Vec<ActionEntry>, CollectorError> {
        let mut entries = Vec::new();
        for span in parse_otlp_http_json(payload)? {
            entries.push(self.ingest_otel_span(span)?);
        }
        Ok(entries)
    }

    pub fn ingest_otel_span(&mut self, span: OtelSpan) -> Result<ActionEntry, CollectorError> {
        let entry = normalize_otel_span(span);
        self.storage.write_action(entry.clone())?;
        Ok(entry)
    }

    pub fn ingest_sdk_event(&mut self, event: SdkEvent) -> Result<ActionEntry, CollectorError> {
        let entry = normalize_sdk_event(event);
        self.storage.write_action(entry.clone())?;
        Ok(entry)
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    pub fn into_storage(self) -> S {
        self.storage
    }
}

fn classify_action_type(entry: &ActionEntry) -> LogActionType {
    resolve_action_type(&ActionTypeHints {
        action_name: &entry.action_type,
        payload: &entry.payload,
        tool_name: entry.tool_name.as_deref(),
        target: entry.target.as_deref(),
        has_data_accessed: !entry.context.data_accessed.is_empty(),
    })
}

fn json_string_paths(value: &serde_json::Value, paths: &[&[&str]]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| json_value_path(value, path))
        .and_then(|value| match value {
            serde_json::Value::String(text) => Some(text.clone()),
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
}

fn json_value_paths(value: &serde_json::Value, paths: &[&[&str]]) -> Option<serde_json::Value> {
    paths
        .iter()
        .find_map(|path| json_value_path(value, path))
        .cloned()
        .filter(value_has_content)
}

fn json_value_path<'a>(
    value: &'a serde_json::Value,
    path: &[&str],
) -> Option<&'a serde_json::Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
}

fn value_has_content(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(object) => !object.is_empty(),
        _ => true,
    }
}
