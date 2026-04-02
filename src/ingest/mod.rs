pub mod helpers;

use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Map, Value, json};

use crate::{
    ingest::helpers::{ActionTypeHints, resolve_action_type},
    storage::{Storage, StorageError},
};

type Result<T> = std::result::Result<T, IngestError>;

pub const REDACTED_VALUE: &str = "[REDACTED]";

#[derive(Debug)]
pub enum IngestError {
    Json(serde_json::Error),
    Storage(StorageError),
}

impl Display for IngestError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::Storage(error) => write!(f, "storage error: {error}"),
        }
    }
}

impl std::error::Error for IngestError {}

impl From<serde_json::Error> for IngestError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<StorageError> for IngestError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct NormalizedActionRecord {
    timestamp: Option<String>,
    session_id: String,
    trace_id: Option<String>,
    span_id: Option<String>,
    agent: String,
    agent_type: String,
    action_type: String,
    tool_name: Option<String>,
    target: Option<String>,
    schema_version: Option<String>,
    idempotency_key: Option<String>,
    request_metadata: Option<Value>,
    result_metadata: Option<Value>,
    outcome: String,
    payload: Value,
}

pub fn apply_cli_defaults(mut value: Value, agent_type: &str, session_id: &str) -> Value {
    let Some(object) = value.as_object_mut() else {
        return value;
    };

    if !object.contains_key("session_id") && !object.contains_key("sessionId") {
        object.insert(
            "session_id".to_string(),
            Value::String(session_id.to_string()),
        );
    }

    if !object.contains_key("agent_type") && !object.contains_key("agentType") {
        object.insert(
            "agent_type".to_string(),
            Value::String(agent_type.to_string()),
        );
    }

    if !object.contains_key("agent_id")
        && !object.contains_key("agentId")
        && !object.contains_key("agent")
        && !object.contains_key("name")
    {
        object.insert(
            "agent_id".to_string(),
            Value::String(format!("{agent_type}-stdin")),
        );
    }

    value
}

pub fn redact_json_fields(mut value: Value, field_names: &[&str]) -> Value {
    let fields = field_names
        .iter()
        .map(|field| field.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    redact_value(&mut value, &fields);
    value
}

pub fn ingest_json_action(
    storage: &Storage,
    payload: Value,
    source: &str,
    dedup_key: Option<&str>,
) -> Result<Option<String>> {
    let action = normalize_sdk_action(payload);
    let (stored_timestamp, display_timestamp) = resolved_timestamp(action.timestamp.clone());
    let log_action_type = resolve_action_type(&ActionTypeHints {
        action_name: &action.action_type,
        payload: &action.payload,
        tool_name: action.tool_name.as_deref(),
        target: action.target.as_deref(),
        has_data_accessed: false,
    });
    let context = json!({
        "trailing": {
            "kind": "action",
            "event_kind": "action",
            "source": source,
            "api_type": action.action_type,
            "tool_name": action.tool_name,
            "target": action.target,
            "schema_version": action.schema_version,
            "trace_id": action.trace_id,
            "span_id": action.span_id,
            "idempotency_key": action.idempotency_key,
            "request_metadata": action.request_metadata,
            "result_metadata": action.result_metadata,
            "display_timestamp": display_timestamp,
        }
    });

    let entry = match dedup_key {
        Some(dedup_key) => storage.append_action_with_dedup_at(
            dedup_key,
            stored_timestamp,
            action.agent,
            action.agent_type,
            action.session_id,
            log_action_type,
            action.payload,
            context,
            action.outcome,
        )?,
        None => Some(storage.append_action_at(
            stored_timestamp,
            action.agent,
            action.agent_type,
            action.session_id,
            log_action_type,
            action.payload,
            context,
            action.outcome,
        )?),
    };

    Ok(entry.map(|entry| entry.id.to_string()))
}

fn normalize_sdk_action(item: Value) -> NormalizedActionRecord {
    let session_id = json_string_paths(&item, &[&["session_id"], &["sessionId"]])
        .unwrap_or_else(|| "unknown-session".to_string());
    let trace_id = json_string_paths(
        &item,
        &[
            &["trace_id"],
            &["traceId"],
            &["context", "trace_id"],
            &["context", "traceId"],
        ],
    );
    let span_id = json_string_paths(
        &item,
        &[
            &["span_id"],
            &["spanId"],
            &["context", "span_id"],
            &["context", "spanId"],
        ],
    );
    let agent = json_string_paths(&item, &[&["agent_id"], &["agentId"], &["agent"], &["name"]])
        .unwrap_or_else(|| "unknown-agent".to_string());
    let agent_type = json_string_paths(&item, &[&["agent_type"], &["agentType"]])
        .unwrap_or_else(|| "unknown".to_string());
    let action_type = json_string_paths(
        &item,
        &[
            &["action", "type"],
            &["action", "action_type"],
            &["type"],
            &["name"],
            &["event_type"],
        ],
    )
    .unwrap_or_else(|| "event".to_string());
    let tool_name = json_string_paths(
        &item,
        &[
            &["action", "tool_name"],
            &["action", "toolName"],
            &["tool_name"],
            &["toolName"],
            &["payload", "tool"],
        ],
    );
    let target = json_string_paths(
        &item,
        &[
            &["action", "target"],
            &["target"],
            &["resource"],
            &["resource", "name"],
        ],
    );
    let outcome = json_string_paths(&item, &[&["status"], &["action", "status"], &["outcome"]])
        .unwrap_or_else(|| "ok".to_string());
    let timestamp = json_string_paths(&item, &[&["timestamp"]]);
    let schema_version = json_string_paths(&item, &[&["schema_version"], &["schemaVersion"]]);
    let idempotency_key = json_string_paths(&item, &[&["idempotency_key"], &["idempotencyKey"]]);
    let request_metadata = json_value_paths(
        &item,
        &[
            &["request_metadata"],
            &["requestMetadata"],
            &["request", "metadata"],
            &["action", "request_metadata"],
            &["action", "requestMetadata"],
            &["action", "request"],
            &["metadata", "request"],
        ],
    );
    let result_metadata = json_value_paths(
        &item,
        &[
            &["result_metadata"],
            &["resultMetadata"],
            &["result", "metadata"],
            &["action", "result_metadata"],
            &["action", "resultMetadata"],
            &["action", "result"],
            &["metadata", "result"],
        ],
    );

    NormalizedActionRecord {
        timestamp,
        session_id,
        trace_id,
        span_id,
        agent,
        agent_type,
        action_type,
        tool_name,
        target,
        schema_version,
        idempotency_key,
        request_metadata,
        result_metadata,
        outcome,
        payload: item,
    }
}

fn resolved_timestamp(raw: Option<String>) -> (DateTime<Utc>, String) {
    match raw {
        Some(display_timestamp) => (
            parse_stored_timestamp(&display_timestamp).unwrap_or_else(current_time),
            display_timestamp,
        ),
        None => {
            let timestamp = current_time();
            (timestamp, timestamp.to_rfc3339())
        }
    }
}

fn parse_stored_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(timestamp) = DateTime::parse_from_rfc3339(raw) {
        return Some(timestamp.with_timezone(&Utc));
    }

    let nanos = raw.parse::<i64>().ok()?;
    let seconds = nanos.div_euclid(1_000_000_000);
    let subsec_nanos = nanos.rem_euclid(1_000_000_000) as u32;
    Utc.timestamp_opt(seconds, subsec_nanos).single()
}

fn current_time() -> DateTime<Utc> {
    std::time::SystemTime::now().into()
}

fn json_string_paths(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| json_value_at_path(value, path))
        .and_then(value_to_string)
}

fn json_value_paths(value: &Value, paths: &[&[&str]]) -> Option<Value> {
    paths
        .iter()
        .find_map(|path| json_value_at_path(value, path))
        .cloned()
        .filter(value_has_content)
}

fn json_value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        let Value::Object(object) = current else {
            return None;
        };
        current = object.get(*key)?;
    }
    Some(current)
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Object(map) => {
            if map.is_empty() {
                None
            } else {
                Some(Value::Object(map.clone()).to_string())
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                None
            } else {
                Some(Value::Array(items.clone()).to_string())
            }
        }
        Value::Null => None,
    }
}

fn value_has_content(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        _ => true,
    }
}

pub fn object(fields: impl IntoIterator<Item = (impl Into<String>, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in fields {
        map.insert(key.into(), value);
    }
    Value::Object(map)
}

fn redact_value(value: &mut Value, fields: &HashSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object.iter_mut() {
                if fields.contains(&key.to_ascii_lowercase()) {
                    *nested = Value::String(REDACTED_VALUE.to_string());
                } else {
                    redact_value(nested, fields);
                }
            }
        }
        Value::Array(items) => {
            for nested in items {
                redact_value(nested, fields);
            }
        }
        _ => {}
    }
}
