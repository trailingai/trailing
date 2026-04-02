use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Value};

use super::otel::OtelSpan;
use super::sdk::SdkEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentType {
    Claude,
    Codex,
    Cursor,
    OpenAi,
    Anthropic,
    Unknown(String),
}

impl AgentType {
    pub fn detect(agent_type: &str) -> Self {
        let normalized = agent_type.trim().to_ascii_lowercase();
        if normalized.contains("codex") {
            Self::Codex
        } else if normalized.contains("claude") {
            Self::Claude
        } else if normalized.contains("cursor") {
            Self::Cursor
        } else if normalized.contains("anthropic") {
            Self::Anthropic
        } else if normalized.contains("openai") || normalized.contains("gpt") {
            Self::OpenAi
        } else {
            Self::Unknown(agent_type.to_string())
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            Self::Claude => "claude".to_string(),
            Self::Codex => "codex".to_string(),
            Self::Cursor => "cursor".to_string(),
            Self::OpenAi => "openai".to_string(),
            Self::Anthropic => "anthropic".to_string(),
            Self::Unknown(value) => value.clone(),
        }
    }
}

static ENTRY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActionContext {
    pub parent_span_id: Option<String>,
    pub data_accessed: Vec<String>,
    pub permissions_used: Vec<String>,
    pub policy_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionEntry {
    pub entry_id: String,
    pub modified_entry_id: Option<String>,
    pub agent_id: String,
    pub agent_type: AgentType,
    pub session_id: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub action_type: String,
    pub tool_name: Option<String>,
    pub target: Option<String>,
    pub payload: Value,
    pub result: Option<Value>,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub status: Option<String>,
    pub context: ActionContext,
}

impl ActionEntry {
    pub fn is_human_oversight(&self) -> bool {
        self.action_type == "HumanOverride"
    }
}

pub(crate) fn next_entry_id(prefix: &str) -> String {
    let sequence = ENTRY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{sequence}")
}

pub fn normalize_sdk_event(event: SdkEvent) -> ActionEntry {
    ActionEntry {
        entry_id: next_entry_id("sdk"),
        modified_entry_id: None,
        agent_id: event.agent_id,
        agent_type: AgentType::detect(&event.agent_type),
        session_id: event.session_id,
        trace_id: None,
        span_id: None,
        action_type: event.action.action_type,
        tool_name: event.action.tool_name,
        target: event.action.target,
        payload: event.action.parameters,
        result: event.action.result,
        started_at: None,
        ended_at: None,
        status: None,
        context: ActionContext {
            parent_span_id: None,
            data_accessed: event.context.data_accessed,
            permissions_used: event.context.permissions_used,
            policy_refs: event.context.policy_refs,
        },
    }
}

pub fn normalize_otel_span(span: OtelSpan) -> ActionEntry {
    let entry_id = format!("otel-{}-{}", span.trace_id, span.span_id);
    let agent_id = find_string_attribute(&span.attributes, &["agent.id", "agent_id"])
        .unwrap_or_else(|| span.trace_id.clone());
    let agent_type_value = find_string_attribute(&span.attributes, &["agent.type", "agent_type"])
        .unwrap_or_else(|| "unknown".to_string());
    let session_id = find_string_attribute(&span.attributes, &["session.id", "session_id"])
        .or_else(|| span.parent_span_id.clone())
        .unwrap_or_else(|| span.trace_id.clone());
    let tool_name = find_string_attribute(&span.attributes, &["tool.name", "tool_name"]);
    let target = find_string_attribute(
        &span.attributes,
        &["target", "target.id", "resource.name", "http.url"],
    );

    ActionEntry {
        entry_id,
        modified_entry_id: None,
        agent_id,
        agent_type: AgentType::detect(&agent_type_value),
        session_id,
        trace_id: Some(span.trace_id),
        span_id: Some(span.span_id),
        action_type: span.name,
        tool_name,
        target,
        payload: Value::Object(span.attributes.clone()),
        result: None,
        started_at: span.start_time,
        ended_at: span.end_time,
        status: span.status,
        context: ActionContext {
            parent_span_id: span.parent_span_id,
            data_accessed: collect_string_values(&span.attributes, &["data.accessed"]),
            permissions_used: collect_string_values(
                &span.attributes,
                &["permissions.used", "permissions"],
            ),
            policy_refs: collect_string_values(&span.attributes, &["policy.refs", "policy_refs"]),
        },
    }
}

fn find_string_attribute(attributes: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| attributes.get(*key))
        .and_then(|value| match value {
            Value::String(raw) => Some(raw.clone()),
            Value::Number(raw) => Some(raw.to_string()),
            _ => None,
        })
}

fn collect_string_values(attributes: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| attributes.get(*key))
        .map(value_to_string_list)
        .unwrap_or_default()
}

fn value_to_string_list(value: &Value) -> Vec<String> {
    match value {
        Value::String(raw) => vec![raw.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                Value::String(raw) => Some(raw.clone()),
                Value::Number(raw) => Some(raw.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}
