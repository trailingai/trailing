use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::action_log::ActionType as LegacyActionType;
use crate::log::ActionType as LogActionType;

pub const CURRENT_AUDIT_EVENT_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub version: u16,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub agent_type: String,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(flatten)]
    pub kind: AuditEventKind,
}

impl AuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        timestamp: DateTime<Utc>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        session_id: impl Into<String>,
        trace_id: Option<String>,
        span_id: Option<String>,
        kind: AuditEventKind,
    ) -> Self {
        Self {
            version: CURRENT_AUDIT_EVENT_VERSION,
            timestamp,
            agent_id: agent_id.into(),
            agent_type: agent_type.into(),
            session_id: session_id.into(),
            trace_id,
            span_id,
            kind,
        }
    }

    pub fn action_type(&self) -> LogActionType {
        self.into()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_type", content = "event", rename_all = "snake_case")]
pub enum AuditEventKind {
    ToolCall(ToolCallEvent),
    ToolResult(ToolResultEvent),
    LlmRequest(LlmRequestEvent),
    LlmResponse(LlmResponseEvent),
    Retrieval(RetrievalEvent),
    ExternalWrite(ExternalWriteEvent),
    DecisionPoint(DecisionPointEvent),
    PolicyCheck(PolicyCheckEvent),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCallEvent {
    pub name: String,
    #[serde(default)]
    pub args: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResultEvent {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmRequestEvent {
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<LlmMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<LlmTokenUsage>,
    pub provider: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmResponseEvent {
    pub model: String,
    pub completion: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_used: Option<LlmTokenUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: String,
    pub content: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmTokenUsage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalEvent {
    pub source: String,
    pub query: String,
    pub results_count: u32,
    pub context_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalWriteEvent {
    pub target_system: String,
    pub operation: String,
    pub resource: String,
    pub payload_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPointEvent {
    pub condition: String,
    pub branches: Vec<String>,
    pub chosen: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyCheckEvent {
    pub policy_id: String,
    pub control_id: String,
    pub result: String,
    #[serde(default)]
    pub evidence: Value,
}

impl From<&AuditEventKind> for LogActionType {
    fn from(value: &AuditEventKind) -> Self {
        match value {
            AuditEventKind::ToolCall(_) | AuditEventKind::ToolResult(_) => Self::ToolCall,
            AuditEventKind::LlmRequest(_)
            | AuditEventKind::LlmResponse(_)
            | AuditEventKind::DecisionPoint(_) => Self::Decision,
            AuditEventKind::Retrieval(_) => Self::DataAccess,
            AuditEventKind::ExternalWrite(_) => Self::SystemWrite,
            AuditEventKind::PolicyCheck(_) => Self::PolicyCheck,
        }
    }
}

impl From<AuditEventKind> for LogActionType {
    fn from(value: AuditEventKind) -> Self {
        (&value).into()
    }
}

impl From<&AuditEvent> for LogActionType {
    fn from(value: &AuditEvent) -> Self {
        (&value.kind).into()
    }
}

impl From<AuditEvent> for LogActionType {
    fn from(value: AuditEvent) -> Self {
        (&value).into()
    }
}

impl From<&AuditEventKind> for LegacyActionType {
    fn from(_: &AuditEventKind) -> Self {
        Self::AgentAction
    }
}

impl From<AuditEventKind> for LegacyActionType {
    fn from(value: AuditEventKind) -> Self {
        (&value).into()
    }
}

impl From<&AuditEvent> for LegacyActionType {
    fn from(value: &AuditEvent) -> Self {
        (&value.kind).into()
    }
}

impl From<AuditEvent> for LegacyActionType {
    fn from(value: AuditEvent) -> Self {
        (&value).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn timestamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 30, 14, 5, 6)
            .single()
            .expect("valid timestamp")
    }

    fn sample_event(kind: AuditEventKind) -> AuditEvent {
        AuditEvent::new(
            timestamp(),
            "agent-1",
            "codex",
            "session-1",
            Some("trace-1".to_string()),
            Some("span-1".to_string()),
            kind,
        )
    }

    fn sample_events() -> Vec<(AuditEvent, Value)> {
        vec![
            (
                sample_event(AuditEventKind::ToolCall(ToolCallEvent {
                    name: "shell.exec".to_string(),
                    args: json!({"cmd": "cargo check"}),
                })),
                json!({
                    "version": 1,
                    "timestamp": "2026-03-30T14:05:06Z",
                    "agent_id": "agent-1",
                    "agent_type": "codex",
                    "session_id": "session-1",
                    "trace_id": "trace-1",
                    "span_id": "span-1",
                    "event_type": "tool_call",
                    "event": {
                        "name": "shell.exec",
                        "args": {"cmd": "cargo check"}
                    }
                }),
            ),
            (
                sample_event(AuditEventKind::ToolResult(ToolResultEvent {
                    name: "shell.exec".to_string(),
                    result: Some(json!({"status": "ok"})),
                    duration: Some(145),
                    error: None,
                })),
                json!({
                    "version": 1,
                    "timestamp": "2026-03-30T14:05:06Z",
                    "agent_id": "agent-1",
                    "agent_type": "codex",
                    "session_id": "session-1",
                    "trace_id": "trace-1",
                    "span_id": "span-1",
                    "event_type": "tool_result",
                    "event": {
                        "name": "shell.exec",
                        "result": {"status": "ok"},
                        "duration": 145
                    }
                }),
            ),
            (
                sample_event(AuditEventKind::LlmRequest(LlmRequestEvent {
                    model: "gpt-5.4".to_string(),
                    prompt: None,
                    messages: vec![
                        LlmMessage {
                            role: "system".to_string(),
                            content: json!("Follow policy."),
                        },
                        LlmMessage {
                            role: "user".to_string(),
                            content: json!("Summarize this run."),
                        },
                    ],
                    temperature: Some(0.2),
                    tokens: Some(LlmTokenUsage {
                        input: Some(300),
                        output: Some(1200),
                        total: Some(1500),
                    }),
                    provider: "openai".to_string(),
                })),
                json!({
                    "version": 1,
                    "timestamp": "2026-03-30T14:05:06Z",
                    "agent_id": "agent-1",
                    "agent_type": "codex",
                    "session_id": "session-1",
                    "trace_id": "trace-1",
                    "span_id": "span-1",
                    "event_type": "llm_request",
                    "event": {
                        "model": "gpt-5.4",
                        "messages": [
                            {"role": "system", "content": "Follow policy."},
                            {"role": "user", "content": "Summarize this run."}
                        ],
                        "temperature": 0.2,
                        "tokens": {
                            "input": 300,
                            "output": 1200,
                            "total": 1500
                        },
                        "provider": "openai"
                    }
                }),
            ),
            (
                sample_event(AuditEventKind::LlmResponse(LlmResponseEvent {
                    model: "gpt-5.4".to_string(),
                    completion: "Approved with conditions.".to_string(),
                    tokens_used: Some(LlmTokenUsage {
                        input: Some(300),
                        output: Some(125),
                        total: Some(425),
                    }),
                    latency: Some(842),
                    finish_reason: Some("stop".to_string()),
                })),
                json!({
                    "version": 1,
                    "timestamp": "2026-03-30T14:05:06Z",
                    "agent_id": "agent-1",
                    "agent_type": "codex",
                    "session_id": "session-1",
                    "trace_id": "trace-1",
                    "span_id": "span-1",
                    "event_type": "llm_response",
                    "event": {
                        "model": "gpt-5.4",
                        "completion": "Approved with conditions.",
                        "tokens_used": {
                            "input": 300,
                            "output": 125,
                            "total": 425
                        },
                        "latency": 842,
                        "finish_reason": "stop"
                    }
                }),
            ),
            (
                sample_event(AuditEventKind::Retrieval(RetrievalEvent {
                    source: "vector-db".to_string(),
                    query: "latest policy".to_string(),
                    results_count: 4,
                    context_type: "policy_context".to_string(),
                })),
                json!({
                    "version": 1,
                    "timestamp": "2026-03-30T14:05:06Z",
                    "agent_id": "agent-1",
                    "agent_type": "codex",
                    "session_id": "session-1",
                    "trace_id": "trace-1",
                    "span_id": "span-1",
                    "event_type": "retrieval",
                    "event": {
                        "source": "vector-db",
                        "query": "latest policy",
                        "results_count": 4,
                        "context_type": "policy_context"
                    }
                }),
            ),
            (
                sample_event(AuditEventKind::ExternalWrite(ExternalWriteEvent {
                    target_system: "salesforce".to_string(),
                    operation: "upsert".to_string(),
                    resource: "case/123".to_string(),
                    payload_hash: "deadbeef".to_string(),
                })),
                json!({
                    "version": 1,
                    "timestamp": "2026-03-30T14:05:06Z",
                    "agent_id": "agent-1",
                    "agent_type": "codex",
                    "session_id": "session-1",
                    "trace_id": "trace-1",
                    "span_id": "span-1",
                    "event_type": "external_write",
                    "event": {
                        "target_system": "salesforce",
                        "operation": "upsert",
                        "resource": "case/123",
                        "payload_hash": "deadbeef"
                    }
                }),
            ),
            (
                sample_event(AuditEventKind::DecisionPoint(DecisionPointEvent {
                    condition: "policy score >= threshold".to_string(),
                    branches: vec!["approve".to_string(), "escalate".to_string()],
                    chosen: "approve".to_string(),
                    reason: "confidence exceeded the escalation threshold".to_string(),
                })),
                json!({
                    "version": 1,
                    "timestamp": "2026-03-30T14:05:06Z",
                    "agent_id": "agent-1",
                    "agent_type": "codex",
                    "session_id": "session-1",
                    "trace_id": "trace-1",
                    "span_id": "span-1",
                    "event_type": "decision_point",
                    "event": {
                        "condition": "policy score >= threshold",
                        "branches": ["approve", "escalate"],
                        "chosen": "approve",
                        "reason": "confidence exceeded the escalation threshold"
                    }
                }),
            ),
            (
                sample_event(AuditEventKind::PolicyCheck(PolicyCheckEvent {
                    policy_id: "nist-ai-rmf".to_string(),
                    control_id: "GV-3".to_string(),
                    result: "pass".to_string(),
                    evidence: json!({
                        "refs": ["log://audit/2026-03-30/1"],
                        "notes": "verified at ingest"
                    }),
                })),
                json!({
                    "version": 1,
                    "timestamp": "2026-03-30T14:05:06Z",
                    "agent_id": "agent-1",
                    "agent_type": "codex",
                    "session_id": "session-1",
                    "trace_id": "trace-1",
                    "span_id": "span-1",
                    "event_type": "policy_check",
                    "event": {
                        "policy_id": "nist-ai-rmf",
                        "control_id": "GV-3",
                        "result": "pass",
                        "evidence": {
                            "refs": ["log://audit/2026-03-30/1"],
                            "notes": "verified at ingest"
                        }
                    }
                }),
            ),
        ]
    }

    #[test]
    fn audit_events_round_trip_through_json() {
        for (expected_event, expected_json) in sample_events() {
            let parsed: AuditEvent =
                serde_json::from_value(expected_json.clone()).expect("event should deserialize");
            assert_eq!(parsed, expected_event);

            let serialized = serde_json::to_value(&parsed).expect("event should serialize");
            assert_eq!(serialized, expected_json);
        }
    }

    #[test]
    fn canonical_events_bridge_to_existing_action_types() {
        let cases = vec![
            (
                AuditEventKind::ToolCall(ToolCallEvent {
                    name: "shell.exec".to_string(),
                    args: json!({}),
                }),
                LogActionType::ToolCall,
            ),
            (
                AuditEventKind::ToolResult(ToolResultEvent {
                    name: "shell.exec".to_string(),
                    result: None,
                    duration: None,
                    error: Some("timeout".to_string()),
                }),
                LogActionType::ToolCall,
            ),
            (
                AuditEventKind::LlmRequest(LlmRequestEvent {
                    model: "gpt-5.4".to_string(),
                    prompt: Some("Review this".to_string()),
                    messages: Vec::new(),
                    temperature: None,
                    tokens: None,
                    provider: "openai".to_string(),
                }),
                LogActionType::Decision,
            ),
            (
                AuditEventKind::LlmResponse(LlmResponseEvent {
                    model: "gpt-5.4".to_string(),
                    completion: "Approved".to_string(),
                    tokens_used: None,
                    latency: None,
                    finish_reason: None,
                }),
                LogActionType::Decision,
            ),
            (
                AuditEventKind::Retrieval(RetrievalEvent {
                    source: "vector-db".to_string(),
                    query: "policy".to_string(),
                    results_count: 2,
                    context_type: "policy_context".to_string(),
                }),
                LogActionType::DataAccess,
            ),
            (
                AuditEventKind::ExternalWrite(ExternalWriteEvent {
                    target_system: "salesforce".to_string(),
                    operation: "upsert".to_string(),
                    resource: "case/123".to_string(),
                    payload_hash: "deadbeef".to_string(),
                }),
                LogActionType::SystemWrite,
            ),
            (
                AuditEventKind::DecisionPoint(DecisionPointEvent {
                    condition: "risk > limit".to_string(),
                    branches: vec!["approve".to_string(), "deny".to_string()],
                    chosen: "deny".to_string(),
                    reason: "risk exceeded limit".to_string(),
                }),
                LogActionType::Decision,
            ),
            (
                AuditEventKind::PolicyCheck(PolicyCheckEvent {
                    policy_id: "policy-1".to_string(),
                    control_id: "control-1".to_string(),
                    result: "pass".to_string(),
                    evidence: json!(["evidence-1"]),
                }),
                LogActionType::PolicyCheck,
            ),
        ];

        for (kind, expected_action_type) in cases {
            let event = sample_event(kind.clone());
            assert_eq!(LogActionType::from(&kind), expected_action_type);
            assert_eq!(LogActionType::from(&event), expected_action_type);
            assert_eq!(LegacyActionType::from(&kind), LegacyActionType::AgentAction);
            assert_eq!(
                LegacyActionType::from(&event),
                LegacyActionType::AgentAction
            );
        }
    }
}
