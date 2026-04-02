use serde_json::{Map, Value};

use crate::log::ActionType;

const TRAILING_KEY: &str = "trailing";
const INSTRUMENTATION_KEY: &str = "instrumentation";
const ACTION_TYPE_KEY: &str = "action_type";
const CANONICAL_ACTION_TYPE_KEY: &str = "canonical_action_type";
const KIND_KEY: &str = "kind";
const TARGET_KEY: &str = "target";
const POLICY_REFS_KEY: &str = "policy_refs";
const ATTRIBUTE_ACTION_TYPE_KEY: &str = "trailing.instrumentation.action_type";
const ATTRIBUTE_CANONICAL_ACTION_TYPE_KEY: &str = "trailing.instrumentation.canonical_action_type";
const ATTRIBUTE_KIND_KEY: &str = "trailing.instrumentation.kind";
const ATTRIBUTE_TARGET_KEY: &str = "trailing.instrumentation.target";
const ATTRIBUTE_POLICY_REFS_KEY: &str = "trailing.instrumentation.policy_refs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrumentationKind {
    Write,
    Retrieval,
    Policy,
}

impl InstrumentationKind {
    pub fn action_type(self) -> ActionType {
        match self {
            Self::Write => ActionType::SystemWrite,
            Self::Retrieval => ActionType::DataAccess,
            Self::Policy => ActionType::PolicyCheck,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Retrieval => "retrieval",
            Self::Policy => "policy",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrumentationEvent {
    kind: InstrumentationKind,
    target: Option<String>,
    policy_refs: Vec<String>,
}

impl InstrumentationEvent {
    pub fn write(target: impl Into<String>) -> Self {
        Self {
            kind: InstrumentationKind::Write,
            target: Some(target.into()),
            policy_refs: Vec::new(),
        }
    }

    pub fn retrieval(target: impl Into<String>) -> Self {
        Self {
            kind: InstrumentationKind::Retrieval,
            target: Some(target.into()),
            policy_refs: Vec::new(),
        }
    }

    pub fn policy<I, S>(policy_refs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            kind: InstrumentationKind::Policy,
            target: None,
            policy_refs: policy_refs.into_iter().map(Into::into).collect(),
        }
    }

    pub fn apply_to_payload(&self, payload: Value) -> Value {
        let mut object = match payload {
            Value::Object(object) => object,
            other => {
                let mut object = Map::new();
                object.insert("payload".to_string(), other);
                object
            }
        };

        if let Some(target) = self.target.as_ref() {
            object
                .entry(TARGET_KEY.to_string())
                .or_insert_with(|| Value::String(target.clone()));
        }

        if !self.policy_refs.is_empty() && !object.contains_key(POLICY_REFS_KEY) {
            object.insert(POLICY_REFS_KEY.to_string(), string_array(&self.policy_refs));
        }

        let instrumentation = ensure_child_object(
            ensure_child_object(&mut object, TRAILING_KEY),
            INSTRUMENTATION_KEY,
        );
        instrumentation.insert(
            KIND_KEY.to_string(),
            Value::String(self.kind.as_str().to_string()),
        );
        instrumentation.insert(
            ACTION_TYPE_KEY.to_string(),
            Value::String(self.kind.action_type().to_string()),
        );

        if let Some(target) = self.target.as_ref() {
            instrumentation.insert(TARGET_KEY.to_string(), Value::String(target.clone()));
        }

        if !self.policy_refs.is_empty() {
            instrumentation.insert(POLICY_REFS_KEY.to_string(), string_array(&self.policy_refs));
        }

        Value::Object(object)
    }

    pub fn to_attributes(&self) -> Map<String, Value> {
        let mut attributes = Map::new();
        attributes.insert(
            ATTRIBUTE_KIND_KEY.to_string(),
            Value::String(self.kind.as_str().to_string()),
        );
        attributes.insert(
            ATTRIBUTE_ACTION_TYPE_KEY.to_string(),
            Value::String(self.kind.action_type().to_string()),
        );

        if let Some(target) = self.target.as_ref() {
            attributes.insert(TARGET_KEY.to_string(), Value::String(target.clone()));
            attributes.insert(
                ATTRIBUTE_TARGET_KEY.to_string(),
                Value::String(target.clone()),
            );
        }

        if !self.policy_refs.is_empty() {
            let policy_refs = string_array(&self.policy_refs);
            attributes.insert("policy.refs".to_string(), policy_refs.clone());
            attributes.insert(ATTRIBUTE_POLICY_REFS_KEY.to_string(), policy_refs);
        }

        attributes
    }
}

pub fn instrument_write(payload: Value, target: impl Into<String>) -> Value {
    InstrumentationEvent::write(target).apply_to_payload(payload)
}

pub fn instrument_retrieval(payload: Value, target: impl Into<String>) -> Value {
    InstrumentationEvent::retrieval(target).apply_to_payload(payload)
}

pub fn instrument_policy<I, S>(payload: Value, policy_refs: I) -> Value
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    InstrumentationEvent::policy(policy_refs).apply_to_payload(payload)
}

pub fn write_attributes(target: impl Into<String>) -> Map<String, Value> {
    InstrumentationEvent::write(target).to_attributes()
}

pub fn retrieval_attributes(target: impl Into<String>) -> Map<String, Value> {
    InstrumentationEvent::retrieval(target).to_attributes()
}

pub fn policy_attributes<I, S>(policy_refs: I) -> Map<String, Value>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    InstrumentationEvent::policy(policy_refs).to_attributes()
}

#[derive(Debug, Clone, Copy)]
pub struct ActionTypeHints<'a> {
    pub action_name: &'a str,
    pub payload: &'a Value,
    pub tool_name: Option<&'a str>,
    pub target: Option<&'a str>,
    pub has_data_accessed: bool,
}

pub fn resolve_action_type(hints: &ActionTypeHints<'_>) -> ActionType {
    if let Some(action_type) = canonical_action_type(hints.payload) {
        return action_type;
    }

    let action = hints.action_name.to_ascii_lowercase();

    if action.contains("policy") {
        ActionType::PolicyCheck
    } else if action.contains("override")
        || action.contains("approval")
        || action.contains("review")
        || action.contains("human")
        || action.contains("escalat")
        || action.contains("kill")
    {
        ActionType::HumanOverride
    } else if action.contains("write") {
        ActionType::SystemWrite
    } else if action.contains("tool")
        || action.contains("exec")
        || hints.tool_name.is_some()
        || hints.payload.get("tool").is_some()
        || hints.payload.pointer("/action/tool_name").is_some()
        || hints.payload.pointer("/action/toolName").is_some()
    {
        ActionType::ToolCall
    } else if action.contains("read")
        || action.contains("access")
        || hints.target.is_some()
        || hints.payload.get(TARGET_KEY).is_some()
        || hints.payload.get("resource").is_some()
        || hints.payload.pointer("/action/target").is_some()
        || hints.payload.pointer("/context/data_accessed").is_some()
        || hints.payload.pointer("/attributes/data.accessed").is_some()
        || hints.has_data_accessed
    {
        ActionType::DataAccess
    } else {
        ActionType::Decision
    }
}

pub fn canonical_action_type(payload: &Value) -> Option<ActionType> {
    let direct_paths = [
        &[TRAILING_KEY, INSTRUMENTATION_KEY, ACTION_TYPE_KEY][..],
        &[TRAILING_KEY, INSTRUMENTATION_KEY, CANONICAL_ACTION_TYPE_KEY][..],
        &[
            "action",
            "parameters",
            TRAILING_KEY,
            INSTRUMENTATION_KEY,
            ACTION_TYPE_KEY,
        ][..],
        &[
            "action",
            "parameters",
            TRAILING_KEY,
            INSTRUMENTATION_KEY,
            CANONICAL_ACTION_TYPE_KEY,
        ][..],
    ];

    direct_paths
        .iter()
        .find_map(|path| value_at_path(payload, path))
        .and_then(value_to_string)
        .and_then(parse_action_type)
        .or_else(|| {
            instrumentation_container(payload)
                .and_then(|container| find_direct_string(container, ACTION_TYPE_KEY))
                .and_then(parse_action_type)
        })
        .or_else(|| {
            instrumentation_container(payload)
                .and_then(|container| find_direct_string(container, CANONICAL_ACTION_TYPE_KEY))
                .and_then(parse_action_type)
        })
        .or_else(|| {
            find_flat_metadata_string(payload, ATTRIBUTE_ACTION_TYPE_KEY)
                .and_then(parse_action_type)
        })
        .or_else(|| {
            find_flat_metadata_string(payload, ATTRIBUTE_CANONICAL_ACTION_TYPE_KEY)
                .and_then(parse_action_type)
        })
        .or_else(|| {
            direct_paths
                .iter()
                .find_map(|path| {
                    let kind_path = &path[..path.len() - 1];
                    let mut kind_path = kind_path.to_vec();
                    kind_path.push(KIND_KEY);
                    value_at_path(payload, &kind_path)
                })
                .and_then(value_to_string)
                .and_then(parse_action_type)
        })
        .or_else(|| {
            instrumentation_container(payload)
                .and_then(|container| find_direct_string(container, KIND_KEY))
                .and_then(parse_action_type)
        })
        .or_else(|| {
            find_flat_metadata_string(payload, ATTRIBUTE_KIND_KEY).and_then(parse_action_type)
        })
}

fn instrumentation_container(value: &Value) -> Option<&Map<String, Value>> {
    let Value::Object(object) = value else {
        return None;
    };

    object
        .get(TRAILING_KEY)
        .and_then(Value::as_object)
        .and_then(|trailing| trailing.get(INSTRUMENTATION_KEY))
        .and_then(Value::as_object)
}

fn find_flat_metadata_string(value: &Value, key: &str) -> Option<String> {
    let Value::Object(object) = value else {
        return None;
    };

    find_direct_string(object, key)
        .or_else(|| {
            object
                .get("attributes")
                .and_then(Value::as_object)
                .and_then(|attrs| find_direct_string(attrs, key))
        })
        .or_else(|| {
            object
                .get("action")
                .and_then(Value::as_object)
                .and_then(|action| action.get("parameters"))
                .and_then(Value::as_object)
                .and_then(|params| find_direct_string(params, key))
        })
}

fn find_direct_string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(value_to_string)
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
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
        Value::String(raw) => Some(raw.clone()),
        Value::Number(raw) => Some(raw.to_string()),
        _ => None,
    }
}

fn parse_action_type(raw: String) -> Option<ActionType> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "toolcall" | "tool_call" | "tool" => Some(ActionType::ToolCall),
        "systemwrite" | "system_write" | "write" => Some(ActionType::SystemWrite),
        "dataaccess" | "data_access" | "retrieval" | "read" => Some(ActionType::DataAccess),
        "humanoverride" | "human_override" | "human" | "override" => {
            Some(ActionType::HumanOverride)
        }
        "policycheck" | "policy_check" | "policy" => Some(ActionType::PolicyCheck),
        "decision" => Some(ActionType::Decision),
        _ => None,
    }
}

fn ensure_child_object<'a>(
    object: &'a mut Map<String, Value>,
    key: &str,
) -> &'a mut Map<String, Value> {
    let entry = object
        .entry(key.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !entry.is_object() {
        *entry = Value::Object(Map::new());
    }
    entry
        .as_object_mut()
        .expect("object entry should be an object after initialization")
}

fn string_array(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        ActionTypeHints, InstrumentationEvent, canonical_action_type, instrument_policy,
        instrument_retrieval, resolve_action_type, write_attributes,
    };
    use crate::log::ActionType;

    #[test]
    fn payload_helpers_embed_canonical_metadata() {
        let payload = InstrumentationEvent::write("sqlite://ledger")
            .apply_to_payload(json!({ "name": "db.flush" }));

        assert_eq!(payload["target"], json!("sqlite://ledger"));
        assert_eq!(
            payload["trailing"]["instrumentation"]["kind"],
            json!("write")
        );
        assert_eq!(
            payload["trailing"]["instrumentation"]["action_type"],
            json!("SystemWrite")
        );
    }

    #[test]
    fn policy_helper_adds_policy_refs() {
        let payload = instrument_policy(
            json!({ "name": "audit.governance" }),
            ["hipaa", "eu-ai-act"],
        );

        assert_eq!(payload["policy_refs"], json!(["hipaa", "eu-ai-act"]));
        assert_eq!(
            payload["trailing"]["instrumentation"]["policy_refs"],
            json!(["hipaa", "eu-ai-act"])
        );
    }

    #[test]
    fn canonical_metadata_overrides_heuristics() {
        let payload = instrument_retrieval(json!({ "name": "policy.review" }), "memory://cache");

        let action_type = resolve_action_type(&ActionTypeHints {
            action_name: "policy.review",
            payload: &payload,
            tool_name: None,
            target: payload.get("target").and_then(Value::as_str),
            has_data_accessed: false,
        });

        assert_eq!(action_type, ActionType::DataAccess);
    }

    #[test]
    fn canonical_action_type_is_available_in_otlp_attributes() {
        let attributes = Value::Object(write_attributes("file:///tmp/report.json"));

        assert_eq!(
            canonical_action_type(&attributes),
            Some(ActionType::SystemWrite)
        );
    }
}
