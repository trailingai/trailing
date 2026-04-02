use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SdkEvent {
    pub agent_id: String,
    pub agent_type: String,
    pub session_id: String,
    pub action: SdkAction,
    pub context: SdkContext,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SdkAction {
    pub action_type: String,
    pub tool_name: Option<String>,
    pub target: Option<String>,
    #[serde(default)]
    pub parameters: Value,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SdkContext {
    #[serde(default)]
    pub data_accessed: Vec<String>,
    #[serde(default)]
    pub permissions_used: Vec<String>,
    #[serde(default)]
    pub policy_refs: Vec<String>,
}
