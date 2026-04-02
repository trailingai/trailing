use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::time::sleep;

use crate::{
    ingest::ingest_json_action,
    storage::{Storage, StorageError},
};

type Result<T> = std::result::Result<T, WatcherError>;

#[derive(Debug)]
pub enum WatcherError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Storage(StorageError),
}

impl Display for WatcherError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::Storage(error) => write!(f, "storage error: {error}"),
        }
    }
}

impl std::error::Error for WatcherError {}

impl From<std::io::Error> for WatcherError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for WatcherError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<StorageError> for WatcherError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchTarget {
    pub dir: PathBuf,
    pub agent_type: String,
}

#[derive(Debug, Clone)]
pub struct WatchConfig {
    pub db_path: String,
    pub targets: Vec<WatchTarget>,
    pub recursive: bool,
    pub poll_interval: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedAction {
    pub offset: u64,
    pub block_index: usize,
    pub payload: Value,
    pub dedup_seed: Option<String>,
}

#[derive(Debug, Clone)]
struct ClaudeDocument {
    root: Option<Value>,
    rows: Vec<(u64, Value)>,
}

#[derive(Debug, Clone)]
struct ClaudeHookContext {
    hook_path: String,
    hook_event_name: Option<String>,
    hook_reason: Option<String>,
    cwd: Option<String>,
}

#[derive(Debug, Clone)]
struct ClaudeToolResult {
    result: Value,
    is_error: bool,
}

#[derive(Debug, Clone)]
struct CursorDocument {
    root: Option<Value>,
    rows: Vec<(u64, Value)>,
}

#[derive(Debug, Clone)]
struct CursorToolCall {
    tool_name: String,
    parameters: Value,
}

pub async fn run(config: WatchConfig) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::open(&config.db_path)?;

    loop {
        for target in &config.targets {
            if let Err(error) = scan_target(&storage, target, config.recursive) {
                eprintln!(
                    "watch scan failed for {} ({}): {error}",
                    target.dir.display(),
                    target.agent_type
                );
            }
        }
        sleep(config.poll_interval).await;
    }
}

fn scan_target(storage: &Storage, target: &WatchTarget, recursive: bool) -> Result<()> {
    let mut files = Vec::new();
    collect_files(&target.dir, recursive, &mut files)?;

    for file in files {
        if !supports_file(&file, &target.agent_type) {
            continue;
        }

        let actions = match parse_actions_from_path(&file, &target.agent_type) {
            Ok(actions) => actions,
            Err(error) => {
                eprintln!("failed to parse {}: {error}", file.display());
                continue;
            }
        };

        for action in actions {
            let dedup_key = dedup_key_for_action(&file, &action);
            if let Err(error) = ingest_json_action(
                storage,
                action.payload,
                &format!("watcher:{}", target.agent_type),
                Some(&dedup_key),
            ) {
                eprintln!("failed to ingest {}: {error}", file.display());
            }
        }
    }

    Ok(())
}

pub fn parse_actions_from_path(path: &Path, agent_type: &str) -> Result<Vec<ParsedAction>> {
    let content = fs::read_to_string(path)?;
    parse_actions(path, agent_type, &content)
}

pub fn parse_actions(path: &Path, agent_type: &str, content: &str) -> Result<Vec<ParsedAction>> {
    let normalized = agent_type.trim().to_ascii_lowercase();
    if normalized.contains("claude") {
        parse_claude_source(path, content)
    } else if normalized.contains("codex") {
        parse_codex_rollout(path, content)
    } else if normalized.contains("cursor") {
        parse_cursor_source(path, content)
    } else {
        Ok(Vec::new())
    }
}

fn parse_claude_source(path: &Path, content: &str) -> Result<Vec<ParsedAction>> {
    if let Some(actions) = parse_claude_hook_capture(path, content)? {
        return Ok(actions);
    }

    parse_claude_transcript(path, content)
}

pub fn parse_claude_transcript(path: &Path, content: &str) -> Result<Vec<ParsedAction>> {
    parse_claude_transcript_with_context(path, content, None)
}

fn parse_claude_transcript_with_context(
    path: &Path,
    content: &str,
    hook_context: Option<&ClaudeHookContext>,
) -> Result<Vec<ParsedAction>> {
    let document = parse_claude_document(content)?;
    let mut tool_names = HashMap::new();
    let mut tool_results = HashMap::new();

    for (_, item) in &document.rows {
        collect_claude_tool_metadata(item, &mut tool_names, &mut tool_results);
    }

    let mut actions = Vec::new();
    for (offset, item) in document.rows {
        let session_id = resolve_string_paths(
            &item,
            &[
                &["session_id"],
                &["sessionId"],
                &["message", "session_id"],
                &["message", "sessionId"],
            ],
        )
        .or_else(|| {
            document
                .root
                .as_ref()
                .and_then(|root| resolve_string_paths(root, &[&["session_id"], &["sessionId"]]))
        })
        .unwrap_or_else(|| "unknown-session".to_string());
        let agent_id = resolve_string_paths(
            &item,
            &[
                &["agent_id"],
                &["agentId"],
                &["agent"],
                &["message", "agent_id"],
                &["message", "agentId"],
            ],
        )
        .or_else(|| {
            document.root.as_ref().and_then(|root| {
                resolve_string_paths(root, &[&["agent_id"], &["agentId"], &["agent"]])
            })
        })
        .unwrap_or_else(|| "claude".to_string());
        let timestamp = resolve_string_paths(
            &item,
            &[
                &["timestamp"],
                &["created_at"],
                &["createdAt"],
                &["message", "timestamp"],
                &["message", "created_at"],
                &["message", "createdAt"],
            ],
        )
        .unwrap_or_default();
        let record_uuid = resolve_string_paths(
            &item,
            &[&["uuid"], &["id"], &["message", "uuid"], &["message", "id"]],
        )
        .unwrap_or_default();
        let message = message_object(&item).unwrap_or(&item);
        let role = resolve_string_paths(message, &[&["role"]])
            .or_else(|| resolve_string_paths(&item, &[&["role"], &["type"]]))
            .unwrap_or_else(|| "unknown".to_string());
        let model = resolve_string_paths(message, &[&["model"], &["model_name"]]);
        let stop_reason = resolve_string_paths(message, &[&["stop_reason"]]);
        let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
        let content_blocks = content_array(message);
        let content_is_text = message
            .get("content")
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .map(str::to_string);

        if role == "assistant"
            && content_blocks.is_none()
            && let Some(text) = content_is_text
        {
            push_action(
                &mut actions,
                offset,
                0,
                json!({
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "agent_type": "claude",
                    "timestamp": timestamp,
                    "action": {
                        "type": "assistant_response",
                        "parameters": {
                            "text": text,
                            "model": model,
                            "stop_reason": stop_reason,
                        }
                    },
                    "context": claude_context(
                        path,
                        &role,
                        &record_uuid,
                        Some("text"),
                        hook_context,
                        &[],
                    ),
                }),
            );
        }

        if is_reasoning_item(&item)
            && let Some(reasoning) = extract_reasoning_text(&item)
        {
            push_action(
                &mut actions,
                offset,
                0,
                json!({
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "agent_type": "claude",
                    "timestamp": timestamp,
                    "action": {
                        "type": "reasoning",
                        "parameters": {
                            "reasoning": reasoning,
                        }
                    },
                    "context": claude_context(
                        path,
                        &role,
                        &record_uuid,
                        Some(item_type),
                        hook_context,
                        &[],
                    ),
                }),
            );
        }

        if let Some(content_blocks) = content_blocks {
            for (block_index, block) in content_blocks.iter().enumerate() {
                let block_type = block
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                match block_type {
                    "text" if role == "assistant" => {
                        let text = block
                            .get("text")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        if text.is_empty() {
                            continue;
                        }
                        push_action(
                            &mut actions,
                            offset,
                            block_index,
                            json!({
                                "session_id": session_id,
                                "agent_id": agent_id,
                                "agent_type": "claude",
                                "timestamp": timestamp,
                                "action": {
                                    "type": "assistant_response",
                                    "parameters": {
                                        "text": text,
                                        "model": model,
                                        "stop_reason": stop_reason,
                                    }
                                },
                                "context": claude_context(
                                    path,
                                    &role,
                                    &record_uuid,
                                    Some(block_type),
                                    hook_context,
                                    &[],
                                ),
                            }),
                        );
                    }
                    "thinking" | "reasoning" | "redacted_thinking" => {
                        if let Some(reasoning) = extract_reasoning_text(block) {
                            push_action(
                                &mut actions,
                                offset,
                                block_index,
                                json!({
                                    "session_id": session_id,
                                    "agent_id": agent_id,
                                    "agent_type": "claude",
                                    "timestamp": timestamp,
                                    "action": {
                                        "type": "reasoning",
                                        "parameters": {
                                            "reasoning": reasoning,
                                            "model": model,
                                        }
                                    },
                                    "context": claude_context(
                                        path,
                                        &role,
                                        &record_uuid,
                                        Some(block_type),
                                        hook_context,
                                        &[],
                                    ),
                                }),
                            );
                        }
                    }
                    "tool_use" => {
                        let tool_use_id = resolve_string_paths(
                            block,
                            &[&["id"], &["tool_use_id"], &["toolUseId"]],
                        )
                        .unwrap_or_else(|| format!("tool-{offset}-{block_index}"));
                        let tool_name = resolve_string_paths(block, &[&["name"]])
                            .unwrap_or_else(|| "unknown-tool".to_string());
                        let input = block.get("input").cloned().unwrap_or(Value::Null);
                        let result = tool_results.get(&tool_use_id);

                        push_action(
                            &mut actions,
                            offset,
                            block_index,
                            json!({
                                "session_id": session_id,
                                "agent_id": agent_id,
                                "agent_type": "claude",
                                "timestamp": timestamp,
                                "action": {
                                    "type": "tool_call",
                                    "tool_name": tool_name,
                                    "target": extract_target(&input),
                                    "parameters": input,
                                },
                                "context": claude_context(
                                    path,
                                    &role,
                                    &record_uuid,
                                    Some(block_type),
                                    hook_context,
                                    &[("tool_use_id", Value::String(tool_use_id.clone()))],
                                ),
                            }),
                        );

                        if let Some(file_action_type) = file_action_type(&tool_name) {
                            let status = result
                                .map(|entry| if entry.is_error { "error" } else { "ok" })
                                .unwrap_or("ok");
                            let file_result = result.map(|entry| entry.result.clone());
                            push_action(
                                &mut actions,
                                offset,
                                block_index + 10_000,
                                json!({
                                    "session_id": session_id,
                                    "agent_id": agent_id,
                                    "agent_type": "claude",
                                    "timestamp": timestamp,
                                    "status": status,
                                    "action": {
                                        "type": file_action_type,
                                        "tool_name": tool_name,
                                        "target": extract_target(&input),
                                        "parameters": input,
                                        "result": file_result,
                                    },
                                    "context": claude_context(
                                        path,
                                        &role,
                                        &record_uuid,
                                        Some(block_type),
                                        hook_context,
                                        &[
                                            ("tool_use_id", Value::String(tool_use_id)),
                                            (
                                                "derived_from",
                                                Value::String("tool_use".to_string()),
                                            ),
                                        ],
                                    ),
                                }),
                            );
                        }
                    }
                    "tool_result" => {
                        let tool_use_id = resolve_string_paths(
                            block,
                            &[&["tool_use_id"], &["id"], &["toolUseId"]],
                        )
                        .unwrap_or_default();
                        let result = block
                            .get("content")
                            .cloned()
                            .or_else(|| item.get("toolUseResult").cloned())
                            .unwrap_or(Value::Null);
                        let is_error = block
                            .get("is_error")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        push_action(
                            &mut actions,
                            offset,
                            block_index,
                            json!({
                                "session_id": session_id,
                                "agent_id": agent_id,
                                "agent_type": "claude",
                                "timestamp": timestamp,
                                "status": if is_error { "error" } else { "ok" },
                                "action": {
                                    "type": "tool_result",
                                    "tool_name": tool_names.get(&tool_use_id).cloned(),
                                    "parameters": {
                                        "tool_use_id": tool_use_id,
                                        "is_error": is_error,
                                    },
                                    "result": result,
                                },
                                "context": claude_context(
                                    path,
                                    &role,
                                    &record_uuid,
                                    Some(block_type),
                                    hook_context,
                                    &[],
                                ),
                            }),
                        );
                    }
                    _ => {}
                }
            }
        } else {
            match item_type {
                "tool_use" => {
                    let tool_use_id =
                        resolve_string_paths(&item, &[&["id"], &["tool_use_id"], &["toolUseId"]])
                            .unwrap_or_else(|| format!("tool-{offset}"));
                    let tool_name = resolve_string_paths(&item, &[&["name"], &["tool_name"]])
                        .unwrap_or_else(|| "unknown-tool".to_string());
                    let input = item
                        .get("input")
                        .cloned()
                        .or_else(|| item.get("tool_input").cloned())
                        .unwrap_or(Value::Null);
                    let result = tool_results.get(&tool_use_id);

                    push_action(
                        &mut actions,
                        offset,
                        0,
                        json!({
                            "session_id": session_id,
                            "agent_id": agent_id,
                            "agent_type": "claude",
                            "timestamp": timestamp,
                            "action": {
                                "type": "tool_call",
                                "tool_name": tool_name,
                                "target": extract_target(&input),
                                "parameters": input,
                            },
                            "context": claude_context(
                                path,
                                &role,
                                &record_uuid,
                                Some(item_type),
                                hook_context,
                                &[("tool_use_id", Value::String(tool_use_id.clone()))],
                            ),
                        }),
                    );

                    if let Some(file_action_type) = file_action_type(&tool_name) {
                        push_action(
                            &mut actions,
                            offset,
                            10_000,
                            json!({
                                "session_id": session_id,
                                "agent_id": agent_id,
                                "agent_type": "claude",
                                "timestamp": timestamp,
                                "status": result.map(|entry| if entry.is_error { "error" } else { "ok" }).unwrap_or("ok"),
                                "action": {
                                    "type": file_action_type,
                                    "tool_name": tool_name,
                                    "target": extract_target(&input),
                                    "parameters": input,
                                    "result": result.map(|entry| entry.result.clone()),
                                },
                                "context": claude_context(
                                    path,
                                    &role,
                                    &record_uuid,
                                    Some(item_type),
                                    hook_context,
                                    &[
                                        ("tool_use_id", Value::String(tool_use_id)),
                                        (
                                            "derived_from",
                                            Value::String("tool_use".to_string()),
                                        ),
                                    ],
                                ),
                            }),
                        );
                    }
                }
                "tool_result" => {
                    let tool_use_id =
                        resolve_string_paths(&item, &[&["tool_use_id"], &["id"], &["toolUseId"]])
                            .unwrap_or_default();
                    let is_error = item
                        .get("is_error")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    push_action(
                        &mut actions,
                        offset,
                        0,
                        json!({
                            "session_id": session_id,
                            "agent_id": agent_id,
                            "agent_type": "claude",
                            "timestamp": timestamp,
                            "status": if is_error { "error" } else { "ok" },
                            "action": {
                                "type": "tool_result",
                                "tool_name": tool_names.get(&tool_use_id).cloned(),
                                "parameters": {
                                    "tool_use_id": tool_use_id,
                                    "is_error": is_error,
                                },
                                "result": item.get("content").cloned().or_else(|| item.get("tool_response").cloned()).unwrap_or(Value::Null),
                            },
                            "context": claude_context(
                                path,
                                &role,
                                &record_uuid,
                                Some(item_type),
                                hook_context,
                                &[],
                            ),
                        }),
                    );
                }
                "assistant" if role == "assistant" => {
                    if let Some(text) = extract_text_field(&item) {
                        push_action(
                            &mut actions,
                            offset,
                            0,
                            json!({
                                "session_id": session_id,
                                "agent_id": agent_id,
                                "agent_type": "claude",
                                "timestamp": timestamp,
                                "action": {
                                    "type": "assistant_response",
                                    "parameters": {
                                        "text": text,
                                        "model": model,
                                        "stop_reason": stop_reason,
                                    }
                                },
                                "context": claude_context(
                                    path,
                                    &role,
                                    &record_uuid,
                                    Some(item_type),
                                    hook_context,
                                    &[],
                                ),
                            }),
                        );
                    }
                }
                _ => {}
            }
        }
    }

    Ok(actions)
}

fn parse_claude_hook_capture(path: &Path, content: &str) -> Result<Option<Vec<ParsedAction>>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let value = match serde_json::from_str::<Value>(trimmed) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    if !is_claude_hook_payload(&value) {
        return Ok(None);
    }

    let transcript_path = value
        .get("transcript_path")
        .and_then(Value::as_str)
        .filter(|candidate| !candidate.trim().is_empty())
        .map(|candidate| resolve_hook_transcript_path(path, candidate));
    let Some(transcript_path) = transcript_path else {
        return Ok(Some(Vec::new()));
    };

    let hook_context = ClaudeHookContext {
        hook_path: path.display().to_string(),
        hook_event_name: resolve_string_paths(&value, &[&["hook_event_name"], &["hook_event"]]),
        hook_reason: resolve_string_paths(&value, &[&["reason"], &["hook_reason"]]),
        cwd: resolve_string_paths(&value, &[&["cwd"]]),
    };
    let transcript_content = fs::read_to_string(&transcript_path)?;

    Ok(Some(parse_claude_transcript_with_context(
        &transcript_path,
        &transcript_content,
        Some(&hook_context),
    )?))
}

fn parse_claude_document(content: &str) -> Result<ClaudeDocument> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(ClaudeDocument {
            root: None,
            rows: Vec::new(),
        });
    }

    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Ok(value) = serde_json::from_str::<Value>(trimmed)
    {
        if let Some(items) = value.as_array() {
            return Ok(ClaudeDocument {
                root: None,
                rows: items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| (index as u64, item.clone()))
                    .collect(),
            });
        }

        if let Some(object) = value.as_object() {
            let mut rows = Vec::new();
            for key in ["messages", "events", "conversation"] {
                if let Some(items) = object.get(key).and_then(Value::as_array) {
                    rows.extend(
                        items
                            .iter()
                            .enumerate()
                            .map(|(index, item)| (index as u64, item.clone())),
                    );
                }
            }

            if rows.is_empty() {
                rows.push((0, value.clone()));
            }

            return Ok(ClaudeDocument {
                root: Some(Value::Object(object.clone())),
                rows,
            });
        }

        return Ok(ClaudeDocument {
            root: None,
            rows: vec![(0, value)],
        });
    }

    Ok(ClaudeDocument {
        root: None,
        rows: parse_records_with_offsets(content)?,
    })
}

fn collect_claude_tool_metadata(
    item: &Value,
    tool_names: &mut HashMap<String, String>,
    tool_results: &mut HashMap<String, ClaudeToolResult>,
) {
    let message = message_object(item).unwrap_or(item);

    if let Some(content_blocks) = content_array(message) {
        for block in content_blocks {
            match block
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
            {
                "tool_use" => {
                    if let Some(tool_use_id) =
                        resolve_string_paths(block, &[&["id"], &["tool_use_id"], &["toolUseId"]])
                    {
                        let tool_name = resolve_string_paths(block, &[&["name"]])
                            .unwrap_or_else(|| "unknown-tool".to_string());
                        tool_names.insert(tool_use_id, tool_name);
                    }
                }
                "tool_result" => {
                    if let Some(tool_use_id) =
                        resolve_string_paths(block, &[&["tool_use_id"], &["id"], &["toolUseId"]])
                    {
                        tool_results.insert(
                            tool_use_id,
                            ClaudeToolResult {
                                result: block.get("content").cloned().unwrap_or(Value::Null),
                                is_error: block
                                    .get("is_error")
                                    .and_then(Value::as_bool)
                                    .unwrap_or(false),
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }

    match item.get("type").and_then(Value::as_str).unwrap_or_default() {
        "tool_use" => {
            if let Some(tool_use_id) =
                resolve_string_paths(item, &[&["id"], &["tool_use_id"], &["toolUseId"]])
            {
                let tool_name = resolve_string_paths(item, &[&["name"], &["tool_name"]])
                    .unwrap_or_else(|| "unknown-tool".to_string());
                tool_names.insert(tool_use_id, tool_name);
            }
        }
        "tool_result" => {
            if let Some(tool_use_id) =
                resolve_string_paths(item, &[&["tool_use_id"], &["id"], &["toolUseId"]])
            {
                tool_results.insert(
                    tool_use_id,
                    ClaudeToolResult {
                        result: item
                            .get("content")
                            .cloned()
                            .or_else(|| item.get("tool_response").cloned())
                            .unwrap_or(Value::Null),
                        is_error: item
                            .get("is_error")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    },
                );
            }
        }
        _ => {}
    }
}

fn parse_codex_rollout(path: &Path, content: &str) -> Result<Vec<ParsedAction>> {
    let rows = parse_records_with_offsets(content)?;
    let mut session_id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("unknown-session")
        .to_string();
    let mut call_names = HashMap::new();

    for (_, item) in &rows {
        if item.get("type").and_then(Value::as_str) == Some("session_meta")
            && let Some(id) = item
                .pointer("/payload/id")
                .and_then(Value::as_str)
                .map(str::to_string)
        {
            session_id = id;
        }

        if item.get("type").and_then(Value::as_str) == Some("response_item")
            && item.pointer("/payload/type").and_then(Value::as_str) == Some("function_call")
            && let (Some(call_id), Some(name)) = (
                item.pointer("/payload/call_id").and_then(Value::as_str),
                item.pointer("/payload/name").and_then(Value::as_str),
            )
        {
            call_names.insert(call_id.to_string(), name.to_string());
        }
    }

    let mut actions = Vec::new();
    for (offset, item) in rows {
        let timestamp = item
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();

        match item_type {
            "event_msg"
                if item.pointer("/payload/type").and_then(Value::as_str)
                    == Some("agent_reasoning") =>
            {
                let text = item
                    .pointer("/payload/text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if text.is_empty() {
                    continue;
                }
                push_action(
                    &mut actions,
                    offset,
                    0,
                    json!({
                        "session_id": session_id,
                        "agent_id": "codex-cli",
                        "agent_type": "codex",
                        "timestamp": timestamp,
                        "action": {
                            "type": "decision",
                            "parameters": {
                                "reasoning": text,
                            }
                        },
                        "context": {
                            "rollout_path": path.display().to_string(),
                            "event_type": "agent_reasoning",
                        }
                    }),
                );
            }
            "response_item" => {
                let payload_type = item.pointer("/payload/type").and_then(Value::as_str);
                match payload_type {
                    Some("function_call") => {
                        let name = item
                            .pointer("/payload/name")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown-tool");
                        let arguments = item
                            .pointer("/payload/arguments")
                            .and_then(Value::as_str)
                            .map(parse_jsonish_string)
                            .unwrap_or(Value::Null);
                        push_action(
                            &mut actions,
                            offset,
                            0,
                            json!({
                                "session_id": session_id,
                                "agent_id": "codex-cli",
                                "agent_type": "codex",
                                "timestamp": timestamp,
                                "action": {
                                    "type": "tool_call",
                                    "tool_name": name,
                                    "target": extract_target(&arguments),
                                    "parameters": arguments,
                                },
                                "context": {
                                    "rollout_path": path.display().to_string(),
                                    "call_id": item.pointer("/payload/call_id").cloned(),
                                    "payload_type": payload_type,
                                }
                            }),
                        );
                    }
                    Some("function_call_output") => {
                        let call_id = item
                            .pointer("/payload/call_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        let output = item
                            .pointer("/payload/output")
                            .and_then(Value::as_str)
                            .map(parse_jsonish_string)
                            .unwrap_or(Value::Null);
                        push_action(
                            &mut actions,
                            offset,
                            0,
                            json!({
                                "session_id": session_id,
                                "agent_id": "codex-cli",
                                "agent_type": "codex",
                                "timestamp": timestamp,
                                "action": {
                                    "type": "tool_result",
                                    "tool_name": call_names.get(&call_id).cloned(),
                                    "parameters": {
                                        "call_id": call_id,
                                    },
                                    "result": output,
                                },
                                "context": {
                                    "rollout_path": path.display().to_string(),
                                    "payload_type": payload_type,
                                }
                            }),
                        );
                    }
                    Some("message")
                        if item.pointer("/payload/role").and_then(Value::as_str)
                            == Some("assistant") =>
                    {
                        let text = extract_codex_message_text(
                            item.pointer("/payload/content").unwrap_or(&Value::Null),
                        );
                        if text.is_empty() {
                            continue;
                        }
                        push_action(
                            &mut actions,
                            offset,
                            0,
                            json!({
                                "session_id": session_id,
                                "agent_id": "codex-cli",
                                "agent_type": "codex",
                                "timestamp": timestamp,
                                "action": {
                                    "type": "assistant_response",
                                    "parameters": {
                                        "text": text,
                                    }
                                },
                                "context": {
                                    "rollout_path": path.display().to_string(),
                                    "payload_type": payload_type,
                                }
                            }),
                        );
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    Ok(actions)
}

fn parse_cursor_source(path: &Path, content: &str) -> Result<Vec<ParsedAction>> {
    let document = parse_cursor_document(content)?;
    let default_session_id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("cursor-session")
        .to_string();
    let root = document.root.as_ref();
    let default_agent_id = resolve_string_paths(
        root.unwrap_or(&Value::Null),
        &[
            &["agent_id"],
            &["agentId"],
            &["agent"],
            &["composerId"],
            &["composer_id"],
        ],
    )
    .unwrap_or_else(|| "cursor-composer".to_string());

    let mut tool_calls = HashMap::new();
    for (_, item) in &document.rows {
        let merged = merge_cursor_payload(item);
        let event_name = cursor_event_name(&merged);
        if event_name.as_deref().is_some_and(is_cursor_tool_call_event)
            && let Some(call_id) = resolve_string_paths(
                &merged,
                &[&["call_id"], &["callId"], &["run_id"], &["runId"], &["id"]],
            ) {
                let parameters = merged
                    .get("input")
                    .cloned()
                    .or_else(|| merged.get("arguments").cloned())
                    .unwrap_or(Value::Null);
                let tool_name = resolve_string_paths(&merged, &[&["tool_name"], &["action"]])
                    .unwrap_or_else(|| "tool".to_string());
                tool_calls.insert(
                    call_id,
                    CursorToolCall {
                        tool_name,
                        parameters,
                    },
                );
            }
    }

    let mut actions = Vec::new();
    for (offset, item) in document.rows {
        let merged = merge_cursor_payload(&item);
        let timestamp = resolve_string_paths(
            &merged,
            &[
                &["timestamp"],
                &["created_at"],
                &["createdAt"],
                &["ts"],
                &["time"],
            ],
        )
        .unwrap_or_default();
        let session_id = resolve_string_paths(
            &merged,
            &[
                &["session_id"],
                &["sessionId"],
                &["composer_id"],
                &["composerId"],
                &["conversation_id"],
                &["conversationId"],
            ],
        )
        .or_else(|| {
            root.and_then(|root| {
                resolve_string_paths(
                    root,
                    &[
                        &["session_id"],
                        &["sessionId"],
                        &["composer_id"],
                        &["composerId"],
                        &["conversation_id"],
                        &["conversationId"],
                    ],
                )
            })
        })
        .unwrap_or_else(|| default_session_id.clone());
        let agent_id = resolve_string_paths(
            &merged,
            &[
                &["agent_id"],
                &["agentId"],
                &["agent"],
                &["composerId"],
                &["composer_id"],
            ],
        )
        .unwrap_or_else(|| default_agent_id.clone());
        let role = resolve_string_paths(&merged, &[&["role"]]);
        let event_name = cursor_event_name(&merged);
        let phase = cursor_phase(&merged);

        if event_name.as_deref() == Some("composer")
            && phase
                .as_deref()
                .is_some_and(|value| matches!(value, "start" | "request"))
        {
            push_action(
                &mut actions,
                offset,
                0,
                json!({
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "agent_type": "cursor",
                    "timestamp": timestamp,
                    "action": {
                        "type": "session_start",
                        "target": resolve_string_paths(&merged, &[&["workspace"]]).unwrap_or_else(|| "cursor-composer".to_string()),
                        "parameters": {
                            "prompt": merged.get("prompt").cloned(),
                            "workspace": merged.get("workspace").cloned(),
                        }
                    },
                    "context": cursor_context(path, role.as_deref(), event_name.as_deref(), phase.as_deref(), &[]),
                }),
            );
            continue;
        }

        if event_name.as_deref() == Some("composer")
            && phase
                .as_deref()
                .is_some_and(|value| matches!(value, "end" | "stop" | "complete"))
        {
            push_action(
                &mut actions,
                offset,
                0,
                json!({
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "agent_type": "cursor",
                    "timestamp": timestamp,
                    "action": {
                        "type": "session_end",
                        "target": "cursor-composer",
                        "parameters": {},
                        "result": {
                            "summary": merged.get("summary").cloned(),
                        }
                    },
                    "context": cursor_context(path, role.as_deref(), event_name.as_deref(), phase.as_deref(), &[]),
                }),
            );
            continue;
        }

        if event_name.as_deref().is_some_and(is_cursor_tool_call_event) {
            let parameters = merged
                .get("input")
                .cloned()
                .or_else(|| merged.get("arguments").cloned())
                .unwrap_or(Value::Null);
            let tool_name = resolve_string_paths(&merged, &[&["tool_name"], &["action"]])
                .unwrap_or_else(|| "tool".to_string());
            let call_id = resolve_string_paths(
                &merged,
                &[&["call_id"], &["callId"], &["run_id"], &["runId"], &["id"]],
            );

            push_action(
                &mut actions,
                offset,
                0,
                json!({
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "agent_type": "cursor",
                    "timestamp": timestamp,
                    "action": {
                        "type": "tool_call",
                        "tool_name": tool_name,
                        "target": extract_target(&parameters),
                        "parameters": parameters,
                    },
                    "context": cursor_context(
                        path,
                        role.as_deref(),
                        event_name.as_deref(),
                        phase.as_deref(),
                        &[("call_id", call_id.map(Value::String).unwrap_or(Value::Null))],
                    ),
                }),
            );
            continue;
        }

        if event_name
            .as_deref()
            .is_some_and(is_cursor_tool_result_event)
        {
            let call_id = resolve_string_paths(
                &merged,
                &[&["call_id"], &["callId"], &["run_id"], &["runId"], &["id"]],
            )
            .unwrap_or_default();
            let cached = tool_calls.get(&call_id);
            let result = merged
                .get("output")
                .cloned()
                .or_else(|| merged.get("result").cloned())
                .unwrap_or(Value::Null);
            let status = resolve_string_paths(&merged, &[&["status"], &["state"]])
                .unwrap_or_else(|| "ok".to_string());

            push_action(
                &mut actions,
                offset,
                0,
                json!({
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "agent_type": "cursor",
                    "timestamp": timestamp,
                    "status": status,
                    "action": {
                        "type": "tool_result",
                        "tool_name": cached.map(|entry| entry.tool_name.clone()),
                        "parameters": {
                            "call_id": call_id,
                            "input": cached.map(|entry| entry.parameters.clone()),
                        },
                        "result": result,
                    },
                    "context": cursor_context(
                        path,
                        role.as_deref(),
                        event_name.as_deref(),
                        phase.as_deref(),
                        &[],
                    ),
                }),
            );
            continue;
        }

        if event_name.as_deref().is_some_and(is_cursor_file_event) {
            let target = resolve_string_paths(&merged, &[&["path"], &["target"]])
                .unwrap_or_else(|| "file".to_string());
            push_action(
                &mut actions,
                offset,
                0,
                json!({
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "agent_type": "cursor",
                    "timestamp": timestamp,
                    "action": {
                        "type": "file_write",
                        "tool_name": "filesystem",
                        "target": target,
                        "parameters": {
                            "path": merged.get("path").cloned().or_else(|| merged.get("target").cloned()),
                            "operation": merged.get("operation").cloned().unwrap_or_else(|| Value::String("write".to_string())),
                            "content": merged.get("content").cloned().or_else(|| merged.get("diff").cloned()),
                        },
                        "result": {
                            "written": true
                        }
                    },
                    "context": cursor_context(path, role.as_deref(), event_name.as_deref(), phase.as_deref(), &[]),
                }),
            );
            continue;
        }

        if event_name.as_deref() == Some("approval") {
            push_action(
                &mut actions,
                offset,
                0,
                json!({
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "agent_type": "cursor",
                    "timestamp": timestamp,
                    "action": {
                        "type": "human_in_the_loop",
                        "target": resolve_string_paths(&merged, &[&["target"], &["actor"], &["approver"]]).unwrap_or_else(|| "approval".to_string()),
                        "parameters": {
                            "actor": merged.get("actor").cloned().or_else(|| merged.get("approver").cloned()),
                            "request": merged.get("request").cloned().or_else(|| merged.get("prompt").cloned()),
                        },
                        "result": {
                            "response": merged.get("response").cloned().or_else(|| merged.get("decision").cloned()),
                            "approved": merged.get("approved").cloned(),
                        }
                    },
                    "context": cursor_context(
                        path,
                        role.as_deref(),
                        event_name.as_deref(),
                        phase.as_deref(),
                        &[(
                            "permissions_used",
                            Value::Array(vec![Value::String("human-oversight".to_string())]),
                        )],
                    ),
                }),
            );
            continue;
        }

        if role.as_deref() == Some("assistant")
            && let Some(text) = extract_cursor_message_text(&merged)
        {
            push_action(
                &mut actions,
                offset,
                0,
                json!({
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "agent_type": "cursor",
                    "timestamp": timestamp,
                    "action": {
                        "type": "assistant_response",
                        "parameters": {
                            "text": text,
                            "model": merged.get("model").cloned().or_else(|| merged.get("model_name").cloned()),
                        }
                    },
                    "context": cursor_context(path, role.as_deref(), event_name.as_deref(), phase.as_deref(), &[]),
                }),
            );
            continue;
        }

        if let Some(event_name) = event_name {
            push_action(
                &mut actions,
                offset,
                0,
                json!({
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "agent_type": "cursor",
                    "timestamp": timestamp,
                    "action": {
                        "type": "decision",
                        "target": event_name,
                        "parameters": {
                            "event": merged,
                        }
                    },
                    "context": cursor_context(path, role.as_deref(), Some(&event_name), phase.as_deref(), &[]),
                }),
            );
        }
    }

    Ok(actions)
}

fn parse_records_with_offsets(content: &str) -> Result<Vec<(u64, Value)>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Ok(value) = serde_json::from_str::<Value>(trimmed)
    {
        if let Some(items) = value.as_array() {
            return Ok(items
                .iter()
                .enumerate()
                .map(|(index, item)| (index as u64, item.clone()))
                .collect());
        }
        return Ok(vec![(0, value)]);
    }

    let mut offset = 0u64;
    let mut rows = Vec::new();
    for raw_line in content.split_inclusive('\n') {
        let trimmed_line = raw_line.trim();
        let line_offset = offset;
        offset += raw_line.len() as u64;
        if trimmed_line.is_empty() {
            continue;
        }
        rows.push((line_offset, serde_json::from_str(trimmed_line)?));
    }

    if !content.ends_with('\n') {
        let last_line = content.lines().last().unwrap_or_default().trim();
        if !last_line.is_empty()
            && rows.last().is_none_or(|(_, value)| {
                serde_json::to_string(value).ok().as_deref() != Some(last_line)
            })
        {
            rows.push((offset, serde_json::from_str(last_line)?));
        }
    }

    Ok(rows)
}

fn collect_files(dir: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                collect_files(&path, true, out)?;
            }
            continue;
        }
        out.push(path);
    }

    Ok(())
}

fn supports_file(path: &Path, agent_type: &str) -> bool {
    let normalized = agent_type.trim().to_ascii_lowercase();
    let extension = path.extension().and_then(|value| value.to_str());

    if normalized.contains("claude") {
        return matches!(extension, Some("json") | Some("jsonl"));
    }

    if normalized.contains("codex") {
        return matches!(extension, Some("json") | Some("jsonl"));
    }

    if normalized.contains("cursor") {
        return matches!(extension, Some("json") | Some("jsonl")) && cursor_path_hint(path);
    }

    false
}

fn dedup_key_for_action(path: &Path, action: &ParsedAction) -> String {
    if let Some(seed) = action.dedup_seed.as_deref() {
        return hash_string(seed);
    }

    let canonical = format!(
        "{}:{}:{}",
        path.display(),
        action.offset,
        action.block_index
    );
    hash_string(&canonical)
}

fn hash_string(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn push_action(actions: &mut Vec<ParsedAction>, offset: u64, block_index: usize, payload: Value) {
    let dedup_seed = stable_action_seed(&payload);
    actions.push(ParsedAction {
        offset,
        block_index,
        payload,
        dedup_seed,
    });
}

fn stable_action_seed(payload: &Value) -> Option<String> {
    let session_id = payload.get("session_id").and_then(Value::as_str)?;
    let action_type = payload.pointer("/action/type").and_then(Value::as_str)?;
    let record_id = resolve_string_paths(
        payload,
        &[
            &["context", "tool_use_id"],
            &["context", "record_uuid"],
            &["context", "call_id"],
        ],
    )
    .unwrap_or_default();
    let timestamp = payload
        .get("timestamp")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let tool_name = resolve_string_paths(payload, &[&["action", "tool_name"]]).unwrap_or_default();
    let target = resolve_string_paths(payload, &[&["action", "target"]]).unwrap_or_default();
    let text = resolve_string_paths(
        payload,
        &[
            &["action", "parameters", "text"],
            &["action", "parameters", "reasoning"],
        ],
    )
    .unwrap_or_default();

    Some(format!(
        "{session_id}:{action_type}:{record_id}:{timestamp}:{tool_name}:{target}:{text}"
    ))
}

fn claude_context(
    path: &Path,
    role: &str,
    record_uuid: &str,
    block_type: Option<&str>,
    hook_context: Option<&ClaudeHookContext>,
    extra: &[(&str, Value)],
) -> Value {
    let mut context = Map::new();
    context.insert(
        "source_path".to_string(),
        Value::String(path.display().to_string()),
    );
    context.insert(
        "transcript_path".to_string(),
        Value::String(path.display().to_string()),
    );
    context.insert("message_role".to_string(), Value::String(role.to_string()));
    if !record_uuid.is_empty() {
        context.insert(
            "record_uuid".to_string(),
            Value::String(record_uuid.to_string()),
        );
    }
    if let Some(block_type) = block_type {
        context.insert(
            "block_type".to_string(),
            Value::String(block_type.to_string()),
        );
    }
    if let Some(hook_context) = hook_context {
        context.insert(
            "capture_mode".to_string(),
            Value::String("hook".to_string()),
        );
        context.insert(
            "hook_path".to_string(),
            Value::String(hook_context.hook_path.clone()),
        );
        if let Some(hook_event_name) = &hook_context.hook_event_name {
            context.insert(
                "hook_event_name".to_string(),
                Value::String(hook_event_name.clone()),
            );
        }
        if let Some(hook_reason) = &hook_context.hook_reason {
            context.insert(
                "hook_reason".to_string(),
                Value::String(hook_reason.clone()),
            );
        }
        if let Some(cwd) = &hook_context.cwd {
            context.insert("cwd".to_string(), Value::String(cwd.clone()));
        }
    }

    for (key, value) in extra {
        context.insert((*key).to_string(), value.clone());
    }

    Value::Object(context)
}

fn message_object(item: &Value) -> Option<&Value> {
    item.get("message")
        .filter(|value| value.is_object())
        .or(Some(item))
}

fn content_array(message: &Value) -> Option<&Vec<Value>> {
    message.get("content").and_then(Value::as_array)
}

fn resolve_string_paths(value: &Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        let mut current = value;
        for segment in *path {
            current = current.get(*segment)?;
        }
        match current {
            Value::String(value) if !value.trim().is_empty() => Some(value.to_string()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        }
    })
}

fn extract_text_field(value: &Value) -> Option<String> {
    resolve_string_paths(value, &[&["text"], &["content"], &["message"]])
}

fn extract_reasoning_text(value: &Value) -> Option<String> {
    resolve_string_paths(
        value,
        &[&["thinking"], &["text"], &["reasoning"], &["summary"]],
    )
}

fn is_reasoning_item(item: &Value) -> bool {
    matches!(
        item.get("type").and_then(Value::as_str).unwrap_or_default(),
        "thinking" | "reasoning" | "assistant_thinking" | "redacted_thinking"
    )
}

fn is_claude_hook_payload(value: &Value) -> bool {
    value.get("transcript_path").is_some()
        || value.get("hook_event_name").is_some()
        || value.get("hook_event").is_some()
}

fn resolve_hook_transcript_path(hook_path: &Path, candidate: &str) -> PathBuf {
    let transcript_path = PathBuf::from(candidate);
    if transcript_path.is_absolute() {
        transcript_path
    } else {
        hook_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(transcript_path)
    }
}

fn file_action_type(tool_name: &str) -> Option<&'static str> {
    let normalized = tool_name.trim().to_ascii_lowercase();

    if matches!(
        normalized.as_str(),
        "read" | "view" | "grep" | "glob" | "ls" | "listfiles"
    ) || normalized.contains("read")
    {
        return Some("file_read");
    }

    if matches!(
        normalized.as_str(),
        "write" | "edit" | "multiedit" | "notebookedit" | "apply_patch"
    ) || normalized.contains("write")
        || normalized.contains("edit")
        || normalized.contains("patch")
    {
        return Some("file_write");
    }

    None
}

fn extract_target(value: &Value) -> Option<String> {
    let object = value.as_object()?;

    ["file_path", "path", "target", "resource", "url", "command"]
        .iter()
        .find_map(|key| object.get(*key))
        .and_then(|value| match value {
            Value::String(value) => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            Value::Array(values) => {
                let rendered = values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ");
                (!rendered.is_empty()).then_some(rendered)
            }
            _ => None,
        })
}

fn parse_jsonish_string(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()))
}

fn parse_cursor_document(content: &str) -> Result<CursorDocument> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(CursorDocument {
            root: None,
            rows: Vec::new(),
        });
    }

    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Ok(value) = serde_json::from_str::<Value>(trimmed)
    {
        if let Some(items) = value.as_array() {
            return Ok(CursorDocument {
                root: None,
                rows: items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| (index as u64, item.clone()))
                    .collect(),
            });
        }

        if let Some(object) = value.as_object() {
            let mut rows = Vec::new();
            for key in [
                "events",
                "messages",
                "conversation",
                "items",
                "records",
                "entries",
            ] {
                if let Some(items) = object.get(key).and_then(Value::as_array) {
                    rows.extend(
                        items
                            .iter()
                            .enumerate()
                            .map(|(index, item)| (index as u64, item.clone())),
                    );
                }
            }

            if rows.is_empty() {
                rows.push((0, value.clone()));
            }

            return Ok(CursorDocument {
                root: Some(Value::Object(object.clone())),
                rows,
            });
        }

        return Ok(CursorDocument {
            root: None,
            rows: vec![(0, value)],
        });
    }

    Ok(CursorDocument {
        root: None,
        rows: parse_records_with_offsets(content)?,
    })
}

fn merge_cursor_payload(item: &Value) -> Value {
    let Some(object) = item.as_object() else {
        return item.clone();
    };

    let merged = object.clone();
    if let Some(payload) = item.get("payload").and_then(Value::as_object) {
        let mut nested = payload.clone();
        for (key, value) in merged {
            nested.entry(key).or_insert(value);
        }
        return Value::Object(nested);
    }

    Value::Object(merged)
}

fn cursor_event_name(value: &Value) -> Option<String> {
    resolve_string_paths(value, &[&["event"], &["type"], &["kind"]]).map(normalize_cursor_name)
}

fn cursor_phase(value: &Value) -> Option<String> {
    resolve_string_paths(value, &[&["phase"], &["status"], &["state"]]).map(normalize_cursor_name)
}

fn normalize_cursor_name(value: String) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(['.', '-', ' '], "_")
}

fn is_cursor_tool_call_event(value: &str) -> bool {
    matches!(value, "tool_call" | "agent_action" | "composer_tool")
}

fn is_cursor_tool_result_event(value: &str) -> bool {
    matches!(
        value,
        "tool_result" | "tool_output" | "composer_tool_result"
    )
}

fn is_cursor_file_event(value: &str) -> bool {
    matches!(value, "file_write" | "file_saved" | "edit_applied")
}

fn cursor_context(
    path: &Path,
    role: Option<&str>,
    event_name: Option<&str>,
    phase: Option<&str>,
    extra: &[(&str, Value)],
) -> Value {
    let mut context = Map::new();
    context.insert(
        "source_path".to_string(),
        Value::String(path.display().to_string()),
    );
    context.insert(
        "transcript_path".to_string(),
        Value::String(path.display().to_string()),
    );
    if let Some(role) = role {
        context.insert("message_role".to_string(), Value::String(role.to_string()));
    }
    if let Some(event_name) = event_name {
        context.insert(
            "event_name".to_string(),
            Value::String(event_name.to_string()),
        );
    }
    if let Some(phase) = phase {
        context.insert("phase".to_string(), Value::String(phase.to_string()));
    }

    for (key, value) in extra {
        if !value.is_null() {
            context.insert((*key).to_string(), value.clone());
        }
    }

    Value::Object(context)
}

fn extract_cursor_message_text(value: &Value) -> Option<String> {
    let message = value.get("message").unwrap_or(value);

    if let Some(text) = resolve_string_paths(message, &[&["text"]]) {
        return Some(text);
    }

    if let Some(content) = message.get("content") {
        return extract_cursor_text_content(content);
    }

    None
}

fn extract_cursor_text_content(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.trim().is_empty() => Some(text.to_string()),
        Value::Array(items) => {
            let text = items
                .iter()
                .filter_map(|item| match item {
                    Value::String(text) => {
                        Some(text.trim().to_string()).filter(|text| !text.is_empty())
                    }
                    Value::Object(_) => resolve_string_paths(item, &[&["text"], &["content"]]),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            (!text.is_empty()).then_some(text)
        }
        Value::Object(_) => resolve_string_paths(value, &[&["text"], &["content"]]),
        _ => None,
    }
}

fn cursor_path_hint(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains("cursor")
    }) || path
        .file_stem()
        .and_then(|value| value.to_str())
        .map(|value| {
            let normalized = value.to_ascii_lowercase();
            ["composer", "agent", "session", "chat"]
                .iter()
                .any(|needle| normalized.contains(needle))
        })
        .unwrap_or(false)
}

fn extract_codex_message_text(content: &Value) -> String {
    content
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let kind = item.get("type").and_then(Value::as_str).unwrap_or_default();
            match kind {
                "output_text" | "text" | "input_text" => item.get("text").and_then(Value::as_str),
                _ => None,
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{
        WatchTarget, parse_actions_from_path, parse_claude_transcript, parse_codex_rollout,
        parse_cursor_source, scan_target,
    };
    use crate::{ingest::ingest_json_action, log::ActionType, storage::Storage};
    use serde_json::json;
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn parses_claude_tool_use_results_and_assistant_text() {
        let transcript = [
            json!({
                "sessionId": "claude-session",
                "agentId": "claude-agent",
                "uuid": "user-1",
                "timestamp": "2026-03-30T10:00:00Z",
                "message": {
                    "role": "user",
                    "content": "Read Cargo.toml"
                }
            })
            .to_string(),
            json!({
                "sessionId": "claude-session",
                "agentId": "claude-agent",
                "uuid": "assistant-1",
                "timestamp": "2026-03-30T10:00:01Z",
                "message": {
                    "role": "assistant",
                    "model": "claude-opus-4-6",
                    "stop_reason": "tool_use",
                    "content": [
                        { "type": "text", "text": "I’ll inspect the file." },
                        { "type": "tool_use", "id": "toolu_1", "name": "Read", "input": { "file_path": "/tmp/Cargo.toml" } }
                    ]
                }
            })
            .to_string(),
            json!({
                "sessionId": "claude-session",
                "agentId": "claude-agent",
                "uuid": "tool-1",
                "timestamp": "2026-03-30T10:00:02Z",
                "message": {
                    "role": "user",
                    "content": [
                        { "type": "tool_result", "tool_use_id": "toolu_1", "content": [{ "type": "text", "text": "[package]" }] }
                    ]
                }
            })
            .to_string(),
            json!({
                "sessionId": "claude-session",
                "agentId": "claude-agent",
                "uuid": "assistant-2",
                "timestamp": "2026-03-30T10:00:03Z",
                "message": {
                    "role": "assistant",
                    "model": "claude-opus-4-6",
                    "stop_reason": "end_turn",
                    "content": [
                        { "type": "text", "text": "The manifest defines the package metadata." }
                    ]
                }
            })
            .to_string(),
        ]
        .join("\n");

        let actions = parse_claude_transcript(Path::new("/tmp/sample.jsonl"), &transcript).unwrap();

        assert_eq!(actions.len(), 5);
        assert_eq!(actions[0].payload["action"]["type"], "assistant_response");
        assert_eq!(actions[1].payload["action"]["tool_name"], "Read");
        assert_eq!(actions[1].payload["action"]["target"], "/tmp/Cargo.toml");
        assert_eq!(actions[2].payload["action"]["type"], "file_read");
        assert_eq!(actions[3].payload["action"]["type"], "tool_result");
        assert_eq!(actions[3].payload["action"]["tool_name"], "Read");
        assert_eq!(actions[4].payload["action"]["type"], "assistant_response");
    }

    #[test]
    fn parses_claude_session_json_with_reasoning_and_file_writes() {
        let session = json!({
            "sessionId": "claude-session",
            "agentId": "claude-agent",
            "messages": [
                {
                    "uuid": "assistant-1",
                    "timestamp": "2026-03-30T10:00:01Z",
                    "message": {
                        "role": "assistant",
                        "model": "claude-opus-4-6",
                        "content": [
                            { "type": "thinking", "thinking": "Need to inspect the repo first." },
                            { "type": "tool_use", "id": "toolu_read", "name": "Read", "input": { "file_path": "/repo/src/main.rs" } }
                        ]
                    }
                },
                {
                    "uuid": "tool-result-1",
                    "timestamp": "2026-03-30T10:00:02Z",
                    "message": {
                        "role": "user",
                        "content": [
                            { "type": "tool_result", "tool_use_id": "toolu_read", "content": [{ "type": "text", "text": "fn main() {}" }] }
                        ]
                    }
                },
                {
                    "uuid": "assistant-2",
                    "timestamp": "2026-03-30T10:00:03Z",
                    "message": {
                        "role": "assistant",
                        "content": [
                            { "type": "text", "text": "I updated the file." },
                            { "type": "tool_use", "id": "toolu_write", "name": "Edit", "input": { "file_path": "/repo/src/main.rs", "old_string": "fn main() {}", "new_string": "fn main() { println!(\\\"hi\\\"); }" } }
                        ]
                    }
                },
                {
                    "uuid": "tool-result-2",
                    "timestamp": "2026-03-30T10:00:04Z",
                    "message": {
                        "role": "user",
                        "content": [
                            { "type": "tool_result", "tool_use_id": "toolu_write", "content": "applied", "is_error": false }
                        ]
                    }
                }
            ]
        })
        .to_string();

        let actions = parse_claude_transcript(Path::new("/tmp/session.json"), &session).unwrap();
        let action_types = actions
            .iter()
            .map(|action| {
                action.payload["action"]["type"]
                    .as_str()
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();

        assert!(action_types.contains(&"reasoning"));
        assert!(action_types.contains(&"tool_call"));
        assert!(action_types.contains(&"tool_result"));
        assert!(action_types.contains(&"file_read"));
        assert!(action_types.contains(&"assistant_response"));
        assert!(action_types.contains(&"file_write"));
    }

    #[test]
    fn watcher_reconciles_hook_payload_with_transcript() {
        let root = temp_dir("claude-hook-reconcile");
        let transcript_path = root.join("session.jsonl");
        let hook_path = root.join("session-end.json");

        fs::write(
            &transcript_path,
            [
                json!({
                    "sessionId": "claude-session",
                    "agentId": "claude-agent",
                    "uuid": "assistant-1",
                    "timestamp": "2026-03-30T10:00:01Z",
                    "message": {
                        "role": "assistant",
                        "content": [
                            { "type": "tool_use", "id": "toolu_1", "name": "Read", "input": { "file_path": "/repo/Cargo.toml" } }
                        ]
                    }
                })
                .to_string(),
                json!({
                    "sessionId": "claude-session",
                    "agentId": "claude-agent",
                    "uuid": "tool-1",
                    "timestamp": "2026-03-30T10:00:02Z",
                    "message": {
                        "role": "user",
                        "content": [
                            { "type": "tool_result", "tool_use_id": "toolu_1", "content": [{ "type": "text", "text": "[package]" }] }
                        ]
                    }
                })
                .to_string(),
            ]
            .join("\n"),
        )
        .unwrap();
        fs::write(
            &hook_path,
            json!({
                "hook_event_name": "SessionEnd",
                "session_id": "claude-session",
                "transcript_path": transcript_path,
                "cwd": "/repo"
            })
            .to_string(),
        )
        .unwrap();

        let storage = Storage::open_in_memory().unwrap();
        scan_target(
            &storage,
            &WatchTarget {
                dir: root.clone(),
                agent_type: "claude".to_string(),
            },
            false,
        )
        .unwrap();

        let entries = storage.entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert!(
            entries
                .iter()
                .any(|entry| entry.payload["action"]["type"] == "tool_call")
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.payload["action"]["type"] == "file_read")
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.payload["action"]["type"] == "tool_result")
        );
    }

    #[test]
    fn ingests_file_actions_with_read_and_write_classification() {
        let storage = Storage::open_in_memory().unwrap();
        let session = json!({
            "sessionId": "claude-session",
            "messages": [
                {
                    "uuid": "assistant-1",
                    "timestamp": "2026-03-30T10:00:01Z",
                    "message": {
                        "role": "assistant",
                        "content": [
                            { "type": "tool_use", "id": "toolu_read", "name": "Read", "input": { "file_path": "/repo/src/lib.rs" } },
                            { "type": "tool_use", "id": "toolu_write", "name": "Edit", "input": { "file_path": "/repo/src/lib.rs", "old_string": "old", "new_string": "new" } }
                        ]
                    }
                }
            ]
        })
        .to_string();

        for action in parse_claude_transcript(Path::new("/tmp/session.json"), &session).unwrap() {
            let dedup = format!("{}:{}", action.offset, action.block_index);
            let _ = ingest_json_action(&storage, action.payload, "test", Some(&dedup)).unwrap();
        }

        let mut tool_call = 0;
        let mut system_write = 0;
        let mut saw_file_read = false;
        let mut saw_file_write = false;
        for entry in storage.entries().unwrap() {
            saw_file_read |= entry.payload["action"]["type"] == "file_read";
            saw_file_write |= entry.payload["action"]["type"] == "file_write";
            match entry.action_type {
                ActionType::ToolCall => tool_call += 1,
                ActionType::SystemWrite => system_write += 1,
                _ => {}
            }
        }

        assert!(saw_file_read);
        assert!(saw_file_write);
        assert!(tool_call >= 1);
        assert_eq!(system_write, 1);
    }

    #[test]
    fn parses_hook_payload_from_path() {
        let root = temp_dir("claude-hook-path");
        let transcript_path = root.join("session.jsonl");
        let hook_path = root.join("session-end.json");

        fs::write(
            &transcript_path,
            json!({
                "sessionId": "claude-session",
                "agentId": "claude-agent",
                "uuid": "assistant-1",
                "timestamp": "2026-03-30T10:00:01Z",
                "message": {
                    "role": "assistant",
                    "content": [
                        { "type": "text", "text": "Done." }
                    ]
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            &hook_path,
            json!({
                "hook_event_name": "SessionEnd",
                "transcript_path": transcript_path,
                "reason": "stop",
                "cwd": "/repo"
            })
            .to_string(),
        )
        .unwrap();

        let actions = parse_actions_from_path(&hook_path, "claude").unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0].payload["context"]["hook_event_name"],
            "SessionEnd"
        );
        assert_eq!(actions[0].payload["action"]["type"], "assistant_response");
    }

    #[test]
    fn parses_codex_reasoning_tool_calls_and_assistant_messages() {
        let rollout = [
            json!({
                "timestamp": "2026-03-30T10:00:00Z",
                "type": "session_meta",
                "payload": {
                    "id": "codex-session"
                }
            })
            .to_string(),
            json!({
                "timestamp": "2026-03-30T10:00:01Z",
                "type": "event_msg",
                "payload": {
                    "type": "agent_reasoning",
                    "text": "**Inspecting source tree**"
                }
            })
            .to_string(),
            json!({
                "timestamp": "2026-03-30T10:00:02Z",
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "name": "shell",
                    "call_id": "call_1",
                    "arguments": "{\"command\":[\"bash\",\"-lc\",\"ls\"],\"workdir\":\"/repo\"}"
                }
            })
            .to_string(),
            json!({
                "timestamp": "2026-03-30T10:00:03Z",
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "call_1",
                    "output": "{\"output\":\"Cargo.toml\\nsrc\\n\",\"metadata\":{\"exit_code\":0}}"
                }
            })
            .to_string(),
            json!({
                "timestamp": "2026-03-30T10:00:04Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        { "type": "output_text", "text": "I found the crate root and source directory." }
                    ]
                }
            })
            .to_string(),
        ]
        .join("\n");

        let actions = parse_codex_rollout(Path::new("/tmp/rollout.jsonl"), &rollout).unwrap();

        assert_eq!(actions.len(), 4);
        assert_eq!(actions[0].payload["action"]["type"], "decision");
        assert_eq!(actions[1].payload["action"]["tool_name"], "shell");
        assert_eq!(actions[1].payload["action"]["target"], "bash -lc ls");
        assert_eq!(actions[2].payload["action"]["type"], "tool_result");
        assert_eq!(actions[2].payload["action"]["tool_name"], "shell");
        assert_eq!(actions[3].payload["action"]["type"], "assistant_response");
        assert_eq!(actions[3].payload["session_id"], "codex-session");
    }

    #[test]
    fn parses_cursor_events_and_assistant_messages() {
        let transcript = [
            json!({
                "event": "composer",
                "phase": "start",
                "session_id": "cursor-session",
                "workspace": "/repo",
                "prompt": "Refactor auth",
                "timestamp": "2026-03-30T10:00:00Z",
            })
            .to_string(),
            json!({
                "session_id": "cursor-session",
                "role": "assistant",
                "timestamp": "2026-03-30T10:00:01Z",
                "content": [
                    { "type": "text", "text": "I’ll inspect the repo first." }
                ]
            })
            .to_string(),
            json!({
                "event": "tool_call",
                "session_id": "cursor-session",
                "call_id": "tool-1",
                "tool_name": "read_file",
                "input": { "path": "src/main.rs" },
                "timestamp": "2026-03-30T10:00:02Z",
            })
            .to_string(),
            json!({
                "event": "tool_result",
                "session_id": "cursor-session",
                "call_id": "tool-1",
                "output": { "contents": "fn main() {}" },
                "status": "ok",
                "timestamp": "2026-03-30T10:00:03Z",
            })
            .to_string(),
            json!({
                "event": "file_write",
                "session_id": "cursor-session",
                "path": "src/main.rs",
                "content": { "diff": "+println!(\\\"hi\\\");" },
                "timestamp": "2026-03-30T10:00:04Z",
            })
            .to_string(),
            json!({
                "event": "approval",
                "session_id": "cursor-session",
                "actor": "operator",
                "request": "Apply the edit?",
                "response": "approved",
                "approved": true,
                "target": "editor",
                "timestamp": "2026-03-30T10:00:05Z",
            })
            .to_string(),
            json!({
                "event": "composer",
                "phase": "end",
                "session_id": "cursor-session",
                "summary": "done",
                "timestamp": "2026-03-30T10:00:06Z",
            })
            .to_string(),
        ]
        .join("\n");

        let actions =
            parse_cursor_source(Path::new("/tmp/composer-session.jsonl"), &transcript).unwrap();

        assert_eq!(actions.len(), 7);
        assert_eq!(actions[0].payload["action"]["type"], "session_start");
        assert_eq!(actions[1].payload["action"]["type"], "assistant_response");
        assert_eq!(actions[2].payload["action"]["type"], "tool_call");
        assert_eq!(actions[2].payload["action"]["target"], "src/main.rs");
        assert_eq!(actions[3].payload["action"]["type"], "tool_result");
        assert_eq!(actions[3].payload["action"]["tool_name"], "read_file");
        assert_eq!(actions[4].payload["action"]["type"], "file_write");
        assert_eq!(actions[5].payload["action"]["type"], "human_in_the_loop");
        assert_eq!(actions[6].payload["action"]["type"], "session_end");
    }

    #[test]
    fn watcher_scans_cursor_session_files() {
        let root = temp_dir("cursor-watch");
        let cursor_dir = root.join(".cursor");
        fs::create_dir_all(&cursor_dir).unwrap();
        let session_path = cursor_dir.join("composer-session.jsonl");

        fs::write(
            &session_path,
            [
                json!({
                    "event": "tool_call",
                    "session_id": "cursor-session",
                    "call_id": "tool-1",
                    "tool_name": "read_file",
                    "input": { "path": "src/lib.rs" },
                    "timestamp": "2026-03-30T10:00:02Z",
                })
                .to_string(),
                json!({
                    "event": "tool_result",
                    "session_id": "cursor-session",
                    "call_id": "tool-1",
                    "output": { "contents": "pub fn lib() {}" },
                    "timestamp": "2026-03-30T10:00:03Z",
                })
                .to_string(),
            ]
            .join("\n"),
        )
        .unwrap();

        let storage = Storage::open_in_memory().unwrap();
        scan_target(
            &storage,
            &WatchTarget {
                dir: root,
                agent_type: "cursor".to_string(),
            },
            true,
        )
        .unwrap();

        let entries = storage.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .any(|entry| entry.payload["action"]["type"] == "tool_call")
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.payload["action"]["type"] == "tool_result")
        );
    }

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("trailing-{name}-{suffix}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
