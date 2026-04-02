use std::fmt::{Display, Formatter};
use std::path::Path;

use chrono::Utc;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};
use uuid::Uuid;

use crate::{
    ingest::ingest_json_action,
    storage::{Storage, StorageError},
};

type Result<T> = std::result::Result<T, ProxyError>;

const DEFAULT_HOSTS: [&str; 2] = ["api.openai.com", "api.anthropic.com"];
const MAX_HEADER_BYTES: usize = 1024 * 1024;
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const PREVIEW_LIMIT: usize = 512;

#[derive(Debug)]
pub enum ProxyError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Storage(StorageError),
    InvalidRequest(String),
}

impl Display for ProxyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Json(error) => write!(f, "json error: {error}"),
            Self::Storage(error) => write!(f, "storage error: {error}"),
            Self::InvalidRequest(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ProxyError {}

impl From<std::io::Error> for ProxyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ProxyError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<StorageError> for ProxyError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

impl From<crate::ingest::IngestError> for ProxyError {
    fn from(value: crate::ingest::IngestError) -> Self {
        Self::InvalidRequest(value.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub port: u16,
    pub db_path: String,
    pub upstream_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExchangeSummary {
    pub provider: String,
    pub model: Option<String>,
    pub prompt_preview: Option<String>,
    pub response_preview: Option<String>,
    pub tools: Vec<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
}

#[derive(Debug, Clone)]
struct ParsedHead {
    first_line: String,
    headers: Vec<(String, String)>,
}

pub async fn run(config: ProxyConfig) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(("0.0.0.0", config.port)).await?;
    let intercept_hosts = if config.upstream_hosts.is_empty() {
        DEFAULT_HOSTS.iter().map(|host| host.to_string()).collect()
    } else {
        config.upstream_hosts
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let db_path = config.db_path.clone();
        let intercept_hosts = intercept_hosts.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, &db_path, &intercept_hosts).await {
                eprintln!("proxy connection failed: {error}");
            }
        });
    }
}

async fn handle_connection(
    mut client: TcpStream,
    db_path: &str,
    intercept_hosts: &[String],
) -> Result<()> {
    let (head_bytes, mut remainder) = read_http_head(&mut client).await?;
    let head = parse_head(&head_bytes)?;
    let mut parts = head.first_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(client, target, db_path, intercept_hosts).await
    } else {
        handle_http(
            client,
            method,
            target,
            head,
            &mut remainder,
            db_path,
            intercept_hosts,
        )
        .await
    }
}

async fn handle_connect(
    mut client: TcpStream,
    target: String,
    db_path: &str,
    intercept_hosts: &[String],
) -> Result<()> {
    let (host, port) = split_host_port(&target, 443);
    let mut upstream = TcpStream::connect((host.as_str(), port)).await?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    if should_intercept(&host, intercept_hosts) {
        let provider = provider_for_host(&host);
        log_proxy_action(
            db_path,
            json!({
                "session_id": format!("proxy-{}", Uuid::new_v4()),
                "agent_id": provider,
                "agent_type": provider,
                "timestamp": Utc::now().to_rfc3339(),
                "action": {
                    "type": "proxy_tunnel",
                    "target": target,
                    "parameters": {
                        "provider": provider,
                        "encrypted_tunnel": true,
                    }
                },
                "context": {
                    "host": host,
                    "port": port,
                    "transport": "connect",
                    "opaque_tls": true,
                }
            }),
        )?;
    }

    let _ = copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn handle_http(
    mut client: TcpStream,
    method: String,
    target: String,
    head: ParsedHead,
    remainder: &mut Vec<u8>,
    db_path: &str,
    intercept_hosts: &[String],
) -> Result<()> {
    let content_length = header_value(&head.headers, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_BODY_BYTES);
    if remainder.len() < content_length {
        let mut body = vec![0u8; content_length - remainder.len()];
        client.read_exact(&mut body).await?;
        remainder.extend_from_slice(&body);
    }
    let request_body = remainder[..content_length].to_vec();

    let (host, port, path) = resolve_target(&target, &head.headers)?;
    let mut upstream = TcpStream::connect((host.as_str(), port)).await?;
    let request_bytes = build_forward_request(&method, &path, &head.headers, &request_body);
    upstream.write_all(&request_bytes).await?;
    let response_bytes = read_http_response(&mut upstream, &method).await?;
    client.write_all(&response_bytes).await?;

    if should_intercept(&host, intercept_hosts)
        && let Some(summary) = summarize_exchange(&host, &request_body, &response_bytes)
    {
        let status_code = parse_response_status(&response_bytes).unwrap_or(0);
        log_proxy_action(
            db_path,
            json!({
                "session_id": format!("proxy-{}", Uuid::new_v4()),
                "agent_id": summary.provider,
                "agent_type": summary.provider,
                "timestamp": Utc::now().to_rfc3339(),
                "action": {
                    "type": "llm_proxy",
                    "target": path,
                    "parameters": {
                        "provider": summary.provider,
                        "model": summary.model,
                        "prompt_preview": summary.prompt_preview,
                        "tools": summary.tools,
                    },
                    "result": {
                        "response_preview": summary.response_preview,
                        "input_tokens": summary.input_tokens,
                        "output_tokens": summary.output_tokens,
                        "total_tokens": summary.total_tokens,
                        "cost_usd": summary.cost_usd,
                        "status_code": status_code,
                    }
                },
                "context": {
                    "host": host,
                    "port": port,
                    "method": method,
                    "transport": "http",
                }
            }),
        )?;
    }

    Ok(())
}

fn log_proxy_action(db_path: &str, payload: Value) -> Result<()> {
    let storage = Storage::open(Path::new(db_path))?;
    let _ = ingest_json_action(&storage, payload, "proxy", None)?;
    Ok(())
}

async fn read_http_head(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(ProxyError::InvalidRequest(
                "client closed connection before sending headers".to_string(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            let split_at = buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
                .unwrap_or(buffer.len());
            let remainder = buffer.split_off(split_at);
            return Ok((buffer, remainder));
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(ProxyError::InvalidRequest(
                "http headers exceeded maximum size".to_string(),
            ));
        }
    }
}

async fn read_http_response(stream: &mut TcpStream, method: &str) -> Result<Vec<u8>> {
    let (head_bytes, mut remainder) = read_http_head(stream).await?;
    let head = parse_head(&head_bytes)?;
    let mut response_bytes = head_bytes;
    let status_code = parse_response_status(&response_bytes).unwrap_or(0);

    if !response_has_body(method, status_code) {
        return Ok(response_bytes);
    }

    if header_value(&head.headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        let chunked_len = read_chunked_body(stream, &mut remainder).await?;
        response_bytes.extend_from_slice(&remainder[..chunked_len]);
        return Ok(response_bytes);
    }

    if let Some(content_length) =
        header_value(&head.headers, "content-length").and_then(|value| value.parse::<usize>().ok())
    {
        if remainder.len() < content_length {
            let mut body = vec![0u8; content_length - remainder.len()];
            stream.read_exact(&mut body).await?;
            remainder.extend_from_slice(&body);
        }
        response_bytes.extend_from_slice(&remainder[..content_length]);
        return Ok(response_bytes);
    }

    response_bytes.extend_from_slice(&remainder);
    stream.read_to_end(&mut response_bytes).await?;
    Ok(response_bytes)
}

async fn read_chunked_body(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<usize> {
    let mut chunk = [0u8; 4096];

    loop {
        if let Some(len) = complete_chunked_body_len(buffer)? {
            return Ok(len);
        }

        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(ProxyError::InvalidRequest(
                "upstream closed connection before finishing chunked response".to_string(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn complete_chunked_body_len(buffer: &[u8]) -> Result<Option<usize>> {
    let mut offset = 0;

    loop {
        let Some(line_end) = find_bytes(buffer, offset, b"\r\n") else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&buffer[offset..line_end]).map_err(|_| {
            ProxyError::InvalidRequest("upstream sent invalid chunk size".to_string())
        })?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| {
                ProxyError::InvalidRequest("upstream sent invalid chunk size".to_string())
            })?;
        let chunk_start = line_end + 2;

        if size == 0 {
            if buffer.len() < chunk_start + 2 {
                return Ok(None);
            }
            if &buffer[chunk_start..chunk_start + 2] == b"\r\n" {
                return Ok(Some(chunk_start + 2));
            }
            if let Some(trailer_end) = find_bytes(buffer, chunk_start, b"\r\n\r\n") {
                return Ok(Some(trailer_end + 4));
            }
            return Ok(None);
        }

        let chunk_end = chunk_start + size;
        if buffer.len() < chunk_end + 2 {
            return Ok(None);
        }
        if &buffer[chunk_end..chunk_end + 2] != b"\r\n" {
            return Err(ProxyError::InvalidRequest(
                "upstream sent malformed chunked response".to_string(),
            ));
        }
        offset = chunk_end + 2;
    }
}

fn find_bytes(buffer: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    buffer[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|index| start + index)
}

fn response_has_body(method: &str, status_code: u16) -> bool {
    !method.eq_ignore_ascii_case("HEAD")
        && !(100..200).contains(&status_code)
        && status_code != 204
        && status_code != 304
}

fn parse_head(bytes: &[u8]) -> Result<ParsedHead> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n").filter(|line| !line.is_empty());
    let first_line = lines
        .next()
        .ok_or_else(|| ProxyError::InvalidRequest("missing request line".to_string()))?
        .to_string();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();

    Ok(ParsedHead {
        first_line,
        headers,
    })
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn resolve_target(target: &str, headers: &[(String, String)]) -> Result<(String, u16, String)> {
    if let Some(rest) = target.strip_prefix("http://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = split_host_port(authority, 80);
        return Ok((host, port, format!("/{}", path)));
    }

    if let Some(rest) = target.strip_prefix("https://") {
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = split_host_port(authority, 443);
        return Ok((host, port, format!("/{}", path)));
    }

    let host = header_value(headers, "host")
        .ok_or_else(|| ProxyError::InvalidRequest("missing Host header".to_string()))?;
    let (host, port) = split_host_port(host, 80);
    Ok((host, port, target.to_string()))
}

fn split_host_port(value: &str, default_port: u16) -> (String, u16) {
    if let Some((host, port)) = value.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.to_string(), port);
    }
    (value.to_string(), default_port)
}

fn build_forward_request(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut request = format!("{method} {path} HTTP/1.1\r\n");
    let mut saw_connection = false;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        if name.eq_ignore_ascii_case("connection") {
            saw_connection = true;
            request.push_str("Connection: close\r\n");
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }

    if !saw_connection {
        request.push_str("Connection: close\r\n");
    }

    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn should_intercept(host: &str, intercept_hosts: &[String]) -> bool {
    intercept_hosts
        .iter()
        .any(|candidate| host.eq_ignore_ascii_case(candidate))
}

pub fn summarize_exchange(
    host: &str,
    request_body: &[u8],
    response_bytes: &[u8],
) -> Option<ExchangeSummary> {
    let request_json: Value = serde_json::from_slice(request_body).ok()?;
    let response_body = extract_response_body(response_bytes)?;
    let response_json: Value = serde_json::from_slice(&response_body).ok()?;
    let provider = provider_for_host(host);
    let model = request_json
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_string);
    let tools = extract_tool_names(&request_json);
    let prompt_preview = truncate(extract_prompt_text(&request_json));
    let response_preview = truncate(extract_response_text(&response_json));
    let usage = extract_usage(&response_json);
    let cost_usd = estimate_cost(&provider, model.as_deref(), usage.0, usage.1);

    Some(ExchangeSummary {
        provider,
        model,
        prompt_preview,
        response_preview,
        tools,
        input_tokens: usage.0,
        output_tokens: usage.1,
        total_tokens: usage.2,
        cost_usd,
    })
}

fn extract_response_body(response_bytes: &[u8]) -> Option<Vec<u8>> {
    let split_at = response_bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?
        + 4;
    Some(response_bytes[split_at..].to_vec())
}

fn parse_response_status(response_bytes: &[u8]) -> Option<u16> {
    let head = response_bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|index| &response_bytes[..index])?;
    let line = String::from_utf8_lossy(head);
    line.split_whitespace().nth(1)?.parse::<u16>().ok()
}

fn provider_for_host(host: &str) -> String {
    if host.contains("anthropic") {
        "anthropic".to_string()
    } else {
        "openai".to_string()
    }
}

fn extract_tool_names(request_json: &Value) -> Vec<String> {
    request_json
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .or_else(|| tool.pointer("/function/name").and_then(Value::as_str))
                .map(str::to_string)
        })
        .collect()
}

fn extract_prompt_text(request_json: &Value) -> Option<String> {
    if let Some(prompt) = request_json.get("prompt").and_then(Value::as_str) {
        return Some(prompt.to_string());
    }

    if let Some(input) = request_json.get("input") {
        let text = collect_text(input);
        if !text.is_empty() {
            return Some(text);
        }
    }

    if let Some(system) = request_json.get("system") {
        let text = collect_text(system);
        if !text.is_empty() {
            return Some(text);
        }
    }

    request_json
        .get("messages")
        .and_then(Value::as_array)
        .map(|messages| {
            messages
                .iter()
                .map(collect_text)
                .filter(|text| !text.is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|text| !text.is_empty())
}

fn extract_response_text(response_json: &Value) -> Option<String> {
    if let Some(output) = response_json.get("output") {
        let text = collect_text(output);
        if !text.is_empty() {
            return Some(text);
        }
    }

    if let Some(content) = response_json.get("content") {
        let text = collect_text(content);
        if !text.is_empty() {
            return Some(text);
        }
    }

    response_json
        .pointer("/choices/0/message")
        .map(collect_text)
        .filter(|text| !text.is_empty())
}

fn collect_text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Array(values) => values
            .iter()
            .map(collect_text)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Object(map) => {
            if let Some(text) = map.get("text").and_then(Value::as_str) {
                return text.to_string();
            }
            if let Some(text) = map.get("output_text").and_then(Value::as_str) {
                return text.to_string();
            }
            if let Some(text) = map.get("content") {
                let nested = collect_text(text);
                if !nested.is_empty() {
                    return nested;
                }
            }
            if let Some(text) = map.get("input_text").and_then(Value::as_str) {
                return text.to_string();
            }
            String::new()
        }
        _ => String::new(),
    }
}

fn extract_usage(response_json: &Value) -> (Option<u64>, Option<u64>, Option<u64>) {
    let input = response_json
        .pointer("/usage/input_tokens")
        .or_else(|| response_json.pointer("/usage/prompt_tokens"))
        .and_then(Value::as_u64);
    let output = response_json
        .pointer("/usage/output_tokens")
        .or_else(|| response_json.pointer("/usage/completion_tokens"))
        .and_then(Value::as_u64);
    let total = response_json
        .pointer("/usage/total_tokens")
        .and_then(Value::as_u64)
        .or_else(|| match (input, output) {
            (Some(input), Some(output)) => Some(input + output),
            _ => None,
        });

    (input, output, total)
}

fn truncate(value: Option<String>) -> Option<String> {
    value.map(|value| {
        if value.chars().count() <= PREVIEW_LIMIT {
            value
        } else {
            let mut truncated = value.chars().take(PREVIEW_LIMIT).collect::<String>();
            truncated.push_str("...");
            truncated
        }
    })
}

fn estimate_cost(
    provider: &str,
    model: Option<&str>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
) -> Option<f64> {
    let model = model?.to_ascii_lowercase();
    let input_tokens = input_tokens? as f64 / 1_000_000.0;
    let output_tokens = output_tokens.unwrap_or_default() as f64 / 1_000_000.0;
    let (input_rate, output_rate) = if provider == "anthropic" {
        if model.contains("opus") {
            (15.0, 75.0)
        } else if model.contains("haiku") {
            (0.8, 4.0)
        } else {
            (3.0, 15.0)
        }
    } else if model.contains("5.4-mini") {
        (0.75, 4.5)
    } else if model.contains("5.4-nano") {
        (0.2, 1.25)
    } else if model.contains("5.4") {
        (2.5, 15.0)
    } else if model.contains("4.1-mini") {
        (0.4, 1.6)
    } else if model.contains("4.1-nano") {
        (0.1, 0.4)
    } else if model.contains("4.1") {
        (2.0, 8.0)
    } else if model.contains("mini") {
        (0.25, 2.0)
    } else if model.contains("nano") {
        (0.05, 0.4)
    } else {
        (1.25, 10.0)
    };

    Some(
        (((input_tokens * input_rate) + (output_tokens * output_rate)) * 10000.0).round()
            / 10000.0,
    )
}

#[cfg(test)]
mod tests {
    use super::{estimate_cost, summarize_exchange};
    use serde_json::json;

    #[test]
    fn summarizes_openai_exchange() {
        let request = json!({
            "model": "gpt-5-mini",
            "input": [
                {
                    "role": "user",
                    "content": [
                        { "type": "input_text", "text": "Summarize the repo." }
                    ]
                }
            ],
            "tools": [
                { "type": "function", "function": { "name": "shell" } }
            ]
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{}",
            json!({
                "output": [
                    {
                        "type": "message",
                        "content": [
                            { "type": "output_text", "text": "The repo contains a Rust service." }
                        ]
                    }
                ],
                "usage": {
                    "input_tokens": 120,
                    "output_tokens": 30,
                    "total_tokens": 150
                }
            })
        );

        let summary =
            summarize_exchange("api.openai.com", request.as_bytes(), response.as_bytes()).unwrap();

        assert_eq!(summary.provider, "openai");
        assert_eq!(summary.model.as_deref(), Some("gpt-5-mini"));
        assert_eq!(summary.tools, vec!["shell"]);
        assert_eq!(summary.input_tokens, Some(120));
        assert_eq!(summary.output_tokens, Some(30));
        assert_eq!(
            summary.prompt_preview.as_deref(),
            Some("Summarize the repo.")
        );
        assert_eq!(
            summary.response_preview.as_deref(),
            Some("The repo contains a Rust service.")
        );
        assert!(summary.cost_usd.is_some());
    }

    #[test]
    fn summarizes_anthropic_exchange() {
        let request = json!({
            "model": "claude-sonnet-4-5",
            "system": "You are a coding assistant.",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        { "type": "text", "text": "Read Cargo.toml" }
                    ]
                }
            ],
            "tools": [
                { "name": "Read" }
            ]
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{}",
            json!({
                "content": [
                    { "type": "text", "text": "Cargo.toml defines the package metadata." }
                ],
                "usage": {
                    "input_tokens": 90,
                    "output_tokens": 12
                }
            })
        );

        let summary =
            summarize_exchange("api.anthropic.com", request.as_bytes(), response.as_bytes())
                .unwrap();

        assert_eq!(summary.provider, "anthropic");
        assert_eq!(summary.model.as_deref(), Some("claude-sonnet-4-5"));
        assert_eq!(summary.tools, vec!["Read"]);
        assert_eq!(summary.input_tokens, Some(90));
        assert_eq!(summary.output_tokens, Some(12));
        assert!(summary.prompt_preview.is_some());
        assert!(summary.response_preview.unwrap().contains("Cargo.toml"));
    }

    #[test]
    fn estimates_cost_after_summing_input_and_output() {
        assert_eq!(
            estimate_cost("openai", Some("gpt-5-mini"), Some(1_000_000), Some(100)),
            Some(0.2502)
        );
    }

    #[test]
    fn estimates_gpt_5_4_pricing_with_current_rates() {
        assert_eq!(
            estimate_cost("openai", Some("gpt-5.4"), Some(1_000_000), Some(1_000_000)),
            Some(17.5)
        );
    }

    #[test]
    fn estimates_gpt_4_1_mini_pricing_with_current_rates() {
        assert_eq!(
            estimate_cost("openai", Some("gpt-4.1-mini"), Some(1_000_000), Some(1_000_000)),
            Some(2.0)
        );
    }
}
