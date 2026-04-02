use std::{collections::BTreeSet, fmt, process::Stdio};

use chrono::{SecondsFormat, Utc};
use clap::ValueEnum;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, process::Command};

const HMAC_BLOCK_SIZE: usize = 64;
const SIGNATURE_HEADER: &str = "X-Trailing-Signature";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum WebhookEventKind {
    HumanOversightRecorded,
    ComplianceThresholdBreached,
    ChainIntegrityFailure,
    LegalHoldCreated,
}

#[derive(Clone, Debug)]
pub struct WebhookConfig {
    pub url: String,
    pub secret: String,
    pub event_filter: BTreeSet<WebhookEventKind>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WebhookNotification {
    pub event: WebhookEventKind,
    pub occurred_at: String,
    pub payload: Value,
}

impl WebhookConfig {
    pub fn new(
        url: impl Into<String>,
        secret: impl Into<String>,
        event_filter: impl IntoIterator<Item = WebhookEventKind>,
    ) -> Result<Self, String> {
        let url = url.into().trim().to_string();
        if url.is_empty() {
            return Err("webhook url cannot be empty".to_string());
        }

        let secret = secret.into().trim().to_string();
        if secret.is_empty() {
            return Err("webhook secret cannot be empty".to_string());
        }

        let mut configured_filter = event_filter.into_iter().collect::<BTreeSet<_>>();
        if configured_filter.is_empty() {
            configured_filter = WebhookEventKind::value_variants().iter().cloned().collect();
        }

        Ok(Self {
            url,
            secret,
            event_filter: configured_filter,
        })
    }

    pub fn should_deliver(&self, event: &WebhookEventKind) -> bool {
        self.event_filter.contains(event)
    }
}

impl WebhookNotification {
    pub fn new(event: WebhookEventKind, payload: Value) -> Self {
        Self {
            event,
            occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            payload,
        }
    }
}

pub fn notify_in_background(config: Option<WebhookConfig>, notification: WebhookNotification) {
    let Some(config) = config else {
        return;
    };
    if !config.should_deliver(&notification.event) {
        return;
    }

    tokio::spawn(async move {
        if let Err(error) = webhook_notify(&config, &notification).await {
            eprintln!(
                "[webhook] failed to deliver {} webhook: {error}",
                notification.event
            );
        }
    });
}

pub async fn webhook_notify(
    config: &WebhookConfig,
    notification: &WebhookNotification,
) -> Result<(), WebhookError> {
    let body = serde_json::to_vec(notification)?;
    let signature = hmac_sha256_hex(config.secret.as_bytes(), &body);
    let mut child = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail")
        .arg("--max-time")
        .arg("10")
        .arg("--request")
        .arg("POST")
        .arg("--header")
        .arg("Content-Type: application/json")
        .arg("--header")
        .arg(format!("{SIGNATURE_HEADER}: {signature}"))
        .arg("--data-binary")
        .arg("@-")
        .arg(&config.url)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(&body).await?;
    }

    let output = child.wait_with_output().await?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(WebhookError::CommandFailed {
        status: output.status.code(),
        stderr,
    })
}

fn hmac_sha256_hex(secret: &[u8], message: &[u8]) -> String {
    let mut key = if secret.len() > HMAC_BLOCK_SIZE {
        Sha256::digest(secret).to_vec()
    } else {
        secret.to_vec()
    };
    key.resize(HMAC_BLOCK_SIZE, 0);

    let mut inner_pad = vec![0x36; HMAC_BLOCK_SIZE];
    let mut outer_pad = vec![0x5c; HMAC_BLOCK_SIZE];
    for (index, key_byte) in key.iter().enumerate() {
        inner_pad[index] ^= key_byte;
        outer_pad[index] ^= key_byte;
    }

    let mut inner = Sha256::new();
    inner.update(&inner_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&outer_pad);
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

#[derive(Debug)]
pub enum WebhookError {
    Io(std::io::Error),
    Serialize(serde_json::Error),
    CommandFailed { status: Option<i32>, stderr: String },
}

impl fmt::Display for WebhookEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HumanOversightRecorded => "human_oversight_recorded",
            Self::ComplianceThresholdBreached => "compliance_threshold_breached",
            Self::ChainIntegrityFailure => "chain_integrity_failure",
            Self::LegalHoldCreated => "legal_hold_created",
        })
    }
}

impl fmt::Display for WebhookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Serialize(error) => write!(f, "{error}"),
            Self::CommandFailed { status, stderr } => match status {
                Some(status) if stderr.is_empty() => write!(f, "curl exited with status {status}"),
                Some(status) => write!(f, "curl exited with status {status}: {stderr}"),
                None if stderr.is_empty() => f.write_str("curl terminated without an exit status"),
                None => write!(f, "curl terminated without an exit status: {stderr}"),
            },
        }
    }
}

impl std::error::Error for WebhookError {}

impl From<std::io::Error> for WebhookError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for WebhookError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialize(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{WebhookConfig, WebhookEventKind, hmac_sha256_hex};

    #[test]
    fn webhook_config_defaults_to_all_events() {
        let config = WebhookConfig::new("https://example.com/webhook", "secret", []).unwrap();

        assert!(config.should_deliver(&WebhookEventKind::HumanOversightRecorded));
        assert!(config.should_deliver(&WebhookEventKind::ComplianceThresholdBreached));
        assert!(config.should_deliver(&WebhookEventKind::ChainIntegrityFailure));
        assert!(config.should_deliver(&WebhookEventKind::LegalHoldCreated));
    }

    #[test]
    fn hmac_signature_matches_known_vector() {
        let signature = hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog");

        assert_eq!(
            signature,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }
}
