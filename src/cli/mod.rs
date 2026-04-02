use std::{
    collections::HashMap,
    io::{self, BufRead},
    path::PathBuf,
    time::Duration,
};

use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};

use crate::api::{
    ActionsQuery, AppOptions, export_json_for_cli, export_pdf_for_cli, query_actions_for_cli,
    serve, shared_state_with_db, status_report, verify_integrity_for_cli,
};
use crate::checkpoint::{CheckpointSigner, SignatureAlgorithm};
use crate::ingest::{apply_cli_defaults, ingest_json_action};
use crate::proxy::{ProxyConfig, run as run_proxy};
use crate::storage::migration::{
    MigrationDirection, MigrationOptions, execute as execute_migration,
};
use crate::storage::{ExternalAnchorInput, Storage};
use crate::watcher::{WatchConfig, WatchTarget, run as run_watcher};
use crate::webhook::{WebhookConfig, WebhookEventKind};

const DEFAULT_DB_PATH: &str = "./trailing.db";

#[derive(Debug, Parser)]
#[command(
    name = "trailing",
    version,
    about = "Trailing — audit trails for AI agents"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Serve {
        #[arg(long, env = "TRAILING_PORT", default_value_t = 3001)]
        port: u16,
        #[arg(long, env = "TRAILING_DB_PATH", default_value = DEFAULT_DB_PATH)]
        db: String,
        #[arg(long = "rate-limit-per-minute", default_value_t = 100)]
        rate_limit_per_minute: usize,
        #[arg(long = "rate-limit-per-hour", default_value_t = 6000)]
        rate_limit_per_hour: usize,
        #[arg(long = "cors-origin")]
        cors_origins: Vec<String>,
        #[arg(long = "webhook-url", env = "TRAILING_WEBHOOK_URL")]
        webhook_url: Option<String>,
        #[arg(long = "webhook-secret", env = "TRAILING_WEBHOOK_SECRET")]
        webhook_secret: Option<String>,
        #[arg(
            long = "webhook-event",
            env = "TRAILING_WEBHOOK_EVENTS",
            value_delimiter = ','
        )]
        webhook_events: Vec<WebhookEventKind>,
        /// Seed realistic sample audit data on startup for demos
        #[arg(long, default_value_t = false)]
        demo: bool,
    },
    Verify,
    Export {
        #[arg(long, value_enum)]
        format: ExportFormat,
        #[arg(long)]
        framework: String,
    },
    Query {
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long = "type")]
        action_type: Option<String>,
    },
    Watch {
        #[arg(long = "dir", required = true)]
        dirs: Vec<String>,
        #[arg(long = "agent-type", required = true)]
        agent_types: Vec<String>,
        #[arg(long, default_value_t = false)]
        recursive: bool,
        #[arg(long, env = "TRAILING_DB_PATH", default_value = DEFAULT_DB_PATH)]
        db: String,
    },
    Proxy {
        #[arg(long, default_value_t = 3002)]
        port: u16,
        #[arg(long = "upstream-host")]
        upstream_hosts: Vec<String>,
        #[arg(long, env = "TRAILING_DB_PATH", default_value = DEFAULT_DB_PATH)]
        db: String,
    },
    Ingest {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        session: String,
        #[arg(long, env = "TRAILING_DB_PATH", default_value = DEFAULT_DB_PATH)]
        db: String,
    },
    Checkpoint {
        #[command(subcommand)]
        command: CheckpointCommands,
    },
    Migrate {
        #[arg(long, env = "TRAILING_DB_PATH", default_value = DEFAULT_DB_PATH)]
        db: String,
        #[arg(long, default_value_t = false)]
        apply: bool,
        #[arg(long, default_value_t = false)]
        rollback: bool,
        #[arg(long, default_value_t = true)]
        verify: bool,
    },
    Status,
}

#[derive(Debug, Subcommand)]
pub enum CheckpointCommands {
    Create {
        #[arg(long, env = "TRAILING_DB_PATH", default_value = DEFAULT_DB_PATH)]
        db: String,
        #[arg(long, value_enum)]
        algorithm: CheckpointAlgorithm,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        private_key_hex: String,
        #[arg(long)]
        key_label: Option<String>,
        #[arg(long = "anchor")]
        anchors: Vec<String>,
    },
    List {
        #[arg(long, env = "TRAILING_DB_PATH", default_value = DEFAULT_DB_PATH)]
        db: String,
    },
    Verify {
        #[arg(long, env = "TRAILING_DB_PATH", default_value = DEFAULT_DB_PATH)]
        db: String,
        #[arg(long)]
        checkpoint_id: Option<String>,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum ExportFormat {
    Json,
    Pdf,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum CheckpointAlgorithm {
    Ed25519,
    EcdsaP256Sha256,
}

impl From<CheckpointAlgorithm> for SignatureAlgorithm {
    fn from(value: CheckpointAlgorithm) -> Self {
        match value {
            CheckpointAlgorithm::Ed25519 => SignatureAlgorithm::Ed25519,
            CheckpointAlgorithm::EcdsaP256Sha256 => SignatureAlgorithm::EcdsaP256Sha256,
        }
    }
}

pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Serve {
            port,
            db,
            rate_limit_per_minute,
            rate_limit_per_hour,
            cors_origins,
            webhook_url,
            webhook_secret,
            webhook_events,
            demo,
        } => {
            if rate_limit_per_minute == 0 {
                return Err("rate limit per minute must be greater than zero".into());
            }
            if rate_limit_per_hour == 0 {
                return Err("rate limit per hour must be greater than zero".into());
            }
            if demo {
                let storage = Storage::open(&db)?;
                match crate::demo::seed_demo_data(&storage) {
                    Ok(count) => eprintln!("[demo] seeded {count} sample audit records"),
                    Err(err) => eprintln!("[demo] warning: failed to seed demo data: {err}"),
                }
            }
            serve(
                port,
                api_key_from_env(),
                db,
                AppOptions {
                    rate_limit_per_minute,
                    rate_limit_per_hour,
                    org_rate_limits: HashMap::new(),
                    cors_origins,
                    redact_fields: Vec::new(),
                    webhook: webhook_config(webhook_url, webhook_secret, webhook_events)?,
                },
            )
            .await?;
        }
        Commands::Verify => {
            let state = shared_state_with_db(default_db_path(), api_key_from_env())?;
            let report = verify_integrity_for_cli(&state).await;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::Export { format, framework } => {
            let state = shared_state_with_db(default_db_path(), api_key_from_env())?;
            match format {
                ExportFormat::Json => {
                    let package = export_json_for_cli(&state, Some(framework)).await?;
                    println!("{}", serde_json::to_string_pretty(&package)?);
                }
                ExportFormat::Pdf => {
                    let bytes = export_pdf_for_cli(&state, Some(framework.clone())).await?;
                    let summary = json!({
                        "framework": framework,
                        "bytes": bytes.len(),
                        "content_type": "application/pdf",
                    });
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                }
            }
        }
        Commands::Query {
            session,
            agent,
            action_type,
        } => {
            let state = shared_state_with_db(default_db_path(), api_key_from_env())?;
            let actions = query_actions_for_cli(
                &state,
                ActionsQuery {
                    session_id: session,
                    agent,
                    from: None,
                    to: None,
                    action_type,
                    include_oversight: None,
                },
            )
            .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&Value::Array(
                    actions
                        .into_iter()
                        .map(|action| serde_json::to_value(action).unwrap_or(Value::Null))
                        .collect(),
                ))?
            );
        }
        Commands::Migrate {
            db,
            apply,
            rollback,
            verify,
        } => {
            let db_path = PathBuf::from(db);
            let outcome = execute_migration(
                db_path.as_path(),
                &MigrationOptions {
                    apply,
                    direction: if rollback {
                        MigrationDirection::Rollback
                    } else {
                        MigrationDirection::Apply
                    },
                    verify,
                },
                |progress| {
                    eprintln!(
                        "[{}] {}/{} {}",
                        progress.phase, progress.completed, progress.total, progress.message
                    );
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        Commands::Status => {
            let report = status_report(api_key_from_env().as_deref());
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::Watch {
            dirs,
            agent_types,
            recursive,
            db,
        } => {
            let targets = build_watch_targets(&dirs, &agent_types)?;
            run_watcher(WatchConfig {
                db_path: db,
                targets,
                recursive,
                poll_interval: Duration::from_secs(1),
            })
            .await?;
        }
        Commands::Proxy {
            port,
            upstream_hosts,
            db,
        } => {
            run_proxy(ProxyConfig {
                port,
                db_path: db,
                upstream_hosts,
            })
            .await?;
        }
        Commands::Ingest { agent, session, db } => {
            let storage = Storage::open(db)?;
            let stdin = io::stdin();
            let mut ingested = 0usize;
            let mut skipped = 0usize;
            let mut action_ids = Vec::new();

            for (line_index, line) in stdin.lock().lines().enumerate() {
                let line = line?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let payload = serde_json::from_str::<Value>(trimmed)?;
                let payload = apply_cli_defaults(payload, &agent, &session);
                match ingest_json_action(&storage, payload, "stdin", None)? {
                    Some(action_id) => {
                        ingested += 1;
                        action_ids.push(action_id);
                    }
                    None => skipped += 1 + usize::from(line_index == usize::MAX),
                }
            }

            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ingested": ingested,
                    "skipped": skipped,
                    "action_ids": action_ids,
                }))?
            );
        }
        Commands::Checkpoint { command } => match command {
            CheckpointCommands::Create {
                db,
                algorithm,
                key_id,
                private_key_hex,
                key_label,
                anchors,
            } => {
                let private_key = hex::decode(private_key_hex.trim())?;
                let signer = CheckpointSigner::from_secret_bytes(
                    algorithm.into(),
                    key_id,
                    key_label,
                    &private_key,
                    Utc::now(),
                )?;
                let storage = Storage::open(db)?;
                let anchors = anchors
                    .iter()
                    .map(|anchor| parse_anchor_arg(anchor))
                    .collect::<Result<Vec<_>, _>>()?;
                let checkpoint = storage.create_signed_checkpoint(&signer, &anchors)?;
                println!("{}", serde_json::to_string_pretty(&checkpoint)?);
            }
            CheckpointCommands::List { db } => {
                let storage = Storage::open(db)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&storage.signed_checkpoints()?)?
                );
            }
            CheckpointCommands::Verify { db, checkpoint_id } => {
                let storage = Storage::open(db)?;
                let verification = match checkpoint_id.as_deref() {
                    Some(checkpoint_id) => storage.verify_signed_checkpoint(checkpoint_id)?,
                    None => storage.verify_latest_signed_checkpoint()?,
                };
                println!("{}", serde_json::to_string_pretty(&verification)?);
            }
        },
    }

    Ok(())
}

fn api_key_from_env() -> Option<String> {
    env_value("TRAILING_API_KEY")
}

fn webhook_config(
    webhook_url: Option<String>,
    webhook_secret: Option<String>,
    webhook_events: Vec<WebhookEventKind>,
) -> Result<Option<WebhookConfig>, String> {
    let webhook_url = webhook_url.filter(|value| !value.trim().is_empty());
    let webhook_secret = webhook_secret.filter(|value| !value.trim().is_empty());

    match (webhook_url, webhook_secret) {
        (None, None) => Ok(None),
        (Some(_), None) => {
            Err("webhook secret required when webhook url is configured".to_string())
        }
        (None, Some(_)) => {
            Err("webhook url required when webhook secret is configured".to_string())
        }
        (Some(url), Some(secret)) => WebhookConfig::new(url, secret, webhook_events).map(Some),
    }
}

fn default_db_path() -> String {
    env_value("TRAILING_DB_PATH").unwrap_or_else(|| DEFAULT_DB_PATH.to_string())
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn parse_anchor_arg(value: &str) -> Result<ExternalAnchorInput, String> {
    let Some((provider, reference)) = value.split_once('=') else {
        return Err("anchors must use provider=reference format".to_string());
    };
    let provider = provider.trim();
    let reference = reference.trim();
    if provider.is_empty() || reference.is_empty() {
        return Err("anchors must use provider=reference format".to_string());
    }

    Ok(ExternalAnchorInput {
        provider: provider.to_string(),
        reference: reference.to_string(),
        anchored_at: None,
        metadata: Value::Null,
    })
}

fn build_watch_targets(
    dirs: &[String],
    agent_types: &[String],
) -> Result<Vec<WatchTarget>, String> {
    if agent_types.len() != 1 && agent_types.len() != dirs.len() {
        return Err(
            "watch requires one --agent-type for all directories or one per --dir".to_string(),
        );
    }

    Ok(dirs
        .iter()
        .enumerate()
        .map(|(index, dir)| WatchTarget {
            dir: expand_home(dir),
            agent_type: agent_types[if agent_types.len() == 1 { 0 } else { index }].clone(),
        })
        .collect())
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/")
        && let Some(home) = env_value("HOME")
    {
        return PathBuf::from(home).join(stripped);
    }

    PathBuf::from(path)
}
