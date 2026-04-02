use chrono::{Duration, Utc};
use serde_json::{Value, json};

use crate::ingest::ingest_json_action;
use crate::storage::Storage;

/// Seed realistic demo data: ~20 agent actions across 3 agents, plus oversight events.
pub fn seed_demo_data(storage: &Storage) -> Result<usize, Box<dyn std::error::Error>> {
    let now = Utc::now();
    let mut count = 0usize;

    let actions: Vec<Value> = vec![
        // ── claude-code-agent actions ──
        json!({
            "timestamp": (now - Duration::days(6) - Duration::hours(2)).to_rfc3339(),
            "agent_id": "claude-code-agent",
            "agent_type": "claude-code",
            "session_id": "demo-session-claude-1",
            "action": { "type": "tool_call" },
            "tool_name": "shell.exec",
            "target": "src/api/mod.rs",
            "status": "ok",
            "payload": { "cmd": "cargo check", "working_dir": "/app" }
        }),
        json!({
            "timestamp": (now - Duration::days(6) - Duration::hours(1)).to_rfc3339(),
            "agent_id": "claude-code-agent",
            "agent_type": "claude-code",
            "session_id": "demo-session-claude-1",
            "action": { "type": "file_write" },
            "tool_name": "file.write",
            "target": "src/api/handlers.rs",
            "status": "ok",
            "payload": { "path": "src/api/handlers.rs", "lines_changed": 42 }
        }),
        json!({
            "timestamp": (now - Duration::days(5) - Duration::hours(8)).to_rfc3339(),
            "agent_id": "claude-code-agent",
            "agent_type": "claude-code",
            "session_id": "demo-session-claude-2",
            "action": { "type": "tool_call" },
            "tool_name": "shell.exec",
            "target": "tests/",
            "status": "ok",
            "payload": { "cmd": "cargo test --all", "exit_code": 0 }
        }),
        json!({
            "timestamp": (now - Duration::days(5) - Duration::hours(6)).to_rfc3339(),
            "agent_id": "claude-code-agent",
            "agent_type": "claude-code",
            "session_id": "demo-session-claude-2",
            "action": { "type": "api_request" },
            "tool_name": "http.request",
            "target": "https://api.github.com/repos/trailing/main/pulls",
            "status": "ok",
            "payload": { "method": "POST", "endpoint": "/repos/trailing/main/pulls", "title": "feat: add rate limiting middleware" }
        }),
        json!({
            "timestamp": (now - Duration::days(4) - Duration::hours(10)).to_rfc3339(),
            "agent_id": "claude-code-agent",
            "agent_type": "claude-code",
            "session_id": "demo-session-claude-3",
            "action": { "type": "code_review" },
            "tool_name": "review.diff",
            "target": "pr/147",
            "status": "ok",
            "payload": { "pr_number": 147, "files_reviewed": 8, "comments": 3, "verdict": "approved" }
        }),
        json!({
            "timestamp": (now - Duration::days(4) - Duration::hours(5)).to_rfc3339(),
            "agent_id": "claude-code-agent",
            "agent_type": "claude-code",
            "session_id": "demo-session-claude-3",
            "action": { "type": "file_write" },
            "tool_name": "file.write",
            "target": "src/schema/mod.rs",
            "status": "ok",
            "payload": { "path": "src/schema/mod.rs", "lines_changed": 18, "description": "add AuditEvent validation" }
        }),
        json!({
            "timestamp": (now - Duration::days(3) - Duration::hours(3)).to_rfc3339(),
            "agent_id": "claude-code-agent",
            "agent_type": "claude-code",
            "session_id": "demo-session-claude-3",
            "action": { "type": "tool_call" },
            "tool_name": "shell.exec",
            "target": "migrations/",
            "status": "ok",
            "payload": { "cmd": "trailing migrate --apply --db ./trailing.db" }
        }),

        // ── codex-deploy-bot actions ──
        json!({
            "timestamp": (now - Duration::days(5) - Duration::hours(3)).to_rfc3339(),
            "agent_id": "codex-deploy-bot",
            "agent_type": "codex",
            "session_id": "demo-session-codex-1",
            "action": { "type": "deployment" },
            "tool_name": "deploy.push",
            "target": "production/trailing-api",
            "status": "ok",
            "payload": { "environment": "staging", "image": "trailing-api:v0.9.2", "replicas": 3 }
        }),
        json!({
            "timestamp": (now - Duration::days(5) - Duration::hours(2)).to_rfc3339(),
            "agent_id": "codex-deploy-bot",
            "agent_type": "codex",
            "session_id": "demo-session-codex-1",
            "action": { "type": "api_request" },
            "tool_name": "http.request",
            "target": "https://api.cloudflare.com/client/v4/zones",
            "status": "ok",
            "payload": { "method": "PUT", "endpoint": "/zones/purge_cache", "zone": "trailing.ai" }
        }),
        json!({
            "timestamp": (now - Duration::days(3) - Duration::hours(7)).to_rfc3339(),
            "agent_id": "codex-deploy-bot",
            "agent_type": "codex",
            "session_id": "demo-session-codex-2",
            "action": { "type": "deployment" },
            "tool_name": "deploy.push",
            "target": "production/trailing-api",
            "status": "ok",
            "payload": { "environment": "production", "image": "trailing-api:v0.9.3", "replicas": 3, "rollback_image": "trailing-api:v0.9.2" }
        }),
        json!({
            "timestamp": (now - Duration::days(2) - Duration::hours(9)).to_rfc3339(),
            "agent_id": "codex-deploy-bot",
            "agent_type": "codex",
            "session_id": "demo-session-codex-2",
            "action": { "type": "tool_call" },
            "tool_name": "shell.exec",
            "target": "k8s/trailing-api",
            "status": "ok",
            "payload": { "cmd": "kubectl rollout status deployment/trailing-api -n production", "exit_code": 0 }
        }),
        json!({
            "timestamp": (now - Duration::days(2) - Duration::hours(4)).to_rfc3339(),
            "agent_id": "codex-deploy-bot",
            "agent_type": "codex",
            "session_id": "demo-session-codex-2",
            "action": { "type": "api_request" },
            "tool_name": "http.request",
            "target": "https://hooks.slack.com/services/T00/B00/xxx",
            "status": "ok",
            "payload": { "method": "POST", "endpoint": "/slack/notify", "message": "Deploy v0.9.3 to production complete" }
        }),
        json!({
            "timestamp": (now - Duration::days(1) - Duration::hours(6)).to_rfc3339(),
            "agent_id": "codex-deploy-bot",
            "agent_type": "codex",
            "session_id": "demo-session-codex-3",
            "action": { "type": "deployment" },
            "tool_name": "deploy.push",
            "target": "production/trailing-worker",
            "status": "ok",
            "payload": { "environment": "staging", "image": "trailing-worker:v0.4.1", "replicas": 2 }
        }),

        // ── cursor-review-agent actions ──
        json!({
            "timestamp": (now - Duration::days(4) - Duration::hours(1)).to_rfc3339(),
            "agent_id": "cursor-review-agent",
            "agent_type": "cursor",
            "session_id": "demo-session-cursor-1",
            "action": { "type": "code_review" },
            "tool_name": "review.diff",
            "target": "pr/142",
            "status": "ok",
            "payload": { "pr_number": 142, "files_reviewed": 5, "comments": 1, "verdict": "changes_requested" }
        }),
        json!({
            "timestamp": (now - Duration::days(3) - Duration::hours(9)).to_rfc3339(),
            "agent_id": "cursor-review-agent",
            "agent_type": "cursor",
            "session_id": "demo-session-cursor-1",
            "action": { "type": "code_review" },
            "tool_name": "review.diff",
            "target": "pr/145",
            "status": "ok",
            "payload": { "pr_number": 145, "files_reviewed": 12, "comments": 5, "verdict": "approved" }
        }),
        json!({
            "timestamp": (now - Duration::days(2) - Duration::hours(11)).to_rfc3339(),
            "agent_id": "cursor-review-agent",
            "agent_type": "cursor",
            "session_id": "demo-session-cursor-2",
            "action": { "type": "tool_call" },
            "tool_name": "linter.run",
            "target": "src/",
            "status": "ok",
            "payload": { "tool": "clippy", "warnings": 2, "errors": 0 }
        }),
        json!({
            "timestamp": (now - Duration::days(1) - Duration::hours(8)).to_rfc3339(),
            "agent_id": "cursor-review-agent",
            "agent_type": "cursor",
            "session_id": "demo-session-cursor-2",
            "action": { "type": "file_write" },
            "tool_name": "file.write",
            "target": "docs/architecture.md",
            "status": "ok",
            "payload": { "path": "docs/architecture.md", "lines_changed": 67, "description": "update architecture docs after refactor" }
        }),
        json!({
            "timestamp": (now - Duration::days(1) - Duration::hours(2)).to_rfc3339(),
            "agent_id": "cursor-review-agent",
            "agent_type": "cursor",
            "session_id": "demo-session-cursor-2",
            "action": { "type": "api_request" },
            "tool_name": "http.request",
            "target": "https://api.github.com/repos/trailing/main/issues",
            "status": "ok",
            "payload": { "method": "POST", "endpoint": "/repos/trailing/main/issues", "title": "Refactor storage layer for multi-backend support" }
        }),
        json!({
            "timestamp": (now - Duration::hours(5)).to_rfc3339(),
            "agent_id": "cursor-review-agent",
            "agent_type": "cursor",
            "session_id": "demo-session-cursor-2",
            "action": { "type": "code_review" },
            "tool_name": "review.diff",
            "target": "pr/151",
            "status": "ok",
            "payload": { "pr_number": 151, "files_reviewed": 3, "comments": 0, "verdict": "approved" }
        }),
    ];

    // ── Oversight / policy-check events ──
    let oversight_events: Vec<Value> = vec![
        json!({
            "timestamp": (now - Duration::days(5) - Duration::hours(3) - Duration::minutes(5)).to_rfc3339(),
            "agent_id": "codex-deploy-bot",
            "agent_type": "codex",
            "session_id": "demo-session-codex-1",
            "action": { "type": "human_approval" },
            "status": "ok",
            "payload": { "reviewer": "alice@trailing.ai", "action": "approved staging deploy of trailing-api:v0.9.2", "decision": "approve" }
        }),
        json!({
            "timestamp": (now - Duration::days(3) - Duration::hours(7) - Duration::minutes(10)).to_rfc3339(),
            "agent_id": "codex-deploy-bot",
            "agent_type": "codex",
            "session_id": "demo-session-codex-2",
            "action": { "type": "human_approval" },
            "status": "ok",
            "payload": { "reviewer": "bob@trailing.ai", "action": "approved production deploy of trailing-api:v0.9.3", "decision": "approve" }
        }),
        json!({
            "timestamp": (now - Duration::days(4) - Duration::hours(10) - Duration::minutes(2)).to_rfc3339(),
            "agent_id": "claude-code-agent",
            "agent_type": "claude-code",
            "session_id": "demo-session-claude-3",
            "action": { "type": "policy_check" },
            "status": "ok",
            "payload": { "policy_id": "nist-ai-rmf", "control_id": "GV-3", "result": "pass", "evidence": "all code changes reviewed before merge" }
        }),
        json!({
            "timestamp": (now - Duration::days(3) - Duration::hours(9) - Duration::minutes(1)).to_rfc3339(),
            "agent_id": "cursor-review-agent",
            "agent_type": "cursor",
            "session_id": "demo-session-cursor-1",
            "action": { "type": "policy_check" },
            "status": "ok",
            "payload": { "policy_id": "soc2-cc8.1", "control_id": "CC8.1", "result": "pass", "evidence": "PR #145 passed all CI checks and code review" }
        }),
        json!({
            "timestamp": (now - Duration::days(2) - Duration::hours(9) - Duration::minutes(3)).to_rfc3339(),
            "agent_id": "codex-deploy-bot",
            "agent_type": "codex",
            "session_id": "demo-session-codex-2",
            "action": { "type": "policy_check" },
            "status": "ok",
            "payload": { "policy_id": "deploy-policy", "control_id": "DP-1", "result": "pass", "evidence": "rollout health check passed within SLA" }
        }),
        json!({
            "timestamp": (now - Duration::days(1) - Duration::hours(6) - Duration::minutes(5)).to_rfc3339(),
            "agent_id": "codex-deploy-bot",
            "agent_type": "codex",
            "session_id": "demo-session-codex-3",
            "action": { "type": "human_approval" },
            "status": "ok",
            "payload": { "reviewer": "alice@trailing.ai", "action": "approved staging deploy of trailing-worker:v0.4.1", "decision": "approve" }
        }),
        json!({
            "timestamp": (now - Duration::hours(3)).to_rfc3339(),
            "agent_id": "claude-code-agent",
            "agent_type": "claude-code",
            "session_id": "demo-session-claude-3",
            "action": { "type": "policy_check" },
            "status": "ok",
            "payload": { "policy_id": "nist-ai-rmf", "control_id": "MP-4", "result": "pass", "evidence": "all agent actions logged to immutable ledger" }
        }),
    ];

    for action in actions.into_iter().chain(oversight_events) {
        match ingest_json_action(storage, action, "demo-seed", None) {
            Ok(Some(_)) => count += 1,
            Ok(None) => {}
            Err(err) => eprintln!("[demo] warning: failed to seed record: {err}"),
        }
    }

    Ok(count)
}
