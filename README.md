# trailing

[![PyPI](https://img.shields.io/pypi/v/trailing)](https://pypi.org/project/trailing/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.86+-orange)](https://www.rust-lang.org/)

**Independent compliance and audit system of record for autonomous AI agents**

Agentic systems are already making recommendations, routing work, and taking actions inside regulated environments. In financial services, healthcare, and other high-risk domains, those actions increasingly matter for policy, safety, and legal accountability. Most teams can observe that an agent ran, but they cannot reconstruct exactly what it decided, what tools it used, what data it touched, or whether a human intervened. Trailing exists to make autonomous agent behavior auditable, defensible, and reviewable before an auditor, regulator, customer, or internal risk committee asks for proof.

## Why Trailing

Traditional observability tells you whether a service was up. It does not give you a compliance-grade system of record for autonomous agents making decisions in regulated workflows. When an AI agent executes a tool call, overrides a control, accesses sensitive data, or triggers human escalation, teams need a tamper-evident record tied to policy obligations and evidence export. Trailing is the layer that ingests agent traces, preserves an immutable audit log, maps behavior to control frameworks, and packages evidence into forms auditors can consume.

## Key Features

- Immutable hash-chained action log
- Signed checkpoints with Ed25519 or ECDSA signatures and external anchor records
- Agent-agnostic ingestion via OpenTelemetry and SDK events
- Policy mapping for EU AI Act, NIST AI RMF, SR 11-7, HIPAA, and custom frameworks
- Human oversight capture for approvals, escalations, overrides, and kill switches
- Auditor-ready evidence export in PDF and JSON
- REST API and CLI for ingestion, verification, query, and export workflows
- Web dashboard surface for investigators, risk teams, and internal audit

## Quick Start

### Python SDK

```bash
pip install trailing
```

```python
from trailing import TrailingClient

client = TrailingClient("http://localhost:3001", api_key="your-key")
client.ingest(agent="my-agent", action_type="tool_call", payload={"tool": "search"})
```

Adapter for your framework:

```bash
pip install trailing[claude]    # Claude Code hooks
pip install trailing[codex]     # Codex CLI wrapper
pip install trailing[cursor]    # Cursor event capture
pip install trailing[langchain] # LangChain callback
pip install trailing[crewai]    # CrewAI event listener
pip install trailing[openai]    # OpenAI Agents tracer
pip install trailing[all]       # Everything
```

### Rust backend

Install the CLI from the repo:

```bash
cargo install --path .
```

Start the API server:

```bash
trailing serve --port 3001
```

The CLI also honors:

- `TRAILING_PORT`
- `TRAILING_DB_PATH`
- `TRAILING_API_KEY`

Ingest a trace:

```bash
curl -sS -X POST http://127.0.0.1:3001/v1/traces \
  -H 'content-type: application/json' \
  -d '{
    "actions": [
      {
        "session_id": "session-1",
        "agent": "planner",
        "type": "tool_call",
        "timestamp": "2026-03-29T12:00:00Z",
        "payload": { "tool": "search" }
      }
    ]
  }'
```

Check compliance:

```bash
curl -sS http://127.0.0.1:3001/v1/compliance/eu-ai-act
```

You can also ingest OTLP-style JSON traces:

```bash
curl -sS -X POST http://127.0.0.1:3001/v1/traces/otlp \
  -H 'content-type: application/json' \
  -d '{
    "resourceSpans": [
      {
        "scopeSpans": [
          {
            "spans": [
              {
                "traceId": "trace-123",
                "name": "llm.call",
                "agent": "runtime",
                "timestamp": "2026-03-29T12:05:00Z"
              }
            ]
          }
        ]
      }
    ]
  }'
```

## Architecture

```text
+---------+      +-----------+      +---------------+      +---------------+      +------------------+
|  Agent  | ---> | Collector | ---> | Immutable Log | ---> | Policy Engine | ---> | Evidence Export  |
+---------+      +-----------+      +---------------+      +---------------+      +------------------+
     |                 |                    |                       |                         |
     |                 |                    |                       |                         |
     |                 |                    +--> Human Oversight ---+                         |
     |                 |                                                                    +-+-+
     +--> OTel / SDK --+                                                                    |PDF|
                                                                                             |JSON
                                                                                             |API
                                                                                             |CLI
                                                                                             +---+
```

## API Reference

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/v1/health` | Service health and basic status |
| `POST` | `/v1/traces` | Ingest normalized SDK-style agent actions |
| `POST` | `/v1/traces/otlp` | Ingest OTLP-style JSON spans |
| `GET` | `/v1/actions` | Query actions by session, agent, time range, or type |
| `GET` | `/v1/actions/{id}` | Fetch a single action by ID |
| `POST` | `/v1/oversight` | Record a human oversight event |
| `GET` | `/v1/compliance/{framework}` | Generate a framework-specific compliance summary |
| `POST` | `/v1/export/json` | Export audit evidence as JSON |
| `POST` | `/v1/export/pdf` | Export audit evidence as PDF |
| `GET` | `/v1/integrity` | Verify the current hash chain integrity |
| `GET` | `/v1/checkpoints` | List signed checkpoints and key metadata |
| `GET` | `/v1/checkpoints/{id}` | Fetch a signed checkpoint with verification status |

## CLI

The binary currently exposes a small operational surface:

```bash
trailing serve --port 3001
trailing verify
trailing export --format json --framework eu-ai-act
trailing export --format pdf --framework eu-ai-act
trailing query --session session-1 --agent planner --type tool_call
trailing migrate --db ./trailing.db --apply
trailing checkpoint create --algorithm ed25519 --key-id auditor-1 --private-key-hex <hex-seed>
trailing checkpoint list
trailing checkpoint verify --checkpoint-id <checkpoint-id>
trailing proxy --port 3002
trailing watch --dir ~/.claude/projects --agent-type claude --recursive
trailing status
```

## Docker

Build and run with Docker Compose:

```bash
docker compose up --build
```

That command uses SQLite and persists data in the `trailing-data` volume.

To run the API against Postgres instead, use the override file:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up --build
```

The Postgres override starts a `postgres:16-alpine` service, persists database state in the `postgres-data` volume, and points `TRAILING_DB_PATH` at `postgres://trailing:trailing@postgres:5432/trailing` by default. If you change the Postgres credentials or database name, set `TRAILING_DB_PATH` accordingly.

Supported runtime environment variables:

- `TRAILING_PORT`
- `TRAILING_API_KEY`
- `TRAILING_DB_PATH`

The compose setup exposes a container health check on `/v1/health`.

## Postgres Deployment

Trailing accepts a Postgres DSN anywhere `TRAILING_DB_PATH` is used. Set it to a `postgres://` or `postgresql://` connection string before starting the server:

```bash
export TRAILING_DB_PATH='postgres://trailing:trailing@127.0.0.1:5432/trailing'
export TRAILING_API_KEY='replace-me'
trailing serve --port 3001
```

If you want to verify connectivity and initialize the database before serving traffic, open the DSN with any command that loads storage:

```bash
TRAILING_DB_PATH='postgres://trailing:trailing@127.0.0.1:5432/trailing' trailing status
```

For Postgres, schema migrations run automatically the first time Trailing opens the DSN. The `trailing migrate` command is for the SQLite ledger migration path; you do not need a separate manual migration step for a fresh Postgres deployment.

## SSO / SAML

SAML assertion validation shells out to `python3` and requires the `lxml` and `cryptography` packages to be installed in that Python environment:

```bash
python3 -m pip install lxml cryptography
```

The current SAML IdP configuration API is backed by the SQLite tenant store. Use this flow on SQLite-backed deployments.

Configure your IdP against Trailing's assertion consumer service:

- ACS URL: `http://127.0.0.1:3001/v1/sso/saml/<org-id>/acs`
- SP entity ID: your Trailing service identifier, for example `trailing-local`
- IdP metadata you need in Trailing: entity ID, SSO URL, signing certificate PEM

Upload the SAML configuration with an admin API key or admin bearer session:

```bash
curl -sS -X PUT http://127.0.0.1:3001/v1/admin/orgs/<org-id>/sso/saml \
  -H "content-type: application/json" \
  -H "x-api-key: $TRAILING_API_KEY" \
  -d '{
    "enabled": true,
    "idp_entity_id": "https://idp.example.com/metadata",
    "sso_url": "https://idp.example.com/sso",
    "idp_certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "sp_entity_id": "trailing-local",
    "acs_url": "http://127.0.0.1:3001/v1/sso/saml/<org-id>/acs",
    "email_attribute": "email",
    "first_name_attribute": "first_name",
    "last_name_attribute": "last_name",
    "role_attribute": "groups",
    "role_mappings": {
      "Trailing Admins": "admin",
      "Trailing Auditors": "auditor"
    },
    "default_role": "auditor"
  }'
```

After that, POST the IdP's `SAMLResponse` to `/v1/sso/saml/<org-id>/acs`. Trailing validates the assertion, provisions the user if needed, and returns a `session_token` you can use as a bearer token for authenticated API requests.

## Dashboard

The embedded dashboard is served from the same process at `http://127.0.0.1:3001/dashboard`.

When the dashboard opens it prompts for an API key. Enter the same value you configured in `TRAILING_API_KEY`, or another valid Trailing API key, and the UI will use it to query `/v1/actions`, `/v1/compliance/*`, `/v1/integrity`, and export endpoints.

## Proxy Mode

Use proxy mode when you want Trailing to sit in front of LLM API traffic:

```bash
trailing proxy --port 3002
```

By default the proxy watches `api.openai.com` and `api.anthropic.com`. To add or restrict hosts, pass `--upstream-host` multiple times:

```bash
trailing proxy \
  --port 3002 \
  --upstream-host api.openai.com \
  --upstream-host api.anthropic.com
```

Then point your client at the proxy:

```bash
export HTTP_PROXY=http://127.0.0.1:3002
export HTTPS_PROXY=http://127.0.0.1:3002
```

Trailing records proxy tunnel events for HTTPS `CONNECT` traffic and records request or response summaries for proxied HTTP calls it can parse, including provider, model, prompt preview, response preview, token counts, and estimated cost.

## File Watcher

Use watcher mode to tail Claude or Codex session files and ingest them continuously:

```bash
trailing watch --dir ~/.claude/projects --agent-type claude --recursive
trailing watch --dir ~/.codex/sessions --agent-type codex --recursive
```

You can watch multiple directories in one process. Pass one `--agent-type` for every `--dir`, or a single `--agent-type` to apply to all directories:

```bash
trailing watch \
  --dir ~/.claude/projects \
  --dir ~/.codex/sessions \
  --agent-type claude \
  --agent-type codex \
  --recursive
```

The watcher scans supported `.json` and `.jsonl` session files, understands both Claude and Codex transcript formats, and deduplicates ingested events across repeated scans.

## Regulatory Frameworks Supported

- EU AI Act
- NIST AI RMF
- SR 11-7
- HIPAA
- FDA 21 CFR Part 11
- Custom TOML-defined internal frameworks

The current Rust crate ships built-in policy controls for EU AI Act and NIST AI RMF, exposes framework identifiers for SR 11-7, HIPAA, and FDA 21 CFR Part 11, and supports loading custom frameworks from TOML for organization-specific controls.

## Repository Layout

```text
.
|-- Cargo.toml
|-- Dockerfile
|-- docker-compose.yml
|-- examples
|   |-- README.md
|   |-- demo.sh
|   |-- hooks
|   |   |-- README.md
|   |   `-- claude-trailing.sh
|   |-- langchain
|   |   |-- README.md
|   |   `-- trailing_callback.py
|   |-- langchain-callback
|   |   `-- trailing_callback.py
|   |-- crewai
|   |   |-- README.md
|   |   `-- trailing_crewai.py
|   |-- node-sdk
|   |   |-- README.md
|   |   |-- package.json
|   |   `-- trailing.js
|   `-- python-sdk
|       |-- README.md
|       `-- trailing.py
|-- src
|   |-- api
|   |-- cli
|   |-- collector
|   |-- export
|   |-- oversight
|   |-- policy
|   `-- storage
|-- tests
`-- vendor
```

## License

Apache 2.0. See [LICENSE](LICENSE).
