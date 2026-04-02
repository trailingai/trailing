# Trailing -- Full Subtask Breakdown

Consolidated from 9 parallel Codex agent investigations of the Trailing codebase.

---

## 1. Ingestion Layer

### Current State
- REST ingest exists via `/v1/traces` and `/v1/traces/otlp`, plus a separate `src/ingest/mod.rs` path and a Rust collector; normalization/classification logic is duplicated across three modules (`src/api`, `src/ingest`, `src/collector`).
- The core semantic model is coarse: only 6 `ActionType` enums with heuristic string-matching classification; no first-class audit event taxonomy for LLM requests/responses, retrievals, external writes, or decision points.
- SDK integrations (Python, Node, LangChain, CrewAI, Claude Code hook) exist only as example files with sys.path hacks; the watcher only supports Claude and Codex logs; the proxy only intercepts OpenAI and Anthropic hosts with 512-char truncation.

### Subtasks
1. [M] Define a canonical versioned audit-event schema with typed events for `tool_call`, `tool_result`, `llm_request`, `llm_response`, `retrieval`, `external_write`, `decision_point`, and `policy_check`.
2. [L] Unify the Rust ingestion pipeline into one normalization/classification/append path used by API, watcher, proxy, and collector.
3. [L] Migrate storage for full-fidelity envelopes: schema changes for event kind, schema version, correlation IDs, org/idempotency keys, and preserved request/result metadata.
4. [L] Upgrade the ingest API contract: strict validation, batch partial-failure semantics, org-scoped API keys, idempotency keys, and configurable redaction.
5. [L] Ship a publishable Python core SDK with sync/async client, background queue, retries, batching, typed event builders, and redaction config.
6. [L] Ship a publishable Node/TypeScript core SDK with typed events, transport abstraction, batching, retries, and shared config.
7. [L] Build the LangChain adapter on top of the Python SDK capturing LLM start/end, streaming tokens, tool start/end/error, retriever events, and chain transitions.
8. [M] Build the CrewAI adapter on top of the Python SDK capturing crew/task lifecycle, agent execution, tool calls/results, retrieval/memory, delegation, and approvals.
9. [L] Productize Claude Code ingestion: supported hook/watcher integration capturing tool calls/results, messages, file reads/writes, reasoning events, and transcript reconciliation.
10. [L] Build an OpenAI Agents adapter capturing model requests/responses, tool executions, handoffs, retrieval, guardrails, and run/span correlation.
11. [L] Build an AutoGPT adapter capturing planner steps, command execution, memory retrieval, file/API writes, cycle state, and branch decisions.
12. [M] Add reusable write/retrieval/policy instrumentation helpers so adapters emit canonical events instead of relying on action-name heuristics.
13. [L] Build the compatibility and replay test matrix: schema contract tests, golden fixtures, replay/idempotency tests, privacy/redaction tests, and E2E harnesses.

---

## 2. Immutable Ledger

### Current State
- The persisted ledger is `log::ActionEntry` with SHA-256 hash chain (`previous_hash` + `entry_hash`), a fixed genesis hash, and sidecar `.root` anchor file; SQLite triggers reject UPDATE and most DELETE operations.
- `verify_chain` recomputes hashes, checks linkage, compares full-chain head to the root anchor, and records results in `chain_integrity_checks`; tests cover payload tampering and forged suffix rewrites.
- Retention exists as `RetentionPolicy { min_retention_days, legal_hold }` but enforcement is a global legal-hold check plus `purge_expired` which physically deletes rows and rewrites the anchor. A duplicate in-memory `ActionLog` model exists in `src/action_log.rs`.

### Subtasks
1. [L] Build a backend-neutral ledger core and collapse duplicate action models into one canonical ledger record/proof surface.
2. [M] Define a versioned canonical hashing spec for entries and checkpoints, including canonical JSON serialization and algorithm/version identifiers.
3. [L] Rebuild the SQLite backend around immutable ledger/checkpoint tables, remove `allow_purge`-style delete toggling, and eliminate silent re-anchoring on startup.
4. [L] Add a real retention/legal-hold domain: persisted hold records, retention windows, release events, and policy enforcement blocking destructive operations before expiry.
5. [L] Add signed checkpoints and external anchors so an auditor can verify a checkpoint without trusting the database alone.
6. [L] Implement Merkle batching for efficient bulk verification and inclusion proofs per checkpoint interval.
7. [L] Add a PostgreSQL backend with the same ledger semantics, migrations, and least-privilege write model for production.
8. [M] Build a verification/proof service supporting full-chain, range, checkpoint, and Merkle inclusion proof validation.
9. [M] Populate auditor-facing proof artifacts in exports and APIs instead of emitting empty proof arrays.
10. [L] Add migration/backfill tooling from the current `action_log` table to the new immutable-ledger/checkpoint model.
11. [L] Add adversarial and cross-backend tests for trigger bypass, restart with missing anchor, checkpoint signatures, Merkle proofs, legal holds, and SQLite/Postgres parity.

---

## 3. Human Oversight

### Current State
- Oversight primitives exist: `Approval`, `Override`, `Escalation`, and `KillSwitch` events with fields like `reviewer`, `modified_entry_id`, `reason`, `new_outcome`, but no first-class human identity or role object.
- The API exposes `POST /v1/oversight` accepting arbitrary JSON, deriving only `severity`, `note`, `framework`, `session_id`, and `timestamp`; the stored actor is synthetic (`oversight/api`), not the human approver.
- EU AI Act compliance (Art. 14/72) is heuristic: "human oversight" evidence is based on oversight-to-action ratio; auth is a single shared `x-api-key`; the dashboard has a reviewer/approver field mismatch.

### Subtasks
1. [L] Define a canonical oversight schema for `HumanIdentity`, `HumanRole`, `ApprovalDecision`, `OverrideDecision`, `NotificationReceipt`, `EscalationCase`, `CheckpointPolicy`, and `CheckpointDecision`.
2. [L] Add normalized storage for oversight evidence with indexes for queryability by action, human, role, session, and case.
3. [L] Wire real request auth into the API so every human intervention is attributable to an authenticated principal and role.
4. [M] Replace the free-form `/v1/oversight` payload with typed oversight endpoints or a typed discriminator schema plus strict validation.
5. [M] Build approval capture storing approver ID, role, authority basis, target action hash/ID, timestamp, and justification.
6. [M] Build override capture storing verified actor identity, role, prior decision state, new disposition, mandatory reason, and originating action linkage.
7. [L] Add notification delivery-proof capture: recipient, channel, provider receipt, delivery status, timestamps, and acknowledgment.
8. [L] Add escalation-case tracking with multi-step chains, timestamps, and computed response-time metrics.
9. [L] Build policy-driven HITL checkpoints so oversight requirements are configurable by policy, risk level, tool/action type, or uncertainty state.
10. [M] Rework compliance evidence generation so Art. 14/72 are based on concrete oversight facts, not count/ratio heuristics.
11. [M] Upgrade export and dashboard surfaces to preserve and display full oversight evidence.
12. [M] Reconcile or retire the legacy in-memory action-log model and add E2E tests for immutable oversight capture, auth attribution, notification receipts, escalation SLAs, and checkpoint enforcement.

---

## 4. Policy Engine

### Current State
- `PolicyEngine` is an in-memory `HashMap<Framework, Vec<Control>>`; controls only have `id`, `framework`, `article`, `requirement`, and `evidence_requirements` -- no rule logic, scope, severity, versioning, or inheritance.
- Built-in frameworks (EU AI Act, HIPAA, FDA 21 CFR Part 11, SR 11-7, NIST AI RMF) are hard-coded keyword catalogs; evaluation is normalized substring matching against action/evidence strings.
- Custom frameworks exist only as a TOML parser into the same flat shape, registered in-memory only; the API rejects `Framework::Custom`. Compliance scoping is session/time only, not org/project-aware.

### Subtasks
1. [L] Define a structured compliance fact model replacing the token-bag with facts for action type, timestamps, actor, tool, target, oversight linkage, and evidence provenance.
2. [M] Create a versioned policy schema for YAML/JSON with typed policy packs, controls, rules, severity, scope, inheritance, citations, and effective dates.
3. [L] Add a persistent policy registry storing policy definitions, versions, status, effective windows, and scope assignments in SQLite.
4. [L] Implement scope resolution and inheritance: built-in framework baseline + org defaults + project overrides + custom extensions with conflict rules and auditability.
5. [L] Replace substring matching with a real rules evaluator: predicate execution over structured facts with `all/any/not`, threshold checks, temporal windows, joins, and explicit evidence selection.
6. [L] Externalize built-in framework catalogs as versioned YAML/JSON files with clause citations and rule definitions.
7. [M] Productize custom policy authoring: API and CLI flows to upload, validate, lint, diff, dry-run, and activate org-specific policies without code changes.
8. [L] Persist evaluation results and provenance: store evaluation runs with scope, policy version, evaluator version, input window, evidence refs, and control results.
9. [M] Add severity to controls and violations: `critical/high/medium/low` on controls plus derived violation severity and weighted scoring.
10. [M] Rewire compliance and export endpoints to use the versioned policy registry and rule evaluator; remove `action_count > 0` / `oversight_count > 0` placeholders.
11. [L] Add org/project-aware policy selection: resolve active policy by tenant and project, not just session/time.
12. [M] Build a regulatory fixture and regression suite: golden tests for EU AI Act, HIPAA, FDA Part 11, SR 11-7, NIST AI RMF, plus versioning, inheritance, and custom-policy scenarios.

---

## 5. Realtime Guardrails

### Current State
- A proxy mode exists but is a logger, not an enforcer: it forwards upstream first and only summarizes/logs after the response returns; `CONNECT` traffic only records tunnel metadata then blindly tunnels TLS bytes.
- API middleware exists but protects Trailing's own API (shared key check + per-IP rate limit), not provider calls; live SSE events exist for ingested actions/oversight but are not used for blocking.
- Policy evaluation is retrospective compliance scoring only; kill-switch is a logged oversight event with no enforcement; no PII/PHI detection, tool allowlists, or alert delivery mechanism.

### Subtasks
1. [M] Guardrail core types and config: provider-neutral `InterceptedCall`, `GuardrailDecision`, severity, and failure-mode config.
2. [L] HTTPS interception foundation: replace opaque CONNECT pass-through with explicit forward-proxy/TLS MITM support and local CA/cert plumbing.
3. [L] Provider adapters and normalization: normalize OpenAI/Anthropic request/response bodies, tool schemas, session IDs, and streaming frames into one internal model.
4. [L] Real-time policy engine: request-time and response-time evaluation returning `allow`, `flag`, or `block` with matched rule IDs and rationale.
5. [M] Org/auth context plumbing: replace shared env-key-only path with storage-backed API keys/org IDs and org-scoped audit records.
6. [M] Proxy-time rate limiting: token-bucket limits keyed by `org_id + agent_id + provider (+ model)` before upstream calls.
7. [L] Sensitive-data detection and redaction: scan prompts, tool arguments, and completions for PII/PHI, support redaction, feed hits into policy decisions.
8. [M] Tool allowlist/blocklist enforcement: evaluate requested tools/functions against policy by provider, agent, and org.
9. [L] Session registry and kill-switch enforcement: live session state, critical-violation counters, and manual kill status for short-circuiting future calls.
10. [M] Violation records and alert fan-out: persist violations, expose via API/SSE, add webhook delivery with retry/backoff.
11. [M] Graceful degradation controls: evaluator timeouts, health probes, cached policy snapshots, and configurable fail-open vs fail-closed.
12. [M] End-to-end guardrail tests: MITM proxying, streaming, block/allow/flag, kill switch, org rate limits, PII/PHI detection, alert delivery, and failure modes.

---

## 6. Evidence Packages

### Current State
- Core `EvidencePackage` types exist in `src/export/mod.rs` with metadata, chain-integrity status, and compliance results; a PDF exporter renders generic sections; a richer JSON exporter exists in `src/export/json.rs` but the live API does not use it.
- Production `POST /v1/export/json` returns a simpler ad hoc payload bypassing package hash, control results, and proof slots; `POST /v1/export/pdf` uses only three generic `AP-*` controls (`action_count > 0`, `oversight_count > 0`).
- Oversight export is lossy (drops `agent_id`, flattens details); the ledger leaves `proofs` empty; retention/legal-hold metadata is incomplete; no CSV export exists; framework-specific templates do not exist.

### Subtasks
1. [M] Unify the production export contract around `EvidencePackage` and `JsonEvidenceExport`.
2. [M] Expose export scoping by session, time range, agent, action type, and legal-hold state, wiring existing filter logic into API and CLI.
3. [M] Build a canonical combined timeline model for actions, oversight, and exception events with stable ordering and cross-links.
4. [L] Add an authorization-chain model capturing approver identity, org, role, auth source, authority basis, target artifact, and timestamp.
5. [M] Create a first-class exception log for overrides, escalations, kill switches, policy failures, waivers, and unresolved follow-ups.
6. [L] Replace generic `AP-*` package controls with real framework-evaluated control results and evidence references from the policy engine.
7. [L] Populate chain-of-custody proofs from the hash ledger, root anchor, and integrity-check records; emit a detached manifest/hash tree.
8. [M] Extend package metadata with retention period, expiry, legal-hold status/reason, generation provenance, and export job identifiers.
9. [M] Add CSV export for timeline rows, control results, and exception logs.
10. [L] Add framework-specific template descriptors for EU AI Act, HIPAA, FDA, NIST AI RMF, and SR 11-7 so PDF/JSON sections are framework-aware.
11. [S] Consolidate or retire the duplicate in-memory `src/action_log.rs` path so there is one evidence/timeline source of truth.
12. [M] Lock the new package contract with E2E tests, schema updates, and docs.

---

## 7. Multi-Tenant Auth

### Current State
- The running API is single-tenant with an optional shared secret (`x-api-key` env check); a half-implemented storage-layer API key system exists (CRUD/auth functions in SQLite) but has no HTTP routes or CLI commands.
- Tenant hooks exist only in storage: `action_log` has nullable `org_id` and org-aware methods, but API ingest/query paths always use unscoped methods; `RequestAuth { key_id, org_id, is_admin }` is defined but unused.
- RBAC is not implemented; the admin model is global (singleton `app_settings.admin_key_id`); rate limiting is per-IP only; per-org config does not exist; auth events are not written to the audit ledger.

### Subtasks
1. [L] Build the tenant catalog and project model; make audit rows tenant-scoped by schema rather than convention.
2. [L] Refactor every read/write path to require resolved org and project context; remove unscoped use of `entries()` and `append_action_at()`.
3. [L] Add a principal model for human users, org memberships, and five required roles (admin, compliance officer, developer, auditor, read-only).
4. [L] Replace the ad hoc key record with a first-class credential model for API keys and service accounts: scope-by-project, expiry, rotation lineage, creator metadata, and revocation reason.
5. [L] Build authentication middleware resolving request auth from session, SSO assertion, API key, or service account token.
6. [M] Implement route-level authorization and a permission matrix for all roles with separate permissions for export, config, key management, and org admin.
7. [M] Add a per-org configuration store for retention policies, enabled frameworks, and guardrail settings threaded into compliance/export.
8. [M] Add append-only auth/security audit events for all identity actions, queryable/exportable without mixing org data.
9. [L] Implement enterprise SSO/SAML with per-org IdP config, ACS endpoints, signed assertion validation, and JIT provisioning.
10. [M] Add MFA for human accounts with enrollment, challenge, recovery codes, and enforcement policy hooks.
11. [M] Replace the IP-only limiter with per-org/per-key/service-account quotas that work across instances.
12. [M] Expose management surfaces for orgs, memberships, keys, service accounts, SSO, MFA, and settings through API and CLI; add E2E cross-org isolation tests.

---

## 8. Dashboard

### Current State
- The dashboard is a single embedded HTML file served at `/dashboard` polling four endpoints every 5 seconds; functional UI includes sidebar view switching, log table with client-side filters, oversight list, and hash-chain list.
- Many UI elements are decorative or misleading: `Today/7D/30D`, `Logs/Stream` tabs, date selector, `View all` links, and `Manage` buttons have no listeners; compliance tab always fetches `eu-ai-act` using hardcoded client-side heuristics instead of backend control results; the existing SSE stream is not consumed.
- Org/project scoping is not wired; protected deployments break the dashboard (no API key in fetches); drill-down is shallow (raw `JSON.stringify`); no session timeline, alert feed, search, user management, or configuration UI.

### Subtasks
1. [M] Split the inline dashboard into a maintainable, responsive app shell with separate JS/CSS modules.
2. [L] Wire real auth and tenant context through the API and dashboard.
3. [M] Replace polling with SSE-driven live state reconciliation.
4. [L] Add a first-class active-sessions backend and "what's running now" UI.
5. [L] Build real compliance-overview aggregations by org, framework, and project.
6. [L] Add an alerts pipeline and feed for policy violations, guardrail triggers, and anomalies.
7. [L] Expose session/action drill-down APIs with trace/span/related-step linkage.
8. [M] Build the session timeline/Gantt view on top of normalized step timing.
9. [L] Add report-generation endpoints/UI with HTTP-exposed filters paired with search.
10. [L] Build admin UX for invites, roles, and API-key lifecycle.
11. [L] Build configuration UX for policy rules, guardrails, and retention settings.
12. [M] Add dashboard-focused route/UI regression coverage before rollout.

---

## 9. Agent Connectors

### Current State
- Three ingestion paths exist (REST, file watching, TCP proxy) with two parallel normalization stacks (`src/collector/` vs `src/api/` + `src/ingest/`); the watcher only supports Claude and Codex; the proxy only supports OpenAI and Anthropic.
- Persisted classification is coarse (6 action types); the outward `ActionRecord` has no first-class run/thread/span/tool-call/model/token/cost fields; connector-specific detail is buried in `payload` or `context`.
- SDK/integration code is demo-quality under `examples/` with path hacks; agent typing only recognizes claude, codex, cursor, openai, anthropic -- no Gemini, GitHub Copilot, LangGraph, AutoGen, AutoGPT, or custom framework support.

### Subtasks
1. [M] Define a canonical connector event schema and registry.
2. [L] Collapse the duplicated normalizers into one shared path.
3. [L] Extend persistence/query fields for connector correlation IDs and lifecycle metadata.
4. [L] Build a production Anthropic connector covering Claude Code hooks, Claude Code SDK streams, and Messages API tool use.
5. [L] Build a production OpenAI connector for Responses, Assistants, and Agents SDK tracing.
6. [L] Build a Gemini/Google ADK connector for callbacks, ADK events, and Gemini OpenAI-compatible traffic.
7. [L] Build a GitHub Copilot connector ingesting hook events, session logs, and enterprise audit-log events.
8. [M] Promote LangChain and LangGraph from examples to production packages with stable event mapping.
9. [M] Promote CrewAI listener code into a production package with stable event mapping.
10. [L] Add AutoGen and AutoGPT connectors using their native event/logger/component surfaces.
11. [L] Rework the proxy into a real agent gateway instead of a best-effort HTTP sniffer.
12. [L] Split watcher parsing into per-framework modules and add backfill parsers for Claude, Codex, Copilot session logs, and AutoGen/AutoGPT logs.
13. [L] Add connector conformance fixtures and E2E tests for every supported framework and mode.

---

## Summary

### Total Subtask Count

| Component | Subtasks |
|-|-|
| 1. Ingestion Layer | 13 |
| 2. Immutable Ledger | 11 |
| 3. Human Oversight | 12 |
| 4. Policy Engine | 12 |
| 5. Realtime Guardrails | 12 |
| 6. Evidence Packages | 12 |
| 7. Multi-Tenant Auth | 12 |
| 8. Dashboard | 12 |
| 9. Agent Connectors | 13 |
| **Total** | **109** |

### Size Distribution

| Size | Count |
|-|-|
| S | 1 |
| M | 40 |
| L | 68 |

### Dependency Graph

The components have the following blocking relationships (A -> B means A blocks B):

```
Ingestion Layer (1) ──────┬──> Evidence Packages (6)
                          ├──> Realtime Guardrails (5)
                          └──> Agent Connectors (9)

Immutable Ledger (2) ─────┬──> Evidence Packages (6)
                          └──> Realtime Guardrails (5)

Multi-Tenant Auth (7) ────┬──> Dashboard (8)
                          ├──> Realtime Guardrails (5)
                          ├──> Human Oversight (3)
                          └──> Policy Engine (4)

Policy Engine (4) ────────┬──> Realtime Guardrails (5)
                          ├──> Evidence Packages (6)
                          └──> Dashboard (8)

Human Oversight (3) ──────┬──> Evidence Packages (6)
                          └──> Dashboard (8)

Agent Connectors (9) ─────┬──> Ingestion Layer (1) [bidirectional: schema]
                          └──> Dashboard (8)

Realtime Guardrails (5) ──┴──> Dashboard (8)
```

**Critical path:** Multi-Tenant Auth (7) + Ingestion Layer (1) are the two foundational components that unblock the most downstream work. The recommended build order is:

1. **Foundation (parallel):** Ingestion Layer (schema + unified pipeline) + Multi-Tenant Auth (tenant model + auth middleware) + Immutable Ledger (backend abstraction + hashing spec)
2. **Core logic:** Policy Engine (facts + rules evaluator) + Human Oversight (typed schema + storage)
3. **Enforcement:** Realtime Guardrails (interception + inline policy) + Agent Connectors (canonical schema + first connectors)
4. **Surfaces:** Evidence Packages (unified export + proofs) + Dashboard (auth + SSE + drill-down)
