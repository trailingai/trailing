# Competitive Landscape — Trailing

## Executive Summary

The closest competitors are not all competing for the same budget. The field splits into three clusters: **engineering observability/evals** (Langfuse, Arize/Phoenix, Galileo, AgentOps), **security/governance for enterprise AI surfaces** (Zenity), and **model governance for regulated enterprises** (Monitaur). The strongest wedge for a new entrant is **becoming the compliance system of record that translates agent behavior into auditor-ready evidence, approvals, policy mapping, retention, and exception handling**. That gap is real today.

## The 6 Closest Threats

### 1. Galileo AI
- **Funding:** $68M total ($45M Series B Oct 2024, Scale Venture Partners)
- **Pricing:** Free (5K traces/mo), Pro ($100/mo), Enterprise (custom)
- **Customers:** Twilio, Comcast, HP, ServiceTitan, Clearwater Analytics
- **Gap for compliance buyer:** Engineering evaluation/guardrail tool. No policy-to-control mapping, regulatory obligation inventory, approval workflows, attestations, or auditor workflows.
- Source: https://galileo.ai/pricing

### 2. AgentOps
- **Funding:** $2.6M pre-seed (Aug 2024, 645 Ventures)
- **Status:** In maintenance mode as of early 2026
- **Gap:** Developer trace/debug tool. No governance workflows, policy mapping, or enterprise compliance depth.
- Source: https://docs.agentops.ai/v0/introduction

### 3. Zenity
- **Funding:** $55M+ total ($38M Series B Oct 2024, Third Point Ventures, DTCP, M12)
- **Customers:** Varonis, Telit Cinterion
- **Gap:** Security-native (securing enterprise AI agents/copilots). Adjacent to but not identical with an independent audit/compliance system of record. No deep cross-platform action replay or canonical audit evidence packs.
- Source: https://zenity.io/company

### 4. Langfuse
- **Funding:** ~$4M seed (YC W23, Lightspeed)
- **Status:** Acquired by ClickHouse Jan 2026
- **Compliance surface:** SOC 2 Type II, ISO 27001, HIPAA BAA, audit logs on Enterprise ($2,499/mo)
- **Gap:** Engineering platform. Compliance story is about security/retention/deployment posture, not full regulatory workflow management.
- Source: https://langfuse.com/pricing

### 5. Arize / Phoenix
- **Funding:** $135M+ total ($70M Series C Feb 2025)
- **Customers:** Spotify, Uber, PepsiCo, Priceline, Booking.com
- **Gap:** AI engineering observability. Does not present as compliance owner's source of truth for regulatory obligations, sign-offs, or enterprise policy enforcement.
- Source: https://arize.com/customers/

### 6. Monitaur
- **Funding:** ~$13M total ($6M Series A May 2024)
- **Customers:** Progressive, Unum, Nayya
- **Gap:** Closest to governance workflows, but historically model-governance centric (insurance), not agent-runtime audit trail centric.
- Source: https://www.monitaur.ai/

## YC Companies in Adjacent Space

| Company | Batch | Positioning | Status |
|-|-|-|-|
| Langfuse | W23 | LLM engineering/observability | Acquired by ClickHouse |
| Helicone | W23 | LLM observability/logging | Active |
| Truthsystems | S25 | Compliance agent for generative AI | Active |
| Golf | P25 | Agentic AI security/governance | Active |
| Sphinx | — | AI compliance for banks/fintechs | Active |
| Delve | — | AI compliance automation | Active (45 employees) |
| Agentic Fabriq | — | Identity/governance for AI agents | Active |
| Cardamon | — | AI compliance for financial businesses | Active |
| Regology | — | AI agents for regulatory compliance | Active |

## Competitive Positioning

The strongest positioning is: **independent compliance evidence layer for agentic work** — vendor-neutral, regulation-mapped, immutable/tamper-evident provenance, human approvals and kill-switches, and auditor-ready exports for specific high-stakes workflows.

## The Kill Question

**Steel-man:** "This will collapse into existing categories within 12 months."

Evidence for: Langfuse already has audit logs + SOC2 + HIPAA BAA. Arize adding compliance hooks. Zenity targeting agent governance. OTel standardizing tracing. Buyers prefer consolidated vendors.

**Where it breaks down:** Telemetry is not compliance evidence. Observability tools use ephemeral, sampled data. Compliance needs immutable WORM storage. The company that builds the agent AND audits it has a conflict of interest. Reorganizing product and GTM around the compliance buyer is harder than shipping audit-log endpoints.

A new entrant is justified **only if** it is visibly **not** "another observability vendor."
