# YC S26 Pitch — Trailing

## One-liner
Independent audit system of record for autonomous AI agents in regulated industries.

## Problem
Companies are deploying AI agents that write code, process patient records, handle legal documents, and make financial decisions. Nobody can answer: "What did the agent do, why, and was it compliant?" Right now the answer is grep through logs and pray. That doesn't fly in healthcare, finance, or legal — regulators will come knocking and there's nothing to show them.

## Solution
Drop-in agent monitoring that records every action, decision, and outcome across any AI agent (Claude, Codex, Copilot, Gemini). Full provenance chain. Automatic compliance reports mapped to SOC2/HIPAA/legal discovery requirements. Real-time guardrails that kill agent sessions when they violate policy. Cross-agent orchestration so you can run multiple agents with enforced boundaries.

## Why now
2025-2026 is the year enterprises actually deployed agents. W26 had 56 fully autonomous agent companies. Every one of their customers will need to prove to auditors what those agents did. The compliance gap is about 12 months from becoming a crisis.

Key regulatory deadlines:
- EU AI Act: Articles 12/13/14 require logging, transparency, human oversight. Enforcement begins Aug 2, 2026. Penalties up to 35M EUR or 7% of global turnover.
- FDA 21 CFR Part 11: Immutable audit trails for anything touching clinical systems.
- SR 11-7: Governance, validation, controls for AI models in banking.
- NIST AI RMF: Maps directly to agent audit trails (GOVERN, MEASURE, MANAGE).

## Why existing tools don't solve this
Three clusters, none of which are the answer:

1. **Engineering observability** (Langfuse, Arize, Galileo) — answers "is my model working?" not "can I prove to a regulator what the agent did?" Ephemeral, sampled data. Not legally defensible under 21 CFR Part 11 or EU AI Act Article 12.
2. **Security governance** (Zenity) — answers "is something unauthorized happening?" not "here's the evidence package for the audit." Protects the boundary but doesn't audit the autonomous workflow inside.
3. **Model governance** (Monitaur, Credo AI) — answers "are our AI policies documented?" not "here's the step-by-step execution trail of this agent's autonomous actions."

The gap: telemetry is not compliance evidence. You cannot retrofit an ephemeral metrics pipeline into a cryptographically immutable, append-only ledger by adding a dashboard.

## What we build
- **Immutable action trail.** Every agent decision, tool call, external system write, and context retrieval — hash-chained, tamper-evident, WORM-compliant. Not sampled. Not overwritten.
- **Human oversight capture.** Who approved, who overrode, who was notified, what was escalated. Articles 14 and 72 of the EU AI Act require this. Nobody captures it cleanly today.
- **Policy-to-proof mapping.** Map agent behavior directly to regulatory controls — EU AI Act Articles 12/13/14, NIST AI RMF GOVERN/MEASURE/MANAGE, SR 11-7, HIPAA. Compliance officers see controls, not spans.
- **Auditor-ready evidence packages.** One-click export of everything a regulator or internal auditor needs: action timeline, authorization chain, policy compliance status, exception log, retention proof.
- **Vendor-neutral.** Works across Claude, GPT, Gemini, Copilot, open-source agents. The company that builds the agent cannot also be its independent auditor — regulated buyers need separation of duties.

## Traction
Working product with 79 tests passing. Built in Rust (15K+ lines). Immutable hash-chained action log, real compliance evaluation across 5 regulatory frameworks, REST API, CLI, web dashboard, SDKs (Python, Node, LangChain, CrewAI), Docker deployment, CI/CD pipeline. Not starting from zero.

No external users yet — this is the gap to close before May 4.

## Market
Bottom-up: 500-2,700 healthcare and financial institutions have deployed or are piloting autonomous agents. At 5% capture and $50K-$200K ACV, near-term wedge is $1.25M-$16.6M ARR across just two verticals.

## Why agents won't eat this
Anthropic and OpenAI don't want compliance liability. They'll build safety features into their models but they won't certify that their agent was HIPAA-compliant in your environment. That's our job. There's an inherent conflict of interest in having the system that runs the AI also act as its independent auditor.

## Competitive landscape
- **Direct-ish:** Galileo ($68M), LangSmith (acquired by ClickHouse), AgentOps (maintenance mode), Arize ($135M), Zenity ($55M)
- **Adjacencies:** Lakera, WhyLabs, Protect AI, Credo AI, Holistic AI
- **Incumbent/platform risk:** Datadog, Splunk, AWS, Google, Microsoft, OpenAI
- **Open-source floor:** Langfuse, OpenLIT, Phoenix OSS, OpenTelemetry

17+ YC-funded companies in adjacent space. None cleanly own "independent audit system of record for agent execution."

## Team
Solo technical founder. Built the full product. Deep in the agent infrastructure stack.

## Ask
$500K. First hire is a compliance domain expert (healthcare or fintech regulatory background). Ship enterprise pilot with 3 regulated organizations in 90 days. Target: evidence of buyer pull before Demo Day.

## An honest note
The idea is strong. The positioning is defensible. The timing is right. But founder-market fit is the weakest link. Compliance buyers in healthcare and banking purchase from people who speak their regulatory language fluently, have domain credibility, and can survive 12-month procurement cycles. The first hire isn't an engineer — it's someone who has sat across the table from an OCC examiner or an FDA auditor and knows what "show me the evidence" actually means in practice. The real question this application is asking isn't "is there a market?" — it's "can this founder assemble the team and credibility to sell into it fast enough?" That's what the $500K is for.
