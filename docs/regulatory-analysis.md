# Regulatory Analysis — Trailing

## EU AI Act

### High-risk system obligations
- **Article 12 (Logging):** High-risk AI systems must automatically record events over system lifetime for traceability. Logs must capture start/end time, reference databases, input data.
- **Article 13 (Transparency):** Systems must be sufficiently transparent so deployers can interpret outputs and use them appropriately.
- **Article 14 (Human Oversight):** Systems must support meaningful, documented oversight by trained personnel to intervene or override.
- **Article 19 (Retention):** Providers must keep logs for at least six months unless other law specifies otherwise.
- **Article 72 (Post-market monitoring):** Ongoing monitoring and incident reporting required.

### Enforcement timeline
- Entered into force: August 1, 2024
- Fully applicable: **August 2, 2026** (some provisions earlier/later)
- Some high-risk categories may extend to December 2027 or August 2028

### Penalties
Up to **35M EUR or 7% of global annual turnover**.

Source: https://artificialintelligenceact.eu/article/12/

## FDA / US Healthcare

### 21 CFR Part 11
When an autonomous AI agent writes to an electronic system of record (modifying clinical narratives, triaging safety signals, logging decisions), it falls under 21 CFR Part 11:
- Closed-system controls
- **Immutable audit trails**
- Data integrity based on ALCOA+ principles (Attributable, Legible, Contemporaneous, Original, Accurate)

A generic observability tool that drops spans or overwrites old logs cannot legally meet these requirements.

### FDA AI/ML guidance
- Jan 2025 draft: AI-enabled device software functions — lifecycle risk management
- Aug 2025 final: PCCP guidance — predetermined change control plans for AI modifications

Source: https://www.fda.gov/regulatory-information/search-fda-guidance-documents/artificial-intelligence-enabled-device-software-functions-lifecycle-management-and-marketing

## US Banking (SR 11-7)

SR 11-7 describes model risk management including:
- Robust development, implementation, and use
- Sound validation
- Governance/control mechanisms including board and senior management oversight
- Authority to restrict model usage

AI agents making/influencing decisions in banking fall within this governance logic. Banks need validation, monitoring, documentation, escalation, override, and usage restrictions.

### US Treasury FS AI RMF (Feb 2026)
230 specific control objectives to operationalize continuous governance for financial AI.

Source: https://www.federalreserve.gov/supervisionreg/srletters/sr1107a1.pdf

## NIST AI RMF

Most relevant mappings for "agent action audit trail":
- **MAP 2.2:** Document knowledge limits and how outputs should be overseen
- **MEASURE 3.1:** Regular approaches to identify/track existing and emergent risks
- **MANAGE 4.1:** Post-deployment monitoring including appeal, override, decommissioning, incident response
- **Appendix C:** Human roles/responsibilities, override frequency tracking

Source: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf

## Enforcement Actions (2024-2026)

No agent-specific enforcement action yet, but adjacent signals:
- FTC Operation AI Comply (Sept 2024): targeting deceptive AI claims
- FTC vs Rytr (set aside Dec 2025)
- SEC/DOJ "AI washing" focus including Nate case (2025)
- Healthcare: AI-assisted denial controversies, Section 1557 nondiscrimination pressure

**The forcing function is "compliance fear + supervisory expectation + litigation risk" more than a stack of fines.** Market opens with risk leaders and early adopters, then expands after first high-profile enforcement.

Source: https://www.ftc.gov/news-events/news/press-releases/2024/09/ftc-announces-crackdown-deceptive-ai-claims-schemes

## Implication for Trailing

The most commercially useful wedge is: **operationalize Articles 12/13/14/72/73 into durable evidence** — who acted, what the agent did, what the human saw, what was overridden, what changed, and what incident trail exists. Not "we help with AI Act generally" but specific, provable, exportable evidence.
