# Demo Guide — Trailing

## Quick start

```bash
# Build
cd ~/projects/agentproof
cargo build --release

# Start server (fresh DB)
rm -f trailing.db
./target/release/trailing serve --port 3099

# In another terminal, seed data:
bash examples/demo.sh  # or manually below
```

## Manual seed data

```bash
# Ingest 10 agent actions
for i in $(seq 1 10); do
  curl -s -X POST http://localhost:3099/v1/traces \
    -H "Content-Type: application/json" \
    -d "{
      \"agent_id\": \"claude-$(printf '%03d' $i)\",
      \"agent_type\": \"claude\",
      \"session_id\": \"ses-demo-1\",
      \"action\": {
        \"type\": \"ToolCall\",
        \"tool_name\": \"query_patient_db\",
        \"target\": \"patient_$((200+i))\",
        \"parameters\": {},
        \"result\": \"completed\"
      },
      \"context\": {
        \"data_accessed\": [\"patient_$((200+i))\"],
        \"permissions_used\": [\"phi_read\"],
        \"policy_refs\": [\"hipaa_minimum_necessary\"]
      }
    }"
done

# Log oversight events
curl -s -X POST http://localhost:3099/v1/oversight \
  -H "Content-Type: application/json" \
  -d '{"event_type":"approval","approver":"dr.chen@mercy-health.org","scope":"Approved automated claims batch CLM-9840 through CLM-9847"}'

curl -s -X POST http://localhost:3099/v1/oversight \
  -H "Content-Type: application/json" \
  -d '{"event_type":"override","approver":"compliance@mercy-health.org","scope":"Blocked agent access to restricted psych records per 42 CFR Part 2"}'
```

## URLs
- Landing page: http://localhost:3099/
- Dashboard: http://localhost:3099/dashboard
- Health check: http://localhost:3099/v1/health
- Actions API: http://localhost:3099/v1/actions
- Compliance: http://localhost:3099/v1/compliance/eu-ai-act
- Chain integrity: http://localhost:3099/v1/integrity

## Demo walkthrough

1. Open http://localhost:3099/ — landing page with hero, problem cards, CTA
2. Click "Book a Demo" → opens dashboard
3. **Dashboard view**: Show 4 metric cards (Compliance Score, Chain Integrity, Total Actions, Oversight Events) + Top Active Agents, Pending Oversight, Recent Sessions
4. **Click Monitoring icon** (sidebar): Show Logs/Stream tabs, filter row, full action table with expandable rows
5. **Click Oversight icon**: Show timeline with approval (green) and override (amber) events
6. **Click Compliance icon**: Show EU AI Act tab with per-control Passing/Failing/Review + click HIPAA/NIST/SR 11-7 tabs
7. **Click Hash Chain icon**: Show connected chain visualization with Genesis tag
8. **Click Export icons** (bottom of sidebar): Download JSON evidence package or PDF

## Key talking points for demo
- "Every agent action is hash-chained — tamper with one entry and the entire chain breaks"
- "Oversight events link to the actions they modified — full audit trail of who approved what"
- "Compliance evaluation maps directly to EU AI Act articles, not a vague percentage"
- "One-click evidence export produces what an auditor actually needs"
- "Works with any agent — Claude, GPT, Gemini, Copilot — no vendor lock-in"

## Known limitations in demo
- Data is seeded manually (no real agent connected yet)
- Compliance evaluation is based on action/oversight counts, not deep analysis
- PDF export is basic (not full evidence package format)
- vendor/uuid is a stub
- No authentication UI (API keys work via CLI but no login page)
