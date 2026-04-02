#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${TRAILING_PORT:-3001}"
BASE_URL="${TRAILING_BASE_URL:-http://127.0.0.1:${PORT}}"
API_KEY="${TRAILING_API_KEY:-}"
DB_PATH="${TRAILING_DB_PATH:-/tmp/trailing-demo-$$.db}"
EXPORT_DIR="${TRAILING_EXPORT_DIR:-/tmp/trailing-evidence-$$}"
SERVER_LOG="/tmp/trailing-demo-server-$$.log"
RATE_LIMIT="${TRAILING_RATE_LIMIT:-500}"
DASHBOARD_URL="${BASE_URL}/dashboard"

mkdir -p "${EXPORT_DIR}"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ -x "${ROOT_DIR}/target/debug/trailing" ]]; then
  TRAILING_API_KEY="${API_KEY}" "${ROOT_DIR}/target/debug/trailing" \
    serve \
    --port "${PORT}" \
    --db "${DB_PATH}" \
    --rate-limit-per-minute "${RATE_LIMIT}" \
    >"${SERVER_LOG}" 2>&1 &
else
  TRAILING_API_KEY="${API_KEY}" cargo run --manifest-path "${ROOT_DIR}/Cargo.toml" -- \
    serve \
    --port "${PORT}" \
    --db "${DB_PATH}" \
    --rate-limit-per-minute "${RATE_LIMIT}" \
    >"${SERVER_LOG}" 2>&1 &
fi
SERVER_PID=$!

python3 - "${BASE_URL}" "${API_KEY}" <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request

base_url, api_key = sys.argv[1:3]
headers = {"accept": "application/json"}
if api_key:
    headers["x-api-key"] = api_key

deadline = time.time() + 30
while time.time() < deadline:
    request = urllib.request.Request(f"{base_url}/v1/health", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
            if payload.get("status") == "ok":
                raise SystemExit(0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        time.sleep(0.25)

print("trailing demo: server did not become healthy in time", file=sys.stderr)
raise SystemExit(1)
PY

python3 - "${BASE_URL}" "${API_KEY}" "${EXPORT_DIR}" "${DASHBOARD_URL}" <<'PY'
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request


BASE_URL, API_KEY, EXPORT_DIR, DASHBOARD_URL = sys.argv[1:5]
FRAMEWORKS = [
    "eu-ai-act",
    "nist-ai-rmf",
    "sr-11-7",
    "hipaa",
    "fda-21-cfr-part-11",
]


def request(method: str, path: str, payload: dict | None = None, expect_json: bool = True):
    headers = {"accept": "application/json"}
    data = None
    if payload is not None:
        headers["content-type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    if API_KEY:
        headers["x-api-key"] = API_KEY

    req = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as response:
        body = response.read()
        if not expect_json:
            return body
        return json.loads(body.decode("utf-8"))


def action(
    *,
    session_id: str,
    agent: str,
    agent_type: str,
    action_type: str,
    timestamp: str,
    target: str,
    parameters: dict,
    result: object,
    context: dict,
    tool_name: str | None = None,
) -> dict:
    payload = {
        "session_id": session_id,
        "agent": agent,
        "agent_id": agent,
        "agent_type": agent_type,
        "type": action_type,
        "timestamp": timestamp,
        "target": target,
        "parameters": parameters,
        "result": result,
        "context": context,
        "status": "ok",
    }
    if tool_name is not None:
        payload["tool_name"] = tool_name
        payload["tool"] = tool_name
        payload["name"] = tool_name
    return payload


actions = [
    action(
        session_id="intake-session-20260330-1",
        agent="triage-agent-01",
        agent_type="gpt",
        action_type="data_access",
        timestamp="2026-03-30T12:00:00Z",
        target="ehr://patients/patient-2048",
        parameters={"patient_id": "patient-2048", "fields": ["demographics", "care_team"]},
        result={"patient_found": True, "pcp": "Dr. Garcia"},
        context={"workflow": "er-intake", "permissions_used": ["phi_read"], "policy_refs": ["hipaa-minimum-necessary"]},
    ),
    action(
        session_id="intake-session-20260330-1",
        agent="triage-agent-01",
        agent_type="gpt",
        action_type="policy_check",
        timestamp="2026-03-30T12:00:05Z",
        target="policy://hipaa/minimum-necessary",
        parameters={"requested_fields": ["demographics", "care_team", "allergies"]},
        result={"allowed": True, "reason": "treatment workflow"},
        context={"workflow": "er-intake", "reviewer_required": False},
    ),
    action(
        session_id="intake-session-20260330-1",
        agent="triage-agent-01",
        agent_type="gpt",
        action_type="tool_call",
        timestamp="2026-03-30T12:00:10Z",
        target="ehr://allergies/patient-2048",
        parameters={"patient_id": "patient-2048"},
        result={"allergies": ["penicillin"], "severity": "high"},
        context={"workflow": "er-intake", "data_accessed": ["allergies"]},
        tool_name="query_allergies",
    ),
    action(
        session_id="intake-session-20260330-1",
        agent="triage-agent-01",
        agent_type="gpt",
        action_type="tool_call",
        timestamp="2026-03-30T12:00:18Z",
        target="ehr://encounters/patient-2048",
        parameters={"lookback_days": 30, "encounter_type": "ed"},
        result={"recent_ed_visits": 2, "most_recent_reason": "shortness of breath"},
        context={"workflow": "er-intake", "data_accessed": ["encounters"]},
        tool_name="summarize_recent_ed_visits",
    ),
    action(
        session_id="intake-session-20260330-1",
        agent="triage-agent-01",
        agent_type="gpt",
        action_type="decision",
        timestamp="2026-03-30T12:00:25Z",
        target="risk://triage-escalation/patient-2048",
        parameters={"model": "triage-priority-v3", "signals": ["allergy-risk", "repeat-ed-visit"]},
        result={"priority": "urgent", "recommended_destination": "observation-unit"},
        context={"workflow": "er-intake", "policy_refs": ["eu-ai-act-risk-management"]},
    ),
    action(
        session_id="readmission-session-20260330-2",
        agent="care-planner-02",
        agent_type="claude",
        action_type="data_access",
        timestamp="2026-03-30T12:05:00Z",
        target="ehr://discharge/patient-8821",
        parameters={"patient_id": "patient-8821", "fields": ["discharge_summary", "care_team"]},
        result={"discharge_date": "2026-03-28", "pcp_followup_scheduled": False},
        context={"workflow": "readmission-prevention", "permissions_used": ["phi_read"], "policy_refs": ["hipaa-treatment-use"]},
    ),
    action(
        session_id="readmission-session-20260330-2",
        agent="care-planner-02",
        agent_type="claude",
        action_type="tool_call",
        timestamp="2026-03-30T12:05:08Z",
        target="ehr://labs/patient-8821",
        parameters={"lookback_days": 14, "panel": "bmp"},
        result={"records_returned": 4, "latest_abnormal": "creatinine"},
        context={"workflow": "readmission-prevention", "data_accessed": ["labs"]},
        tool_name="query_lab_results",
    ),
    action(
        session_id="readmission-session-20260330-2",
        agent="care-planner-02",
        agent_type="claude",
        action_type="tool_call",
        timestamp="2026-03-30T12:05:16Z",
        target="ehr://medications/patient-8821",
        parameters={"include_recent_changes": True},
        result={"high_risk_medications": ["warfarin"], "recent_changes": 3},
        context={"workflow": "readmission-prevention", "data_accessed": ["medications"]},
        tool_name="summarize_medications",
    ),
    action(
        session_id="readmission-session-20260330-2",
        agent="care-planner-02",
        agent_type="claude",
        action_type="decision",
        timestamp="2026-03-30T12:05:26Z",
        target="risk://readmission/patient-8821",
        parameters={"model": "readmission-risk-v2", "signals": ["abnormal-labs", "medication-change", "recent-discharge"]},
        result={"risk_level": "high", "recommended_next_step": "same-day-outreach"},
        context={"workflow": "readmission-prevention", "policy_refs": ["nist-ai-rmf-monitoring"]},
    ),
    action(
        session_id="readmission-session-20260330-2",
        agent="care-planner-02",
        agent_type="claude",
        action_type="system_write",
        timestamp="2026-03-30T12:05:35Z",
        target="careplan://patient-8821/draft",
        parameters={"template": "post-discharge-high-risk"},
        result={"draft_id": "careplan-8821", "status": "created"},
        context={"workflow": "readmission-prevention", "requires_human_review": True},
    ),
    action(
        session_id="readmission-session-20260330-2",
        agent="care-planner-02",
        agent_type="claude",
        action_type="tool_call",
        timestamp="2026-03-30T12:05:43Z",
        target="review://nurse-manager",
        parameters={"queue": "readmission-high-risk", "priority": "urgent"},
        result={"ticket_id": "review-8821", "queue_position": 1},
        context={"workflow": "readmission-prevention", "oversight_expected": True},
        tool_name="queue_nurse_review",
    ),
    action(
        session_id="prior-auth-session-20260330-3",
        agent="utilization-agent-03",
        agent_type="gemini",
        action_type="data_access",
        timestamp="2026-03-30T12:10:00Z",
        target="payer://authorizations/patient-5531",
        parameters={"patient_id": "patient-5531", "service_line": "home-health"},
        result={"previous_denials": 1, "payer_id": "payer-44"},
        context={"workflow": "prior-authorization", "permissions_used": ["payer_portal_read"]},
    ),
    action(
        session_id="prior-auth-session-20260330-3",
        agent="utilization-agent-03",
        agent_type="gemini",
        action_type="tool_call",
        timestamp="2026-03-30T12:10:08Z",
        target="payer://prior-auth/patient-5531",
        parameters={"payer_id": "payer-44", "cpt_codes": ["G0151", "G0299"]},
        result={"status": "expired", "authorization_id": "auth-5531"},
        context={"workflow": "prior-authorization", "data_accessed": ["authorization-history"]},
        tool_name="retrieve_prior_authorization",
    ),
    action(
        session_id="prior-auth-session-20260330-3",
        agent="utilization-agent-03",
        agent_type="gemini",
        action_type="policy_check",
        timestamp="2026-03-30T12:10:15Z",
        target="policy://medical-necessity/home-health",
        parameters={"clinical_indicators": ["reduced-mobility", "recent-hospitalization"]},
        result={"allowed": True, "evidence_strength": "moderate"},
        context={"workflow": "prior-authorization", "policy_refs": ["sr-11-7-model-governance"]},
    ),
    action(
        session_id="prior-auth-session-20260330-3",
        agent="utilization-agent-03",
        agent_type="gemini",
        action_type="decision",
        timestamp="2026-03-30T12:10:24Z",
        target="workflow://prior-auth/patient-5531",
        parameters={"decision_model": "medical-necessity-qa-v1", "threshold": 0.72},
        result={"recommendation": "submit-with-additional-clinicals", "human_review_required": True},
        context={"workflow": "prior-authorization", "policy_refs": ["eu-ai-act-human-oversight"]},
    ),
    action(
        session_id="prior-auth-session-20260330-3",
        agent="utilization-agent-03",
        agent_type="gemini",
        action_type="system_write",
        timestamp="2026-03-30T12:10:32Z",
        target="payer://submission-packets/patient-5531",
        parameters={"template": "home-health-reauthorization"},
        result={"packet_id": "packet-5531", "status": "drafted"},
        context={"workflow": "prior-authorization", "requires_human_review": True},
    ),
    action(
        session_id="prior-auth-session-20260330-3",
        agent="utilization-agent-03",
        agent_type="gemini",
        action_type="tool_call",
        timestamp="2026-03-30T12:10:40Z",
        target="payer://submission-queue/home-health",
        parameters={"packet_id": "packet-5531"},
        result={"submission_id": "sub-5531", "status": "pending-review"},
        context={"workflow": "prior-authorization", "oversight_expected": True},
        tool_name="submit_prior_auth_packet",
    ),
    action(
        session_id="billing-session-20260330-4",
        agent="billing-audit-04",
        agent_type="claude",
        action_type="tool_call",
        timestamp="2026-03-30T12:15:00Z",
        target="claims://encounters/claim-9001",
        parameters={"claim_id": "claim-9001", "codes": ["99232", "J1885"]},
        result={"modifier_needed": "59", "coding_risk": "medium"},
        context={"workflow": "claim-audit", "policy_refs": ["fda-21-cfr-part-11-audit-trail"]},
        tool_name="verify_billing_codes",
    ),
    action(
        session_id="billing-session-20260330-4",
        agent="billing-audit-04",
        agent_type="claude",
        action_type="decision",
        timestamp="2026-03-30T12:15:08Z",
        target="claims://hold/claim-9001",
        parameters={"hold_reason_candidates": ["coding-mismatch", "missing-documentation"]},
        result={"decision": "manual-review", "confidence": 0.81},
        context={"workflow": "claim-audit", "policy_refs": ["sr-11-7-challenge-process"]},
    ),
    action(
        session_id="billing-session-20260330-4",
        agent="billing-audit-04",
        agent_type="claude",
        action_type="system_write",
        timestamp="2026-03-30T12:15:15Z",
        target="claims://queues/manual-review",
        parameters={"claim_id": "claim-9001", "queue": "clinical-coding-review"},
        result={"ticket_id": "audit-9001", "status": "queued"},
        context={"workflow": "claim-audit", "assigned_team": "billing-compliance"},
    ),
]

trace_response = request("POST", "/v1/traces", {"actions": actions})
action_ids = trace_response["action_ids"]
if len(action_ids) != 20:
    raise RuntimeError(f"expected 20 action ids, received {len(action_ids)}")

oversight_events = [
    {
        "session_id": "readmission-session-20260330-2",
        "framework": "hipaa",
        "severity": "high",
        "note": "nurse supervisor approved release of the outreach care plan",
        "timestamp": "2026-03-30T12:06:00Z",
        "event_type": "approval",
        "approver": "nurse.supervisor",
        "scope": "care-plan-release",
        "related_action_id": action_ids[9],
    },
    {
        "session_id": "intake-session-20260330-1",
        "framework": "hipaa",
        "severity": "medium",
        "note": "privacy officer confirmed minimum necessary data access",
        "timestamp": "2026-03-30T12:01:00Z",
        "event_type": "approval",
        "approver": "privacy.officer",
        "scope": "hipaa-minimum-necessary",
        "related_action_id": action_ids[1],
    },
    {
        "session_id": "prior-auth-session-20260330-3",
        "framework": "eu-ai-act",
        "severity": "high",
        "note": "utilization director overrode the automatic recommendation and required peer review",
        "timestamp": "2026-03-30T12:11:00Z",
        "event_type": "override",
        "approver": "utilization.director",
        "scope": "medical-necessity-disposition",
        "related_action_id": action_ids[14],
    },
    {
        "session_id": "billing-session-20260330-4",
        "framework": "sr-11-7",
        "severity": "high",
        "note": "billing manager overrode auto-release and held the claim for manual audit",
        "timestamp": "2026-03-30T12:16:00Z",
        "event_type": "override",
        "approver": "billing.manager",
        "scope": "claim-hold-disposition",
        "related_action_id": action_ids[18],
    },
    {
        "session_id": "prior-auth-session-20260330-3",
        "framework": "fda-21-cfr-part-11",
        "severity": "medium",
        "note": "compliance lead reviewed the submission packet before payer delivery",
        "timestamp": "2026-03-30T12:11:30Z",
        "event_type": "review",
        "approver": "compliance.lead",
        "scope": "submission-packet-review",
        "related_action_id": action_ids[16],
    },
]

oversight_ids = []
for event in oversight_events:
    response = request("POST", "/v1/oversight", event)
    oversight_ids.append(response["id"])

compliance = {}
exports = {}
for framework in FRAMEWORKS:
    compliance[framework] = request("GET", f"/v1/compliance/{framework}")
    exports[framework] = request("POST", "/v1/export/json", {"framework": framework})
    with open(f"{EXPORT_DIR}/{framework}.json", "w", encoding="utf-8") as handle:
        json.dump(exports[framework], handle, indent=2)

integrity = request("GET", "/v1/integrity")

summary = {
    "actions_ingested": len(action_ids),
    "oversight_events_logged": len(oversight_ids),
    "chain_valid": integrity["valid"],
    "checked_entries": integrity["checked_entries"],
    "latest_hash": integrity["latest_hash"],
    "compliance_scores": {framework: report["score"] for framework, report in compliance.items()},
    "exports_written_to": EXPORT_DIR,
    "dashboard": DASHBOARD_URL,
}

print("Trailing healthcare demo complete")
print(json.dumps(summary, indent=2))
PY

if [[ "${TRAILING_SKIP_BROWSER:-0}" != "1" ]]; then
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${DASHBOARD_URL}" >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then
    open "${DASHBOARD_URL}" >/dev/null 2>&1 || true
  fi
fi
