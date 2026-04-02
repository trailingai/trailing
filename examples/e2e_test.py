#!/usr/bin/env python3
"""End-to-end integration test for Trailing using the Python SDK."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import requests


REPO_ROOT = Path(__file__).resolve().parents[1]
SDK_DIR = REPO_ROOT / "examples" / "python-sdk"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from trailing import TrailingClient, TrailingError  # noqa: E402


PORT = 3098
BASE_URL = f"http://127.0.0.1:{PORT}"
FRAMEWORKS = ["eu-ai-act", "nist-ai-rmf", "sr-11-7", "hipaa"]
HEALTH_TIMEOUT_SECONDS = 20.0
REQUEST_TIMEOUT_SECONDS = 5.0


@dataclass
class TestResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class TestRunner:
    results: List[TestResult] = field(default_factory=list)

    def run(self, name: str, check: Callable[[], None]) -> None:
        try:
            check()
        except Exception as exc:  # noqa: BLE001
            detail = str(exc).strip()
            if not detail:
                detail = exc.__class__.__name__
            self.results.append(TestResult(name=name, passed=False, detail=detail))
        else:
            self.results.append(TestResult(name=name, passed=True))

    def passed_count(self) -> int:
        return sum(1 for result in self.results if result.passed)

    def total_count(self) -> int:
        return len(self.results)

    def failures(self) -> List[TestResult]:
        return [result for result in self.results if not result.passed]


class ServerManager:
    def __init__(self, binary_path: Path, db_path: Path) -> None:
        self.binary_path = binary_path
        self.db_path = db_path
        self.process: Optional[subprocess.Popen[str]] = None

    def start(self) -> None:
        if self.process and self.process.poll() is None:
            raise RuntimeError("server is already running")

        self.process = subprocess.Popen(
            [
                str(self.binary_path),
                "serve",
                "--port",
                str(PORT),
                "--db",
                str(self.db_path),
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def wait_until_healthy(self, timeout_seconds: float = HEALTH_TIMEOUT_SECONDS) -> Dict[str, Any]:
        deadline = time.time() + timeout_seconds
        last_error = "health check did not complete"

        while time.time() < deadline:
            if self.process is None:
                raise RuntimeError("server process was not started")

            if self.process.poll() is not None:
                raise RuntimeError(self._failure_detail("server exited before becoming healthy"))

            try:
                response = requests.get(
                    f"{BASE_URL}/v1/health",
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
                if response.status_code == 200:
                    payload = response.json()
                    if payload.get("status") == "ok":
                        return payload
                    last_error = f"unexpected health payload: {payload}"
                else:
                    last_error = f"unexpected health status {response.status_code}: {response.text}"
            except requests.RequestException as exc:
                last_error = str(exc)

            time.sleep(0.25)

        raise RuntimeError(self._failure_detail(f"health check timed out: {last_error}"))

    def stop(self) -> None:
        if self.process is None:
            return

        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

        if self.process.stdout is not None:
            self.process.stdout.close()
        self.process = None

    def _failure_detail(self, message: str) -> str:
        if self.process is None or self.process.stdout is None:
            return message

        if self.process.poll() is None:
            return message

        try:
            output = self.process.stdout.read().strip()
        except Exception:  # noqa: BLE001
            output = ""

        if output:
            return f"{message}. server output:\n{output}"
        return message


def build_binary_path() -> Path:
    binary_path = REPO_ROOT / "target" / "release" / "trailing"
    if not binary_path.exists():
        raise FileNotFoundError(
            "missing release binary at target/release/trailing; run `cargo build --release` first"
        )
    return binary_path


def cleanup_db(db_path: Path) -> None:
    for path in (db_path, db_path.with_name(f"{db_path.name}-wal"), db_path.with_name(f"{db_path.name}-shm")):
        if path.exists():
            path.unlink()


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_equal(actual: Any, expected: Any, message: str) -> None:
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {actual!r}")


def make_sdk_actions() -> List[Dict[str, Any]]:
    return [
        {
            "agent_id": "triage-intake-agent",
            "agent_type": "claude",
            "session_id": "sess-intake-001",
            "action_type": "tool_call",
            "tool_name": "query_ehr",
            "target": "ehr://patients/patient-1001",
            "params": {"patient_id": "patient-1001", "fields": ["allergies", "vitals"]},
            "result": {"records_returned": 2, "critical_alert": False},
            "context": {"workflow": "intake", "department": "emergency", "policy_refs": ["hipaa-minimum-necessary"]},
        },
        {
            "agent_id": "triage-intake-agent",
            "agent_type": "claude",
            "session_id": "sess-intake-001",
            "action_type": "decision",
            "tool_name": None,
            "target": "care://routing/high-risk",
            "params": {"acuity_score": 7, "reason": "chest-pain"},
            "result": {"decision": "escalate_to_clinician"},
            "context": {"workflow": "intake", "risk_level": "high"},
        },
        {
            "agent_id": "medication-recon-agent",
            "agent_type": "gpt",
            "session_id": "sess-intake-001",
            "action_type": "tool_call",
            "tool_name": "check_drug_interactions",
            "target": "pharmacy://interactions/patient-1001",
            "params": {"medications": ["warfarin", "amoxicillin"]},
            "result": {"interaction_found": True, "severity": "major"},
            "context": {"workflow": "med-recon", "department": "pharmacy"},
        },
        {
            "agent_id": "triage-policy-agent",
            "agent_type": "gpt",
            "session_id": "sess-intake-001",
            "action_type": "policy_check",
            "tool_name": "policy_lookup",
            "target": "policy://care-path/chest-pain",
            "params": {"policy": "cardiac-triage-v2"},
            "result": {"policy_match": True},
            "context": {"workflow": "governance", "policy": {"name": "cardiac-triage-v2"}},
        },
        {
            "agent_id": "consent-review-agent",
            "agent_type": "claude",
            "session_id": "sess-consent-002",
            "action_type": "read_record",
            "tool_name": None,
            "target": "consent://patients/patient-1002/latest",
            "params": {"patient_id": "patient-1002"},
            "result": {"consent_status": "valid"},
            "context": {"workflow": "consent-review", "department": "admissions"},
        },
        {
            "agent_id": "consent-review-agent",
            "agent_type": "claude",
            "session_id": "sess-consent-002",
            "action_type": "system_write",
            "tool_name": "update_case_status",
            "target": "case://patient-1002",
            "params": {"status": "ready-for-procedure"},
            "result": {"updated": True},
            "context": {"workflow": "consent-review", "department": "admissions"},
        },
        {
            "agent_id": "care-plan-agent",
            "agent_type": "gpt",
            "session_id": "sess-careplan-003",
            "action_type": "tool_call",
            "tool_name": "summarize_lab_results",
            "target": "lab://panels/patient-1003",
            "params": {"panel_id": "cmp-443"},
            "result": {"abnormal_values": 3},
            "context": {"workflow": "care-plan", "department": "oncology"},
        },
        {
            "agent_id": "care-plan-agent",
            "agent_type": "gpt",
            "session_id": "sess-careplan-003",
            "action_type": "decision",
            "tool_name": None,
            "target": "plan://patient-1003",
            "params": {"recommendation": "urgent-follow-up"},
            "result": {"requires_review": True},
            "context": {"workflow": "care-plan", "risk_assessment": {"score": 0.82}},
        },
        {
            "agent_id": "claims-audit-agent",
            "agent_type": "claude",
            "session_id": "sess-claims-004",
            "action_type": "tool_call",
            "tool_name": "verify_billing_codes",
            "target": "claims://encounters/enc-1004",
            "params": {"encounter_id": "enc-1004"},
            "result": {"mismatches": 1},
            "context": {"workflow": "claims-audit", "department": "revenue-cycle"},
        },
        {
            "agent_id": "claims-audit-agent",
            "agent_type": "claude",
            "session_id": "sess-claims-004",
            "action_type": "override",
            "tool_name": None,
            "target": "claims://encounters/enc-1004",
            "params": {"override_reason": "manual coding correction"},
            "result": {"status": "requires-human-approval"},
            "context": {"workflow": "claims-audit", "department": "revenue-cycle"},
        },
        {
            "agent_id": "prior-auth-agent",
            "agent_type": "gpt",
            "session_id": "sess-auth-005",
            "action_type": "tool_call",
            "tool_name": "fetch_prior_auth_rules",
            "target": "payer://rules/procedure-mri",
            "params": {"payer": "payer-a", "procedure_code": "70553"},
            "result": {"requires_prior_auth": True},
            "context": {"workflow": "prior-auth", "department": "utilization-management"},
        },
        {
            "agent_id": "prior-auth-agent",
            "agent_type": "gpt",
            "session_id": "sess-auth-005",
            "action_type": "system_write",
            "tool_name": "submit_prior_auth",
            "target": "payer://requests/auth-1005",
            "params": {"request_id": "auth-1005"},
            "result": {"submitted": True},
            "context": {"workflow": "prior-auth", "department": "utilization-management"},
        },
        {
            "agent_id": "discharge-agent",
            "agent_type": "claude",
            "session_id": "sess-discharge-006",
            "action_type": "tool_call",
            "tool_name": "generate_discharge_summary",
            "target": "discharge://patient-1006",
            "params": {"patient_id": "patient-1006"},
            "result": {"summary_sections": 6},
            "context": {"workflow": "discharge", "department": "hospitalist"},
        },
        {
            "agent_id": "discharge-agent",
            "agent_type": "claude",
            "session_id": "sess-discharge-006",
            "action_type": "read_record",
            "tool_name": None,
            "target": "ehr://patients/patient-1006/followups",
            "params": {"patient_id": "patient-1006"},
            "result": {"follow_up_count": 2},
            "context": {"workflow": "discharge", "department": "hospitalist"},
        },
        {
            "agent_id": "population-health-agent",
            "agent_type": "gpt",
            "session_id": "sess-pophealth-007",
            "action_type": "tool_call",
            "tool_name": "stratify_readmission_risk",
            "target": "analytics://cohort/readmission-risk",
            "params": {"cohort": "copd-weekly"},
            "result": {"high_risk_patients": 4},
            "context": {"workflow": "population-health", "department": "care-management"},
        },
        {
            "agent_id": "population-health-agent",
            "agent_type": "gpt",
            "session_id": "sess-pophealth-007",
            "action_type": "decision",
            "tool_name": None,
            "target": "outreach://campaigns/copd-weekly",
            "params": {"campaign": "copd-weekly"},
            "result": {"recommended_outreach": 4},
            "context": {"workflow": "population-health", "department": "care-management"},
        },
    ]


def make_otlp_payloads() -> List[Dict[str, Any]]:
    return [
        {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": f"trace-{uuid.uuid4().hex[:12]}",
                                    "spanId": "span-001",
                                    "name": "tool_call",
                                    "timestamp": "2026-03-30T12:00:00Z",
                                    "attributes": {
                                        "session.id": "sess-intake-001",
                                        "agent.id": "radiology-agent",
                                        "agent.type": "gpt",
                                        "tool.name": "screen_imaging_order",
                                        "target": "radiology://orders/img-1008",
                                    },
                                    "status": "ok",
                                }
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": f"trace-{uuid.uuid4().hex[:12]}",
                                    "spanId": "span-002",
                                    "name": "decision",
                                    "timestamp": "2026-03-30T12:01:00Z",
                                    "attributes": {
                                        "session.id": "sess-careplan-003",
                                        "agent.id": "sepsis-watch-agent",
                                        "agent.type": "claude",
                                        "target": "monitoring://alerts/sepsis-1009",
                                    },
                                    "status": "ok",
                                }
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": f"trace-{uuid.uuid4().hex[:12]}",
                                    "spanId": "span-003",
                                    "name": "tool_call",
                                    "timestamp": "2026-03-30T12:02:00Z",
                                    "attributes": {
                                        "session.id": "sess-auth-005",
                                        "agent.id": "appeals-agent",
                                        "agent.type": "gpt",
                                        "tool.name": "draft_appeal_letter",
                                        "target": "appeals://cases/app-1010",
                                    },
                                    "status": "ok",
                                }
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": f"trace-{uuid.uuid4().hex[:12]}",
                                    "spanId": "span-004",
                                    "name": "policy_check",
                                    "timestamp": "2026-03-30T12:03:00Z",
                                    "attributes": {
                                        "session.id": "sess-discharge-006",
                                        "agent.id": "privacy-guard-agent",
                                        "agent.type": "claude",
                                        "tool.name": "verify_minimum_necessary",
                                        "target": "policy://privacy/minimum-necessary",
                                    },
                                    "status": "ok",
                                }
                            ]
                        }
                    ]
                }
            ]
        },
    ]


def make_oversight_events(action_ids: List[str]) -> List[Dict[str, str]]:
    return [
        {
            "event_type": "approval",
            "approver": "nurse.supervisor",
            "scope": "triage-release",
            "related_action_id": action_ids[1],
        },
        {
            "event_type": "override",
            "approver": "pharmacist.lead",
            "scope": "medication-reconciliation",
            "related_action_id": action_ids[2],
        },
        {
            "event_type": "review",
            "approver": "oncology.attending",
            "scope": "care-plan-review",
            "related_action_id": action_ids[7],
        },
        {
            "event_type": "kill_switch",
            "approver": "privacy.officer",
            "scope": "claims-audit-escalation",
            "related_action_id": action_ids[9],
        },
        {
            "event_type": "approval",
            "approver": "utilization.manager",
            "scope": "prior-authorization-submit",
            "related_action_id": action_ids[11],
        },
    ]


def main() -> int:
    runner = TestRunner()
    binary_path = build_binary_path()
    db_path = Path(tempfile.gettempdir()) / f"trailing-e2e-{uuid.uuid4().hex}.db"
    server = ServerManager(binary_path=binary_path, db_path=db_path)

    action_ids: List[str] = []
    oversight_ids: List[str] = []
    health_payload: Dict[str, Any] = {}

    cleanup_db(db_path)

    try:
        runner.run(
            "server starts and passes health check",
            lambda: _start_and_check_health(server, health_payload),
        )

        with TrailingClient(base_url=BASE_URL, timeout=REQUEST_TIMEOUT_SECONDS) as client:
            runner.run(
                "ingests 20 varied healthcare agent actions",
                lambda: _ingest_actions(client, action_ids),
            )
            runner.run(
                "logs 5 oversight events",
                lambda: _log_oversight_events(client, action_ids, oversight_ids),
            )
            runner.run(
                "queries actions and verifies count",
                lambda: _verify_action_query(client),
            )
            for framework in FRAMEWORKS:
                runner.run(
                    f"checks compliance for {framework}",
                    lambda framework=framework: _verify_compliance(client, framework),
                )
            runner.run(
                "verifies chain integrity",
                lambda: _verify_integrity(client),
            )
            runner.run(
                "exports JSON evidence and validates structure",
                lambda: _verify_json_export(client, action_ids, oversight_ids),
            )
            runner.run(
                "exports PDF evidence and validates header",
                lambda: _verify_pdf_export(client),
            )
            runner.run(
                "rejects malformed ingest payload with 400",
                lambda: _verify_malformed_ingest(client),
            )
            runner.run(
                "returns 404 for non-existent action",
                lambda: _verify_missing_action(),
            )
            runner.run(
                "returns 404 for unsupported framework",
                lambda: _verify_unsupported_framework(client),
            )

        runner.run(
            "persists data across server restart",
            lambda: _verify_persistence(server),
        )
    except Exception as exc:  # noqa: BLE001
        detail = traceback.format_exc().strip()
        runner.results.append(
            TestResult(
                name="unhandled script error",
                passed=False,
                detail=f"{exc}\n{detail}",
            )
        )
    finally:
        server.stop()
        cleanup_db(db_path)

    print_summary(runner, db_path, health_payload)
    return 0 if not runner.failures() else 1


def _start_and_check_health(server: ServerManager, health_payload: Dict[str, Any]) -> None:
    server.start()
    payload = server.wait_until_healthy()
    health_payload.clear()
    health_payload.update(payload)
    expect_equal(payload.get("status"), "ok", "health status should be ok")
    expect_equal(payload.get("service"), "trailing", "health service should be trailing")


def _ingest_actions(client: TrailingClient, action_ids: List[str]) -> None:
    created_ids: List[str] = []

    for action in make_sdk_actions():
        response = client.ingest(**action)
        expect_equal(response.get("ingested"), 1, "SDK ingest should create one action")
        ids = response.get("action_ids", [])
        expect_equal(len(ids), 1, "SDK ingest should return one action id")
        created_ids.extend(ids)

    for payload in make_otlp_payloads():
        response = client.ingest_otel(payload)
        expect_equal(response.get("ingested"), 1, "OTLP ingest should create one action")
        ids = response.get("action_ids", [])
        expect_equal(len(ids), 1, "OTLP ingest should return one action id")
        created_ids.extend(ids)

    expect_equal(len(created_ids), 20, "expected 20 ingested action ids")
    expect_equal(len(set(created_ids)), 20, "expected action ids to be unique")

    action_ids.clear()
    action_ids.extend(created_ids)


def _log_oversight_events(
    client: TrailingClient,
    action_ids: List[str],
    oversight_ids: List[str],
) -> None:
    expect_equal(len(action_ids), 20, "oversight logging requires 20 ingested actions")

    created_ids: List[str] = []
    for event in make_oversight_events(action_ids):
        response = client.log_oversight(**event)
        created_ids.append(str(response.get("id", "")))
        expect(response.get("severity") in {"info", "medium", "high"}, "unexpected oversight severity")

    expect_equal(len(created_ids), 5, "expected 5 oversight events")
    expect(all(created_ids), "expected oversight event ids to be returned")

    oversight_ids.clear()
    oversight_ids.extend(created_ids)


def _verify_action_query(client: TrailingClient) -> None:
    actions = client.get_actions()
    expect_equal(len(actions), 20, "query should return exactly 20 actions")

    sessions = {action["session_id"] for action in actions}
    agents = {action["agent"] for action in actions}
    expect(len(sessions) >= 6, "expected actions from multiple sessions")
    expect(len(agents) >= 8, "expected actions from multiple agents")


def _verify_compliance(client: TrailingClient, framework: str) -> None:
    report = client.get_compliance(framework)
    expect_equal(report.get("framework"), framework, "framework should round-trip")
    expect_equal(report.get("total_actions"), 20, "compliance report should see all actions")
    expect_equal(report.get("oversight_events"), 5, "compliance report should see all oversight events")
    expect(report.get("integrity_valid") is True, "compliance report should reflect valid integrity")
    expect(isinstance(report.get("controls_met"), list), "controls_met should be a list")
    expect(isinstance(report.get("controls_gaps"), list), "controls_gaps should be a list")


def _verify_integrity(client: TrailingClient) -> None:
    report = client.verify_integrity()
    expect(report.get("valid") is True, "integrity report should be valid")
    expect_equal(report.get("checked_entries"), 25, "integrity should cover all actions and oversight events")
    expect(isinstance(report.get("latest_hash"), str) and report["latest_hash"], "latest hash should be present")


def _verify_json_export(
    client: TrailingClient,
    action_ids: List[str],
    oversight_ids: List[str],
) -> None:
    export = client.export_json("hipaa")
    expect_equal(export.get("framework"), "hipaa", "JSON export should include requested framework")
    expect(isinstance(export.get("actions"), list), "JSON export should include actions")
    expect(isinstance(export.get("oversight_events"), list), "JSON export should include oversight events")
    expect(isinstance(export.get("integrity"), dict), "JSON export should include integrity")
    expect_equal(len(export["actions"]), 20, "JSON export should contain 20 actions")
    expect_equal(len(export["oversight_events"]), 5, "JSON export should contain 5 oversight events")
    expect(export["integrity"].get("valid") is True, "JSON export integrity should be valid")

    exported_action_ids = {item["id"] for item in export["actions"]}
    exported_oversight_ids = {item["id"] for item in export["oversight_events"]}
    expect(set(action_ids).issubset(exported_action_ids), "JSON export is missing action ids")
    expect(set(oversight_ids).issubset(exported_oversight_ids), "JSON export is missing oversight ids")

    sample_action = export["actions"][0]
    sample_event = export["oversight_events"][0]
    for key in ("id", "session_id", "agent", "type", "hash"):
        expect(key in sample_action, f"exported action missing {key}")
    for key in ("id", "severity", "note", "hash"):
        expect(key in sample_event, f"exported oversight event missing {key}")


def _verify_pdf_export(client: TrailingClient) -> None:
    pdf_bytes = client.export_pdf("hipaa")
    expect(pdf_bytes.startswith(b"%PDF"), "PDF export should start with %PDF")
    expect(len(pdf_bytes) > 64, "PDF export should not be empty")


def _verify_malformed_ingest(client: TrailingClient) -> None:
    try:
        client.ingest_otel({"resourceSpans": [{"scopeSpans": [{"spans": [{"name": "broken-span"}]}]}]})
    except TrailingError as exc:
        expect_equal(exc.status_code, 400, "malformed ingest should return 400")
        expect(exc.response_text is not None and "traceId" in exc.response_text, "error should explain malformed span")
        return

    raise AssertionError("malformed ingest unexpectedly succeeded")


def _verify_missing_action() -> None:
    response = requests.get(
        f"{BASE_URL}/v1/actions/does-not-exist",
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    expect_equal(response.status_code, 404, "missing action should return 404")
    payload = response.json()
    expect_equal(payload.get("code"), "NOT_FOUND", "missing action should return NOT_FOUND")


def _verify_unsupported_framework(client: TrailingClient) -> None:
    try:
        client.get_compliance("made-up-framework")
    except TrailingError as exc:
        expect_equal(exc.status_code, 404, "unsupported framework should return 404")
        expect(exc.response_text is not None and "not supported" in exc.response_text, "error should mention unsupported framework")
        return

    raise AssertionError("unsupported framework unexpectedly succeeded")


def _verify_persistence(server: ServerManager) -> None:
    server.stop()
    server.start()
    payload = server.wait_until_healthy()
    expect_equal(payload.get("status"), "ok", "health should be ok after restart")

    with TrailingClient(base_url=BASE_URL, timeout=REQUEST_TIMEOUT_SECONDS) as client:
        actions = client.get_actions()
        integrity = client.verify_integrity()

    expect_equal(len(actions), 20, "actions should persist after restart")
    expect(integrity.get("valid") is True, "integrity should remain valid after restart")
    expect_equal(integrity.get("checked_entries"), 25, "all persisted entries should remain present after restart")


def print_summary(runner: TestRunner, db_path: Path, health_payload: Dict[str, Any]) -> None:
    print(f"{runner.passed_count()}/{runner.total_count()} tests passed")
    if health_payload:
        print(
            json.dumps(
                {
                    "server": "trailing",
                    "port": PORT,
                    "db_path": str(db_path),
                    "health": health_payload,
                },
                indent=2,
            )
        )

    failures = runner.failures()
    if not failures:
        return

    print("Failures:")
    for result in failures:
        print(f"- {result.name}: {result.detail}")


if __name__ == "__main__":
    raise SystemExit(main())
