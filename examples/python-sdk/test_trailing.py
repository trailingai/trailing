#!/usr/bin/env python3
"""Exercise the Python Trailing SDK against a running server."""

from __future__ import annotations

import json
import os
import uuid

from trailing import TrailingClient


FRAMEWORK = os.getenv("TRAILING_FRAMEWORK", "eu-ai-act")


def main() -> None:
    session_id = f"python-sdk-test-{uuid.uuid4()}"
    otlp_session_id = f"{session_id}-otlp"

    with TrailingClient() as client:
        ingest_response = client.ingest(
            agent_id="python-sdk-agent",
            agent_type="gpt",
            session_id=session_id,
            action_type="tool_call",
            tool_name="query_ehr",
            target="ehr://patients/patient-1001",
            params={"patient_id": "patient-1001", "fields": ["allergies", "labs"]},
            result={"records_returned": 2, "abnormal_lab": True},
            context={"workflow": "clinical-triage", "department": "care-management"},
        )
        action_id = ingest_response["action_ids"][0]

        otlp_response = client.ingest_otel(
            {
                "resourceSpans": [
                    {
                        "scopeSpans": [
                            {
                                "spans": [
                                    {
                                        "traceId": f"trace-{uuid.uuid4().hex[:12]}",
                                        "spanId": "span-001",
                                        "name": "llm.decision",
                                        "timestamp": "2026-03-30T12:00:00Z",
                                        "attributes": {
                                            "session.id": otlp_session_id,
                                            "agent.id": "python-sdk-agent",
                                            "agent.type": "gpt",
                                            "tool.name": "risk_classifier",
                                            "target": "risk://patient-1001",
                                        },
                                        "status": "ok",
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        )
        client.log_oversight(
            event_type="approval",
            approver="nurse.supervisor",
            scope="care-plan-release",
            related_action_id=action_id,
        )

        actions = client.get_actions(session_id=session_id)
        compliance = client.get_compliance(FRAMEWORK)
        integrity = client.verify_integrity()
        export_json = client.export_json(FRAMEWORK)
        export_pdf = client.export_pdf(FRAMEWORK)

    assert ingest_response["ingested"] == 1
    assert otlp_response["ingested"] == 1
    assert any(action["session_id"] == session_id for action in actions)
    assert compliance["framework"] == FRAMEWORK
    assert isinstance(integrity["valid"], bool)
    assert export_json["framework"] == FRAMEWORK
    assert export_pdf.startswith(b"%PDF-")

    print(
        json.dumps(
            {
                "status": "ok",
                "session_id": session_id,
                "framework": FRAMEWORK,
                "actions_seen": len(actions),
                "integrity_valid": integrity["valid"],
                "pdf_bytes": len(export_pdf),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
