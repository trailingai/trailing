from __future__ import annotations

import unittest

from trailing import RedactionConfig, SdkAction, SdkContext, SdkEvent


class ModelTests(unittest.TestCase):
    def test_sdk_event_to_dict_matches_rust_schema(self) -> None:
        event = SdkEvent(
            agent_id="agent-1",
            agent_type="Claude Code",
            session_id="session-42",
            action=SdkAction(
                action_type="file.read",
                tool_name="fs",
                target="/tmp/example.txt",
                parameters={"path": "/tmp/example.txt"},
                result={"bytes": 128},
            ),
            context=SdkContext(
                data_accessed=["/tmp/example.txt"],
                permissions_used=["workspace-write"],
                policy_refs=["policy-1"],
            ),
        )

        self.assertEqual(
            event.to_dict(),
            {
                "agent_id": "agent-1",
                "agent_type": "Claude Code",
                "session_id": "session-42",
                "action": {
                    "action_type": "file.read",
                    "tool_name": "fs",
                    "target": "/tmp/example.txt",
                    "parameters": {"path": "/tmp/example.txt"},
                    "result": {"bytes": 128},
                },
                "context": {
                    "data_accessed": ["/tmp/example.txt"],
                    "permissions_used": ["workspace-write"],
                    "policy_refs": ["policy-1"],
                },
            },
        )

    def test_tool_call_builder_populates_expected_fields(self) -> None:
        event = SdkEvent.tool_call(
            agent_id="planner",
            agent_type="codex",
            session_id="session-123",
            tool_name="web.search",
            target="https://example.com",
            parameters={"query": "retention"},
            result={"count": 2},
        )

        self.assertEqual(event.action.action_type, "tool_call")
        self.assertEqual(event.action.tool_name, "web.search")
        self.assertEqual(event.action.target, "https://example.com")
        self.assertEqual(event.action.parameters["query"], "retention")
        self.assertEqual(event.action.result["count"], 2)

    def test_redaction_config_redacts_nested_sensitive_values(self) -> None:
        config = RedactionConfig(redact_keys=frozenset({"password", "authorization"}))
        payload = {
            "password": "plaintext",
            "headers": {"Authorization": "Bearer abc123"},
            "nested": [{"authorization": "Bearer def456"}],
            "safe": "visible",
        }

        self.assertEqual(
            config.redact(payload),
            {
                "password": "[REDACTED]",
                "headers": {"Authorization": "[REDACTED]"},
                "nested": [{"authorization": "[REDACTED]"}],
                "safe": "visible",
            },
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
