from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional


SDK_ROOT = Path(__file__).resolve().parents[1]
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from trailing.adapters._base import TrailingAdapterBase  # noqa: E402
from trailing.adapters.claude_code import TrailingClaudeCodeAdapter  # noqa: E402


class FakeClient:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def ingest(
        self,
        *,
        agent_id: str,
        agent_type: str,
        session_id: str,
        action_type: str,
        tool_name: Optional[str],
        target: Optional[str],
        params: Optional[Mapping[str, Any]],
        result: Any,
        context: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        payload = {
            "agent_id": agent_id,
            "agent_type": agent_type,
            "session_id": session_id,
            "action_type": action_type,
            "tool_name": tool_name,
            "target": target,
            "params": dict(params or {}),
            "result": result,
            "context": dict(context or {}),
        }
        self.calls.append(payload)
        return {"action_ids": [f"action-{len(self.calls)}"]}

    def close(self) -> None:
        return None


class ClaudeCodeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FakeClient()
        self.adapter = TrailingClaudeCodeAdapter(
            client=self.client,
            session_id="claude-session",
        )

    def test_adapter_subclasses_base_and_exposes_hook_helpers(self) -> None:
        self.assertTrue(issubclass(TrailingClaudeCodeAdapter, TrailingAdapterBase))

        command = self.adapter.hook_command(python_executable="/usr/bin/python3")
        script = self.adapter.render_hook_script(python_executable="/usr/bin/python3")
        config = self.adapter.hook_config(python_executable="/usr/bin/python3")

        self.assertIn("-m trailing.adapters.claude_code hook", command)
        self.assertIn(command, script)
        self.assertEqual(sorted(config["hooks"].keys()), ["Notification", "PostToolUse", "PreToolUse", "Stop"])

    def test_pre_and_post_tool_hooks_forward_events(self) -> None:
        self.adapter.capture_event(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "session_id": "claude-run-1",
                    "tool_use_id": "tool-1",
                    "tool_name": "Read",
                    "input": {"path": "README.md"},
                }
            )
        )
        self.adapter.capture_event(
            {
                "hook_event_name": "PostToolUse",
                "session_id": "claude-run-1",
                "tool_use_id": "tool-1",
                "tool_name": "Read",
                "input": {"path": "README.md"},
                "output": {"contents": "# Trailing"},
                "status": "ok",
            }
        )

        start_event = self.client.calls[0]
        end_event = self.client.calls[1]

        self.assertEqual(start_event["action_type"], "tool_call")
        self.assertEqual(start_event["tool_name"], "Read")
        self.assertEqual(start_event["target"], "README.md")
        self.assertEqual(start_event["params"]["input"], {"path": "README.md"})

        self.assertEqual(end_event["action_type"], "tool_result")
        self.assertEqual(end_event["tool_name"], "Read")
        self.assertEqual(end_event["result"]["output"], {"contents": "# Trailing"})
        self.assertEqual(end_event["context"]["related_action_id"], "action-1")

    def test_notification_and_stop_map_session_lifecycle(self) -> None:
        self.adapter.capture_event(
            {
                "hook_event_name": "Notification",
                "session_id": "claude-run-2",
                "subtype": "session_start",
                "cwd": "/repo",
                "prompt": "Inspect the workspace",
            }
        )
        self.adapter.capture_event(
            {
                "hook_event_name": "Stop",
                "session_id": "claude-run-2",
                "reason": "completed",
                "summary": "done",
            }
        )

        self.assertEqual(self.client.calls[0]["action_type"], "session_start")
        self.assertEqual(self.client.calls[0]["target"], "/repo")
        self.assertEqual(self.client.calls[1]["action_type"], "session_end")
        self.assertEqual(self.client.calls[1]["result"]["summary"], "done")


if __name__ == "__main__":
    unittest.main()
