from __future__ import annotations

import unittest
import sys
from unittest import mock
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional


SDK_ROOT = Path(__file__).resolve().parents[1]
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from trailing.adapters._base import TrailingAdapterBase  # noqa: E402
from trailing.adapters.codex_cli import TrailingCodexCLIAdapter  # noqa: E402
from trailing.__main__ import main as trailing_main  # noqa: E402


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


class CodexCLIAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FakeClient()
        self.adapter = TrailingCodexCLIAdapter(client=self.client)

    def test_adapter_subclasses_base_and_exposes_wrapper_command(self) -> None:
        self.assertTrue(issubclass(TrailingCodexCLIAdapter, TrailingAdapterBase))
        self.assertEqual(
            self.adapter.wrapper_command("fix failing tests"),
            "trailing wrap codex -- 'fix failing tests'",
        )

    def test_cli_entrypoint_dispatches_to_codex_wrapper(self) -> None:
        with mock.patch(
            "trailing.adapters.codex_cli.TrailingCodexCLIAdapter.run_wrapped_command",
            return_value=0,
        ) as run_wrapped_command:
            exit_code = trailing_main(["wrap", "codex", "--", "fix failing tests"])

        self.assertEqual(exit_code, 0)
        run_wrapped_command.assert_called_once_with("fix failing tests")

    def test_rollout_response_items_map_exec_lifecycle(self) -> None:
        self.adapter.capture_event(
            {
                "type": "session_meta",
                "payload": {
                    "id": "codex-session",
                    "cwd": "/repo",
                },
            }
        )
        self.adapter.capture_event(
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "name": "shell",
                    "call_id": "call-1",
                    "arguments": "{\"command\":[\"bash\",\"-lc\",\"ls\"],\"workdir\":\"/repo\"}",
                },
            }
        )
        self.adapter.capture_event(
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "call-1",
                    "output": "{\"output\":\"README.md\\n\",\"metadata\":{\"exit_code\":0}}",
                },
            }
        )

        start_session = self.client.calls[0]
        tool_start = self.client.calls[1]
        tool_end = self.client.calls[2]

        self.assertEqual(start_session["action_type"], "session_start")
        self.assertEqual(start_session["session_id"], "codex-session")

        self.assertEqual(tool_start["action_type"], "tool_call")
        self.assertEqual(tool_start["tool_name"], "shell")
        self.assertEqual(tool_start["target"], "bash -lc ls")
        self.assertEqual(tool_start["session_id"], "codex-session")

        self.assertEqual(tool_end["action_type"], "tool_result")
        self.assertEqual(tool_end["tool_name"], "shell")
        self.assertEqual(tool_end["result"]["exit_code"], 0)
        self.assertEqual(tool_end["context"]["related_action_id"], "action-2")

    def test_file_write_and_approval_events_are_forwarded(self) -> None:
        self.adapter.capture_event(
            {
                "type": "file_write",
                "session_id": "codex-session",
                "path": "/tmp/out.txt",
                "content": {"diff": "+done"},
            }
        )
        self.adapter.capture_event(
            {
                "type": "approval_request",
                "session_id": "codex-session",
                "request": "Approve workspace write?",
                "actor": "operator",
                "target": "workspace-write",
            }
        )
        self.adapter.capture_event(
            {
                "type": "approval_result",
                "session_id": "codex-session",
                "request": "Approve workspace write?",
                "response": "approved",
                "approved": True,
                "actor": "operator",
                "target": "workspace-write",
            }
        )

        file_write = self.client.calls[0]
        approval_request = self.client.calls[1]
        approval_result = self.client.calls[2]

        self.assertEqual(file_write["action_type"], "file_write")
        self.assertEqual(file_write["target"], "/tmp/out.txt")

        self.assertEqual(approval_request["action_type"], "human_review_requested")
        self.assertEqual(approval_request["target"], "workspace-write")

        self.assertEqual(approval_result["action_type"], "human_in_the_loop")
        self.assertEqual(approval_result["result"]["approved"], True)
        self.assertEqual(approval_result["context"]["permissions_used"], ["human-oversight"])


if __name__ == "__main__":
    unittest.main()
