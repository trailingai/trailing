from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional


SDK_ROOT = Path(__file__).resolve().parents[1]
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from trailing.adapters._base import TrailingAdapterBase  # noqa: E402
from trailing.adapters.cursor import TrailingCursorAdapter  # noqa: E402


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


class CursorAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FakeClient()
        self.adapter = TrailingCursorAdapter(client=self.client)

    def test_adapter_subclasses_base(self) -> None:
        self.assertTrue(issubclass(TrailingCursorAdapter, TrailingAdapterBase))

    def test_log_file_capture_maps_composer_actions(self) -> None:
        events = [
            {
                "event": "composer",
                "phase": "start",
                "session_id": "cursor-session",
                "workspace": "/repo",
                "prompt": "Refactor auth",
            },
            {
                "event": "tool_call",
                "session_id": "cursor-session",
                "call_id": "tool-1",
                "tool_name": "read_file",
                "input": {"path": "src/app.py"},
            },
            {
                "event": "tool_result",
                "session_id": "cursor-session",
                "call_id": "tool-1",
                "output": {"contents": "print('ok')"},
                "status": "ok",
            },
            {
                "event": "file_write",
                "session_id": "cursor-session",
                "path": "src/app.py",
                "content": {"diff": "+print('ok')"},
            },
            {
                "event": "composer",
                "phase": "end",
                "session_id": "cursor-session",
                "summary": "done",
            },
        ]

        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as handle:
            for event in events:
                handle.write(json.dumps(event))
                handle.write("\n")
            log_path = Path(handle.name)

        try:
            self.adapter.capture_log_file(log_path)
        finally:
            log_path.unlink(missing_ok=True)

        self.assertEqual(
            [call["action_type"] for call in self.client.calls],
            ["session_start", "tool_call", "tool_result", "file_write", "session_end"],
        )
        self.assertEqual(self.client.calls[1]["target"], "src/app.py")
        self.assertEqual(self.client.calls[2]["context"]["related_action_id"], "action-2")

    def test_approval_event_is_forwarded(self) -> None:
        self.adapter.capture_event(
            {
                "event": "approval",
                "session_id": "cursor-session",
                "actor": "operator",
                "request": "Apply the edit?",
                "response": "approved",
                "approved": True,
                "target": "editor",
            }
        )

        approval_event = self.client.calls[0]
        self.assertEqual(approval_event["action_type"], "human_in_the_loop")
        self.assertEqual(approval_event["target"], "editor")
        self.assertEqual(approval_event["result"]["approved"], True)
        self.assertEqual(approval_event["context"]["permissions_used"], ["human-oversight"])


if __name__ == "__main__":
    unittest.main()
