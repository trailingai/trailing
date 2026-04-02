from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SDK_ROOT = Path(__file__).resolve().parents[1]
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from trailing.__main__ import main as trailing_main  # noqa: E402


def _mock_client() -> mock.MagicMock:
    client = mock.MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = None
    return client


class TrailingCliTests(unittest.TestCase):
    def test_wrap_claude_dispatches_to_adapter(self) -> None:
        with mock.patch("trailing.__main__.TrailingClaudeCodeAdapter") as adapter_cls:
            adapter = adapter_cls.return_value
            adapter.handle_hook_stdin.return_value = {"action_ids": ["action-1"]}

            exit_code = trailing_main(["wrap", "claude"])

        self.assertEqual(exit_code, 0)
        adapter.handle_hook_stdin.assert_called_once_with()
        adapter.close.assert_called_once_with()

    def test_wrap_cursor_reads_stdin_and_forwards_event(self) -> None:
        stdin = io.StringIO(json.dumps({"event": "approval", "approved": True}))
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch("trailing.__main__.TrailingCursorAdapter") as adapter_cls,
            mock.patch("sys.stdin", stdin),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            adapter = adapter_cls.return_value
            exit_code = trailing_main(["wrap", "cursor"])

        self.assertEqual(exit_code, 0)
        adapter.capture_event.assert_called_once_with({"event": "approval", "approved": True})
        adapter.close.assert_called_once_with()

    def test_ingest_reads_file_and_calls_client_ingest(self) -> None:
        client = _mock_client()
        client.ingest.return_value = {"action_ids": ["action-1"], "ingested": 1}
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch("trailing.__main__.TrailingClient", return_value=client),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            payload = {
                "agent_id": "agent-1",
                "agent_type": "claude",
                "session_id": "session-1",
                "action": {
                    "action_type": "tool_call",
                    "tool_name": "Read",
                    "target": "README.md",
                    "parameters": {"path": "README.md"},
                    "result": None,
                },
                "context": {"source": "cli"},
            }
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
                json.dump(payload, handle)
                file_path = handle.name
            try:
                exit_code = trailing_main(["ingest", "--file", file_path])
            finally:
                Path(file_path).unlink(missing_ok=True)

        self.assertEqual(exit_code, 0)
        client.ingest.assert_called_once_with(
            agent_id="agent-1",
            agent_type="claude",
            session_id="session-1",
            action_type="tool_call",
            tool_name="Read",
            target="README.md",
            params={"path": "README.md"},
            result=None,
            context={"source": "cli"},
        )
        self.assertIn('"ingested": 1', stdout.getvalue())

    def test_query_filters_actions(self) -> None:
        client = _mock_client()
        client.get_actions.return_value = [{"id": "action-1"}]
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch("trailing.__main__.TrailingClient", return_value=client),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            exit_code = trailing_main(["query", "--session", "session-1", "--agent", "agent-1", "--type", "tool_call"])

        self.assertEqual(exit_code, 0)
        client.get_actions.assert_called_once_with(
            session_id="session-1",
            agent="agent-1",
            action_type="tool_call",
        )
        self.assertIn('"id": "action-1"', stdout.getvalue())

    def test_export_json_prints_payload(self) -> None:
        client = _mock_client()
        client.export_json.return_value = {"framework": "eu-ai-act"}
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch("trailing.__main__.TrailingClient", return_value=client),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            exit_code = trailing_main(["export", "--format", "json", "--framework", "eu-ai-act"])

        self.assertEqual(exit_code, 0)
        client.export_json.assert_called_once_with("eu-ai-act")
        self.assertIn('"framework": "eu-ai-act"', stdout.getvalue())

    def test_health_prints_server_status(self) -> None:
        client = _mock_client()
        client.get_health.return_value = {"status": "ok"}
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch("trailing.__main__.TrailingClient", return_value=client),
            mock.patch("sys.stdout", stdout),
            mock.patch("sys.stderr", stderr),
        ):
            exit_code = trailing_main(["health"])

        self.assertEqual(exit_code, 0)
        client.get_health.assert_called_once_with()
        self.assertIn('"status": "ok"', stdout.getvalue())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
