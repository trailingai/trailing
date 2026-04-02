"""Self-contained Cursor adapter example for Trailing."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Mapping


SDK_DIR = Path(__file__).resolve().parents[2] / "sdk" / "python"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from trailing.adapters.cursor import TrailingCursorAdapter


class RecordingClient:
    """Minimal client for local dry runs."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def ingest(
        self,
        *,
        agent_id: str,
        agent_type: str,
        session_id: str,
        action_type: str,
        tool_name: str | None,
        target: str | None,
        params: Mapping[str, Any] | None,
        result: Any,
        context: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
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
        return {"action_ids": [f"action-{len(self.calls)}"], "ingested": 1}

    def close(self) -> None:
        return None


def build_adapter(
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    agent_id: str = "cursor-demo",
    session_id: str | None = None,
    dry_run: bool = False,
) -> TrailingCursorAdapter:
    """Create a Cursor adapter."""
    client = RecordingClient() if dry_run else None
    return TrailingCursorAdapter(
        client=client,
        base_url=base_url,
        api_key=api_key,
        agent_id=agent_id,
        session_id=session_id,
    )


def sample_cursor_events(*, session_id: str, workspace: str, prompt: str) -> list[dict[str, Any]]:
    """Representative Cursor composer log events."""
    return [
        {
            "event": "composer",
            "phase": "start",
            "session_id": session_id,
            "workspace": workspace,
            "prompt": prompt,
        },
        {
            "event": "tool_call",
            "session_id": session_id,
            "call_id": "tool-1",
            "tool_name": "read_file",
            "input": {"path": "src/app.py"},
        },
        {
            "event": "tool_result",
            "session_id": session_id,
            "call_id": "tool-1",
            "output": {"contents": "print('ok')"},
            "status": "ok",
        },
        {
            "event": "file_write",
            "session_id": session_id,
            "path": "src/app.py",
            "content": {"diff": "+print('patched')"},
        },
        {
            "event": "approval",
            "session_id": session_id,
            "actor": "operator",
            "request": "Apply the edit?",
            "response": "approved",
            "approved": True,
            "target": "editor",
        },
        {
            "event": "composer",
            "phase": "end",
            "session_id": session_id,
            "summary": "updated src/app.py",
        },
    ]


def simulate_cursor_session(
    adapter: TrailingCursorAdapter,
    *,
    session_id: str,
    workspace: str,
    prompt: str,
) -> dict[str, Any]:
    """Write a temporary Cursor log file and replay it through the adapter."""
    events = sample_cursor_events(session_id=session_id, workspace=workspace, prompt=prompt)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        for event in events:
            handle.write(json.dumps(event))
            handle.write("\n")
        log_path = Path(handle.name)

    try:
        adapter.capture_log_file(log_path, session_id=session_id)
    finally:
        log_path.unlink(missing_ok=True)

    return {
        "session_id": session_id,
        "action_types": [
            "session_start",
            "tool_call",
            "tool_result",
            "file_write",
            "human_in_the_loop",
            "session_end",
        ],
    }


def replay_log_file(
    adapter: TrailingCursorAdapter,
    *,
    log_file: str,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Replay an existing Cursor JSONL log file."""
    adapter.capture_log_file(log_file, session_id=session_id)
    return {"session_id": session_id, "log_file": log_file}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", help="Trailing base URL. Defaults to TRAILING_URL.")
    parser.add_argument("--api-key", help="Trailing API key. Defaults to TRAILING_API_KEY.")
    parser.add_argument("--agent-id", default="cursor-demo")
    parser.add_argument("--workspace", default="/tmp/cursor-demo")
    parser.add_argument("--prompt", default="Refactor auth flow")
    parser.add_argument("--session-id", default=f"cursor-{uuid.uuid4().hex[:8]}")
    parser.add_argument("--log-file", help="Replay an existing Cursor JSONL log file.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use an in-memory client instead of sending events to Trailing.",
    )
    args = parser.parse_args(argv)

    adapter = build_adapter(
        base_url=args.base_url,
        api_key=args.api_key,
        agent_id=args.agent_id,
        session_id=args.session_id,
        dry_run=args.dry_run,
    )
    try:
        if args.log_file:
            summary = replay_log_file(
                adapter,
                log_file=args.log_file,
                session_id=args.session_id,
            )
        else:
            summary = simulate_cursor_session(
                adapter,
                session_id=args.session_id,
                workspace=args.workspace,
                prompt=args.prompt,
            )
    finally:
        adapter.close()

    if args.dry_run and isinstance(adapter.client, RecordingClient):
        summary["recorded_events"] = len(adapter.client.calls)

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["TrailingCursorAdapter", "build_adapter", "replay_log_file", "simulate_cursor_session"]
