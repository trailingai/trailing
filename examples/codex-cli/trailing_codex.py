"""Self-contained Codex CLI adapter example for Trailing."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Mapping


SDK_DIR = Path(__file__).resolve().parents[2] / "sdk" / "python"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from trailing.adapters.codex_cli import TrailingCodexCLIAdapter


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
    agent_id: str = "codex-cli-demo",
    session_id: str | None = None,
    dry_run: bool = False,
) -> TrailingCodexCLIAdapter:
    """Create a Codex CLI adapter."""
    client = RecordingClient() if dry_run else None
    return TrailingCodexCLIAdapter(
        client=client,
        base_url=base_url,
        api_key=api_key,
        agent_id=agent_id,
        session_id=session_id,
    )


def sample_codex_events(*, session_id: str, prompt: str, workspace: str) -> list[dict[str, Any]]:
    """Representative Codex JSONL wrapper events."""
    return [
        {
            "type": "session_meta",
            "payload": {
                "id": session_id,
                "cwd": workspace,
                "prompt": prompt,
                "argv": ["codex", prompt],
            },
        },
        {
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "shell",
                "call_id": "call-1",
                "arguments": json.dumps(
                    {
                        "command": ["bash", "-lc", "pytest -q"],
                        "workdir": workspace,
                    }
                ),
            },
        },
        {
            "type": "response_item",
            "payload": {
                "type": "function_call_output",
                "call_id": "call-1",
                "output": json.dumps(
                    {
                        "output": "1 failed, 12 passed\n",
                        "metadata": {"exit_code": 1},
                    }
                ),
            },
        },
        {
            "type": "file_write",
            "session_id": session_id,
            "path": f"{workspace}/src/app.py",
            "content": {"diff": "+print('patched')"},
        },
        {
            "type": "approval_request",
            "session_id": session_id,
            "request": "Approve workspace write?",
            "actor": "operator",
            "target": "workspace-write",
        },
        {
            "type": "approval_result",
            "session_id": session_id,
            "request": "Approve workspace write?",
            "response": "approved",
            "approved": True,
            "actor": "operator",
            "target": "workspace-write",
        },
        {
            "type": "session_end",
            "session_id": session_id,
            "argv": ["codex", prompt],
            "exit_code": 0,
        },
    ]


def simulate_codex_session(
    adapter: TrailingCodexCLIAdapter,
    *,
    session_id: str,
    prompt: str,
    workspace: str,
) -> dict[str, Any]:
    """Feed representative Codex wrapper events through the adapter."""
    for event in sample_codex_events(session_id=session_id, prompt=prompt, workspace=workspace):
        adapter.capture_event(event)
    return {
        "session_id": session_id,
        "wrapper_command": adapter.wrapper_command(prompt),
        "action_types": [
            "session_start",
            "tool_call",
            "tool_result",
            "file_write",
            "human_review_requested",
            "human_in_the_loop",
            "session_end",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", help="Trailing base URL. Defaults to TRAILING_URL.")
    parser.add_argument("--api-key", help="Trailing API key. Defaults to TRAILING_API_KEY.")
    parser.add_argument("--agent-id", default="codex-cli-demo")
    parser.add_argument("--prompt", default="fix the failing tests")
    parser.add_argument("--workspace", default="/tmp/codex-demo")
    parser.add_argument("--session-id", default=f"codex-cli-{uuid.uuid4().hex[:8]}")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use an in-memory client instead of sending events to Trailing.",
    )
    parser.add_argument(
        "--run-codex",
        action="store_true",
        help="Execute Codex instead of replaying a sample event stream.",
    )
    parser.add_argument("--executable", default="codex", help="Codex executable to run.")
    args = parser.parse_args(argv)

    adapter = build_adapter(
        base_url=args.base_url,
        api_key=args.api_key,
        agent_id=args.agent_id,
        session_id=args.session_id,
        dry_run=args.dry_run,
    )
    try:
        if args.run_codex:
            exit_code = adapter.run_wrapped_command(
                args.prompt,
                executable=args.executable,
                session_id=args.session_id,
                cwd=args.workspace,
            )
            summary = {
                "session_id": args.session_id,
                "wrapper_command": adapter.wrapper_command(args.prompt),
                "exit_code": exit_code,
            }
        else:
            summary = simulate_codex_session(
                adapter,
                session_id=args.session_id,
                prompt=args.prompt,
                workspace=args.workspace,
            )
    finally:
        adapter.close()

    if args.dry_run and isinstance(adapter.client, RecordingClient):
        summary["recorded_events"] = len(adapter.client.calls)

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["TrailingCodexCLIAdapter", "build_adapter", "simulate_codex_session"]
