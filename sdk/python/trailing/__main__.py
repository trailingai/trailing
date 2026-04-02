from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Optional

from .adapters.claude_code import TrailingClaudeCodeAdapter
from .adapters.codex_cli import TrailingCodexCLIAdapter
from .adapters.cursor import TrailingCursorAdapter
from .client import TrailingClient, TrailingError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trailing")
    subparsers = parser.add_subparsers(dest="command")

    wrap_parser = subparsers.add_parser("wrap", help="Wrap a supported agent integration.")
    wrap_subparsers = wrap_parser.add_subparsers(dest="agent")

    wrap_codex_parser = wrap_subparsers.add_parser("codex", help="Run Codex through Trailing.")
    wrap_codex_parser.add_argument("prompt_or_args", nargs=argparse.REMAINDER)

    wrap_subparsers.add_parser("claude", help="Forward a Claude Code hook payload from stdin.")
    wrap_subparsers.add_parser("cursor", help="Forward a Cursor event payload from stdin.")

    ingest_parser = subparsers.add_parser("ingest", help="Ingest a JSON action into Trailing.")
    ingest_parser.add_argument("--file", help="Read the action JSON from a file instead of stdin.")

    query_parser = subparsers.add_parser("query", help="Query recorded actions.")
    query_parser.add_argument("--session", dest="session_id", help="Filter by session ID.")
    query_parser.add_argument("--agent", help="Filter by agent ID.")
    query_parser.add_argument("--type", dest="action_type", help="Filter by action type.")

    export_parser = subparsers.add_parser("export", help="Export evidence from Trailing.")
    export_parser.add_argument("--format", choices=["json", "pdf"], default="json")
    export_parser.add_argument("--framework", default="eu-ai-act")

    subparsers.add_parser("health", help="Check Trailing server health.")

    return parser


def _read_json_payload(path: str | None) -> Any:
    if path is not None:
        raw = Path(path).read_text(encoding="utf-8")
    else:
        is_tty = getattr(sys.stdin, "isatty", lambda: False)()
        if is_tty:
            raise ValueError("expected JSON on stdin or via --file")
        raw = sys.stdin.read()
    if not raw.strip():
        raise ValueError("expected a non-empty JSON payload")
    return json.loads(raw)


def _dump_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _require_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"expected '{field_name}' to be a JSON object")
    return {str(key): nested for key, nested in value.items()}


def _coerce_ingest_args(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValueError("expected the action payload to be a JSON object")

    action_payload = payload.get("action")
    action = action_payload if isinstance(action_payload, Mapping) else payload

    agent_id = payload.get("agent_id") or payload.get("agent")
    agent_type = payload.get("agent_type")
    session_id = payload.get("session_id")
    action_type = action.get("action_type") or payload.get("action_type") or payload.get("type")

    missing = [
        name
        for name, value in (
            ("agent_id", agent_id),
            ("agent_type", agent_type),
            ("session_id", session_id),
            ("action_type", action_type),
        )
        if not isinstance(value, str) or not value
    ]
    if missing:
        raise ValueError(f"missing required action fields: {', '.join(missing)}")

    return {
        "agent_id": agent_id,
        "agent_type": agent_type,
        "session_id": session_id,
        "action_type": action_type,
        "tool_name": action.get("tool_name") or payload.get("tool_name"),
        "target": action.get("target") or payload.get("target"),
        "params": _require_mapping(action.get("parameters") or payload.get("parameters"), "parameters"),
        "result": action.get("result") if "result" in action else payload.get("result"),
        "context": _require_mapping(payload.get("context"), "context"),
    }


def _run_wrap_codex(prompt_or_args: list[str]) -> int:
    prompt_or_args = list(prompt_or_args)
    if prompt_or_args and prompt_or_args[0] == "--":
        prompt_or_args = prompt_or_args[1:]
    if not prompt_or_args:
        raise ValueError("expected a Codex prompt or argument list after '--'")

    adapter = TrailingCodexCLIAdapter()
    try:
        payload: str | list[str]
        if len(prompt_or_args) == 1:
            payload = prompt_or_args[0]
        else:
            payload = prompt_or_args
        return adapter.run_wrapped_command(payload)
    finally:
        adapter.close()


def _run_wrap_claude() -> int:
    adapter = TrailingClaudeCodeAdapter()
    try:
        adapter.handle_hook_stdin()
        return 0
    finally:
        adapter.close()


def _run_wrap_cursor() -> int:
    adapter = TrailingCursorAdapter()
    try:
        data = _read_json_payload(None)
        adapter.capture_event(data)
        return 0
    finally:
        adapter.close()


def _run_ingest(file_path: str | None) -> int:
    payload = _read_json_payload(file_path)
    ingest_args = _coerce_ingest_args(payload)
    with TrailingClient(enable_background_queue=False) as client:
        response = client.ingest(**ingest_args)
    _dump_json(response)
    return 0


def _run_query(session_id: str | None, agent: str | None, action_type: str | None) -> int:
    with TrailingClient(enable_background_queue=False) as client:
        actions = client.get_actions(session_id=session_id, agent=agent, action_type=action_type)
    _dump_json(actions)
    return 0


def _run_export(export_format: str, framework: str) -> int:
    with TrailingClient(enable_background_queue=False) as client:
        if export_format == "json":
            _dump_json(client.export_json(framework))
            return 0
        sys.stdout.buffer.write(client.export_pdf(framework))
        return 0


def _run_health() -> int:
    with TrailingClient(enable_background_queue=False) as client:
        _dump_json(client.get_health())
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    try:
        if args.command == "wrap":
            if args.agent == "codex":
                return _run_wrap_codex(args.prompt_or_args)
            if args.agent == "claude":
                return _run_wrap_claude()
            if args.agent == "cursor":
                return _run_wrap_cursor()
            parser.error("expected a supported agent")

        if args.command == "ingest":
            return _run_ingest(args.file)

        if args.command == "query":
            return _run_query(args.session_id, args.agent, args.action_type)

        if args.command == "export":
            return _run_export(args.format, args.framework)

        if args.command == "health":
            return _run_health()
    except (OSError, ValueError, json.JSONDecodeError, TrailingError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
