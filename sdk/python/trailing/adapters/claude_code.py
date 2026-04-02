"""Claude Code hook adapter for Trailing."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
import uuid
from typing import Any, Dict, Mapping, Optional

from ..client import JsonDict, TrailingClient
from ._base import TrailingAdapterBase


class TrailingClaudeCodeAdapter(TrailingAdapterBase):
    """Forward Claude Code hook events into Trailing."""

    ADAPTER_NAME = "claude_code"
    DEFAULT_AGENT_TYPE = "claude"

    def __init__(
        self,
        base_url: Optional[str] = None,
        agent_id: str = "claude-code",
        agent_type: str = DEFAULT_AGENT_TYPE,
        api_key: Optional[str] = None,
        session_id: Optional[str] = None,
        client: Optional[TrailingClient] = None,
    ) -> None:
        super().__init__(
            base_url=base_url,
            agent_id=agent_id,
            agent_type=agent_type,
            adapter_name=self.ADAPTER_NAME,
            api_key=api_key,
            session_id=session_id,
            client=client,
        )
        self._tool_runs: Dict[str, Dict[str, Any]] = {}

    def hook_command(
        self,
        *,
        python_executable: Optional[str] = None,
        module: str = "trailing.adapters.claude_code",
    ) -> str:
        """Return the command users add to Claude Code hook config."""
        executable = python_executable or sys.executable or "python3"
        return f"{shlex.quote(executable)} -m {module} hook"

    def hook_config(self, *, python_executable: Optional[str] = None) -> JsonDict:
        """Return a settings.json-ready hook configuration snippet."""
        command = self.hook_command(python_executable=python_executable)
        hook = {"type": "command", "command": command}
        return {
            "hooks": {
                "PreToolUse": [{"hooks": [hook]}],
                "PostToolUse": [{"hooks": [hook]}],
                "Notification": [{"hooks": [hook]}],
                "Stop": [{"hooks": [hook]}],
            }
        }

    def render_hook_script(self, *, python_executable: Optional[str] = None) -> str:
        """Return a shell hook script that forwards stdin into this module."""
        command = self.hook_command(python_executable=python_executable)
        return "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                f"exec {command}",
            ]
        )

    def record_session_start(
        self,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        prompt: Any = None,
        cwd: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record the start of a Claude Code session."""
        if session_id:
            self.default_session_id = session_id
        return self._ingest(
            session_id=session_id,
            run_id=run_id,
            action_type="session_start",
            target=cwd or "claude-session",
            params={
                "prompt": self._jsonable(prompt),
                "cwd": cwd,
            },
            result=None,
            context=self._context("session_start", metadata),
        )

    def record_session_end(
        self,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        stop_reason: Optional[str] = None,
        summary: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record the end of a Claude Code session."""
        if session_id:
            self.default_session_id = session_id
        return self._ingest(
            session_id=session_id,
            run_id=run_id,
            action_type="session_end",
            target=stop_reason or "claude-session",
            params={"stop_reason": stop_reason},
            result={"summary": self._jsonable(summary)},
            context=self._context("session_end", metadata),
        )

    def begin_tool_call(
        self,
        tool_name: str,
        *,
        tool_input: Any = None,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record the start of a Claude Code tool call."""
        resolved_run_id = run_id or str(uuid.uuid4())
        resolved_session_id = self._resolve_session_id(session_id, resolved_run_id)
        params = {"input": self._jsonable(tool_input)}
        target = self._extract_target(tool_input)
        response = self._ingest(
            session_id=resolved_session_id,
            run_id=resolved_run_id,
            action_type="tool_call",
            tool_name=tool_name,
            target=target,
            params=params,
            result=None,
            context=self._context("pre_tool_use", metadata),
        )
        self._tool_runs[resolved_run_id] = {
            "session_id": resolved_session_id,
            "tool_name": tool_name,
            "target": target,
            "params": params,
            "related_action_id": self._first_action_id(response),
        }
        return response

    def end_tool_call(
        self,
        *,
        run_id: str,
        tool_name: Optional[str] = None,
        tool_input: Any = None,
        output: Any = None,
        status: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record the completion of a Claude Code tool call."""
        pending = self._tool_runs.pop(run_id, {})
        params = pending.get("params") or {"input": self._jsonable(tool_input)}
        return self._ingest(
            session_id=pending.get("session_id"),
            run_id=run_id,
            action_type="tool_result",
            tool_name=self._optional_string(pending.get("tool_name")) or tool_name,
            target=self._optional_string(pending.get("target")) or self._extract_target(tool_input),
            params=params,
            result={
                "output": self._jsonable(output),
                "status": status,
            },
            context=self._context(
                "post_tool_use",
                self._merge_dicts(
                    metadata,
                    {"related_action_id": pending.get("related_action_id")},
                ),
            ),
        )

    def capture_event(
        self,
        event: Any,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Capture a Claude Code hook payload."""
        payload = self._coerce_event(event)
        raw_payload = payload.get("payload")
        event_payload = self._merge_event_payload(payload, raw_payload if isinstance(raw_payload, Mapping) else None)
        event_name = self._normalize_hook_name(
            event_payload.get("hook_event_name")
            or event_payload.get("event")
            or event_payload.get("event_name")
            or event_payload.get("hook")
            or event_payload.get("type")
        )
        combined_metadata = self._merge_dicts(metadata, {"raw_event": payload})
        resolved_session_id = session_id or self._optional_string(
            event_payload.get("session_id")
            or event_payload.get("sessionId")
            or payload.get("session_id")
            or payload.get("sessionId")
        )
        resolved_run_id = run_id or self._event_run_id(event_payload)

        if self._matches(event_name, "pretooluse", "pre_tool_use"):
            tool_name = self._optional_string(event_payload.get("tool_name") or event_payload.get("tool"))
            return self.begin_tool_call(
                tool_name or "tool",
                tool_input=event_payload.get("input"),
                session_id=resolved_session_id,
                run_id=resolved_run_id,
                metadata=combined_metadata,
            )

        if self._matches(event_name, "posttooluse", "post_tool_use"):
            tool_name = self._optional_string(event_payload.get("tool_name") or event_payload.get("tool"))
            return self.end_tool_call(
                run_id=resolved_run_id,
                tool_name=tool_name,
                tool_input=event_payload.get("input"),
                output=event_payload.get("output"),
                status=self._optional_string(event_payload.get("status")) or "ok",
                metadata=combined_metadata,
            )

        if self._matches(event_name, "notification"):
            notification_name = self._normalize_hook_name(
                event_payload.get("notification_type")
                or event_payload.get("subtype")
                or event_payload.get("status")
                or event_payload.get("name")
            )
            if self._matches(notification_name, "session_start", "session_started", "startup", "start"):
                return self.record_session_start(
                    session_id=resolved_session_id,
                    run_id=resolved_run_id,
                    prompt=event_payload.get("prompt"),
                    cwd=self._optional_string(event_payload.get("cwd")),
                    metadata=combined_metadata,
                )

        if self._matches(event_name, "stop", "session_end", "session_stop"):
            return self.record_session_end(
                session_id=resolved_session_id,
                run_id=resolved_run_id,
                stop_reason=self._optional_string(event_payload.get("stop_reason") or event_payload.get("reason")),
                summary=event_payload.get("summary"),
                metadata=combined_metadata,
            )

        return self._ingest(
            session_id=resolved_session_id,
            run_id=resolved_run_id,
            action_type="decision",
            target=event_name or "claude-hook",
            params={"event": self._jsonable(event_payload)},
            result=None,
            context=self._context("notification", combined_metadata),
        )

    def handle_hook_stdin(self, stdin_data: Optional[str] = None) -> JsonDict:
        """Read hook stdin payload and forward it to Trailing."""
        data = sys.stdin.read() if stdin_data is None else stdin_data
        return self.capture_event(data)

    @staticmethod
    def _coerce_event(event: Any) -> Dict[str, Any]:
        if isinstance(event, Mapping):
            return {str(key): value for key, value in event.items()}
        if isinstance(event, str):
            raw = event.strip()
            if not raw:
                return {}
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                return {"message": raw}
            if isinstance(payload, Mapping):
                return {str(key): value for key, value in payload.items()}
            return {"payload": payload}
        return TrailingAdapterBase._event_payload(event)

    @staticmethod
    def _merge_event_payload(
        payload: Mapping[str, Any],
        nested_payload: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        merged = dict(nested_payload or {})
        for key, value in payload.items():
            merged.setdefault(str(key), value)
        return merged

    @staticmethod
    def _normalize_hook_name(value: Any) -> str:
        normalized = TrailingAdapterBase._normalize_event_name(value)
        return normalized.replace("-", "_").replace(" ", "_")

    @staticmethod
    def _event_run_id(payload: Mapping[str, Any]) -> str:
        for key in ("tool_use_id", "run_id", "call_id", "id", "event_id"):
            value = payload.get(key)
            if value is not None:
                return str(value)
        return str(uuid.uuid4())

    @staticmethod
    def _extract_target(tool_input: Any) -> Optional[str]:
        if not isinstance(tool_input, Mapping):
            return None
        for key in ("file_path", "path", "target", "resource", "url", "command"):
            value = tool_input.get(key)
            if isinstance(value, (str, int, float)):
                return str(value)
            if isinstance(value, list):
                rendered = " ".join(str(item) for item in value if isinstance(item, (str, int, float)))
                if rendered:
                    return rendered
        return None


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entrypoint used by the generated Claude Code hook script."""
    parser = argparse.ArgumentParser(description="Forward Claude Code hook events to Trailing.")
    parser.add_argument("mode", nargs="?", default="hook")
    args = parser.parse_args(argv)

    adapter = TrailingClaudeCodeAdapter()
    try:
        if args.mode != "hook":
            parser.error(f"unsupported mode: {args.mode}")
        adapter.handle_hook_stdin()
    except Exception:
        adapter.close()
        return 1
    adapter.close()
    return 0


TrailingClaudeAdapter = TrailingClaudeCodeAdapter


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
