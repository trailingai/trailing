"""Cursor composer adapter for Trailing."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from ..client import JsonDict, TrailingClient
from ._base import TrailingAdapterBase


class TrailingCursorAdapter(TrailingAdapterBase):
    """Forward Cursor composer log and extension events into Trailing."""

    ADAPTER_NAME = "cursor"
    DEFAULT_AGENT_TYPE = "cursor"

    def __init__(
        self,
        base_url: Optional[str] = None,
        agent_id: str = "cursor-composer",
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

    def record_session_start(
        self,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        prompt: Any = None,
        workspace: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record the start of a Cursor composer session."""
        if session_id:
            self.default_session_id = session_id
        return self._ingest(
            session_id=session_id,
            run_id=run_id,
            action_type="session_start",
            target=workspace or "cursor-composer",
            params={
                "prompt": self._jsonable(prompt),
                "workspace": workspace,
            },
            result=None,
            context=self._context("session_start", metadata),
        )

    def record_session_end(
        self,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        summary: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record the end of a Cursor composer session."""
        if session_id:
            self.default_session_id = session_id
        return self._ingest(
            session_id=session_id,
            run_id=run_id,
            action_type="session_end",
            target="cursor-composer",
            params={},
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
        """Record a Cursor composer tool start."""
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
            context=self._context("tool_call_start", metadata),
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
        output: Any = None,
        status: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record a Cursor composer tool completion."""
        pending = self._tool_runs.pop(run_id, {})
        return self._ingest(
            session_id=pending.get("session_id"),
            run_id=run_id,
            action_type="tool_result",
            tool_name=self._optional_string(pending.get("tool_name")),
            target=self._optional_string(pending.get("target")),
            params=pending.get("params", {}),
            result={
                "output": self._jsonable(output),
                "status": status,
            },
            context=self._context(
                "tool_call_end",
                self._merge_dicts(
                    metadata,
                    {"related_action_id": pending.get("related_action_id")},
                ),
            ),
        )

    def record_file_write(
        self,
        path: str,
        *,
        content: Any = None,
        operation: str = "write",
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record a file mutation observed in Cursor composer."""
        return self._ingest(
            session_id=session_id,
            run_id=run_id,
            action_type="file_write",
            tool_name="filesystem",
            target=path,
            params={
                "path": path,
                "operation": operation,
                "content": self._jsonable(content),
            },
            result={"written": True},
            context=self._context("file_write", metadata),
        )

    def record_approval(
        self,
        *,
        request: Any = None,
        approved: Optional[bool] = None,
        response: Any = None,
        actor: Optional[str] = None,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record a Cursor approval decision."""
        oversight_metadata = self._merge_dicts(
            metadata,
            {"permissions_used": ["human-oversight"]},
        )
        return self._ingest(
            session_id=session_id,
            run_id=run_id,
            action_type="human_in_the_loop",
            target=target or actor or "approval",
            params={
                "actor": actor,
                "request": self._jsonable(request),
            },
            result={
                "response": self._jsonable(response),
                "approved": approved,
            },
            context=self._context("approval", oversight_metadata),
        )

    def capture_log_file(
        self,
        path: str | Path,
        *,
        session_id: Optional[str] = None,
        follow: bool = False,
        poll_interval: float = 0.25,
        max_idle_cycles: int = 1,
    ) -> list[JsonDict]:
        """Read Cursor log lines from a file and forward them to Trailing."""
        log_path = Path(path)
        responses: list[JsonDict] = []
        idle_cycles = 0
        with log_path.open("r", encoding="utf-8") as handle:
            while True:
                line = handle.readline()
                if line:
                    idle_cycles = 0
                    if line.strip():
                        responses.append(self.capture_event(line, session_id=session_id))
                    continue
                if not follow:
                    break
                idle_cycles += 1
                if idle_cycles >= max_idle_cycles:
                    break
                time.sleep(poll_interval)
        return responses

    def capture_events(
        self,
        events: Iterable[Any],
        *,
        session_id: Optional[str] = None,
    ) -> list[JsonDict]:
        """Capture a batch of Cursor events."""
        return [self.capture_event(event, session_id=session_id) for event in events]

    def capture_event(
        self,
        event: Any,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Capture a Cursor extension or log event."""
        payload = self._coerce_event(event)
        raw_payload = payload.get("payload")
        event_payload = self._merge_event_payload(payload, raw_payload if isinstance(raw_payload, Mapping) else None)
        event_name = self._normalize_cursor_name(
            event_payload.get("event")
            or event_payload.get("type")
            or event_payload.get("kind")
            or payload.get("event")
            or payload.get("type")
        )
        phase = self._normalize_cursor_name(
            event_payload.get("phase") or event_payload.get("status") or event_payload.get("state")
        )
        combined_metadata = self._merge_dicts(metadata, {"raw_event": payload})
        resolved_session_id = session_id or self._optional_string(
            event_payload.get("session_id")
            or event_payload.get("sessionId")
            or payload.get("session_id")
            or payload.get("sessionId")
        )
        resolved_run_id = run_id or self._optional_string(
            event_payload.get("call_id") or event_payload.get("run_id") or event_payload.get("id")
        )

        if self._matches(event_name, "composer") and self._matches(phase, "start", "request"):
            return self.record_session_start(
                session_id=resolved_session_id,
                run_id=resolved_run_id,
                prompt=event_payload.get("prompt"),
                workspace=self._optional_string(event_payload.get("workspace")),
                metadata=combined_metadata,
            )

        if self._matches(event_name, "composer") and self._matches(phase, "end", "stop", "complete"):
            return self.record_session_end(
                session_id=resolved_session_id,
                run_id=resolved_run_id,
                summary=event_payload.get("summary"),
                metadata=combined_metadata,
            )

        if event_name in {"tool_call", "agent_action", "composer_tool"}:
            return self.begin_tool_call(
                self._optional_string(event_payload.get("tool_name") or event_payload.get("action")) or "tool",
                tool_input=event_payload.get("input") or event_payload.get("arguments"),
                session_id=resolved_session_id,
                run_id=resolved_run_id,
                metadata=combined_metadata,
            )

        if event_name in {"tool_result", "tool_output", "composer_tool_result"}:
            return self.end_tool_call(
                run_id=resolved_run_id or str(uuid.uuid4()),
                output=event_payload.get("output") or event_payload.get("result"),
                status=self._optional_string(event_payload.get("status")) or "ok",
                metadata=combined_metadata,
            )

        if self._matches(event_name, "file_write", "file_saved", "edit_applied"):
            path = self._optional_string(event_payload.get("path") or event_payload.get("target")) or "file"
            return self.record_file_write(
                path,
                content=event_payload.get("content") or event_payload.get("diff"),
                operation=self._optional_string(event_payload.get("operation")) or "write",
                session_id=resolved_session_id,
                run_id=resolved_run_id,
                metadata=combined_metadata,
            )

        if self._matches(event_name, "approval"):
            return self.record_approval(
                request=event_payload.get("request") or event_payload.get("prompt"),
                approved=self._optional_bool(event_payload.get("approved")),
                response=event_payload.get("response") or event_payload.get("decision"),
                actor=self._optional_string(event_payload.get("actor") or event_payload.get("approver")),
                session_id=resolved_session_id,
                run_id=resolved_run_id,
                target=self._optional_string(event_payload.get("target")),
                metadata=combined_metadata,
            )

        return self._ingest(
            session_id=resolved_session_id,
            run_id=resolved_run_id,
            action_type="decision",
            target=event_name or "cursor-event",
            params={"event": self._jsonable(event_payload)},
            result=None,
            context=self._context("generic_event", combined_metadata),
        )

    @staticmethod
    def _coerce_event(event: Any) -> Dict[str, Any]:
        if isinstance(event, Mapping):
            return {str(key): value for key, value in event.items()}
        if isinstance(event, str):
            raw = event.strip()
            if not raw:
                return {}
            parsed = json.loads(raw)
            if isinstance(parsed, Mapping):
                return {str(key): value for key, value in parsed.items()}
            return {"payload": parsed}
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
    def _normalize_cursor_name(value: Any) -> str:
        normalized = TrailingAdapterBase._normalize_event_name(value)
        return normalized.replace(".", "_").replace("-", "_").replace(" ", "_")

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


TrailingCursorComposerAdapter = TrailingCursorAdapter
