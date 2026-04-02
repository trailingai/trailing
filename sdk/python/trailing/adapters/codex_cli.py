"""Codex CLI adapter for Trailing."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import uuid
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence

from ..client import JsonDict, TrailingClient
from ._base import TrailingAdapterBase


class TrailingCodexCLIAdapter(TrailingAdapterBase):
    """Forward Codex CLI rollout and wrapper events into Trailing."""

    ADAPTER_NAME = "codex_cli"
    DEFAULT_AGENT_TYPE = "codex"

    def __init__(
        self,
        base_url: Optional[str] = None,
        agent_id: str = "codex-cli",
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
        self._call_names: Dict[str, str] = {}

    def wrapper_command(self, prompt: str, *, trailing_binary: str = "trailing") -> str:
        """Return the user-facing wrapper command for Codex CLI."""
        return f"{trailing_binary} wrap codex -- {shlex.quote(prompt)}"

    def build_codex_command(
        self,
        prompt_or_args: str | Sequence[str],
        *,
        executable: str = "codex",
    ) -> list[str]:
        """Build the underlying Codex CLI command."""
        if isinstance(prompt_or_args, str):
            return [executable, prompt_or_args]
        return [executable, *list(prompt_or_args)]

    def run_wrapped_command(
        self,
        prompt_or_args: str | Sequence[str],
        *,
        executable: str = "codex",
        session_id: Optional[str] = None,
        cwd: Optional[str] = None,
        env: Optional[MutableMapping[str, str]] = None,
        event_stream: Optional[Iterable[str]] = None,
        popen_factory: Any = subprocess.Popen,
    ) -> int:
        """Run Codex through a thin wrapper and forward any streamed events."""
        command = self.build_codex_command(prompt_or_args, executable=executable)
        run_id = str(uuid.uuid4())
        resolved_session_id = self._resolve_session_id(session_id, run_id)
        self.record_session_start(
            session_id=resolved_session_id,
            run_id=run_id,
            argv=command,
            cwd=cwd,
            prompt=prompt_or_args if isinstance(prompt_or_args, str) else None,
        )

        process = popen_factory(
            command,
            cwd=cwd,
            env={**os.environ, **dict(env or {})},
        )
        try:
            if event_stream is not None:
                self.consume_event_stream(event_stream, session_id=resolved_session_id)
            return_code = int(process.wait())
        finally:
            self.record_session_end(
                session_id=resolved_session_id,
                run_id=run_id,
                argv=command,
                exit_code=getattr(process, "returncode", None),
            )
        return return_code

    def consume_event_stream(
        self,
        lines: Iterable[str],
        *,
        session_id: Optional[str] = None,
    ) -> list[JsonDict]:
        """Parse a JSONL event stream emitted while Codex runs."""
        responses: list[JsonDict] = []
        for line in lines:
            if not str(line).strip():
                continue
            responses.append(self.capture_event(line, session_id=session_id))
        return responses

    def record_session_start(
        self,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        prompt: Any = None,
        argv: Optional[Sequence[str]] = None,
        cwd: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record the start of a wrapped Codex session."""
        if session_id:
            self.default_session_id = session_id
        return self._ingest(
            session_id=session_id,
            run_id=run_id,
            action_type="session_start",
            target=cwd or "codex-session",
            params={
                "prompt": self._jsonable(prompt),
                "argv": self._jsonable(list(argv or [])),
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
        argv: Optional[Sequence[str]] = None,
        exit_code: Optional[int] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record the end of a wrapped Codex session."""
        if session_id:
            self.default_session_id = session_id
        return self._ingest(
            session_id=session_id,
            run_id=run_id,
            action_type="session_end",
            target="codex-session",
            params={"argv": self._jsonable(list(argv or []))},
            result={"exit_code": exit_code},
            context=self._context("session_end", metadata),
        )

    def begin_exec(
        self,
        tool_name: str,
        *,
        arguments: Any = None,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        call_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record the start of a Codex tool or exec event."""
        resolved_run_id = run_id or call_id or str(uuid.uuid4())
        resolved_session_id = self._resolve_session_id(session_id, resolved_run_id)
        normalized_arguments = self._jsonable(arguments)
        params = {
            "call_id": call_id or resolved_run_id,
            "arguments": normalized_arguments,
        }
        target = self._extract_target(arguments)
        response = self._ingest(
            session_id=resolved_session_id,
            run_id=resolved_run_id,
            action_type="tool_call",
            tool_name=tool_name,
            target=target,
            params=params,
            result=None,
            context=self._context("exec_start", metadata),
        )
        self._tool_runs[resolved_run_id] = {
            "session_id": resolved_session_id,
            "tool_name": tool_name,
            "target": target,
            "params": params,
            "related_action_id": self._first_action_id(response),
        }
        if call_id:
            self._call_names[call_id] = tool_name
        return response

    def end_exec(
        self,
        *,
        run_id: str,
        call_id: Optional[str] = None,
        result: Any = None,
        status: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record the completion of a Codex tool or exec event."""
        pending = self._tool_runs.pop(run_id, {})
        output = self._coerce_jsonish(result)
        exit_code = None
        if isinstance(output, Mapping):
            raw_exit_code = output.get("exit_code")
            if raw_exit_code is None:
                nested_metadata = output.get("metadata")
                if isinstance(nested_metadata, Mapping):
                    raw_exit_code = nested_metadata.get("exit_code")
            exit_code = self._optional_int(raw_exit_code)
        return self._ingest(
            session_id=pending.get("session_id"),
            run_id=run_id,
            action_type="tool_result",
            tool_name=self._optional_string(pending.get("tool_name"))
            or self._optional_string(call_id and self._call_names.get(call_id)),
            target=self._optional_string(pending.get("target")),
            params=pending.get("params", {"call_id": call_id}),
            result={
                "output": self._jsonable(output),
                "status": status,
                "exit_code": exit_code,
            },
            context=self._context(
                "exec_end",
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
        """Record a file write observed in Codex CLI."""
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

    def record_approval_request(
        self,
        *,
        request: Any,
        actor: Optional[str] = None,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record an approval request emitted by Codex."""
        return self._ingest(
            session_id=session_id,
            run_id=run_id,
            action_type="human_review_requested",
            target=target or actor or "approval",
            params={
                "actor": actor,
                "request": self._jsonable(request),
            },
            result=None,
            context=self._context("approval_requested", metadata),
        )

    def record_approval_result(
        self,
        *,
        approved: Optional[bool],
        request: Any = None,
        response: Any = None,
        actor: Optional[str] = None,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Record an approval decision emitted by Codex."""
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
            context=self._context("approval_result", oversight_metadata),
        )

    def capture_event(
        self,
        event: Any,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        """Capture a Codex CLI rollout or wrapper event."""
        payload = self._coerce_event(event)
        event_type = self._normalize_event_name(payload.get("type") or payload.get("event"))
        event_payload = payload.get("payload") if isinstance(payload.get("payload"), Mapping) else payload
        combined_metadata = self._merge_dicts(metadata, {"raw_event": payload})
        resolved_session_id = session_id or self._optional_string(
            payload.get("session_id")
            or payload.get("sessionId")
            or event_payload.get("session_id")
            or event_payload.get("id")
        )

        if event_type == "session_meta":
            return self.record_session_start(
                session_id=resolved_session_id or self._optional_string(event_payload.get("id")),
                run_id=run_id or str(uuid.uuid4()),
                prompt=event_payload.get("prompt"),
                argv=event_payload.get("argv") if isinstance(event_payload.get("argv"), list) else None,
                cwd=self._optional_string(event_payload.get("cwd")),
                metadata=self._merge_dicts(combined_metadata, {"event_type": "session_meta"}),
            )

        if event_type == "response_item":
            payload_type = self._normalize_event_name(event_payload.get("type"))
            if payload_type == "function_call":
                arguments = self._coerce_jsonish(event_payload.get("arguments"))
                return self.begin_exec(
                    self._optional_string(event_payload.get("name")) or "tool",
                    arguments=arguments,
                    session_id=resolved_session_id,
                    run_id=run_id or self._optional_string(event_payload.get("call_id")),
                    call_id=self._optional_string(event_payload.get("call_id")),
                    metadata=self._merge_dicts(combined_metadata, {"payload_type": payload_type}),
                )
            if payload_type == "function_call_output":
                return self.end_exec(
                    run_id=run_id or self._optional_string(event_payload.get("call_id")) or str(uuid.uuid4()),
                    call_id=self._optional_string(event_payload.get("call_id")),
                    result=event_payload.get("output"),
                    status=self._optional_string(event_payload.get("status")) or "ok",
                    metadata=self._merge_dicts(combined_metadata, {"payload_type": payload_type}),
                )

        if event_type in {"exec_start", "exec", "command_start"}:
            return self.begin_exec(
                self._optional_string(payload.get("tool_name") or payload.get("name")) or "exec",
                arguments=payload.get("input") or payload.get("arguments"),
                session_id=resolved_session_id,
                run_id=run_id or self._optional_string(payload.get("call_id") or payload.get("run_id")),
                call_id=self._optional_string(payload.get("call_id")),
                metadata=combined_metadata,
            )

        if event_type in {"exec_result", "command_result", "exec_end"}:
            return self.end_exec(
                run_id=run_id or self._optional_string(payload.get("call_id") or payload.get("run_id")) or str(uuid.uuid4()),
                call_id=self._optional_string(payload.get("call_id")),
                result=payload.get("output") or payload.get("result"),
                status=self._optional_string(payload.get("status")) or "ok",
                metadata=combined_metadata,
            )

        if self._matches(event_type, "file_write", "write_file", "file_saved"):
            path = self._optional_string(payload.get("path") or payload.get("target")) or "file"
            return self.record_file_write(
                path,
                content=payload.get("content") or payload.get("diff"),
                operation=self._optional_string(payload.get("operation")) or "write",
                session_id=resolved_session_id,
                run_id=run_id,
                metadata=combined_metadata,
            )

        if self._matches(event_type, "approval") and self._optional_bool(payload.get("approved")) is None:
            return self.record_approval_request(
                request=payload.get("request") or payload.get("prompt"),
                actor=self._optional_string(payload.get("actor") or payload.get("approver")),
                session_id=resolved_session_id,
                run_id=run_id,
                target=self._optional_string(payload.get("target")),
                metadata=combined_metadata,
            )

        if self._matches(event_type, "approval"):
            return self.record_approval_result(
                approved=self._optional_bool(payload.get("approved")),
                request=payload.get("request") or payload.get("prompt"),
                response=payload.get("response") or payload.get("decision"),
                actor=self._optional_string(payload.get("actor") or payload.get("approver")),
                session_id=resolved_session_id,
                run_id=run_id,
                target=self._optional_string(payload.get("target")),
                metadata=combined_metadata,
            )

        if self._matches(event_type, "session_end", "stop"):
            return self.record_session_end(
                session_id=resolved_session_id,
                run_id=run_id or str(uuid.uuid4()),
                argv=payload.get("argv") if isinstance(payload.get("argv"), list) else None,
                exit_code=self._optional_int(payload.get("exit_code")),
                metadata=combined_metadata,
            )

        return self._ingest(
            session_id=resolved_session_id,
            run_id=run_id,
            action_type="decision",
            target=event_type or "codex-event",
            params={"event": self._jsonable(payload)},
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
    def _coerce_jsonish(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        raw = value.strip()
        if not raw:
            return value
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return value

    @staticmethod
    def _extract_target(arguments: Any) -> Optional[str]:
        if not isinstance(arguments, Mapping):
            return None
        for key in ("file_path", "path", "target", "resource", "url", "command"):
            value = arguments.get(key)
            if isinstance(value, (str, int, float)):
                return str(value)
            if isinstance(value, list):
                rendered = " ".join(str(item) for item in value if isinstance(item, (str, int, float)))
                if rendered:
                    return rendered
        return None


TrailingCodexAdapter = TrailingCodexCLIAdapter
