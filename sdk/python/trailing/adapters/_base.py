"""Shared runtime helpers for Trailing adapter integrations."""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Iterable, Mapping, Optional

from ..client import JsonDict, TrailingClient, TrailingError


ContextDict = Dict[str, Any]


class TrailingAdapterBase:
    """Base class that normalizes framework runtime activity into Trailing actions."""

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        agent_id: str,
        agent_type: str,
        adapter_name: str,
        api_key: Optional[str] = None,
        session_id: Optional[str] = None,
        client: Optional[TrailingClient] = None,
    ) -> None:
        self.client = client or TrailingClient(base_url=base_url, api_key=api_key)
        self._owns_client = client is None
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.adapter_name = adapter_name
        self.default_session_id = session_id
        self._session_by_run: Dict[str, str] = {}

    def close(self) -> None:
        """Close the underlying Trailing client if this handler created it."""
        if self._owns_client:
            self.client.close()

    def capture_log_record(
        self,
        record: logging.LogRecord,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> JsonDict:
        """Convert a log record into a framework event and ingest it."""
        return self.capture_event(
            self._log_record_payload(record),
            session_id=session_id,
            run_id=run_id,
        )

    def capture_autogen_log_record(
        self,
        record: logging.LogRecord,
        *,
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> JsonDict:
        """Backward-compatible alias for log-based event capture."""
        return self.capture_log_record(record, session_id=session_id, run_id=run_id)

    def _ingest(
        self,
        *,
        action_type: str,
        params: Mapping[str, Any],
        result: Any,
        context: Mapping[str, Any],
        session_id: Optional[str] = None,
        run_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        target: Optional[str] = None,
    ) -> JsonDict:
        resolved_run_id = run_id or str(uuid.uuid4())
        resolved_session_id = self._resolve_session_id(session_id, resolved_run_id)
        try:
            return self.client.ingest(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                session_id=resolved_session_id,
                action_type=action_type,
                tool_name=tool_name,
                target=target,
                params=self._jsonable(dict(params)),
                result=self._jsonable(result),
                context=self._context_dict(
                    self._merge_dicts(
                        context,
                        {
                            "adapter": self.adapter_name,
                            "run_id": resolved_run_id,
                        },
                    )
                ),
            )
        except TrailingError:
            return {}

    def _resolve_session_id(self, session_id: Optional[str], run_id: str) -> str:
        if session_id:
            self._session_by_run[run_id] = session_id
            return session_id
        if run_id in self._session_by_run:
            return self._session_by_run[run_id]
        resolved = self.default_session_id or str(uuid.uuid4())
        self._session_by_run[run_id] = resolved
        return resolved

    def _context(self, event_type: str, metadata: Optional[Mapping[str, Any]]) -> ContextDict:
        return self._context_dict(
            self._merge_dicts(
                metadata,
                {
                    "adapter": self.adapter_name,
                    "event_type": event_type,
                },
            )
        )

    @staticmethod
    def _event_payload(event: Any) -> Dict[str, Any]:
        if isinstance(event, Mapping):
            return {str(key): value for key, value in event.items()}
        if hasattr(event, "__dict__"):
            return {
                key: value
                for key, value in vars(event).items()
                if not key.startswith("_")
            }
        return {"message": str(event)}

    @staticmethod
    def _log_record_payload(record: logging.LogRecord) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "type": getattr(record, "event_type", None) or getattr(record, "type", None),
            "message": record.getMessage(),
        }
        for key in (
            "tool_name",
            "command_name",
            "command_id",
            "call_id",
            "arguments",
            "input",
            "content",
            "output",
            "result",
            "key",
            "value",
            "query",
            "results",
            "scope",
            "target",
            "path",
            "url",
            "operation",
            "method",
            "request",
            "response",
            "status_code",
            "from_state",
            "previous_state",
            "to_state",
            "state",
            "cycle_id",
            "step_id",
            "planner",
            "branch",
            "selected_branch",
            "alternatives",
            "reason",
            "sender",
            "recipient",
            "role",
            "conversation_id",
            "caller",
            "callee",
            "executor",
            "language",
            "code",
            "selected_agent",
            "candidates",
            "actor",
            "approved",
            "prompt",
        ):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return payload

    @staticmethod
    def _context_dict(context: Optional[Mapping[str, Any]]) -> ContextDict:
        payload = dict(context or {})
        payload.setdefault("permissions_used", [])
        payload.setdefault("policy_refs", [])
        payload.setdefault("data_accessed", [])
        return TrailingAdapterBase._jsonable(payload)

    @staticmethod
    def _jsonable(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Mapping):
            return {str(key): TrailingAdapterBase._jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [TrailingAdapterBase._jsonable(item) for item in value]
        return str(value)

    @staticmethod
    def _merge_dicts(*items: Optional[Mapping[str, Any]]) -> ContextDict:
        merged: ContextDict = {}
        for item in items:
            if item:
                merged.update(dict(item))
        return merged

    @staticmethod
    def _matches(value: str, *needles: str) -> bool:
        return any(needle in value for needle in needles)

    @staticmethod
    def _normalize_event_name(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip().lower()

    @staticmethod
    def _optional_string(value: Any) -> Optional[str]:
        return str(value) if value is not None else None

    @staticmethod
    def _optional_int(value: Any) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _optional_bool(value: Any) -> Optional[bool]:
        if isinstance(value, bool):
            return value
        if value is None:
            return None
        normalized = str(value).strip().lower()
        if normalized in {"1", "true", "yes", "approved"}:
            return True
        if normalized in {"0", "false", "no", "rejected"}:
            return False
        return None

    @staticmethod
    def _iterable(value: Any) -> Iterable[Any]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return value
        return [value]

    @staticmethod
    def _first_action_id(response: Mapping[str, Any]) -> Optional[str]:
        action_ids = response.get("action_ids")
        if isinstance(action_ids, list) and action_ids:
            return str(action_ids[0])
        return None
