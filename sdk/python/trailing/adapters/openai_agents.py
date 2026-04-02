"""OpenAI Agents SDK tracing adapter for Trailing."""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from ..client import TrailingClient, TrailingError
from ..models import SdkContext, SdkEvent

try:  # pragma: no cover
    from agents import add_trace_processor
except ImportError:  # pragma: no cover
    add_trace_processor = None

try:  # pragma: no cover
    from agents.tracing.processor_interface import TracingProcessor as _TracingProcessorBase
except ImportError:  # pragma: no cover
    class _TracingProcessorBase:
        """Fallback base when the OpenAI Agents SDK is unavailable."""

        def on_trace_start(self, trace: Any) -> None:
            return None

        def on_trace_end(self, trace: Any) -> None:
            return None

        def on_span_start(self, span: Any) -> None:
            return None

        def on_span_end(self, span: Any) -> None:
            return None

        def force_flush(self) -> None:
            return None

        def shutdown(self) -> None:
            return None


JsonDict = dict[str, Any]

_RETRIEVAL_TOOL_NAMES = {"file_search", "retrieval", "search", "vector_search", "knowledge_base"}


class TrailingOpenAITracer(_TracingProcessorBase):
    """Bridge OpenAI Agents tracing callbacks into Trailing SDK events."""

    def __init__(
        self,
        *,
        client: TrailingClient | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        agent_id: str = "openai-agent",
        agent_type: str = "openai",
        session_id: str | None = None,
        background: bool = True,
        raise_on_error: bool = False,
        emit_trace_lifecycle: bool = True,
    ) -> None:
        self.client = client or TrailingClient(base_url=base_url, api_key=api_key)
        self._owns_client = client is None
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.default_session_id = session_id
        self.background = background
        self.raise_on_error = raise_on_error
        self.emit_trace_lifecycle = emit_trace_lifecycle
        self._lock = threading.RLock()
        self._session_by_trace: dict[str, str] = {}
        self._last_error: BaseException | None = None

    def register_with_openai_agents(self) -> "TrailingOpenAITracer":
        """Register this tracer as a global OpenAI Agents tracing processor."""
        if add_trace_processor is None:  # pragma: no cover
            raise ImportError("openai-agents must be installed to register a tracing processor")
        add_trace_processor(self)
        return self

    def close(self) -> None:
        """Flush and close the underlying Trailing client when owned by this tracer."""
        try:
            self.force_flush()
        finally:
            if self._owns_client:
                self.client.close()

    def shutdown(self) -> None:
        """OpenAI Agents tracing processor shutdown hook."""
        self.close()

    def force_flush(self) -> None:
        """Flush the Trailing background queue."""
        self.client.flush()

    def on_trace_start(self, trace: Any) -> None:
        session_id = self._session_for_trace(trace)
        if not self.emit_trace_lifecycle:
            return
        payload = self._clean_dict(
            {
                "workflow_name": self._stringify(getattr(trace, "name", None)),
                "group_id": self._stringify(getattr(trace, "group_id", None)),
                "metadata": self._serialize(getattr(trace, "metadata", None)),
                "trace": self._trace_reference(
                    trace_id=self._stringify(getattr(trace, "trace_id", None)),
                ),
            }
        )
        self._emit(
            session_id=session_id,
            action_type="session_start",
            target=payload.get("workflow_name"),
            parameters=payload,
        )

    def on_trace_end(self, trace: Any) -> None:
        session_id = self._session_for_trace(trace)
        if not self.emit_trace_lifecycle:
            return
        payload = self._clean_dict(
            {
                "workflow_name": self._stringify(getattr(trace, "name", None)),
                "group_id": self._stringify(getattr(trace, "group_id", None)),
                "metadata": self._serialize(getattr(trace, "metadata", None)),
                "trace": self._trace_reference(
                    trace_id=self._stringify(getattr(trace, "trace_id", None)),
                ),
            }
        )
        self._emit(
            session_id=session_id,
            action_type="session_end",
            target=payload.get("workflow_name"),
            parameters=payload,
        )

    def on_span_start(self, span: Any) -> None:
        session_id = self._session_for_span(span)
        span_type, span_payload = self._span_payload(span)
        if span_type in {"generation", "response"}:
            self._emit_llm_request(
                session_id=session_id,
                payload=span_payload,
                correlation=self._span_correlation(span),
            )
            return
        if span_type == "function":
            self._emit_function_call(
                session_id=session_id,
                payload=span_payload,
                correlation=self._span_correlation(span),
            )

    def on_span_end(self, span: Any) -> None:
        session_id = self._session_for_span(span)
        span_type, span_payload = self._span_payload(span)
        correlation = self._span_correlation(span)
        error = self._serialize(getattr(span, "error", None))
        if span_type in {"generation", "response"}:
            self._emit_llm_response(
                session_id=session_id,
                payload=span_payload,
                correlation=correlation,
                error=error,
            )
            return
        if span_type == "function":
            self._emit_function_result(
                session_id=session_id,
                payload=span_payload,
                correlation=correlation,
                error=error,
            )
            return
        if span_type == "handoff":
            parameters = self._clean_dict(
                {
                    "from_agent": span_payload.get("from_agent"),
                    "to_agent": span_payload.get("to_agent"),
                    "trace": correlation,
                }
            )
            self._emit(
                session_id=session_id,
                action_type="agent_handoff",
                target=self._stringify(span_payload.get("to_agent")),
                parameters=parameters,
            )
            return
        if span_type == "guardrail":
            name = self._stringify(span_payload.get("name"))
            context = SdkContext(policy_refs=[name] if name else [])
            result = self._clean_dict(
                {
                    "triggered": span_payload.get("triggered"),
                    "error": error,
                }
            )
            self._emit(
                session_id=session_id,
                action_type="guardrail_check",
                target=name,
                parameters=self._clean_dict({"name": name, "trace": correlation}),
                result=result,
                context=context,
            )
            return
        if span_type == "custom" and self._looks_like_retrieval(span_payload):
            target = self._extract_target(span_payload)
            context = SdkContext(data_accessed=[target] if target else [])
            self._emit(
                session_id=session_id,
                action_type="retrieval_result",
                tool_name="retrieval",
                target=target,
                parameters=self._clean_dict({"span": span_payload, "trace": correlation}),
                result=self._clean_dict({"output": span_payload.get("data"), "error": error}),
                context=context,
            )

    def _emit_llm_request(
        self,
        *,
        session_id: str,
        payload: JsonDict,
        correlation: JsonDict,
    ) -> None:
        response = payload.get("response")
        model = self._stringify(payload.get("model")) or self._stringify(
            self._lookup_nested(response, "model")
        )
        parameters = self._clean_dict(
            {
                "input": payload.get("input"),
                "messages": payload.get("input"),
                "tools": payload.get("tools"),
                "model_config": payload.get("model_config"),
                "trace": correlation,
            }
        )
        self._emit(
            session_id=session_id,
            action_type="llm_request",
            target=model,
            parameters=parameters,
        )

    def _emit_llm_response(
        self,
        *,
        session_id: str,
        payload: JsonDict,
        correlation: JsonDict,
        error: Any,
    ) -> None:
        response = payload.get("response")
        model = self._stringify(payload.get("model")) or self._stringify(
            self._lookup_nested(response, "model")
        )
        completion = self._extract_completion(payload.get("output")) or self._extract_completion(response)
        usage = payload.get("usage") or self._lookup_nested(response, "usage")
        finish_reason = self._lookup_nested(response, "status") or self._lookup_nested(
            response, "finish_reason"
        )
        result = self._clean_dict(
            {
                "completion": completion,
                "output": payload.get("output"),
                "usage": usage,
                "finish_reason": self._stringify(finish_reason),
                "error": error,
                "response": response,
            }
        )
        self._emit(
            session_id=session_id,
            action_type="llm_response",
            target=model,
            parameters=self._clean_dict({"trace": correlation}),
            result=result,
        )

    def _emit_function_call(
        self,
        *,
        session_id: str,
        payload: JsonDict,
        correlation: JsonDict,
    ) -> None:
        tool_name = self._stringify(payload.get("name")) or "function"
        arguments = self._coerce_jsonish(payload.get("input"))
        target = self._extract_target(arguments)
        action_type = "retrieval" if self._is_retrieval(tool_name, payload) else "tool_call"
        context = SdkContext(data_accessed=[target] if action_type == "retrieval" and target else [])
        self._emit(
            session_id=session_id,
            action_type=action_type,
            tool_name=tool_name,
            target=target,
            parameters=self._clean_dict(
                {
                    "arguments": arguments,
                    "trace": correlation,
                    "tool": payload,
                }
            ),
            context=context,
        )

    def _emit_function_result(
        self,
        *,
        session_id: str,
        payload: JsonDict,
        correlation: JsonDict,
        error: Any,
    ) -> None:
        tool_name = self._stringify(payload.get("name")) or "function"
        arguments = self._coerce_jsonish(payload.get("input"))
        output = self._coerce_jsonish(payload.get("output"))
        target = self._extract_target(arguments)
        action_type = "retrieval_result" if self._is_retrieval(tool_name, payload) else "tool_result"
        context = SdkContext(data_accessed=[target] if action_type == "retrieval_result" and target else [])
        self._emit(
            session_id=session_id,
            action_type=action_type,
            tool_name=tool_name,
            target=target,
            parameters=self._clean_dict(
                {
                    "arguments": arguments,
                    "trace": correlation,
                }
            ),
            result=self._clean_dict({"output": output, "error": error}),
            context=context,
        )

    def _emit(
        self,
        *,
        session_id: str,
        action_type: str,
        parameters: Mapping[str, Any] | None = None,
        result: Any = None,
        target: str | None = None,
        tool_name: str | None = None,
        context: SdkContext | None = None,
    ) -> None:
        event = SdkEvent.build(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            session_id=session_id,
            action_type=action_type,
            tool_name=tool_name,
            target=target,
            parameters=self._clean_dict(dict(parameters or {})),
            result=self._serialize(result),
            context=context or SdkContext(),
        )
        try:
            self.client.track(event, background=self.background)
            self._last_error = None
        except TrailingError as exc:
            self._last_error = exc
            if self.raise_on_error:
                raise

    def _session_for_trace(self, trace: Any) -> str:
        trace_id = self._stringify(getattr(trace, "trace_id", None)) or str(uuid.uuid4())
        with self._lock:
            if trace_id in self._session_by_trace:
                return self._session_by_trace[trace_id]
            metadata = getattr(trace, "metadata", None)
            metadata_thread_id = None
            if isinstance(metadata, Mapping):
                metadata_thread_id = self._optional_string(metadata.get("thread_id"))
            session_id = (
                self._stringify(getattr(trace, "group_id", None))
                or metadata_thread_id
                or self.default_session_id
                or trace_id
            )
            self._session_by_trace[trace_id] = session_id
            return session_id

    def _session_for_span(self, span: Any) -> str:
        trace_id = self._stringify(getattr(span, "trace_id", None))
        if trace_id:
            with self._lock:
                session_id = self._session_by_trace.get(trace_id)
            if session_id:
                return session_id
        return self.default_session_id or trace_id or str(uuid.uuid4())

    def _span_correlation(self, span: Any) -> JsonDict:
        return self._clean_dict(
            {
                "trace_id": self._stringify(getattr(span, "trace_id", None)),
                "span_id": self._stringify(getattr(span, "span_id", None)),
                "parent_span_id": self._stringify(getattr(span, "parent_id", None)),
                "started_at": self._stringify(getattr(span, "started_at", None)),
                "ended_at": self._stringify(getattr(span, "ended_at", None)),
                "metadata": self._serialize(getattr(span, "trace_metadata", None)),
            }
        )

    def _trace_reference(self, *, trace_id: str | None) -> JsonDict:
        return self._clean_dict({"trace_id": trace_id})

    def _span_payload(self, span: Any) -> tuple[str, JsonDict]:
        span_data = getattr(span, "span_data", None)
        exported = self._serialize(getattr(span_data, "export", lambda: None)())
        if not isinstance(exported, Mapping):
            exported = {}
        payload = dict(exported)
        for attribute in (
            "input",
            "output",
            "model",
            "model_config",
            "usage",
            "response",
            "name",
            "from_agent",
            "to_agent",
            "triggered",
            "data",
        ):
            value = getattr(span_data, attribute, None)
            if value is not None and attribute not in payload:
                payload[attribute] = self._serialize(value)
        span_type = self._stringify(payload.get("type")) or self._stringify(
            getattr(span_data, "type", None)
        )
        return span_type or "unknown", payload

    def _extract_completion(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, Mapping):
            if "output_text" in value and value["output_text"] is not None:
                return self._serialize(value["output_text"])
            if "content" in value and value["content"] is not None:
                return self._serialize(value["content"])
            if "text" in value and value["text"] is not None:
                return self._serialize(value["text"])
            if "output" in value and value["output"] is not None:
                return self._extract_completion(value["output"])
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            completions = [self._extract_completion(item) for item in value]
            completions = [item for item in completions if item not in (None, "")]
            if not completions:
                return None
            if len(completions) == 1:
                return completions[0]
            return completions
        if hasattr(value, "output_text"):
            return self._extract_completion(getattr(value, "output_text"))
        if hasattr(value, "content"):
            return self._extract_completion(getattr(value, "content"))
        if hasattr(value, "text"):
            return self._extract_completion(getattr(value, "text"))
        return self._serialize(value)

    def _is_retrieval(self, tool_name: str, payload: Mapping[str, Any] | None = None) -> bool:
        lowered = tool_name.lower()
        if lowered in _RETRIEVAL_TOOL_NAMES:
            return True
        if any(token in lowered for token in ("retriev", "search", "vector", "knowledge")):
            return True
        return payload is not None and self._looks_like_retrieval(payload)

    def _looks_like_retrieval(self, payload: Mapping[str, Any]) -> bool:
        lowered_keys = {str(key).lower() for key in payload.keys()}
        if {"query", "results"} <= lowered_keys:
            return True
        if {"documents", "query"} <= lowered_keys:
            return True
        if "file_search" in lowered_keys or "retrieval" in lowered_keys:
            return True
        name = self._optional_string(payload.get("name"))
        return bool(name and self._is_retrieval(name))

    def _extract_target(self, value: Any) -> str | None:
        if isinstance(value, Mapping):
            for key in ("target", "resource", "file_id", "file_ids", "vector_store_id", "url", "path", "query"):
                candidate = value.get(key)
                if isinstance(candidate, list) and candidate:
                    return self._stringify(candidate[0])
                if candidate is not None:
                    return self._stringify(candidate)
        if isinstance(value, str) and value:
            return value
        return None

    def _coerce_jsonish(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return self._serialize(value)

    def _serialize(self, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Mapping):
            return {str(key): self._serialize(item) for key, item in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self._serialize(item) for item in value]
        model_dump = getattr(value, "model_dump", None)
        if callable(model_dump):
            try:
                return self._serialize(model_dump(mode="json"))
            except TypeError:
                return self._serialize(model_dump())
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            return self._serialize(to_dict())
        if hasattr(value, "__dict__"):
            return self._serialize(
                {
                    key: item
                    for key, item in vars(value).items()
                    if not key.startswith("_")
                }
            )
        return str(value)

    def _clean_dict(self, value: Mapping[str, Any]) -> JsonDict:
        cleaned: JsonDict = {}
        for key, item in value.items():
            if item is None:
                continue
            if item == {} or item == []:
                continue
            cleaned[str(key)] = self._serialize(item)
        return cleaned

    def _lookup_nested(self, value: Any, *path: str) -> Any:
        current = value
        for key in path:
            if current is None:
                return None
            if isinstance(current, Mapping):
                current = current.get(key)
                continue
            current = getattr(current, key, None)
        return current

    @staticmethod
    def _stringify(value: Any) -> str | None:
        return str(value) if value is not None else None

    @staticmethod
    def _optional_string(value: Any) -> str | None:
        return str(value) if value is not None else None
