"""LangChain callback adapter for Trailing."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Mapping, Optional, Sequence

from ..client import TrailingClient, TrailingError

try:  # pragma: no cover
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:  # pragma: no cover
    try:
        from langchain.callbacks.base import BaseCallbackHandler
    except ImportError:  # pragma: no cover
        class BaseCallbackHandler:  # type: ignore[no-redef]
            """Fallback base class when LangChain is not installed."""


JsonDict = Dict[str, Any]


class TrailingCallbackHandler(BaseCallbackHandler):
    """Forward LangChain callback events into Trailing's Python SDK."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        agent_id: str = "langchain-agent",
        api_key: Optional[str] = None,
        session_id: Optional[str] = None,
        client: Optional[Any] = None,
    ) -> None:
        super().__init__()
        self.client = client or TrailingClient(base_url=base_url, api_key=api_key)
        self.agent_id = agent_id
        self.default_session_id = session_id
        self._session_by_run: Dict[str, str] = {}
        self._run_state: Dict[str, JsonDict] = {}

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        run_id = self._run_id(kwargs)
        session_id = self._ensure_session_id(run_id, kwargs.get("parent_run_id"))
        chain_name = self._component_name(serialized, "chain")
        agent_type = self._agent_type_for_run(kwargs, fallback="langchain")

        self._run_state[run_id] = {
            "component": "chain",
            "name": chain_name,
            "session_id": session_id,
            "agent_type": agent_type,
        }
        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="session_start",
            tool_name=None,
            target=None,
            params={
                "chain": chain_name,
                "inputs": self._normalize_value(inputs),
            },
            result=None,
            context=self._build_context(
                component="chain",
                phase="start",
                run_id=run_id,
                kwargs=kwargs,
                extra={
                    "name": chain_name,
                    "serialized": self._normalize_value(serialized),
                },
            ),
        )

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        run_id = self._run_id(kwargs)
        state = self._run_state.get(run_id, {})
        session_id = str(state.get("session_id") or self._ensure_session_id(run_id, kwargs.get("parent_run_id")))
        chain_name = str(state.get("name") or "chain")
        agent_type = str(state.get("agent_type") or self._agent_type_for_run(kwargs, fallback="langchain"))

        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="session_end",
            tool_name=None,
            target=None,
            params={"chain": chain_name},
            result=self._normalize_value(outputs),
            context=self._build_context(
                component="chain",
                phase="end",
                run_id=run_id,
                kwargs=kwargs,
                extra={"name": chain_name},
            ),
        )
        self._finalize_run(run_id)

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        run_id = self._run_id(kwargs)
        state = self._run_state.get(run_id, {})
        session_id = str(state.get("session_id") or self._ensure_session_id(run_id, kwargs.get("parent_run_id")))
        chain_name = str(state.get("name") or "chain")
        agent_type = str(state.get("agent_type") or self._agent_type_for_run(kwargs, fallback="langchain"))

        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="error",
            tool_name=None,
            target=None,
            params={"chain": chain_name},
            result={"message": str(error), "error_type": error.__class__.__name__},
            context=self._build_context(
                component="chain",
                phase="error",
                run_id=run_id,
                kwargs=kwargs,
                extra={"name": chain_name},
            ),
        )
        self._finalize_run(run_id)

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: list[list[Any]],
        **kwargs: Any,
    ) -> None:
        self._record_llm_start(
            serialized=serialized,
            prompts=self._messages_to_prompts(messages),
            kwargs=kwargs,
            message_batches=self._serialize_messages(messages),
        )

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        self._record_llm_start(
            serialized=serialized,
            prompts=list(prompts),
            kwargs=kwargs,
            message_batches=None,
        )

    def on_llm_new_token(self, token: str, **kwargs: Any) -> None:
        run_id = self._run_id(kwargs)
        state = self._run_state.get(run_id, {})
        session_id = str(state.get("session_id") or self._ensure_session_id(run_id, kwargs.get("parent_run_id")))
        model_name = self._optional_string(state.get("name"))
        agent_type = str(state.get("agent_type") or self._agent_type_for_run(kwargs, fallback="langchain"))

        params: JsonDict = {"token": token}
        if model_name:
            params["model"] = model_name

        chunk = self._normalize_value(kwargs.get("chunk"))
        if chunk is not None:
            params["chunk"] = chunk

        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="decision",
            tool_name=None,
            target=None,
            params=params,
            result={"token": token},
            context=self._build_context(
                component="llm",
                phase="stream",
                run_id=run_id,
                kwargs=kwargs,
                extra={"model": model_name},
            ),
        )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        run_id = self._run_id(kwargs)
        state = self._run_state.get(run_id, {})
        session_id = str(state.get("session_id") or self._ensure_session_id(run_id, kwargs.get("parent_run_id")))
        model_name = str(state.get("name") or self._extract_model_name({}, kwargs))
        agent_type = str(state.get("agent_type") or self._detect_agent_type(model_name))
        token_usage = self._extract_token_usage(response)

        params: JsonDict = {"model": model_name}
        if token_usage:
            params["token_usage"] = token_usage

        result: JsonDict = {
            "generations": self._extract_generations(response),
        }
        if token_usage:
            result["token_usage"] = token_usage

        llm_output = self._normalize_value(getattr(response, "llm_output", None))
        if llm_output is not None:
            result["llm_output"] = llm_output

        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="completion",
            tool_name=None,
            target=None,
            params=params,
            result=result,
            context=self._build_context(
                component="llm",
                phase="end",
                run_id=run_id,
                kwargs=kwargs,
                extra={"model": model_name},
            ),
        )
        self._finalize_run(run_id)

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        run_id = self._run_id(kwargs)
        state = self._run_state.get(run_id, {})
        session_id = str(state.get("session_id") or self._ensure_session_id(run_id, kwargs.get("parent_run_id")))
        model_name = self._optional_string(state.get("name"))
        agent_type = str(state.get("agent_type") or self._agent_type_for_run(kwargs, fallback="langchain"))

        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="error",
            tool_name=None,
            target=None,
            params={"model": model_name} if model_name else {},
            result={"message": str(error), "error_type": error.__class__.__name__},
            context=self._build_context(
                component="llm",
                phase="error",
                run_id=run_id,
                kwargs=kwargs,
                extra={"model": model_name},
            ),
        )
        self._finalize_run(run_id)

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        run_id = self._run_id(kwargs)
        session_id = self._ensure_session_id(run_id, kwargs.get("parent_run_id"))
        tool_name = self._component_name(serialized, "tool")
        parsed_input = self._coerce(input_str)
        target = self._extract_target(parsed_input)
        agent_type = self._agent_type_for_run(kwargs, fallback="langchain")

        response = self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="tool_call",
            tool_name=tool_name,
            target=target,
            params={"input": self._normalize_value(parsed_input)},
            result=None,
            context=self._build_context(
                component="tool",
                phase="start",
                run_id=run_id,
                kwargs=kwargs,
                extra={
                    "name": tool_name,
                    "serialized": self._normalize_value(serialized),
                },
            ),
        )
        action_ids = response.get("action_ids", []) if isinstance(response, dict) else []
        self._run_state[run_id] = {
            "component": "tool",
            "name": tool_name,
            "session_id": session_id,
            "agent_type": agent_type,
            "params": {"input": self._normalize_value(parsed_input)},
            "target": target,
            "related_action_id": action_ids[0] if action_ids else None,
        }

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        run_id = self._run_id(kwargs)
        state = self._run_state.get(run_id, {})
        session_id = str(state.get("session_id") or self._ensure_session_id(run_id, kwargs.get("parent_run_id")))
        tool_name = self._optional_string(state.get("name"))
        agent_type = str(state.get("agent_type") or self._agent_type_for_run(kwargs, fallback="langchain"))

        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="tool_result",
            tool_name=tool_name,
            target=self._optional_string(state.get("target")),
            params=self._normalize_mapping(state.get("params")),
            result=self._normalize_value(output),
            context=self._build_context(
                component="tool",
                phase="end",
                run_id=run_id,
                kwargs=kwargs,
                extra={
                    "name": tool_name,
                    "related_action_id": state.get("related_action_id"),
                },
            ),
        )
        self._finalize_run(run_id)

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        run_id = self._run_id(kwargs)
        state = self._run_state.get(run_id, {})
        session_id = str(state.get("session_id") or self._ensure_session_id(run_id, kwargs.get("parent_run_id")))
        tool_name = self._optional_string(state.get("name"))
        agent_type = str(state.get("agent_type") or self._agent_type_for_run(kwargs, fallback="langchain"))

        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="error",
            tool_name=tool_name,
            target=self._optional_string(state.get("target")),
            params=self._normalize_mapping(state.get("params")),
            result={"message": str(error), "error_type": error.__class__.__name__},
            context=self._build_context(
                component="tool",
                phase="error",
                run_id=run_id,
                kwargs=kwargs,
                extra={
                    "name": tool_name,
                    "related_action_id": state.get("related_action_id"),
                },
            ),
        )
        self._finalize_run(run_id)

    def on_retriever_start(
        self,
        serialized: Dict[str, Any],
        query: str,
        **kwargs: Any,
    ) -> None:
        run_id = self._run_id(kwargs)
        session_id = self._ensure_session_id(run_id, kwargs.get("parent_run_id"))
        retriever_name = self._component_name(serialized, "retriever")
        agent_type = self._agent_type_for_run(kwargs, fallback="langchain")

        self._run_state[run_id] = {
            "component": "retriever",
            "name": retriever_name,
            "session_id": session_id,
            "agent_type": agent_type,
            "params": {"retriever": retriever_name, "query": query},
        }
        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="data_access",
            tool_name=None,
            target=query or None,
            params={"retriever": retriever_name, "query": query},
            result=None,
            context=self._build_context(
                component="retriever",
                phase="start",
                run_id=run_id,
                kwargs=kwargs,
                extra={
                    "name": retriever_name,
                    "serialized": self._normalize_value(serialized),
                },
            ),
        )

    def on_retriever_end(self, documents: Sequence[Any], **kwargs: Any) -> None:
        run_id = self._run_id(kwargs)
        state = self._run_state.get(run_id, {})
        session_id = str(state.get("session_id") or self._ensure_session_id(run_id, kwargs.get("parent_run_id")))
        retriever_name = str(state.get("name") or "retriever")
        agent_type = str(state.get("agent_type") or self._agent_type_for_run(kwargs, fallback="langchain"))

        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="data_access",
            tool_name=None,
            target=None,
            params=self._normalize_mapping(state.get("params")),
            result={"documents": self._normalize_documents(documents)},
            context=self._build_context(
                component="retriever",
                phase="end",
                run_id=run_id,
                kwargs=kwargs,
                extra={"name": retriever_name},
            ),
        )
        self._finalize_run(run_id)

    def on_retriever_error(self, error: BaseException, **kwargs: Any) -> None:
        run_id = self._run_id(kwargs)
        state = self._run_state.get(run_id, {})
        session_id = str(state.get("session_id") or self._ensure_session_id(run_id, kwargs.get("parent_run_id")))
        retriever_name = str(state.get("name") or "retriever")
        agent_type = str(state.get("agent_type") or self._agent_type_for_run(kwargs, fallback="langchain"))

        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="error",
            tool_name=None,
            target=None,
            params=self._normalize_mapping(state.get("params")),
            result={"message": str(error), "error_type": error.__class__.__name__},
            context=self._build_context(
                component="retriever",
                phase="error",
                run_id=run_id,
                kwargs=kwargs,
                extra={"name": retriever_name},
            ),
        )
        self._finalize_run(run_id)

    def close(self) -> None:
        close = getattr(self.client, "close", None)
        if callable(close):
            close()

    def _record_llm_start(
        self,
        *,
        serialized: Mapping[str, Any],
        prompts: list[str],
        kwargs: Mapping[str, Any],
        message_batches: Optional[list[list[JsonDict]]],
    ) -> None:
        run_id = self._run_id(kwargs)
        session_id = self._ensure_session_id(run_id, kwargs.get("parent_run_id"))
        model_name = self._extract_model_name(serialized, kwargs)
        agent_type = self._detect_agent_type(model_name)
        invocation_params = self._normalize_mapping(kwargs.get("invocation_params"))

        params: JsonDict = {
            "model": model_name,
            "prompts": prompts,
            "invocation_params": invocation_params,
        }
        if message_batches is not None:
            params["messages"] = message_batches

        self._run_state[run_id] = {
            "component": "llm",
            "name": model_name,
            "session_id": session_id,
            "agent_type": agent_type,
        }
        self._safe_ingest(
            agent_type=agent_type,
            session_id=session_id,
            action_type="decision",
            tool_name=None,
            target=None,
            params=params,
            result=None,
            context=self._build_context(
                component="llm",
                phase="start",
                run_id=run_id,
                kwargs=kwargs,
                extra={
                    "model": model_name,
                    "serialized": self._normalize_value(serialized),
                },
            ),
        )

    def _safe_ingest(
        self,
        *,
        agent_type: str,
        session_id: str,
        action_type: str,
        tool_name: Optional[str],
        target: Optional[str],
        params: Mapping[str, Any],
        result: Any,
        context: Mapping[str, Any],
    ) -> JsonDict:
        try:
            return self.client.ingest(
                agent_id=self.agent_id,
                agent_type=agent_type,
                session_id=session_id,
                action_type=action_type,
                tool_name=tool_name,
                target=target,
                params=params,
                result=result,
                context=context,
            )
        except TrailingError:
            return {}

    def _ensure_session_id(self, run_id: str, parent_run_id: Any) -> str:
        if run_id in self._session_by_run:
            return self._session_by_run[run_id]

        parent_id = self._stringify(parent_run_id)
        if parent_id and parent_id in self._session_by_run:
            session_id = self._session_by_run[parent_id]
        else:
            session_id = self.default_session_id or str(uuid.uuid4())

        self._session_by_run[run_id] = session_id
        return session_id

    def _finalize_run(self, run_id: str) -> None:
        self._run_state.pop(run_id, None)
        self._session_by_run.pop(run_id, None)

    def _build_context(
        self,
        *,
        component: str,
        phase: str,
        run_id: str,
        kwargs: Mapping[str, Any],
        extra: Optional[Mapping[str, Any]] = None,
    ) -> JsonDict:
        context: JsonDict = {
            "component": component,
            "phase": phase,
            "run_id": run_id,
            "parent_run_id": self._stringify(kwargs.get("parent_run_id")),
        }

        tags = kwargs.get("tags")
        if isinstance(tags, Sequence) and not isinstance(tags, (str, bytes)):
            context["tags"] = [str(tag) for tag in tags]

        metadata = self._normalize_value(kwargs.get("metadata"))
        if metadata is not None:
            context["metadata"] = metadata

        if extra:
            for key, value in extra.items():
                normalized = self._normalize_value(value)
                if normalized is not None:
                    context[key] = normalized

        return context

    def _agent_type_for_run(self, kwargs: Mapping[str, Any], fallback: str) -> str:
        invocation_params = kwargs.get("invocation_params")
        if isinstance(invocation_params, Mapping):
            model_name = invocation_params.get("model") or invocation_params.get("model_name")
            if model_name:
                return self._detect_agent_type(str(model_name))

        parent_id = self._stringify(kwargs.get("parent_run_id"))
        if parent_id:
            parent_state = self._run_state.get(parent_id)
            if isinstance(parent_state, Mapping) and parent_state.get("agent_type"):
                return str(parent_state["agent_type"])

        return fallback

    @staticmethod
    def _coerce(value: str) -> Any:
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return value

    @staticmethod
    def _component_name(serialized: Mapping[str, Any], fallback: str) -> str:
        name = serialized.get("name")
        if name:
            return str(name)
        identifier = serialized.get("id")
        if isinstance(identifier, list) and identifier:
            return str(identifier[-1])
        return fallback

    @staticmethod
    def _extract_model_name(serialized: Mapping[str, Any], kwargs: Mapping[str, Any]) -> str:
        invocation_params = kwargs.get("invocation_params")
        if isinstance(invocation_params, Mapping):
            for key in ("model", "model_name"):
                value = invocation_params.get(key)
                if value:
                    return str(value)

        metadata = kwargs.get("metadata")
        if isinstance(metadata, Mapping):
            for key in ("model", "model_name"):
                value = metadata.get(key)
                if value:
                    return str(value)

        kwargs_payload = serialized.get("kwargs")
        if isinstance(kwargs_payload, Mapping):
            for key in ("model", "model_name"):
                value = kwargs_payload.get(key)
                if value:
                    return str(value)

        if serialized.get("name"):
            return str(serialized["name"])
        return "unknown-model"

    @classmethod
    def _extract_target(cls, value: Any) -> Optional[str]:
        if isinstance(value, Mapping):
            for key in ("target", "resource", "file_path", "path", "url", "query"):
                candidate = value.get(key)
                if candidate:
                    return str(candidate)
        return None

    @staticmethod
    def _run_id(kwargs: Mapping[str, Any]) -> str:
        run_id = kwargs.get("run_id")
        return str(run_id) if run_id is not None else str(uuid.uuid4())

    @staticmethod
    def _stringify(value: Any) -> Optional[str]:
        return str(value) if value is not None else None

    @staticmethod
    def _optional_string(value: Any) -> Optional[str]:
        return str(value) if value is not None else None

    @staticmethod
    def _detect_agent_type(model_name: str) -> str:
        lowered = model_name.lower()
        if "claude" in lowered:
            return "claude"
        if "gpt" in lowered or "openai" in lowered or lowered.startswith(("o1", "o3", "o4")):
            return "gpt"
        if "gemini" in lowered:
            return "gemini"
        if "llama" in lowered:
            return "llama"
        if "mistral" in lowered:
            return "mistral"
        return "langchain"

    @classmethod
    def _normalize_value(cls, value: Any) -> Any:
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        if isinstance(value, Mapping):
            return {str(key): cls._normalize_value(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._normalize_value(item) for item in value]
        if hasattr(value, "model_dump") and callable(value.model_dump):
            return cls._normalize_value(value.model_dump())
        if hasattr(value, "dict") and callable(value.dict):
            try:
                return cls._normalize_value(value.dict())
            except TypeError:
                pass
        if hasattr(value, "__dict__") and value.__dict__:
            return cls._normalize_value(vars(value))
        return str(value)

    @classmethod
    def _normalize_mapping(cls, value: Any) -> JsonDict:
        normalized = cls._normalize_value(value)
        return normalized if isinstance(normalized, dict) else {}

    @classmethod
    def _serialize_messages(cls, messages: Sequence[Sequence[Any]]) -> list[list[JsonDict]]:
        return [[cls._serialize_message(message) for message in batch] for batch in messages]

    @classmethod
    def _messages_to_prompts(cls, messages: Sequence[Sequence[Any]]) -> list[str]:
        prompts: list[str] = []
        for batch in messages:
            prompts.append("\n".join(cls._stringify_message(message) for message in batch))
        return prompts

    @classmethod
    def _serialize_message(cls, message: Any) -> JsonDict:
        payload: JsonDict = {
            "type": getattr(message, "type", message.__class__.__name__),
            "content": cls._normalize_value(getattr(message, "content", message)),
        }

        for key in ("additional_kwargs", "response_metadata", "tool_calls", "name"):
            value = getattr(message, key, None)
            normalized = cls._normalize_value(value)
            if normalized is not None:
                payload[key] = normalized

        return payload

    @classmethod
    def _stringify_message(cls, message: Any) -> str:
        payload = cls._serialize_message(message)
        return f"{payload['type']}: {payload['content']}"

    @classmethod
    def _extract_generations(cls, response: Any) -> list[list[JsonDict]]:
        generations = getattr(response, "generations", None)
        if not isinstance(generations, Sequence):
            return []

        normalized: list[list[JsonDict]] = []
        for batch in generations:
            if not isinstance(batch, Sequence) or isinstance(batch, (str, bytes)):
                continue
            normalized.append([cls._normalize_generation(generation) for generation in batch])
        return normalized

    @classmethod
    def _normalize_generation(cls, generation: Any) -> JsonDict:
        payload: JsonDict = {}

        text = getattr(generation, "text", None)
        if text is not None:
            payload["text"] = cls._normalize_value(text)

        message = getattr(generation, "message", None)
        if message is not None:
            payload["message"] = cls._serialize_message(message)

        generation_info = getattr(generation, "generation_info", None)
        normalized_info = cls._normalize_value(generation_info)
        if normalized_info is not None:
            payload["generation_info"] = normalized_info

        if payload:
            return payload

        normalized = cls._normalize_value(generation)
        return normalized if isinstance(normalized, dict) else {"value": normalized}

    @classmethod
    def _extract_token_usage(cls, response: Any) -> JsonDict:
        candidates: list[Any] = []

        llm_output = getattr(response, "llm_output", None)
        if isinstance(llm_output, Mapping):
            candidates.extend(
                [
                    llm_output.get("token_usage"),
                    llm_output.get("usage"),
                    llm_output.get("usage_metadata"),
                    llm_output,
                ]
            )

        generations = getattr(response, "generations", None)
        if isinstance(generations, Sequence):
            for batch in generations:
                if not isinstance(batch, Sequence) or isinstance(batch, (str, bytes)):
                    continue
                for generation in batch:
                    message = getattr(generation, "message", None)
                    if message is not None:
                        candidates.extend(
                            [
                                getattr(message, "usage_metadata", None),
                                getattr(message, "response_metadata", None),
                            ]
                        )
                        response_metadata = getattr(message, "response_metadata", None)
                        if isinstance(response_metadata, Mapping):
                            candidates.extend(
                                [
                                    response_metadata.get("token_usage"),
                                    response_metadata.get("usage"),
                                ]
                            )
                    candidates.append(getattr(generation, "generation_info", None))

        for candidate in candidates:
            usage = cls._coerce_usage(candidate)
            if usage:
                return usage
        return {}

    @classmethod
    def _coerce_usage(cls, candidate: Any) -> JsonDict:
        if not isinstance(candidate, Mapping):
            return {}

        for nested_key in ("token_usage", "usage", "usage_metadata"):
            nested = candidate.get(nested_key)
            nested_usage = cls._coerce_usage(nested)
            if nested_usage:
                return nested_usage

        usage: JsonDict = {}
        mapping = (
            ("prompt_tokens", "prompt_tokens"),
            ("input_tokens", "prompt_tokens"),
            ("prompt_token_count", "prompt_tokens"),
            ("completion_tokens", "completion_tokens"),
            ("output_tokens", "completion_tokens"),
            ("completion_token_count", "completion_tokens"),
            ("total_tokens", "total_tokens"),
            ("total_token_count", "total_tokens"),
        )
        for source_key, target_key in mapping:
            value = candidate.get(source_key)
            if value is not None and target_key not in usage:
                usage[target_key] = value

        return usage

    @classmethod
    def _normalize_documents(cls, documents: Sequence[Any]) -> list[JsonDict]:
        normalized: list[JsonDict] = []
        for document in documents:
            if isinstance(document, Mapping):
                normalized.append(
                    {
                        "page_content": cls._normalize_value(document.get("page_content")),
                        "metadata": cls._normalize_value(document.get("metadata") or {}),
                    }
                )
                continue

            normalized.append(
                {
                    "page_content": cls._normalize_value(getattr(document, "page_content", None)),
                    "metadata": cls._normalize_value(getattr(document, "metadata", {}) or {}),
                }
            )
        return normalized


__all__ = ["TrailingCallbackHandler"]
