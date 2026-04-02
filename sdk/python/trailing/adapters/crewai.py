"""CrewAI event listener for Trailing."""

from __future__ import annotations

import uuid
from typing import Any, Callable, Dict, Iterable, Mapping, Optional

from ..client import TrailingClient, TrailingError

try:  # pragma: no cover
    import crewai.events as crewai_events
    from crewai.events import BaseEventListener
except ImportError:  # pragma: no cover
    crewai_events = None

    class BaseEventListener:  # type: ignore[override]
        """Fallback base class so the adapter remains importable without CrewAI."""


JsonDict = Dict[str, Any]
Handler = Callable[[Any, Any], None]


class TrailingCrewAIListener(BaseEventListener):
    """Forward CrewAI lifecycle, tool, memory, delegation, and approval events to Trailing."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        agent_id: str = "crewai-agent",
        api_key: Optional[str] = None,
        session_id: Optional[str] = None,
        oversight_framework: Optional[str] = None,
    ) -> None:
        self.client = TrailingClient(base_url=base_url, api_key=api_key)
        self.agent_id = agent_id
        self.default_session_id = session_id
        self.oversight_framework = oversight_framework
        self._session_by_key: Dict[str, str] = {}
        self._pending_action_ids: Dict[str, str] = {}
        super().__init__()

    def setup_listeners(self, crewai_event_bus: Any) -> None:
        self._bind_many(
            crewai_event_bus,
            ("CrewKickoffStartedEvent", "CrewStartedEvent"),
            self._on_crew_started,
        )
        self._bind_many(
            crewai_event_bus,
            ("CrewKickoffCompletedEvent", "CrewCompletedEvent"),
            self._on_crew_completed,
        )
        self._bind_many(
            crewai_event_bus,
            ("CrewKickoffFailedEvent", "CrewFailedEvent"),
            self._on_crew_failed,
        )
        self._bind_many(
            crewai_event_bus,
            ("TaskStartedEvent", "TaskExecutionStartedEvent"),
            self._on_task_started,
        )
        self._bind_many(
            crewai_event_bus,
            ("TaskCompletedEvent", "TaskExecutionCompletedEvent"),
            self._on_task_completed,
        )
        self._bind_many(
            crewai_event_bus,
            ("TaskFailedEvent", "TaskExecutionFailedEvent"),
            self._on_task_failed,
        )
        self._bind_many(
            crewai_event_bus,
            ("AgentExecutionStartedEvent", "AgentStartedEvent"),
            self._on_agent_execution_started,
        )
        self._bind_many(
            crewai_event_bus,
            ("AgentExecutionCompletedEvent", "AgentCompletedEvent"),
            self._on_agent_execution_completed,
        )
        self._bind_many(
            crewai_event_bus,
            ("AgentExecutionFailedEvent", "AgentFailedEvent"),
            self._on_agent_execution_failed,
        )
        self._bind_many(
            crewai_event_bus,
            ("ToolUsageStartedEvent",),
            self._on_tool_usage_started,
        )
        self._bind_many(
            crewai_event_bus,
            ("ToolUsageFinishedEvent", "ToolUsageCompletedEvent"),
            self._on_tool_usage_finished,
        )
        self._bind_many(
            crewai_event_bus,
            ("ToolUsageErrorEvent",),
            self._on_tool_usage_error,
        )
        self._bind_many(
            crewai_event_bus,
            (
                "MemoryQueryStartedEvent",
                "MemoryAccessStartedEvent",
                "KnowledgeRetrievalStartedEvent",
                "RetrievalStartedEvent",
            ),
            self._on_memory_started,
        )
        self._bind_many(
            crewai_event_bus,
            (
                "MemoryQueryCompletedEvent",
                "MemoryAccessCompletedEvent",
                "KnowledgeRetrievalCompletedEvent",
                "RetrievalCompletedEvent",
            ),
            self._on_memory_completed,
        )
        self._bind_many(
            crewai_event_bus,
            (
                "MemoryQueryErrorEvent",
                "MemoryAccessErrorEvent",
                "KnowledgeRetrievalErrorEvent",
                "RetrievalErrorEvent",
            ),
            self._on_memory_error,
        )
        self._bind_many(
            crewai_event_bus,
            ("AgentDelegationStartedEvent", "DelegationStartedEvent"),
            self._on_delegation_started,
        )
        self._bind_many(
            crewai_event_bus,
            ("AgentDelegationCompletedEvent", "DelegationCompletedEvent"),
            self._on_delegation_completed,
        )
        self._bind_many(
            crewai_event_bus,
            ("AgentDelegationFailedEvent", "DelegationFailedEvent"),
            self._on_delegation_failed,
        )
        self._bind_many(
            crewai_event_bus,
            (
                "HumanApprovalRequestedEvent",
                "ApprovalRequestedEvent",
                "HumanInputRequestedEvent",
            ),
            self._on_human_approval_requested,
        )
        self._bind_many(
            crewai_event_bus,
            (
                "HumanApprovalCompletedEvent",
                "HumanApprovalReceivedEvent",
                "ApprovalCompletedEvent",
                "HumanInputReceivedEvent",
            ),
            self._on_human_approval_completed,
        )

    def close(self) -> None:
        self.client.close()

    def _bind_many(self, event_bus: Any, event_names: Iterable[str], handler: Handler) -> None:
        for event_name in event_names:
            self._bind(event_bus, event_name, handler)

    def _bind(self, event_bus: Any, event_name: str, handler: Handler) -> None:
        if crewai_events is None:
            raise ImportError("CrewAI must be installed to use TrailingCrewAIListener")

        event_cls = getattr(crewai_events, event_name, None)
        if event_cls is None:
            return

        @event_bus.on(event_cls)
        def _listener(source: Any, event: Any) -> None:
            handler(source, event)

    def _on_crew_started(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        crew_name = self._crew_name(source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="session_start",
            target=crew_name,
            params={
                "crew_name": crew_name,
                "process": self._stringify(self._value(source, event, "process")),
                "task_count": self._count(self._value(source, event, "tasks")),
            },
            result=None,
            context=self._event_context(source, event, component="crew", phase="start"),
        )

    def _on_crew_completed(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="session_end",
            target=self._crew_name(source, event),
            params={"crew_name": self._crew_name(source, event)},
            result=self._stringify(self._value(source, event, "output", "result")),
            context=self._event_context(source, event, component="crew", phase="end"),
        )

    def _on_crew_failed(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="error",
            target=self._crew_name(source, event),
            params={"crew_name": self._crew_name(source, event)},
            result={"message": self._stringify(self._value(source, event, "error", "exception"))},
            context=self._event_context(source, event, component="crew", phase="error"),
        )

    def _on_task_started(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        task_name = self._task_name(source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="task_assignment",
            target=task_name,
            params={
                "task": task_name,
                "description": self._stringify(self._value(source, event, "description")),
                "expected_output": self._stringify(
                    self._value(source, event, "expected_output", "expectedOutput")
                ),
                "agent_role": self._agent_role(source, event),
            },
            result=None,
            context=self._event_context(source, event, component="task", phase="start"),
        )

    def _on_task_completed(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="task_completion",
            target=self._task_name(source, event),
            params={"task": self._task_name(source, event)},
            result=self._stringify(self._value(source, event, "output", "result")),
            context=self._event_context(source, event, component="task", phase="end"),
        )

    def _on_task_failed(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="error",
            target=self._task_name(source, event),
            params={"task": self._task_name(source, event)},
            result={"message": self._stringify(self._value(source, event, "error", "exception"))},
            context=self._event_context(source, event, component="task", phase="error"),
        )

    def _on_agent_execution_started(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="decision",
            target=self._agent_role(source, event),
            params={
                "task": self._task_name(source, event),
                "agent_role": self._agent_role(source, event),
                "inputs": self._jsonify(self._value(source, event, "inputs", "input")),
            },
            result=None,
            context=self._event_context(source, event, component="agent_execution", phase="start"),
        )

    def _on_agent_execution_completed(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="completion",
            target=self._agent_role(source, event),
            params={"task": self._task_name(source, event)},
            result=self._stringify(self._value(source, event, "output", "result")),
            context=self._event_context(source, event, component="agent_execution", phase="end"),
        )

    def _on_agent_execution_failed(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="error",
            target=self._agent_role(source, event),
            params={"task": self._task_name(source, event)},
            result={"message": self._stringify(self._value(source, event, "error", "exception"))},
            context=self._event_context(source, event, component="agent_execution", phase="error"),
        )

    def _on_tool_usage_started(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        tool_name = self._tool_name(source, event)
        tool_input = self._extract_payload(event, "tool_input", "input", "arguments")
        response = self._safe_ingest(
            session_id=session_id,
            action_type="tool_call",
            tool_name=tool_name,
            target=self._extract_target(tool_input),
            params={"input": tool_input},
            result=None,
            context=self._event_context(source, event, component="tool", phase="start"),
        )
        self._remember_action_id("tool", source, event, response)

    def _on_tool_usage_finished(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        related_action_id = self._pop_action_id("tool", source, event)
        tool_input = self._extract_payload(event, "tool_input", "input", "arguments")
        self._safe_ingest(
            session_id=session_id,
            action_type="tool_result",
            tool_name=self._tool_name(source, event),
            target=None,
            params={"input": tool_input},
            result=self._extract_payload(event, "output", "tool_output", "result"),
            context=self._event_context(
                source,
                event,
                component="tool",
                phase="end",
                related_action_id=related_action_id,
            ),
        )

    def _on_tool_usage_error(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        related_action_id = self._pop_action_id("tool", source, event)
        tool_input = self._extract_payload(event, "tool_input", "input", "arguments")
        self._safe_ingest(
            session_id=session_id,
            action_type="error",
            tool_name=self._tool_name(source, event),
            target="tool_error",
            params={"input": tool_input},
            result={"message": self._stringify(self._value(source, event, "error", "exception"))},
            context=self._event_context(
                source,
                event,
                component="tool",
                phase="error",
                related_action_id=related_action_id,
            ),
        )

    def _on_memory_started(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        query = self._extract_payload(
            event,
            "query",
            "memory_query",
            "input",
            "search_query",
            "search_term",
        )
        response = self._safe_ingest(
            session_id=session_id,
            action_type="memory_access",
            target=self._extract_target(query) or self._memory_name(source, event),
            params={
                "query": query,
                "memory": self._memory_name(source, event),
            },
            result=None,
            context=self._event_context(source, event, component="memory", phase="start"),
        )
        self._remember_action_id("memory", source, event, response)

    def _on_memory_completed(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        related_action_id = self._pop_action_id("memory", source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="memory_result",
            target=self._memory_name(source, event),
            params={
                "query": self._extract_payload(
                    event,
                    "query",
                    "memory_query",
                    "input",
                    "search_query",
                    "search_term",
                )
            },
            result=self._extract_payload(event, "results", "result", "output", "matches"),
            context=self._event_context(
                source,
                event,
                component="memory",
                phase="end",
                related_action_id=related_action_id,
            ),
        )

    def _on_memory_error(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        related_action_id = self._pop_action_id("memory", source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="error",
            target=self._memory_name(source, event),
            params={
                "query": self._extract_payload(
                    event,
                    "query",
                    "memory_query",
                    "input",
                    "search_query",
                    "search_term",
                )
            },
            result={"message": self._stringify(self._value(source, event, "error", "exception"))},
            context=self._event_context(
                source,
                event,
                component="memory",
                phase="error",
                related_action_id=related_action_id,
            ),
        )

    def _on_delegation_started(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        response = self._safe_ingest(
            session_id=session_id,
            action_type="delegation",
            target=self._delegatee(source, event),
            params={
                "from_agent": self._delegator(source, event),
                "to_agent": self._delegatee(source, event),
                "task": self._task_name(source, event),
            },
            result=None,
            context=self._event_context(source, event, component="delegation", phase="start"),
        )
        self._remember_action_id("delegation", source, event, response)

    def _on_delegation_completed(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        related_action_id = self._pop_action_id("delegation", source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="delegation_result",
            target=self._delegatee(source, event),
            params={
                "from_agent": self._delegator(source, event),
                "to_agent": self._delegatee(source, event),
                "task": self._task_name(source, event),
            },
            result=self._stringify(self._value(source, event, "output", "result")),
            context=self._event_context(
                source,
                event,
                component="delegation",
                phase="end",
                related_action_id=related_action_id,
            ),
        )

    def _on_delegation_failed(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        related_action_id = self._pop_action_id("delegation", source, event)
        self._safe_ingest(
            session_id=session_id,
            action_type="error",
            target=self._delegatee(source, event),
            params={
                "from_agent": self._delegator(source, event),
                "to_agent": self._delegatee(source, event),
                "task": self._task_name(source, event),
            },
            result={"message": self._stringify(self._value(source, event, "error", "exception"))},
            context=self._event_context(
                source,
                event,
                component="delegation",
                phase="error",
                related_action_id=related_action_id,
            ),
        )

    def _on_human_approval_requested(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        response = self._safe_ingest(
            session_id=session_id,
            action_type="human_review_requested",
            target=self._approval_scope(source, event),
            params={
                "task": self._task_name(source, event),
                "agent_role": self._agent_role(source, event),
                "request": self._extract_payload(event, "request", "prompt", "question", "input"),
            },
            result=None,
            context=self._event_context(source, event, component="approval", phase="request"),
        )
        self._remember_action_id("approval", source, event, response)

    def _on_human_approval_completed(self, source: Any, event: Any) -> None:
        session_id = self._ensure_session(source, event)
        related_action_id = self._pop_action_id("approval", source, event)
        self._safe_log_oversight(
            event_type=self._oversight_event_type(event),
            approver=self._human_actor(source, event),
            scope=self._approval_scope(source, event),
            related_action_id=related_action_id or self._stringify(
                self._value(source, event, "related_action_id", "modified_entry_id")
            ),
            session_id=session_id,
            note=self._approval_note(source, event),
            metadata={
                "decision": self._stringify(
                    self._value(source, event, "decision", "status", "outcome")
                ),
                "task": self._task_name(source, event),
                "agent_role": self._agent_role(source, event),
            },
        )

    def _safe_ingest(
        self,
        *,
        session_id: str,
        action_type: str,
        target: Optional[str],
        params: Mapping[str, Any],
        result: Any,
        context: Mapping[str, Any],
        tool_name: Optional[str] = None,
    ) -> JsonDict:
        try:
            return self.client.ingest(
                agent_id=self.agent_id,
                agent_type="crewai",
                session_id=session_id,
                action_type=action_type,
                tool_name=tool_name,
                target=target,
                params=self._jsonify(params),
                result=self._jsonify(result),
                context=self._jsonify(context),
            )
        except TrailingError:
            return {}

    def _safe_log_oversight(
        self,
        *,
        event_type: str,
        approver: str,
        scope: str,
        related_action_id: Optional[str],
        session_id: str,
        note: str,
        metadata: Mapping[str, Any],
    ) -> None:
        try:
            self.client.log_oversight(
                event_type=event_type,
                approver=approver,
                scope=scope,
                related_action_id=related_action_id,
                session_id=session_id,
                framework=self.oversight_framework,
                note=note,
                metadata=self._jsonify(metadata),
            )
        except Exception:
            return

    def _ensure_session(self, source: Any, event: Any) -> str:
        keys = self._session_keys(source, event)
        for key in keys:
            if key in self._session_by_key:
                return self._session_by_key[key]

        session_id = self.default_session_id or str(uuid.uuid4())
        for key in keys:
            self._session_by_key[key] = session_id
        return session_id

    def _session_keys(self, source: Any, event: Any) -> list[str]:
        keys = [self._identity_key(source), self._identity_key(event)]
        for candidate in (
            self._value(source, event, "session_id", "sessionId"),
            self._value(source, event, "crew_id", "crewId"),
            self._value(source, event, "crew_name", "crewName", "name"),
            self._value(source, event, "task_id", "taskId"),
            self._value(source, event, "task_name", "taskName"),
            self._value(source, event, "run_id", "runId"),
            self._value(source, event, "request_id", "requestId"),
            self._agent_role(source, event),
            self._task_name(source, event),
        ):
            if candidate:
                keys.append(f"stable:{candidate}")
        return keys

    def _remember_action_id(
        self,
        kind: str,
        source: Any,
        event: Any,
        response: Mapping[str, Any],
    ) -> None:
        action_ids = response.get("action_ids", [])
        if not isinstance(action_ids, list) or not action_ids:
            return
        action_id = action_ids[0]
        if not isinstance(action_id, str):
            return
        for key in self._pending_keys(kind, source, event):
            self._pending_action_ids[key] = action_id

    def _pop_action_id(self, kind: str, source: Any, event: Any) -> Optional[str]:
        for key in self._pending_keys(kind, source, event):
            action_id = self._pending_action_ids.pop(key, None)
            if action_id:
                return action_id
        return None

    def _pending_keys(self, kind: str, source: Any, event: Any) -> list[str]:
        keys = [f"{kind}:{self._identity_key(source)}", f"{kind}:{self._identity_key(event)}"]
        for candidate in (
            self._value(source, event, "tool_call_id", "toolCallId"),
            self._value(source, event, "query_id", "queryId"),
            self._value(source, event, "delegation_id", "delegationId"),
            self._value(source, event, "approval_id", "approvalId"),
            self._task_name(source, event),
            self._tool_name(source, event),
            self._memory_name(source, event),
            self._delegatee(source, event),
            self._approval_scope(source, event),
        ):
            if candidate:
                keys.append(f"{kind}:stable:{candidate}")
        return keys

    @staticmethod
    def _identity_key(value: Any) -> str:
        return f"{value.__class__.__name__}:{id(value)}"

    def _event_context(
        self,
        source: Any,
        event: Any,
        *,
        component: str,
        phase: str,
        related_action_id: Optional[str] = None,
    ) -> JsonDict:
        context = self._compact(
            {
                "component": component,
                "phase": phase,
                "event_type": getattr(event, "type", None) or event.__class__.__name__,
                "crew_name": self._crew_name(source, event),
                "task_name": self._task_name(source, event),
                "agent_role": self._agent_role(source, event),
                "related_action_id": related_action_id,
                "delegated_to": self._delegatee(source, event),
                "delegated_from": self._delegator(source, event),
            }
        )
        return context

    @staticmethod
    def _compact(values: Mapping[str, Any]) -> JsonDict:
        return {key: value for key, value in values.items() if value is not None}

    @staticmethod
    def _count(value: Any) -> Optional[int]:
        if value is None:
            return None
        try:
            return len(value)
        except TypeError:
            return None

    def _crew_name(self, source: Any, event: Any) -> Optional[str]:
        return self._stringify(self._value(source, event, "crew_name", "crewName", "name"))

    def _task_name(self, source: Any, event: Any) -> Optional[str]:
        return self._stringify(
            self._value(source, event, "task_name", "taskName", "name", "description")
        )

    def _agent_role(self, source: Any, event: Any) -> Optional[str]:
        agent = self._value(source, event, "agent", "sender_agent", "from_agent")
        if agent is not None:
            for attr in ("role", "name"):
                value = self._attr(agent, attr)
                if value:
                    return str(value)
        return self._stringify(self._value(source, event, "agent_role", "agentRole"))

    def _tool_name(self, source: Any, event: Any) -> Optional[str]:
        tool = self._value(source, event, "tool")
        if tool is not None:
            for attr in ("name", "__name__"):
                value = self._attr(tool, attr)
                if value:
                    return str(value)
        return self._stringify(self._value(source, event, "tool_name", "toolName"))

    def _memory_name(self, source: Any, event: Any) -> Optional[str]:
        memory = self._value(source, event, "memory", "memory_store", "knowledge_source")
        if memory is not None:
            for attr in ("name", "id"):
                value = self._attr(memory, attr)
                if value:
                    return str(value)
        return self._stringify(
            self._value(source, event, "memory_name", "memoryName", "retriever_name")
        )

    def _delegator(self, source: Any, event: Any) -> Optional[str]:
        agent = self._value(source, event, "from_agent", "sender_agent", "agent")
        if agent is not None:
            for attr in ("role", "name"):
                value = self._attr(agent, attr)
                if value:
                    return str(value)
        return self._agent_role(source, event)

    def _delegatee(self, source: Any, event: Any) -> Optional[str]:
        agent = self._value(source, event, "to_agent", "delegate_agent", "target_agent")
        if agent is not None:
            for attr in ("role", "name"):
                value = self._attr(agent, attr)
                if value:
                    return str(value)
        return self._stringify(self._value(source, event, "delegate_to", "delegateTo"))

    def _human_actor(self, source: Any, event: Any) -> str:
        actor = self._value(source, event, "reviewer", "approver", "actor", "human")
        if actor is not None:
            for attr in ("name", "id", "role"):
                value = self._attr(actor, attr)
                if value:
                    return str(value)
            return str(actor)
        return "human-reviewer"

    def _approval_scope(self, source: Any, event: Any) -> str:
        return (
            self._stringify(self._value(source, event, "scope"))
            or self._task_name(source, event)
            or self._crew_name(source, event)
            or "human-approval"
        )

    def _approval_note(self, source: Any, event: Any) -> str:
        decision = self._stringify(self._value(source, event, "decision", "status", "outcome"))
        scope = self._approval_scope(source, event)
        approver = self._human_actor(source, event)
        if decision:
            return f"{approver} recorded {decision} for {scope}"
        return f"{approver} reviewed {scope}"

    def _oversight_event_type(self, event: Any) -> str:
        decision = (
            self._stringify(self._value(event, event, "decision", "status", "outcome")) or ""
        ).lower()
        approved = self._value(event, event, "approved", "is_approved")
        if approved is True or decision in {"approved", "approve", "accepted", "granted"}:
            return "approval"
        if decision in {"override", "overridden", "rejected", "denied"}:
            return "override"
        if decision in {"escalated", "escalation"}:
            return "escalation"
        if "kill" in decision:
            return "kill_switch"
        return "review"

    def _extract_payload(self, event: Any, *names: str) -> Any:
        for name in names:
            value = self._attr(event, name)
            if value is not None:
                return self._jsonify(value)
        return {}

    def _extract_target(self, value: Any) -> Optional[str]:
        if isinstance(value, Mapping):
            for key in ("target", "resource", "file_path", "path", "url", "query"):
                candidate = value.get(key)
                if candidate:
                    return str(candidate)
        return self._stringify(value) if isinstance(value, str) else None

    def _value(self, source: Any, event: Any, *names: str) -> Any:
        for name in names:
            value = self._attr(event, name)
            if value is not None:
                return value
            value = self._attr(source, name)
            if value is not None:
                return value
        return None

    @staticmethod
    def _attr(value: Any, name: str) -> Any:
        if isinstance(value, Mapping):
            return value.get(name)
        return getattr(value, name, None)

    def _jsonify(self, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Mapping):
            return {str(key): self._jsonify(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._jsonify(item) for item in value]
        return str(value)

    @staticmethod
    def _stringify(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value)
        return str(value)
