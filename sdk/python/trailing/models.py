from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


JsonObject = dict[str, Any]


def _copy_mapping(value: Mapping[str, Any] | None) -> JsonObject:
    if value is None:
        return {}
    return dict(value)


def _copy_strings(values: list[str] | tuple[str, ...] | None) -> list[str]:
    if values is None:
        return []
    return [str(item) for item in values]


@dataclass(slots=True)
class SdkContext:
    data_accessed: list[str] = field(default_factory=list)
    permissions_used: list[str] = field(default_factory=list)
    policy_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> JsonObject:
        return {
            "data_accessed": _copy_strings(self.data_accessed),
            "permissions_used": _copy_strings(self.permissions_used),
            "policy_refs": _copy_strings(self.policy_refs),
        }


@dataclass(slots=True)
class SdkAction:
    action_type: str
    tool_name: str | None = None
    target: str | None = None
    parameters: JsonObject = field(default_factory=dict)
    result: Any = None

    @classmethod
    def decision(
        cls,
        *,
        action_type: str = "decision",
        parameters: Mapping[str, Any] | None = None,
        result: Any = None,
        target: str | None = None,
    ) -> "SdkAction":
        return cls(
            action_type=action_type,
            target=target,
            parameters=_copy_mapping(parameters),
            result=result,
        )

    @classmethod
    def tool_call(
        cls,
        *,
        tool_name: str,
        target: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        result: Any = None,
        action_type: str = "tool_call",
    ) -> "SdkAction":
        return cls(
            action_type=action_type,
            tool_name=tool_name,
            target=target,
            parameters=_copy_mapping(parameters),
            result=result,
        )

    def to_dict(self) -> JsonObject:
        return {
            "action_type": self.action_type,
            "tool_name": self.tool_name,
            "target": self.target,
            "parameters": _copy_mapping(self.parameters),
            "result": self.result,
        }


@dataclass(slots=True)
class SdkEvent:
    agent_id: str
    agent_type: str
    session_id: str
    action: SdkAction
    context: SdkContext = field(default_factory=SdkContext)

    @classmethod
    def build(
        cls,
        *,
        agent_id: str,
        agent_type: str,
        session_id: str,
        action_type: str,
        tool_name: str | None = None,
        target: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        result: Any = None,
        context: SdkContext | None = None,
    ) -> "SdkEvent":
        return cls(
            agent_id=agent_id,
            agent_type=agent_type,
            session_id=session_id,
            action=SdkAction(
                action_type=action_type,
                tool_name=tool_name,
                target=target,
                parameters=_copy_mapping(parameters),
                result=result,
            ),
            context=context or SdkContext(),
        )

    @classmethod
    def tool_call(
        cls,
        *,
        agent_id: str,
        agent_type: str,
        session_id: str,
        tool_name: str,
        target: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        result: Any = None,
        context: SdkContext | None = None,
        action_type: str = "tool_call",
    ) -> "SdkEvent":
        return cls(
            agent_id=agent_id,
            agent_type=agent_type,
            session_id=session_id,
            action=SdkAction.tool_call(
                tool_name=tool_name,
                target=target,
                parameters=parameters,
                result=result,
                action_type=action_type,
            ),
            context=context or SdkContext(),
        )

    @classmethod
    def decision(
        cls,
        *,
        agent_id: str,
        agent_type: str,
        session_id: str,
        parameters: Mapping[str, Any] | None = None,
        result: Any = None,
        context: SdkContext | None = None,
        action_type: str = "decision",
        target: str | None = None,
    ) -> "SdkEvent":
        return cls(
            agent_id=agent_id,
            agent_type=agent_type,
            session_id=session_id,
            action=SdkAction.decision(
                action_type=action_type,
                parameters=parameters,
                result=result,
                target=target,
            ),
            context=context or SdkContext(),
        )

    def to_dict(self) -> JsonObject:
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "session_id": self.session_id,
            "action": self.action.to_dict(),
            "context": self.context.to_dict(),
        }
