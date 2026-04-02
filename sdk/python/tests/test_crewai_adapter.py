from __future__ import annotations

import inspect
import importlib
import sys
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SDK_ROOT = REPO_ROOT / "sdk" / "python"
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from trailing import TrailingClient  # noqa: E402
from trailing.adapters import crewai as crewai_adapter  # noqa: E402


class FakeClient:
    def __init__(self) -> None:
        self.ingest_calls = []
        self.oversight_calls = []
        self.closed = False

    def ingest(self, **kwargs):
        self.ingest_calls.append(kwargs)
        return {"action_ids": [f"action-{len(self.ingest_calls)}"], "ingested": 1}

    def log_oversight(
        self,
        event_type,
        approver,
        scope,
        related_action_id=None,
        session_id=None,
        framework=None,
        note=None,
        metadata=None,
    ):
        self.oversight_calls.append(
            {
                "event_type": event_type,
                "approver": approver,
                "scope": scope,
                "related_action_id": related_action_id,
                "session_id": session_id,
                "framework": framework,
                "note": note,
                "metadata": metadata,
            }
        )
        return {"id": f"oversight-{len(self.oversight_calls)}"}

    def close(self) -> None:
        self.closed = True


class FakeEventBus:
    def __init__(self) -> None:
        self.listeners = {}

    def on(self, event_cls):
        def decorator(handler):
            self.listeners.setdefault(event_cls, []).append(handler)
            return handler

        return decorator

    def emit(self, event_cls, source, event) -> None:
        for handler in self.listeners.get(event_cls, []):
            handler(source, event)


class CrewAIAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self._original_crewai_events = crewai_adapter.crewai_events

    def tearDown(self) -> None:
        crewai_adapter.crewai_events = self._original_crewai_events

    def test_fake_client_matches_real_oversight_signature(self) -> None:
        real_params = [
            (param.name, param.kind, param.default)
            for param in inspect.signature(TrailingClient.log_oversight).parameters.values()
        ]
        fake_params = [
            (param.name, param.kind, param.default)
            for param in inspect.signature(FakeClient.log_oversight).parameters.values()
        ]

        self.assertEqual(fake_params, real_params)

    def test_lifecycle_and_tool_events_are_forwarded(self) -> None:
        event_types = types.SimpleNamespace(
            CrewKickoffStartedEvent=type("CrewKickoffStartedEvent", (), {}),
            TaskStartedEvent=type("TaskStartedEvent", (), {}),
            AgentExecutionStartedEvent=type("AgentExecutionStartedEvent", (), {}),
            ToolUsageStartedEvent=type("ToolUsageStartedEvent", (), {}),
            ToolUsageFinishedEvent=type("ToolUsageFinishedEvent", (), {}),
            TaskCompletedEvent=type("TaskCompletedEvent", (), {}),
            AgentExecutionCompletedEvent=type("AgentExecutionCompletedEvent", (), {}),
            CrewKickoffCompletedEvent=type("CrewKickoffCompletedEvent", (), {}),
        )
        crewai_adapter.crewai_events = event_types

        listener = crewai_adapter.TrailingCrewAIListener(session_id="crew-session")
        fake_client = FakeClient()
        listener.client = fake_client

        bus = FakeEventBus()
        listener.setup_listeners(bus)

        agent = types.SimpleNamespace(role="Research Analyst")
        tool = types.SimpleNamespace(name="query_kb")
        crew = types.SimpleNamespace(name="care-crew", tasks=["task-1"], process="sequential")
        task = types.SimpleNamespace(
            description="Collect discharge notes",
            expected_output="Risk summary",
            agent=agent,
        )

        bus.emit(
            event_types.CrewKickoffStartedEvent,
            crew,
            types.SimpleNamespace(crew_name="care-crew"),
        )
        bus.emit(event_types.TaskStartedEvent, task, types.SimpleNamespace(agent=agent))
        bus.emit(
            event_types.AgentExecutionStartedEvent,
            task,
            types.SimpleNamespace(agent=agent),
        )
        bus.emit(
            event_types.ToolUsageStartedEvent,
            types.SimpleNamespace(tool=tool),
            types.SimpleNamespace(tool=tool, tool_input={"target": "kb://patients/42"}),
        )
        bus.emit(
            event_types.ToolUsageFinishedEvent,
            types.SimpleNamespace(tool=tool),
            types.SimpleNamespace(tool=tool, output={"matches": 2}),
        )
        bus.emit(
            event_types.TaskCompletedEvent,
            task,
            types.SimpleNamespace(output="summary ready"),
        )
        bus.emit(
            event_types.AgentExecutionCompletedEvent,
            task,
            types.SimpleNamespace(agent=agent, output="approved draft"),
        )
        bus.emit(
            event_types.CrewKickoffCompletedEvent,
            crew,
            types.SimpleNamespace(crew_name="care-crew", output="done"),
        )

        self.assertEqual(
            [call["action_type"] for call in fake_client.ingest_calls],
            [
                "session_start",
                "task_assignment",
                "decision",
                "tool_call",
                "tool_result",
                "task_completion",
                "completion",
                "session_end",
            ],
        )
        self.assertEqual(fake_client.ingest_calls[3]["target"], "kb://patients/42")
        self.assertEqual(
            fake_client.ingest_calls[4]["context"]["related_action_id"],
            "action-4",
        )

    def test_memory_delegation_and_human_approval_are_captured(self) -> None:
        event_types = types.SimpleNamespace(
            MemoryQueryStartedEvent=type("MemoryQueryStartedEvent", (), {}),
            MemoryQueryCompletedEvent=type("MemoryQueryCompletedEvent", (), {}),
            AgentDelegationStartedEvent=type("AgentDelegationStartedEvent", (), {}),
            AgentDelegationCompletedEvent=type("AgentDelegationCompletedEvent", (), {}),
            HumanApprovalRequestedEvent=type("HumanApprovalRequestedEvent", (), {}),
            HumanApprovalCompletedEvent=type("HumanApprovalCompletedEvent", (), {}),
        )
        crewai_adapter.crewai_events = event_types

        listener = crewai_adapter.TrailingCrewAIListener(
            session_id="crew-session",
            oversight_framework="eu-ai-act",
        )
        fake_client = FakeClient()
        listener.client = fake_client

        bus = FakeEventBus()
        listener.setup_listeners(bus)

        sender = types.SimpleNamespace(role="Planner")
        delegate = types.SimpleNamespace(role="Reviewer")
        memory = types.SimpleNamespace(name="patient-memory")
        source = types.SimpleNamespace(description="Review chart", agent=sender)

        bus.emit(
            event_types.MemoryQueryStartedEvent,
            types.SimpleNamespace(memory=memory),
            types.SimpleNamespace(query={"query": "allergies"}),
        )
        bus.emit(
            event_types.MemoryQueryCompletedEvent,
            types.SimpleNamespace(memory=memory),
            types.SimpleNamespace(result=[{"record": "peanut allergy"}]),
        )
        bus.emit(
            event_types.AgentDelegationStartedEvent,
            source,
            types.SimpleNamespace(from_agent=sender, to_agent=delegate),
        )
        bus.emit(
            event_types.AgentDelegationCompletedEvent,
            source,
            types.SimpleNamespace(from_agent=sender, to_agent=delegate, output="handoff done"),
        )
        bus.emit(
            event_types.HumanApprovalRequestedEvent,
            source,
            types.SimpleNamespace(scope="release-plan", prompt="Approve release?"),
        )
        bus.emit(
            event_types.HumanApprovalCompletedEvent,
            source,
            types.SimpleNamespace(
                scope="release-plan",
                status="approved",
                approver="alice.supervisor",
            ),
        )

        self.assertEqual(
            [call["action_type"] for call in fake_client.ingest_calls],
            [
                "memory_access",
                "memory_result",
                "delegation",
                "delegation_result",
                "human_review_requested",
            ],
        )
        self.assertEqual(
            fake_client.ingest_calls[1]["context"]["related_action_id"],
            "action-1",
        )
        self.assertEqual(
            fake_client.ingest_calls[3]["context"]["related_action_id"],
            "action-3",
        )
        self.assertEqual(len(fake_client.oversight_calls), 1)
        self.assertEqual(fake_client.oversight_calls[0]["event_type"], "approval")
        self.assertEqual(fake_client.oversight_calls[0]["framework"], "eu-ai-act")
        self.assertEqual(fake_client.oversight_calls[0]["related_action_id"], "action-5")
        self.assertEqual(fake_client.oversight_calls[0]["session_id"], "crew-session")

    def test_oversight_logging_exceptions_are_swallowed(self) -> None:
        class FailingOversightClient(FakeClient):
            def log_oversight(
                self,
                event_type,
                approver,
                scope,
                related_action_id=None,
                session_id=None,
                framework=None,
                note=None,
                metadata=None,
            ):
                raise TypeError("signature mismatch")

        listener = crewai_adapter.TrailingCrewAIListener(
            session_id="crew-session",
            oversight_framework="eu-ai-act",
        )
        listener.client = FailingOversightClient()

        listener._safe_log_oversight(
            event_type="approval",
            approver="alice.supervisor",
            scope="release-plan",
            related_action_id="action-5",
            session_id="crew-session",
            note="approved release",
            metadata={"decision": "approved"},
        )

    def test_example_wrappers_export_packaged_sdk(self) -> None:
        trailing_modules = {
            key: value
            for key, value in sys.modules.items()
            if key == "trailing" or key.startswith("trailing.") or key == "trailing_crewai"
        }
        original_path = list(sys.path)
        try:
            for key in list(trailing_modules):
                sys.modules.pop(key, None)

            sys.path.insert(0, str(REPO_ROOT / "examples" / "python-sdk"))
            sys.path.insert(0, str(REPO_ROOT / "examples" / "crewai"))

            python_sdk_wrapper = importlib.import_module("trailing")
            crewai_wrapper = importlib.import_module("trailing_crewai")

            self.assertEqual(
                python_sdk_wrapper.TrailingClient.__name__,
                TrailingClient.__name__,
            )
            self.assertTrue(hasattr(python_sdk_wrapper.TrailingClient, "ingest"))
            self.assertTrue(hasattr(crewai_wrapper, "TrailingCrewAIListener"))
        finally:
            sys.path[:] = original_path
            for key in list(sys.modules):
                if key == "trailing" or key.startswith("trailing.") or key == "trailing_crewai":
                    sys.modules.pop(key, None)
            sys.modules.update(trailing_modules)


if __name__ == "__main__":
    unittest.main()
