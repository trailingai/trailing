from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest import mock


SDK_ROOT = Path(__file__).resolve().parents[1]
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from trailing.adapters.openai_agents import TrailingOpenAITracer  # noqa: E402


class RecordingClient:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.flush_count = 0
        self.closed = False

    def track(self, event: Any, *, background: bool = True) -> Dict[str, Any]:
        payload = event.to_dict()
        payload["background"] = background
        self.calls.append(payload)
        return {"action_ids": [f"action-{len(self.calls)}"], "ingested": 1}

    def flush(self) -> None:
        self.flush_count += 1

    def close(self) -> None:
        self.closed = True


class FakeSpanData:
    def __init__(self, **payload: Any) -> None:
        self._payload = dict(payload)
        for key, value in payload.items():
            setattr(self, key, value)

    def export(self) -> Dict[str, Any]:
        return dict(self._payload)


class FakeSpan:
    def __init__(
        self,
        *,
        trace_id: str,
        span_id: str,
        parent_id: str | None = None,
        started_at: str = "2025-01-01T00:00:00Z",
        ended_at: str = "2025-01-01T00:00:01Z",
        trace_metadata: Dict[str, Any] | None = None,
        error: Any = None,
        **payload: Any,
    ) -> None:
        self.trace_id = trace_id
        self.span_id = span_id
        self.parent_id = parent_id
        self.started_at = started_at
        self.ended_at = ended_at
        self.trace_metadata = trace_metadata or {}
        self.error = error
        self.span_data = FakeSpanData(**payload)


class OpenAIAgentsAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = RecordingClient()
        self.tracer = TrailingOpenAITracer(
            agent_id="openai-agents-audit",
            session_id="default-session",
            client=self.client,
            background=False,
        )

    def test_tracer_can_be_instantiated_without_real_http_calls(self) -> None:
        mocked_client = RecordingClient()

        with mock.patch(
            "trailing.adapters.openai_agents.TrailingClient",
            return_value=mocked_client,
        ) as client_cls:
            tracer = TrailingOpenAITracer(
                base_url="http://trailing.test",
                api_key="test-key",
                background=False,
            )

        self.assertIs(tracer.client, mocked_client)
        self.assertTrue(tracer._owns_client)
        self.assertEqual(tracer.agent_id, "openai-agent")
        self.assertEqual(tracer.agent_type, "openai")
        client_cls.assert_called_once_with(base_url="http://trailing.test", api_key="test-key")

    def test_span_events_produce_expected_action_payloads(self) -> None:
        trace = SimpleNamespace(
            trace_id="trace-123",
            group_id="thread-123",
            name="customer_support",
            metadata={"thread_id": "thread-123", "tenant": "acme"},
        )
        generation_span = FakeSpan(
            trace_id="trace-123",
            span_id="span-generation",
            type="generation",
            model="gpt-4.1-mini",
            input=[{"role": "user", "content": "Summarize the ticket"}],
            model_config={"temperature": 0},
            tools=[{"type": "function", "name": "lookup_ticket"}],
            output={"output_text": "The ticket is resolved."},
            usage={"input_tokens": 12, "output_tokens": 5},
            response={"model": "gpt-4.1-mini", "status": "completed"},
        )
        function_span = FakeSpan(
            trace_id="trace-123",
            span_id="span-function",
            parent_id="span-generation",
            type="function",
            name="lookup_ticket",
            input='{"url":"crm://tickets/42","ticket_id":"42"}',
            output='{"status":"resolved"}',
        )
        retrieval_span = FakeSpan(
            trace_id="trace-123",
            span_id="span-retrieval",
            parent_id="span-generation",
            type="function",
            name="file_search",
            input='{"query":"refund policy"}',
            output='{"documents":[{"id":"doc-1"}]}',
        )

        self.tracer.on_trace_start(trace)
        self.tracer.on_span_start(generation_span)
        self.tracer.on_span_end(generation_span)
        self.tracer.on_span_start(function_span)
        self.tracer.on_span_end(function_span)
        self.tracer.on_span_start(retrieval_span)
        self.tracer.on_span_end(retrieval_span)

        self.assertEqual(
            [call["action"]["action_type"] for call in self.client.calls],
            [
                "session_start",
                "llm_request",
                "llm_response",
                "tool_call",
                "tool_result",
                "retrieval",
                "retrieval_result",
            ],
        )
        for call in self.client.calls:
            self.assertEqual(call["session_id"], "thread-123")
            self.assertFalse(call["background"])

        llm_request = self.client.calls[1]
        self.assertEqual(llm_request["action"]["target"], "gpt-4.1-mini")
        self.assertEqual(
            llm_request["action"]["parameters"]["messages"][0]["content"],
            "Summarize the ticket",
        )

        llm_response = self.client.calls[2]
        self.assertEqual(llm_response["action"]["result"]["completion"], "The ticket is resolved.")
        self.assertEqual(
            llm_response["action"]["result"]["usage"],
            {"input_tokens": 12, "output_tokens": 5},
        )

        tool_call = self.client.calls[3]
        self.assertEqual(tool_call["action"]["tool_name"], "lookup_ticket")
        self.assertEqual(tool_call["action"]["target"], "crm://tickets/42")
        self.assertEqual(tool_call["action"]["parameters"]["arguments"]["ticket_id"], "42")

        tool_result = self.client.calls[4]
        self.assertEqual(tool_result["action"]["tool_name"], "lookup_ticket")
        self.assertEqual(tool_result["action"]["result"]["output"], {"status": "resolved"})

        retrieval_call = self.client.calls[5]
        self.assertEqual(retrieval_call["action"]["action_type"], "retrieval")
        self.assertEqual(retrieval_call["action"]["target"], "refund policy")
        self.assertEqual(retrieval_call["context"]["data_accessed"], ["refund policy"])

        retrieval_result = self.client.calls[6]
        self.assertEqual(retrieval_result["action"]["action_type"], "retrieval_result")
        self.assertEqual(retrieval_result["action"]["result"]["output"]["documents"][0]["id"], "doc-1")

    def test_trace_processor_lifecycle_methods(self) -> None:
        mocked_client = RecordingClient()

        with mock.patch(
            "trailing.adapters.openai_agents.TrailingClient",
            return_value=mocked_client,
        ):
            tracer = TrailingOpenAITracer(background=False)

        trace = SimpleNamespace(
            trace_id="trace-lifecycle",
            group_id="workflow-123",
            name="daily_sync",
            metadata={"thread_id": "thread-999"},
        )

        tracer.on_trace_start(trace)
        tracer.on_trace_end(trace)
        tracer.force_flush()
        tracer.shutdown()

        self.assertEqual(
            [call["action"]["action_type"] for call in mocked_client.calls],
            ["session_start", "session_end"],
        )
        self.assertEqual(mocked_client.calls[0]["session_id"], "workflow-123")
        self.assertEqual(mocked_client.calls[0]["action"]["target"], "daily_sync")
        self.assertEqual(mocked_client.calls[1]["action"]["parameters"]["group_id"], "workflow-123")
        self.assertEqual(mocked_client.flush_count, 2)
        self.assertTrue(mocked_client.closed)


if __name__ == "__main__":
    unittest.main()
