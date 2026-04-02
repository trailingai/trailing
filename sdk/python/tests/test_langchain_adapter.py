from __future__ import annotations

import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional


SDK_ROOT = Path(__file__).resolve().parents[1]
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from trailing.adapters.langchain import TrailingCallbackHandler


class RecordingClient:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.closed = False

    def ingest(
        self,
        *,
        agent_id: str,
        agent_type: str,
        session_id: str,
        action_type: str,
        tool_name: Optional[str],
        target: Optional[str],
        params: Dict[str, Any],
        result: Any,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        self.calls.append(
            {
                "agent_id": agent_id,
                "agent_type": agent_type,
                "session_id": session_id,
                "action_type": action_type,
                "tool_name": tool_name,
                "target": target,
                "params": params,
                "result": result,
                "context": context,
            }
        )
        return {"ingested": 1, "action_ids": [f"action-{len(self.calls)}"]}

    def close(self) -> None:
        self.closed = True


class FakeMessage:
    def __init__(
        self,
        message_type: str,
        content: Any,
        *,
        additional_kwargs: Optional[Dict[str, Any]] = None,
        response_metadata: Optional[Dict[str, Any]] = None,
        usage_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.type = message_type
        self.content = content
        self.additional_kwargs = additional_kwargs or {}
        self.response_metadata = response_metadata or {}
        self.usage_metadata = usage_metadata or {}


class FakeDocument:
    def __init__(self, page_content: str, metadata: Dict[str, Any]) -> None:
        self.page_content = page_content
        self.metadata = metadata


class TrailingLangChainAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = RecordingClient()
        self.handler = TrailingCallbackHandler(
            agent_id="langchain-audit-agent",
            session_id="session-123",
            client=self.client,
        )
        self.chain_run_id = uuid.uuid4()

    def tearDown(self) -> None:
        self.handler.close()
        self.assertTrue(self.client.closed)

    def test_records_chain_llm_and_streaming_events(self) -> None:
        llm_run_id = uuid.uuid4()
        messages = [
            [
                FakeMessage("system", "You are a careful reviewer."),
                FakeMessage("human", "Summarize this chart."),
            ]
        ]

        self.handler.on_chain_start(
            {"name": "patient_summary_chain"},
            {"patient_id": "123"},
            run_id=self.chain_run_id,
            metadata={"workflow": "triage"},
        )
        self.handler.on_chat_model_start(
            {"name": "ChatOpenAI"},
            messages,
            run_id=llm_run_id,
            parent_run_id=self.chain_run_id,
            invocation_params={"model": "gpt-4.1-mini", "temperature": 0},
            tags=["clinical"],
        )
        self.handler.on_llm_new_token(
            "Hello",
            run_id=llm_run_id,
            parent_run_id=self.chain_run_id,
            chunk=FakeMessage("ai", "Hello"),
        )
        self.handler.on_llm_end(
            SimpleNamespace(
                llm_output={"token_usage": {"prompt_tokens": 9, "completion_tokens": 2, "total_tokens": 11}},
                generations=[
                    [
                        SimpleNamespace(
                            text="Hello world",
                            message=FakeMessage(
                                "ai",
                                "Hello world",
                                usage_metadata={"input_tokens": 9, "output_tokens": 2, "total_tokens": 11},
                            ),
                        )
                    ]
                ],
            ),
            run_id=llm_run_id,
            parent_run_id=self.chain_run_id,
        )
        self.handler.on_chain_end(
            {"output": "Hello world"},
            run_id=self.chain_run_id,
        )

        self.assertEqual([call["action_type"] for call in self.client.calls], ["session_start", "decision", "decision", "completion", "session_end"])
        for call in self.client.calls:
            self.assertEqual(call["session_id"], "session-123")

        llm_start = self.client.calls[1]
        self.assertEqual(llm_start["agent_type"], "gpt")
        self.assertEqual(llm_start["params"]["model"], "gpt-4.1-mini")
        self.assertEqual(llm_start["params"]["messages"][0][0]["type"], "system")
        self.assertEqual(llm_start["context"]["phase"], "start")

        token_event = self.client.calls[2]
        self.assertEqual(token_event["params"]["token"], "Hello")
        self.assertEqual(token_event["context"]["phase"], "stream")

        llm_end = self.client.calls[3]
        self.assertEqual(
            llm_end["result"]["token_usage"],
            {"prompt_tokens": 9, "completion_tokens": 2, "total_tokens": 11},
        )
        self.assertEqual(llm_end["result"]["generations"][0][0]["text"], "Hello world")

    def test_records_tool_and_retriever_lifecycle(self) -> None:
        tool_run_id = uuid.uuid4()
        retriever_run_id = uuid.uuid4()

        self.handler.on_chain_start(
            {"name": "tool_chain"},
            {"query": "latest lab"},
            run_id=self.chain_run_id,
        )
        self.handler.on_tool_start(
            {"name": "lookup_patient"},
            '{"query": "patient-123", "url": "ehr://patients/123"}',
            run_id=tool_run_id,
            parent_run_id=self.chain_run_id,
        )
        self.handler.on_tool_end(
            {"records": 2},
            run_id=tool_run_id,
            parent_run_id=self.chain_run_id,
        )
        self.handler.on_retriever_start(
            {"name": "chart_retriever"},
            "A1C trend",
            run_id=retriever_run_id,
            parent_run_id=self.chain_run_id,
        )
        self.handler.on_retriever_end(
            [
                FakeDocument("A1C was elevated last quarter.", {"source": "chart", "page": 1}),
                FakeDocument("Medication was adjusted.", {"source": "chart", "page": 2}),
            ],
            run_id=retriever_run_id,
            parent_run_id=self.chain_run_id,
        )

        tool_start = self.client.calls[1]
        self.assertEqual(tool_start["action_type"], "tool_call")
        self.assertEqual(tool_start["tool_name"], "lookup_patient")
        self.assertEqual(tool_start["target"], "ehr://patients/123")

        tool_end = self.client.calls[2]
        self.assertEqual(tool_end["action_type"], "tool_result")
        self.assertEqual(tool_end["result"], {"records": 2})

        retriever_start = self.client.calls[3]
        self.assertEqual(retriever_start["action_type"], "data_access")
        self.assertEqual(retriever_start["target"], "A1C trend")

        retriever_end = self.client.calls[4]
        self.assertEqual(retriever_end["result"]["documents"][0]["metadata"]["source"], "chart")
        self.assertEqual(retriever_end["context"]["phase"], "end")

    def test_records_tool_errors(self) -> None:
        tool_run_id = uuid.uuid4()

        self.handler.on_chain_start(
            {"name": "error_chain"},
            {"query": "patient"},
            run_id=self.chain_run_id,
        )
        self.handler.on_tool_start(
            {"name": "lookup_patient"},
            '{"query": "patient-123"}',
            run_id=tool_run_id,
            parent_run_id=self.chain_run_id,
        )
        self.handler.on_tool_error(
            RuntimeError("downstream timeout"),
            run_id=tool_run_id,
            parent_run_id=self.chain_run_id,
        )
        self.handler.on_chain_error(
            ValueError("workflow failed"),
            run_id=self.chain_run_id,
        )

        tool_error = self.client.calls[2]
        self.assertEqual(tool_error["action_type"], "error")
        self.assertEqual(tool_error["tool_name"], "lookup_patient")
        self.assertEqual(tool_error["result"]["error_type"], "RuntimeError")

        chain_error = self.client.calls[3]
        self.assertEqual(chain_error["action_type"], "error")
        self.assertEqual(chain_error["context"]["component"], "chain")


if __name__ == "__main__":
    unittest.main()
