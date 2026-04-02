from __future__ import annotations

import asyncio
import json
import time
import unittest
import urllib.parse
from typing import Any
from unittest.mock import patch

from trailing import AsyncTrailingClient, RedactionConfig, RetryConfig, SdkEvent, TrailingClient


class _ScriptedTransport:
    """Mock transport that intercepts _perform_request on TrailingClient."""

    def __init__(self, responses: dict[tuple[str, str], list[tuple[int, Any]]]) -> None:
        self._responses = {key: list(value) for key, value in responses.items()}
        self.requests: list[dict[str, Any]] = []
        self._patch: Any = None

    def __enter__(self) -> "_ScriptedTransport":
        self._patch = patch.object(
            TrailingClient, "_perform_request", side_effect=self._handle
        )
        self._patch.start()
        return self

    def __exit__(self, *_: object) -> None:
        if self._patch is not None:
            self._patch.stop()

    @property
    def base_url(self) -> str:
        return "http://trailing.test"

    def _handle(
        self, method: str, request_target: str, headers: Any, body: bytes | None
    ) -> tuple[int, bytes]:
        path = request_target.split("?")[0]
        query = request_target.split("?")[1] if "?" in request_target else ""
        payload = json.loads(body.decode("utf-8")) if body else None
        self.requests.append(
            {
                "method": method,
                "path": path,
                "query": query,
                "payload": payload,
                "headers": dict(headers) if headers else {},
            }
        )

        key = (method, path)
        scripted = self._responses.get(key, [])
        if scripted:
            status_code, response_body = scripted.pop(0)
        else:
            status_code, response_body = (200, {})

        if isinstance(response_body, (dict, list)):
            encoded = json.dumps(response_body).encode("utf-8")
        else:
            encoded = (
                response_body if isinstance(response_body, bytes) else str(response_body).encode("utf-8")
            )

        return status_code, encoded


class ClientTests(unittest.TestCase):
    def test_send_event_retries_and_redacts_payload(self) -> None:
        responses = {
            ("POST", "/v1/traces"): [
                (500, {"error": "try again"}),
                (201, {"ingested": 1, "action_ids": ["action-1"]}),
            ]
        }
        event = SdkEvent.tool_call(
            agent_id="agent-1",
            agent_type="codex",
            session_id="session-1",
            tool_name="shell",
            target="cargo test",
            parameters={"password": "secret-value"},
        )

        with _ScriptedTransport(responses) as server:
            client = TrailingClient(
                base_url=server.base_url,
                retry_config=RetryConfig(max_attempts=2, initial_delay=0.01, max_delay=0.01),
                redaction_config=RedactionConfig(redact_keys=frozenset({"password"})),
                enable_background_queue=False,
            )
            response = client.send_event(event)

        self.assertEqual(response["ingested"], 1)
        self.assertEqual(len(server.requests), 2)
        self.assertEqual(
            server.requests[-1]["payload"]["actions"][0]["action"]["parameters"]["password"],
            "[REDACTED]",
        )

    def test_background_queue_batches_until_flush(self) -> None:
        responses = {("POST", "/v1/traces"): [(201, {"ingested": 2, "action_ids": ["a", "b"]})]}

        with _ScriptedTransport(responses) as server:
            client = TrailingClient(
                base_url=server.base_url,
                batch_size=2,
                flush_interval=60.0,
                enable_background_queue=True,
            )
            client.enqueue(
                SdkEvent.decision(
                    agent_id="agent-1",
                    agent_type="codex",
                    session_id="session-1",
                    parameters={"step": "plan"},
                )
            )
            client.enqueue(
                SdkEvent.decision(
                    agent_id="agent-1",
                    agent_type="codex",
                    session_id="session-1",
                    parameters={"step": "execute"},
                )
            )
            client.flush()
            client.close()

        self.assertEqual(len(server.requests), 1)
        self.assertEqual(len(server.requests[0]["payload"]["actions"]), 2)

    def test_ingest_preserves_legacy_context_shape(self) -> None:
        responses = {("POST", "/v1/traces"): [(201, {"ingested": 1, "action_ids": ["legacy-1"]})]}

        with _ScriptedTransport(responses) as server:
            client = TrailingClient(base_url=server.base_url, enable_background_queue=False)
            client.ingest(
                agent_id="agent-1",
                agent_type="gpt",
                session_id="session-1",
                action_type="tool_call",
                tool_name="query_ehr",
                target="ehr://patients/1",
                params={"patient_id": "1"},
                result={"records": 1},
                context={"workflow": "triage"},
            )

        payload = server.requests[0]["payload"]["actions"][0]
        self.assertEqual(payload["context"]["workflow"], "triage")
        self.assertEqual(payload["action"]["tool_name"], "query_ehr")

    def test_get_actions_supports_type_filter(self) -> None:
        responses = {("GET", "/v1/actions"): [(200, {"actions": [{"id": "action-1"}]})]}

        with _ScriptedTransport(responses) as server:
            client = TrailingClient(base_url=server.base_url, enable_background_queue=False)
            actions = client.get_actions(
                session_id="session-1",
                agent="agent-1",
                action_type="tool_call",
            )

        self.assertEqual(actions, [{"id": "action-1"}])
        self.assertEqual(server.requests[0]["path"], "/v1/actions")
        self.assertEqual(
            urllib.parse.parse_qs(server.requests[0]["query"]),
            {"agent": ["agent-1"], "session_id": ["session-1"], "type": ["tool_call"]},
        )

    def test_get_health_uses_health_endpoint(self) -> None:
        responses = {("GET", "/v1/health"): [(200, {"status": "ok", "service": "trailing"})]}

        with _ScriptedTransport(responses) as server:
            client = TrailingClient(base_url=server.base_url, enable_background_queue=False)
            health = client.get_health()

        self.assertEqual(health["status"], "ok")
        self.assertEqual(server.requests[0]["path"], "/v1/health")


class AsyncClientTests(unittest.TestCase):
    def test_async_client_uses_same_transport(self) -> None:
        asyncio.run(self._run_async_client_test())

    def test_async_client_does_not_block_event_loop(self) -> None:
        asyncio.run(self._run_async_non_blocking_test())

    async def _run_async_client_test(self) -> None:
        responses = {("POST", "/v1/traces"): [(201, {"ingested": 1, "action_ids": ["async-1"]})]}

        with _ScriptedTransport(responses) as server:
            async with AsyncTrailingClient(
                base_url=server.base_url,
                enable_background_queue=False,
            ) as client:
                response = await client.send_event(
                    SdkEvent.tool_call(
                        agent_id="agent-async",
                        agent_type="codex",
                        session_id="session-async",
                        tool_name="web.search",
                        parameters={"query": "policy"},
                    )
                )

        self.assertEqual(response["action_ids"], ["async-1"])
        self.assertEqual(server.requests[0]["payload"]["actions"][0]["agent_id"], "agent-async")

    async def _run_async_non_blocking_test(self) -> None:
        event = SdkEvent.tool_call(
            agent_id="agent-async",
            agent_type="codex",
            session_id="session-async",
            tool_name="web.search",
            parameters={"query": "policy"},
        )

        original_perform = TrailingClient._perform_request

        def slow_perform(method: str, request_target: str, headers: Any, body: Any) -> tuple[int, bytes]:
            time.sleep(0.05)
            return (201, b'{"ingested": 1, "action_ids": ["async-1"]}')

        async with AsyncTrailingClient(
            base_url="http://trailing.test",
            enable_background_queue=False,
        ) as client:
            with patch.object(TrailingClient, "_perform_request", side_effect=slow_perform):
                send_task = asyncio.create_task(client.send_event(event))
                await asyncio.sleep(0)
                self.assertFalse(send_task.done())

                loop_progress = asyncio.create_task(asyncio.sleep(0.01))
                await loop_progress
                self.assertFalse(send_task.done())

                response = await asyncio.wait_for(send_task, timeout=1.0)

        self.assertEqual(response["action_ids"], ["async-1"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
