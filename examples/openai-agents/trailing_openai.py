"""Self-contained OpenAI Agents adapter example for Trailing."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any


SDK_DIR = Path(__file__).resolve().parents[2] / "sdk" / "python"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from trailing.adapters.openai_agents import TrailingOpenAITracer


class RecordingClient:
    """Minimal client for local dry runs."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def track(self, event: Any, *, background: bool = True) -> dict[str, Any]:
        payload = event.to_dict()
        payload["background"] = background
        self.calls.append(payload)
        return {"action_ids": [f"action-{len(self.calls)}"], "ingested": 1}

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None


class _FakeSpanData:
    def __init__(self, **payload: Any) -> None:
        self._payload = dict(payload)
        for key, value in payload.items():
            setattr(self, key, value)

    def export(self) -> dict[str, Any]:
        return dict(self._payload)


class _FakeSpan:
    def __init__(
        self,
        *,
        trace_id: str,
        span_id: str,
        parent_id: str | None = None,
        started_at: str = "2025-01-01T00:00:00Z",
        ended_at: str = "2025-01-01T00:00:01Z",
        trace_metadata: dict[str, Any] | None = None,
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
        self.span_data = _FakeSpanData(**payload)


def build_tracer(
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    agent_id: str = "openai-agents-demo",
    session_id: str | None = None,
    dry_run: bool = False,
) -> TrailingOpenAITracer:
    """Create a tracer that can be registered with OpenAI Agents."""
    client = RecordingClient() if dry_run else None
    return TrailingOpenAITracer(
        client=client,
        base_url=base_url,
        api_key=api_key,
        agent_id=agent_id,
        session_id=session_id,
        background=False,
    )


def simulate_trace(
    tracer: TrailingOpenAITracer,
    *,
    session_id: str,
) -> dict[str, Any]:
    """Emit a representative OpenAI Agents trace through the tracer."""
    trace_id = f"trace-{uuid.uuid4().hex[:12]}"
    trace = SimpleNamespace(
        trace_id=trace_id,
        group_id=session_id,
        name="customer_support",
        metadata={"thread_id": session_id, "tenant": "acme"},
    )
    generation_span = _FakeSpan(
        trace_id=trace_id,
        span_id="span-generation",
        type="generation",
        model="gpt-4.1-mini",
        input=[{"role": "user", "content": "Summarize the latest ticket"}],
        model_config={"temperature": 0},
        tools=[{"type": "function", "name": "lookup_ticket"}],
        output={"output_text": "The ticket is resolved and waiting on follow-up."},
        usage={"input_tokens": 18, "output_tokens": 9},
        response={"model": "gpt-4.1-mini", "status": "completed"},
    )
    function_span = _FakeSpan(
        trace_id=trace_id,
        span_id="span-function",
        parent_id="span-generation",
        type="function",
        name="lookup_ticket",
        input='{"url":"crm://tickets/42","ticket_id":"42"}',
        output='{"status":"resolved","owner":"support"}',
    )
    retrieval_span = _FakeSpan(
        trace_id=trace_id,
        span_id="span-retrieval",
        parent_id="span-generation",
        type="function",
        name="file_search",
        input='{"query":"refund policy"}',
        output='{"documents":[{"id":"doc-1","title":"Refund Policy"}]}',
    )

    tracer.on_trace_start(trace)
    tracer.on_span_start(generation_span)
    tracer.on_span_end(generation_span)
    tracer.on_span_start(function_span)
    tracer.on_span_end(function_span)
    tracer.on_span_start(retrieval_span)
    tracer.on_span_end(retrieval_span)
    tracer.on_trace_end(trace)

    return {
        "session_id": session_id,
        "action_types": [
            "session_start",
            "llm_request",
            "llm_response",
            "tool_call",
            "tool_result",
            "retrieval",
            "retrieval_result",
            "session_end",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", help="Trailing base URL. Defaults to TRAILING_URL.")
    parser.add_argument("--api-key", help="Trailing API key. Defaults to TRAILING_API_KEY.")
    parser.add_argument("--agent-id", default="openai-agents-demo")
    parser.add_argument("--session-id", default=f"openai-agents-{uuid.uuid4().hex[:8]}")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use an in-memory client instead of sending events to Trailing.",
    )
    args = parser.parse_args(argv)

    tracer = build_tracer(
        base_url=args.base_url,
        api_key=args.api_key,
        agent_id=args.agent_id,
        session_id=args.session_id,
        dry_run=args.dry_run,
    )
    try:
        summary = simulate_trace(tracer, session_id=args.session_id)
        tracer.force_flush()
    finally:
        tracer.close()

    if args.dry_run and isinstance(tracer.client, RecordingClient):
        summary["recorded_events"] = len(tracer.client.calls)

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["TrailingOpenAITracer", "build_tracer", "simulate_trace"]
