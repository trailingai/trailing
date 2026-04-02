# OpenAI Agents Adapter

Example wrapper and demo script for `TrailingOpenAITracer`.

## Requirements

- Python 3.10+
- A Trailing server for live ingestion
- Optional: `openai-agents` if you want to register the tracer with the real SDK

## Install

```bash
cd examples/openai-agents
python3 -m venv .venv
. .venv/bin/activate
```

Install the OpenAI Agents SDK only if you are wiring this into a real agent runtime:

```bash
pip install openai-agents openai
```

Keep the repository layout intact so the example can import `sdk/python/trailing`.

If you want to copy this example outside the repository, install the Python SDK package first:

```bash
pip install -e ../../sdk/python
```

## Dry Run

This mode does not require a Trailing server. It emits a representative trace into an in-memory recording client and prints the action summary.

```bash
python3 trailing_openai.py --dry-run
```

## Live Run

Point the example at a running Trailing server to ingest the simulated OpenAI Agents events.

```bash
TRAILING_URL=http://127.0.0.1:3001 python3 trailing_openai.py
```

The script emits:

- `session_start` and `session_end`
- `llm_request` and `llm_response`
- `tool_call` and `tool_result`
- `retrieval` and `retrieval_result`

## Register With OpenAI Agents

Use the same tracer in a real OpenAI Agents process:

```python
from trailing_openai import build_tracer

tracer = build_tracer(
    base_url="http://127.0.0.1:3001",
    agent_id="customer-support-agent",
)
tracer.register_with_openai_agents()
```

After registration, run your OpenAI Agents workflow normally and call `tracer.close()` during shutdown.
