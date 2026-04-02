# Trailing Python SDK

Python client for sending trace and oversight events to Trailing, plus adapter integrations for Claude, Codex, Cursor, CrewAI, LangChain, and OpenAI Agents.

## Install

```bash
pip install .
```

Optional extras:

```bash
pip install '.[claude]'
pip install '.[codex]'
pip install '.[cursor]'
pip install '.[crewai]'
pip install '.[langchain]'
pip install '.[openai]'
pip install '.[all]'
```

If you are installing from PyPI instead of the local repo, replace `.` with `trailing`.

The SDK reads `TRAILING_URL` and `TRAILING_API_KEY` from the environment by default.

## Base Client

```python
from trailing import SdkContext, SdkEvent, TrailingClient

event = SdkEvent.tool_call(
    agent_id="planner-agent",
    agent_type="codex",
    session_id="session-123",
    tool_name="web.search",
    target="https://example.com/policy",
    parameters={"query": "retention"},
    context=SdkContext(policy_refs=["EU-AIA-12"]),
)

with TrailingClient(base_url="http://127.0.0.1:3001") as client:
    client.send_event(event)
```

## Adapters

### Claude Code

Use `TrailingClaudeCodeAdapter` to generate Claude hook config or forward hook payloads directly.

```python
from trailing.adapters import TrailingClaudeCodeAdapter

adapter = TrailingClaudeCodeAdapter(
    base_url="http://127.0.0.1:3001",
    api_key="trailing-api-key",
)

print(adapter.hook_config())
```

You can also wire Claude hooks to the module entrypoint:

```bash
python -m trailing.adapters.claude_code hook < hook-payload.json
```

### Codex

Use `TrailingCodexCLIAdapter` to wrap a Codex CLI run and forward streamed rollout events.

```python
from trailing.adapters import TrailingCodexCLIAdapter

adapter = TrailingCodexCLIAdapter(
    base_url="http://127.0.0.1:3001",
    api_key="trailing-api-key",
)

try:
    exit_code = adapter.run_wrapped_command("fix the failing tests")
finally:
    adapter.close()
```

The package also exposes a CLI wrapper:

```bash
trailing wrap codex -- "fix the failing tests"
```

### Cursor

Use `TrailingCursorAdapter` to capture Cursor composer events or replay a Cursor log file.

```python
from trailing.adapters import TrailingCursorAdapter

adapter = TrailingCursorAdapter(
    base_url="http://127.0.0.1:3001",
    api_key="trailing-api-key",
)

adapter.capture_event(
    {
        "event": "tool_call_start",
        "session_id": "cursor-session-123",
        "tool_name": "edit_file",
        "input": {"target": "src/app.py"},
    }
)
adapter.capture_log_file("/path/to/cursor-composer.jsonl", follow=True)
adapter.close()
```

### CrewAI

Use `TrailingCrewAIListener` as a CrewAI event listener and register it with your event bus before starting the crew.

```python
from trailing.adapters import TrailingCrewAIListener

listener = TrailingCrewAIListener(
    base_url="http://127.0.0.1:3001",
    api_key="trailing-api-key",
    agent_id="crewai-ops",
    session_id="crew-session-123",
)

listener.setup_listeners(crewai_event_bus)
```

### LangChain

Use `TrailingCallbackHandler` anywhere LangChain accepts callbacks.

```python
from trailing.adapters import TrailingCallbackHandler

callback = TrailingCallbackHandler(
    base_url="http://127.0.0.1:3001",
    api_key="trailing-api-key",
    agent_id="langchain-agent",
)

chain.invoke(
    {"question": "Summarize the policy changes"},
    config={"callbacks": [callback]},
)
```

### OpenAI Agents

Use `TrailingOpenAITracer` to register a tracing processor with the OpenAI Agents SDK.

```python
from trailing.adapters import TrailingOpenAITracer

tracer = TrailingOpenAITracer(
    base_url="http://127.0.0.1:3001",
    api_key="trailing-api-key",
    agent_id="openai-agent",
)

tracer.register_with_openai_agents()

# Run your OpenAI Agents workflow normally after registration.

tracer.close()
```
