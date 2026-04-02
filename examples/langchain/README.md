# LangChain Callback

Production LangChain callback handler that streams decision, tool, and error events into Trailing.

## Install

```bash
pip install langchain langchain-core requests
```

Install the Python SDK from the sibling directory or keep this example layout intact so the callback can import `examples/python-sdk/trailing.py`.

## Usage

```python
from trailing_callback import TrailingCallbackHandler

callback = TrailingCallbackHandler(
    base_url="http://127.0.0.1:3001",
    agent_id="langchain-care-agent",
)
```

Attach the handler through LangChain's standard callback configuration:

```python
chain.invoke(inputs, config={"callbacks": [callback]})
```

The handler:

- creates a `session_id` per chain run
- logs `on_llm_start` as a Trailing `decision`
- logs `on_tool_start` as `tool_call`
- logs `on_tool_end` as `tool_result`
- logs `on_chain_error` as `error`
