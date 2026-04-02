# CrewAI Integration

Production CrewAI event listener that forwards task assignment, tool usage, and completion events to Trailing.

This integration follows CrewAI's current event-listener model by extending `BaseEventListener` and registering handlers in `setup_listeners`.

## Install

```bash
pip install crewai requests
```

Keep this example layout intact so the listener can import `examples/python-sdk/trailing.py`.

## Usage

Instantiate the listener before your crew is created so CrewAI registers the handlers:

```python
from trailing_crewai import TrailingCrewAIListener

trailing_listener = TrailingCrewAIListener(
    base_url="http://127.0.0.1:3001",
    agent_id="crewai-healthcare-ops",
)
```

Then define and run your crew normally.

The listener captures:

- task assignment and task start events
- agent execution starts and completions
- tool usage start, finish, and error events
- crew start and completion boundaries
