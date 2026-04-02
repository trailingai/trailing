# Examples

Production-ready integrations and demo assets for Trailing.

## Included

- `hooks/`: Claude Code `SessionEnd` hook
- `python-sdk/`: Python SDK plus live test script
- `node-sdk/`: Node.js SDK plus live test script
- `openai-agents/`: OpenAI Agents tracing adapter example
- `codex-cli/`: Codex CLI adapter example
- `cursor/`: Cursor composer adapter example
- `langchain/`: LangChain callback handler
- `crewai/`: CrewAI event listener
- `demo.sh`: end-to-end healthcare demo against a live Trailing server

## Demo

Run the demo from the repository root after building:

```bash
./examples/demo.sh
```

The demo starts a local server, ingests realistic healthcare actions, records oversight events, runs all compliance frameworks, exports JSON evidence, verifies chain integrity, and opens the dashboard.
