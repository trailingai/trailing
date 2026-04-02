# Claude Code Hook

Production Claude Code `SessionEnd` hook that replays the full session transcript, extracts tool uses, and POSTs them to Trailing one by one.

## Install

1. Make the hook executable:

```bash
chmod +x examples/hooks/claude-trailing.sh
```

2. Add it to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "\"examples/hooks/claude-trailing.sh\""
          }
        ]
      }
    ]
  }
}
```

# Add to ~/.claude/settings.json hooks.session_end

## Required Environment

- `CLAUDE_SESSION_ID`
- `CLAUDE_CONVERSATION_DIR`

The hook also honors Claude Code's `transcript_path` from hook stdin when available.

## Optional Environment

- `TRAILING_URL` default: `http://localhost:3001`
- `TRAILING_API_KEY`
- `TRAILING_AGENT_ID` default: `claude-code`
- `TRAILING_AGENT_TYPE` default: `claude`
- `TRAILING_TIMEOUT` default: `10`
- `TRAILING_MAX_RETRIES` default: `4`
- `TRAILING_LOG_FILE`

## Behavior

- reads the `SessionEnd` hook payload from stdin
- locates the transcript from `CLAUDE_CONVERSATION_DIR` or `transcript_path`
- parses `.json` and `.jsonl` transcripts
- extracts `tool_use` and matching `tool_result` blocks
- POSTs each tool use independently to `/v1/traces`
- retries transient HTTP and network failures with exponential backoff
