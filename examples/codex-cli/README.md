# Codex CLI Adapter

Example wrapper and demo script for `TrailingCodexCLIAdapter`.

## Requirements

- Python 3.10+
- A Trailing server for live ingestion
- Optional: the `codex` executable for a real wrapped CLI run

## Install

```bash
cd examples/codex-cli
python3 -m venv .venv
. .venv/bin/activate
```

Keep the repository layout intact so the example can import `sdk/python/trailing`.

If you want to copy this example outside the repository, install the Python SDK package first:

```bash
pip install -e ../../sdk/python
```

## Dry Run

This replays a representative Codex JSONL event stream into an in-memory recording client and prints the mapped action summary.

```bash
python3 trailing_codex.py --dry-run
```

## Live Run Against Trailing

Replay the same sample event stream into a running Trailing server:

```bash
TRAILING_URL=http://127.0.0.1:3001 python3 trailing_codex.py
```

## Real Codex Wrapper Run

If the `codex` binary is installed, the example can wrap an actual Codex invocation:

```bash
TRAILING_URL=http://127.0.0.1:3001 python3 trailing_codex.py \
  --run-codex \
  --prompt "fix the failing tests"
```

The helper also exposes the user-facing wrapper string:

```python
from trailing_codex import build_adapter

adapter = build_adapter(base_url="http://127.0.0.1:3001")
print(adapter.wrapper_command("fix the failing tests"))
```
