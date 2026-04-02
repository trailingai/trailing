# Cursor Adapter

Example wrapper and demo script for `TrailingCursorAdapter`.

## Requirements

- Python 3.10+
- A Trailing server for live ingestion

## Install

```bash
cd examples/cursor
python3 -m venv .venv
. .venv/bin/activate
```

Keep the repository layout intact so the example can import `sdk/python/trailing`.

If you want to copy this example outside the repository, install the Python SDK package first:

```bash
pip install -e ../../sdk/python
```

## Dry Run

This writes a temporary Cursor-style JSONL log, replays it through the adapter, and prints the mapped action summary without sending anything to Trailing.

```bash
python3 trailing_cursor.py --dry-run
```

## Live Run Against Trailing

Replay the same sample Cursor log into a running Trailing server:

```bash
TRAILING_URL=http://127.0.0.1:3001 python3 trailing_cursor.py
```

## Replay A Real Cursor Log

If you already have a Cursor JSONL log file, point the example at it directly:

```bash
TRAILING_URL=http://127.0.0.1:3001 python3 trailing_cursor.py \
  --log-file /path/to/cursor-log.jsonl
```

The example covers:

- composer session start and end
- tool call and tool result
- file write tracking
- approval events mapped to human oversight
