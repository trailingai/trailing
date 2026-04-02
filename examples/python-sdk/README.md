# Python SDK

Production Python client for Trailing's REST API.

## Requirements

- Python 3.10+
- A Trailing server for live ingestion

## Install

```bash
cd examples/python-sdk
python3 -m venv .venv
. .venv/bin/activate
```

`trailing.py` is the import shim for the packaged SDK in `sdk/python/trailing`, and `test_trailing.py` is the runnable end-to-end client example.

If you want to copy this example outside the repository, install the package directly:

```bash
pip install -e ../../sdk/python
```

## Usage

```python
from trailing import TrailingClient

with TrailingClient(base_url="http://127.0.0.1:3001", api_key=None) as client:
    client.ingest(
        agent_id="care-agent-01",
        agent_type="claude",
        session_id="session-123",
        action_type="tool_call",
        tool_name="query_ehr",
        target="ehr://patients/123",
        params={"patient_id": "123"},
        result={"records": 1},
        context={"workflow": "triage"},
    )
```

`TrailingClient()` defaults to `TRAILING_URL` and `TRAILING_API_KEY` when present.

You can also verify the shim directly:

```bash
python3 -c "from trailing import TrailingClient; print(TrailingClient.__name__)"
```

## Test Against A Running Server

```bash
TRAILING_URL=http://127.0.0.1:3001 python3 test_trailing.py
```

The test script exercises `ingest`, `ingest_otel`, `log_oversight`, `get_actions`, `get_compliance`, `verify_integrity`, `export_json`, and `export_pdf`.
