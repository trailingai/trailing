# Node SDK

Production Node.js client for Trailing's REST API.

## Requirements

- Node.js 18+

## Usage

```js
import { TrailingClient } from "./trailing.js";

const client = new TrailingClient("http://127.0.0.1:3001");
await client.ingest(
  "care-agent-01",
  "claude",
  "session-123",
  "tool_call",
  "query_ehr",
  "ehr://patients/123",
  { patient_id: "123" },
  { records: 1 },
  { workflow: "triage" },
);
```

`TrailingClient()` defaults to `TRAILING_URL` and `TRAILING_API_KEY` when present.

## Test Against A Running Server

```bash
cd examples/node-sdk
npm test
```

The test script exercises `ingest`, `ingest_otel`, `log_oversight`, `get_actions`, `get_compliance`, `verify_integrity`, `export_json`, and `export_pdf`.
