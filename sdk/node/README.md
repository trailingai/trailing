# Trailing Node SDK

TypeScript-first SDK for Trailing's HTTP API.

## Install

```bash
npm install @trailing/core
```

## Usage

```ts
import {
  BatchQueue,
  TrailingClient,
  type ToolCallEvent
} from "@trailing/core";

const client = new TrailingClient({
  baseUrl: "http://127.0.0.1:3001"
});

const event: ToolCallEvent = {
  type: "tool_call",
  agentId: "care-agent-01",
  agentType: "claude",
  sessionId: "session-123",
  toolName: "query_ehr",
  target: "ehr://patients/123",
  input: { patient_id: "123" },
  output: { records: 1 },
  context: {
    dataAccessed: ["ehr://patients/123"],
    permissionsUsed: ["workspace-write"],
    policyRefs: ["hipaa-164.312(b)"]
  }
};

const receipt = await client.ingestAction(event);
console.log(receipt.action_id);

const actions = await client.queryActions({ sessionId: "session-123" });
const report = await client.getCompliance("hipaa", { sessionId: "session-123" });
const evidence = await client.exportEvidence({ framework: "hipaa" });

const queue = new BatchQueue(client, { maxSize: 25, flushIntervalMs: 500 });
await queue.enqueue(event);
await queue.flush();
```

Use `BatchQueue` when you want buffered ingestion. The core `TrailingClient` keeps one-shot API calls simple and predictable.
