import assert from "node:assert/strict";
import test from "node:test";

import {
  BatchQueue,
  TrailingClient,
  TrailingError,
  serializeTraceEvent
} from "../dist/index.js";
import type { ToolCallEvent } from "../src/index.ts";

function createToolCallEvent(suffix = "1"): ToolCallEvent {
  return {
    type: "tool_call",
    sessionId: "session-42",
    agentId: `agent-${suffix}`,
    agentType: "codex",
    toolName: "query_ehr",
    target: `ehr://patients/${suffix}`,
    input: { patient_id: suffix },
    output: { records: 1 },
    context: {
      dataAccessed: [`ehr://patients/${suffix}`],
      permissionsUsed: ["read:ehr"],
      policyRefs: ["hipaa-164.312(b)"]
    }
  };
}

test("serializeTraceEvent matches /v1/traces normalization", () => {
  const event = createToolCallEvent("123");

  assert.deepEqual(serializeTraceEvent(event), {
    session_id: "session-42",
    agent_id: "agent-123",
    agent_type: "codex",
    status: "ok",
    action: {
      type: "tool_call",
      tool_name: "query_ehr",
      target: "ehr://patients/123",
      status: "ok"
    },
    payload: {
      type: "tool_call",
      tool_name: "query_ehr",
      target: "ehr://patients/123",
      input: { patient_id: "123" },
      output: { records: 1 },
      context: {
        data_accessed: ["ehr://patients/123"],
        permissions_used: ["read:ehr"],
        policy_refs: ["hipaa-164.312(b)"]
      }
    }
  });
});

test("queryActions maps camelCase query params to API params", async () => {
  const requests: Array<unknown> = [];
  const client = new TrailingClient({
    transport: {
      async request<T>(request: T): Promise<T> {
        requests.push(request);
        return {
          actions: [],
          total: 0,
          pagination: {
            limit: 25,
            offset: 10,
            count: 0,
            has_more: false
          }
        } as T;
      }
    }
  });

  await client.queryActions({
    sessionId: "session-42",
    agent: "agent-7",
    type: "tool_call",
    includeOversight: true,
    limit: 25,
    offset: 10
  });

  assert.deepEqual(requests[0], {
    method: "GET",
    path: "/v1/actions",
    query: {
      session_id: "session-42",
      agent: "agent-7",
      type: "tool_call",
      include_oversight: true,
      limit: 25,
      offset: 10
    }
  });
});

test("logOversight maps params to oversight payload with derived defaults", async () => {
  const requests: Array<unknown> = [];
  const client = new TrailingClient({
    transport: {
      async request<T>(request: T): Promise<T> {
        requests.push(request);
        return {
          id: "oversight-1",
          severity: "high",
          note: "override recorded by reviewer-1 for production",
          timestamp: "2026-03-29T12:00:00Z",
          payload: {},
          hash: "hash-1"
        } as T;
      }
    }
  });

  await client.logOversight({
    eventType: "override",
    approver: "reviewer-1",
    scope: "production",
    sessionId: "session-42",
    framework: "eu-ai-act",
    relatedActionId: "action-7",
    metadata: { reviewer_role: "auditor" }
  });

  const request = requests[0] as {
    method: string;
    path: string;
    body: Record<string, unknown>;
  };

  assert.equal(request.method, "POST");
  assert.equal(request.path, "/v1/oversight");
  assert.equal(request.body.event_type, "override");
  assert.equal(request.body.approver, "reviewer-1");
  assert.equal(request.body.scope, "production");
  assert.equal(request.body.related_action_id, "action-7");
  assert.equal(request.body.session_id, "session-42");
  assert.equal(request.body.framework, "eu-ai-act");
  assert.equal(request.body.severity, "high");
  assert.equal(
    request.body.note,
    "override recorded by reviewer-1 for production"
  );
  assert.deepEqual(request.body.metadata, { reviewer_role: "auditor" });
  assert.match(
    String(request.body.timestamp),
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u
  );
});

test("verifyIntegrity, ingestOtel, and checkpoint methods hit the expected endpoints", async () => {
  const requests: Array<unknown> = [];
  const client = new TrailingClient({
    transport: {
      async request<T>(request: T): Promise<T> {
        requests.push(request);

        if ((request as { path?: string }).path === "/v1/integrity") {
          return {
            valid: true,
            checked_entries: 1,
            latest_hash: "hash-1",
            root_anchor_persisted: true,
            merkle_root_hash: "merkle-1",
            checkpoint_signature: "sig-1",
            proofs: []
          } as T;
        }

        if ((request as { path?: string }).path === "/v1/traces/otlp") {
          return {
            ingested: 1,
            action_ids: ["action-1"]
          } as T;
        }

        if ((request as { path?: string }).path === "/v1/checkpoints") {
          return [] as T;
        }

        return {
          checkpoint: {
            checkpoint_id: "checkpoint-1",
            created_at: "2026-03-29T12:00:00Z",
            sequence: 1,
            entry_id: "entry-1",
            ledger_root_hash: "root-1",
            checkpoint_hash: "checkpoint-hash-1",
            signature: "signature-1",
            key: {
              key_id: "key-1",
              algorithm: "ed25519",
              public_key: "pub-1",
              fingerprint: "fingerprint-1",
              created_at: "2026-03-29T11:00:00Z"
            },
            anchors: []
          },
          verification: {
            checkpoint_hash_valid: true,
            signature_valid: true,
            verified: true
          },
          anchor_hashes_valid: true,
          verified: true
        } as T;
      }
    }
  });

  await client.verifyIntegrity();
  await client.ingestOtel([
    {
      scopeSpans: [
        {
          spans: [{ traceId: "trace-123", spanId: "span-1", name: "llm.call" }]
        }
      ]
    }
  ]);
  await client.listCheckpoints();
  await client.getCheckpoint("checkpoint/1");

  assert.deepEqual(requests[0], {
    method: "GET",
    path: "/v1/integrity"
  });
  assert.deepEqual(requests[1], {
    method: "POST",
    path: "/v1/traces/otlp",
    body: {
      resourceSpans: [
        {
          scopeSpans: [
            {
              spans: [
                { traceId: "trace-123", spanId: "span-1", name: "llm.call" }
              ]
            }
          ]
        }
      ]
    }
  });
  assert.deepEqual(requests[2], {
    method: "GET",
    path: "/v1/checkpoints"
  });
  assert.deepEqual(requests[3], {
    method: "GET",
    path: "/v1/checkpoints/checkpoint%2F1"
  });
});

test("exportEvidence requests PDF bytes when format is pdf", async () => {
  const client = new TrailingClient({
    transport: {
      async request() {
        return new Uint8Array([1, 2, 3, 4]);
      }
    }
  });

  const pdf = await client.exportEvidence({
    framework: "eu-ai-act",
    format: "pdf"
  });

  assert.ok(pdf instanceof Uint8Array);
  assert.deepEqual(Array.from(pdf), [1, 2, 3, 4]);
});

test("BatchQueue flushes at threshold", async () => {
  const requests: Array<unknown> = [];
  const client = new TrailingClient({
    transport: {
      async request<T>(request: T): Promise<T> {
        requests.push(request);
        return {
          ingested: 2,
          action_ids: ["action-1", "action-2"]
        } as T;
      }
    }
  });
  const queue = new BatchQueue(client, {
    maxSize: 2,
    flushIntervalMs: 60_000
  });

  const first = queue.enqueue(createToolCallEvent("1"));
  const second = queue.enqueue(createToolCallEvent("2"));

  assert.deepEqual(await first, { action_id: "action-1" });
  assert.deepEqual(await second, { action_id: "action-2" });
  assert.equal(requests.length, 1);
});

test("getCompliance retries transient failures", async () => {
  let attempts = 0;
  const client = new TrailingClient({
    retry: {
      maxAttempts: 3,
      baseDelayMs: 0,
      maxDelayMs: 0,
      jitterRatio: 0
    },
    transport: {
      async request<T>(): Promise<T> {
        attempts += 1;
        if (attempts < 3) {
          throw new TrailingError("temporarily unavailable", {
            statusCode: 503
          });
        }

        return {
          framework: "eu-ai-act",
          total_actions: 1,
          oversight_events: 0,
          integrity_valid: true,
          score: 100,
          controls_met: [],
          controls_gaps: [],
          evidence_refs: []
        } as T;
      }
    }
  });

  const report = await client.getCompliance("eu-ai-act");

  assert.equal(attempts, 3);
  assert.equal(report.framework, "eu-ai-act");
});
