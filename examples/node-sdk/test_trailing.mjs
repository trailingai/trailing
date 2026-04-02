#!/usr/bin/env node

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

import { TrailingClient } from "./trailing.js";

const framework = process.env.TRAILING_FRAMEWORK || "eu-ai-act";
const sessionId = `node-sdk-test-${randomUUID()}`;

const client = new TrailingClient();
const ingestResponse = await client.ingest(
  "node-sdk-agent",
  "claude",
  sessionId,
  "tool_call",
  "query_prior_auth",
  "payer://prior-auth/patient-1002",
  { patient_id: "patient-1002", service_line: "home-health" },
  { status: "expired", authorization_id: "auth-2002" },
  { workflow: "utilization-review", department: "payer-ops" },
);
const actionId = ingestResponse.action_ids[0];

const otlpResponse = await client.ingest_otel({
  resourceSpans: [
    {
      scopeSpans: [
        {
          spans: [
            {
              traceId: `trace-${randomUUID().replaceAll("-", "").slice(0, 12)}`,
              spanId: "span-001",
              name: "llm.decision",
              timestamp: "2026-03-30T12:10:00Z",
              attributes: {
                "session.id": `${sessionId}-otlp`,
                "agent.id": "node-sdk-agent",
                "agent.type": "claude",
                "tool.name": "coverage_classifier",
                target: "coverage://patient-1002",
              },
              status: "ok",
            },
          ],
        },
      ],
    },
  ],
});

const oversightResponse = await client.log_oversight(
  "override",
  "utilization.manager",
  "authorization-disposition",
  actionId,
);
const actions = await client.get_actions(sessionId);
const compliance = await client.get_compliance(framework);
const integrity = await client.verify_integrity();
const exported = await client.export_json(framework);
const pdfBytes = await client.export_pdf(framework);

assert.equal(ingestResponse.ingested, 1);
assert.equal(otlpResponse.ingested, 1);
assert.ok(oversightResponse.id);
assert.ok(actions.some((action) => action.session_id === sessionId));
assert.equal(compliance.framework, framework);
assert.equal(typeof integrity.valid, "boolean");
assert.equal(exported.framework, framework);
assert.ok(pdfBytes.subarray(0, 5).toString("utf8") === "%PDF-");

console.log(
  JSON.stringify(
    {
      status: "ok",
      sessionId,
      framework,
      actionsSeen: actions.length,
      integrityValid: integrity.valid,
      pdfBytes: pdfBytes.length,
    },
    null,
    2,
  ),
);
