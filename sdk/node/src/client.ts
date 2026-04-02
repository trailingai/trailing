import {
  DEFAULT_RETRY_OPTIONS,
  type RetryOptions,
  withRetry
} from "./retry.js";
import type {
  ComplianceQuery,
  ComplianceReport,
  DecisionOption,
  ErrorResponse,
  ExportEvidenceJsonOptions,
  ExportEvidenceJsonResponse,
  ExportEvidenceOptions,
  ExportEvidencePdfOptions,
  IngestReceipt,
  IngestRequest,
  IngestResponse,
  IntegrityReport,
  JsonObject,
  JsonValue,
  LogOversightParams,
  OtelResourceSpan,
  OversightEventRecord,
  PaginatedActionsResponse,
  QueryActionsParams,
  RetrievalDocument,
  SerializedTraceAction,
  SignedCheckpoint,
  TokenUsage,
  TraceEvent,
  VerifiedCheckpoint
} from "./types.js";

export interface TransportRequest {
  method: "GET" | "POST";
  path: string;
  query?: Record<string, string | number | boolean | null | undefined>;
  body?: unknown;
  headers?: Record<string, string>;
  responseType?: "json" | "bytes";
}

export interface Transport {
  request<TResponse>(request: TransportRequest): Promise<TResponse>;
}

export interface TrailingClientOptions {
  baseUrl?: string;
  apiKey?: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
  retry?: Partial<RetryOptions>;
  fetch?: typeof globalThis.fetch;
  transport?: Transport;
}

interface ResolvedClientOptions {
  baseUrl: string;
  apiKey: string | undefined;
  timeoutMs: number;
  headers: Record<string, string>;
  retry: RetryOptions;
  transport: Transport;
}

export class TrailingError extends Error {
  readonly statusCode?: number;
  readonly code?: ErrorResponse["code"];
  readonly responseText?: string;

  constructor(
    message: string,
    options: {
      statusCode?: number;
      code?: ErrorResponse["code"];
      responseText?: string;
      cause?: unknown;
    } = {}
  ) {
    super(message, { cause: options.cause });
    this.name = "TrailingError";
    this.statusCode = options.statusCode;
    this.code = options.code;
    this.responseText = options.responseText;
  }
}

class FetchTransport implements Transport {
  readonly #baseUrl: string;
  readonly #apiKey: string | undefined;
  readonly #timeoutMs: number;
  readonly #headers: Record<string, string>;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: Omit<ResolvedClientOptions, "retry" | "transport"> & {
    fetch?: typeof globalThis.fetch;
  }) {
    this.#baseUrl = options.baseUrl;
    this.#apiKey = options.apiKey;
    this.#timeoutMs = options.timeoutMs;
    this.#headers = { ...options.headers };
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  async request<TResponse>(request: TransportRequest): Promise<TResponse> {
    const url = new URL(`${this.#baseUrl}${request.path}`);

    for (const [key, value] of Object.entries(request.query ?? {})) {
      if (value === undefined || value === null) {
        continue;
      }

      url.searchParams.set(key, String(value));
    }

    const headers: Record<string, string> = {
      accept: request.responseType === "bytes" ? "application/pdf" : "application/json",
      ...this.#headers,
      ...(request.headers ?? {})
    };

    if (request.body !== undefined) {
      headers["content-type"] = "application/json";
    }

    if (this.#apiKey) {
      headers["x-api-key"] = this.#apiKey;
    }

    let response: Response;
    try {
      response = await this.#fetch(url, {
        method: request.method,
        headers,
        body: request.body === undefined ? undefined : JSON.stringify(request.body),
        signal: AbortSignal.timeout(this.#timeoutMs)
      });
    } catch (error) {
      throw new TrailingError(
        `request failed for ${request.method} ${request.path}`,
        { cause: error }
      );
    }

    if (!response.ok) {
      const responseText = await response.text();
      const errorDetails = parseErrorResponse(responseText);

      throw new TrailingError(
        `${request.method} ${request.path} failed with status ${response.status}: ${errorDetails.message}`,
        {
          statusCode: response.status,
          code: errorDetails.code,
          responseText
        }
      );
    }

    if (request.responseType === "bytes") {
      return new Uint8Array(await response.arrayBuffer()) as TResponse;
    }

    try {
      return (await response.json()) as TResponse;
    } catch (error) {
      throw new TrailingError(
        `invalid JSON returned by ${request.method} ${request.path}`,
        { cause: error }
      );
    }
  }
}

export class TrailingClient {
  readonly #options: ResolvedClientOptions;

  constructor(options: TrailingClientOptions = {}) {
    const resolvedOptions = resolveClientOptions(options);
    this.#options = {
      ...resolvedOptions,
      transport:
        options.transport ??
        new FetchTransport({
          baseUrl: resolvedOptions.baseUrl,
          apiKey: resolvedOptions.apiKey,
          timeoutMs: resolvedOptions.timeoutMs,
          headers: resolvedOptions.headers,
          fetch: options.fetch
        })
    };
  }

  async ingestAction(event: TraceEvent): Promise<IngestReceipt> {
    const response = await this.ingestActions([event]);
    const [actionId] = response.action_ids;

    if (!actionId) {
      throw new TrailingError("ingestAction returned no action id");
    }

    return { action_id: actionId };
  }

  async ingestActions(events: readonly TraceEvent[]): Promise<IngestResponse> {
    if (events.length === 0) {
      return { ingested: 0, action_ids: [] };
    }

    const body: IngestRequest = {
      actions: events.map(serializeTraceEvent)
    };

    return this.#request<IngestResponse>({
      method: "POST",
      path: "/v1/traces",
      body
    });
  }

  async queryActions(
    query: QueryActionsParams = {}
  ): Promise<PaginatedActionsResponse> {
    return this.#request<PaginatedActionsResponse>({
      method: "GET",
      path: "/v1/actions",
      query: serializeActionQuery(query)
    });
  }

  async getCompliance(
    framework: string,
    query: ComplianceQuery = {}
  ): Promise<ComplianceReport> {
    return this.#request<ComplianceReport>({
      method: "GET",
      path: `/v1/compliance/${encodeURIComponent(framework)}`,
      query: serializeComplianceQuery(query)
    });
  }

  async logOversight(
    params: LogOversightParams
  ): Promise<OversightEventRecord> {
    return this.#request<OversightEventRecord>({
      method: "POST",
      path: "/v1/oversight",
      body: serializeOversightParams(params)
    });
  }

  async verifyIntegrity(): Promise<IntegrityReport> {
    return this.#request<IntegrityReport>({
      method: "GET",
      path: "/v1/integrity"
    });
  }

  async ingestOtel(
    resourceSpans: readonly OtelResourceSpan[]
  ): Promise<IngestResponse> {
    return this.#request<IngestResponse>({
      method: "POST",
      path: "/v1/traces/otlp",
      body: { resourceSpans }
    });
  }

  async listCheckpoints(): Promise<SignedCheckpoint[]> {
    return this.#request<SignedCheckpoint[]>({
      method: "GET",
      path: "/v1/checkpoints"
    });
  }

  async getCheckpoint(id: string): Promise<VerifiedCheckpoint> {
    return this.#request<VerifiedCheckpoint>({
      method: "GET",
      path: `/v1/checkpoints/${encodeURIComponent(id)}`
    });
  }

  async exportEvidence(
    options?: ExportEvidenceJsonOptions
  ): Promise<ExportEvidenceJsonResponse>;
  async exportEvidence(options: ExportEvidencePdfOptions): Promise<Uint8Array>;
  async exportEvidence(
    options: ExportEvidenceOptions = {}
  ): Promise<ExportEvidenceJsonResponse | Uint8Array> {
    const format = options.format ?? "json";

    return this.#request<ExportEvidenceJsonResponse | Uint8Array>({
      method: "POST",
      path: format === "pdf" ? "/v1/export/pdf" : "/v1/export/json",
      body: compactObject({
        framework: options.framework
      }),
      responseType: format === "pdf" ? "bytes" : "json"
    });
  }

  async #request<TResponse>(request: TransportRequest): Promise<TResponse> {
    return withRetry(
      async () => this.#options.transport.request<TResponse>(request),
      this.#options.retry
    );
  }
}

export function serializeTraceEvent(event: TraceEvent): SerializedTraceAction {
  const status = event.status ?? "ok";
  const payload = compactObject({
    type: event.type,
    ...(serializeEventPayload(event) as JsonObject),
    ...(event.context ? { context: serializeContext(event.context) } : {}),
    ...(event.metadata ? { metadata: compactObject(event.metadata) } : {})
  });

  return compactObject({
    session_id: event.sessionId,
    agent_id: event.agentId,
    agent_type: event.agentType ?? "unknown",
    timestamp: event.timestamp,
    status,
    action: compactObject({
      type: event.type,
      tool_name: getToolName(event),
      target: getTarget(event),
      status
    }),
    payload
  });
}

function resolveClientOptions(
  options: TrailingClientOptions
): Omit<ResolvedClientOptions, "transport"> {
  return {
    baseUrl: stripTrailingSlashes(
      options.baseUrl ?? "http://127.0.0.1:3001"
    ),
    apiKey: options.apiKey,
    timeoutMs: options.timeoutMs ?? 10_000,
    headers: { ...(options.headers ?? {}) },
    retry: {
      ...DEFAULT_RETRY_OPTIONS,
      ...(options.retry ?? {})
    }
  };
}

function serializeActionQuery(
  query: QueryActionsParams
): Record<string, string | number | boolean | undefined> {
  return compactObject({
    session_id: query.sessionId,
    agent: query.agent,
    from: query.from,
    to: query.to,
    type: query.type,
    include_oversight: query.includeOversight,
    limit: query.limit,
    offset: query.offset
  });
}

function serializeComplianceQuery(
  query: ComplianceQuery
): Record<string, string | undefined> {
  return compactObject({
    session_id: query.sessionId,
    from: query.from,
    to: query.to
  });
}

function serializeOversightParams(params: LogOversightParams): JsonObject {
  return compactObject({
    event_type: params.eventType,
    approver: params.approver,
    scope: params.scope,
    related_action_id: params.relatedActionId,
    session_id: params.sessionId,
    framework: params.framework,
    severity: getOversightSeverity(params.eventType),
    note:
      params.note ??
      `${params.eventType} recorded by ${params.approver} for ${params.scope}`,
    timestamp: formatUtcTimestamp(new Date()),
    metadata: params.metadata ? compactObject(params.metadata) : undefined
  });
}

function serializeEventPayload(event: TraceEvent): JsonObject {
  switch (event.type) {
    case "tool_call":
      return compactObject({
        tool_name: event.toolName,
        target: event.target,
        input: event.input,
        output: event.output,
        duration_ms: event.durationMs
      });
    case "llm_request":
      return compactObject({
        model: event.model,
        prompt: event.prompt,
        messages: event.messages,
        temperature: event.temperature,
        max_tokens: event.maxTokens,
        request_id: event.requestId
      });
    case "llm_response":
      return compactObject({
        model: event.model,
        response: event.response,
        finish_reason: event.finishReason,
        latency_ms: event.latencyMs,
        usage: serializeUsage(event.usage),
        request_id: event.requestId
      });
    case "retrieval":
      return compactObject({
        query: event.query,
        documents: event.documents.map(serializeRetrievalDocument),
        result_count: event.resultCount ?? event.documents.length,
        retriever: event.retriever
      });
    case "external_write":
      return compactObject({
        destination: event.destination,
        operation: event.operation,
        bytes_written: event.bytesWritten,
        checksum: event.checksum,
        value: event.value
      });
    case "decision_point":
      return compactObject({
        decision: event.decision,
        rationale: event.rationale,
        selected_option_id: event.selectedOptionId,
        options: event.options?.map(serializeDecisionOption),
        confidence: event.confidence
      });
    case "policy_check":
      return compactObject({
        policy_id: event.policyId,
        outcome: event.outcome,
        evaluator: event.evaluator,
        violations: event.violations,
        matched_rules: event.matchedRules
      });
  }
}

function serializeContext(context: TraceEvent["context"]): JsonObject {
  if (!context) {
    return {};
  }

  return compactObject({
    data_accessed: context.dataAccessed,
    permissions_used: context.permissionsUsed,
    policy_refs: context.policyRefs
  });
}

function serializeUsage(
  usage: TokenUsage | undefined
): JsonObject | undefined {
  if (!usage) {
    return undefined;
  }

  return compactObject({
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
    total_tokens: usage.totalTokens
  });
}

function serializeRetrievalDocument(
  document: RetrievalDocument
): JsonObject {
  return compactObject({
    id: document.id,
    uri: document.uri,
    title: document.title,
    score: document.score,
    metadata: document.metadata ? compactObject(document.metadata) : undefined
  });
}

function serializeDecisionOption(
  option: DecisionOption
): JsonObject {
  return compactObject({
    id: option.id,
    label: option.label,
    score: option.score,
    metadata: option.metadata ? compactObject(option.metadata) : undefined
  });
}

function getToolName(event: TraceEvent): string | undefined {
  if (event.type === "tool_call") {
    return event.toolName;
  }

  return undefined;
}

function getTarget(event: TraceEvent): string | undefined {
  if (event.target) {
    return event.target;
  }

  if (event.type === "external_write") {
    return event.destination;
  }

  return undefined;
}

function parseErrorResponse(responseText: string): {
  message: string;
  code?: ErrorResponse["code"];
} {
  try {
    const payload = JSON.parse(responseText) as Partial<ErrorResponse>;
    return {
      message:
        typeof payload.error === "string" ? payload.error : responseText,
      code: payload.code
    };
  } catch {
    return { message: responseText };
  }
}

function stripTrailingSlashes(value: string): string {
  return value.replace(/\/+$/u, "");
}

function formatUtcTimestamp(value: Date): string {
  return value.toISOString().replace(/\.\d{3}Z$/u, "Z");
}

function getOversightSeverity(eventType: string): string {
  const lowered = eventType.toLowerCase();

  if (lowered === "override" || lowered === "kill_switch" || lowered === "kill-switch") {
    return "high";
  }

  if (lowered === "approval" || lowered === "escalation") {
    return "medium";
  }

  return "low";
}

function compactObject<TValue extends Record<string, unknown>>(value: TValue): TValue {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => entry !== undefined)
  ) as TValue;
}
