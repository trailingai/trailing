export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];

export interface JsonObject {
  [key: string]: JsonValue | undefined;
}

export type ActionStatus = "ok" | "error" | "pending" | "blocked" | string;
export type TraceEventType =
  | "tool_call"
  | "llm_request"
  | "llm_response"
  | "retrieval"
  | "external_write"
  | "decision_point"
  | "policy_check";

export interface EventContext {
  dataAccessed?: string[];
  permissionsUsed?: string[];
  policyRefs?: string[];
}

export interface BaseTraceEvent {
  type: TraceEventType;
  sessionId: string;
  agentId: string;
  agentType?: string;
  timestamp?: string;
  status?: ActionStatus;
  target?: string;
  context?: EventContext;
  metadata?: JsonObject;
}

export interface ToolCallEvent extends BaseTraceEvent {
  type: "tool_call";
  toolName: string;
  input?: JsonValue;
  output?: JsonValue;
  durationMs?: number;
}

export interface LlmRequestEvent extends BaseTraceEvent {
  type: "llm_request";
  model: string;
  prompt?: string;
  messages?: JsonValue[];
  temperature?: number;
  maxTokens?: number;
  requestId?: string;
}

export interface TokenUsage {
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
}

export interface LlmResponseEvent extends BaseTraceEvent {
  type: "llm_response";
  model: string;
  response?: string;
  finishReason?: string;
  latencyMs?: number;
  usage?: TokenUsage;
  requestId?: string;
}

export interface RetrievalDocument {
  id?: string;
  uri?: string;
  title?: string;
  score?: number;
  metadata?: JsonObject;
}

export interface RetrievalEvent extends BaseTraceEvent {
  type: "retrieval";
  query: string;
  documents: RetrievalDocument[];
  resultCount?: number;
  retriever?: string;
}

export interface ExternalWriteEvent extends BaseTraceEvent {
  type: "external_write";
  destination: string;
  operation: string;
  bytesWritten?: number;
  checksum?: string;
  value?: JsonValue;
}

export interface DecisionOption {
  id: string;
  label: string;
  score?: number;
  metadata?: JsonObject;
}

export interface DecisionPointEvent extends BaseTraceEvent {
  type: "decision_point";
  decision: string;
  rationale?: string;
  selectedOptionId?: string;
  options?: DecisionOption[];
  confidence?: number;
}

export interface PolicyCheckEvent extends BaseTraceEvent {
  type: "policy_check";
  policyId: string;
  outcome: "pass" | "fail" | "warn" | string;
  evaluator?: string;
  violations?: string[];
  matchedRules?: string[];
}

export type TraceEvent =
  | ToolCallEvent
  | LlmRequestEvent
  | LlmResponseEvent
  | RetrievalEvent
  | ExternalWriteEvent
  | DecisionPointEvent
  | PolicyCheckEvent;

export interface SerializedTraceAction {
  session_id: string;
  agent_id: string;
  agent_type: string;
  timestamp?: string;
  status: string;
  action: {
    type: TraceEventType;
    tool_name?: string;
    target?: string;
    status: string;
  };
  payload: JsonObject;
}

export interface IngestRequest {
  actions: SerializedTraceAction[];
}

export interface QueryActionsParams {
  sessionId?: string;
  agent?: string;
  from?: string;
  to?: string;
  type?: TraceEventType | string;
  includeOversight?: boolean;
  limit?: number;
  offset?: number;
}

export interface ComplianceQuery {
  sessionId?: string;
  from?: string;
  to?: string;
}

export interface ErrorResponse {
  error: string;
  code:
    | "INVALID_JSON"
    | "MISSING_FIELD"
    | "NOT_FOUND"
    | "UNSUPPORTED_FRAMEWORK"
    | "RATE_LIMITED"
    | "UNAUTHORIZED"
    | "INVALID_REQUEST"
    | "INTERNAL_ERROR"
    | "REQUEST_TOO_LARGE";
}

export interface LogOversightParams {
  eventType: string;
  approver: string;
  scope: string;
  relatedActionId?: string;
  sessionId?: string;
  framework?: string;
  note?: string;
  metadata?: JsonObject;
}

export type OtelResourceSpan = JsonObject;

export interface IngestResponse {
  ingested: number;
  action_ids: string[];
}

export interface IngestReceipt {
  action_id: string;
}

export interface ActionRecord {
  id: string;
  session_id: string;
  agent: string;
  agent_type: string;
  kind: "action" | "oversight" | string;
  type: string;
  tool_name?: string | null;
  target?: string | null;
  source: string;
  timestamp: string;
  payload: JsonObject;
  hash: string;
  previous_hash?: string | null;
}

export interface OversightEventRecord {
  id: string;
  session_id?: string | null;
  framework?: string | null;
  severity: string;
  note: string;
  timestamp: string;
  payload: JsonObject;
  hash: string;
  previous_hash?: string | null;
}

export interface PaginationMetadata {
  limit: number;
  offset: number;
  count: number;
  has_more: boolean;
}

export interface PaginatedActionsResponse {
  actions: ActionRecord[];
  total: number;
  pagination: PaginationMetadata;
}

export interface ComplianceControlResult {
  id: string;
  article: string;
  requirement: string;
  matched_evidence: string[];
  missing_evidence: string[];
  evidence_refs: string[];
}

export interface ComplianceReport {
  framework: string;
  total_actions: number;
  oversight_events: number;
  integrity_valid: boolean;
  score: number;
  controls_met: ComplianceControlResult[];
  controls_gaps: ComplianceControlResult[];
  evidence_refs: string[];
}

export interface IntegrityReport {
  valid: boolean;
  checked_entries: number;
  latest_hash?: string | null;
  root_anchor_hash?: string | null;
  root_anchor_persisted: boolean;
  merkle_root_hash: string;
  checkpoint_signature: string;
  proofs: IntegrityProof[];
}

export interface ExportEvidenceRequest {
  framework?: string;
}

export interface IntegrityProof {
  proof_id: string;
  scope: string;
  algorithm: string;
  value: string;
  verified: boolean;
}

export interface CheckpointSigningKey {
  key_id: string;
  algorithm: string;
  public_key: string;
  fingerprint: string;
  label?: string | null;
  created_at: string;
}

export interface ExternalAnchorRecord {
  anchor_id: string;
  provider: string;
  reference: string;
  anchored_at: string;
  anchored_hash: string;
  metadata: JsonValue;
}

export interface SignedCheckpoint {
  checkpoint_id: string;
  created_at: string;
  sequence: number;
  entry_id: string;
  ledger_root_hash: string;
  checkpoint_hash: string;
  signature: string;
  key: CheckpointSigningKey;
  anchors: ExternalAnchorRecord[];
}

export interface CheckpointVerification {
  checkpoint_hash_valid: boolean;
  signature_valid: boolean;
  verified: boolean;
}

export interface VerifiedCheckpoint {
  checkpoint: SignedCheckpoint;
  verification: CheckpointVerification;
  anchor_hashes_valid: boolean;
  verified: boolean;
}

export interface ExportEvidenceJsonResponse {
  framework: string;
  actions: ActionRecord[];
  oversight_events: OversightEventRecord[];
  integrity: IntegrityReport;
}

export interface ExportEvidenceJsonOptions extends ExportEvidenceRequest {
  format?: "json";
}

export interface ExportEvidencePdfOptions extends ExportEvidenceRequest {
  format: "pdf";
}

export type ExportEvidenceOptions =
  | ExportEvidenceJsonOptions
  | ExportEvidencePdfOptions;
