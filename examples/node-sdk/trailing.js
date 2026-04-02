/**
 * Production Trailing SDK for Node.js 18+.
 */

/**
 * @typedef {Record<string, any>} JsonObject
 */

export class TrailingError extends Error {
  /**
   * @param {string} message
   * @param {{statusCode?: number, responseText?: string}} [details]
   */
  constructor(message, details = {}) {
    super(message);
    this.name = "TrailingError";
    this.statusCode = details.statusCode ?? null;
    this.responseText = details.responseText ?? null;
  }
}

export class TrailingClient {
  /**
   * @param {string} [baseUrl]
   * @param {string | null} [apiKey]
   * @param {{timeoutMs?: number}} [options]
   */
  constructor(
    baseUrl = process.env.TRAILING_URL || "http://127.0.0.1:3001",
    apiKey = process.env.TRAILING_API_KEY || null,
    options = {},
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  /**
   * @param {string} agentId
   * @param {string} agentType
   * @param {string} sessionId
   * @param {string} actionType
   * @param {string | null} toolName
   * @param {string | null} target
   * @param {JsonObject | null | undefined} params
   * @param {any} result
   * @param {JsonObject | null | undefined} context
   * @returns {Promise<JsonObject>}
   */
  async ingest(agentId, agentType, sessionId, actionType, toolName, target, params, result, context) {
    /** @type {JsonObject} */
    const action = {
      session_id: sessionId,
      agent: agentId,
      agent_id: agentId,
      agent_type: agentType,
      type: actionType,
      timestamp: new Date().toISOString(),
      parameters: params ?? {},
      result,
      context: context ?? {},
      status: "ok",
    };

    if (toolName) {
      action.tool_name = toolName;
      action.tool = toolName;
      action.name = toolName;
    }
    if (target) {
      action.target = target;
    }

    return this.#request("POST", "/v1/traces", { jsonBody: { actions: [action] } });
  }

  /**
   * @param {JsonObject} otlpPayload
   * @returns {Promise<JsonObject>}
   */
  async ingest_otel(otlpPayload) {
    return this.#request("POST", "/v1/traces/otlp", { jsonBody: otlpPayload });
  }

  /**
   * @param {string} eventType
   * @param {string} approver
   * @param {string} scope
   * @param {string | null} [relatedActionId]
   * @returns {Promise<JsonObject>}
   */
  async log_oversight(eventType, approver, scope, relatedActionId = null) {
    /** @type {JsonObject} */
    const payload = {
      event_type: eventType,
      approver,
      scope,
      severity: this.#oversightSeverity(eventType),
      note: `${eventType} recorded by ${approver} for ${scope}`,
      timestamp: new Date().toISOString(),
    };

    if (relatedActionId) {
      payload.related_action_id = relatedActionId;
    }

    return this.#request("POST", "/v1/oversight", { jsonBody: payload });
  }

  /**
   * @param {string | null} [sessionId]
   * @param {string | null} [agent]
   * @param {string | null} [fromTime]
   * @param {string | null} [toTime]
   * @returns {Promise<JsonObject[]>}
   */
  async get_actions(sessionId = null, agent = null, fromTime = null, toTime = null) {
    const response = await this.#request("GET", "/v1/actions", {
      query: this.#compact({
        session_id: sessionId,
        agent,
        from: fromTime,
        to: toTime,
      }),
    });
    return Array.isArray(response.actions) ? response.actions : [];
  }

  /**
   * @param {string} [framework]
   * @returns {Promise<JsonObject>}
   */
  async get_compliance(framework = "eu-ai-act") {
    return this.#request("GET", `/v1/compliance/${framework}`);
  }

  /**
   * @returns {Promise<JsonObject>}
   */
  async verify_integrity() {
    return this.#request("GET", "/v1/integrity");
  }

  /**
   * @param {string} [framework]
   * @returns {Promise<JsonObject>}
   */
  async export_json(framework = "eu-ai-act") {
    return this.#request("POST", "/v1/export/json", { jsonBody: { framework } });
  }

  /**
   * @param {string} [framework]
   * @returns {Promise<Buffer>}
   */
  async export_pdf(framework = "eu-ai-act") {
    const bytes = await this.#request("POST", "/v1/export/pdf", {
      jsonBody: { framework },
      expectJson: false,
    });
    return Buffer.from(bytes);
  }

  /**
   * @param {"GET" | "POST"} method
   * @param {string} path
   * @param {{jsonBody?: JsonObject, query?: Record<string, string>, expectJson?: boolean}} [options]
   * @returns {Promise<any>}
   */
  async #request(method, path, options = {}) {
    const url = new URL(`${this.baseUrl}${path}`);
    for (const [key, value] of Object.entries(options.query ?? {})) {
      url.searchParams.set(key, value);
    }

    const headers = {
      accept: "application/json",
      "content-type": "application/json",
    };
    if (this.apiKey) {
      headers["x-api-key"] = this.apiKey;
    }

    let response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: options.jsonBody ? JSON.stringify(options.jsonBody) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new TrailingError(`request failed for ${method} ${url}: ${error}`);
    }

    if (!response.ok) {
      const responseText = await response.text();
      let message = responseText;
      try {
        const payload = JSON.parse(responseText);
        if (payload && typeof payload === "object" && "error" in payload) {
          message = String(payload.error);
        }
      } catch {
        // Keep the plain text body.
      }

      throw new TrailingError(`${method} ${path} failed with status ${response.status}: ${message}`, {
        statusCode: response.status,
        responseText,
      });
    }

    if (options.expectJson === false) {
      return new Uint8Array(await response.arrayBuffer());
    }

    try {
      return await response.json();
    } catch (error) {
      throw new TrailingError(`invalid JSON returned by ${method} ${path}: ${error}`);
    }
  }

  /**
   * @param {Record<string, string | null>} values
   * @returns {Record<string, string>}
   */
  #compact(values) {
    return Object.fromEntries(Object.entries(values).filter(([, value]) => value !== null));
  }

  /**
   * @param {string} eventType
   * @returns {string}
   */
  #oversightSeverity(eventType) {
    const lowered = eventType.toLowerCase();
    if (lowered === "override" || lowered === "kill_switch" || lowered === "kill-switch") {
      return "high";
    }
    if (lowered === "escalation" || lowered === "review") {
      return "medium";
    }
    return "info";
  }
}
