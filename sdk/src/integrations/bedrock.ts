/**
 * AWS Bedrock Integration
 *
 * Wraps a BedrockRuntimeClient's `send(command)` method. Supports:
 *  - ConverseCommand / ConverseStreamCommand   (unified messages API)
 *  - InvokeModelCommand / InvokeModelWithResponseStreamCommand
 *    (model-native JSON bodies: Anthropic `messages`, Titan `inputText`,
 *     Llama `prompt` - handled generically)
 *
 * Fully supports pre-call block/redact (re-encodes the body for
 * InvokeModel). Streaming responses are wrapped: text accumulates while
 * chunks pass through, with one audit event on completion.
 *
 * @packageDocumentation
 */

// Interception: ES Proxy (non-mutating). Original BedrockRuntimeClient is never modified; returns a new Proxy. Double-wrap guard via WRAPPED_MARKER Symbol.

import type { ResolvedConfig } from "../proxy/types.js";
import {
  applyPreCallPolicy,
  blockedCallError,
  blockedPromptForStorage,
  blockedUserInputForStorage,
  emitIntegrationEvent,
  getConfig,
  redactBuiltinPii,
  redactForStorage,
  setupExitHandlers,
  shouldSample,
  type ComplianceInfo,
  type IntegrationOptions,
} from "./core.js";

const WRAPPED_MARKER = Symbol("obsvr-bedrock-wrapped");
const PROVIDER = "bedrock" as const;

type AnyRecord = Record<string, any>;

const COMMAND_OPERATIONS: Record<string, string> = {
  ConverseCommand: "bedrock.converse",
  ConverseStreamCommand: "bedrock.converse_stream",
  InvokeModelCommand: "bedrock.invoke_model",
  InvokeModelWithResponseStreamCommand: "bedrock.invoke_model_stream",
};

// ---------------------------------------------------------------------------
// Request extraction
// ---------------------------------------------------------------------------

/** Join all text blocks from Converse-style content arrays */
function converseContentText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((b: AnyRecord) => (typeof b?.text === "string" ? b.text : ""))
    .filter((t) => t.length > 0)
    .join("\n");
}

/** Extract formatted prompt from a Converse input */
function extractConversePrompt(input: AnyRecord): string {
  const parts: string[] = [];
  if (Array.isArray(input?.system)) {
    const sys = input.system
      .map((s: AnyRecord) => (typeof s?.text === "string" ? s.text : ""))
      .filter((t: string) => t.length > 0)
      .join("\n");
    if (sys) parts.push(`system: ${sys}`);
  }
  if (Array.isArray(input?.messages)) {
    for (const msg of input.messages as AnyRecord[]) {
      parts.push(`${msg?.role ?? "user"}: ${converseContentText(msg?.content)}`);
    }
  }
  return parts.join("\n");
}

/** Last user message text from a Converse input */
function extractConverseLastUser(input: AnyRecord): string {
  if (Array.isArray(input?.messages)) {
    for (let i = input.messages.length - 1; i >= 0; i--) {
      const msg = input.messages[i] as AnyRecord;
      if (msg?.role === "user") return converseContentText(msg?.content);
    }
  }
  return extractConversePrompt(input);
}

/** Redact Converse input in place */
function redactConverseInPlace(input: AnyRecord): void {
  if (Array.isArray(input?.system)) {
    for (const s of input.system as AnyRecord[]) {
      if (typeof s?.text === "string") s.text = redactBuiltinPii(s.text);
    }
  }
  if (Array.isArray(input?.messages)) {
    for (const msg of input.messages as AnyRecord[]) {
      if (typeof msg?.content === "string") {
        msg.content = redactBuiltinPii(msg.content);
      } else if (Array.isArray(msg?.content)) {
        for (const b of msg.content as AnyRecord[]) {
          if (typeof b?.text === "string") b.text = redactBuiltinPii(b.text);
        }
      }
    }
  }
}

/** Decode an InvokeModel body (string | Uint8Array) into a JSON object */
function decodeBody(body: unknown): AnyRecord | null {
  try {
    let text: string;
    if (typeof body === "string") {
      text = body;
    } else if (body instanceof Uint8Array) {
      text = new TextDecoder().decode(body);
    } else {
      return null;
    }
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

/** Extract formatted prompt from a decoded InvokeModel body */
function extractInvokeBodyPrompt(body: AnyRecord | null): string {
  if (!body) return "";
  const parts: string[] = [];

  if (typeof body.system === "string" && body.system) {
    parts.push(`system: ${body.system}`);
  }
  // Anthropic-style messages
  if (Array.isArray(body.messages)) {
    for (const msg of body.messages as AnyRecord[]) {
      let text = "";
      if (typeof msg?.content === "string") {
        text = msg.content;
      } else if (Array.isArray(msg?.content)) {
        text = (msg.content as AnyRecord[])
          .map((p) => (typeof p?.text === "string" ? p.text : ""))
          .filter((t) => t.length > 0)
          .join("\n");
      }
      parts.push(`${msg?.role ?? "user"}: ${text}`);
    }
  }
  // Titan
  if (typeof body.inputText === "string") parts.push(body.inputText);
  // Llama / generic
  if (typeof body.prompt === "string") parts.push(body.prompt);

  return parts.join("\n");
}

/** Last user message text from a decoded InvokeModel body */
function extractInvokeBodyLastUser(body: AnyRecord | null): string {
  if (!body) return "";
  if (Array.isArray(body.messages)) {
    for (let i = body.messages.length - 1; i >= 0; i--) {
      const msg = body.messages[i] as AnyRecord;
      if (msg?.role === "user") {
        if (typeof msg.content === "string") return msg.content;
        if (Array.isArray(msg.content)) {
          return (msg.content as AnyRecord[])
            .map((p) => (typeof p?.text === "string" ? p.text : ""))
            .join(" ");
        }
      }
    }
  }
  if (typeof body.inputText === "string") return body.inputText;
  if (typeof body.prompt === "string") return body.prompt;
  return extractInvokeBodyPrompt(body);
}

/** Redact a decoded InvokeModel body in place */
function redactInvokeBodyInPlace(body: AnyRecord): void {
  if (typeof body.system === "string") body.system = redactBuiltinPii(body.system);
  if (Array.isArray(body.messages)) {
    for (const msg of body.messages as AnyRecord[]) {
      if (typeof msg?.content === "string") {
        msg.content = redactBuiltinPii(msg.content);
      } else if (Array.isArray(msg?.content)) {
        for (const p of msg.content as AnyRecord[]) {
          if (typeof p?.text === "string") p.text = redactBuiltinPii(p.text);
        }
      }
    }
  }
  if (typeof body.inputText === "string") {
    body.inputText = redactBuiltinPii(body.inputText);
  }
  if (typeof body.prompt === "string") {
    body.prompt = redactBuiltinPii(body.prompt);
  }
}

/** Re-encode a body, preserving the original type (string vs Uint8Array) */
function encodeBody(body: AnyRecord, original: unknown): string | Uint8Array {
  const json = JSON.stringify(body);
  return original instanceof Uint8Array ? new TextEncoder().encode(json) : json;
}

// ---------------------------------------------------------------------------
// Response extraction
// ---------------------------------------------------------------------------

interface Usage {
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
}

/** Extract text + usage from a Converse response */
function extractConverseResponse(response: AnyRecord): {
  text: string;
  usage: Usage;
} {
  const text = converseContentText(response?.output?.message?.content);
  const u = response?.usage ?? {};
  return {
    text,
    usage: {
      inputTokens: u.inputTokens,
      outputTokens: u.outputTokens,
      totalTokens:
        u.totalTokens ??
        (u.inputTokens !== undefined && u.outputTokens !== undefined
          ? u.inputTokens + u.outputTokens
          : undefined),
    },
  };
}

/** Extract text + usage from a decoded InvokeModel response body */
function extractInvokeResponse(body: AnyRecord | null): {
  text: string;
  usage: Usage;
} {
  if (!body) return { text: "", usage: {} };

  let text = "";
  // Anthropic
  if (Array.isArray(body.content)) {
    text = (body.content as AnyRecord[])
      .map((c) => (typeof c?.text === "string" ? c.text : ""))
      .join("");
  }
  // Titan
  if (!text && Array.isArray(body.results)) {
    text = body.results
      .map((r: AnyRecord) =>
        typeof r?.outputText === "string" ? r.outputText : "",
      )
      .join("");
  }
  // Llama
  if (!text && typeof body.generation === "string") text = body.generation;
  // Nova / Converse-shaped bodies
  if (!text && body.output?.message?.content) {
    text = converseContentText(body.output.message.content);
  }
  // OpenAI-compatible bodies
  if (!text && typeof body.choices?.[0]?.message?.content === "string") {
    text = body.choices[0].message.content;
  }

  const usage: Usage = {};
  const u = body.usage ?? {};
  if (typeof u.input_tokens === "number") usage.inputTokens = u.input_tokens;
  if (typeof u.output_tokens === "number") usage.outputTokens = u.output_tokens;
  if (typeof u.inputTokens === "number") usage.inputTokens = u.inputTokens;
  if (typeof u.outputTokens === "number") usage.outputTokens = u.outputTokens;
  if (typeof u.total_tokens === "number") usage.totalTokens = u.total_tokens;
  if (typeof u.totalTokens === "number") usage.totalTokens = u.totalTokens;
  if (
    usage.totalTokens === undefined &&
    usage.inputTokens !== undefined &&
    usage.outputTokens !== undefined
  ) {
    usage.totalTokens = usage.inputTokens + usage.outputTokens;
  }
  // Titan top-level counts
  if (typeof body.inputTextTokenCount === "number") {
    usage.inputTokens = body.inputTextTokenCount;
  }
  return { text, usage };
}

/** Extract text fragment from a single streaming chunk (any model family) */
function streamChunkText(chunk: AnyRecord): string {
  // ConverseStream
  const converseDelta = chunk?.contentBlockDelta?.delta?.text;
  if (typeof converseDelta === "string") return converseDelta;
  // Anthropic invoke stream
  const anthropicDelta = chunk?.delta?.text;
  if (typeof anthropicDelta === "string") return anthropicDelta;
  // Titan stream
  if (typeof chunk?.outputText === "string") return chunk.outputText;
  // Llama stream
  if (typeof chunk?.generation === "string") return chunk.generation;
  return "";
}

/** Extract usage from a streaming chunk if present */
function streamChunkUsage(chunk: AnyRecord): Usage | null {
  const u =
    chunk?.metadata?.usage ??
    chunk?.["amazon-bedrock-invocationMetrics"] ??
    chunk?.usage;
  if (!u || typeof u !== "object") return null;
  const usage: Usage = {};
  if (typeof u.inputTokens === "number") usage.inputTokens = u.inputTokens;
  if (typeof u.outputTokens === "number") usage.outputTokens = u.outputTokens;
  if (typeof u.totalTokens === "number") usage.totalTokens = u.totalTokens;
  if (typeof u.inputTokenCount === "number") usage.inputTokens = u.inputTokenCount;
  if (typeof u.outputTokenCount === "number") usage.outputTokens = u.outputTokenCount;
  if (typeof u.input_tokens === "number") usage.inputTokens = u.input_tokens;
  if (typeof u.output_tokens === "number") usage.outputTokens = u.output_tokens;
  if (
    usage.totalTokens === undefined &&
    usage.inputTokens !== undefined &&
    usage.outputTokens !== undefined
  ) {
    usage.totalTokens = usage.inputTokens + usage.outputTokens;
  }
  return Object.keys(usage).length > 0 ? usage : null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Wrap a BedrockRuntimeClient for automatic audit tracking.
 */
export function wrapBedrock<T extends object>(
  client: T,
  opts: IntegrationOptions = {},
): T {
  const config = getConfig();
  if (config.disabled) return client;
  if ((client as Record<symbol, unknown>)[WRAPPED_MARKER]) return client;
  setupExitHandlers(config);

  return new Proxy(client, {
    get(obj, prop: string | symbol) {
      if (prop === WRAPPED_MARKER) return true;
      if (typeof prop === "symbol") return Reflect.get(obj, prop);
      const value = Reflect.get(obj, prop);
      if (prop === "send" && typeof value === "function") {
        return createAuditedSend(value, obj, config, opts);
      }
      if (typeof value === "function") return value.bind(obj);
      return value;
    },
    has(obj, prop) {
      if (prop === WRAPPED_MARKER) return true;
      return Reflect.has(obj, prop);
    },
  });
}

function createAuditedSend(
  originalSend: Function,
  target: object,
  config: ResolvedConfig,
  opts: IntegrationOptions,
): Function {
  const source = opts.source ?? "bedrock";

  return async function auditedSend(...args: unknown[]): Promise<unknown> {
    const command = args[0] as AnyRecord | undefined;
    const commandName = command?.constructor?.name ?? "";
    const operation = COMMAND_OPERATIONS[commandName];

    // Unknown command → passthrough (not an auditable Bedrock operation).
    if (!operation) {
      return originalSend.apply(target, args);
    }
    // sampling gates ONLY audit emission (below), never enforcement — the
    // compliance boundary must run for every governed call.
    const shouldAudit = shouldSample(config.sample_rate);

    const isConverse = commandName.startsWith("Converse");
    const isStream = commandName.includes("Stream");
    const input: AnyRecord = command?.input ?? {};
    // Bedrock modelId is already the fully-versioned id (e.g.
    // anthropic.claude-3-5-sonnet-20241022-v2:0) and responses carry no separate
    // model echo, so there is no distinct model_resolved to capture here.
    const model = String(input.modelId ?? "unknown");

    // --- Extract prompt text ---
    let invokeBody: AnyRecord | null = null;
    let promptText: string;
    let userText: string;
    if (isConverse) {
      promptText = extractConversePrompt(input);
      userText = extractConverseLastUser(input);
    } else {
      invokeBody = decodeBody(input.body);
      promptText = extractInvokeBodyPrompt(invokeBody);
      userText = extractInvokeBodyLastUser(invokeBody);
    }

    // --- Pre-call policy ---
    const policy = await applyPreCallPolicy(userText, {
      config,
      provider: PROVIDER,
      operation,
      userId: opts.user_id,
      serviceName: opts.service_name,
      model,
      metadata: opts.metadata,
    });

    if (policy.decision === "block") {
      emitIntegrationEvent({
        config,
        provider: PROVIDER,
        model,
        operation,
        source,
        prompt: blockedPromptForStorage(promptText, policy.compliance, policy.securityNormalized),
        response: "",
        userInput: blockedUserInputForStorage(userText, policy),
        latencyMs: 0,
        success: false,
        statusCode: 403,
        options: opts,
        canaryTelemetry: policy.canaryTelemetry,
        floorTelemetry: policy.floorTelemetry,
        compliance: policy.compliance,
      });
      throw blockedCallError(policy.compliance);
    }
    if (policy.decision === "redact") {
      if (isConverse) {
        redactConverseInPlace(input);
        promptText = extractConversePrompt(input);
        userText = extractConverseLastUser(input);
      } else if (invokeBody) {
        redactInvokeBodyInPlace(invokeBody);
        input.body = encodeBody(invokeBody, input.body);
        promptText = extractInvokeBodyPrompt(invokeBody);
        userText = extractInvokeBodyLastUser(invokeBody);
      }
    }

    // Allowed/redacted: emit only when sampled in; redaction is always recorded.
    const auditThisCall = shouldAudit || policy.decision !== "allow";

    // --- Call Bedrock ---
    const startTime = performance.now();
    let response: AnyRecord;
    try {
      response = await originalSend.apply(target, args);
    } catch (error) {
      const latencyMs = Math.round(performance.now() - startTime);
      emitIntegrationEvent({
        config,
        provider: PROVIDER,
        model,
        operation,
        source,
        prompt: promptText,
        response: "",
        userInput: userText,
        latencyMs,
        success: false,
        statusCode:
          (error as AnyRecord)?.$metadata?.httpStatusCode ??
          (error as AnyRecord)?.statusCode ??
          500,
        error,
        options: opts,
        compliance: policy.compliance,
      });
      throw error;
    }

    // --- Streaming: wrap the async-iterable and audit on completion ---
    if (isStream) {
      if (!auditThisCall) return response;
      const streamKey = commandName === "ConverseStreamCommand" ? "stream" : "body";
      const inner = response?.[streamKey];
      if (inner && typeof inner === "object" && Symbol.asyncIterator in inner) {
        const wrapped = wrapBedrockStream(
          inner as AsyncIterable<unknown>,
          commandName,
          {
            config,
            model,
            operation,
            source,
            promptText,
            userText,
            options: opts,
            compliance: policy.compliance,
            startTime,
          },
        );
        return { ...response, [streamKey]: wrapped };
      }
      // Unexpected shape: audit what we have
      emitIntegrationEvent({
        config,
        provider: PROVIDER,
        model,
        operation,
        source,
        prompt: promptText,
        response: "",
        userInput: userText,
        latencyMs: Math.round(performance.now() - startTime),
        options: opts,
        compliance: policy.compliance,
      });
      return response;
    }

    // --- Non-streaming response extraction ---
    if (!auditThisCall) return response;
    const latencyMs = Math.round(performance.now() - startTime);
    let text = "";
    let usage: Usage = {};
    if (commandName === "ConverseCommand") {
      ({ text, usage } = extractConverseResponse(response));
    } else {
      ({ text, usage } = extractInvokeResponse(decodeBody(response?.body)));
    }

    emitIntegrationEvent({
      config,
      provider: PROVIDER,
      model,
      operation,
      source,
      prompt: promptText,
      response: text,
      userInput: userText,
      inputTokens: usage.inputTokens,
      outputTokens: usage.outputTokens,
      totalTokens: usage.totalTokens,
      latencyMs,
      options: opts,
      compliance: policy.compliance,
    });

    return response;
  };
}

function wrapBedrockStream(
  iter: AsyncIterable<unknown>,
  commandName: string,
  ctx: {
    config: ResolvedConfig;
    model: string;
    operation: string;
    source: string;
    promptText: string;
    userText: string;
    options: IntegrationOptions;
    compliance: ComplianceInfo;
    startTime: number;
  },
): AsyncGenerator<unknown, void, unknown> {
  return (async function* () {
    let text = "";
    let usage: Usage | null = null;
    let streamError: unknown = null;
    let firstChunkTime: number | null = null;
    try {
      for await (const event of iter) {
        if (firstChunkTime === null) firstChunkTime = performance.now();
        const e = event as AnyRecord;
        if (commandName === "InvokeModelWithResponseStreamCommand") {
          // Each event: { chunk: { bytes: Uint8Array } } - decode + parse
          const parsed = decodeBody(e?.chunk?.bytes);
          if (parsed) {
            text += streamChunkText(parsed);
            usage = streamChunkUsage(parsed) ?? usage;
          }
        } else {
          text += streamChunkText(e);
          usage = streamChunkUsage(e) ?? usage;
        }
        yield event;
      }
    } catch (err) {
      streamError = err;
      throw err;
    } finally {
      emitIntegrationEvent({
        config: ctx.config,
        provider: PROVIDER,
        model: ctx.model,
        operation: ctx.operation,
        source: ctx.source,
        prompt: ctx.promptText,
        response: text,
        userInput: ctx.userText,
        inputTokens: usage?.inputTokens,
        outputTokens: usage?.outputTokens,
        totalTokens: usage?.totalTokens,
        latencyMs: Math.round(performance.now() - ctx.startTime),
        timeToFirstTokenMs:
          firstChunkTime !== null
            ? Math.round(firstChunkTime - ctx.startTime)
            : undefined,
        success: streamError === null,
        statusCode: streamError === null ? 200 : 500,
        error: streamError ?? undefined,
        options: ctx.options,
        compliance: ctx.compliance,
      });
    }
  })();
}
