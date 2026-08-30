/**
 * Enforcing LlamaIndex.TS LLM boundary.
 *
 * LlamaIndex's event callbacks run in microtasks, so callback errors cannot
 * stop the model method. This wrapper instead owns the actual `chat` and
 * `complete` calls. Policy therefore resolves before the underlying LLM body
 * is entered, and a requested redaction changes the provider-bound input.
 */

import {
  applyPreCallPolicy,
  blockedCallError,
  blockedPromptForStorage,
  blockedUserInputForStorage,
  emitIntegrationEvent,
  inferProviderFromModel,
  monitorModeRequiresEvidence,
  setupExitHandlers,
  shouldSample,
  tryGetConfig,
  type IntegrationOptions,
  type PreCallPolicyResult,
} from "./core.js";

const SOURCE = "llamaindex_ts";
const POLICY_REDACTION_PLACEHOLDER = "[REDACTED_BY_POLICY]";

type LlamaIndexMethod = "chat" | "complete";

/** The stable LlamaIndex.TS LLM surface from the supported 0.5.x-0.x line. */
export interface LlamaIndexLLMLike {
  metadata?: { model?: unknown } | Record<string, unknown>;
  chat(params: Record<string, unknown>): Promise<unknown>;
  complete(params: Record<string, unknown>): Promise<unknown>;
}

function contentText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((part) => {
      if (!part || typeof part !== "object") return "";
      const text = (part as Record<string, unknown>).text;
      return typeof text === "string" ? text : "";
    })
    .filter(Boolean)
    .join(" ");
}

function requestText(
  method: LlamaIndexMethod,
  params: Record<string, unknown>,
): { prompt: string; userText: string } {
  if (method === "complete") {
    const prompt = contentText(params.prompt);
    return { prompt, userText: prompt };
  }

  const messages = Array.isArray(params.messages) ? params.messages : [];
  const lines: string[] = [];
  let userText = "";
  for (const value of messages) {
    if (!value || typeof value !== "object") continue;
    const message = value as Record<string, unknown>;
    const role = typeof message.role === "string" ? message.role : "unknown";
    const text = contentText(message.content);
    lines.push(`${role}: ${text}`);
    if (role === "user") userText = text;
  }
  const prompt = lines.join("\n");
  return { prompt, userText: userText || prompt };
}

function safeRedactedText(prompt: string, policy: PreCallPolicyResult): string {
  return policy.redactedPrompt !== prompt
    ? policy.redactedPrompt
    : POLICY_REDACTION_PLACEHOLDER;
}

/**
 * Build a fresh provider-bound request with no original text references.
 *
 * Completion keeps its normal shape. Chat is collapsed into one sanitized
 * transcript message because a policy-floor or customer-hook redaction may
 * not identify individual spans. Preserving the original message objects in
 * that case would risk forwarding content the decision said to redact.
 */
function redactedParams(
  method: LlamaIndexMethod,
  params: Record<string, unknown>,
  prompt: string,
  policy: PreCallPolicyResult,
): Record<string, unknown> {
  const redacted = safeRedactedText(prompt, policy);
  if (method === "complete") return { ...params, prompt: redacted };
  return {
    ...params,
    messages: [{ role: "user", content: redacted }],
  };
}

function responseText(value: unknown): string {
  if (!value || typeof value !== "object") return typeof value === "string" ? value : "";
  const response = value as Record<string, unknown>;
  if (typeof response.text === "string") return response.text;
  const message = response.message;
  if (message && typeof message === "object") {
    return contentText((message as Record<string, unknown>).content);
  }
  if (typeof response.delta === "string") return response.delta;
  return "";
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return Boolean(
    value &&
      typeof value === "object" &&
      Symbol.asyncIterator in (value as Record<PropertyKey, unknown>),
  );
}

function modelName(llm: LlamaIndexLLMLike): string {
  const metadata = Reflect.get(llm as object, "metadata", llm as object) as
    | Record<string, unknown>
    | undefined;
  const model = metadata?.model;
  return typeof model === "string" && model.trim() ? model.trim() : "unknown";
}

function emitBlocked(
  config: NonNullable<ReturnType<typeof tryGetConfig>>,
  model: string,
  prompt: string,
  userText: string,
  policy: PreCallPolicyResult,
  opts: IntegrationOptions,
): void {
  emitIntegrationEvent({
    config,
    provider: inferProviderFromModel(model),
    model,
    operation: "llamaindex.llm",
    source: SOURCE,
    prompt: blockedPromptForStorage(prompt, policy.compliance, policy.securityNormalized),
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
}

/**
 * Wrap a LlamaIndex.TS LLM so policy executes on the real model boundary.
 * Assign the returned value wherever the original LLM was used, including
 * `Settings.llm`.
 */
export function obsvrGovernLlamaIndexLLM<T extends LlamaIndexLLMLike>(
  llm: T,
  opts: IntegrationOptions = {},
): T {
  if (!llm || typeof llm.chat !== "function" || typeof llm.complete !== "function") {
    throw new Error("[obsvr] obsvrGovernLlamaIndexLLM requires a LlamaIndex LLM");
  }

  const initialConfig = tryGetConfig();
  if (initialConfig) setupExitHandlers(initialConfig);
  const methodCache = new Map<LlamaIndexMethod, (params: Record<string, unknown>) => Promise<unknown>>();

  return new Proxy(llm, {
    get(target, property) {
      if (property !== "chat" && property !== "complete") {
        return Reflect.get(target, property, target);
      }
      const method = property as LlamaIndexMethod;
      const cached = methodCache.get(method);
      if (cached) return cached;

      const governed = async (params: Record<string, unknown>): Promise<unknown> => {
        const original = Reflect.get(target, method, target) as (
          value: Record<string, unknown>,
        ) => Promise<unknown>;
        const config = tryGetConfig();
        if (!config) return original.call(target, params);

        const started = performance.now();
        const model = modelName(target);
        const provider = inferProviderFromModel(model);
        const { prompt, userText } = requestText(method, params ?? {});
        const policy = await applyPreCallPolicy(prompt, {
          config,
          provider,
          operation: "llamaindex.llm",
          userId: opts.user_id,
          serviceName: opts.service_name,
          model,
          metadata: opts.metadata,
        });

        if (policy.decision === "block") {
          emitBlocked(config, model, prompt, userText, policy, opts);
          throw blockedCallError(policy.compliance);
        }

        const outbound =
          policy.decision === "redact"
            ? redactedParams(method, params ?? {}, prompt, policy)
            : params;
        const auditThisCall =
          monitorModeRequiresEvidence(config) ||
          shouldSample(config.sample_rate) ||
          policy.decision === "redact" ||
          policy.compliance.action_reason !== "none";

        const emitResult = (response: string, success: boolean, error?: unknown): void => {
          if (!auditThisCall && success) return;
          emitIntegrationEvent({
            config,
            provider,
            model,
            operation: "llamaindex.llm",
            source: SOURCE,
            prompt:
              policy.decision === "redact"
                ? safeRedactedText(prompt, policy)
                : prompt,
            response,
            userInput:
              policy.decision === "redact"
                ? safeRedactedText(userText, policy)
                : userText,
            latencyMs: Math.round(performance.now() - started),
            success,
            error,
            options: opts,
            canaryTelemetry: policy.canaryTelemetry,
            floorTelemetry: policy.floorTelemetry,
            compliance: policy.compliance,
          });
        };

        try {
          const result = await original.call(target, outbound);
          if (!isAsyncIterable(result)) {
            emitResult(responseText(result), true);
            return result;
          }

          return (async function* governedStream(): AsyncIterable<unknown> {
            let text = "";
            try {
              for await (const chunk of result) {
                text += responseText(chunk);
                yield chunk;
              }
              emitResult(text, true);
            } catch (error) {
              emitResult(text, false, error);
              throw error;
            }
          })();
        } catch (error) {
          emitResult("", false, error);
          throw error;
        }
      };

      methodCache.set(method, governed);
      return governed;
    },
  });
}
