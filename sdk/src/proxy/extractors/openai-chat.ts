/**
 * OpenAI Chat Extractor
 *
 * Extracts prompt and response from OpenAI chat completion calls.
 *
 * @packageDocumentation
 */

import type {
  ExtractionResult,
  OpenAIChatMessage,
  OpenAIChatRequest,
  OpenAIChatResponse,
  OpenAIContentPart,
  TokenUsage,
} from "./types.js";

/**
 * Extract text content from a message's content field
 * Handles string, array of content parts, and null/undefined
 */
function extractMessageContent(
  content: string | null | undefined | OpenAIContentPart[]
): string {
  if (content === null || content === undefined) {
    return "";
  }

  if (typeof content === "string") {
    return content;
  }

  // Array of content parts (multimodal)
  if (Array.isArray(content)) {
    return content
      .filter((part) => part.type === "text" && part.text)
      .map((part) => part.text!)
      .join("\n");
  }

  return "";
}

/**
 * Format a single message for the prompt string
 */
function formatMessage(message: OpenAIChatMessage): string {
  const role = message.role;
  const content = extractMessageContent(message.content);

  // Handle function calls
  if (message.function_call) {
    const fnCall = `[Function call: ${message.function_call.name}(${message.function_call.arguments})]`;
    return content ? `${role}: ${content}\n${fnCall}` : `${role}: ${fnCall}`;
  }

  // Handle tool calls
  if (message.tool_calls && message.tool_calls.length > 0) {
    const toolCalls = message.tool_calls
      .map(
        (tc) =>
          `[Tool call: ${tc.function.name}(${tc.function.arguments})]`
      )
      .join("\n");
    return content ? `${role}: ${content}\n${toolCalls}` : `${role}: ${toolCalls}`;
  }

  return `${role}: ${content}`;
}

/**
 * Extract prompt from OpenAI chat request
 *
 * Formats all messages into a readable prompt string
 */
export function extractPrompt(request: OpenAIChatRequest): string {
  if (!request.messages || !Array.isArray(request.messages)) {
    return "";
  }

  return request.messages.map(formatMessage).join("\n");
}

/**
 * Extract response from OpenAI chat completion response
 *
 * Uses choices[0].message.content by default
 */
export function extractResponse(response: OpenAIChatResponse): string {
  if (!response.choices || !Array.isArray(response.choices)) {
    return "";
  }

  const firstChoice = response.choices[0];
  if (!firstChoice || !firstChoice.message) {
    return "";
  }

  const message = firstChoice.message;
  const content = extractMessageContent(message.content);

  // Include function/tool calls in response
  if (message.function_call) {
    const fnCall = `[Function call: ${message.function_call.name}(${message.function_call.arguments})]`;
    return content ? `${content}\n${fnCall}` : fnCall;
  }

  if (message.tool_calls && message.tool_calls.length > 0) {
    const toolCalls = message.tool_calls
      .map(
        (tc) =>
          `[Tool call: ${tc.function.name}(${tc.function.arguments})]`
      )
      .join("\n");
    return content ? `${content}\n${toolCalls}` : toolCalls;
  }

  return content;
}

/**
 * Extract model from request (normalized)
 */
export function extractModel(request: OpenAIChatRequest): string {
  const model = request.model;
  if (typeof model !== "string") {
    return "unknown";
  }
  return model.trim();
}

/**
 * The provider-RESOLVED model snapshot from the response body (e.g.
 * "gpt-4o-2024-08-06"), vs extractModel which returns the request alias.
 * Returns undefined when the response carries no model. Temporal provenance.
 */
export function extractResolvedModel(response: OpenAIChatResponse): string | undefined {
  const m = (response as { model?: unknown })?.model;
  return typeof m === "string" && m.trim().length > 0 ? m.trim() : undefined;
}

/**
 * Check if request is a streaming request
 */
export function isStreamingRequest(request: OpenAIChatRequest): boolean {
  return request.stream === true;
}

/**
 * Extract token usage from OpenAI response
 * Returns undefined if usage data is not available
 */
export function extractTokenUsage(response: OpenAIChatResponse): TokenUsage | undefined {
  if (!response.usage) {
    return undefined;
  }

  return {
    input_tokens: response.usage.prompt_tokens || 0,
    output_tokens: response.usage.completion_tokens || 0,
    total_tokens: response.usage.total_tokens || 0,
  };
}

/**
 * Accumulate text and token usage from a stream of OpenAI ChatCompletionChunk objects.
 * Token usage is only present when the request was made with
 * `stream_options: { include_usage: true }`.
 */
export function accumulateOpenAIStream(chunks: unknown[]): {
  text: string;
  usage?: TokenUsage;
  model: string;
} {
  let text = "";
  let usage: TokenUsage | undefined;
  let model = "unknown";

  for (const chunk of chunks as Record<string, any>[]) {
    if (chunk.model && typeof chunk.model === "string") {
      model = chunk.model;
    }
    const delta = chunk.choices?.[0]?.delta?.content;
    if (typeof delta === "string") {
      text += delta;
    }
    // Usage present in final chunk when stream_options.include_usage is true
    if (chunk.usage) {
      usage = {
        input_tokens: (chunk.usage.prompt_tokens as number) ?? 0,
        output_tokens: (chunk.usage.completion_tokens as number) ?? 0,
        total_tokens: (chunk.usage.total_tokens as number) ?? 0,
      };
    }
  }

  return { text, usage, model };
}

/**
 * Full extraction from request and response
 */
export function extractOpenAIChat(
  request: unknown,
  response: unknown
): ExtractionResult {
  const req = request as OpenAIChatRequest;
  const res = response as OpenAIChatResponse;

  return {
    prompt: extractPrompt(req),
    response: extractResponse(res),
    model: extractModel(req),
    token_usage: extractTokenUsage(res),
  };
}
