/**
 * Anthropic Messages Extractor
 *
 * Extracts prompt and response from Anthropic Messages API calls.
 *
 * Handles:
 *  - Standard (non-streaming) message responses
 *  - Streaming responses via content_block_delta events
 *  - Error responses (4xx/5xx)
 *
 * @packageDocumentation
 */

import type { ExtractionResult, TokenUsage } from "./types.js";

// ---------------------------------------------------------------------------
// Anthropic API Types
// ---------------------------------------------------------------------------

/**
 * A single message in the Anthropic Messages API request
 */
export interface AnthropicMessage {
  role: "user" | "assistant";
  content: string | AnthropicContentBlock[];
}

/**
 * A content block in an Anthropic message
 */
export interface AnthropicContentBlock {
  type: "text" | "image" | "tool_use" | "tool_result";
  text?: string;
  // image source (not extracted as text)
  source?: {
    type: string;
    media_type?: string;
    data?: string;
    url?: string;
  };
  // tool_use fields
  id?: string;
  name?: string;
  input?: unknown;
  // tool_result fields
  tool_use_id?: string;
}

/**
 * Anthropic Messages API request body
 */
export interface AnthropicMessagesRequest {
  model: string;
  messages: AnthropicMessage[];
  max_tokens: number;
  system?: string;
  stream?: boolean;
  temperature?: number;
  top_p?: number;
  top_k?: number;
  metadata?: {
    user_id?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

/**
 * Anthropic Messages API response body (non-streaming)
 */
export interface AnthropicMessagesResponse {
  id: string;
  type: "message";
  role: "assistant";
  content: AnthropicContentBlock[];
  model: string;
  stop_reason: "end_turn" | "max_tokens" | "stop_sequence" | "tool_use" | null;
  stop_sequence?: string | null;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
}

/**
 * A single server-sent event in a streaming Anthropic response
 */
export interface AnthropicStreamEvent {
  type: string;
  index?: number;
  delta?: {
    type: "text_delta" | "input_json_delta";
    text?: string;
    partial_json?: string;
  };
  message?: AnthropicMessagesResponse;
  content_block?: AnthropicContentBlock;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Extract text from a single Anthropic content block.
 * Non-text blocks (image, tool_use, tool_result) are rendered as
 * human-readable placeholders so the prompt/response strings remain
 * meaningful without discarding structural information.
 */
function extractBlockText(block: AnthropicContentBlock): string {
  switch (block.type) {
    case "text":
      return block.text ?? "";
    case "image":
      return "[image]";
    case "tool_use":
      return `[tool_use: ${block.name ?? "unknown"}(${JSON.stringify(block.input ?? {})})]`;
    case "tool_result":
      return `[tool_result: ${block.tool_use_id ?? "unknown"}]`;
    default:
      return "";
  }
}

/**
 * Convert an Anthropic content field (string or block array) to plain text.
 */
function contentToText(
  content: string | AnthropicContentBlock[] | undefined | null
): string {
  if (content === null || content === undefined) {
    return "";
  }
  if (typeof content === "string") {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .map(extractBlockText)
      .filter((s) => s.length > 0)
      .join("\n");
  }
  return "";
}

// ---------------------------------------------------------------------------
// Exported extractor functions (mirrors openai-chat.ts API surface)
// ---------------------------------------------------------------------------

/**
 * Extract the formatted prompt string from an Anthropic Messages request.
 *
 * The system prompt (if present) is prepended as "system: <text>".
 * Each message is rendered as "<role>: <content>".
 */
export function extractPrompt(request: AnthropicMessagesRequest): string {
  const parts: string[] = [];

  // Include system prompt if present
  if (typeof request.system === "string" && request.system.trim().length > 0) {
    parts.push(`system: ${request.system}`);
  }

  if (!request.messages || !Array.isArray(request.messages)) {
    return parts.join("\n");
  }

  for (const message of request.messages) {
    const text = contentToText(message.content);
    parts.push(`${message.role}: ${text}`);
  }

  return parts.join("\n");
}

/**
 * Extract the response text from an Anthropic Messages API response.
 *
 * Uses content[0].text for standard responses.
 * Handles multi-block responses by joining all text blocks.
 */
export function extractResponse(response: AnthropicMessagesResponse): string {
  if (!response || !response.content || !Array.isArray(response.content)) {
    return "";
  }
  return contentToText(response.content);
}

/**
 * Extract the normalised model identifier from an Anthropic request.
 */
export function extractModel(request: AnthropicMessagesRequest): string {
  const model = request.model;
  if (typeof model !== "string") {
    return "unknown";
  }
  return model.trim();
}

/**
 * Return true when the request is a streaming request.
 */
export function isStreamingRequest(request: AnthropicMessagesRequest): boolean {
  return request.stream === true;
}

/**
 * Extract token usage from an Anthropic Messages response.
 *
 * Maps Anthropic's `usage.input_tokens` / `usage.output_tokens` to the
 * shared `TokenUsage` shape used throughout the SDK.
 *
 * Returns `undefined` when usage data is absent (e.g., error responses or
 * partial streaming accumulations that have not yet received the final
 * `message_delta` event).
 */
export function extractTokenUsage(
  response: AnthropicMessagesResponse
): TokenUsage | undefined {
  if (!response || !response.usage) {
    return undefined;
  }

  const inputTokens = response.usage.input_tokens ?? 0;
  const outputTokens = response.usage.output_tokens ?? 0;

  return {
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    total_tokens: inputTokens + outputTokens,
  };
}

/**
 * Accumulate text from a stream of Anthropic server-sent events.
 *
 * The Anthropic streaming protocol emits `content_block_delta` events with
 * `delta.type === "text_delta"`.  This helper collects all delta texts in
 * order and returns the concatenated result, along with the final usage
 * data found in `message_delta` events.
 *
 * @param events - Array of parsed SSE event objects
 * @returns Object containing accumulated text and optional token usage
 */
export function extractStreamingResponse(events: AnthropicStreamEvent[]): {
  text: string;
  usage?: TokenUsage;
} {
  const textChunks: string[] = [];
  let inputTokens: number | undefined;
  let outputTokens: number | undefined;

  for (const event of events) {
    if (
      event.type === "content_block_delta" &&
      event.delta?.type === "text_delta" &&
      typeof event.delta.text === "string"
    ) {
      textChunks.push(event.delta.text);
    }

    // The final `message_delta` event carries output token count
    if (event.type === "message_delta" && event.usage) {
      if (typeof event.usage.output_tokens === "number") {
        outputTokens = event.usage.output_tokens;
      }
    }

    // The `message_start` event carries the initial message with input tokens
    if (event.type === "message_start" && event.message?.usage) {
      if (typeof event.message.usage.input_tokens === "number") {
        inputTokens = event.message.usage.input_tokens;
      }
    }
  }

  let usage: TokenUsage | undefined;
  if (inputTokens !== undefined || outputTokens !== undefined) {
    const inp = inputTokens ?? 0;
    const out = outputTokens ?? 0;
    usage = { input_tokens: inp, output_tokens: out, total_tokens: inp + out };
  }

  return {
    text: textChunks.join(""),
    usage,
  };
}

/**
 * Full extraction from an Anthropic request and response pair.
 *
 * This is the primary entry point for the proxy wrapper - mirrors
 * `extractOpenAIChat` from `openai-chat.ts`.
 */
export function extractAnthropicMessages(
  request: unknown,
  response: unknown
): ExtractionResult {
  const req = request as AnthropicMessagesRequest;
  const res = response as AnthropicMessagesResponse;

  return {
    prompt: extractPrompt(req),
    response: extractResponse(res),
    model: extractModel(req),
    token_usage: extractTokenUsage(res),
  };
}
