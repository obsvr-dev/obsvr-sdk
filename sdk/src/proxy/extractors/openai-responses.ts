/**
 * OpenAI Responses API Extractor
 *
 * Extracts prompt and response from OpenAI `responses.create` calls
 * (the successor surface to Chat Completions). The request carries
 * `instructions` (system) and `input` (a plain string or a list of
 * message-like items); the response carries an `output` item list
 * (and, on SDK objects, an `output_text` convenience aggregate).
 *
 * @packageDocumentation
 */

import type { TokenUsage } from "./types.js";

/** One content part inside a Responses input/output message item. */
export interface OpenAIResponsesContentPart {
  type?: string; // 'input_text' | 'output_text' | 'input_image' | ...
  text?: string;
}

/** One item in the Responses `input` list (message, function_call, ...). */
export interface OpenAIResponsesInputItem {
  type?: string; // 'message' (default) | 'function_call' | 'function_call_output' | ...
  role?: string;
  content?: string | OpenAIResponsesContentPart[] | null;
  // function_call items
  name?: string;
  arguments?: string;
  // function_call_output items
  output?: string;
}

export interface OpenAIResponsesRequest {
  model?: string;
  instructions?: string | null;
  input?: string | OpenAIResponsesInputItem[];
  stream?: boolean;
}

/** One item in the Responses `output` list. */
export interface OpenAIResponsesOutputItem {
  type?: string; // 'message' | 'function_call' | 'reasoning' | ...
  role?: string;
  content?: OpenAIResponsesContentPart[];
  name?: string;
  arguments?: string;
}

export interface OpenAIResponsesResponse {
  model?: string;
  /** SDK convenience aggregate of all output_text parts. */
  output_text?: string;
  output?: OpenAIResponsesOutputItem[];
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
    total_tokens?: number;
  };
}

/**
 * Extract text from an item's content field (string or content-part array).
 */
function extractItemContent(
  content: string | null | undefined | OpenAIResponsesContentPart[],
): string {
  if (content === null || content === undefined) {
    return "";
  }
  if (typeof content === "string") {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .filter((part) => typeof part.text === "string" && part.text)
      .map((part) => part.text!)
      .join("\n");
  }
  return "";
}

/**
 * Format a single input item for the prompt string (mirrors the
 * Chat Completions extractor's "role: content" convention).
 */
function formatInputItem(item: OpenAIResponsesInputItem): string {
  if (item.type === "function_call") {
    return `[Function call: ${item.name}(${item.arguments ?? ""})]`;
  }
  if (item.type === "function_call_output") {
    return `[Function output: ${item.output ?? ""}]`;
  }
  const role = item.role ?? "user";
  return `${role}: ${extractItemContent(item.content)}`;
}

/**
 * Extract prompt from a Responses API request:
 * instructions (as system) + input (string or item list).
 */
export function extractPrompt(request: OpenAIResponsesRequest): string {
  const parts: string[] = [];
  if (typeof request.instructions === "string" && request.instructions) {
    parts.push(`system: ${request.instructions}`);
  }
  if (typeof request.input === "string") {
    parts.push(`user: ${request.input}`);
  } else if (Array.isArray(request.input)) {
    for (const item of request.input) {
      parts.push(formatInputItem(item));
    }
  }
  return parts.join("\n");
}

/**
 * Extract response text from a Responses API response.
 * Prefers the SDK's `output_text` aggregate; otherwise walks the
 * `output` item list (message text + function calls).
 */
export function extractResponse(response: OpenAIResponsesResponse): string {
  if (typeof response.output_text === "string" && response.output_text) {
    return response.output_text;
  }
  if (!Array.isArray(response.output)) {
    return "";
  }
  const parts: string[] = [];
  for (const item of response.output) {
    if (item.type === "function_call") {
      parts.push(`[Function call: ${item.name}(${item.arguments ?? ""})]`);
    } else if (Array.isArray(item.content)) {
      for (const part of item.content) {
        if (part.type === "output_text" && typeof part.text === "string") {
          parts.push(part.text);
        }
      }
    }
  }
  return parts.join("\n");
}

/**
 * Extract model from request (normalized)
 */
export function extractModel(request: OpenAIResponsesRequest): string {
  const model = request.model;
  if (typeof model !== "string") {
    return "unknown";
  }
  return model.trim();
}

/**
 * Extract token usage from a Responses API response.
 * (Native field names are already input/output/total_tokens.)
 */
export function extractTokenUsage(
  response: OpenAIResponsesResponse,
): TokenUsage | undefined {
  if (!response.usage) {
    return undefined;
  }
  return {
    input_tokens: response.usage.input_tokens || 0,
    output_tokens: response.usage.output_tokens || 0,
    total_tokens: response.usage.total_tokens || 0,
  };
}

/**
 * Accumulate text, token usage, and model from a Responses API event
 * stream: `response.output_text.delta` events carry text increments and
 * `response.completed` carries the final response (usage + model).
 */
export function accumulateResponsesStream(chunks: unknown[]): {
  text: string;
  usage?: TokenUsage;
  model: string;
} {
  let text = "";
  let usage: TokenUsage | undefined;
  let model = "unknown";
  let completed: OpenAIResponsesResponse | undefined;

  for (const chunk of chunks as Record<string, any>[]) {
    if (chunk.type === "response.output_text.delta" && typeof chunk.delta === "string") {
      text += chunk.delta;
    }
    // Lifecycle events (response.created / response.completed / ...) embed
    // a response snapshot; the last one wins for model/usage.
    const snapshot = chunk.response as OpenAIResponsesResponse | undefined;
    if (snapshot && typeof snapshot === "object") {
      if (typeof snapshot.model === "string" && snapshot.model) {
        model = snapshot.model;
      }
      if (chunk.type === "response.completed") {
        completed = snapshot;
      }
    }
  }

  if (completed?.usage) {
    usage = extractTokenUsage(completed);
  }
  // No deltas observed (e.g. only lifecycle events buffered): fall back to
  // the completed response's output.
  if (!text && completed) {
    text = extractResponse(completed);
  }

  return { text, usage, model };
}
