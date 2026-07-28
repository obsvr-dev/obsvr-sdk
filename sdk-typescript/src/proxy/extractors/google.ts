/**
 * Google Gemini Extractor
 *
 * Extracts prompt and response from Google Generative AI SDK calls
 * (@google/generative-ai).
 *
 * Handles:
 *  - Standard (non-streaming) generateContent responses
 *  - Streaming responses via generateContentStream
 *  - String and object request shapes
 *
 * @packageDocumentation
 */

import type { ExtractionResult, TokenUsage } from "./types.js";

// ---------------------------------------------------------------------------
// Google Gemini API Types
// ---------------------------------------------------------------------------

/**
 * A single part in a Gemini content block
 */
export interface GeminiPart {
  text?: string;
  inlineData?: unknown;
}

/**
 * A single content entry in a Gemini request
 */
export interface GeminiContent {
  role: "user" | "model";
  parts: GeminiPart[];
}

/**
 * Gemini request object shape (when not a plain string)
 */
export interface GeminiRequestObject {
  contents: GeminiContent[];
  systemInstruction?: {
    parts: Array<{ text: string }>;
  };
  generationConfig?: {
    maxOutputTokens?: number;
    temperature?: number;
  };
}

/**
 * Google Gemini generateContent request - either a plain string prompt
 * or a structured request object.
 */
export type GeminiRequest = string | GeminiRequestObject;

/**
 * Google Gemini generateContent response (bare GenerateContentResponse shape)
 */
export interface GeminiResponse {
  candidates: Array<{
    content: {
      parts: GeminiPart[];
      role: string;
    };
    finishReason: string;
  }>;
  usageMetadata?: {
    promptTokenCount: number;
    candidatesTokenCount: number;
    totalTokenCount: number;
  };
  /** The actual served model snapshot, e.g. "gemini-2.5-flash-002". */
  modelVersion?: string;
}

/**
 * The @google/generative-ai SDK wraps the response in a GenerateContentResult:
 *   { response: GenerateContentResponse }
 * Unwrap it so extractors always operate on the bare response.
 */
function unwrap(raw: unknown): GeminiResponse {
  if (
    raw &&
    typeof raw === 'object' &&
    'response' in (raw as object) &&
    typeof (raw as Record<string, unknown>).response === 'object' &&
    (raw as Record<string, unknown>).response !== null &&
    'candidates' in ((raw as Record<string, unknown>).response as object)
  ) {
    return (raw as { response: GeminiResponse }).response;
  }
  return raw as GeminiResponse;
}

// Exposed so callers outside this module (e.g. the model_resolved / temporal
// provenance read in wrapper.ts) can unwrap a raw GenerateContentResult the
// same way the prompt/response/token extractors above already do — instead
// of reading fields directly off the still-wrapped `{ response: ... }` shape.
export const unwrapGeminiResponse = unwrap;

// ---------------------------------------------------------------------------
// Exported extractor functions (mirrors anthropic.ts API surface)
// ---------------------------------------------------------------------------

/**
 * Extract the formatted prompt string from a Gemini request.
 *
 * If the request is a plain string, return it as-is.
 * If it is a structured object, include the system instruction (if present)
 * and join all contents as "<role>: <text>" lines.
 */
export function extractPrompt(request: GeminiRequest): string {
  if (typeof request === "string") {
    return request;
  }

  const parts: string[] = [];

  // Include system instruction if present
  if (request.systemInstruction && Array.isArray(request.systemInstruction.parts)) {
    const systemText = request.systemInstruction.parts
      .map((p) => p.text ?? "")
      .filter((t) => t.length > 0)
      .join("\n");
    if (systemText.length > 0) {
      parts.push(`system: ${systemText}`);
    }
  }

  // Include each content entry
  if (Array.isArray(request.contents)) {
    for (const content of request.contents) {
      const text = Array.isArray(content.parts)
        ? content.parts
            .map((p) => p.text ?? "")
            .filter((t) => t.length > 0)
            .join("\n")
        : "";
      parts.push(`${content.role}: ${text}`);
    }
  }

  return parts.join("\n");
}

/**
 * Extract the response text from a Gemini generateContent response.
 *
 * Joins all text parts from the first candidate's content.
 */
export function extractResponse(response: GeminiResponse): string {
  const r = unwrap(response) as GeminiResponse & { text?: () => string };

  // Use the SDK's built-in text() helper - it handles multi-candidate and
  // finish-reason edge cases and is always in sync with the actual SDK version.
  if (typeof r?.text === 'function') {
    try {
      const t = r.text();
      if (t) return t;
      // empty string - fall through to manual walk
    } catch {
      // safety/recitation - fall through to manual walk
    }
  }

  // Fallback: navigate candidates manually
  if (!r || !Array.isArray(r.candidates) || r.candidates.length === 0) {
    return '';
  }
  const firstCandidate = r.candidates[0];
  if (!firstCandidate?.content || !Array.isArray(firstCandidate.content.parts)) {
    return '';
  }
  return firstCandidate.content.parts
    .map((p) => p.text ?? '')
    .filter((t) => t.length > 0)
    .join('');
}

/**
 * Extract the model identifier from a Gemini request.
 *
 * The model is attached to the GenerativeModel instance, not the request
 * payload. If a modelHint is provided (e.g., from `target.model`), use it
 * after stripping the "models/" prefix. Otherwise return "gemini".
 */
export function extractModel(_request: GeminiRequest, modelHint?: string): string {
  if (modelHint) return modelHint.replace(/^models\//, "");
  return "gemini";
}

/**
 * Extract token usage from a Gemini response.
 *
 * Maps promptTokenCount -> input_tokens, candidatesTokenCount -> output_tokens.
 * Returns undefined when usageMetadata is absent.
 */
export function extractTokenUsage(
  response: GeminiResponse
): TokenUsage | undefined {
  const r = unwrap(response);
  if (!r || !r.usageMetadata) {
    return undefined;
  }

  const inputTokens = r.usageMetadata.promptTokenCount ?? 0;
  const outputTokens = r.usageMetadata.candidatesTokenCount ?? 0;
  const totalTokens = r.usageMetadata.totalTokenCount ?? inputTokens + outputTokens;

  return {
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    total_tokens: totalTokens,
  };
}

/**
 * Convenience wrapper that performs full extraction from a Gemini
 * request and response pair.
 *
 * This is the primary entry point for the proxy wrapper - mirrors
 * `extractAnthropicMessages` from `anthropic.ts`.
 */
export function extractGemini(
  request: unknown,
  response: unknown
): ExtractionResult {
  const req = request as GeminiRequest;
  const res = response as GeminiResponse;

  return {
    prompt: extractPrompt(req),
    response: extractResponse(res),
    model: extractModel(req),
    token_usage: extractTokenUsage(res),
  };
}
