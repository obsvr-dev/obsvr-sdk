/**
 * Google Gemini Extractor
 *
 * Extracts prompt and response from Google Generative AI SDK calls
 * (@google/genai and the legacy @google/generative-ai package).
 *
 * Handles:
 *  - Standard (non-streaming) generateContent responses
 *  - Streaming responses via generateContentStream
 *  - String and object request shapes
 *
 * @packageDocumentation
 */

import type { ExtractionResult, TokenUsage } from "./types.js";
import { readTokenUsage } from "./token-usage.js";

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
  role?: "user" | "model";
  parts: GeminiPart[];
}

/**
 * Gemini request object shape (when not a plain string)
 */
export interface GeminiRequestObject {
  /** Maintained SDK carries the model per call; legacy stores it on the model. */
  model?: string;
  contents?: string | GeminiPart | GeminiContent | Array<string | GeminiPart | GeminiContent>;
  /** Chat session methods carry the newest turn under `message`. */
  message?: string | GeminiPart | GeminiContent | Array<string | GeminiPart | GeminiContent>;
  systemInstruction?: string | GeminiPart | GeminiContent;
  config?: {
    systemInstruction?: string | GeminiPart | GeminiContent;
    responseMimeType?: string;
    responseSchema?: unknown;
    responseJsonSchema?: unknown;
    [key: string]: unknown;
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
  candidates?: Array<{
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
  /** Maintained @google/genai exposes response text through a getter. */
  readonly text?: string | (() => string);
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

/** Extract text recursively from every request content union either SDK accepts. */
function contentText(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value.map(contentText).filter(Boolean).join("\n");
  }
  if (!value || typeof value !== "object") return "";
  const record = value as Record<string, unknown>;
  if (typeof record.text === "string") return record.text;
  if (Array.isArray(record.parts)) return contentText(record.parts);
  return "";
}

/** Newest user turn, including the maintained SDK's string/part shorthand. */
export function extractLastUserText(request: GeminiRequest): string {
  if (typeof request === "string") return request;
  if (request?.message !== undefined) return contentText(request.message);
  const contents = request?.contents;
  if (!Array.isArray(contents)) return contentText(contents);
  for (let i = contents.length - 1; i >= 0; i--) {
    const entry = contents[i];
    if (
      entry &&
      typeof entry === "object" &&
      "role" in entry &&
      (entry as GeminiContent).role !== "user"
    ) {
      continue;
    }
    const text = contentText(entry);
    if (text) return text;
  }
  return "";
}

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

  const systemText = contentText(
    request.systemInstruction ?? request.config?.systemInstruction,
  );
  if (systemText) parts.push(`system: ${systemText}`);

  const messageText = contentText(request.message);
  if (messageText) parts.push(messageText);

  if (Array.isArray(request.contents)) {
    for (const content of request.contents) {
      const text = contentText(content);
      if (!text) continue;
      const role =
        content && typeof content === "object" && "role" in content
          ? (content as GeminiContent).role
          : undefined;
      parts.push(role ? `${role}: ${text}` : text);
    }
  } else {
    const text = contentText(request.contents);
    if (text) parts.push(text);
  }

  return parts.join("\n");
}

/**
 * Extract the response text from a Gemini generateContent response.
 *
 * Joins all text parts from the first candidate's content.
 */
export function extractResponse(response: GeminiResponse): string {
  const r = unwrap(response);

  // Maintained SDK: getter. Legacy SDK: text() helper.
  if (typeof r?.text === "string") return r.text;
  if (typeof r?.text === "function") {
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
export function extractModel(request: GeminiRequest, modelHint?: string): string {
  if (
    request &&
    typeof request === "object" &&
    typeof request.model === "string" &&
    request.model.length > 0
  ) {
    return request.model.replace(/^models\//, "");
  }
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
  return readTokenUsage(unwrap(response)?.usageMetadata);
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
