/**
 * Extractor Types
 *
 * @packageDocumentation
 */

/**
 * Token usage extracted from an LLM response.
 *
 * Every field is optional, and that is the point: a count obsvr could not read
 * must be able to be ABSENT. When these were required, an extractor handed a
 * payload it did not understand had no way to say so — it had to invent a
 * number, and `|| 0` was the number it invented. A fabricated zero is
 * indistinguishable in the audit trail from a call that genuinely consumed
 * nothing, so the type itself was the reason the evidence could lie.
 *
 * Produced by {@link ./token-usage.normalizeTokenUsage}; do not build one by
 * hand.
 */
export interface TokenUsage {
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
}

/**
 * Extracted prompt and response from an LLM call
 */
export interface ExtractionResult {
  prompt: string;
  response: string;
  model: string;
  token_usage?: TokenUsage;
}

/**
 * OpenAI Chat Message structure
 */
export interface OpenAIChatMessage {
  role: string;
  content?: string | null | OpenAIContentPart[];
  name?: string;
  function_call?: {
    name: string;
    arguments: string;
  };
  tool_calls?: Array<{
    id: string;
    type: string;
    function: {
      name: string;
      arguments: string;
    };
  }>;
}

/**
 * OpenAI Content Part (for multimodal)
 */
export interface OpenAIContentPart {
  type: "text" | "image_url";
  text?: string;
  image_url?: {
    url: string;
    detail?: string;
  };
}

/**
 * OpenAI Chat Completion Request
 */
export interface OpenAIChatRequest {
  model: string;
  messages: OpenAIChatMessage[];
  stream?: boolean;
  [key: string]: unknown;
}

/**
 * OpenAI Chat Completion Response
 */
export interface OpenAIChatResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: OpenAIChatMessage;
    finish_reason: string | null;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}
