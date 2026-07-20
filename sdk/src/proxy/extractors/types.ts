/**
 * Extractor Types
 *
 * @packageDocumentation
 */

/**
 * Token usage extracted from LLM response (V2)
 */
export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
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
