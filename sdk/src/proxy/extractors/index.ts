/**
 * Extractors Module
 *
 * @packageDocumentation
 */

// OpenAI extractors
export {
  extractPrompt as extractOpenAIPrompt,
  extractResponse as extractOpenAIResponse,
  extractModel as extractOpenAIModel,
  isStreamingRequest as isOpenAIStreamingRequest,
  extractTokenUsage as extractOpenAITokenUsage,
  extractOpenAIChat,
} from "./openai-chat.js";

// Anthropic extractors
export {
  extractPrompt as extractAnthropicPrompt,
  extractResponse as extractAnthropicResponse,
  extractModel as extractAnthropicModel,
  isStreamingRequest as isAnthropicStreamingRequest,
  extractTokenUsage as extractAnthropicTokenUsage,
  extractAnthropicMessages,
} from "./anthropic.js";

// Legacy exports (for backward compatibility)
export {
  extractPrompt,
  extractResponse,
  extractModel,
  isStreamingRequest,
  extractTokenUsage,
} from "./openai-chat.js";

export type {
  ExtractionResult,
  OpenAIChatMessage,
  OpenAIChatRequest,
  OpenAIChatResponse,
  OpenAIContentPart,
  TokenUsage,
} from "./types.js";

export type {
  AnthropicMessage,
  AnthropicMessagesRequest,
  AnthropicMessagesResponse,
  AnthropicContentBlock,
} from "./anthropic.js";
