import {
  extractPrompt,
  extractResponse,
  extractModel,
  extractTokenUsage,
  extractStreamingResponse,
  isStreamingRequest,
} from '../../src/proxy/extractors/anthropic';
import type {
  AnthropicMessagesRequest,
  AnthropicMessagesResponse,
  AnthropicStreamEvent,
} from '../../src/proxy/extractors/anthropic';

// ---------------------------------------------------------------------------
// extractPrompt
// ---------------------------------------------------------------------------

describe('extractPrompt', () => {
  it('should prepend system prompt when present', () => {
    const request: AnthropicMessagesRequest = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      system: 'You are a helpful assistant.',
      messages: [{ role: 'user', content: 'Hello!' }],
    };

    const result = extractPrompt(request);
    expect(result).toBe('system: You are a helpful assistant.\nuser: Hello!');
  });

  it('should not include empty/whitespace-only system prompt', () => {
    const request: AnthropicMessagesRequest = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      system: '   ',
      messages: [{ role: 'user', content: 'Hi' }],
    };

    const result = extractPrompt(request);
    expect(result).toBe('user: Hi');
  });

  it('should handle request without system prompt', () => {
    const request: AnthropicMessagesRequest = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      messages: [
        { role: 'user', content: 'What is 2+2?' },
        { role: 'assistant', content: 'It is 4.' },
      ],
    };

    const result = extractPrompt(request);
    expect(result).toBe('user: What is 2+2?\nassistant: It is 4.');
  });

  it('should handle multi-block content with text and tool_use blocks', () => {
    const request: AnthropicMessagesRequest = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      messages: [
        {
          role: 'assistant',
          content: [
            { type: 'text', text: 'Let me look that up.' },
            {
              type: 'tool_use',
              id: 'tool_abc',
              name: 'search',
              input: { query: 'current weather' },
            },
          ],
        },
      ],
    };

    const result = extractPrompt(request);
    expect(result).toContain('Let me look that up.');
    expect(result).toContain('[tool_use: search({"query":"current weather"})]');
  });

  it('should handle image blocks by rendering a placeholder', () => {
    const request: AnthropicMessagesRequest = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'Describe this image.' },
            {
              type: 'image',
              source: { type: 'base64', media_type: 'image/png', data: 'abc123' },
            },
          ],
        },
      ],
    };

    const result = extractPrompt(request);
    expect(result).toContain('Describe this image.');
    expect(result).toContain('[image]');
  });

  it('should handle tool_result blocks', () => {
    const request: AnthropicMessagesRequest = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      messages: [
        {
          role: 'user',
          content: [
            { type: 'tool_result', tool_use_id: 'tool_abc' },
          ],
        },
      ],
    };

    const result = extractPrompt(request);
    expect(result).toContain('[tool_result: tool_abc]');
  });

  it('should handle empty messages array', () => {
    const request: AnthropicMessagesRequest = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      messages: [],
    };

    expect(extractPrompt(request)).toBe('');
  });

  it('should return empty string when messages field is missing', () => {
    const request = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
    } as any;

    expect(extractPrompt(request)).toBe('');
  });
});

// ---------------------------------------------------------------------------
// extractResponse
// ---------------------------------------------------------------------------

describe('extractResponse', () => {
  it('should extract text from a single text content block', () => {
    const response: AnthropicMessagesResponse = {
      id: 'msg_01',
      type: 'message',
      role: 'assistant',
      content: [{ type: 'text', text: 'The answer is 42.' }],
      model: 'claude-3-opus-20240229',
      stop_reason: 'end_turn',
      usage: { input_tokens: 10, output_tokens: 6 },
    };

    expect(extractResponse(response)).toBe('The answer is 42.');
  });

  it('should join multiple content blocks with newlines', () => {
    const response: AnthropicMessagesResponse = {
      id: 'msg_02',
      type: 'message',
      role: 'assistant',
      content: [
        { type: 'text', text: 'First paragraph.' },
        { type: 'text', text: 'Second paragraph.' },
      ],
      model: 'claude-3-opus-20240229',
      stop_reason: 'end_turn',
      usage: { input_tokens: 5, output_tokens: 10 },
    };

    expect(extractResponse(response)).toBe('First paragraph.\nSecond paragraph.');
  });

  it('should handle tool_use block in response', () => {
    const response: AnthropicMessagesResponse = {
      id: 'msg_03',
      type: 'message',
      role: 'assistant',
      content: [
        {
          type: 'tool_use',
          id: 'toolu_01',
          name: 'get_weather',
          input: { city: 'NYC' },
        },
      ],
      model: 'claude-3-opus-20240229',
      stop_reason: 'tool_use',
      usage: { input_tokens: 8, output_tokens: 4 },
    };

    const result = extractResponse(response);
    expect(result).toContain('get_weather');
    expect(result).toContain('{"city":"NYC"}');
  });

  it('should return empty string when content array is empty', () => {
    const response: AnthropicMessagesResponse = {
      id: 'msg_04',
      type: 'message',
      role: 'assistant',
      content: [],
      model: 'claude-3-opus-20240229',
      stop_reason: 'end_turn',
      usage: { input_tokens: 5, output_tokens: 0 },
    };

    expect(extractResponse(response)).toBe('');
  });

  it('should return empty string when response has no content field', () => {
    expect(extractResponse(null as any)).toBe('');
    expect(extractResponse(undefined as any)).toBe('');
    expect(extractResponse({} as any)).toBe('');
  });
});

// ---------------------------------------------------------------------------
// extractTokenUsage
// ---------------------------------------------------------------------------

describe('extractTokenUsage', () => {
  it('should map input_tokens and output_tokens correctly', () => {
    const response: AnthropicMessagesResponse = {
      id: 'msg_05',
      type: 'message',
      role: 'assistant',
      content: [{ type: 'text', text: 'Hello' }],
      model: 'claude-3-opus-20240229',
      stop_reason: 'end_turn',
      usage: { input_tokens: 20, output_tokens: 8 },
    };

    const usage = extractTokenUsage(response);
    expect(usage).toBeDefined();
    expect(usage!.input_tokens).toBe(20);
    expect(usage!.output_tokens).toBe(8);
    expect(usage!.total_tokens).toBe(28);
  });

  it('should compute total_tokens as the sum of input and output', () => {
    const response: AnthropicMessagesResponse = {
      id: 'msg_06',
      type: 'message',
      role: 'assistant',
      content: [],
      model: 'claude-3-opus-20240229',
      stop_reason: 'end_turn',
      usage: { input_tokens: 100, output_tokens: 50 },
    };

    const usage = extractTokenUsage(response);
    expect(usage!.total_tokens).toBe(150);
  });

  it('should return undefined when response has no usage field', () => {
    expect(extractTokenUsage(null as any)).toBeUndefined();
    expect(extractTokenUsage(undefined as any)).toBeUndefined();
    expect(extractTokenUsage({} as any)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// extractStreamingResponse
// ---------------------------------------------------------------------------

describe('extractStreamingResponse', () => {
  it('should accumulate text from content_block_delta text_delta events', () => {
    const events: AnthropicStreamEvent[] = [
      { type: 'message_start', message: { id: 'msg_01', type: 'message', role: 'assistant', content: [], model: 'claude-3-opus-20240229', stop_reason: null, usage: { input_tokens: 15, output_tokens: 0 } } },
      { type: 'content_block_start', index: 0, content_block: { type: 'text' } } as any,
      { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'Hello' } },
      { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: ' world' } },
      { type: 'content_block_stop', index: 0 } as any,
      { type: 'message_delta', delta: { type: 'end_turn', stop_reason: 'end_turn' } as any, usage: { output_tokens: 2 } },
      { type: 'message_stop' } as any,
    ];

    const result = extractStreamingResponse(events);
    expect(result.text).toBe('Hello world');
  });

  it('should ignore non-text_delta deltas', () => {
    const events: AnthropicStreamEvent[] = [
      {
        type: 'content_block_delta',
        index: 0,
        delta: { type: 'input_json_delta', partial_json: '{"key":' },
      },
      {
        type: 'content_block_delta',
        index: 0,
        delta: { type: 'text_delta', text: 'real text' },
      },
    ];

    const result = extractStreamingResponse(events);
    expect(result.text).toBe('real text');
  });

  it('should extract input_tokens from message_start event', () => {
    const events: AnthropicStreamEvent[] = [
      {
        type: 'message_start',
        message: {
          id: 'msg_01',
          type: 'message',
          role: 'assistant',
          content: [],
          model: 'claude-3-opus-20240229',
          stop_reason: null,
          usage: { input_tokens: 42, output_tokens: 0 },
        },
      },
      { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'hi' } },
      { type: 'message_delta', usage: { output_tokens: 1 } } as any,
    ];

    const result = extractStreamingResponse(events);
    expect(result.usage).toBeDefined();
    expect(result.usage!.input_tokens).toBe(42);
  });

  it('should extract output_tokens from message_delta event', () => {
    const events: AnthropicStreamEvent[] = [
      {
        type: 'message_start',
        message: {
          id: 'msg_01',
          type: 'message',
          role: 'assistant',
          content: [],
          model: 'claude-3-opus-20240229',
          stop_reason: null,
          usage: { input_tokens: 10, output_tokens: 0 },
        },
      },
      { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'Done' } },
      { type: 'message_delta', usage: { output_tokens: 7 } } as any,
    ];

    const result = extractStreamingResponse(events);
    expect(result.usage!.output_tokens).toBe(7);
  });

  it('should compute total_tokens as input + output from streaming events', () => {
    const events: AnthropicStreamEvent[] = [
      {
        type: 'message_start',
        message: {
          id: 'msg_01',
          type: 'message',
          role: 'assistant',
          content: [],
          model: 'claude-3-opus-20240229',
          stop_reason: null,
          usage: { input_tokens: 30, output_tokens: 0 },
        },
      },
      { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'ok' } },
      { type: 'message_delta', usage: { output_tokens: 15 } } as any,
    ];

    const result = extractStreamingResponse(events);
    expect(result.usage!.total_tokens).toBe(45);
  });

  it('should return undefined usage when no usage events are present', () => {
    const events: AnthropicStreamEvent[] = [
      { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'Hello' } },
    ];

    const result = extractStreamingResponse(events);
    expect(result.usage).toBeUndefined();
  });

  it('should return empty text for an empty event array', () => {
    const result = extractStreamingResponse([]);
    expect(result.text).toBe('');
    expect(result.usage).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// extractModel
// ---------------------------------------------------------------------------

describe('extractModel', () => {
  it('preserves model case (exact model must appear in the audit record)', () => {
    const request: AnthropicMessagesRequest = {
      model: 'Claude-3-Opus-20240229',
      max_tokens: 1024,
      messages: [],
    };

    expect(extractModel(request)).toBe('Claude-3-Opus-20240229');
  });

  it('should strip surrounding whitespace', () => {
    const request: AnthropicMessagesRequest = {
      model: '  claude-3-sonnet  ',
      max_tokens: 1024,
      messages: [],
    };

    expect(extractModel(request)).toBe('claude-3-sonnet');
  });

  it('should return "unknown" when model is missing', () => {
    const request = { max_tokens: 1024, messages: [] } as any;
    expect(extractModel(request)).toBe('unknown');
  });

  it('should return "unknown" when model is not a string', () => {
    const request = { model: 42, max_tokens: 1024, messages: [] } as any;
    expect(extractModel(request)).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------
// isStreamingRequest
// ---------------------------------------------------------------------------

describe('isStreamingRequest (anthropic)', () => {
  it('should return true when stream is true', () => {
    const request: AnthropicMessagesRequest = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      messages: [],
      stream: true,
    };
    expect(isStreamingRequest(request)).toBe(true);
  });

  it('should return false when stream is false', () => {
    const request: AnthropicMessagesRequest = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      messages: [],
      stream: false,
    };
    expect(isStreamingRequest(request)).toBe(false);
  });

  it('should return false when stream field is absent', () => {
    const request: AnthropicMessagesRequest = {
      model: 'claude-3-opus-20240229',
      max_tokens: 1024,
      messages: [],
    };
    expect(isStreamingRequest(request)).toBe(false);
  });
});
