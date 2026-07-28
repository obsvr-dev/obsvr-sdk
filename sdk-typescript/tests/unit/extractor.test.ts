import {
  extractPrompt,
  extractResponse,
  extractModel,
  isStreamingRequest,
  extractOpenAIChat
} from '../../src/proxy/extractors/openai-chat';

describe('extractPrompt', () => {
  it('should extract prompt from messages array', () => {
    const request = {
      model: 'gpt-4',
      messages: [
        { role: 'system', content: 'You are a helpful assistant.' },
        { role: 'user', content: 'Hello!' }
      ]
    };

    const prompt = extractPrompt(request);
    expect(prompt).toBe('system: You are a helpful assistant.\nuser: Hello!');
  });

  it('should handle empty messages', () => {
    const request = { model: 'gpt-4', messages: [] };
    expect(extractPrompt(request)).toBe('');
  });

  it('should handle missing messages', () => {
    const request = { model: 'gpt-4' } as any;
    expect(extractPrompt(request)).toBe('');
  });

  it('should handle multimodal content parts', () => {
    const request = {
      model: 'gpt-4-vision',
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text' as const, text: 'What is this?' },
            { type: 'image_url' as const, image_url: { url: 'http://example.com/img.png' } }
          ]
        }
      ]
    };

    const prompt = extractPrompt(request);
    expect(prompt).toBe('user: What is this?');
  });

  it('should handle function calls', () => {
    const request = {
      model: 'gpt-4',
      messages: [
        {
          role: 'assistant',
          content: null,
          function_call: { name: 'get_weather', arguments: '{"city":"NYC"}' }
        }
      ]
    };

    const prompt = extractPrompt(request);
    expect(prompt).toContain('get_weather');
    expect(prompt).toContain('{"city":"NYC"}');
  });

  it('should handle tool calls', () => {
    const request = {
      model: 'gpt-4',
      messages: [
        {
          role: 'assistant',
          content: null,
          tool_calls: [
            {
              id: 'call_123',
              type: 'function',
              function: { name: 'search', arguments: '{"q":"test"}' }
            }
          ]
        }
      ]
    };

    const prompt = extractPrompt(request);
    expect(prompt).toContain('search');
    expect(prompt).toContain('{"q":"test"}');
  });
});

describe('extractResponse', () => {
  it('should extract response from choices', () => {
    const response = {
      id: 'chatcmpl-123',
      object: 'chat.completion',
      created: 1234567890,
      model: 'gpt-4',
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: 'Hello! How can I help?' },
          finish_reason: 'stop'
        }
      ]
    };

    const result = extractResponse(response);
    expect(result).toBe('Hello! How can I help?');
  });

  it('should handle empty choices', () => {
    const response = {
      id: 'chatcmpl-123',
      object: 'chat.completion',
      created: 1234567890,
      model: 'gpt-4',
      choices: []
    };

    expect(extractResponse(response)).toBe('');
  });

  it('should handle null content', () => {
    const response = {
      id: 'chatcmpl-123',
      object: 'chat.completion',
      created: 1234567890,
      model: 'gpt-4',
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: null },
          finish_reason: 'stop'
        }
      ]
    };

    expect(extractResponse(response)).toBe('');
  });

  it('should handle function call in response', () => {
    const response = {
      id: 'chatcmpl-123',
      object: 'chat.completion',
      created: 1234567890,
      model: 'gpt-4',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: null,
            function_call: { name: 'get_weather', arguments: '{"city":"NYC"}' }
          },
          finish_reason: 'function_call'
        }
      ]
    };

    const result = extractResponse(response);
    expect(result).toContain('get_weather');
  });
});

describe('extractModel', () => {
  it('preserves model case (audit record must reflect the exact model requested) and trims whitespace', () => {
    // Model IDs can be case-sensitive (e.g. meta-llama/Llama-3-70b) and must
    // be stored exactly as requested for accurate audit + model_gate matching.
    expect(extractModel({ model: 'GPT-4', messages: [] })).toBe('GPT-4');
    expect(extractModel({ model: '  gpt-4o  ', messages: [] })).toBe('gpt-4o');
  });

  it('should return unknown for missing model', () => {
    expect(extractModel({ messages: [] } as any)).toBe('unknown');
  });
});

describe('isStreamingRequest', () => {
  it('should detect streaming requests', () => {
    expect(isStreamingRequest({ model: 'gpt-4', messages: [], stream: true })).toBe(true);
    expect(isStreamingRequest({ model: 'gpt-4', messages: [], stream: false })).toBe(false);
    expect(isStreamingRequest({ model: 'gpt-4', messages: [] })).toBe(false);
  });
});

describe('extractOpenAIChat', () => {
  it('should extract full data from request and response', () => {
    const request = {
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hello' }]
    };
    const response = {
      id: 'chatcmpl-123',
      object: 'chat.completion',
      created: 1234567890,
      model: 'gpt-4',
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: 'Hi there!' },
          finish_reason: 'stop'
        }
      ]
    };

    const result = extractOpenAIChat(request, response);

    expect(result.prompt).toBe('user: Hello');
    expect(result.response).toBe('Hi there!');
    expect(result.model).toBe('gpt-4');
  });
});
