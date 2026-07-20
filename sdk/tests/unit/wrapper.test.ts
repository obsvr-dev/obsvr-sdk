import { jest } from '@jest/globals';
import { init, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

describe('wrap', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });

  it('should throw if init() not called', () => {
    const mockClient = { chat: { completions: { create: () => {} } } };
    expect(() => wrap(mockClient)).toThrow('Call init() before using');
  });

  it('should return unwrapped client when disabled', () => {
    init({ api_key: 'test', disabled: true });
    const mockClient = { chat: { completions: { create: () => {} } } };

    const wrapped = wrap(mockClient);
    expect(wrapped).toBe(mockClient);
  });

  it('should preserve non-function properties', () => {
    init({ api_key: 'test' });
    const mockClient = {
      version: '1.0.0',
      chat: { completions: { create: () => {} } }
    };

    const wrapped = wrap(mockClient);
    expect(wrapped.version).toBe('1.0.0');
  });

  it('should preserve method binding', () => {
    init({ api_key: 'test' });

    class MockClient {
      value = 42;
      getValue() { return this.value; }
    }

    const client = new MockClient();
    const wrapped = wrap(client as any);

    // Method should still have access to `this`
    expect(wrapped.getValue()).toBe(42);
  });

  it('should not double-wrap clients', () => {
    init({ api_key: 'test' });
    const mockClient = { chat: { completions: { create: () => {} } } };

    const wrapped1 = wrap(mockClient);
    const wrapped2 = wrap(wrapped1);

    // Should return the same wrapped instance
    expect(wrapped2).toBe(wrapped1);
  });

  it('should pass through unknown methods unchanged', () => {
    init({ api_key: 'test' });

    let calledWith: unknown[] = [];
    const mockClient = {
      customMethod: (...args: unknown[]) => {
        calledWith = args;
        return 'result';
      },
      chat: { completions: { create: () => {} } }
    };

    const wrapped = wrap(mockClient);
    const result = wrapped.customMethod('arg1', 'arg2');

    expect(calledWith).toEqual(['arg1', 'arg2']);
    expect(result).toBe('result');
  });

  it('should handle nested property access', () => {
    init({ api_key: 'test' });

    const mockClient = {
      chat: {
        completions: {
          create: () => Promise.resolve({
            id: 'test',
            choices: [{ message: { content: 'Hello!' } }]
          })
        }
      }
    };

    const wrapped = wrap(mockClient);

    // Should be able to access nested properties
    expect(wrapped.chat).toBeDefined();
    expect(wrapped.chat.completions).toBeDefined();
    expect(typeof wrapped.chat.completions.create).toBe('function');
  });
});

describe('wrap with auditable method', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });

  it('should call original method and return response', async () => {
    init({ api_key: 'test', sample_rate: 0 }); // Disable sampling for this test

    const mockResponse = {
      id: 'chatcmpl-123',
      choices: [{ message: { content: 'Hello!' } }]
    };

    let receivedArgs: unknown[] = [];
    const mockClient = {
      chat: {
        completions: {
          create: (...args: unknown[]) => {
            receivedArgs = args;
            return Promise.resolve(mockResponse);
          }
        }
      }
    };

    const wrapped = wrap(mockClient);

    const result = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }]
    });

    expect(result).toEqual(mockResponse);
    expect(receivedArgs[0]).toEqual({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }]
    });
  });

  it('should filter audit fields from request', async () => {
    init({ api_key: 'test', sample_rate: 0 }); // Disable sampling

    let receivedArgs: unknown[] = [];
    const mockClient = {
      chat: {
        completions: {
          create: (...args: unknown[]) => {
            receivedArgs = args;
            return Promise.resolve({
              id: 'chatcmpl-123',
              choices: [{ message: { content: 'Hello!' } }]
            });
          }
        }
      }
    };

    const wrapped = wrap(mockClient);

    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }],
      request_id: 'req_123',
      region: 'us-east-1',
      source: 'test',
      metadata: { user_id: 'user_123' }
    } as any);

    // Audit fields should be stripped
    expect(receivedArgs[0]).toEqual({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }]
    });
  });

  it('should re-throw LLM errors', async () => {
    init({ api_key: 'test', sample_rate: 0 });

    const mockClient = {
      chat: {
        completions: {
          create: (_args: any) => Promise.reject(new Error('OpenAI API error'))
        }
      }
    };

    const wrapped = wrap(mockClient);

    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'Hi' }]
      })
    ).rejects.toThrow('OpenAI API error');
  });

  it('emits a signed audit event when an OpenAI-family call FAILS (audit-on-error)', async () => {
    // Regression: the OpenAI branch of buildAuditEvent called the response
    // extractor UNGUARDED, so on a failed call (response=null) it threw inside
    // the error path's try/catch and the forensic record was silently dropped —
    // the exact events an auditor most needs. The anthropic/google/responses
    // branches already guarded null; this asserts the OpenAI family now does too.
    const sentEvents: any[] = [];
    (global as any).fetch = async (_url: any, opts: any) => {
      const body = JSON.parse(opts.body);
      Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
      return { ok: true, status: 200, json: async () => ({}) };
    };
    init({ api_key: 'test', sample_rate: 1 });

    const mockClient = {
      chat: {
        completions: {
          create: (_args: any) => Promise.reject(new Error('OpenAI API error')),
        },
      },
    };
    const wrapped = wrap(mockClient);

    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'Hi' }],
      }),
    ).rejects.toThrow('OpenAI API error');

    // The failed call must still produce exactly one signed forensic record.
    for (let i = 0; i < 100 && sentEvents.length < 1; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(sentEvents.length).toBe(1);
    const ev = sentEvents[0];
    expect(ev.success).toBe(false);
    expect(ev.status_code).toBe(500);
    expect(ev.error_type).toBeTruthy();
    expect(ev.response).toBe('');
    expect(ev.model).toBe('gpt-4');
    // Still a fully-signed chain event (evidence, not a bare log line).
    expect(typeof ev.sdk_sig).toBe('string');
    expect(ev.sdk_sig).toHaveLength(64);
    expect(ev.seq_no).toBeGreaterThanOrEqual(1);

    delete (global as any).fetch;
  });

  it('runs enforcement even when the call is sampled OUT (sampling gates audit, not enforcement)', async () => {
    // Regression: sampling must never disable the compliance boundary. Before
    // the fix, sample_rate:0 returned the raw provider call before PII/policy
    // ran, so a fraction of traffic was governed by nobody.
    const sentEvents: any[] = [];
    (global as any).fetch = async (_url: any, opts: any) => {
      const body = JSON.parse(opts.body);
      Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
      return { ok: true, status: 200, json: async () => ({}) };
    };
    init({ api_key: 'test', ingest_url: 'https://x', sample_rate: 0, pii_policy: {} });

    const create = jest.fn(async (_args: any) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } });

    // ssn is a block-severity built-in type; the call MUST be blocked at sample_rate:0.
    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'my ssn is 123-45-6789' }],
      }),
    ).rejects.toThrow(/blocked by policy/i);
    // Provider was never contacted (blocked pre-call)...
    expect(create).not.toHaveBeenCalled();
    // ...and a blocked_call forensic event is ALWAYS emitted, even sampled out.
    for (let i = 0; i < 100 && sentEvents.length < 1; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(sentEvents.length).toBe(1);
    expect(sentEvents[0].event_type).toBe('blocked_call');

    delete (global as any).fetch;
  });

  it('does not emit an allowed-call audit event when sampled out, but still returns', async () => {
    const sentEvents: any[] = [];
    (global as any).fetch = async (_url: any, opts: any) => {
      const body = JSON.parse(opts.body);
      Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
      return { ok: true, status: 200, json: async () => ({}) };
    };
    init({ api_key: 'test', ingest_url: 'https://x', sample_rate: 0 });

    const create = jest.fn(async (_args: any) => ({ choices: [{ message: { content: 'hello' } }], model: 'gpt-4' }));
    const wrapped = wrap({ chat: { completions: { create } } });

    const res: any = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'hi' }],
    });
    // The call goes through and returns normally...
    expect(res.choices[0].message.content).toBe('hello');
    expect(create).toHaveBeenCalledTimes(1);
    // ...but no allowed-call audit event is emitted at sample_rate:0.
    await new Promise((r) => setTimeout(r, 30));
    expect(sentEvents.length).toBe(0);

    delete (global as any).fetch;
  });

  it('hook redact scrubs all provider shapes, not just .messages', async () => {
    // Regression: a hook `redact` verdict cleared only OpenAI's `.messages`, so
    // an Anthropic `system` / Gemini `contents` / Responses `input` / string
    // prompt was sent to the provider UNREDACTED while the event claimed
    // "redacted" — a false record and a real leak.
    init({
      api_key: 'test',
      ingest_url: 'https://x',
      sample_rate: 1,
      on_pre_call: () => ({ decision: 'redact' }),
    });
    let received: any;
    const create = jest.fn(async (args: any) => {
      received = args;
      return { choices: [{ message: { content: 'ok' } }] };
    });
    const wrapped = wrap({ chat: { completions: { create } } });

    await wrapped.chat.completions.create({
      model: 'gpt-4',
      system: 'caller SSN is 123-45-6789', // Anthropic-shaped field
      messages: [{ role: 'user', content: 'my email is bob@example.com' }],
    } as any);

    // The provider must receive PII scrubbed from EVERY shape, not just messages.
    expect(received.system).not.toContain('123-45-6789');
    expect(JSON.stringify(received.messages)).not.toContain('bob@example.com');
  });

  it('should skip streaming requests by default', async () => {
    init({ api_key: 'test', sample_rate: 1, streaming_mode: 'skip' });

    const mockStream = (async function* () {
      yield { choices: [{ delta: { content: 'Hello' } }] };
    })();

    const mockClient = {
      chat: {
        completions: {
          create: (_args: any) => Promise.resolve(mockStream)
        }
      }
    };

    const wrapped = wrap(mockClient);

    const result = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }],
      stream: true
    } as any);

    // Should return the stream unchanged
    expect(result).toBe(mockStream);
  });
});

describe('wrap provenance_source labeling', () => {
  let sentEvents: any[] = [];

  beforeEach(() => {
    _reset();
    _resetSender();
    sentEvents = [];
    (global as any).fetch = async (_url: any, opts: any) => {
      sentEvents.push(JSON.parse(opts.body));
      return { ok: true, status: 200 };
    };
  });

  async function waitForEvents(n = 1): Promise<void> {
    for (let i = 0; i < 100 && sentEvents.length < n; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  it('labels a native provider response.model as provider_response', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const mockClient = {
      chat: {
        completions: {
          create: (_args: any) =>
            Promise.resolve({
              id: 'chatcmpl-1',
              model: 'gpt-4o-2024-08-06',
              choices: [{ message: { content: 'Hello!' } }],
              usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
            }),
        },
      },
    };

    const wrapped = wrap(mockClient);
    await wrapped.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hi' }],
    } as any);

    await waitForEvents(1);
    expect(sentEvents[0].model_resolved).toBe('gpt-4o-2024-08-06');
    // Proxy read the native provider's response.model directly → highest trust.
    expect(sentEvents[0].provenance_source).toBe('provider_response');
  });

  it('omits provenance_source when the response carries no resolved model', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const mockClient = {
      chat: {
        completions: {
          create: (_args: any) =>
            Promise.resolve({
              id: 'chatcmpl-2',
              choices: [{ message: { content: 'Hello!' } }],
            }),
        },
      },
    };

    const wrapped = wrap(mockClient);
    await wrapped.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hi' }],
    } as any);

    await waitForEvents(1);
    // No resolved model → no source label (present iff model_resolved).
    expect(sentEvents[0].model_resolved).toBeUndefined();
    expect(sentEvents[0].provenance_source).toBeUndefined();
  });
});
