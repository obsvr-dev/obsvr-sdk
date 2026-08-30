import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrapVertexAI } from '../../src/integrations/vertex';

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

const GEMINI_RESPONSE = {
  candidates: [
    {
      content: { parts: [{ text: 'Hello from Gemini!' }], role: 'model' },
      finishReason: 'STOP',
    },
  ],
  usageMetadata: {
    promptTokenCount: 7,
    candidatesTokenCount: 3,
    totalTokenCount: 10,
  },
};

describe('wrapVertexAI', () => {
  it('unwraps .response and extracts content + usage', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const model = wrapVertexAI({
      model: 'models/gemini-1.5-pro',
      generateContent: async (_req: any) => ({ response: GEMINI_RESPONSE }),
    });

    const result: any = await model.generateContent({
      contents: [{ role: 'user', parts: [{ text: 'Hi Gemini' }] }],
    });

    expect(result.response).toEqual(GEMINI_RESPONSE);
    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.provider).toBe('vertex_ai');
    expect(e.source).toBe('vertex_ai');
    expect(e.model).toBe('gemini-1.5-pro'); // "models/" prefix stripped
    expect(e.prompt).toContain('user: Hi Gemini');
    expect(e.response).toBe('Hello from Gemini!');
    expect(e.input_tokens).toBe(7);
    expect(e.output_tokens).toBe(3);
    expect(e.total_tokens).toBe(10);
  });

  it('captures the resolved model from response.modelVersion', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const model = wrapVertexAI({
      model: 'models/gemini-1.5-pro',
      generateContent: async (_req: any) => ({
        response: { ...GEMINI_RESPONSE, modelVersion: 'gemini-1.5-pro-002' },
      }),
    });

    await model.generateContent({
      contents: [{ role: 'user', parts: [{ text: 'Hi Gemini' }] }],
    });

    await waitForEvents(1);
    expect(sentEvents[0].model).toBe('gemini-1.5-pro');
    expect(sentEvents[0].model_resolved).toBe('gemini-1.5-pro-002');
    // Read directly from the native Vertex response → highest-trust tier.
    expect(sentEvents[0].provenance_source).toBe('provider_response');
  });

  it('handles string requests', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const model = wrapVertexAI({
      model: 'gemini-1.5-flash',
      generateContent: async (_req: any) => ({ response: GEMINI_RESPONSE }),
    });

    await model.generateContent('plain string prompt');
    await waitForEvents(1);
    expect(sentEvents[0].prompt).toBe('plain string prompt');
  });

  it('blocks calls containing an SSN', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let called = false;
    const model = wrapVertexAI({
      model: 'gemini-1.5-pro',
      generateContent: async (_req: any) => {
        called = true;
        return { response: GEMINI_RESPONSE };
      },
    });

    await expect(
      model.generateContent({
        contents: [
          { role: 'user', parts: [{ text: 'my ssn is 123-45-6789' }] },
        ],
      }),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(called).toBe(false);
    await waitForEvents(1);
    expect(sentEvents[0].event_type).toBe('blocked_call');
    expect(sentEvents[0].status_code).toBe(403);
  });

  it('blocks system instructions before a clean user request reaches Vertex', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    let providerCalls = 0;
    const model = wrapVertexAI({
      model: 'gemini-1.5-pro',
      generateContent: async (_req: any) => {
        providerCalls += 1;
        return { response: GEMINI_RESPONSE };
      },
    });

    await expect(model.generateContent({
      systemInstruction: { parts: [{ text: 'SSN 123-45-6789' }] },
      contents: [{ role: 'user', parts: [{ text: 'safe request' }] }],
    })).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(providerCalls).toBe(0);
  });

  it('blocks model-configured system instructions before a clean request', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    let providerCalls = 0;
    const model = wrapVertexAI({
      model: 'gemini-1.5-pro',
      systemInstruction: { role: 'system', parts: [{ text: 'SSN 123-45-6789' }] },
      generateContent: async (_req: any) => {
        providerCalls += 1;
        return { response: GEMINI_RESPONSE };
      },
    });

    await expect(model.generateContent({
      contents: [{ role: 'user', parts: [{ text: 'safe request' }] }],
    })).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(providerCalls).toBe(0);
  });

  it('blocks sensitive earlier turns before a clean final user request', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    let providerCalls = 0;
    const model = wrapVertexAI({
      model: 'gemini-1.5-pro',
      generateContent: async (_req: any) => {
        providerCalls += 1;
        return { response: GEMINI_RESPONSE };
      },
    });

    await expect(model.generateContent({
      contents: [
        { role: 'user', parts: [{ text: 'SSN 123-45-6789' }] },
        { role: 'model', parts: [{ text: 'noted' }] },
        { role: 'user', parts: [{ text: 'safe request' }] },
      ],
    })).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(providerCalls).toBe(0);
  });

  it('redacts string requests before sending', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let sentReq: any = null;
    const model = wrapVertexAI({
      model: 'gemini-1.5-pro',
      generateContent: async (req: any) => {
        sentReq = req;
        return { response: GEMINI_RESPONSE };
      },
    });

    await model.generateContent('email john@example.com please');
    expect(sentReq).toContain('[REDACTED_EMAIL]');
  });

  it('redacts configured system instructions without mutating caller input', async () => {
    init({ api_key: 'test', pii_policy: { rules: { email: 'redact' } } });
    let sentReq: any = null;
    const model = wrapVertexAI({
      model: 'gemini-1.5-pro',
      generateContent: async (req: any) => {
        sentReq = req;
        return { response: GEMINI_RESPONSE };
      },
    });
    const request = {
      contents: [{ role: 'user', parts: [{ text: 'safe request' }] }],
      config: { systemInstruction: { parts: [{ text: 'email secret@example.com' }] } },
    };

    await model.generateContent(request);

    expect(sentReq.config.systemInstruction.parts[0].text).toContain('[REDACTED_EMAIL]');
    expect(request.config.systemInstruction.parts[0].text).toBe('email secret@example.com');
  });

  it('fails closed when model-configured system instructions require redaction', async () => {
    init({ api_key: 'test', pii_policy: { rules: { email: 'redact' } } });
    let providerCalls = 0;
    const model = wrapVertexAI({
      model: 'gemini-1.5-pro',
      systemInstruction: { role: 'system', parts: [{ text: 'email system@example.com' }] },
      generateContent: async (_req: any) => {
        providerCalls += 1;
        return { response: GEMINI_RESPONSE };
      },
    });

    await expect(model.generateContent({
      contents: [{ role: 'user', parts: [{ text: 'safe request' }] }],
    })).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(providerCalls).toBe(0);
    await waitForEvents(1);
    expect(sentEvents[0].action_taken).toBe('blocked');
    expect(sentEvents[0].redacted_types).toEqual([]);
  });

  it('audits monitor-mode streams via the aggregated response even when configured to skip', async () => {
    init({
      api_key: 'test',
      sample_rate: 0,
      enforcement_mode: 'monitor',
      streaming_mode: 'skip',
    });
    const model = wrapVertexAI({
      model: 'gemini-1.5-pro',
      generateContentStream: async (_req: any) => ({
        stream: (async function* () {
          yield { candidates: [{ content: { parts: [{ text: 'He' }] } }] };
        })(),
        response: Promise.resolve(GEMINI_RESPONSE),
      }),
    });

    const result: any = await model.generateContentStream({
      contents: [{ role: 'user', parts: [{ text: 'Hi' }] }],
    });

    for await (const _chunk of result.stream) {
      // consume
    }
    await waitForEvents(1);
    expect(sentEvents[0].operation).toBe('generateContentStream');
    expect(sentEvents[0].response).toBe('Hello from Gemini!');
  });

  it('enforces a pre-call block before an enforce-mode skipped stream opens', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      streaming_mode: 'skip',
      pii_policy: { rules: { ssn: 'block' } },
    });
    let providerCalls = 0;
    const model = wrapVertexAI({
      model: 'gemini-1.5-pro',
      generateContentStream: async (_req: any) => {
        providerCalls += 1;
        return {
          stream: (async function* () {})(),
          response: Promise.resolve(GEMINI_RESPONSE),
        };
      },
    });

    await expect(
      model.generateContentStream({
        contents: [
          { role: 'user', parts: [{ text: 'my ssn is 123-45-6789' }] },
        ],
      }),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(providerCalls).toBe(0);
    await waitForEvents(1);
    expect(sentEvents[0].event_type).toBe('blocked_call');
  });

  it('emits failure events on error', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const model = wrapVertexAI({
      model: 'gemini-1.5-pro',
      generateContent: async (_req: any) => {
        throw new Error('vertex unavailable');
      },
    });

    await expect(
      model.generateContent({
        contents: [{ role: 'user', parts: [{ text: 'Hi' }] }],
      }),
    ).rejects.toThrow('vertex unavailable');

    await waitForEvents(1);
    expect(sentEvents[0].success).toBe(false);
  });
});
