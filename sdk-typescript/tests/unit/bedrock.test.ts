import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrapBedrock } from '../../src/integrations/bedrock';

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

// Mock AWS SDK command classes — detection is by constructor.name
class ConverseCommand {
  constructor(public input: any) {}
}
class InvokeModelCommand {
  constructor(public input: any) {}
}
class ConverseStreamCommand {
  constructor(public input: any) {}
}
class UnknownCommand {
  constructor(public input: any) {}
}

describe('wrapBedrock — Converse', () => {
  it('emits an ordinary monitor-mode call at sample_rate 0', async () => {
    init({ api_key: 'test', sample_rate: 0, enforcement_mode: 'monitor' });
    const client = wrapBedrock({
      send: async (_command: unknown) => ({ output: { message: { content: [{ text: 'ok' }] } } }),
    });

    await client.send(new ConverseCommand({
      modelId: 'm',
      messages: [{ role: 'user', content: [{ text: 'hello' }] }],
    }));

    await waitForEvents(1);
    expect(sentEvents[0]).toMatchObject({ action_taken: 'allowed', response: 'ok' });
  });

  it('emits a monitor-converted verdict at sample_rate 0', async () => {
    init({
      api_key: 'test',
      sample_rate: 0,
      enforcement_mode: 'monitor',
      policy_rules: [{
        id: 'block-secret',
        name: 'block secret',
        enabled: true,
        action: 'block',
        type: 'keyword',
        conditions: { keywords: ['secret'] },
      }],
    });
    let called = false;
    const client = wrapBedrock({
      send: async (_command: unknown) => {
        called = true;
        return { output: { message: { content: [{ text: 'ok' }] } } };
      },
    });

    await client.send(new ConverseCommand({
      modelId: 'm',
      messages: [{ role: 'user', content: [{ text: 'a secret request' }] }],
    }));

    expect(called).toBe(true);
    await waitForEvents(1);
    expect(sentEvents[0]).toMatchObject({
      action_taken: 'allowed',
      shadow_outcome: { would: 'block', rule_id: 'block-secret' },
    });
  });

  it('extracts prompt, response and usage', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const client = wrapBedrock({
      send: async (_cmd: any) => ({
        output: { message: { role: 'assistant', content: [{ text: 'Hi there' }] } },
        usage: { inputTokens: 10, outputTokens: 5 },
      }),
    });

    const res: any = await client.send(
      new ConverseCommand({
        modelId: 'anthropic.claude-3-sonnet',
        system: [{ text: 'be nice' }],
        messages: [{ role: 'user', content: [{ text: 'Hello' }] }],
      }),
    );

    expect(res.output.message.content[0].text).toBe('Hi there');
    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.provider).toBe('bedrock');
    expect(e.operation).toBe('bedrock.converse');
    expect(e.model).toBe('anthropic.claude-3-sonnet');
    expect(e.prompt).toContain('system: be nice');
    expect(e.prompt).toContain('user: Hello');
    expect(e.response).toBe('Hi there');
    expect(e.input_tokens).toBe(10);
    expect(e.output_tokens).toBe(5);
    expect(e.total_tokens).toBe(15);
  });

  it('blocks Converse calls containing an SSN', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let called = false;
    const client = wrapBedrock({
      send: async (_cmd: any) => {
        called = true;
        return {};
      },
    });

    await expect(
      client.send(
        new ConverseCommand({
          modelId: 'anthropic.claude-3-sonnet',
          messages: [
            { role: 'user', content: [{ text: 'my ssn is 123-45-6789' }] },
          ],
        }),
      ),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(called).toBe(false);
    await waitForEvents(1);
    expect(sentEvents[0].event_type).toBe('blocked_call');
    expect(sentEvents[0].status_code).toBe(403);
    expect(sentEvents[0].prompt).toContain('[REDACTED_SSN]');
  });

  it('redacts email in Converse messages before sending', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let sentInput: any = null;
    const client = wrapBedrock({
      send: async (cmd: any) => {
        sentInput = cmd.input;
        return { output: { message: { content: [{ text: 'ok' }] } } };
      },
    });

    await client.send(
      new ConverseCommand({
        modelId: 'm',
        messages: [
          { role: 'user', content: [{ text: 'mail john@example.com' }] },
        ],
      }),
    );

    expect(sentInput.messages[0].content[0].text).toContain('[REDACTED_EMAIL]');
    await waitForEvents(1);
    expect(sentEvents[0].action_taken).toBe('redacted');
  });

  it('blocks PII nested in Converse tool results before sending', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    let called = false;
    const client = wrapBedrock({
      send: async (_command: unknown) => {
        called = true;
        return {};
      },
    });

    await expect(
      client.send(new ConverseCommand({
        modelId: 'm',
        messages: [{
          role: 'user',
          content: [{
            toolResult: {
              toolUseId: 'tool-1',
              content: [{ text: 'SSN 123-45-6789' }],
            },
          }],
        }],
      })),
    ).rejects.toThrow('[obsvr] Request blocked by policy');
    expect(called).toBe(false);
  });

  it('redacts PII nested in Converse tool results before sending', async () => {
    init({ api_key: 'test', pii_policy: { rules: { email: 'redact' } } });
    let sentInput: any;
    const client = wrapBedrock({
      send: async (command: any) => {
        sentInput = command.input;
        return { output: { message: { content: [{ text: 'ok' }] } } };
      },
    });

    await client.send(new ConverseCommand({
      modelId: 'm',
      messages: [{
        role: 'user',
        content: [{
          toolResult: {
            toolUseId: 'tool-1',
            content: [{ text: 'Contact secret@example.com' }],
          },
        }],
      }],
    }));

    const wire = JSON.stringify(sentInput);
    expect(wire).not.toContain('secret@example.com');
    expect(wire).toContain('[REDACTED_EMAIL]');
  });

  it('blocks PII in the system prompt when the last user turn is clean', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    let called = false;
    const client = wrapBedrock({
      send: async (_command: unknown) => {
        called = true;
        return {};
      },
    });

    await expect(client.send(new ConverseCommand({
      modelId: 'm',
      system: [{ text: 'SSN 123-45-6789' }],
      messages: [{ role: 'user', content: [{ text: 'safe request' }] }],
    }))).rejects.toThrow('[obsvr] Request blocked by policy');
    expect(called).toBe(false);
  });
});

describe('wrapBedrock — InvokeModel', () => {
  it('decodes Uint8Array body and response (anthropic format)', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const responseBody = new TextEncoder().encode(
      JSON.stringify({
        content: [{ type: 'text', text: 'response text' }],
        usage: { input_tokens: 3, output_tokens: 4 },
      }),
    );
    const client = wrapBedrock({
      send: async (_cmd: any) => ({ body: responseBody }),
    });

    await client.send(
      new InvokeModelCommand({
        modelId: 'anthropic.claude-3-haiku',
        body: new TextEncoder().encode(
          JSON.stringify({
            system: 'sys prompt',
            messages: [{ role: 'user', content: 'Hello invoke' }],
          }),
        ),
      }),
    );

    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.operation).toBe('bedrock.invoke_model');
    expect(e.prompt).toContain('system: sys prompt');
    expect(e.prompt).toContain('user: Hello invoke');
    expect(e.response).toBe('response text');
    expect(e.input_tokens).toBe(3);
    expect(e.output_tokens).toBe(4);
  });

  it('redacts and re-encodes the body', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let sentBody: any = null;
    const client = wrapBedrock({
      send: async (cmd: any) => {
        sentBody = cmd.input.body;
        return { body: JSON.stringify({ generation: 'ok' }) };
      },
    });

    await client.send(
      new InvokeModelCommand({
        modelId: 'meta.llama3',
        body: JSON.stringify({ prompt: 'email john@example.com' }),
      }),
    );

    // String body preserved as string, redacted
    expect(typeof sentBody).toBe('string');
    expect(JSON.parse(sentBody).prompt).toContain('[REDACTED_EMAIL]');
    await waitForEvents(1);
    expect(sentEvents[0].response).toBe('ok');
  });

  it('handles Titan format', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const client = wrapBedrock({
      send: async (_cmd: any) => ({
        body: JSON.stringify({
          inputTextTokenCount: 6,
          results: [{ outputText: 'titan out', tokenCount: 2 }],
        }),
      }),
    });

    await client.send(
      new InvokeModelCommand({
        modelId: 'amazon.titan-text',
        body: JSON.stringify({ inputText: 'titan in' }),
      }),
    );

    await waitForEvents(1);
    expect(sentEvents[0].prompt).toBe('titan in');
    expect(sentEvents[0].response).toBe('titan out');
    expect(sentEvents[0].input_tokens).toBe(6);
  });
});

describe('wrapBedrock — streaming', () => {
  it('wraps ConverseStream and audits accumulated text', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const stream = (async function* () {
      yield { contentBlockDelta: { delta: { text: 'Hel' } } };
      yield { contentBlockDelta: { delta: { text: 'lo' } } };
      yield { metadata: { usage: { inputTokens: 4, outputTokens: 2 } } };
    })();
    const client = wrapBedrock({
      send: async (_cmd: any) => ({ stream }),
    });

    const res: any = await client.send(
      new ConverseStreamCommand({
        modelId: 'm',
        messages: [{ role: 'user', content: [{ text: 'Hi' }] }],
      }),
    );

    const events: unknown[] = [];
    for await (const ev of res.stream) events.push(ev);
    expect(events).toHaveLength(3);

    await waitForEvents(1);
    expect(sentEvents[0].response).toBe('Hello');
    expect(sentEvents[0].input_tokens).toBe(4);
    expect(sentEvents[0].operation).toBe('bedrock.converse_stream');
  });
});

describe('wrapBedrock — passthrough', () => {
  it('passes through unknown commands without auditing', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const client = wrapBedrock({
      send: async (_cmd: any) => ({ ok: true }),
    });
    const res: any = await client.send(new UnknownCommand({}));
    expect(res.ok).toBe(true);
    await new Promise((r) => setTimeout(r, 20));
    expect(sentEvents).toHaveLength(0);
  });

  it('does not double-wrap', () => {
    init({ api_key: 'test' });
    const client = { send: async () => ({}) };
    const w1 = wrapBedrock(client);
    const w2 = wrapBedrock(w1);
    expect(w2).toBe(w1);
  });
});
