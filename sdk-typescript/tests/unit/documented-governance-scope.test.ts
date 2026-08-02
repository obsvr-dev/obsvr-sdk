import { jest } from '@jest/globals';
import { init, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { wrapOpenAICompatible } from '../../src/integrations/openai-compat';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

/**
 * The documented scope of the named compatibility wrappers, pinned against
 * behaviour.
 *
 * `wrapAzureOpenAI` / `wrapTogether` / `wrapOpenAICompatible`
 * consult a ONE-ENTRY path table and govern `chat.completions.create` alone,
 * while `obsvr.wrap()` governs seventeen paths on the same client. Every public
 * document now says so. Nothing enforced that, so the documents could drift back
 * to describing `obsvr.wrap()`'s coverage for a wrapper that does not have it —
 * which is the state they were in.
 *
 * This is a two-way pin, deliberately:
 *
 *   - a path the wrapper starts governing fails the "ungoverned" row, so
 *     widening coverage is a deliberate regrade with a documentation change
 *     rather than a silent improvement nobody wrote down;
 *   - a path it stops governing fails the "governed" row.
 *
 * It grades on EMITTED EVENTS, not on the path table, because a table entry is
 * the claim under test rather than the evidence for it.
 */

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

async function settle(): Promise<void> {
  for (let i = 0; i < 60 && sentEvents.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

const CHAT_RESPONSE = {
  id: 'x',
  model: 'm',
  choices: [{ message: { role: 'assistant', content: 'ok' }, finish_reason: 'stop' }],
  usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
};

/**
 * A client exposing both the governed path and three of the text-bearing paths
 * the documents now name as ungoverned through this wrapper.
 */
function client(seen: string[]) {
  const mk = (label: string) => async (_args: any) => {
    seen.push(label);
    return CHAT_RESPONSE;
  };
  return {
    chat: { completions: { create: mk('chat.completions.create'), parse: mk('chat.completions.parse') } },
    responses: { create: mk('responses.create'), parse: mk('responses.parse') },
    completions: { create: mk('completions.create') },
  };
}

const SSN = '123-45-6789';
const PII_POLICY = { rules: { ssn: 'block' as const } };

describe('documented governance scope: the named compatibility wrappers', () => {
  it('governs chat.completions.create — the one path the documents claim', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: PII_POLICY });
    const seen: string[] = [];
    const c = wrapOpenAICompatible(client(seen) as any, { provider: 'together', source: 'together_js' });
    await expect(
      c.chat.completions.create({
        model: 'm',
        messages: [{ role: 'user', content: `ssn ${SSN}` }],
      }),
    ).rejects.toThrow();
    // The gate fired: the provider was never reached, and there is a record.
    expect(seen).toEqual([]);
    await settle();
    expect(sentEvents.some((e) => e.action_taken === 'blocked')).toBe(true);
  });

  for (const path of ['chat.completions.parse', 'responses.create', 'responses.parse', 'completions.create']) {
    it(`does NOT govern ${path} — no gate and no event`, async () => {
      init({ api_key: 'k', ingest_url: 'https://x', pii_policy: PII_POLICY });
      const seen: string[] = [];
      const c = wrapOpenAICompatible(client(seen) as any, { provider: 'together', source: 'together_js' }) as any;
      const [a, b, d] = path.split('.');
      const fn = d ? c[a][b][d] : c[a][b];
      // The SAME payload that the governed path above refuses.
      await fn({ model: 'm', messages: [{ role: 'user', content: `ssn ${SSN}` }] });
      // Both halves matter: the provider WAS reached, and nothing was recorded.
      // Either alone would be a different (and less bad) finding.
      expect(seen).toEqual([path]);
      await new Promise((r) => setTimeout(r, 30));
      expect(sentEvents).toEqual([]);
    });
  }

  it('obsvr.wrap() DOES govern the same paths on the same client', async () => {
    // The control that makes every row above a statement about the WRAPPER
    // rather than about the client shape or the payload. Without it, "no event"
    // could mean "this SDK cannot see that path at all", which is not what the
    // documents now say and is not true.
    for (const path of ['chat.completions.parse', 'responses.create']) {
      _reset();
      _resetSender();
      sentEvents = [];
      init({ api_key: 'k', ingest_url: 'https://x', pii_policy: PII_POLICY });
      const seen: string[] = [];
      const c = wrap(client(seen)) as any;
      const [a, b, d] = path.split('.');
      const fn = d ? c[a][b][d] : c[a][b];
      await expect(
        fn({ model: 'm', messages: [{ role: 'user', content: `ssn ${SSN}` }] }),
      ).rejects.toThrow();
      expect(seen).toEqual([]);
      await settle();
      expect(sentEvents.some((e) => e.action_taken === 'blocked')).toBe(true);
    }
  });
});
