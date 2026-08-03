import { init, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { useSubject } from '../../src/proxy/subject';

/**
 * The wrap path's SIGNED identity resolves from the ambient useSubject()
 * scope. The integration event builder and the wrap path's session-taint key
 * already resolved the ambient subject; the wrap path's own audit events
 * (completed AND blocked) resolved only per-call audit fields and wrap-time
 * options, so a caller attributing per request with useSubject() got
 * attributed events on every surface except the proxy's. Pins the fallback
 * and its precedence: audit fields > wrap-time options > ambient subject.
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

const waitFor = async (n: number) => {
  for (let i = 0; i < 200 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
};

const fakeClient = () => ({
  chat: {
    completions: {
      create: async (_args: any) => ({
        id: 'chatcmpl-1',
        choices: [{ message: { content: 'Hello!' } }],
      }),
    },
  },
});

describe('wrap(): ambient subject on the signed event identity', () => {
  it('a completed call inside useSubject() carries the ambient user_id', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const wrapped = wrap(fakeClient());

    await useSubject('user:alice', async () => {
      await wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'Hi' }],
      });
    });

    await waitFor(1);
    expect(sentEvents.length).toBe(1);
    expect(sentEvents[0].user_id).toBe('alice');
  });

  it('a BLOCKED call inside useSubject() carries the ambient user_id', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: [
        {
          id: 'kw1', name: 'no magic word', enabled: true,
          action: 'block', type: 'keyword', conditions: { keywords: ['xyzzy'] },
        } as any,
      ],
    });
    const wrapped = wrap(fakeClient());

    let thrown: any;
    await useSubject('user:mallory', async () => {
      try {
        await wrapped.chat.completions.create({
          model: 'gpt-4',
          messages: [{ role: 'user', content: 'please say xyzzy' }],
        });
      } catch (e) {
        thrown = e;
      }
    });

    expect(thrown).toBeDefined();
    await waitFor(1);
    expect(sentEvents.length).toBe(1);
    expect(sentEvents[0].event_type).toBe('blocked_call');
    // The record of mallory being refused says it was mallory.
    expect(sentEvents[0].user_id).toBe('mallory');
  });

  it('wrap-time options win over the ambient subject', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const wrapped = wrap(fakeClient(), { user_id: 'carol' });

    await useSubject('user:alice', async () => {
      await wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'Hi' }],
      });
    });

    await waitFor(1);
    expect(sentEvents.length).toBe(1);
    expect(sentEvents[0].user_id).toBe('carol');
  });

  it('outside any scope the event carries the wrap-time identity, or none', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const wrapped = wrap(fakeClient());

    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }],
    });

    await waitFor(1);
    expect(sentEvents.length).toBe(1);
    expect(sentEvents[0].user_id).toBeUndefined();
  });
});
