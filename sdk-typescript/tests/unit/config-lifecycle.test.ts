/**
 * Config lifecycle: a re-init must reach clients wrapped before it, and a poll
 * must not delete what init() declared.
 *
 * Both halves have the same root cause and it is worth stating once, because
 * the asymmetry is what made the pair confusing: `init()` REPLACES
 * `state.config` while a `/policies` poll MUTATES that same object in place. A
 * context holding the object it was handed at wrap time therefore saw every
 * poll and no re-init — so a policy change arriving over the network reached an
 * already-wrapped client and the same change made in code did not.
 *
 * Measured before this was pinned, in both directions: a client wrapped under a
 * permissive policy kept reaching the provider after a stricter `init()`, and a
 * client wrapped under a strict one kept refusing on a rule a later `init()` had
 * removed. A freshly wrapped client honoured the new policy in both cases,
 * which is the control that makes those rows about the snapshot rather than
 * about a dead rule.
 */
import { init, getConfig, updatePolicyRules, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import type { PolicyRule } from '../../src/proxy/types';

const rule = (id: string, keyword: string): PolicyRule => ({
  id,
  name: id,
  enabled: true,
  action: 'block',
  type: 'keyword',
  conditions: { keywords: [keyword] },
}) as PolicyRule;

/** A minimal client with the shape the wrapper audits. */
function fakeClient() {
  const seen: unknown[] = [];
  return {
    seen,
    chat: {
      completions: {
        create: async (args: unknown) => {
          seen.push(args);
          return { choices: [{ message: { content: 'ok' } }], model: 'm' };
        },
      },
    },
  };
}

beforeEach(() => {
  _reset();
});
afterEach(() => {
  _reset();
});

describe('re-init reaches already-wrapped clients', () => {
  it('applies a rule added by a later init() to a client wrapped before it', async () => {
    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [] });
    const client = fakeClient();
    const wrapped = wrap(client);

    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [rule('added', 'zzz-secret')] });

    await expect(
      wrapped.chat.completions.create({
        model: 'm',
        messages: [{ role: 'user', content: 'please leak zzz-secret' }],
      }),
    ).rejects.toThrow();
    // The gate has to have stopped it before the provider, not after.
    expect(client.seen).toHaveLength(0);
  });

  it('stops applying a rule a later init() removed', async () => {
    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [rule('removed', 'zzz-secret')] });
    const client = fakeClient();
    const wrapped = wrap(client);

    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [] });

    await wrapped.chat.completions.create({
      model: 'm',
      messages: [{ role: 'user', content: 'please leak zzz-secret' }],
    });
    expect(client.seen).toHaveLength(1);
  });

  it('sees a rule added deeper than the first property step', async () => {
    // The context is rebuilt at every step of the proxy traversal, so a fix
    // that made only the root read live would pass the cases above and fail
    // here. `chat.completions.create` is three steps down.
    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [] });
    const client = fakeClient();
    const wrapped = wrap(client);
    const deep = wrapped.chat.completions; // traversed BEFORE the policy changes

    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [rule('added', 'zzz-secret')] });

    await expect(
      deep.create({ model: 'm', messages: [{ role: 'user', content: 'zzz-secret' }] }),
    ).rejects.toThrow();
    expect(client.seen).toHaveLength(0);
  });
});

describe('a poll owns the server set and not the local one', () => {
  it('keeps locally declared rules when the server returns an empty ruleset', () => {
    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [rule('local', 'zzz-local')] });
    updatePolicyRules([]);
    expect((getConfig().policyRules ?? []).map((r) => r.id)).toEqual(['local']);
  });

  it('honours an empty server set for rules the server had previously pushed', () => {
    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [rule('local', 'zzz-local')] });
    updatePolicyRules([rule('server', 'zzz-server')]);
    expect((getConfig().policyRules ?? []).map((r) => r.id)).toEqual(['local', 'server']);

    // An empty ruleset is a VALID server state — the server's own rules go.
    updatePolicyRules([]);
    expect((getConfig().policyRules ?? []).map((r) => r.id)).toEqual(['local']);
  });

  it('refuses to let a server rule take over a locally declared id', () => {
    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [rule('shared', 'zzz-local')] });
    updatePolicyRules([{ ...rule('shared', 'zzz-local'), enabled: false } as PolicyRule]);

    const rules = getConfig().policyRules ?? [];
    expect(rules.map((r) => r.id)).toEqual(['shared']);
    // Disabling a rule by re-sending its id is the same disarming edit wearing
    // a matching id, and it is the shape a deployment with no pinned policy key
    // has no other defence against.
    expect(rules[0].enabled).toBe(true);
  });

  it('lets a later init() replace the local set, because that is the caller speaking', () => {
    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [rule('first', 'zzz-a')] });
    updatePolicyRules([rule('server', 'zzz-server')]);
    init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9', policyRules: [rule('second', 'zzz-b')] });

    // The server set does not survive a re-init either: init() rebuilds the
    // config, and the next poll re-delivers whatever the server still has.
    expect((getConfig().policyRules ?? []).map((r) => r.id)).toEqual(['second']);
  });
});
