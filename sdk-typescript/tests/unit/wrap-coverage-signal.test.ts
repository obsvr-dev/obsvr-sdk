/**
 * `wrap()` says what it governed.
 *
 * A client whose shape carries no auditable method used to come back as an
 * ordinary governance proxy: every call forwarded through, no policy, no event,
 * and nothing said. `init()` already refuses to accept a config key it will not
 * read without saying so — a configuration that is ACCEPTED is a configuration
 * that is IN FORCE — and this is the same acceptance one layer over.
 *
 * The proxy is still returned, so nothing that worked stops working; the change
 * is that the coverage gap is now stated. Both halves are asserted here: the
 * warning fires when nothing is governed, and it does NOT fire when something
 * is — a signal that fires on every wrap is worth no more than one that never
 * does.
 */
import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrap, _resetUngovernedReports } from '../../src/proxy/wrapper';

let warnings: string[] = [];
const realWarn = console.warn;

beforeEach(() => {
  _reset();
  _resetSender();
  _resetUngovernedReports();
  warnings = [];
  console.warn = (...a: unknown[]) => void warnings.push(a.join(' '));
});

afterEach(() => {
  console.warn = realWarn;
  _reset();
});

const boot = (extra: Record<string, unknown> = {}) =>
  init({ api_key: 'k', ingest_url: 'https://example.test', ...extra } as never);

/** A client shaped like nothing obsvr intercepts. */
const ungoverned = () => ({
  invoke: async () => 'hi',
  batch: async () => ['hi'],
});

/** The minimum shape that IS governed: one auditable path, resolving to a fn. */
const governed = () => ({
  chat: { completions: { create: async () => ({ choices: [] }) } },
});

describe('a client with no governed method is reported', () => {
  it('warns, naming the gap and the paths obsvr does intercept', () => {
    boot();
    wrap(ungoverned());

    const text = warnings.join('\n');
    expect(text).toContain('matched no governed method');
    expect(text).toContain('NOT covered');
    // The message has to be actionable: it names what obsvr looks for.
    expect(text).toContain('chat.completions.create');
    expect(text).toContain('requireGovernedSurface');
  });

  it('still returns a working pass-through, so nothing that worked breaks', async () => {
    boot();
    const client = wrap(ungoverned());

    await expect(client.invoke()).resolves.toBe('hi');
  });

  it('warns ONCE per client, not once per wrap of that client', () => {
    boot();
    const client = ungoverned();
    wrap(client);
    wrap(client);
    wrap(client);

    expect(warnings.filter((w) => w.includes('matched no governed method'))).toHaveLength(1);
  });

  it('warns again for a DIFFERENT client, because that is a second gap', () => {
    boot();
    wrap(ungoverned());
    wrap(ungoverned());

    expect(warnings.filter((w) => w.includes('matched no governed method'))).toHaveLength(2);
  });
});

describe('a client that IS governed is not reported', () => {
  // The non-vacuity control. Without it the warning could be unconditional and
  // every case above would still pass.
  it('says nothing for a chat-shaped client', () => {
    boot();
    wrap(governed());

    expect(warnings.join('\n')).not.toContain('matched no governed method');
  });

  it('says nothing for a client whose only surface is a .stream() helper', () => {
    // Governed through the deferred runner rather than AUDITABLE_METHODS. A
    // probe that consulted only that one table would call this uncovered.
    boot();
    wrap({ messages: { stream: () => ({ on: () => undefined }) } });

    expect(warnings.join('\n')).not.toContain('matched no governed method');
  });

  it('says nothing for a client whose only surface is a tool runner', () => {
    boot();
    wrap({ chat: { completions: { runTools: () => ({ on: () => undefined }) } } });

    expect(warnings.join('\n')).not.toContain('matched no governed method');
  });
});

describe('requireGovernedSurface', () => {
  it('throws instead of warning when nothing is governed', () => {
    boot({ require_governed_surface: true });

    expect(() => wrap(ungoverned())).toThrow(/matched no governed method/);
  });

  it('does not throw for a client that is governed', () => {
    boot({ require_governed_surface: true });

    expect(() => wrap(governed())).not.toThrow();
  });

  it('is refused at init() when it is not a boolean', () => {
    expect(() =>
      init({ api_key: 'k', ingest_url: 'https://example.test', require_governed_surface: 'yes' } as never),
    ).toThrow(/requireGovernedSurface must be a boolean/);
  });

  it('defaults to false, so the default posture stays a warning', () => {
    boot();

    expect(() => wrap(ungoverned())).not.toThrow();
    expect(warnings.join('\n')).toContain('matched no governed method');
  });
});

describe('the probe cannot itself break wrap()', () => {
  it('survives a property that throws on read', () => {
    // Provider SDKs build sub-resources in lazy getters. `beta` is the one the
    // probe reads and `detectProvider` does not, so a throw here reaches the
    // probe and nothing else — which is what makes this a test of the probe.
    boot();
    const hostile = {
      get beta(): unknown {
        throw new Error('lazy resource blew up');
      },
      messages: { create: async () => ({}) },
    };

    // `messages.create` resolves, so this client IS governed — a verdict only
    // reachable if the throwing `beta` getter did not abort the probe.
    expect(() => wrap(hostile as object)).not.toThrow();
    expect(warnings.join('\n')).not.toContain('matched no governed method');
  });

  it('reports a gap even when every probed path throws', () => {
    boot();
    const allHostile = {
      get chat(): unknown {
        throw new Error('no');
      },
      get beta(): unknown {
        throw new Error('no');
      },
    };

    // `detectProvider` reads `chat` first, so this one throws out of wrap()
    // before the probe — a pre-existing property of the front door, asserted
    // here so the probe is not credited with a guarantee it does not give.
    expect(() => wrap(allHostile as object)).toThrow(/no/);
  });

  it('treats a non-callable at the method path as no surface', () => {
    // `create` present but not a function: the proxy would never intercept it,
    // so reporting it as covered would be the false direction.
    boot();
    wrap({ chat: { completions: { create: 'not a function' } } });

    expect(warnings.join('\n')).toContain('matched no governed method');
  });
});
