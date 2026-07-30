/**
 * A refused stream has to tell the caller who is listening for it.
 *
 * `governCall` throws inside the ready-box, so the real runner is never
 * constructed — and the queued `.on()` registrations are replayed inside that
 * box only AFTER `start()`, which a refusal never reaches. The gate worked
 * perfectly and the application was never told: a caller using the event API
 * observed a stream that produced nothing, forever. `for await` saw it, because
 * that path awaits the box; the event surface had nothing to await.
 *
 * Measured live before this was pinned: with `.on('error')` registered on a
 * policy-blocked stream, the callback did not fire in six seconds. It now fires
 * in under thirty milliseconds, including when it is registered after the
 * refusal has already happened.
 *
 * The controls matter as much as the cases. An allowed run must NOT fire error
 * — otherwise "it fires" would mean "it always fires" — and the iteration
 * surface, which already worked, must still reject.
 */
import { createDeferredRunner } from '../../src/proxy/runner-wrapper';

const tick = () => new Promise((r) => setTimeout(r, 5));

/** A runner shaped like a provider's: an emitter with done(). */
function fakeRunner() {
  const handlers: Record<string, Array<(...a: unknown[]) => void>> = {};
  return {
    handlers,
    on(event: string, fn: (...a: unknown[]) => void) {
      (handlers[event] ??= []).push(fn);
      return this;
    },
    off() { return this; },
    async done() { return 'finished'; },
  };
}

describe('a refusal reaches .on("error")', () => {
  it('fires a listener registered before the refusal', async () => {
    const boom = new Error('[obsvr] blocked by policy');
    const stand = createDeferredRunner({
      govern: async () => { throw boom; },
      start: () => { throw new Error('start() must never run on a refusal'); },
      finish: () => {},
    });

    const seen: unknown[] = [];
    stand.on?.('error', (e) => seen.push(e));
    await tick();

    expect(seen).toEqual([boom]);
  });

  it('fires a listener registered after the refusal has already happened', async () => {
    // A fix that only drains the queue passes the case above and fails here.
    const boom = new Error('[obsvr] blocked by policy');
    const stand = createDeferredRunner({
      govern: async () => { throw boom; },
      start: () => { throw new Error('start() must never run on a refusal'); },
      finish: () => {},
    });
    await tick();

    const seen: unknown[] = [];
    stand.on?.('error', (e) => seen.push(e));
    await tick();

    expect(seen).toEqual([boom]);
  });

  it('does not throw when nobody is listening', async () => {
    // An unhandled error here would turn a refusal the SDK handled correctly
    // into a crash of the host process — worse than the silence being fixed.
    const stand = createDeferredRunner({
      govern: async () => { throw new Error('[obsvr] blocked by policy'); },
      start: () => { throw new Error('unreachable'); },
      finish: () => {},
    });
    expect(stand).toBeDefined();
    await tick();
  });

  it('survives a listener that throws', async () => {
    const stand = createDeferredRunner({
      govern: async () => { throw new Error('[obsvr] blocked by policy'); },
      start: () => { throw new Error('unreachable'); },
      finish: () => {},
    });
    const seen: unknown[] = [];
    stand.on?.('error', () => { throw new Error("the caller's own bug"); });
    stand.on?.('error', (e) => seen.push(e));
    await tick();
    // The second listener still ran: one caller's exception does not eat the
    // notification for the next.
    expect(seen).toHaveLength(1);
  });

  it('still reports the refusal to an awaiting caller', async () => {
    const boom = new Error('[obsvr] blocked by policy');
    const stand = createDeferredRunner({
      govern: async () => { throw boom; },
      start: () => { throw new Error('unreachable'); },
      finish: () => {},
    });
    await expect((async () => { for await (const _ of stand as AsyncIterable<unknown>) void _; })())
      .rejects.toThrow('blocked by policy');
  });
});

describe('the controls — an allowed run is untouched', () => {
  it('does not fire error, and replays the queued registration onto the real runner', async () => {
    const runner = fakeRunner();
    const stand = createDeferredRunner({
      govern: async () => [],
      start: () => runner as never,
      finish: () => {},
    });

    const errors: unknown[] = [];
    stand.on?.('error', (e) => errors.push(e));
    stand.on?.('content', () => {});
    await tick();

    expect(errors).toHaveLength(0);
    // The replay is the behaviour the refusal path was missing; assert it still
    // happens, or "nothing fired" could mean the queue is simply discarded now.
    expect(runner.handlers.error).toHaveLength(1);
    expect(runner.handlers.content).toHaveLength(1);
  });
});
