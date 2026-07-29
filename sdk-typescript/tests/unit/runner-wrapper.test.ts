/**
 * The deferred runner: governance for provider `.stream()` helpers, which
 * return their runner object synchronously.
 *
 * The property that matters, and the one every other test here exists to
 * protect: **the provider is not called until pre-call governance has
 * resolved, and is not called at all if governance blocks.** Anything that
 * calls the provider first and governs afterwards is not blocking a request,
 * it is cancelling one the model has already seen — which for a governance
 * product is the difference between the product working and not.
 *
 * Everything else is the synchronous contract the provider's own runner
 * promises: `.on(...)` returns the runner so it chains, and it can be called
 * before the real runner exists.
 */
import { createDeferredRunner, isRunnerLike } from '../../src/proxy/runner-wrapper';

/** A fake provider runner with the surface the real ones expose. */
function fakeRunner(script: { chunks?: string[]; error?: unknown } = {}) {
  const listeners = new Map<string, ((...a: unknown[]) => void)[]>();
  const chunks = script.chunks ?? ['a', 'b'];
  let doneResolve!: () => void;
  let doneReject!: (e: unknown) => void;
  const donePromise = new Promise<void>((res, rej) => {
    doneResolve = res;
    doneReject = rej;
  });
  // A real runner settles on its own once the provider finishes; it does not
  // wait for the caller to iterate. The fake has to behave the same way or the
  // tests below hang on a promise nothing resolves.
  setTimeout(() => {
    if (script.error) doneReject(script.error);
    else doneResolve();
  }, 0);
  const runner = {
    aborted: false,
    emitted: [] as string[],
    on(event: string, listener: (...a: unknown[]) => void) {
      listeners.set(event, [...(listeners.get(event) ?? []), listener]);
      runner.emitted.push(`on:${event}`);
      return runner;
    },
    off() {
      return runner;
    },
    abort() {
      runner.aborted = true;
      doneResolve();
    },
    done() {
      return donePromise;
    },
    finalText() {
      return chunks.join('');
    },
    async *[Symbol.asyncIterator]() {
      for (const c of chunks) yield c;
      if (script.error) throw script.error;
    },
  };
  return runner;
}

describe('the provider is not called until governance resolves', () => {
  it('defers construction: nothing is sent while the pipeline is still deciding', async () => {
    let started = false;
    let releaseGovern!: () => void;
    const governGate = new Promise<void>((r) => (releaseGovern = r));

    const runner = createDeferredRunner({
      govern: async () => {
        await governGate;
        return [{ model: 'm' }];
      },
      start: () => {
        started = true;
        return fakeRunner();
      },
      finish: () => undefined,
    });

    // Returned synchronously, and the provider has NOT been reached.
    expect(runner).toBeDefined();
    expect(started).toBe(false);

    releaseGovern();
    await runner.done!();
    expect(started).toBe(true);
  });

  it('a BLOCK means the provider is never called at all', async () => {
    let started = false;
    const runner = createDeferredRunner({
      govern: async () => {
        throw new Error('[obsvr] Request blocked by policy');
      },
      start: () => {
        started = true;
        return fakeRunner();
      },
      finish: () => undefined,
    });

    await expect(runner.done!()).rejects.toThrow('blocked by policy');
    // The whole point: no request left the process.
    expect(started).toBe(false);
  });

  it('a block reaches a caller who only iterates', async () => {
    const runner = createDeferredRunner({
      govern: async () => {
        throw new Error('[obsvr] Request blocked by policy');
      },
      start: () => fakeRunner(),
      finish: () => undefined,
    });

    await expect(
      (async () => {
        for await (const _ of runner as AsyncIterable<unknown>) void _;
      })(),
    ).rejects.toThrow('blocked by policy');
  });

  it('governance can rewrite the arguments the provider is called with', async () => {
    // This is how pre-call redaction reaches the provider: the params handed
    // to start() are the governed ones, not the caller's originals.
    let seen: unknown;
    const runner = createDeferredRunner({
      govern: async () => [{ prompt: '[REDACTED_EMAIL]' }],
      start: (args) => {
        seen = args[0];
        return fakeRunner();
      },
      finish: () => undefined,
    });
    await runner.done!();
    expect(seen).toEqual({ prompt: '[REDACTED_EMAIL]' });
  });
});

describe('the synchronous runner contract is preserved', () => {
  it('.on() is callable immediately and chains', async () => {
    const real = fakeRunner();
    const runner = createDeferredRunner({
      govern: async () => [],
      start: () => real,
      finish: () => undefined,
    });

    // Synchronous, before the real runner exists, and returns something
    // chainable — exactly what `.on('text', …).on('end', …)` needs.
    const chained = runner.on!('text', () => undefined);
    expect(chained).toBeDefined();
    expect((chained as { on?: unknown }).on).toBeInstanceOf(Function);

    await runner.done!();
    // Replayed onto the real runner once it existed.
    expect(real.emitted).toContain('on:text');
  });

  it('registrations are replayed in the order they were made', async () => {
    const real = fakeRunner();
    const runner = createDeferredRunner({
      govern: async () => [],
      start: () => real,
      finish: () => undefined,
    });
    runner.on!('first', () => undefined);
    runner.on!('second', () => undefined);
    runner.on!('third', () => undefined);
    await runner.done!();
    expect(real.emitted).toEqual(['on:first', 'on:second', 'on:third']);
  });

  it('iteration yields the provider chunks unchanged', async () => {
    const runner = createDeferredRunner({
      govern: async () => [],
      start: () => fakeRunner({ chunks: ['x', 'y', 'z'] }),
      finish: () => undefined,
    });
    const seen: unknown[] = [];
    for await (const c of runner as AsyncIterable<unknown>) seen.push(c);
    expect(seen).toEqual(['x', 'y', 'z']);
  });

  it('helper methods the wrapper does not know about are forwarded', async () => {
    // finalMessage / finalChatCompletion / toReadableStream differ per
    // provider; forwarding rather than enumerating keeps this from coupling to
    // each one by name.
    const runner = createDeferredRunner({
      govern: async () => [],
      start: () => fakeRunner({ chunks: ['ab', 'cd'] }),
      finish: () => undefined,
    });
    const text = await (runner as unknown as { finalText(): Promise<string> }).finalText();
    expect(text).toBe('abcd');
  });

  it('abort before the run starts prevents the request entirely', async () => {
    let started = false;
    let releaseGovern!: () => void;
    const gate = new Promise<void>((r) => (releaseGovern = r));
    const runner = createDeferredRunner({
      govern: async () => {
        await gate;
        return [];
      },
      start: () => {
        started = true;
        return fakeRunner();
      },
      finish: () => undefined,
    });

    runner.abort!();
    releaseGovern();
    await expect(runner.done!()).rejects.toThrow('aborted before it started');
    expect(started).toBe(false);
  });
});

describe('the stand-in is not a promise', () => {
  it('does not look thenable, so `await` cannot adopt and hang on it', async () => {
    // The catch-all forwarder returns a function for any unknown property, so
    // without an explicit guard `await runner` would see a `then`, adopt the
    // stand-in as a thenable, and wait on a `then` the real runner does not
    // have. A caller writing `await client.messages.stream(...)` would hang.
    const runner = createDeferredRunner({
      govern: async () => [],
      start: () => fakeRunner(),
      finish: () => undefined,
    });
    expect((runner as Record<string, unknown>).then).toBeUndefined();
    expect((runner as Record<string, unknown>).catch).toBeUndefined();

    // And awaiting it resolves to the runner itself rather than hanging.
    const awaited = await (runner as unknown as Promise<unknown>);
    expect(awaited).toBe(runner);
  });
});

describe('completion is reported exactly once', () => {
  it('finish fires with the runner on success', async () => {
    const calls: { runner?: unknown; error?: unknown }[] = [];
    const runner = createDeferredRunner({
      govern: async () => [],
      start: () => fakeRunner(),
      finish: (r) => calls.push(r),
    });
    await runner.done!();
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toHaveLength(1);
    expect(calls[0].runner).toBeDefined();
    expect(calls[0].error).toBeUndefined();
  });

  it('finish fires with the error when governance blocks', async () => {
    const calls: { runner?: unknown; error?: unknown }[] = [];
    const runner = createDeferredRunner({
      govern: async () => {
        throw new Error('[obsvr] Request blocked by policy');
      },
      start: () => fakeRunner(),
      finish: (r) => calls.push(r),
    });
    await runner.done!().catch(() => undefined);
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toHaveLength(1);
    expect((calls[0].error as Error).message).toContain('blocked by policy');
  });
});

describe('isRunnerLike', () => {
  it('recognises a runner and rejects a promise', () => {
    expect(isRunnerLike(fakeRunner())).toBe(true);
    expect(isRunnerLike(Promise.resolve({}))).toBe(false);
    expect(isRunnerLike({})).toBe(false);
    expect(isRunnerLike(null)).toBe(false);
  });
});
