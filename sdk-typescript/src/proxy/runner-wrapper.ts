/**
 * Governance for the provider `.stream()` helpers, which return their runner
 * object SYNCHRONOUSLY.
 *
 * WHY THESE NEEDED THEIR OWN WRAPPER. `createAuditedMethod` is `async`, so
 * listing `messages.stream` / `chat.completions.stream` / `responses.stream` in
 * the method table would hand the caller a Promise where the SDK's own contract
 * promises a stream object, breaking `.on('text', …)` chaining at every call
 * site. So they sat outside the coverage boundary — chat-shaped, text-bearing,
 * and completely ungoverned, which is the one remaining shape where a caller
 * could reasonably believe they were covered and not be.
 *
 * THE CONSTRAINT, AND WHY IT IS NOT SOLVED BY CALLING THE PROVIDER FIRST.
 * Pre-call enforcement is asynchronous — the optional Presidio scan and the
 * customer `onPreCall` hook (which is where human-in-the-loop lives) both
 * await. If this wrapper called the provider first and governed afterwards, the
 * request would already have left the process: a "block" would abort a stream
 * the model was already answering, which is not a block, it is a cancellation
 * after disclosure. For a governance product that distinction is the product.
 *
 * So the underlying call is DEFERRED. This returns a stand-in that satisfies
 * the synchronous contract immediately, runs the full pre-call pipeline, and
 * only then constructs the real runner. Registrations made before that point
 * are recorded and replayed onto the real runner in the order they were made,
 * so `.on(...)` chaining behaves as it always did. On a block the real runner
 * is never constructed and the request never leaves.
 *
 * Nothing the provider owns is mutated: the stand-in is obsvr's own object, the
 * real runner is returned to it untouched, and completion is observed through
 * the runner's own public surface.
 *
 * @packageDocumentation
 */

/** The subset of a provider runner this wrapper needs to speak. */
export interface RunnerLike {
  on?(event: string, listener: (...args: unknown[]) => void): unknown;
  off?(event: string, listener: (...args: unknown[]) => void): unknown;
  abort?(): void;
  done?(): Promise<unknown>;
  [Symbol.asyncIterator]?(): AsyncIterator<unknown>;
}

/** What the caller did to the stand-in before the real runner existed. */
type PendingCall = { method: string; args: unknown[] };

export interface DeferredRunnerHooks {
  /**
   * Runs the full pre-call pipeline. Resolves to the (possibly rewritten)
   * arguments to call the provider with, or throws to block — in which case
   * the provider is never called.
   */
  govern: () => Promise<unknown[]>;
  /** Construct the real runner from the governed arguments. */
  start: (args: unknown[]) => RunnerLike;
  /** Called once, after the run finishes or fails. */
  finish: (result: { runner?: RunnerLike; error?: unknown }) => void;
  /**
   * How to run the runner to completion, and what its completion value is.
   * Defaults to awaiting `runner.done()`.
   *
   * Supply this for a runner that only ADVANCES while something consumes it:
   * the Anthropic tool runner's `done()` waits on an iteration that never
   * starts by itself, so the default would wait forever. A `complete` that
   * drives the iteration is also the only place the intermediate turns can be
   * observed, since that runner exposes no event emitter.
   */
  complete?: (runner: RunnerLike) => Promise<unknown>;
  /**
   * Whether the REAL runner is itself awaitable.
   *
   * DEFAULT FALSE, AND THE DEFAULT IS LOAD-BEARING. The stand-in must mirror
   * the real object here, and it is wrong in a different way in each
   * direction. The `.stream()` runners are NOT thenable, so synthesising a
   * `then` for them made `await client.messages.stream(...)` adopt the
   * stand-in as a promise and wait on a method the real runner does not have
   * — it hung forever. The Anthropic tool runner IS thenable by design
   * (`await runner` is documented as equivalent to `runUntilDone()`), so
   * REFUSING a `then` there is just as wrong and fails more quietly: `await`
   * would hand back the stand-in itself instead of the final message, and
   * nothing would throw. One flag, because only the real object knows.
   */
  thenable?: boolean;
}

/**
 * A stand-in that is returned synchronously and becomes the real runner.
 *
 * Method calls made before the real runner exists are queued and replayed in
 * order; everything after is forwarded live. Async iteration awaits the real
 * runner and then delegates to it, so `for await` reads the provider's own
 * chunks with nothing interposed.
 */
export function createDeferredRunner(hooks: DeferredRunnerHooks): RunnerLike {
  const pending: PendingCall[] = [];
  let real: RunnerLike | undefined;
  let failed: unknown;
  let aborted = false;

  // BOXED, and the box is not optional. A runner may itself be a thenable —
  // Anthropic's tool runner documents `await runner` as running the loop — and
  // returning a thenable from an async function makes the promise machinery
  // ADOPT it. An unboxed `return runner` would therefore resolve to whatever
  // the RUN eventually produced instead of to the runner, and would start that
  // run the moment governance passed rather than when the caller asked. One
  // object wrapper keeps the runner opaque to promise resolution.
  const readyBox: Promise<{ runner: RunnerLike }> = (async () => {
    const args = await hooks.govern();
    if (aborted) {
      // The caller abandoned the run while governance was still deciding.
      // Constructing the runner now would send a request nobody is listening
      // for, so don't.
      const err = new Error("[obsvr] stream aborted before it started");
      failed = err;
      throw err;
    }
    const runner = hooks.start(args);
    real = runner;
    for (const { method, args: callArgs } of pending) {
      const fn = (runner as Record<string, unknown>)[method];
      if (typeof fn === "function") (fn as (...a: unknown[]) => unknown).apply(runner, callArgs);
    }
    pending.length = 0;
    return { runner };
  })();

  // The rejection is observed by every path that awaits `readyBox`; attaching a
  // no-op keeps a governance block from surfacing as an unhandled rejection in
  // the host process when the caller only uses `.on('error', …)`.
  readyBox.catch(() => undefined);

  // Resolves with the run's completion VALUE (what `await runner` yields when
  // the real runner is thenable). Kept separate from the finish() notification
  // below so a thenable stand-in has something to hand its caller.
  const completed: Promise<unknown> = (async () => {
    const { runner } = await readyBox;
    if (hooks.complete) return hooks.complete(runner);
    if (typeof runner.done === "function") return runner.done();
    return undefined;
  })();
  completed.catch(() => undefined);

  const settle = (async () => {
    try {
      const { runner } = await readyBox;
      if (
        !hooks.complete &&
        typeof runner.done !== "function" &&
        typeof runner[Symbol.asyncIterator] === "function"
      ) {
        // No done() to await and no explicit driver: the run is complete once
        // the caller has drained it, and finish() is driven from the iterator
        // instead.
        return;
      }
      await completed;
      hooks.finish({ runner });
    } catch (err) {
      failed = failed ?? err;
      hooks.finish({ error: err });
    }
  })();
  settle.catch(() => undefined);

  const stand: RunnerLike & Record<string, unknown> = {
    on(event: string, listener: (...a: unknown[]) => void) {
      if (real) real.on?.(event, listener);
      else pending.push({ method: "on", args: [event, listener] });
      return stand; // chaining, exactly as the provider's runner does
    },
    off(event: string, listener: (...a: unknown[]) => void) {
      if (real) real.off?.(event, listener);
      else pending.push({ method: "off", args: [event, listener] });
      return stand;
    },
    abort() {
      aborted = true;
      if (real) real.abort?.();
      else pending.push({ method: "abort", args: [] });
    },
    async done() {
      // Delegate to the single shared completion rather than calling the
      // runner again: a runner whose progress comes from being consumed can
      // only be consumed once, so a second drive would throw rather than
      // return the same answer.
      if (hooks.complete) return completed;
      const { runner } = await readyBox;
      return typeof runner.done === "function" ? runner.done() : undefined;
    },
    [Symbol.asyncIterator]() {
      let inner: AsyncIterator<unknown> | undefined;
      return {
        async next(): Promise<IteratorResult<unknown>> {
          if (!inner) {
            const { runner } = await readyBox;
            const it = runner[Symbol.asyncIterator];
            if (typeof it !== "function") return { done: true, value: undefined };
            inner = it.call(runner);
          }
          return inner.next();
        },
        async return(value?: unknown): Promise<IteratorResult<unknown>> {
          if (inner?.return) return inner.return(value);
          return { done: true, value };
        },
      } as AsyncIterator<unknown>;
    },
  };

  if (hooks.thenable) {
    // Mirror an awaitable runner. `then` resolves with the run's completion
    // value, so `await standIn` yields what `await realRunner` would.
    stand.then = (
      onFulfilled?: ((v: unknown) => unknown) | null,
      onRejected?: ((e: unknown) => unknown) | null,
    ) => completed.then(onFulfilled, onRejected);
  }

  // Anything else the runner exposes (finalMessage, finalChatCompletion,
  // toReadableStream, ...) is forwarded once the real runner exists. Forwarding
  // through a Proxy rather than enumerating keeps this wrapper from having to
  // track each provider's helper surface, which is exactly the kind of
  // by-name coupling that has broken before.
  return new Proxy(stand, {
    get(target, prop, receiver) {
      if (prop in target) return Reflect.get(target, prop, receiver);
      if (typeof prop === "symbol") return Reflect.get(target, prop, receiver);
      // Never SYNTHESIZE a thenable. The catch-all below returns a function for
      // any unknown property, and `await x` probes `x.then` — so without this
      // the stand-in would look like a promise, `await` would adopt it, and the
      // forwarded `then` would wait on a real runner that has no such method.
      // A caller who wrote `await client.messages.stream(...)` would hang
      // forever. A runner that IS awaitable gets a real `then` assigned above,
      // which `prop in target` returns before reaching here — so this refuses
      // only the accidental kind.
      if (prop === "then" || prop === "catch" || prop === "finally") return undefined;
      return (...args: unknown[]) =>
        readyBox.then(({ runner }) => {
          const fn = (runner as Record<string, unknown>)[prop as string];
          if (typeof fn !== "function") return fn;
          return (fn as (...a: unknown[]) => unknown).apply(runner, args);
        });
    },
    has(target, prop) {
      return prop in target || (real !== undefined && prop in (real as object));
    },
  }) as RunnerLike;
}

/** Whether a value looks like a provider runner rather than a plain promise. */
export function isRunnerLike(value: unknown): value is RunnerLike {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.then === "function") return false; // a Promise is not a runner
  return typeof v.on === "function" || typeof v.done === "function";
}
