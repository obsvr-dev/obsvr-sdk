/**
 * Who owns process termination when a signal arrives.
 *
 * Attaching a SIGTERM listener replaces the runtime's default disposition for
 * that signal, so a library that attaches one and never exits swallows the
 * signal and the process ignores SIGTERM forever. Exiting unconditionally is
 * the other failure: it ends the process while the host's own shutdown is still
 * draining connections or committing a transaction, and wrapping a client is
 * not consent to that. Measured before this was pinned, against a real host
 * committing over 600ms under a real signal: terminated 4ms in, with nothing
 * queued to flush.
 *
 * Both failures are asserted here, because a fix for either one alone is a
 * regression into the other. The ownership question is settled WHEN THE SIGNAL
 * FIRES rather than when the handler registered, so the third case installs the
 * host's listener after setup and still expects the host to win.
 */
import { jest } from '@jest/globals';
import { setupExitHandlers, _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { init, getConfig, _reset } from '../../src/proxy/config';
import type { ResolvedConfig } from '../../src/proxy/types';

const SIGNALS: Array<'SIGTERM' | 'SIGINT'> = ['SIGTERM', 'SIGINT'];
const CODE = { SIGTERM: 143, SIGINT: 130 } as const;

let config: ResolvedConfig;
let saved: Record<string, Array<(...a: unknown[]) => void>>;
let exitSpy: ReturnType<typeof jest.spyOn>;

beforeEach(() => {
  _reset();
  _resetSender();
  init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:9/ingest' });
  config = getConfig() as ResolvedConfig;

  // This process is the test runner. Park whatever it had listening and put it
  // back afterwards, or one case leaks a handler into every later suite.
  saved = {};
  for (const s of SIGNALS) {
    saved[s] = process.listeners(s) as Array<(...a: unknown[]) => void>;
    process.removeAllListeners(s);
  }
  exitSpy = jest.spyOn(process, 'exit').mockImplementation((() => undefined) as never);
});

afterEach(() => {
  exitSpy.mockRestore();
  for (const s of SIGNALS) {
    process.removeAllListeners(s);
    for (const fn of saved[s]) process.on(s, fn);
  }
  _resetSender();
  _reset();
});

/** Let the flush promise and its `finally` settle. */
const settle = () => new Promise((r) => setTimeout(r, 20));

describe.each(SIGNALS)('%s', (signal) => {
  it('exits when nothing else is listening, so the signal is not swallowed', async () => {
    setupExitHandlers(config);
    expect(process.listenerCount(signal)).toBe(1);

    process.emit(signal as NodeJS.Signals);
    await settle();

    expect(exitSpy).toHaveBeenCalledWith(CODE[signal]);
  });

  it('leaves termination to a host that was already listening', async () => {
    const hostHandler = jest.fn();
    process.on(signal, hostHandler);
    setupExitHandlers(config);

    process.emit(signal as NodeJS.Signals);
    await settle();

    expect(hostHandler).toHaveBeenCalled();
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it('leaves termination to a host that started listening after setup', async () => {
    setupExitHandlers(config);
    // The order that distinguishes deciding ownership at signal time from
    // deciding it at registration time. A host may wrap a client and install
    // its shutdown afterwards.
    const hostHandler = jest.fn();
    process.on(signal, hostHandler);

    process.emit(signal as NodeJS.Signals);
    await settle();

    expect(hostHandler).toHaveBeenCalled();
    expect(exitSpy).not.toHaveBeenCalled();
  });
});

it('reset removes only SDK-owned listeners across repeated registrations', () => {
  const hostHandler = jest.fn();
  const beforeExitBaseline = process.listenerCount('beforeExit');
  process.on('SIGTERM', hostHandler);

  for (let index = 0; index < 12; index++) {
    setupExitHandlers(config);
    expect(process.listenerCount('SIGTERM')).toBe(2);
    expect(process.listenerCount('beforeExit')).toBe(beforeExitBaseline + 1);
    _resetSender();
    expect(process.listeners('SIGTERM')).toEqual([hostHandler]);
    expect(process.listenerCount('beforeExit')).toBe(beforeExitBaseline);
  }

  setupExitHandlers(config);
  expect(process.listenerCount('SIGTERM')).toBe(2);
  expect(process.listenerCount('beforeExit')).toBe(beforeExitBaseline + 1);
});
