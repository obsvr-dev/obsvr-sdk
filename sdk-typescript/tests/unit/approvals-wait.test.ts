import { init, _reset, getConfig } from '../../src/proxy/config';
import {
  APPROVAL_WAIT_TIMEOUT_REASON_CODE,
  awaitApproval,
  updateApprovals,
  _resetApprovals,
} from '../../src/policy/approvals';
import { ReasonCode } from '../../src/governance/reason-codes';
import type { ResolvedConfig } from '../../src/proxy/types';

/**
 * The blocking approval wait: hold the call while the grant channel is
 * polled, and resolve only ever against the caller unless a live grant
 * lands. Twin: sdk-python/tests/test_approval_blocking.py (the wait
 * primitive; the pipeline wiring is exercised there because the Python
 * pipeline carries it — see the divergence note in the roadmap report).
 */

const FUTURE = new Date(Date.now() + 3_600_000).toISOString();
const GRANT = { id: 'g1', rule_id: 'r-appr', expires_at: FUTURE };

const cfg = { api_key: 'k', ingest_url: '' } as unknown as ResolvedConfig;
const CLAIM = { ruleId: 'r-appr' };

/** Injected sleep that yields without real time passing. */
const instant = () => Promise.resolve();

afterEach(() => {
  _resetApprovals();
  _reset();
});

describe('awaitApproval', () => {
  it('answers approved without polling when the grant is already in the store', async () => {
    updateApprovals([GRANT]);
    let polls = 0;
    const verdict = await awaitApproval(cfg, CLAIM, {
      timeoutMs: 1000,
      pollMs: 50,
      refresh: async () => {
        polls += 1;
      },
      isUnavailable: () => false,
      sleep: instant,
    });
    expect(verdict).toBe('approved');
    expect(polls).toBe(0);
  });

  it('holds through undecided polls and approves when the grant lands', async () => {
    let polls = 0;
    const verdict = await awaitApproval(cfg, CLAIM, {
      timeoutMs: 60_000,
      pollMs: 50,
      refresh: async () => {
        polls += 1;
        if (polls >= 3) updateApprovals([GRANT]);
      },
      isUnavailable: () => false,
      sleep: instant,
    });
    expect(verdict).toBe('approved');
    expect(polls).toBe(3);
  });

  it('times out when nobody answers, and never approves', async () => {
    const start = Date.now();
    const verdict = await awaitApproval(cfg, CLAIM, {
      timeoutMs: 120,
      pollMs: 30,
      refresh: async () => undefined,
      isUnavailable: () => false,
      // real sleep here: the deadline is wall-clock
    });
    expect(verdict).toBe('timeout');
    expect(Date.now() - start).toBeLessThan(5_000);
  });

  it('aborts as unavailable the moment enforcement degrades mid-wait', async () => {
    let polls = 0;
    const verdict = await awaitApproval(cfg, CLAIM, {
      timeoutMs: 60_000,
      pollMs: 50,
      refresh: async () => {
        polls += 1;
      },
      // Degrades after the first poll: a kill switch firing mid-wait.
      isUnavailable: () => polls >= 1,
      sleep: instant,
    });
    expect(verdict).toBe('unavailable');
  });

  it('resolves rather than throws when the grant channel is down', async () => {
    const verdict = await awaitApproval(cfg, CLAIM, {
      timeoutMs: 120,
      pollMs: 30,
      refresh: async () => {
        throw new Error('grant channel down');
      },
      isUnavailable: () => false,
    });
    expect(verdict).toBe('timeout');
  });

  it('exposes the distinct timeout reason code for the pipeline wiring', () => {
    // A hold that expired is a different fact from "refused; ask and retry".
    expect(APPROVAL_WAIT_TIMEOUT_REASON_CODE).toBe(ReasonCode.APPROVAL_TIMEOUT);
    expect(ReasonCode.APPROVAL_TIMEOUT).not.toBe(ReasonCode.APPROVAL_REQUIRED);
  });
});

describe('config opt-in', () => {
  it('defaults approvalWaitMs to 0 - the wait is strictly opt-in', () => {
    // Mutation guard: this fails if the default ever moves off 0, the change
    // that would make a library upgrade start blocking production calls.
    init({ api_key: 'k' });
    expect(getConfig().approvalWaitMs).toBe(0);
    expect(getConfig().approvalPollMs).toBe(5000);
  });

  it('carries the configured budgets through resolution (snake spelling)', () => {
    init({ api_key: 'k', approval_wait_ms: 30_000, approval_poll_ms: 1000 });
    expect(getConfig().approvalWaitMs).toBe(30_000);
    expect(getConfig().approvalPollMs).toBe(1000);
  });

  it('carries the configured budgets through resolution (camel spelling)', () => {
    init({ apiKey: 'k', approvalWaitMs: 30_000, approvalPollMs: 1000 });
    expect(getConfig().approvalWaitMs).toBe(30_000);
    expect(getConfig().approvalPollMs).toBe(1000);
  });

  it('rejects a negative wait budget at init', () => {
    expect(() => init({ api_key: 'k', approval_wait_ms: -1 })).toThrow(
      /approvalWaitMs/,
    );
  });
});
