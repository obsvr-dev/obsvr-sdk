import { jest } from '@jest/globals';
import {
  checkQuota,
  incrementQuota,
  resetQuota,
  getQuotaStatus,
  checkTokenBudget,
  recordTokenUsage,
  quotaStoreSize,
  quotaStoreSaturated,
  _resetAllQuotas,
} from '../../src/governance/quota';

/** Mirrors MAX_QUOTA_SCOPES in src/governance/quota.ts (not exported). */
const CAP = 10_000;

beforeEach(() => {
  _resetAllQuotas();
});

describe('quota tracker', () => {
  it('allows calls within limit', () => {
    const r1 = incrementQuota('user_id', 'user1', 5, 60000);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBe(4);
  });

  it('blocks when quota exceeded', () => {
    for (let i = 0; i < 5; i++) {
      incrementQuota('user_id', 'user1', 5, 60000);
    }
    const result = incrementQuota('user_id', 'user1', 5, 60000);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it('checkQuota does not increment', () => {
    incrementQuota('user_id', 'user1', 5, 60000);
    const check = checkQuota('user_id', 'user1', 5, 60000);
    expect(check.allowed).toBe(true);
    expect(check.remaining).toBe(4);
    // Check again - should be same
    const check2 = checkQuota('user_id', 'user1', 5, 60000);
    expect(check2.remaining).toBe(4);
  });

  it('getQuotaStatus returns current usage', () => {
    incrementQuota('service_name', 'api', 10, 60000);
    incrementQuota('service_name', 'api', 10, 60000);
    incrementQuota('service_name', 'api', 10, 60000);
    const status = getQuotaStatus('service_name', 'api', 10, 60000);
    expect(status.used).toBe(3);
    expect(status.remaining).toBe(7);
  });

  it('resetQuota clears counter', () => {
    for (let i = 0; i < 5; i++) {
      incrementQuota('user_id', 'user1', 5, 60000);
    }
    expect(incrementQuota('user_id', 'user1', 5, 60000).allowed).toBe(false);
    resetQuota('user_id', 'user1');
    expect(incrementQuota('user_id', 'user1', 5, 60000).allowed).toBe(true);
  });

  it('isolates different scopes', () => {
    for (let i = 0; i < 5; i++) {
      incrementQuota('user_id', 'user1', 5, 60000);
    }
    // Different user should still have quota
    const result = incrementQuota('user_id', 'user2', 5, 60000);
    expect(result.allowed).toBe(true);
  });

  it('resets window when expired', async () => {
    // Use a very short window
    for (let i = 0; i < 5; i++) {
      incrementQuota('user_id', 'user1', 5, 1); // 1ms window
    }
    // Wait for window to expire
    await new Promise(resolve => setTimeout(resolve, 10));
    const result = incrementQuota('user_id', 'user1', 5, 1);
    expect(result.allowed).toBe(true);
  });

  it('provides resetAt timestamp', () => {
    const before = Date.now();
    const result = incrementQuota('user_id', 'user1', 5, 60000);
    expect(result.resetAt).toBeGreaterThanOrEqual(before + 60000);
  });
});

const silenceWarn = () => jest.spyOn(console, 'warn').mockImplementation(() => {});

describe('quota store bound', () => {
  let warn: ReturnType<typeof silenceWarn>;

  beforeEach(() => {
    warn = silenceWarn();
  });
  afterEach(() => warn.mockRestore());

  it('caps the request meter under sustained distinct-key pressure', () => {
    for (let i = 0; i < CAP * 2; i++) incrementQuota('user_id', `u${i}`, 5, 60_000);
    expect(quotaStoreSize().requests).toBe(CAP);
    expect(quotaStoreSaturated()).toBe(true);
  });

  it('caps the token meter under sustained distinct-key pressure', () => {
    for (let i = 0; i < CAP * 2; i++) recordTokenUsage('user_id', `u${i}`, 10, 60_000);
    expect(quotaStoreSize().tokens).toBe(CAP);
    expect(quotaStoreSaturated()).toBe(true);
  });

  it('warns once, not once per refused scope', () => {
    for (let i = 0; i < CAP + 50; i++) incrementQuota('user_id', `u${i}`, 5, 60_000);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain('quota store is full');
  });

  it('never resets a live counter to make room (the bypass this prevents)', () => {
    // A tracked scope at its limit stays at its limit no matter how many fresh
    // scopes arrive. Evicting oldest-first here would hand a caller who can
    // mint scope values a free quota reset.
    for (let i = 0; i < 5; i++) incrementQuota('user_id', 'victim', 5, 60_000);
    expect(incrementQuota('user_id', 'victim', 5, 60_000).allowed).toBe(false);

    for (let i = 0; i < CAP * 2; i++) incrementQuota('user_id', `flood${i}`, 5, 60_000);

    expect(getQuotaStatus('user_id', 'victim', 5, 60_000).used).toBeGreaterThanOrEqual(5);
    expect(incrementQuota('user_id', 'victim', 5, 60_000).allowed).toBe(false);
  });

  it('leaves a refused scope unmetered rather than blocking it', () => {
    for (let i = 0; i < CAP; i++) incrementQuota('user_id', `u${i}`, 5, 60_000);
    expect(quotaStoreSaturated()).toBe(false); // exactly at cap, nothing refused

    // Past the cap: allowed (fail-open) but not counted, so repeated calls for
    // the same refused scope never accumulate toward the limit.
    for (let i = 0; i < 20; i++) {
      expect(incrementQuota('user_id', 'newcomer', 5, 60_000).allowed).toBe(true);
    }
    expect(quotaStoreSaturated()).toBe(true);
    expect(quotaStoreSize().requests).toBe(CAP);
    expect(checkQuota('user_id', 'newcomer', 5, 60_000).allowed).toBe(true);
    expect(getQuotaStatus('user_id', 'newcomer', 5, 60_000).used).toBe(0);
  });

  it('admits new scopes again once the tracked windows expire', async () => {
    for (let i = 0; i < CAP; i++) incrementQuota('user_id', `u${i}`, 1, 1); // 1ms window
    expect(quotaStoreSize().requests).toBe(CAP);
    await new Promise((r) => setTimeout(r, 10));

    // The sweep drops only entries the next touch would have reset anyway, so
    // the newcomer is tracked for real: its second call consumes its limit.
    expect(incrementQuota('user_id', 'newcomer', 1, 60_000).allowed).toBe(true);
    expect(incrementQuota('user_id', 'newcomer', 1, 60_000).allowed).toBe(false);
    expect(quotaStoreSize().requests).toBeLessThanOrEqual(CAP);
  });

  it('reopens an already-tracked scope in its own slot with the store full', async () => {
    for (let i = 0; i < CAP - 1; i++) incrementQuota('user_id', `u${i}`, 5, 60_000);
    incrementQuota('user_id', 'known', 1, 5); // fills the last slot, 5ms window
    expect(quotaStoreSize().requests).toBe(CAP);

    await new Promise((r) => setTimeout(r, 15));
    // No free slot, but 'known' is already tracked: its expired entry reuses
    // its own slot, so it stays metered rather than falling through unmetered.
    expect(incrementQuota('user_id', 'known', 1, 5).allowed).toBe(true);
    expect(incrementQuota('user_id', 'known', 1, 5).allowed).toBe(false);
    expect(quotaStoreSize().requests).toBe(CAP);
  });

  it('bounds the token meter without blocking a refused budget', () => {
    for (let i = 0; i < CAP; i++) recordTokenUsage('user_id', `u${i}`, 10, 60_000);
    recordTokenUsage('user_id', 'newcomer', 5_000, 60_000);
    expect(quotaStoreSize().tokens).toBe(CAP);
    const budget = checkTokenBudget('user_id', 'newcomer', 1_000, 60_000);
    expect(budget.allowed).toBe(true);
    expect(budget.remaining).toBe(1_000);
  });
});
