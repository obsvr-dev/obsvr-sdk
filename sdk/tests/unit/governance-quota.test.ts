import { checkQuota, incrementQuota, resetQuota, getQuotaStatus, _resetAllQuotas } from '../../src/governance/quota';

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
