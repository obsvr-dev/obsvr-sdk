/**
 * `getQuotaStatus` must not allocate.
 *
 * It called `getOrCreate`, which INSERTS — and `governance/server.ts` exposes it
 * as `GET /v2/quota/:scope/:value` with the value supplied by the caller. So a
 * sweep of distinct values through the READ endpoint filled the bounded store,
 * and because that store deliberately REFUSES rather than evicting a live
 * counter, every real scope afterwards reported `metered: false`. Under the
 * default `failMode: "open"` those calls then proceeded with no quota
 * enforcement at all: a read endpoint inverted the reasoning the eviction
 * policy was designed around.
 *
 * Measured against the real PDP server over a real socket: 12,000 GET requests
 * took the store from 1 entry to 10,000 and saturated it, a scope that metered
 * before the sweep did not after, and a scope incremented twice DURING the
 * saturation reported `used: 0` — the sweep did not merely stop new metering,
 * it made an actively-used scope report no usage.
 *
 * The control is the other half: a read that allocates nothing must still tell
 * the truth about a scope that IS live, or "no longer writes" would be
 * satisfied by "no longer works".
 */
import {
  getQuotaStatus,
  incrementQuota,
  quotaStoreSize,
  _resetAllQuotas,
} from '../../src/governance/quota';

const WINDOW = 60_000;

beforeEach(() => {
  _resetAllQuotas();
});
afterEach(() => {
  _resetAllQuotas();
});

describe('reading a quota does not create one', () => {
  it('leaves the store empty after reading scopes that do not exist', () => {
    expect(quotaStoreSize().requests).toBe(0);
    for (let i = 0; i < 500; i++) getQuotaStatus('user', `sweep-${i}`, 100, WINDOW);
    expect(quotaStoreSize().requests).toBe(0);
  });

  it('leaves a real scope still meterable after a large read sweep', () => {
    for (let i = 0; i < 500; i++) getQuotaStatus('user', `sweep-${i}`, 100, WINDOW);
    const verdict = incrementQuota('user', 'a-real-user', 100, WINDOW);
    expect(verdict.metered).toBe(true);
  });

  it('reports the fresh-window answer for a scope it did not create', () => {
    const status = getQuotaStatus('user', 'never-seen', 100, WINDOW);
    expect(status.used).toBe(0);
    expect(status.remaining).toBe(100);
    expect(quotaStoreSize().requests).toBe(0);
  });
});

describe('the control — it still reports the truth', () => {
  it('reports real consumption for a scope that is live', () => {
    incrementQuota('user', 'alice', 100, WINDOW);
    incrementQuota('user', 'alice', 100, WINDOW);
    const status = getQuotaStatus('user', 'alice', 100, WINDOW);
    expect(status.used).toBe(2);
    expect(status.remaining).toBe(98);
  });

  it('does not disturb the counter it reports on', () => {
    incrementQuota('user', 'bob', 100, WINDOW);
    getQuotaStatus('user', 'bob', 100, WINDOW);
    getQuotaStatus('user', 'bob', 100, WINDOW);
    expect(getQuotaStatus('user', 'bob', 100, WINDOW).used).toBe(1);
    expect(quotaStoreSize().requests).toBe(1);
  });

  it('still meters normally — incrementing is unaffected', () => {
    // Without this, "the store stays empty" would be satisfied by a quota
    // system that had stopped counting anything at all.
    for (let i = 0; i < 3; i++) incrementQuota('user', 'carol', 100, WINDOW);
    expect(quotaStoreSize().requests).toBe(1);
    expect(getQuotaStatus('user', 'carol', 100, WINDOW).used).toBe(3);
  });
});
