/**
 * An approval that cannot be read as a date must not authorize anything.
 *
 * `Date.parse` returns NaN for a string it cannot read, and every comparison
 * with NaN is false. So `Date.parse(expires_at) <= now` fell straight through
 * and the grant matched forever, while `getApprovalGrants()` used the mirrored
 * `> now` — also false for NaN — so the same permanent grant was invisible to
 * the inspection API. Live in the gate, absent from the listing: an operator
 * auditing grants saw nothing.
 *
 * Measured before this was pinned: `"never"`, `""`, `"forever"` and
 * `"not-a-date"` each satisfied a claim at the current time and still satisfied
 * it at the year 9999, and none of the four appeared in the listing.
 *
 * The module header has always said approvals always expire and that there are
 * no permanent grants. That was true of the intent and false of the code, which
 * is why the code moved rather than the comment.
 */
import {
  updateApprovals,
  hasApproval,
  getApprovalGrants,
  _resetApprovals,
} from '../../src/policy/approvals';

const NOW = Date.UTC(2026, 6, 30);
// A real number, deliberately not `Date.parse("12000-01-01T00:00:00Z")` — that
// string is ITSELF unparseable, so an earlier version of this check compared
// every grant against NaN and reported that all of them matched forever.
const YEAR_9999 = 253402300800000;

const UNPARSEABLE = ['never', '', 'forever', 'not-a-date', 'null', '  '];

beforeEach(() => {
  if (typeof _resetApprovals === 'function') _resetApprovals();
});

describe('an unparseable expiry is expired, not eternal', () => {
  it.each(UNPARSEABLE)('refuses a grant whose expires_at is %p', (expires) => {
    updateApprovals([{ id: 'g1', rule_id: 'r1', expires_at: expires }]);
    expect(Number.isNaN(Date.parse(expires))).toBe(true); // the premise
    expect(hasApproval({ ruleId: 'r1', now: NOW })).toBe(false);
    expect(hasApproval({ ruleId: 'r1', now: YEAR_9999 })).toBe(false);
  });

  it('never lists a grant it would not honour', () => {
    // The two used mirrored comparisons and disagreed on NaN, which is how a
    // live grant became invisible. One predicate now serves both.
    for (const expires of UNPARSEABLE) {
      updateApprovals([{ id: 'g1', rule_id: 'r1', expires_at: expires }]);
      expect(getApprovalGrants()).toHaveLength(0);
    }
  });
});

describe('the controls — real dates still behave', () => {
  it('honours a future grant and lists it', () => {
    updateApprovals([{ id: 'g1', rule_id: 'r1', expires_at: '2099-01-01T00:00:00Z' }]);
    expect(hasApproval({ ruleId: 'r1', now: NOW })).toBe(true);
    expect(getApprovalGrants()).toHaveLength(1);
  });

  it('refuses a past grant and does not list it', () => {
    updateApprovals([{ id: 'g1', rule_id: 'r1', expires_at: '2020-01-01T00:00:00Z' }]);
    expect(hasApproval({ ruleId: 'r1', now: NOW })).toBe(false);
    expect(getApprovalGrants()).toHaveLength(0);
  });

  it('still expires a future grant once that time passes', () => {
    // Without this, "refuses everything" would satisfy the cases above.
    updateApprovals([{ id: 'g1', rule_id: 'r1', expires_at: '2099-01-01T00:00:00Z' }]);
    expect(hasApproval({ ruleId: 'r1', now: YEAR_9999 })).toBe(false);
  });
});
