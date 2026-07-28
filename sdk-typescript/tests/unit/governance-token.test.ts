import { issueExecutionToken, verifyExecutionToken } from '../../src/governance/token';

const TEST_API_KEY = 'test-api-key-12345';

describe('JWT Execution Tokens', () => {
  it('issues and verifies a valid token', () => {
    const token = issueExecutionToken(TEST_API_KEY, {
      action: 'chat.completions.create',
      decision: 'PERMITTED',
    });

    expect(token).toBeTruthy();
    expect(token.split('.')).toHaveLength(3);

    const result = verifyExecutionToken(TEST_API_KEY, token);
    expect(result.valid).toBe(true);
    expect(result.payload?.action).toBe('chat.completions.create');
    expect(result.payload?.decision).toBe('PERMITTED');
    expect(result.payload?.nonce).toBeTruthy();
    expect(result.payload?.exp).toBeGreaterThan(Date.now());
  });

  it('includes rule_id when provided', () => {
    const token = issueExecutionToken(TEST_API_KEY, {
      action: 'tool.call',
      decision: 'PERMITTED',
      rule_id: 'rule-123',
    });
    const result = verifyExecutionToken(TEST_API_KEY, token);
    expect(result.valid).toBe(true);
    expect(result.payload?.rule_id).toBe('rule-123');
  });

  it('rejects token signed with different key', () => {
    const token = issueExecutionToken(TEST_API_KEY, {
      action: 'test',
      decision: 'PERMITTED',
    });
    const result = verifyExecutionToken('wrong-key', token);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('signature');
  });

  it('rejects tampered token', () => {
    const token = issueExecutionToken(TEST_API_KEY, {
      action: 'test',
      decision: 'PERMITTED',
    });
    // Tamper with the payload
    const parts = token.split('.');
    parts[1] = parts[1] + 'x';
    const tampered = parts.join('.');

    const result = verifyExecutionToken(TEST_API_KEY, tampered);
    expect(result.valid).toBe(false);
  });

  it('rejects expired token', () => {
    const token = issueExecutionToken(TEST_API_KEY, {
      action: 'test',
      decision: 'PERMITTED',
    }, -1000); // expired 1 second ago

    const result = verifyExecutionToken(TEST_API_KEY, token);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('expired');
  });

  it('rejects malformed token', () => {
    expect(verifyExecutionToken(TEST_API_KEY, 'not.a.jwt.token').valid).toBe(false);
    expect(verifyExecutionToken(TEST_API_KEY, '').valid).toBe(false);
    expect(verifyExecutionToken(TEST_API_KEY, 'singlepart').valid).toBe(false);
  });

  it('respects custom TTL', () => {
    const token = issueExecutionToken(TEST_API_KEY, {
      action: 'test',
      decision: 'PERMITTED',
    }, 120_000);
    const result = verifyExecutionToken(TEST_API_KEY, token);
    expect(result.valid).toBe(true);
    // Expiry should be ~120s from now
    expect(result.payload!.exp).toBeGreaterThan(Date.now() + 100_000);
  });
});
