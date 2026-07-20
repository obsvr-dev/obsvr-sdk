import { useSubject, getCurrentSubject, parseSubject } from '../../src/proxy/subject';

/**
 * useSubject() ambient subject attribution. Pins parsing of the string forms,
 * ALS scoping (bound inside, cleared outside, survives awaits), and nested
 * override precedence.
 */

describe('parseSubject', () => {
  it('parses user:alice', () => {
    expect(parseSubject('user:alice')).toEqual({ user_id: 'alice' });
  });
  it('parses user:alice;tenant:acme;service=api', () => {
    expect(parseSubject('user:alice;tenant:acme;service=api')).toEqual({
      user_id: 'alice',
      tenant_id: 'acme',
      service_name: 'api',
    });
  });
  it('treats a bare token as user_id', () => {
    expect(parseSubject('alice')).toEqual({ user_id: 'alice' });
  });
  it('passes a Subject object through (copied)', () => {
    const s = { user_id: 'bob', tenant_id: 't1' };
    expect(parseSubject(s)).toEqual(s);
    expect(parseSubject(s)).not.toBe(s);
  });
});

describe('useSubject', () => {
  it('binds the subject only within the scope', () => {
    expect(getCurrentSubject()).toBeUndefined();
    const inside = useSubject('user:alice', () => getCurrentSubject());
    expect(inside).toEqual({ user_id: 'alice' });
    expect(getCurrentSubject()).toBeUndefined();
  });

  it('survives awaits', async () => {
    const seen = await useSubject('user:alice;tenant:acme', async () => {
      await Promise.resolve();
      return getCurrentSubject();
    });
    expect(seen).toEqual({ user_id: 'alice', tenant_id: 'acme' });
  });

  it('nested scope merges over the enclosing subject (inner wins)', () => {
    const result = useSubject('user:alice;tenant:acme', () =>
      useSubject('user:bob', () => getCurrentSubject()),
    );
    // inner user_id overrides; enclosing tenant_id is retained
    expect(result).toEqual({ user_id: 'bob', tenant_id: 'acme' });
  });

  it('returns the callback value', () => {
    expect(useSubject('user:alice', () => 42)).toBe(42);
  });
});
