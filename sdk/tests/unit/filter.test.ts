import { filterArgs, hasAuditFields, getAuditFieldNames } from '../../src/proxy/filters/filter';

describe('filterArgs', () => {
  it('should extract audit fields from request args', () => {
    const args = [{
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hello' }],
      request_id: 'req_123',
      region: 'us-east-1',
      source: 'test_app',
      metadata: { user_id: 'user_123', session_id: 'sess_abc' }
    }];

    const result = filterArgs(args);

    // Cleaned args should not have audit fields
    expect(result.cleaned_args[0]).toEqual({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hello' }]
    });

    // Audit fields should be extracted
    expect(result.audit_fields).toEqual({
      request_id: 'req_123',
      region: 'us-east-1',
      source: 'test_app',
      metadata: { user_id: 'user_123', session_id: 'sess_abc' }
    });
  });

  it('should handle empty args', () => {
    const result = filterArgs([]);
    expect(result.cleaned_args).toEqual([]);
    expect(result.audit_fields).toEqual({});
  });

  it('should handle args without audit fields', () => {
    const args = [{
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hello' }],
      temperature: 0.7
    }];

    const result = filterArgs(args);

    expect(result.cleaned_args[0]).toEqual({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hello' }],
      temperature: 0.7
    });
    expect(result.audit_fields).toEqual({});
  });

  it('should handle non-object first argument', () => {
    const args = ['string_arg', { model: 'gpt-4' }];

    const result = filterArgs(args);

    expect(result.cleaned_args).toEqual(args);
    expect(result.audit_fields).toEqual({});
  });

  it('should only extract valid typed audit fields', () => {
    const args = [{
      model: 'gpt-4',
      request_id: 123, // Wrong type - should be string
      region: 'us-east-1',
      metadata: 'invalid' // Wrong type - should be object
    }];

    const result = filterArgs(args);

    // Invalid types should not be extracted
    expect(result.audit_fields).toEqual({
      region: 'us-east-1'
    });

    // Invalid audit fields should be removed from cleaned args
    expect(result.cleaned_args[0]).toEqual({
      model: 'gpt-4'
    });
  });
});

describe('hasAuditFields', () => {
  it('should return true when audit fields present', () => {
    expect(hasAuditFields({ request_id: 'req_123' })).toBe(true);
    expect(hasAuditFields({ metadata: {} })).toBe(true);
    expect(hasAuditFields({ region: 'us-east-1' })).toBe(true);
    expect(hasAuditFields({ source: 'app' })).toBe(true);
  });

  it('should return false when no audit fields', () => {
    expect(hasAuditFields({ model: 'gpt-4' })).toBe(false);
    expect(hasAuditFields({})).toBe(false);
  });

  it('should return false for non-objects', () => {
    expect(hasAuditFields('string')).toBe(false);
    expect(hasAuditFields(null)).toBe(false);
    expect(hasAuditFields(undefined)).toBe(false);
    expect(hasAuditFields([1, 2, 3])).toBe(false);
  });
});

describe('getAuditFieldNames', () => {
  it('should return all audit field names', () => {
    const names = getAuditFieldNames();
    expect(names).toContain('request_id');
    expect(names).toContain('region');
    expect(names).toContain('source');
    expect(names).toContain('metadata');
    expect(names).toHaveLength(4);
  });
});
