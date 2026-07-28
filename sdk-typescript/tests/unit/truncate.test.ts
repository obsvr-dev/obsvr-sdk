import { truncate, truncateString, safeStringify } from '../../src/utils/truncate';

describe('truncateString', () => {
  it('should return original string if under limit', () => {
    expect(truncateString('hello', 100)).toBe('hello');
  });

  it('should truncate and add marker if over limit', () => {
    const result = truncateString('hello world this is a very long string', 20);
    expect(result).toContain('[TRUNCATED]');
    expect(result.length).toBeLessThanOrEqual(20);
  });

  it('should handle exact length', () => {
    expect(truncateString('hello', 5)).toBe('hello');
  });

  it('should handle very small limit', () => {
    const result = truncateString('hello world', 5);
    expect(result).toBeTruthy();
  });
});

describe('safeStringify', () => {
  it('should return string as-is', () => {
    expect(safeStringify('hello')).toBe('hello');
  });

  it('should stringify objects', () => {
    expect(safeStringify({ a: 1 })).toBe('{"a":1}');
  });

  it('should handle null and undefined', () => {
    expect(safeStringify(null)).toBe('');
    expect(safeStringify(undefined)).toBe('');
  });

  it('should handle circular references', () => {
    const obj: any = { a: 1 };
    obj.self = obj;
    // Should not throw, should return some string
    expect(() => safeStringify(obj)).not.toThrow();
  });
});

describe('truncate', () => {
  it('should truncate string values', () => {
    expect(truncate('hello', 100)).toBe('hello');
  });

  it('should stringify and truncate objects', () => {
    const obj = { key: 'value' };
    const result = truncate(obj, 100);
    expect(result).toBe('{"key":"value"}');
  });

  it('should handle large objects', () => {
    const largeObj = { data: 'x'.repeat(1000) };
    const result = truncate(largeObj, 50);
    expect(result.length).toBeLessThanOrEqual(50);
    expect(result).toContain('[TRUNCATED]');
  });
});
