import { shouldSample } from '../../src/proxy/sender/sampling';

describe('shouldSample', () => {
  it('should always return false for sample_rate 0', () => {
    for (let i = 0; i < 100; i++) {
      expect(shouldSample(0)).toBe(false);
    }
  });

  it('should always return true for sample_rate 1', () => {
    for (let i = 0; i < 100; i++) {
      expect(shouldSample(1)).toBe(true);
    }
  });

  it('should return true approximately sample_rate percent of the time', () => {
    // Test with 50% sample rate
    const iterations = 10000;
    let trueCount = 0;

    for (let i = 0; i < iterations; i++) {
      if (shouldSample(0.5)) {
        trueCount++;
      }
    }

    const ratio = trueCount / iterations;
    // Allow 5% tolerance
    expect(ratio).toBeGreaterThan(0.45);
    expect(ratio).toBeLessThan(0.55);
  });

  it('should handle edge cases', () => {
    expect(shouldSample(-0.5)).toBe(false);
    expect(shouldSample(1.5)).toBe(true);
  });
});
