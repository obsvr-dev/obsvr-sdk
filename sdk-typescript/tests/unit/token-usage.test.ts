/**
 * The token normaliser: what it reads, and — the part that matters — what it
 * refuses to invent.
 *
 * The defect this replaced was not a crash. Eleven sites read tokens with
 * `|| 0`, so an upstream rename produced `input_tokens: 0` — a measurement that
 * never happened, sitting in a signed audit record, indistinguishable from a
 * call that genuinely consumed nothing. The nested-object case was worse still:
 * `{...} || 0` is truthy, so the object itself landed in a numeric field.
 *
 * So the assertions below are mostly negative. A count obsvr could not read
 * must be ABSENT, and a usage payload obsvr could not parse must say so.
 */
import {
  normalizeTokenUsage,
  readTokenUsage,
} from '../../src/proxy/extractors/token-usage';

describe('normalizeTokenUsage — the shapes it accepts', () => {
  it('reads snake_case wire format (OpenAI chat)', () => {
    expect(
      readTokenUsage({ prompt_tokens: 9, completion_tokens: 3, total_tokens: 12 }),
    ).toEqual({ input_tokens: 9, output_tokens: 3, total_tokens: 12 });
  });

  it('reads snake_case wire format (Responses / Anthropic)', () => {
    expect(readTokenUsage({ input_tokens: 11, output_tokens: 2 })).toEqual({
      input_tokens: 11,
      output_tokens: 2,
      total_tokens: 13,
    });
  });

  it('reads Gemini usageMetadata naming', () => {
    expect(
      readTokenUsage({
        promptTokenCount: 5,
        candidatesTokenCount: 7,
        totalTokenCount: 12,
      }),
    ).toEqual({ input_tokens: 5, output_tokens: 7, total_tokens: 12 });
  });

  it('reads flat camelCase (AI SDK spec v2)', () => {
    expect(
      readTokenUsage({ inputTokens: 9, outputTokens: 3, totalTokens: 12 }),
    ).toEqual({ input_tokens: 9, output_tokens: 3, total_tokens: 12 });
  });

  it('reads the legacy camelCase naming (AI SDK spec v1)', () => {
    expect(
      readTokenUsage({ promptTokens: 9, completionTokens: 3, totalTokens: 12 }),
    ).toEqual({ input_tokens: 9, output_tokens: 3, total_tokens: 12 });
  });

  it('reads the NESTED shape and derives the total that spec v3 deleted', () => {
    // The exact payload measured off ai@7.0.41. `totalTokens` does not exist at
    // this spec version, so the total can only come from the two counts.
    expect(
      readTokenUsage({
        inputTokens: { total: 9, noCache: 9, cacheRead: 0, cacheWrite: 0 },
        outputTokens: { total: 3, text: 3, reasoning: 0 },
        raw: { input_tokens: 9, output_tokens: 3 },
      }),
    ).toEqual({ input_tokens: 9, output_tokens: 3, total_tokens: 12 });
  });

  it('reads a nested shape whose inner total is missing as absent, not zero', () => {
    // spec v3 declares every inner field `number | undefined`.
    expect(
      readTokenUsage({
        inputTokens: { total: undefined, noCache: 9 },
        outputTokens: { total: 3 },
      }),
    ).toEqual({ output_tokens: 3 });
  });

  it('reads the Bedrock Titan input count', () => {
    expect(readTokenUsage({ inputTextTokenCount: 14 })).toEqual({
      input_tokens: 14,
    });
  });
});

describe('normalizeTokenUsage — it never fabricates', () => {
  it('absent usage yields no counts and reports "absent"', () => {
    for (const container of [undefined, null, 0, '', false]) {
      expect(normalizeTokenUsage(container)).toEqual({ shape: 'absent' });
    }
  });

  it('an empty usage object is "absent", not a failure to parse', () => {
    // A provider that sent `usage: {}` reported nothing, which is the same fact
    // as sending no usage at all — not a shape obsvr failed to understand.
    expect(normalizeTokenUsage({})).toEqual({ shape: 'absent' });
  });

  it('an UNRECOGNISED payload reports itself instead of counting as zero', () => {
    // This is the case the old `|| 0` sites turned into `input_tokens: 0`.
    const r = normalizeTokenUsage({ tokens_consumed: 42, billing_units: 3 });
    expect(r.shape).toBe('unrecognized');
    expect(r.usage).toBeUndefined();
  });

  it('a half-known payload stays half-known', () => {
    const r = normalizeTokenUsage({ output_tokens: 3 });
    expect(r.shape).toBe('recognized');
    expect(r.usage).toEqual({ output_tokens: 3 });
    // No fabricated input, and therefore no total derived from one.
    expect(r.usage).not.toHaveProperty('input_tokens');
    expect(r.usage).not.toHaveProperty('total_tokens');
  });

  it('a non-numeric count is absent, never coerced', () => {
    const r = normalizeTokenUsage({ input_tokens: 'nine', output_tokens: null });
    expect(r.shape).toBe('unrecognized');
    expect(r.usage).toBeUndefined();
  });

  it('NaN and Infinity are not counts', () => {
    expect(normalizeTokenUsage({ input_tokens: NaN }).usage).toBeUndefined();
    expect(normalizeTokenUsage({ input_tokens: Infinity }).usage).toBeUndefined();
  });

  it('a genuine zero survives as zero, and is not confused with absent', () => {
    // The whole point of refusing to fabricate is that a real 0 keeps meaning
    // something. A cached-prompt call really can bill zero new input tokens.
    const r = normalizeTokenUsage({ input_tokens: 0, output_tokens: 5 });
    expect(r.usage).toEqual({ input_tokens: 0, output_tokens: 5, total_tokens: 5 });
  });

  it('a genuine zero on the first alias does not fall through to the next', () => {
    // `||`-chained alias lookup used to skip a real 0 and land on a later alias
    // (or on undefined). Presence, not truthiness, decides.
    expect(readTokenUsage({ input_tokens: 0, prompt_tokens: 99 })).toEqual({
      input_tokens: 0,
    });
  });

  it('an object where a number belongs never reaches the event', () => {
    // `{...} || 0` is truthy and returned the OBJECT, producing a malformed
    // event no schema check rejected. An object with no numeric `total` is
    // simply unreadable.
    const r = normalizeTokenUsage({ inputTokens: { noCache: 9 } });
    expect(r.usage).toBeUndefined();
    expect(r.shape).toBe('unrecognized');
  });
});
