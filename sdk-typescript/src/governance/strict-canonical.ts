export const STRICT_IDENTIFIER_MAX_BYTES = 256;
export const STRICT_SET_MAX_ITEMS = 64;
export const STRICT_TARGET_MAX_BYTES = 1_024;
export const STRICT_CONTEXT_MAX_BYTES = 65_536;
export const STRICT_PRIOR_ACTIONS_MAX_ITEMS = 256;

export type StrictCanonicalFailure = (message: string) => never;

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function isAsciiWhitespace(code: number): boolean {
  return code === 0x20 || (code >= 0x09 && code <= 0x0d);
}

export function boundedCanonicalText(
  value: unknown,
  field: string,
  maxBytes: number,
  fail: StrictCanonicalFailure,
): string {
  if (typeof value !== 'string') fail(`${field} must be a nonblank string`);
  if (hasUnpairedSurrogate(value)) fail(`${field} contains an unpaired surrogate`);
  if (value.length === 0
    || Array.from(value, (character) => character.codePointAt(0) as number)
      .every(isAsciiWhitespace)) {
    fail(`${field} must be a nonblank string`);
  }
  if (Buffer.byteLength(value, 'utf8') > maxBytes) {
    fail(`${field} exceeds ${maxBytes} UTF-8 bytes`);
  }
  return value;
}

export function compareCodePoints(left: string, right: string): number {
  const a = Array.from(left, (character) => character.codePointAt(0) as number);
  const b = Array.from(right, (character) => character.codePointAt(0) as number);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

export function normalizedBoundedSet(
  value: unknown,
  field: string,
  maxItems: number,
  maxItemBytes: number,
  fail: StrictCanonicalFailure,
): string[] {
  if (!Array.isArray(value)) fail(`${field} must be an array`);
  if (value.length > maxItems) fail(`${field} exceeds ${maxItems} items`);
  const values = value.map((entry, index) => (
    boundedCanonicalText(entry, `${field}[${index}]`, maxItemBytes, fail)
  ));
  values.sort(compareCodePoints);
  return values.filter((entry, index) => index === 0 || entry !== values[index - 1]);
}
