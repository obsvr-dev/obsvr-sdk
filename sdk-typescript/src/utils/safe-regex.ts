/**
 * Safe Regex Utility
 *
 * Guards against ReDoS (catastrophic backtracking) from customer-supplied
 * regex patterns. Policy rules are stored in Firestore and editable from the
 * dashboard, then compiled and executed inside the customer's own process on
 * every LLM call - a pathological pattern like (a+)+$ would freeze the
 * customer's application thread.
 *
 * Two layers of defense:
 * 1. validateRegexPattern() - static analysis at compile time. Rejects
 *    patterns with nested quantifiers, quantified alternation-with-overlap,
 *    excessive length, or too many quantifiers.
 * 2. safeRegexTest() - bounded execution. Caps input length so even a
 *    pattern that passes static checks cannot backtrack over a large input.
 *
 * @packageDocumentation
 */

/** Maximum allowed pattern length. Long patterns are both a ReDoS and a maintainability smell. */
const MAX_PATTERN_LENGTH = 512;

/** Maximum quantifiers ({n,m}, +, *, ?) allowed in a single pattern. */
const MAX_QUANTIFIERS = 20;

/** Maximum input slice a customer regex is allowed to scan. */
const MAX_INPUT_LENGTH = 50_000;

/** Result of validating a pattern. */
export interface RegexValidationResult {
  ok: boolean;
  reason?: string;
}

/**
 * Structurally detect a repetition quantifier applied to a group that itself
 * (at ANY nesting depth) contains a repetition quantifier — the shape behind
 * catastrophic backtracking: (a+)+, (a{2,})+, ((a+)b?)+, ([a-z]{3,})*.
 *
 * The prior regex-based check only saw one paren level and was blind to brace
 * quantifiers, so `(a{2,})+$` and `((a+)b?)+$` passed and could hang the thread
 * for minutes on a 50 KB input (the length cap does not tame super-linear
 * backtracking). This paren-aware scan catches the nesting at any depth.
 *
 * A "repetition" grows the match: `+`, `*`, or a comma-bearing brace (`{n,}` /
 * `{n,m}`). A fixed `{n}` and an optional `?` do not grow and are not flagged.
 * Character classes and escapes are skipped so `[+*]` / `\+` read as literals.
 */
function hasNestedRepetition(pattern: string): boolean {
  const n = pattern.length;
  // Length of a growth quantifier starting at j, or 0 if none.
  const repAt = (j: number): number => {
    if (j >= n) return 0;
    const c = pattern[j];
    if (c === "+" || c === "*") return 1;
    if (c === "{") {
      const m = /^\{\d+,\d*\}/.exec(pattern.slice(j));
      return m ? m[0].length : 0;
    }
    return 0;
  };
  // Per open group: does it (transitively) contain a growth quantifier (`rep`)
  // or a top-level alternation (`alt`)? A growth quantifier applied to a group
  // containing EITHER is the catastrophic shape — `(a+)+` (nested quantifier)
  // AND `((a|aa))+` (quantified alternation wrapped a level deep, which the
  // shallow QUANTIFIED_ALTERNATION regex misses because the quantifier no longer
  // touches the alternation's own `)`).
  const stack: { rep: boolean; alt: boolean }[] = [{ rep: false, alt: false }];
  let i = 0;
  while (i < n) {
    const c = pattern[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "[") {
      // Skip a character class to its closing ']' (a leading '^'/']' is literal).
      i++;
      if (pattern[i] === "^") i++;
      if (pattern[i] === "]") i++;
      while (i < n && pattern[i] !== "]") {
        if (pattern[i] === "\\") i++;
        i++;
      }
      i++;
      continue;
    }
    if (c === "(") {
      stack.push({ rep: false, alt: false });
      i++;
      continue;
    }
    if (c === "|") {
      // A top-level `|` in the current group marks it as an alternation.
      stack[stack.length - 1].alt = true;
      i++;
      continue;
    }
    if (c === ")") {
      const frame = stack.length > 1 ? (stack.pop() as { rep: boolean; alt: boolean }) : { rep: false, alt: false };
      const rlen = repAt(i + 1);
      // Growth quantifier on a group that contains a quantifier OR an alternation.
      if (rlen > 0 && (frame.rep || frame.alt)) return true;
      const parent = stack[stack.length - 1];
      parent.rep = parent.rep || frame.rep || rlen > 0;
      parent.alt = parent.alt || frame.alt;
      i += 1 + rlen;
      continue;
    }
    const rlen = repAt(i);
    if (rlen > 0) {
      stack[stack.length - 1].rep = true;
      i += rlen;
      continue;
    }
    i++;
  }
  return false;
}

/**
 * Detect quantified alternation, e.g. (a|aa)+ - overlapping alternates under
 * a quantifier backtrack exponentially.
 */
const QUANTIFIED_ALTERNATION = /\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)\s*[+*{]/;

/**
 * Statically validate a customer-supplied regex pattern.
 *
 * Call this at rule-write time (dashboard / ingest /policies) AND at
 * compile time in the SDK - defense in depth, since rules written before
 * this guard existed may still be stored.
 */
export function validateRegexPattern(pattern: string): RegexValidationResult {
  if (typeof pattern !== "string" || pattern.length === 0) {
    return { ok: false, reason: "empty_pattern" };
  }
  if (pattern.length > MAX_PATTERN_LENGTH) {
    return { ok: false, reason: `pattern_too_long (max ${MAX_PATTERN_LENGTH})` };
  }

  // Syntactic validity first
  try {
    new RegExp(pattern);
  } catch {
    return { ok: false, reason: "invalid_syntax" };
  }

  // Backreferences force backtracking engines into exponential paths
  if (/\\[1-9]/.test(pattern)) {
    return { ok: false, reason: "backreferences_not_allowed" };
  }

  // Simple quantified alternation first (descriptive reason for `(a|aa)+`); the
  // structural scan below then catches the wrapped/nested forms `((a|aa))+` that
  // this shallow regex misses, plus all nested quantifiers.
  if (QUANTIFIED_ALTERNATION.test(pattern)) {
    return { ok: false, reason: "quantified_alternation" };
  }

  if (hasNestedRepetition(pattern)) {
    return { ok: false, reason: "nested_quantifier" };
  }

  const quantifierCount = (pattern.match(/[+*?]|\{\d+(,\d*)?\}/g) ?? []).length;
  if (quantifierCount > MAX_QUANTIFIERS) {
    return { ok: false, reason: `too_many_quantifiers (max ${MAX_QUANTIFIERS})` };
  }

  return { ok: true };
}

/** Cache of validated + compiled patterns so validation cost is paid once per pattern. */
const compiledCache = new Map<string, RegExp | null>();
const CACHE_MAX = 500;

/**
 * Compile a customer pattern through the safety validator, with caching.
 * Returns null for rejected patterns (callers should treat as no-match and
 * surface a policy-config warning, not throw).
 */
export function compileSafeRegex(pattern: string): RegExp | null {
  if (compiledCache.has(pattern)) {
    return compiledCache.get(pattern) ?? null;
  }
  const verdict = validateRegexPattern(pattern);
  const compiled = verdict.ok ? new RegExp(pattern) : null;
  if (compiledCache.size >= CACHE_MAX) {
    // Simple reset - policy rulesets are small; churn here means misuse
    compiledCache.clear();
  }
  compiledCache.set(pattern, compiled);
  return compiled;
}

/**
 * Execute a customer regex against text with bounded input.
 *
 * Static validation cannot catch every pathological pattern, so the input
 * is capped: even a slow pattern over 50KB stays in linear-feeling territory
 * rather than freezing the process on megabyte prompts.
 *
 * Returns false (no match) for rejected patterns.
 */
export function safeRegexTest(pattern: string, text: string): boolean {
  const re = compileSafeRegex(pattern);
  if (!re) return false;
  const bounded = text.length > MAX_INPUT_LENGTH ? text.slice(0, MAX_INPUT_LENGTH) : text;
  return re.test(bounded);
}
