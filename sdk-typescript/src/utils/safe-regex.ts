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
      // A FIXED {n} does not grow the match, but applied to a group that
      // contains its own growth quantifier or alternation it multiplies that
      // group's backtracking states n times over — `(.*a){20}b` stacks twenty
      // independent `.*` engines against one impossible suffix and stalls for
      // minutes. `{1}` and a fixed brace on a plain group stay allowed.
      if (frame.rep || frame.alt) {
        const fixed = /^\{(\d+)\}/.exec(pattern.slice(i + 1));
        if (fixed && parseInt(fixed[1], 10) >= 2) return true;
      }
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
/**
 * Constructs whose SYNTAX one engine accepts and the other does not, or that
 * both accept and read differently. A `regex` rule is authored once and run by
 * two engines, so a construct in this set enforces in one language and is inert
 * (or means something else) in the other — the same rule, the same input, a
 * different verdict, with nothing on the record to say so.
 *
 * Measured across 30 diverging adversarial cases in 17 construct families:
 *
 *   Python-only syntax, invalid in JS:
 *     (?P<x>...)  (?P=x)   named group / backref
 *     (?i) (?s) (?m) (?x) (?a) (?u) (?L)  and the scoped form (?i:...)
 *     a*+ a++ a?+ a{2,}+   possessive quantifiers
 *     (?>...)              atomic group
 *     \A \Z \z            anchors — LITERAL 'A'/'Z' or invalid in JS
 *     a{,3}                a quantifier in Python, three literal characters in JS
 *   JS-only syntax, invalid in Python:
 *     (?<x>...)  \k<x>     named group / backref (Python spells these (?P<x>) )
 *     (?<=...) with a variable-width body — Python requires fixed width
 *     \p{...} \P{...}      Unicode property escapes
 *     [a--[b]]             character-class set operations
 *     \h and friends       an unknown alphabetic escape is a literal in JS and
 *                          a hard error in Python
 *
 * Rejecting is the only resolution that makes the parity claim true, and it is
 * the SAFE direction: a rejected rule is loud. It fires the existing
 * `sdk:rule_rejected` signal and lands on the audit record naming the id, so a
 * rule that stops enforcing is visible rather than silently one-sided. The
 * alternative — leaving it — is a rule an operator believes is deployed fleet-
 * wide that is enforcing on half the fleet.
 *
 * The SEMANTIC splits — `\d` `\w` `\s` `\b` `$` `.` — are NOT in this list, and
 * rejection is the wrong instrument for them: they carry no syntactic marker,
 * and banning them would ban the most common constructs in the language. They
 * are closed by NORMALIZATION on the Python side instead, at that SDK's one
 * compile call — ECMAScript's meaning is the meaning, so this engine is
 * untouched and nothing already measured here moves. See
 * `_ecmascript_equivalent` in sdk-python/obsvr/safe_regex.py for the rewrite and
 * the per-codepoint measurement behind it.
 *
 * One POSITION still needs a rejection, and it is `unsaturatedNegatedSpaceInClass`
 * below: `\S` inside a character class is the one place the rewrite cannot
 * reach, because a negated shorthand is not expressible inside a positive class
 * without class subtraction, which Python `re` does not have.
 */
const CROSS_DIALECT_CONSTRUCTS: Array<{ re: RegExp; reason: string }> = [
  { re: /\(\?P[<=]/, reason: "python_only_named_group" },
  { re: /\(\?[a-zA-Z]+[):]/, reason: "python_only_inline_flags" },
  { re: /\(\?>/, reason: "python_only_atomic_group" },
  { re: /(?:[*+?]|\{\d+(?:,\d*)?\})\+/, reason: "python_only_possessive_quantifier" },
  { re: /\{,\d+\}/, reason: "brace_quantifier_without_lower_bound" },
  { re: /\(\?<[a-zA-Z_$]/, reason: "js_only_named_group" },
  { re: /--\[/, reason: "js_only_class_set_operation" },
];

/** Escapes both engines read the same way. Anything else alphabetic is split. */
const SHARED_ALPHA_ESCAPES = new Set("dDwWsSbBnrtfv0xu".split(""));

/**
 * Reject a lookbehind whose body is not fixed-width. JS accepts variable-width
 * lookbehind; Python raises `look-behind requires fixed-width pattern`, so the
 * whole rule is inert there.
 */
function hasVariableWidthLookbehind(pattern: string): boolean {
  let i = pattern.indexOf("(?<");
  while (i !== -1) {
    const kind = pattern.slice(i + 3, i + 4);
    if (kind === "=" || kind === "!") {
      // Scan to the matching close paren, then look for a growth quantifier.
      let depth = 0;
      let j = i;
      for (; j < pattern.length; j++) {
        if (pattern[j] === "\\") { j++; continue; }
        if (pattern[j] === "(") depth++;
        else if (pattern[j] === ")") { depth--; if (depth === 0) break; }
      }
      const body = pattern.slice(i + 4, j);
      if (/[*+?]|\{\d*,\d*\}/.test(body.replace(/\\./g, ""))) return true;
    }
    i = pattern.indexOf("(?<", i + 1);
  }
  return false;
}

/**
 * Every character class in `pattern`, as `[openIndex, closeIndex)` spans.
 *
 * A leading `^` and a leading `]` are literal members, which both engines agree
 * on — `[]]` is a class containing `]` in each. Escapes are skipped so `[\]]`
 * reads as one member and not as a class that ends early.
 */
function characterClassSpans(pattern: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  const n = pattern.length;
  let i = 0;
  while (i < n) {
    if (pattern[i] === "\\") {
      i += 2;
      continue;
    }
    if (pattern[i] !== "[") {
      i++;
      continue;
    }
    const start = i;
    i++;
    if (pattern[i] === "^") i++;
    if (pattern[i] === "]") i++;
    while (i < n && pattern[i] !== "]") {
      if (pattern[i] === "\\") i++;
      i++;
    }
    spans.push([start, Math.min(i, n)]);
    i++;
  }
  return spans;
}

/**
 * Is `\S` used inside a character class that does not also hold `\s`?
 *
 * The ONE position Python's normalization cannot reach. `\s` inside a class is
 * spliced out into the explicit ECMAScript whitespace set; `\S` cannot be,
 * because Python `re` has no class subtraction and a NEGATED shorthand is not
 * expressible inside a POSITIVE class.
 *
 * A class holding BOTH is exempt, and provably so rather than by convenience:
 * the spliced `\s` covers exactly the six ASCII spaces the ASCII `\S` omits, so
 * `[\s\S]` denotes every character in both engines — and `[^\s\S]` denotes none
 * in both. That is the dotall idiom people actually write, and it stays legal.
 * `[\S]`, `[a\S]` and `[^\S]` do not: Python's ASCII `\S` admits the nineteen
 * non-ASCII spaces this engine's `\S` refuses, and nothing inside the class can
 * take them back out.
 *
 * Twin: `_unsaturated_negated_space_in_class` in sdk-python/obsvr/safe_regex.py.
 */
function unsaturatedNegatedSpaceInClass(pattern: string): boolean {
  return characterClassSpans(pattern).some(([start, end]) => {
    const body = pattern.slice(start, end);
    return body.includes("\\S") && !body.includes("\\s");
  });
}

/**
 * Reject any construct that does not mean the same thing in both engines.
 * Returns a reason, or null when the pattern is dialect-portable.
 */
export function crossDialectViolation(pattern: string): string | null {
  for (const { re, reason } of CROSS_DIALECT_CONSTRUCTS) {
    if (re.test(pattern)) return reason;
  }
  if (unsaturatedNegatedSpaceInClass(pattern)) {
    return "negated_space_shorthand_in_class (\\S)";
  }
  // Alphabetic escapes outside the shared set: a literal in JS, an error in
  // Python (\h), or an anchor in Python and a literal in JS (\A, \Z, \z).
  for (let i = 0; i < pattern.length - 1; i++) {
    if (pattern[i] !== "\\") continue;
    const c = pattern[i + 1];
    if (/[a-zA-Z]/.test(c) && !SHARED_ALPHA_ESCAPES.has(c)) {
      return `non_portable_escape (\\${c})`;
    }
    i++; // the escaped character is consumed
  }
  if (hasVariableWidthLookbehind(pattern)) return "variable_width_lookbehind";
  return null;
}

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

  // Cross-dialect portability LAST, so a pattern that is also unsafe still
  // reports the safety reason — a ReDoS pattern is a worse finding than a
  // non-portable one and should not be masked by it.
  const dialect = crossDialectViolation(pattern);
  if (dialect) return { ok: false, reason: `not_portable_across_sdks: ${dialect}` };

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
