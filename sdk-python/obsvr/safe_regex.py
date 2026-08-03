"""Safe regex guard — parity with sdk-typescript/src/utils/safe-regex.ts.

Guards against ReDoS (catastrophic backtracking) from customer-supplied
regex patterns. Policy rules are dashboard-editable and executed inside the
customer's own process on every LLM call; a pathological pattern like
(a+)+$ would freeze the application thread.

Two layers of defense:
1. validate_regex_pattern() — static analysis at compile time.
2. safe_regex_search() — bounded input length at execution time.
"""
import re
from typing import Dict, Optional, Tuple

MAX_PATTERN_LENGTH = 512
MAX_QUANTIFIERS = 20
MAX_INPUT_LENGTH = 50_000

# Quantified alternation: (a|aa)+
_QUANTIFIED_ALTERNATION = re.compile(r"\((?:[^()\\]|\\.)*\|(?:[^()\\]|\\.)*\)\s*[+*{]")
_BACKREFERENCE = re.compile(r"\\[1-9]")
_QUANTIFIER_COUNT = re.compile(r"[+*?]|\{\d+(,\d*)?\}")
_BRACE_REP = re.compile(r"\{\d+,\d*\}")
_BRACE_FIXED = re.compile(r"\{(\d+)\}")


def _has_nested_repetition(pattern: str) -> bool:
    """Structurally detect a repetition quantifier applied to a group that
    itself (at ANY nesting depth) contains a repetition — the catastrophic-
    backtracking shape: ``(a+)+``, ``(a{2,})+``, ``((a+)b?)+``, ``([a-z]{3,})*``.

    The prior regex saw only one paren level and missed brace quantifiers, so
    ``(a{2,})+`` and ``((a+)b?)+`` passed and could hang the thread for minutes
    (Python ``re`` has no timeout; the 50 KB input cap does not tame super-linear
    backtracking). A "repetition" grows the match: ``+``, ``*``, or a comma-
    bearing brace (``{n,}`` / ``{n,m}``); a fixed ``{n}`` and ``?`` do not grow.
    Character classes and escapes are skipped so ``[+*]`` / ``\\+`` read literally.

    A fixed ``{n}`` earns one exception: applied to a group that CONTAINS its
    own growth quantifier or alternation, it multiplies that group's
    backtracking states n times over — ``(.*a){20}b`` stacks twenty
    independent ``.*`` engines against one impossible suffix and stalls for
    minutes, without ever growing the match. ``{1}`` and a fixed brace on a
    plain group stay allowed.
    """
    n = len(pattern)

    def rep_at(j: int) -> int:
        if j >= n:
            return 0
        ch = pattern[j]
        if ch in "+*":
            return 1
        if ch == "{":
            m = _BRACE_REP.match(pattern, j)
            return len(m.group(0)) if m else 0
        return 0

    # Per open group: does it (transitively) contain a growth quantifier ("rep")
    # or a top-level alternation ("alt")? A growth quantifier on a group holding
    # EITHER is catastrophic — (a+)+ (nested quantifier) AND ((a|aa))+ (quantified
    # alternation wrapped a level deep, missed by the shallow regex).
    stack = [{"rep": False, "alt": False}]
    i = 0
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            while i < n and pattern[i] != "]":
                if pattern[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if c == "(":
            stack.append({"rep": False, "alt": False})
            i += 1
            continue
        if c == "|":
            stack[-1]["alt"] = True
            i += 1
            continue
        if c == ")":
            frame = stack.pop() if len(stack) > 1 else {"rep": False, "alt": False}
            rlen = rep_at(i + 1)
            if rlen > 0 and (frame["rep"] or frame["alt"]):
                return True
            # The fixed-brace exception documented above: {n>=2} on a
            # rep/alt-bearing group is the multiplied-backtracking shape.
            if frame["rep"] or frame["alt"]:
                fixed = _BRACE_FIXED.match(pattern, i + 1)
                if fixed and int(fixed.group(1)) >= 2:
                    return True
            stack[-1]["rep"] = stack[-1]["rep"] or frame["rep"] or rlen > 0
            stack[-1]["alt"] = stack[-1]["alt"] or frame["alt"]
            i += 1 + rlen
            continue
        rlen = rep_at(i)
        if rlen > 0:
            stack[-1]["rep"] = True
            i += rlen
            continue
        i += 1
    return False


# Constructs whose SYNTAX one engine accepts and the other does not, or that
# both accept and read differently. A ``regex`` rule is authored once and run by
# two engines, so a construct in this set enforces in one language and is inert
# (or means something else) in the other -- the same rule, the same input, a
# different verdict, with nothing on the record to say so.
#
# Measured across 30 diverging adversarial cases in 17 construct families. See
# the TypeScript twin (sdk-typescript/src/utils/safe-regex.ts,
# ``crossDialectViolation``) for the full enumeration; the two lists must stay
# identical or a rule accepted here is rejected there, which is the same defect
# one layer down.
#
# Rejecting is the only resolution that makes the parity claim true, and it is
# the SAFE direction: a rejected rule is loud. It fires the existing
# ``sdk:rule_rejected`` signal and lands on the audit record naming the id, so a
# rule that stops enforcing is visible rather than silently one-sided.
#
# NOT covered here, and deliberately: ``\d`` ``\w`` ``\s`` ``\b`` and their
# negations are Unicode-aware here and ASCII-only in JS; ``$`` matches before a
# trailing newline here and not in JS; ``.`` matches U+000D and U+2028 here and
# neither in JS. Those are SEMANTIC splits with no syntactic marker, so they
# cannot be rejected without banning the most common constructs in the language.
# They are enumerated in SECURITY.md instead.
_CROSS_DIALECT_CONSTRUCTS = [
    (re.compile(r"\(\?P[<=]"), "python_only_named_group"),
    (re.compile(r"\(\?[a-zA-Z]+[):]"), "python_only_inline_flags"),
    (re.compile(r"\(\?>"), "python_only_atomic_group"),
    (re.compile(r"(?:[*+?]|\{\d+(?:,\d*)?\})\+"), "python_only_possessive_quantifier"),
    (re.compile(r"\{,\d+\}"), "brace_quantifier_without_lower_bound"),
    (re.compile(r"\(\?<[a-zA-Z_$]"), "js_only_named_group"),
    (re.compile(r"--\["), "js_only_class_set_operation"),
]

# Escapes both engines read the same way. Anything else alphabetic is split.
_SHARED_ALPHA_ESCAPES = set("dDwWsSbBnrtfv0xu")


def _has_variable_width_lookbehind(pattern: str) -> bool:
    """JS accepts variable-width lookbehind; Python raises, so the whole rule is
    inert here while it enforces there."""
    i = pattern.find("(?<")
    while i != -1:
        if pattern[i + 3 : i + 4] in ("=", "!"):
            depth = 0
            j = i
            while j < len(pattern):
                if pattern[j] == "\\":
                    j += 2
                    continue
                if pattern[j] == "(":
                    depth += 1
                elif pattern[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            body = re.sub(r"\\.", "", pattern[i + 4 : j])
            if re.search(r"[*+?]|\{\d*,\d*\}", body):
                return True
        i = pattern.find("(?<", i + 1)
    return False


def cross_dialect_violation(pattern: str):
    """Reason a pattern does not mean the same thing in both engines, or None.

    Twin: ``crossDialectViolation`` in sdk-typescript/src/utils/safe-regex.ts.
    """
    for rx, reason in _CROSS_DIALECT_CONSTRUCTS:
        if rx.search(pattern):
            return reason
    i = 0
    while i < len(pattern) - 1:
        if pattern[i] != "\\":
            i += 1
            continue
        c = pattern[i + 1]
        if c.isascii() and c.isalpha() and c not in _SHARED_ALPHA_ESCAPES:
            return "non_portable_escape (\\%s)" % c
        i += 2
    if _has_variable_width_lookbehind(pattern):
        return "variable_width_lookbehind"
    return None


def validate_regex_pattern(pattern: str) -> Tuple[bool, Optional[str]]:
    """Statically validate a customer-supplied pattern.

    Returns (ok, reason). Call at rule-write time AND compile time.
    """
    if not isinstance(pattern, str) or not pattern:
        return False, "empty_pattern"
    if len(pattern) > MAX_PATTERN_LENGTH:
        return False, f"pattern_too_long (max {MAX_PATTERN_LENGTH})"

    try:
        re.compile(pattern)
    except re.error:
        return False, "invalid_syntax"

    if _BACKREFERENCE.search(pattern):
        return False, "backreferences_not_allowed"
    # Simple quantified alternation first (descriptive reason for (a|aa)+); the
    # structural scan then catches wrapped/nested forms ((a|aa))+ the shallow
    # regex misses, plus all nested quantifiers.
    if _QUANTIFIED_ALTERNATION.search(pattern):
        return False, "quantified_alternation"
    if _has_nested_repetition(pattern):
        return False, "nested_quantifier"

    quantifiers = _QUANTIFIER_COUNT.findall(pattern)
    if len(quantifiers) > MAX_QUANTIFIERS:
        return False, f"too_many_quantifiers (max {MAX_QUANTIFIERS})"

    # Cross-dialect portability LAST, so a pattern that is also unsafe still
    # reports the safety reason -- a ReDoS pattern is a worse finding than a
    # non-portable one and should not be masked by it.
    dialect = cross_dialect_violation(pattern)
    if dialect:
        return False, f"not_portable_across_sdks: {dialect}"

    return True, None


_compiled_cache: Dict[str, Optional[re.Pattern]] = {}
_CACHE_MAX = 500


def compile_safe_regex(pattern: str) -> Optional[re.Pattern]:
    """Compile through the validator, with caching. Returns None if rejected."""
    if pattern in _compiled_cache:
        return _compiled_cache[pattern]
    ok, _reason = validate_regex_pattern(pattern)
    compiled = re.compile(pattern) if ok else None
    if len(_compiled_cache) >= _CACHE_MAX:
        _compiled_cache.clear()
    _compiled_cache[pattern] = compiled
    return compiled


def safe_regex_search(pattern: str, text: str) -> bool:
    """Bounded regex search. Rejected patterns are treated as no-match."""
    compiled = compile_safe_regex(pattern)
    if compiled is None:
        return False
    bounded = text[:MAX_INPUT_LENGTH] if len(text) > MAX_INPUT_LENGTH else text
    return bool(compiled.search(bounded))
