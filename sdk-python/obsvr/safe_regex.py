"""Safe regex guard — parity with sdk/src/utils/safe-regex.ts.

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
