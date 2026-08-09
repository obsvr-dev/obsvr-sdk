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
import warnings
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
# The SEMANTIC splits -- ``\d`` ``\w`` ``\s`` ``\b`` ``$`` ``.`` -- are NOT in
# this list, because rejection is the wrong instrument for them: they have no
# syntactic marker, and banning them would ban the most common constructs in the
# language. They are closed by NORMALIZATION instead, at the one compile call --
# see ``_ecmascript_equivalent`` below. One position needs a rejection even so,
# and it is the last entry in the list.
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


def _character_class_spans(pattern: str):
    """Yield ``(open_index, close_index)`` for every character class.

    A leading ``^`` and a leading ``]`` are literal members, which both engines
    agree on -- ``[]]`` is a class containing ``]`` in each. Escapes are skipped
    so ``[\\]]`` reads as one member and not as a class that ends early.
    """
    n = len(pattern)
    i = 0
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c != "[":
            i += 1
            continue
        start = i
        i += 1
        if i < n and pattern[i] == "^":
            i += 1
        if i < n and pattern[i] == "]":
            i += 1
        while i < n and pattern[i] != "]":
            if pattern[i] == "\\":
                i += 1
            i += 1
        yield start, min(i, n)
        i += 1


def _unsaturated_negated_space_in_class(pattern: str) -> bool:
    """Is ``\\S`` used inside a character class that does not also hold ``\\s``?

    The ONE position the normalizer below cannot reach. ``\\s`` inside a class is
    spliced out into the explicit ECMAScript whitespace set; ``\\S`` cannot be,
    because Python ``re`` has no class subtraction and a NEGATED shorthand is not
    expressible inside a POSITIVE class.

    A class holding BOTH is exempt, and provably so rather than by convenience:
    the spliced ``\\s`` covers exactly the six ASCII spaces the ASCII ``\\S``
    omits, so ``[\\s\\S]`` denotes every character in both engines -- and
    ``[^\\s\\S]`` denotes none in both. That is the dotall idiom people actually
    write, and it stays legal. ``[\\S]``, ``[a\\S]`` and ``[^\\S]`` do not:
    ASCII ``\\S`` admits the nineteen non-ASCII spaces that ECMAScript ``\\S``
    refuses, and nothing inside the class can take them back out.

    Rejecting is the SAFE direction here for the same reason it is for the
    syntax splits above: a rejected rule fires ``sdk:rule_rejected`` and lands on
    the audit record naming the id, so a rule that stops enforcing is visible
    rather than silently one-sided. The fix is one character: write ``\\s`` in a
    negated class instead.
    """
    for start, end in _character_class_spans(pattern):
        body = pattern[start:end]
        if "\\S" in body and "\\s" not in body:
            return True
    return False


def _unicode_mode_portability_violation(pattern: str) -> Optional[str]:
    """Syntax legacy JS accepts but Python and ECMAScript ``u`` do not share."""
    in_class = False
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            if i + 1 >= len(pattern):
                return "trailing_escape"
            nxt = pattern[i + 1]
            if nxt == "u" and i + 2 < len(pattern) and pattern[i + 2] == "{":
                return "unicode_codepoint_escape"
            raw_hex = pattern[i + 2 : i + 6]
            if nxt == "u" and len(raw_hex) == 4 and all(ch in "0123456789abcdefABCDEF" for ch in raw_hex):
                value = int(raw_hex, 16)
                if 0xD800 <= value <= 0xDFFF:
                    return "surrogate_escape"
                i += 6
                continue
            if not nxt.isalnum() or not nxt.isascii():
                allowed = "^-]\\/" if in_class else "^$\\.*+?()[]{}|/"
                if nxt not in allowed:
                    return f"identity_escape (\\{nxt})"
            i += 2
            continue
        if c == "[":
            in_class = True
            if i + 1 < len(pattern) and pattern[i + 1] == "^":
                i += 1
            if i + 1 < len(pattern) and pattern[i + 1] == "]":
                return "leading_literal_close_bracket"
            i += 1
            continue
        if c == "]":
            if not in_class:
                return "unescaped_close_bracket"
            in_class = False
            i += 1
            continue
        if not in_class and c == "{":
            quantifier = re.match(r"\{\d+(?:,\d*)?\}", pattern[i:])
            if not quantifier:
                return "unescaped_open_brace"
            i += len(quantifier.group(0))
            continue
        if not in_class and c == "}":
            return "unescaped_close_brace"
        i += 1
    return None


def cross_dialect_violation(pattern: str):
    """Reason a pattern does not mean the same thing in both engines, or None.

    Twin: ``crossDialectViolation`` in sdk-typescript/src/utils/safe-regex.ts.
    """
    for rx, reason in _CROSS_DIALECT_CONSTRUCTS:
        if rx.search(pattern):
            return reason
    if _unsaturated_negated_space_in_class(pattern):
        return "negated_space_shorthand_in_class (\\S)"
    unicode_mode = _unicode_mode_portability_violation(pattern)
    if unicode_mode:
        return unicode_mode
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


#: CPython's ``re`` parser warns when a character class LOOKS like it is using
#: another dialect's set operation. Enumerated rather than matched by a prefix:
#: a variant CPython adds later then leaks -- visibly, and in the safe
#: direction -- instead of being silently swallowed by a loose pattern.
_SET_OPERATION_WARNING = (
    r"Possible (nested set|set (difference|intersection|symmetric difference|union))"
)


def _compiles_quietly(pattern: str) -> bool:
    """Is ``pattern`` syntactically valid to this engine? Answered silently.

    A SYNTAX PROBE, and its only output is the boolean it returns. ``re``
    writes a ``FutureWarning`` to stderr for a class like ``[\\w--[0-9]]`` or
    ``[[a]]``, so validating a customer rule printed into the host application's
    logs from a call the host never asked to be noisy -- and the SDK had already
    decided what to do about that pattern.

    Three things this deliberately does NOT do:

    * It does not filter globally. A process-wide filter would silence the same
      warning for the host's own regexes, which are not obsvr's to quiet.
    * It does not reach the OPERATIVE compile in ``compile_safe_regex``. That
      one builds the object that will run against customer data, so a warning
      there is about a pattern the SDK is about to execute and an operator
      should see it. ``[[a]]`` passes validation and still warns from there;
      that boundary is deliberate, not an oversight.
    * It does not suppress by category alone. ``catch_warnings`` swaps
      PROCESS-GLOBAL filter state for the duration of the block, and governed
      calls arrive on whatever thread the application uses, so a concurrent
      warning can fall inside the window. Narrowing to this one message family
      bounds that to a warning this would have suppressed anyway.
    """
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", category=FutureWarning, message=_SET_OPERATION_WARNING
        )
        try:
            re.compile(pattern)
        except re.error:
            return False
    return True


def validate_regex_pattern(pattern: str) -> Tuple[bool, Optional[str]]:
    """Statically validate a customer-supplied pattern.

    Returns (ok, reason). Call at rule-write time AND compile time.
    """
    if not isinstance(pattern, str) or not pattern:
        return False, "empty_pattern"
    if len(pattern) > MAX_PATTERN_LENGTH:
        return False, f"pattern_too_long (max {MAX_PATTERN_LENGTH})"

    if not _compiles_quietly(pattern):
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


# ── ECMAScript semantics for the shorthands ─────────────────────────────────
#
# A customer ``regex`` rule is authored ONCE and run by TWO engines, and six
# constructs read differently in each. They carry no syntactic marker, so the
# validator above cannot refuse them without banning ``\d``. The resolution is
# to make one engine's meaning the meaning, and ECMAScript wins:
#
#   * Python can express ECMAScript's shorthand semantics exactly -- ``re.ASCII``
#     plus a mechanical rewrite for the rest. TypeScript compiles in ``u`` mode
#     so both engines consume astral characters as code points; the shared
#     portability guard rejects syntax accepted only by legacy JS mode.
#   * ASCII classes are what a rule author means by ``\d`` in an SSN or a card
#     number, which is what these rules are written for.
#   * It is one compile call in one file, so nothing already measured on the
#     TypeScript side moves.
#
# Measured per codepoint across the whole BMP, both engines, before and after:
# ``re.ASCII`` alone aligns ``\d`` ``\D`` ``\w`` ``\W`` ``\b`` ``\B`` EXACTLY and
# leaves three families open -- and it makes ``\s`` WORSE, from 6 disagreeing
# codepoints to 19, because ECMAScript ``\s`` is neither Python's Unicode set nor
# its ASCII one. The rewrite below closes those three:
#
#   ``\s`` / ``\S``  ->  the explicit ECMAScript WhiteSpace + LineTerminator set
#   ``.``            ->  ``[^\n\r\u2028\u2029]``  (JS excludes all four
#                        LineTerminators; Python's dot excludes only ``\n``)
#   ``$``            ->  ``\Z``  (Python's ``$`` also matches before a trailing
#                        newline; ECMAScript's, without ``m``, does not)
#
# ``^`` needs no rewrite: without MULTILINE / ``m`` both mean start-of-input.
#
# Code-point parity is closed at the TypeScript compile call with ``u`` mode.
# The portability validator moved with it: identity escapes, unmatched braces
# and brackets, braced codepoint escapes, and surrogate escapes are rejected in
# both SDKs rather than reopening a syntax split in the other direction.

#: ECMAScript ``\s``: WhiteSpace + LineTerminator (ECMA-262), as a class BODY so
#: it can be spliced into a customer's own class as well as stand alone.
_JS_SPACE_BODY = (
    "\\t\\n\\x0b\\f\\r \\u00a0\\u1680\\u2000-\\u200a"
    "\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
)
#: ECMAScript LineTerminator: what ``.`` excludes without the ``s`` flag.
_JS_LINE_TERMINATORS = "\\n\\r\\u2028\\u2029"


def _ecmascript_equivalent(pattern: str) -> str:
    """Rewrite ``pattern`` so Python ``re`` (with ``re.ASCII``) reads it the way
    ECMAScript ``RegExp`` reads the original.

    Applied at COMPILE time, never at validation time: the customer's pattern is
    what gets validated, reported and hashed, and this is only what the engine is
    handed. A single left-to-right scan, because every rewrite is local and the
    only context that matters is whether the cursor is inside a character class.
    """
    out = []
    n = len(pattern)
    i = 0
    in_class = False
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt == "s":
                out.append(_JS_SPACE_BODY if in_class else "[" + _JS_SPACE_BODY + "]")
            elif nxt == "S" and not in_class:
                out.append("[^" + _JS_SPACE_BODY + "]")
            else:
                # Inside a class, ``\S`` reaches here and stays as it is. The
                # validator refuses the classes where that would diverge, so the
                # only ones left are the saturated ``[\s\S]`` family.
                out.append(c + nxt)
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            # A leading ``^`` and a leading ``]`` are literal members in both
            # engines; copying them here keeps the ``]`` from closing the class.
            if i < n and pattern[i] == "^":
                out.append(pattern[i])
                i += 1
            if i < n and pattern[i] == "]":
                out.append(pattern[i])
                i += 1
            continue
        if c == ".":
            out.append("[^" + _JS_LINE_TERMINATORS + "]")
            i += 1
            continue
        if c == "$":
            out.append("\\Z")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


_compiled_cache: Dict[str, Optional[re.Pattern]] = {}
_CACHE_MAX = 500


def compile_safe_regex(pattern: str) -> Optional[re.Pattern]:
    """Compile through the validator, with caching. Returns None if rejected.

    Compiled from the ECMAScript-equivalent rewrite, under ``re.ASCII``, so a
    rule authored once means one thing on both SDKs. The cache is keyed on the
    ORIGINAL pattern -- that is what a caller holds and what the audit record
    names.
    """
    if pattern in _compiled_cache:
        return _compiled_cache[pattern]
    ok, _reason = validate_regex_pattern(pattern)
    compiled = None
    if ok:
        try:
            compiled = re.compile(_ecmascript_equivalent(pattern), re.ASCII)
        except re.error:
            # The rewrite is mechanical and the original already compiled, so
            # this is unreachable in practice and pinned as such by the corpus
            # test. Reaching it means the rewrite produced something this engine
            # will not take, and the honest resolution is the one every rejected
            # pattern gets -- refuse loudly through the existing
            # ``sdk:rule_rejected`` signal -- rather than quietly falling back to
            # un-normalized semantics, which would restore the divergence this
            # exists to close and say nothing.
            compiled = None
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
