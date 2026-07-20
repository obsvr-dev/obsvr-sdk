"""Matching-time text normalization (§6).

EXACT parity with sdk/src/policy/normalize.ts.

Attackers bypass keyword / regex / PII / injection rules with lookalike or
invisible characters: a fullwidth "ｏｖｅｒｒｉｄｅ",
a Cyrillic "оverride", or a zero-width-joined "over‍ride" all read as
"override" to a human (and to the model) but slip past a naive
``"override" in text``.

``normalize_for_matching`` collapses those tricks to a canonical form BEFORE the
scanners match, in three deterministic steps:

    1. Unicode NFKC -- folds compatibility variants (fullwidth, ligatures,
       circled/super/subscript forms) to their canonical characters.
    2. Strip zero-width / invisible format characters (ZWSP, ZWNJ, ZWJ, word
       joiner, BOM, soft hyphen, Mongolian vowel separator).
    3. A small, curated confusable fold -- the highest-value Latin lookalikes
       from Cyrillic and Greek that NFKC does NOT fold (they are distinct
       letters, not compatibility equivalents).

CRITICAL: this is a MATCHING-ONLY transform. It is applied to the copy the
scanners inspect, never to the stored/forwarded prompt or response. The audit
must reflect what the user actually sent -- normalization changes what we
DETECT, not what we RECORD (redaction is the only content mutation, and it runs
on the original text). Kept intentionally minimal and launch-safe.

The step order and character tables are pinned by
conformance/fixtures/normalization.json and must stay byte-for-byte identical to
the TypeScript twin (sdk/src/policy/normalize.ts).
"""

import re
import unicodedata
from typing import List, Tuple

# Zero-width / invisible format characters removed before matching. These carry
# no visible glyph, so removing them cannot change what a human reads -- only
# what a regex sees.
#   U+200B ZERO WIDTH SPACE, U+200C ZWNJ, U+200D ZWJ, U+2060 WORD JOINER,
#   U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM), U+00AD SOFT HYPHEN,
#   U+180E MONGOLIAN VOWEL SEPARATOR.
_ZERO_WIDTH_CODEPOINTS = [
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E,
    # Bidirectional format controls: invisible, and interleavable into
    # keywords/injection payloads to evade matching. LRM/RLM, the embedding /
    # override / pop-directional-format set, and the isolates.
    0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
]
_ZERO_WIDTH_RE = re.compile("[" + "".join(chr(cp) for cp in _ZERO_WIDTH_CODEPOINTS) + "]")

# Curated confusable fold: Latin-lookalike codepoints from Cyrillic and Greek
# that NFKC leaves untouched, mapped to their ASCII twin. Deliberately small --
# only the letters common in real bypass attempts -- so the fold never mangles
# legitimate non-Latin text more than necessary. Listed as (codepoint, ascii)
# so the table is unambiguous and trivially matchable to the TypeScript twin.
_CONFUSABLE_PAIRS = [
    # -- Cyrillic -> Latin (lowercase) --
    (0x0430, "a"),  # а
    (0x0435, "e"),  # е
    (0x043E, "o"),  # о
    (0x0440, "p"),  # р
    (0x0441, "c"),  # с
    (0x0445, "x"),  # х
    (0x0443, "y"),  # у
    (0x0455, "s"),  # ѕ
    (0x0456, "i"),  # і
    (0x0458, "j"),  # ј
    (0x04BB, "h"),  # һ
    # -- Cyrillic -> Latin (uppercase) --
    (0x0410, "A"),  # А
    (0x0412, "B"),  # В
    (0x0415, "E"),  # Е
    (0x041A, "K"),  # К
    (0x041C, "M"),  # М
    (0x041D, "H"),  # Н
    (0x041E, "O"),  # О
    (0x0420, "P"),  # Р
    (0x0421, "C"),  # С
    (0x0422, "T"),  # Т
    (0x0425, "X"),  # Х
    # -- Greek -> Latin --
    (0x03BF, "o"),  # ο (small omicron)
    (0x03B1, "a"),  # α (small alpha)
    (0x03C1, "p"),  # ρ (small rho)
    (0x03BD, "v"),  # ν (small nu)
    (0x0391, "A"),  # Α (capital alpha)
    (0x0392, "B"),  # Β (capital beta)
    (0x0395, "E"),  # Ε (capital epsilon)
    (0x0397, "H"),  # Η (capital eta)
    (0x0399, "I"),  # Ι (capital iota)
    (0x039A, "K"),  # Κ (capital kappa)
    (0x039C, "M"),  # Μ (capital mu)
    (0x039D, "N"),  # Ν (capital nu)
    (0x039F, "O"),  # Ο (capital omicron)
    (0x03A1, "P"),  # Ρ (capital rho)
    (0x03A4, "T"),  # Τ (capital tau)
    (0x03A7, "X"),  # Χ (capital chi)
]

_CONFUSABLES = {chr(cp): ascii_ch for cp, ascii_ch in _CONFUSABLE_PAIRS}
# str.translate wants an int->str mapping.
_TRANSLATE_TABLE = {cp: ascii_ch for cp, ascii_ch in _CONFUSABLE_PAIRS}


def strip_invisible_chars(text: str) -> str:
    """Remove zero-width / bidi / invisible format characters WITHOUT the NFKC,
    confusable-fold, or lowercasing that ``normalize_for_matching`` applies. Use
    before REDACTION so PII split by zero-width chars (detected on the normalized
    text) is actually scrubbed from the raw text instead of forwarded intact."""
    if not text:
        return text
    return _ZERO_WIDTH_RE.sub("", text)


def normalize_for_matching(text: str) -> str:
    """Normalize ``text`` for rule / PII / injection matching.

    Idempotent, and the identity function on plain ASCII (so it never perturbs
    existing behavior).
    """
    if not text:
        return text
    # 1. NFKC compatibility normalization (fullwidth, ligatures, etc.)
    out = unicodedata.normalize("NFKC", text)
    # 2. Strip zero-width / invisible format characters.
    out = _ZERO_WIDTH_RE.sub("", out)
    # 3. Curated confusable fold.
    return out.translate(_TRANSLATE_TABLE)


_ZERO_WIDTH_SET = frozenset(chr(cp) for cp in _ZERO_WIDTH_CODEPOINTS)


def nfkc_with_source_map(text: str) -> Tuple[str, List[int], List[int]]:
    """NFKC-normalize ``text`` one source codepoint at a time (dropping
    zero-width / bidi format chars), returning the folded string plus, for each
    codepoint of that string, the ``[start, end)`` slice of the ORIGINAL string
    it came from.

    This lets REDACTION locate PII on the same folded view DETECTION uses (so a
    fullwidth-digit phone is found) while scrubbing the ORIGINAL text: only the
    matched span is replaced, every other character (including legitimately
    fullwidth / CJK text) is forwarded byte-for-byte. Per-codepoint folding keeps
    the map exact -- whole-string NFKC can merge combining sequences so an offset
    no longer maps to a unique source span. The only forms it can't line up 1:1
    (ligatures like ``fi``) never occur inside a PII digit/token run, and where a
    match edge lands mid-expansion the whole source codepoint is covered
    (over-redacts by at most one char, never leaks).

    On plain ASCII, ``normalized == text`` with an identity map, so callers take
    a fast path that preserves pre-existing behavior exactly.
    """
    normalized_parts: List[str] = []
    map_start: List[int] = []
    map_end: List[int] = []
    for i, ch in enumerate(text):
        if ch in _ZERO_WIDTH_SET:  # dropped: contributes no output
            continue
        folded = unicodedata.normalize("NFKC", ch)
        for _ in folded:
            map_start.append(i)
            map_end.append(i + 1)
        normalized_parts.append(folded)
    return "".join(normalized_parts), map_start, map_end
