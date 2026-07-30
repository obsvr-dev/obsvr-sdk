"""Matching-time text normalization (§6).

EXACT parity with sdk-typescript/src/policy/normalize.ts.

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
the TypeScript twin (sdk-typescript/src/policy/normalize.ts).
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
#
# The last group is here for a different reason, and it is the reason this table
# has to exist at all rather than deferring to NFKC. NFKC is NOT a stable shared
# primitive across languages: Node folds through ICU, which tracks the current
# Unicode release, while CPython ships a frozen ``unicodedata`` per minor
# version. ICU is therefore always ahead, and every Unicode release leaves a
# fresh residue of codepoints one runtime folds to ASCII and the other does not.
# Measured across eight CPython builds against one Node: 41 such codepoints at
# CPython 3.10 (the declared floor), 37 at 3.12/3.13, 1 at 3.14 -- narrowing but
# never reaching zero, because the next Unicode release restocks it. All of them
# fold on Node and none on Python, so the divergence is one-directional and its
# effect is that a ``keyword`` or ``topic_deny`` rule blocks in TypeScript and
# ALLOWS here.
#
# Listing them here rather than vendoring a whole NFKC table is deliberate: an
# entry is IDEMPOTENT and version-independent by construction. On a host whose
# NFKC already folds the codepoint, step 1 consumes it and this map never sees
# it; on a host whose NFKC does not, this map folds it to the same ASCII
# character. Both runtimes therefore agree whatever Unicode version they ship,
# and a future CPython that gains the mapping changes nothing.
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
    # -- Unicode 16/17 additions that only NEWER hosts fold (A-2) --
    (0x1CCD6, "A"),  # OUTLINED LATIN CAPITAL LETTER A
    (0x1CCD7, "B"),  # OUTLINED LATIN CAPITAL LETTER B
    (0x1CCD8, "C"),  # OUTLINED LATIN CAPITAL LETTER C
    (0x1CCD9, "D"),  # OUTLINED LATIN CAPITAL LETTER D
    (0x1CCDA, "E"),  # OUTLINED LATIN CAPITAL LETTER E
    (0x1CCDB, "F"),  # OUTLINED LATIN CAPITAL LETTER F
    (0x1CCDC, "G"),  # OUTLINED LATIN CAPITAL LETTER G
    (0x1CCDD, "H"),  # OUTLINED LATIN CAPITAL LETTER H
    (0x1CCDE, "I"),  # OUTLINED LATIN CAPITAL LETTER I
    (0x1CCDF, "J"),  # OUTLINED LATIN CAPITAL LETTER J
    (0x1CCE0, "K"),  # OUTLINED LATIN CAPITAL LETTER K
    (0x1CCE1, "L"),  # OUTLINED LATIN CAPITAL LETTER L
    (0x1CCE2, "M"),  # OUTLINED LATIN CAPITAL LETTER M
    (0x1CCE3, "N"),  # OUTLINED LATIN CAPITAL LETTER N
    (0x1CCE4, "O"),  # OUTLINED LATIN CAPITAL LETTER O
    (0x1CCE5, "P"),  # OUTLINED LATIN CAPITAL LETTER P
    (0x1CCE6, "Q"),  # OUTLINED LATIN CAPITAL LETTER Q
    (0x1CCE7, "R"),  # OUTLINED LATIN CAPITAL LETTER R
    (0x1CCE8, "S"),  # OUTLINED LATIN CAPITAL LETTER S
    (0x1CCE9, "T"),  # OUTLINED LATIN CAPITAL LETTER T
    (0x1CCEA, "U"),  # OUTLINED LATIN CAPITAL LETTER U
    (0x1CCEB, "V"),  # OUTLINED LATIN CAPITAL LETTER V
    (0x1CCEC, "W"),  # OUTLINED LATIN CAPITAL LETTER W
    (0x1CCED, "X"),  # OUTLINED LATIN CAPITAL LETTER X
    (0x1CCEE, "Y"),  # OUTLINED LATIN CAPITAL LETTER Y
    (0x1CCEF, "Z"),  # OUTLINED LATIN CAPITAL LETTER Z
    (0x1CCF0, "0"),  # OUTLINED DIGIT ZERO
    (0x1CCF1, "1"),  # OUTLINED DIGIT ONE
    (0x1CCF2, "2"),  # OUTLINED DIGIT TWO
    (0x1CCF3, "3"),  # OUTLINED DIGIT THREE
    (0x1CCF4, "4"),  # OUTLINED DIGIT FOUR
    (0x1CCF5, "5"),  # OUTLINED DIGIT FIVE
    (0x1CCF6, "6"),  # OUTLINED DIGIT SIX
    (0x1CCF7, "7"),  # OUTLINED DIGIT SEVEN
    (0x1CCF8, "8"),  # OUTLINED DIGIT EIGHT
    (0x1CCF9, "9"),  # OUTLINED DIGIT NINE
    (0xA7F1, "S"),  # LATIN EXTENDED-D U+A7F1 (assigned in Unicode 17.0)
    (0xA7F2, "C"),  # MODIFIER LETTER CAPITAL C
    (0xA7F3, "F"),  # MODIFIER LETTER CAPITAL F
    (0xA7F4, "Q"),  # MODIFIER LETTER CAPITAL Q
    (0x107A5, "q"),  # MODIFIER LETTER SMALL Q
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
