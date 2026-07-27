"""De-obfuscation views for the injection/PII detectors (server-side normalizer mirror).

Derives read-only scan "views" from a prompt so payloads hidden behind
zero-width characters, homoglyphs, HTML comments, CSS-hidden or aria-hidden
markup, whitespace padding, or base64/hex/percent encoding are still seen by
the pattern scanners.
Behavior-identical to the server-side normalizer,
pinned by conformance/fixtures/deobfuscation.json. Twin:
sdk/src/policy/deobfuscate.ts.

Invariants (same as the gateway):
 - NON-MUTATING: views are derived copies; the caller's text, stored
   prompt, and redaction pipeline never see them.
 - ADDITIVE / FALSE-POSITIVE-NEUTRAL: transforms only de-obfuscate
   (strip, fold, decode) — they never fabricate content that was not
   reachable from the input.
 - BOUNDED: input capped at 64 KiB (UTF-8 bytes), at most 1 canonical +
   5 decoded views, decode depth exactly 1 (decoded output is never
   re-tokenized or re-decoded, so nested encodings are NOT caught).

Deliberately separate from normalize_for_matching (normalize.py), whose
3-step output is byte-pinned by conformance/fixtures/normalization.json
and MUST NOT change. The confusable table here is the gateway's curated
56-entry map — a superset of normalize.py's 38 pairs — and applies only
to derived views.

Character classes (invisible/Cf, whitespace) are hardcoded tables, not
runtime Unicode lookups, so both SDKs agree byte-for-byte regardless of
interpreter Unicode version. Exception: the printable-ratio gate uses
unicodedata categories — a ratio threshold, where a single-codepoint skew
between runtimes cannot flip the outcome for realistic inputs.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional

# ── Caps (gateway parity) ────────────────────────────────────────────────────

_MAX_INPUT_BYTES = 64 << 10
_MAX_DECODED_CANDIDATES = 5
_MIN_ENCODED_TOKEN_LEN = 16
_MIN_PRINTABLE_RATIO = 0.85
_MIN_B64_DECODED_BYTES = 4

# ── Character tables ─────────────────────────────────────────────────────────

# Explicit gateway set plus the full Unicode Cf (format) category,
# enumerated (Unicode 15.0 ranges) for cross-runtime parity.
_INVISIBLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
)


def _is_invisible(cp: int) -> bool:
    for lo, hi in _INVISIBLE_RANGES:
        if lo <= cp <= hi:
            return True
    return False


# The gateway's curated confusable map (56 entries): Cyrillic and Greek
# lookalikes folded to ASCII. NOT the full UTS-39 table, and NOT
# normalize.py's pinned 38-pair table — this one only shapes derived views.
_CONFUSABLES: Dict[int, str] = {
    # Cyrillic lowercase
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c",
    0x0443: "y", 0x0445: "x", 0x0456: "i", 0x0458: "j", 0x0455: "s",
    0x04BB: "h", 0x0261: "g", 0x0501: "d", 0x043C: "m", 0x043D: "n",
    0x0442: "t", 0x0432: "b", 0x043A: "k",
    # Cyrillic uppercase
    0x0410: "A", 0x0415: "E", 0x041E: "O", 0x0420: "P", 0x0421: "C",
    0x0422: "T", 0x0423: "Y", 0x0425: "X", 0x0406: "I", 0x0408: "J",
    0x0412: "B", 0x041D: "H", 0x041A: "K", 0x041C: "M", 0x041F: "N",
    # Greek lowercase
    0x03BF: "o", 0x03B1: "a", 0x03B5: "e", 0x03C1: "p", 0x03C4: "t",
    0x03BD: "v", 0x03B9: "i", 0x03BA: "k", 0x03B7: "n", 0x03C5: "u",
    # Greek uppercase
    0x0391: "A", 0x039F: "O", 0x0395: "E", 0x03A1: "P", 0x03A4: "T",
    0x0397: "H", 0x039A: "K", 0x039C: "M", 0x039D: "N", 0x0392: "B",
    0x03A7: "X", 0x0399: "I", 0x0396: "Z",
}

# Whitespace for collapse: Go unicode.IsSpace exactly — ASCII \t\n\v\f\r and
# space, NEL (U+0085), NBSP (U+00A0), plus categories Zs/Zl/Zp enumerated.
_WS_CLASS = (
    "\t\n\x0b\f\r \x85\xa0"
    "\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000"
)
_WS_RUN_RE = re.compile(f"[{_WS_CLASS}]+")
_WS_TRIM_RE = re.compile(f"^[{_WS_CLASS}]+|[{_WS_CLASS}]+$")

# ── Canonical-view transforms (applied in this exact order) ──────────────────


def strip_invisible(text: str) -> str:
    """Remove (not replace) every invisible/format character."""
    out = []
    changed = False
    for ch in text:
        if _is_invisible(ord(ch)):
            changed = True
            continue
        out.append(ch)
    return "".join(out) if changed else text


def fold_confusables(text: str) -> str:
    """Fold full-width ASCII (U+FF01–U+FF5E) and curated confusables."""
    out = []
    changed = False
    for ch in text:
        cp = ord(ch)
        if 0xFF01 <= cp <= 0xFF5E:
            out.append(chr(cp - 0xFEE0))
            changed = True
        else:
            folded = _CONFUSABLES.get(cp)
            if folded is not None:
                out.append(folded)
                changed = True
            else:
                out.append(ch)
    return "".join(out) if changed else text


def strip_html_comments(text: str) -> str:
    """Replace each complete ``<!-- ... -->`` comment with a single space.

    An unterminated ``<!--`` drops the entire remainder (after writing the
    space). Comment CONTENT is discarded: the raw text is always scanned
    first, so a payload inside a comment is already covered as a substring.
    """
    if "<!--" not in text:
        return text
    out = []
    rest = text
    while True:
        start = rest.find("<!--")
        if start == -1:
            out.append(rest)
            break
        out.append(rest[:start])
        out.append(" ")
        after_open = rest[start + 4:]
        end = after_open.find("-->")
        if end == -1:
            break  # unterminated: drop the remainder
        rest = after_open[end + 3:]
    return "".join(out)


_VOID_ELEMENTS = frozenset(
    (
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr",
    )
)

# ECMAScript's trimEnd() whitespace set, spelled out rather than using
# str.rstrip(): Python strips \x1c-\x1f and NEL that JS does not, and does not
# strip U+FEFF that JS does. The self-closing test below is the only place the
# two sets could disagree on whether a tag is void.
_JS_TRIM_WS = (
    "\t\n\x0b\f\r \xa0"
    "\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)

# Whitespace inside a style value, dropped before the CSS test so
# "display : none" reads the same as "display:none". ASCII only, matching the
# TypeScript twin's character class.
_ATTR_WS_RE = re.compile(r"[ \t\n\r\f\v]+")


def _is_tag_name_start(c: str) -> bool:
    return ("a" <= c <= "z") or ("A" <= c <= "Z")


def _is_tag_name_char(c: str) -> bool:
    return _is_tag_name_start(c) or ("0" <= c <= "9") or c == "-"


def _is_ascii_space(c: str) -> bool:
    """ASCII whitespace only; markup separators are ASCII by spec."""
    return c in (" ", "\t", "\n", "\r", "\f", "\v")


def _find_tag_end(text: str, start: int) -> int:
    """Index of the ``>`` closing the tag whose attributes start at ``start``,
    or -1. Quoted attribute values are honored so a ``>`` inside one does not
    end the tag."""
    quote = ""
    for i in range(start, len(text)):
        c = text[i]
        if quote:
            if c == quote:
                quote = ""
            continue
        if c in ('"', "'"):
            quote = c
            continue
        if c == ">":
            return i
    return -1


def _index_of_closing_tag(text: str, start: int, name: str) -> int:
    """Index just past the first ``</name ... >`` at or after ``start``, or -1."""
    n = len(text)
    i = start
    while True:
        lt = text.find("</", i)
        if lt == -1:
            return -1
        name_start = lt + 2
        if text[name_start:name_start + len(name)].lower() == name:
            after_at = name_start + len(name)
            after = text[after_at] if after_at < n else None
            # A real closer, not a longer name that merely starts the same way.
            if after is None or not _is_tag_name_char(after):
                gt = text.find(">", after_at)
                if gt == -1:
                    return -1
                return gt + 1
        i = lt + 2


def _has_hidden_attribute(attrs: str) -> bool:
    """Whether a tag's attribute text hides the element: ``aria-hidden="true"``,
    or a ``style`` value carrying ``display:none`` / ``visibility:hidden``. Only
    the ``style`` attribute is inspected for the CSS forms, so
    ``data-note="display:none"`` does not hide anything. Attribute text is
    bounded by the tag, so this is cheap."""
    lower = attrs.lower()
    if "aria-hidden" not in lower and "style" not in lower:
        return False
    n = len(lower)
    i = 0
    while i < n:
        while i < n and not _is_tag_name_start(lower[i]):
            i += 1
        name_start = i
        while i < n and _is_tag_name_char(lower[i]):
            i += 1
        if i == name_start:
            break
        name = lower[name_start:i]
        # Only two attribute names can hide anything; skipping the value scan
        # for every other one keeps a tag-heavy prompt off the expensive path.
        interesting = name in ("aria-hidden", "style")
        while i < n and _is_ascii_space(lower[i]):
            i += 1
        value = ""
        if i < n and lower[i] == "=":
            i += 1
            while i < n and _is_ascii_space(lower[i]):
                i += 1
            q = lower[i] if i < n else ""
            if q in ('"', "'"):
                end = lower.find(q, i + 1)
                if interesting:
                    value = lower[i + 1:] if end == -1 else lower[i + 1:end]
                i = n if end == -1 else end + 1
            else:
                value_start = i
                while i < n and not _is_ascii_space(lower[i]):
                    i += 1
                if interesting:
                    value = lower[value_start:i]
        if not interesting:
            continue
        if name == "aria-hidden" and value == "true":
            return True
        if name == "style":
            css = _ATTR_WS_RE.sub("", value)
            if "display:none" in css or "visibility:hidden" in css:
                return True
    return False


def strip_hidden_html(text: str) -> str:
    """Remove CSS-hidden (``display:none``, ``visibility:hidden``) and
    ``aria-hidden="true"`` elements, tag AND content, from the canonical view.

    The attack this closes is not "a payload is hidden" — a payload sitting in
    a hidden div is already plain text in the raw prompt, and the raw text is
    always scanned first. It is the SPLIT: interleaving hidden junk breaks a
    phrase the scanner would otherwise match, so ``ignore <span
    style="display:none">zzz</span>all previous instructions`` reads as an
    injection to the model and as three unrelated fragments to a substring
    scanner. Removing the region rejoins the phrase, exactly as
    ``strip_invisible`` rejoins a zero-width-split word — which is why the
    region is removed with NO separator (unlike ``strip_html_comments``, which
    leaves a space): the canonical view is what a reader actually sees rendered.

    Deliberately a bounded text pass, not a parser (hot-path budget):
     - no regex over the document, so no backtracking surface; the only regex
       is a whitespace squeeze over one tag's attribute value
     - single forward pass, O(input): each hidden region's closing-tag search
       ends where scanning resumes, so no character is examined twice
     - the FIRST matching closing tag ends the region, so same-name nesting
       (``<div style="display:none">a<div>b</div>c</div>``) leaves a tail in
       the view. That fails toward keeping content, and the raw scan still
       covers it.
     - an unterminated hidden element drops the remainder, matching
       ``strip_html_comments``.

    Twin: ``stripHiddenHtml`` in sdk/src/policy/deobfuscate.ts.
    """
    if "<" not in text:
        return text
    n = len(text)
    out: Optional[List[str]] = None
    emitted = 0
    scan = 0
    while scan < n:
        lt = text.find("<", scan)
        if lt == -1:
            break
        name_start = lt + 1
        if name_start >= n or not _is_tag_name_start(text[name_start]):
            scan = lt + 1
            continue
        p = name_start
        while p < n and _is_tag_name_char(text[p]):
            p += 1
        tag_end = _find_tag_end(text, p)
        if tag_end == -1:
            scan = lt + 1
            continue
        attrs = text[p:tag_end]
        if not _has_hidden_attribute(attrs):
            scan = tag_end + 1
            continue
        name = text[name_start:p].lower()
        if out is None:
            out = []
        out.append(text[emitted:lt])
        if attrs.rstrip(_JS_TRIM_WS).endswith("/") or name in _VOID_ELEMENTS:
            region_end = tag_end + 1
        else:
            close = _index_of_closing_tag(text, tag_end + 1, name)
            region_end = n if close == -1 else close
        emitted = region_end
        scan = region_end
    if out is None:
        return text
    out.append(text[emitted:])
    return "".join(out)


def collapse_whitespace(text: str) -> str:
    """Collapse every whitespace run to a single space and trim both ends."""
    return _WS_TRIM_RE.sub("", _WS_RUN_RE.sub(" ", text))


# ── Decoders (Go-semantics, hand-written for cross-language parity) ──────────

_HEX_RE = re.compile(r"[0-9a-fA-F]")


def _printable_ratio_ok(text: str) -> bool:
    """Go printableUTF8: ≥85% of runes printable (categories L/M/N/P/S, the
    ASCII space) or \\n \\t \\r."""
    if not text:
        return False
    total = 0
    printable = 0
    for ch in text:
        total += 1
        if ch in (" ", "\n", "\t", "\r") or unicodedata.category(ch)[0] in "LMNPS":
            printable += 1
    return printable / total >= _MIN_PRINTABLE_RATIO


def _is_hex_byte(b: int) -> bool:
    return 0x30 <= b <= 0x39 or 0x41 <= b <= 0x46 or 0x61 <= b <= 0x66


def _hex_val(b: int) -> int:
    if b <= 0x39:
        return b - 0x30
    if b <= 0x46:
        return b - 0x41 + 10
    return b - 0x61 + 10


def _percent_decode(text: str) -> Optional[str]:
    """Go url.QueryUnescape semantics, byte-wise: '+' becomes space, '%XX'
    requires exactly two hex digits (anything else is an error → skip)."""
    data = text.encode("utf-8")
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b == 0x25:  # %
            if i + 2 >= n:
                return None
            h1, h2 = data[i + 1], data[i + 2]
            if not _is_hex_byte(h1) or not _is_hex_byte(h2):
                return None
            out.append(_hex_val(h1) * 16 + _hex_val(h2))
            i += 3
        elif b == 0x2B:  # +
            out.append(0x20)
            i += 1
        else:
            out.append(b)
            i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_hex_token(tok: str) -> bool:
    if not tok or len(tok) % 2 != 0:
        return False
    return all(_HEX_RE.match(c) for c in tok)


_B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _b64_decode_variant(tok: str, alphabet: str, padded: bool) -> Optional[bytes]:
    """One Go base64 variant: padded requires len%4==0 with 0–2 trailing '=';
    raw forbids '=' and len%4==1. Trailing-bit garbage is accepted (Go's
    default, non-Strict decoders)."""
    data = tok
    if padded:
        if not tok or len(tok) % 4 != 0:
            return None
        pad = 0
        while pad < 2 and tok[len(tok) - 1 - pad] == "=":
            pad += 1
        data = tok[: len(tok) - pad]
        if "=" in data:
            return None  # '=' only at the very end
    else:
        if "=" in tok:
            return None
        if len(tok) % 4 == 1:
            return None
    if len(data) % 4 == 1:
        return None
    vals = []
    for ch in data:
        v = alphabet.find(ch)
        if v == -1:
            return None
        vals.append(v)
    out = bytearray()
    i = 0
    while i + 4 <= len(vals):
        n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3]
        out.extend(((n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF))
        i += 4
    rem = len(vals) - i
    if rem == 2:
        n = (vals[i] << 18) | (vals[i + 1] << 12)
        out.append((n >> 16) & 0xFF)
    elif rem == 3:
        n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6)
        out.extend(((n >> 16) & 0xFF, (n >> 8) & 0xFF))
    return bytes(out)


def _try_base64(tok: str) -> Optional[str]:
    """Go tryBase64: Std, RawStd, URL, RawURL in order; first variant that
    decodes to ≥4 bytes of printable UTF-8 wins."""
    for alphabet, padded in (
        (_B64_STD, True),
        (_B64_STD, False),
        (_B64_URL, True),
        (_B64_URL, False),
    ):
        raw = _b64_decode_variant(tok, alphabet, padded)
        if raw is None or len(raw) < _MIN_B64_DECODED_BYTES:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not _printable_ratio_ok(text):
            continue
        return text
    return None


# ── View derivation ──────────────────────────────────────────────────────────


def _truncate_input(text: str) -> str:
    """Byte-truncate to the input cap (a split rune decodes as U+FFFD)."""
    data = text.encode("utf-8")
    if len(data) <= _MAX_INPUT_BYTES:
        return text
    return data[:_MAX_INPUT_BYTES].decode("utf-8", errors="replace")


_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9+/=_-]+")


def deobfuscate(text: str) -> List[Dict[str, str]]:
    """Derive scan views: at most one canonical "deobfuscated" view
    (strip-invisible → fold-confusables → strip-HTML-comments →
    strip-hidden-HTML → collapse-whitespace, composed) followed by at most 5
    decoded views
    ("percent" whole-string first, then per-token "hex"/"base64" in token
    order). Decode depth is exactly 1. Never mutates or returns the input.
    Each view is {"method": ..., "text": ...}."""
    t = _truncate_input(text)
    views: List[Dict[str, str]] = []

    # collapse_whitespace already trims, so non-empty here is the gateway's
    # TrimSpace(canon) != "" gate.
    canon = collapse_whitespace(
        strip_hidden_html(strip_html_comments(fold_confusables(strip_invisible(t))))
    )
    if canon != t and canon != "":
        views.append({"method": "deobfuscated", "text": canon})

    # Decoded candidates run over the ORIGINAL (truncated) text, not the
    # canonical view — decoding and character folding do not compose.
    decoded: List[Dict[str, str]] = []
    seen = set()

    def _add(method: str, out: str) -> None:
        if len(decoded) >= _MAX_DECODED_CANDIDATES:
            return
        if out == "" or out == t:
            return
        if out in seen:
            return
        if not _printable_ratio_ok(out):
            return
        seen.add(out)
        decoded.append({"method": method, "text": out})

    if "%" in t:
        dec = _percent_decode(t)
        if dec is not None and dec != t:
            _add("percent", dec)

    for tok in _TOKEN_SPLIT_RE.split(t):
        if len(decoded) >= _MAX_DECODED_CANDIDATES:
            break
        if len(tok) < _MIN_ENCODED_TOKEN_LEN:
            continue
        if _is_hex_token(tok):
            try:
                hex_text = bytes.fromhex(tok).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                hex_text = None
            if hex_text is not None:
                _add("hex", hex_text)
        # Not exclusive with hex: an all-hex token is also a base64 candidate.
        b = _try_base64(tok)
        if b is not None:
            _add("base64", b)

    return views + decoded


# ── Scan wrapper ─────────────────────────────────────────────────────────────


def run_deobfuscated_scan(
    text: str, views: Optional[List[Dict[str, str]]] = None
) -> Dict[str, object]:
    """Raw-first scan: run the builtin scanner on the raw text; only when raw
    is clean, scan each de-obfuscation view and merge the detections.

    Returns {"pii_detected", "detected_types", "via"?} where "via" is the
    method of the first view that produced a detection — absent when the RAW
    text already matched (fast path: views are then never derived, so an
    overt hit is byte-identical to the scanner without this layer) and when
    nothing matched. Mirrors the gateway's Result.Via / security_normalized.

    DETECTION-ONLY: view matches carry no offsets into the raw text, so this
    result must never drive span redaction (redact_builtin_pii runs on the
    original text as before).
    """
    from .policy import run_builtin_pii_scan  # lazy: policy imports this module

    raw = run_builtin_pii_scan(text)
    if raw["pii_detected"]:
        return raw

    all_types: List[str] = []
    via: Optional[str] = None
    for v in views if views is not None else deobfuscate(text):
        r = run_builtin_pii_scan(v["text"])
        if r["pii_detected"]:
            if via is None:
                via = v["method"]
            for label in r["detected_types"]:
                if label not in all_types:
                    all_types.append(label)
    if not all_types:
        return {"pii_detected": False, "detected_types": []}
    return {"pii_detected": True, "detected_types": all_types, "via": via}


# ── Pipeline wiring (config gate + view-only decision semantics) ─────────────


def run_configured_pii_scan(
    text: str, deob: Optional[Dict[str, Any]] = None
) -> Dict[str, object]:
    """Config-gated scan entry for every pipeline scan site. With the flag off
    (the default) this IS ``run_builtin_pii_scan`` — byte-identical behavior,
    zero added work. With it on, a raw-clean text is additionally scanned
    through de-obfuscation views, and a view-only hit carries ``via``.
    """
    if deob and deob.get("enabled"):
        return run_deobfuscated_scan(text)
    from .policy import run_builtin_pii_scan  # lazy: policy imports this module

    return run_builtin_pii_scan(text)


def escalate_view_only_action(action: str, via: Optional[str]) -> str:
    """Clamp a resolved PII action for a view-only detection. ``via`` present
    means the RAW text is clean (raw-first invariant), so span redaction is a
    guaranteed no-op: a "redact" outcome would produce a false compliance
    record (``action_taken: "redacted"``) while the encoded payload flows
    through intact. On enforceable pre-delivery paths, ``redact`` therefore
    escalates to ``block``. Identity when ``via`` is absent.
    """
    if via is not None and action == "redact":
        return "block"
    return action


# Whole-text placeholder for stored copies whose detected payload has no
# locatable span (view-only detection). Parity-pinned in
# conformance/fixtures/deobfuscation.json.
OBFUSCATED_REDACTION_PLACEHOLDER = "[REDACTED:obfuscated]"


def redact_for_storage(text: str, via: Optional[str]) -> str:
    """Redact a STORED copy (blocked-event prompt/user_input, post-call stored
    response, observe-path stored fields). With ``via`` absent this is exactly
    ``redact_builtin_pii`` (typed span placeholders). With ``via`` present the
    spans are unlocatable in the raw text, so the whole stored copy is
    replaced — never a silently-intact "redacted" record. Detection
    provenance (detected_types + via) still rides the event, so the record
    stays useful.

    Guarded HERE rather than at each of its call sites, because there is one
    correct answer for all of them and P-02 wants it stated once: this builds a
    STORED copy, so a redactor defect resolves the response-phase way even when
    the caller is on the pre-call path. It fails closed on the stored copy alone
    - the marker, never the raw text, because persisting content nothing vetted
    into an evidence record is the fake enforcement P-02 forbids, and never a
    "[REDACTED..." token, because "we could not scan this" must not read as "we
    scanned it and removed something".

    Twin: sdk/src/policy/deobfuscate.ts (``redactForStorage``).
    """
    try:
        if via is not None:
            return OBFUSCATED_REDACTION_PLACEHOLDER
        from .policy import redact_builtin_pii  # lazy: policy imports this module

        return redact_builtin_pii(text)
    except Exception as _redact_exc:  # noqa: BLE001 - deliberate catch-all
        from .policy import UNSCANNED_PLACEHOLDER, record_detector_failure

        record_detector_failure("deobfuscation_views", _redact_exc, None)
        return UNSCANNED_PLACEHOLDER
