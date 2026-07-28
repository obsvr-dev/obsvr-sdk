/**
 * Matching-time text normalization (§6).
 *
 * Attackers bypass keyword / regex / PII / injection rules with lookalike or
 * invisible characters: a fullwidth "ｏｖｅｒｒｉｄｅ", a Cyrillic "оverride", or a
 * zero-width-joined "over<ZWJ>ride" all read as "override" to a human (and to
 * the model) but slip past a naive `text.includes("override")`.
 *
 * `normalizeForMatching` collapses those tricks to a canonical form BEFORE the
 * scanners match, in three deterministic steps:
 *   1. Unicode NFKC — folds compatibility variants (fullwidth, ligatures,
 *      circled/super/subscript forms) to their canonical characters.
 *   2. Strip zero-width / invisible format characters (ZWSP, ZWNJ, ZWJ, word
 *      joiner, BOM, soft hyphen, Mongolian vowel separator).
 *   3. A small, curated confusable fold — the highest-value Latin lookalikes
 *      from Cyrillic and Greek that NFKC does NOT fold (they are distinct
 *      letters, not compatibility equivalents).
 *
 * CRITICAL: this is a MATCHING-ONLY transform. It is applied to the copy the
 * scanners inspect, never to the stored/forwarded prompt or response. The audit
 * must reflect what the user actually sent — normalization changes what we
 * DETECT, not what we RECORD (redaction is the only content mutation, and it
 * runs on the original text). Kept intentionally minimal and launch-safe.
 *
 * The step order and character tables are pinned by
 * conformance/fixtures/normalization.json and must stay byte-for-byte identical
 * to the Python twin (obsvr/normalize.py).
 *
 * @packageDocumentation
 */

/**
 * Zero-width / invisible format characters removed before matching. These
 * carry no visible glyph, so removing them cannot change what a human reads —
 * only what a regex sees.
 *   U+200B ZERO WIDTH SPACE, U+200C ZWNJ, U+200D ZWJ, U+2060 WORD JOINER,
 *   U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM), U+00AD SOFT HYPHEN,
 *   U+180E MONGOLIAN VOWEL SEPARATOR.
 */
const ZERO_WIDTH_CODEPOINTS = [
  0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x00ad, 0x180e,
  // Bidirectional format controls: invisible, and interleavable into
  // keywords/injection payloads to evade matching. LRM/RLM, the embedding /
  // override / pop-directional-format set, and the isolates.
  0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068,
  0x2069,
];
const ZERO_WIDTH_RE = new RegExp(
  "[" + ZERO_WIDTH_CODEPOINTS.map((cp) => "\\u" + cp.toString(16).padStart(4, "0")).join("") + "]",
  "g",
);

/**
 * Curated confusable fold: Latin-lookalike codepoints from Cyrillic and Greek
 * that NFKC leaves untouched, mapped to their ASCII twin. Deliberately small —
 * only the letters common in real bypass attempts — so the fold never mangles
 * legitimate non-Latin text more than necessary. Listed as [codepoint, ascii]
 * so the table is unambiguous and trivially matchable to the Python twin.
 */
const CONFUSABLE_PAIRS: Array<[number, string]> = [
  // ── Cyrillic → Latin (lowercase) ──
  [0x0430, "a"], // а
  [0x0435, "e"], // е
  [0x043e, "o"], // о
  [0x0440, "p"], // р
  [0x0441, "c"], // с
  [0x0445, "x"], // х
  [0x0443, "y"], // у
  [0x0455, "s"], // ѕ
  [0x0456, "i"], // і
  [0x0458, "j"], // ј
  [0x04bb, "h"], // һ
  // ── Cyrillic → Latin (uppercase) ──
  [0x0410, "A"], // А
  [0x0412, "B"], // В
  [0x0415, "E"], // Е
  [0x041a, "K"], // К
  [0x041c, "M"], // М
  [0x041d, "H"], // Н
  [0x041e, "O"], // О
  [0x0420, "P"], // Р
  [0x0421, "C"], // С
  [0x0422, "T"], // Т
  [0x0425, "X"], // Х
  // ── Greek → Latin ──
  [0x03bf, "o"], // ο (small omicron)
  [0x03b1, "a"], // α (small alpha)
  [0x03c1, "p"], // ρ (small rho)
  [0x03bd, "v"], // ν (small nu)
  [0x0391, "A"], // Α (capital alpha)
  [0x0392, "B"], // Β (capital beta)
  [0x0395, "E"], // Ε (capital epsilon)
  [0x0397, "H"], // Η (capital eta)
  [0x0399, "I"], // Ι (capital iota)
  [0x039a, "K"], // Κ (capital kappa)
  [0x039c, "M"], // Μ (capital mu)
  [0x039d, "N"], // Ν (capital nu)
  [0x039f, "O"], // Ο (capital omicron)
  [0x03a1, "P"], // Ρ (capital rho)
  [0x03a4, "T"], // Τ (capital tau)
  [0x03a7, "X"], // Χ (capital chi)
];

const CONFUSABLES: Map<string, string> = new Map(
  CONFUSABLE_PAIRS.map(([cp, ascii]) => [String.fromCodePoint(cp), ascii]),
);

/**
 * Normalize `text` for rule / PII / injection matching. Idempotent, and the
 * identity function on plain ASCII (so it never perturbs existing behavior).
 *
 * @param text - the raw text the scanner would otherwise match against
 * @returns the canonicalized copy to match against (never stored)
 */
/**
 * Remove zero-width / bidi / invisible format characters WITHOUT the NFKC or
 * confusable folding or lowercasing that `normalizeForMatching` applies. Use
 * before REDACTION so an SSN split by zero-width chars (detected on the
 * normalized text) is actually scrubbed from the raw text, instead of being
 * forwarded intact while the event claims "redacted".
 */
export function stripInvisibleChars(text: string): string {
  if (!text) return text;
  return text.replace(ZERO_WIDTH_RE, "");
}

export function normalizeForMatching(text: string): string {
  if (!text) return text;
  // 1. NFKC compatibility normalization (fullwidth, ligatures, etc.)
  let out = text.normalize("NFKC");
  // 2. Strip zero-width / invisible format characters.
  out = out.replace(ZERO_WIDTH_RE, "");
  // 3. Curated confusable fold (per Unicode scalar value, so astral chars are
  //    iterated correctly and simply pass through unchanged).
  let folded = "";
  for (const ch of out) folded += CONFUSABLES.get(ch) ?? ch;
  return folded;
}

const ZERO_WIDTH_SET: Set<string> = new Set(ZERO_WIDTH_CODEPOINTS.map((cp) => String.fromCodePoint(cp)));

/**
 * NFKC-normalize `text` one source codepoint at a time (dropping zero-width /
 * bidi format chars), returning the folded string plus, for each UTF-16 unit of
 * that string, the [start, end) slice of the ORIGINAL string it came from.
 *
 * This is what lets REDACTION locate PII on the same folded view DETECTION uses
 * — so a fullwidth-digit phone (`５５５…`, which JS's ASCII-only `\d` never
 * matches) is found — while scrubbing the ORIGINAL text: only the matched PII
 * span is replaced, every other character (including legitimately fullwidth,
 * ligature, or CJK text) is forwarded to the provider byte-for-byte. A
 * whole-string `text.normalize("NFKC")` cannot do this: it can merge combining
 * sequences across codepoint boundaries, so a match offset no longer maps back
 * to a unique source span. Per-codepoint folding keeps the map exact, and the
 * only forms it can't line up 1:1 (ligatures like `ﬁ`→`fi`) never occur inside a
 * PII digit/token run — and where a match edge lands mid-expansion the whole
 * source codepoint is covered, which over-redacts by at most one char (never
 * leaks).
 *
 * Idempotent and, on plain ASCII, `normalized === text` with an identity map,
 * so callers can take a fast path that exactly preserves pre-existing behavior.
 */
export function nfkcWithSourceMap(text: string): {
  normalized: string;
  mapStart: number[];
  mapEnd: number[];
} {
  let normalized = "";
  const mapStart: number[] = [];
  const mapEnd: number[] = [];
  let srcIdx = 0; // UTF-16 index into `text`
  for (const cp of text) {
    const start = srcIdx;
    const end = srcIdx + cp.length; // 1 or 2 UTF-16 units
    srcIdx = end;
    if (ZERO_WIDTH_SET.has(cp)) continue; // dropped: contributes no output
    const folded = cp.normalize("NFKC");
    for (let u = 0; u < folded.length; u++) {
      mapStart.push(start);
      mapEnd.push(end);
    }
    normalized += folded;
  }
  return { normalized, mapStart, mapEnd };
}
