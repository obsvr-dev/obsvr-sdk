/**
 * De-obfuscation views for the injection/PII detectors (server-side normalizer mirror).
 *
 * Derives read-only scan "views" from a prompt so payloads hidden behind
 * zero-width characters, homoglyphs, HTML comments, whitespace padding, or
 * base64/hex/percent encoding are still seen by the pattern scanners.
 * Behavior-identical to the server-side normalizer,
 * pinned by conformance/fixtures/deobfuscation.json. Twin:
 * sdk-python/obsvr/deobfuscate.py.
 *
 * Invariants (same as the gateway):
 *  - NON-MUTATING: views are derived copies; the caller's text, stored
 *    prompt, and redaction pipeline never see them.
 *  - ADDITIVE / FALSE-POSITIVE-NEUTRAL: transforms only de-obfuscate
 *    (strip, fold, decode) — they never fabricate content that was not
 *    reachable from the input.
 *  - BOUNDED: input capped at 64 KiB (UTF-8 bytes), at most 1 canonical +
 *    5 decoded views, decode depth exactly 1 (decoded output is never
 *    re-tokenized or re-decoded, so nested encodings are NOT caught).
 *
 * This module is deliberately separate from normalizeForMatching
 * (normalize.ts), whose 3-step output is byte-pinned by
 * conformance/fixtures/normalization.json and MUST NOT change. The
 * confusable table here is the gateway's curated 56-entry map — a superset
 * of normalize.ts's 38 pairs — and applies only to derived views.
 *
 * Character classes (invisible/Cf, whitespace, printable) are hardcoded
 * tables, not runtime Unicode lookups, so both SDKs agree byte-for-byte
 * regardless of engine Unicode version. Exception: the printable-ratio
 * gate uses \p{L}\p{M}\p{N}\p{P}\p{S} — a ratio threshold, where a
 * single-codepoint skew between engines cannot flip the outcome for
 * realistic inputs.
 */

import { runBuiltinPiiScan, redactBuiltinPii } from './hook.js';

// ── Caps (gateway parity) ─────────────────────────────────────────────────────

/** Max input size in UTF-8 bytes; larger inputs are byte-truncated first. */
const MAX_INPUT_BYTES = 64 << 10;
/** Hard cap on decoded views per call (canonical view is separate). */
const MAX_DECODED_CANDIDATES = 5;
/** Tokens shorter than this are never decode candidates. */
const MIN_ENCODED_TOKEN_LEN = 16;
/** Decoded output must be ≥85% printable runes to become a view. */
const MIN_PRINTABLE_RATIO = 0.85;
/** base64 payloads decoding to fewer bytes are ignored. */
const MIN_B64_DECODED_BYTES = 4;

// ── Character tables ──────────────────────────────────────────────────────────

/**
 * Invisible / format characters stripped from the canonical view: the
 * gateway's explicit set (soft hyphen, arabic letter mark, mongolian vowel
 * separator, BOM, zero-width + bidi controls, word joiner + invisible
 * operators, bidi isolates) plus the full Unicode Cf (format) category,
 * enumerated explicitly (Unicode 15.0 ranges) for cross-runtime parity.
 */
const INVISIBLE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00ad, 0x00ad],
  [0x0600, 0x0605],
  [0x061c, 0x061c],
  [0x06dd, 0x06dd],
  [0x070f, 0x070f],
  [0x0890, 0x0891],
  [0x08e2, 0x08e2],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x206f],
  [0xfeff, 0xfeff],
  [0xfff9, 0xfffb],
  [0x110bd, 0x110bd],
  [0x110cd, 0x110cd],
  [0x13430, 0x1343f],
  [0x1bca0, 0x1bca3],
  [0x1d173, 0x1d17a],
  [0xe0001, 0xe0001],
  [0xe0020, 0xe007f],
];

function isInvisible(cp: number): boolean {
  for (const [lo, hi] of INVISIBLE_RANGES) {
    if (cp >= lo && cp <= hi) return true;
  }
  return false;
}

/**
 * The gateway's curated confusable map (56 entries): Cyrillic and Greek
 * lookalikes folded to ASCII. Deliberately NOT the full UTS-39 table, and
 * deliberately NOT normalize.ts's pinned 38-pair table — this one only
 * shapes derived views.
 */
const CONFUSABLES: ReadonlyMap<number, string> = new Map<number, string>([
  // Cyrillic lowercase
  [0x0430, 'a'], [0x0435, 'e'], [0x043e, 'o'], [0x0440, 'p'], [0x0441, 'c'],
  [0x0443, 'y'], [0x0445, 'x'], [0x0456, 'i'], [0x0458, 'j'], [0x0455, 's'],
  [0x04bb, 'h'], [0x0261, 'g'], [0x0501, 'd'], [0x043c, 'm'], [0x043d, 'n'],
  [0x0442, 't'], [0x0432, 'b'], [0x043a, 'k'],
  // Cyrillic uppercase
  [0x0410, 'A'], [0x0415, 'E'], [0x041e, 'O'], [0x0420, 'P'], [0x0421, 'C'],
  [0x0422, 'T'], [0x0423, 'Y'], [0x0425, 'X'], [0x0406, 'I'], [0x0408, 'J'],
  [0x0412, 'B'], [0x041d, 'H'], [0x041a, 'K'], [0x041c, 'M'], [0x041f, 'N'],
  // Greek lowercase
  [0x03bf, 'o'], [0x03b1, 'a'], [0x03b5, 'e'], [0x03c1, 'p'], [0x03c4, 't'],
  [0x03bd, 'v'], [0x03b9, 'i'], [0x03ba, 'k'], [0x03b7, 'n'], [0x03c5, 'u'],
  // Greek uppercase
  [0x0391, 'A'], [0x039f, 'O'], [0x0395, 'E'], [0x03a1, 'P'], [0x03a4, 'T'],
  [0x0397, 'H'], [0x039a, 'K'], [0x039c, 'M'], [0x039d, 'N'], [0x0392, 'B'],
  [0x03a7, 'X'], [0x0399, 'I'], [0x0396, 'Z'],
]);

/**
 * Whitespace for collapse: Go unicode.IsSpace exactly — ASCII \t\n\v\f\r
 * and space, NEL (U+0085), NBSP (U+00A0), plus categories Zs/Zl/Zp
 * enumerated explicitly.
 */
const WHITESPACE_CLASS =
  '\\t\\n\\x0B\\f\\r \\x85\\xA0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000';
const WS_RUN_RE = new RegExp(`[${WHITESPACE_CLASS}]+`, 'g');
const WS_TRIM_RE = new RegExp(
  `^[${WHITESPACE_CLASS}]+|[${WHITESPACE_CLASS}]+$`,
  'g',
);

// ── Canonical-view transforms (applied in this exact order) ───────────────────

/** Remove (not replace) every invisible/format character. */
export function stripInvisible(text: string): string {
  let out = '';
  let changed = false;
  for (const ch of text) {
    if (isInvisible(ch.codePointAt(0)!)) {
      changed = true;
      continue;
    }
    out += ch;
  }
  return changed ? out : text;
}

/** Fold full-width ASCII (U+FF01–U+FF5E) and curated confusables to ASCII. */
export function foldConfusables(text: string): string {
  let out = '';
  let changed = false;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xff01 && cp <= 0xff5e) {
      out += String.fromCharCode(cp - 0xfee0);
      changed = true;
    } else {
      const folded = CONFUSABLES.get(cp);
      if (folded !== undefined) {
        out += folded;
        changed = true;
      } else {
        out += ch;
      }
    }
  }
  return changed ? out : text;
}

/**
 * Replace each complete `<!-- ... -->` comment with a single space. An
 * unterminated `<!--` drops the entire remainder (after writing the space).
 * Comment CONTENT is discarded: the raw text is always scanned first, so a
 * payload inside a comment is already covered as a substring.
 */
export function stripHtmlComments(text: string): string {
  if (!text.includes('<!--')) return text;
  let out = '';
  let rest = text;
  for (;;) {
    const start = rest.indexOf('<!--');
    if (start === -1) {
      out += rest;
      break;
    }
    out += rest.slice(0, start) + ' ';
    const afterOpen = rest.slice(start + 4);
    const end = afterOpen.indexOf('-->');
    if (end === -1) break; // unterminated: drop the remainder
    rest = afterOpen.slice(end + 3);
  }
  return out;
}

/** Collapse every whitespace run to a single space and trim both ends. */
export function collapseWhitespace(text: string): string {
  return text.replace(WS_RUN_RE, ' ').replace(WS_TRIM_RE, '');
}

// ── Decoders (Go-semantics, hand-written for cross-language parity) ───────────

/** Strict UTF-8 decode; null when the bytes are not valid UTF-8. */
function utf8Strict(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

const PRINTABLE_RE = /[\p{L}\p{M}\p{N}\p{P}\p{S}]/u;

/**
 * Go printableUTF8: valid UTF-8 AND ≥85% of runes printable (categories
 * L/M/N/P/S, the ASCII space) or \n \t \r.
 */
function printableRatioOk(text: string): boolean {
  if (text.length === 0) return false;
  let total = 0;
  let printable = 0;
  for (const ch of text) {
    total++;
    if (ch === ' ' || ch === '\n' || ch === '\t' || ch === '\r' || PRINTABLE_RE.test(ch)) {
      printable++;
    }
  }
  return printable / total >= MIN_PRINTABLE_RATIO;
}

function isHexDigit(b: number): boolean {
  return (
    (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66)
  );
}

function hexVal(b: number): number {
  if (b <= 0x39) return b - 0x30;
  if (b <= 0x46) return b - 0x41 + 10;
  return b - 0x61 + 10;
}

/**
 * Go url.QueryUnescape semantics, byte-wise: '+' becomes space, '%XX'
 * requires exactly two hex digits (anything else — including a trailing
 * lone '%' — is an error and the whole decode is skipped).
 */
function percentDecode(text: string): string | null {
  const bytes = new TextEncoder().encode(text);
  const out: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x25 /* % */) {
      if (i + 2 >= bytes.length) return null;
      const h1 = bytes[i + 1];
      const h2 = bytes[i + 2];
      if (!isHexDigit(h1) || !isHexDigit(h2)) return null;
      out.push(hexVal(h1) * 16 + hexVal(h2));
      i += 2;
    } else if (b === 0x2b /* + */) {
      out.push(0x20);
    } else {
      out.push(b);
    }
  }
  return utf8Strict(new Uint8Array(out));
}

/** Even-length all-hex token (empty is false). */
function isHexToken(tok: string): boolean {
  if (tok.length === 0 || tok.length % 2 !== 0) return false;
  for (let i = 0; i < tok.length; i++) {
    if (!isHexDigit(tok.charCodeAt(i))) return false;
  }
  return true;
}

function hexDecode(tok: string): Uint8Array {
  const out = new Uint8Array(tok.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = hexVal(tok.charCodeAt(2 * i)) * 16 + hexVal(tok.charCodeAt(2 * i + 1));
  }
  return out;
}

const B64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * One Go base64 variant: `alphabet` (std or url) with or without padding.
 * Padded: length must be a multiple of 4 with 0–2 trailing '='.
 * Raw: no '=' anywhere; length % 4 must not be 1.
 * Trailing-bit garbage is accepted (Go's default, non-Strict decoders).
 */
function b64DecodeVariant(
  tok: string,
  alphabet: string,
  padded: boolean,
): Uint8Array | null {
  let data = tok;
  if (padded) {
    if (tok.length === 0 || tok.length % 4 !== 0) return null;
    let pad = 0;
    while (pad < 2 && tok[tok.length - 1 - pad] === '=') pad++;
    data = tok.slice(0, tok.length - pad);
    if (data.includes('=')) return null; // '=' only at the very end
  } else {
    if (tok.includes('=')) return null;
    if (tok.length % 4 === 1) return null;
  }
  if (data.length % 4 === 1) return null;
  const vals: number[] = [];
  for (let i = 0; i < data.length; i++) {
    const v = alphabet.indexOf(data[i]);
    if (v === -1) return null;
    vals.push(v);
  }
  const out: number[] = [];
  let i = 0;
  for (; i + 4 <= vals.length; i += 4) {
    const n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3];
    out.push((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  }
  const rem = vals.length - i;
  if (rem === 2) {
    const n = (vals[i] << 18) | (vals[i + 1] << 12);
    out.push((n >> 16) & 0xff);
  } else if (rem === 3) {
    const n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6);
    out.push((n >> 16) & 0xff, (n >> 8) & 0xff);
  }
  return new Uint8Array(out);
}

/**
 * Go tryBase64: attempt Std, RawStd, URL, RawURL in that order; the first
 * variant that decodes to ≥4 bytes of printable UTF-8 wins.
 */
function tryBase64(tok: string): string | null {
  const variants: ReadonlyArray<readonly [string, boolean]> = [
    [B64_STD, true],
    [B64_STD, false],
    [B64_URL, true],
    [B64_URL, false],
  ];
  for (const [alphabet, padded] of variants) {
    const raw = b64DecodeVariant(tok, alphabet, padded);
    if (raw === null || raw.length < MIN_B64_DECODED_BYTES) continue;
    const text = utf8Strict(raw);
    if (text === null || !printableRatioOk(text)) continue;
    return text;
  }
  return null;
}

// ── View derivation ───────────────────────────────────────────────────────────

export interface DeobfuscationView {
  /** Which transform produced this view. */
  method: 'deobfuscated' | 'percent' | 'hex' | 'base64';
  /** The derived text to scan (read-only; never stored or redacted). */
  text: string;
}

/** Byte-truncate to the input cap (a split rune decodes as U+FFFD). */
function truncateInput(text: string): string {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length <= MAX_INPUT_BYTES) return text;
  return new TextDecoder('utf-8').decode(bytes.subarray(0, MAX_INPUT_BYTES));
}

/** Maximal runs of the combined base64 std+url alphabet. */
const TOKEN_SPLIT_RE = /[^A-Za-z0-9+/=_-]+/;

/**
 * Derive scan views from `text`: at most one canonical "deobfuscated" view
 * (strip-invisible → fold-confusables → strip-HTML-comments →
 * collapse-whitespace, composed) followed by at most 5 decoded views
 * ("percent" whole-string first, then per-token "hex"/"base64" in token
 * order). Decode depth is exactly 1. Never mutates or returns the input.
 */
export function deobfuscate(text: string): DeobfuscationView[] {
  const t = truncateInput(text);
  const views: DeobfuscationView[] = [];

  // collapseWhitespace already trims, so non-empty here is the gateway's
  // TrimSpace(canon) != "" gate.
  const canon = collapseWhitespace(stripHtmlComments(foldConfusables(stripInvisible(t))));
  if (canon !== t && canon !== '') {
    views.push({ method: 'deobfuscated', text: canon });
  }

  // Decoded candidates run over the ORIGINAL (truncated) text, not the
  // canonical view — decoding and character folding do not compose.
  const decoded: DeobfuscationView[] = [];
  const seen = new Set<string>();
  const add = (method: DeobfuscationView['method'], out: string): void => {
    if (decoded.length >= MAX_DECODED_CANDIDATES) return;
    if (out === '' || out === t) return;
    if (seen.has(out)) return;
    if (!printableRatioOk(out)) return;
    seen.add(out);
    decoded.push({ method, text: out });
  };

  if (t.includes('%')) {
    const dec = percentDecode(t);
    if (dec !== null && dec !== t) add('percent', dec);
  }

  for (const tok of t.split(TOKEN_SPLIT_RE)) {
    if (decoded.length >= MAX_DECODED_CANDIDATES) break;
    if (tok.length < MIN_ENCODED_TOKEN_LEN) continue;
    if (isHexToken(tok)) {
      const text2 = utf8Strict(hexDecode(tok));
      if (text2 !== null) add('hex', text2);
    }
    // Not exclusive with hex: an all-hex token is also a base64 candidate.
    const b = tryBase64(tok);
    if (b !== null) add('base64', b);
  }

  return views.concat(decoded);
}

// ── Scan wrapper ──────────────────────────────────────────────────────────────

export interface DeobfuscatedScanResult {
  pii_detected: boolean;
  detected_types: string[];
  /**
   * The method of the first view that produced a detection. Absent when the
   * RAW text already matched (fast path: views are then never derived, so
   * an overt hit is byte-identical to the scanner without this layer) and
   * when nothing matched. Mirrors the gateway's Result.Via /
   * security_normalized attribute.
   */
  via?: DeobfuscationView['method'];
}

/**
 * Raw-first scan: run the builtin scanner on the raw text; only when raw is
 * clean, scan each de-obfuscation view and merge the detections.
 * DETECTION-ONLY: view matches carry no offsets into the raw text, so this
 * result must never drive span redaction (redactBuiltinPii runs on the
 * original text as before).
 */
export function runDeobfuscatedScan(
  text: string,
  views?: DeobfuscationView[],
): DeobfuscatedScanResult {
  const raw = runBuiltinPiiScan(text);
  if (raw.pii_detected) return raw;

  const all = new Set<string>();
  let via: DeobfuscationView['method'] | undefined;
  for (const v of views ?? deobfuscate(text)) {
    const r = runBuiltinPiiScan(v.text);
    if (r.pii_detected) {
      if (via === undefined) via = v.method;
      for (const t of r.detected_types) all.add(t);
    }
  }
  if (all.size === 0) return { pii_detected: false, detected_types: [] };
  return { pii_detected: true, detected_types: [...all], via };
}

// ── Pipeline wiring (config gate + view-only decision semantics) ──────────────

/**
 * Config-gated scan entry for every pipeline scan site. With the flag off
 * (the default) this IS `runBuiltinPiiScan` — byte-identical behavior, zero
 * added work. With it on, a raw-clean text is additionally scanned through
 * de-obfuscation views, and a view-only hit carries `via`.
 */
export function runConfiguredPiiScan(
  text: string,
  deob?: { enabled?: boolean },
): DeobfuscatedScanResult {
  return deob?.enabled ? runDeobfuscatedScan(text) : runBuiltinPiiScan(text);
}

/**
 * Clamp a resolved PII action for a view-only detection. `via` present means
 * the RAW text is clean (raw-first invariant), so span redaction is a
 * guaranteed no-op: a "redact" outcome would produce a false compliance
 * record (`action_taken: "redacted"`) while the encoded payload flows through
 * intact. On enforceable pre-delivery paths, `redact` therefore escalates to
 * `block`. Identity when `via` is absent.
 */
export function escalateViewOnlyAction(
  action: 'block' | 'redact' | 'detect_only',
  via: DeobfuscationView['method'] | undefined,
): 'block' | 'redact' | 'detect_only' {
  return via !== undefined && action === 'redact' ? 'block' : action;
}

/**
 * Whole-text placeholder for stored copies whose detected payload has no
 * locatable span (view-only detection). Parity-pinned in
 * conformance/fixtures/deobfuscation.json.
 */
export const OBFUSCATED_REDACTION_PLACEHOLDER = '[REDACTED:obfuscated]';

/**
 * Redact a STORED copy (blocked-event prompt/user_input, post-call stored
 * response, observe-path stored fields). With `via` absent this is exactly
 * `redactBuiltinPii` (typed span placeholders). With `via` present the spans
 * are unlocatable in the raw text, so the whole stored copy is replaced —
 * never a silently-intact "redacted" record. Detection provenance
 * (detected_types + via) still rides the event, so the record stays useful.
 */
export function redactForStorage(
  text: string,
  via: DeobfuscationView['method'] | undefined,
): string {
  return via !== undefined ? OBFUSCATED_REDACTION_PLACEHOLDER : redactBuiltinPii(text);
}
