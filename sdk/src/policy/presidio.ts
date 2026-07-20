/**
 * Presidio Integration for the SDK
 *
 * SDK-local helpers for NLP-level PII detection and redaction via the
 * Microsoft Presidio analyzer and anonymizer services.
 *
 * All functions are fire-and-forget safe: they return [] / null on any
 * network error or timeout so the caller can fall back to regex scanning.
 *
 * @packageDocumentation
 */

import { redactBuiltinPii } from './hook.js';

// ── Entity mappings ───────────────────────────────────────────────────────────

/** Map Presidio entity type → our internal PII label */
const PRESIDIO_TO_LABEL: Record<string, string> = {
  PERSON:           'name',
  EMAIL_ADDRESS:    'email',
  US_SSN:           'ssn',
  PHONE_NUMBER:     'phone',
  IP_ADDRESS:       'ip_address',
  CREDIT_CARD:      'credit_card',
  LOCATION:         'location',
  US_BANK_NUMBER:   'bank_account',
  IBAN_CODE:        'iban',
  MEDICAL_LICENSE:  'medical',
  NRP:              'national_id',
  DATE_TIME:        'date',
};

/** Typed placeholders sent to the Presidio anonymizer per entity type */
const ENTITY_PLACEHOLDERS: Record<string, string> = {
  PERSON:        '[REDACTED_PERSON]',
  EMAIL_ADDRESS: '[REDACTED_EMAIL]',
  US_SSN:        '[REDACTED_SSN]',
  PHONE_NUMBER:  '[REDACTED_PHONE]',
  IP_ADDRESS:    '[REDACTED_IP]',
  CREDIT_CARD:   '[REDACTED_CC]',
  LOCATION:      '[REDACTED_LOCATION]',
};

// ── Internal helpers ──────────────────────────────────────────────────────────

function buildAbortSignal(timeoutMs: number): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

/**
 * Capitalize the first letter of every lowercase-starting word so spaCy NER
 * recognizes names regardless of input casing (e.g. "bob" → "Bob").
 * Only the first character of each word is changed, so character positions
 * remain identical to the original - analyzer spans can be applied as-is.
 */
function normalizeForNer(text: string): string {
  return text.replace(/\b[a-z]/g, c => c.toUpperCase());
}

/** Call /analyze on Presidio; returns [] on any error. */
async function analyzeText(
  text: string,
  analyzerUrl: string,
  timeoutMs: number,
): Promise<Array<{ entity_type: string; start: number; end: number; score: number }>> {
  try {
    const res = await fetch(`${analyzerUrl}/analyze`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      // Send case-normalized text so spaCy NER catches lowercase proper nouns.
      // Positions in the response still map to the original text (case-only change).
      body:    JSON.stringify({ text: normalizeForNer(text), language: 'en' }),
      signal:  buildAbortSignal(timeoutMs),
    });
    if (!res.ok) return [];
    return (await res.json()) as Array<{ entity_type: string; start: number; end: number; score: number }>;
  } catch {
    return [];
  }
}

/** Call /anonymize on Presidio; returns null on any error. */
async function anonymizeText(
  text: string,
  analyzerResults: Array<{ entity_type: string; start: number; end: number; score: number }>,
  anonymizerUrl: string,
  timeoutMs: number,
): Promise<string | null> {
  try {
    // Build per-entity replace anonymizers using our typed placeholders.
    // Presidio anonymizer expects the key "anonymizers", NOT "operators".
    const anonymizers: Record<string, { type: string; new_value: string }> = {};
    for (const r of analyzerResults) {
      if (ENTITY_PLACEHOLDERS[r.entity_type]) {
        anonymizers[r.entity_type] = {
          type:      'replace',
          new_value: ENTITY_PLACEHOLDERS[r.entity_type],
        };
      }
    }

    const res = await fetch(`${anonymizerUrl}/anonymize`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ text, analyzer_results: analyzerResults, anonymizers }),
      signal:  buildAbortSignal(timeoutMs),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { text?: string };
    return data.text ?? null;
  } catch {
    return null;
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Scan a text string with the Presidio analyzer.
 * Returns detected_types (our internal labels) or [] on timeout/error.
 */
export async function presidioScan(
  text: string,
  analyzerUrl: string,
  timeoutMs = 500,
): Promise<{ detected_types: string[] }> {
  const results = await analyzeText(text, analyzerUrl, timeoutMs);
  const types = [
    ...new Set(
      results
        .map(r => PRESIDIO_TO_LABEL[r.entity_type])
        .filter((t): t is string => t !== undefined),
    ),
  ];
  return { detected_types: types };
}

/**
 * Redact a single text string via Presidio analyze + anonymize.
 * Returns the anonymized string, or null on any failure (caller should fall back).
 */
export async function presidioRedactText(
  text: string,
  analyzerUrl: string,
  anonymizerUrl: string,
  timeoutMs = 500,
): Promise<string | null> {
  const results = await analyzeText(text, analyzerUrl, timeoutMs);
  if (results.length === 0) return text; // nothing detected - return original
  return anonymizeText(text, results, anonymizerUrl, timeoutMs);
}

/**
 * Walk structured LLM request args and redact each text node with Presidio.
 * Falls back to redactBuiltinPii per node on Presidio failure.
 *
 * Handles:
 * - req.system          (string) - Anthropic system prompt
 * - req.messages[].content (string | parts[]) - OpenAI / Anthropic
 * - req.contents[].parts[].text - Gemini structured
 */
export async function presidioRedactArgs(
  args: unknown,
  analyzerUrl: string,
  anonymizerUrl: string,
  timeoutMs = 500,
): Promise<void> {
  if (!args || typeof args !== 'object') return;
  const req = args as Record<string, unknown>;

  // Anthropic system prompt
  if (typeof req.system === 'string') {
    req.system =
      (await presidioRedactText(req.system, analyzerUrl, anonymizerUrl, timeoutMs)) ??
      redactBuiltinPii(req.system);
  }

  // OpenAI / Anthropic messages[]
  if (Array.isArray(req.messages)) {
    for (const msg of req.messages as Array<Record<string, unknown>>) {
      if (typeof msg.content === 'string') {
        msg.content =
          (await presidioRedactText(msg.content, analyzerUrl, anonymizerUrl, timeoutMs)) ??
          redactBuiltinPii(msg.content);
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content as Array<Record<string, unknown>>) {
          if (typeof part.text === 'string') {
            part.text =
              (await presidioRedactText(part.text, analyzerUrl, anonymizerUrl, timeoutMs)) ??
              redactBuiltinPii(part.text);
          }
        }
      }
    }
  }

  // Gemini contents[].parts[].text
  if (Array.isArray(req.contents)) {
    for (const content of req.contents as Array<Record<string, unknown>>) {
      if (Array.isArray(content.parts)) {
        for (const part of content.parts as Array<Record<string, unknown>>) {
          if (typeof part.text === 'string') {
            part.text =
              (await presidioRedactText(part.text, analyzerUrl, anonymizerUrl, timeoutMs)) ??
              redactBuiltinPii(part.text);
          }
        }
      }
    }
  }
}
