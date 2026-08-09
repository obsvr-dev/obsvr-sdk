/**
 * Presidio Integration for the SDK
 *
 * SDK-local helpers for NLP-level PII detection and redaction via the
 * Presidio analyzer and anonymizer services.
 *
 * Detection returns an explicit `answered` bit so callers can distinguish an
 * empty result from an unavailable analyzer. Redaction returns null on any
 * unavailable stage; a caller applying an NLP-only redaction must fail closed
 * rather than fall back to a regex tier that cannot locate that type.
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

/** PII labels the built-in regex tier cannot locate. */
export const NLP_ONLY_PII_TYPES: ReadonlySet<string> = new Set([
  'name',
  'address',
  'person',
  'location',
  'medical',
  'national_id',
]);

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

/** Call /analyze on Presidio; reports an unanswered result on any error. */
async function analyzeText(
  text: string,
  analyzerUrl: string,
  timeoutMs: number,
): Promise<{
  answered: boolean;
  results: Array<{ entity_type: string; start: number; end: number; score: number }>;
}> {
  try {
    const res = await fetch(`${analyzerUrl}/analyze`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      // Send case-normalized text so spaCy NER catches lowercase proper nouns.
      // Positions in the response still map to the original text (case-only change).
      body:    JSON.stringify({ text: normalizeForNer(text), language: 'en' }),
      signal:  buildAbortSignal(timeoutMs),
    });
    if (!res.ok) return { answered: false, results: [] };
    const data = await res.json();
    if (!Array.isArray(data)) return { answered: false, results: [] };
    return {
      answered: true,
      results: data as Array<{ entity_type: string; start: number; end: number; score: number }>,
    };
  } catch {
    return { answered: false, results: [] };
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
 * `answered` distinguishes a healthy empty result from timeout/error.
 */
export async function presidioScan(
  text: string,
  analyzerUrl: string,
  timeoutMs = 500,
): Promise<{ detected_types: string[]; answered: boolean }> {
  const analyzed = await analyzeText(text, analyzerUrl, timeoutMs);
  const types = [
    ...new Set(
      analyzed.results
        .map(r => PRESIDIO_TO_LABEL[r.entity_type])
        .filter((t): t is string => t !== undefined),
    ),
  ];
  return { detected_types: types, answered: analyzed.answered };
}

/**
 * Redact a single text string via Presidio analyze + anonymize.
 * Returns the anonymized string, or null on any failure. Callers may use the
 * built-in fallback only when no NLP-only redaction is required.
 */
export async function presidioRedactText(
  text: string,
  analyzerUrl: string,
  anonymizerUrl: string,
  timeoutMs = 500,
): Promise<string | null> {
  const analyzed = await analyzeText(text, analyzerUrl, timeoutMs);
  if (!analyzed.answered) return null;
  if (analyzed.results.length === 0) return text;
  return anonymizeText(text, analyzed.results, anonymizerUrl, timeoutMs);
}

/**
 * Walk structured LLM request args and redact each text node with Presidio.
 * Falls back to redactBuiltinPii per node on Presidio failure unless an
 * NLP-only redaction is required, in which case it throws so the caller can
 * refuse the provider call.
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
  requireNlpRedaction = false,
): Promise<void> {
  if (!args || typeof args !== 'object') return;
  const req = args as Record<string, unknown>;
  let changedByPresidio = false;

  const redactText = async (text: string): Promise<string> => {
    const redacted = await presidioRedactText(
      text,
      analyzerUrl,
      anonymizerUrl,
      timeoutMs,
    );
    if (redacted === null) {
      if (requireNlpRedaction) {
        throw new Error('Presidio did not answer while applying an NLP-only redaction');
      }
      return redactBuiltinPii(text);
    }
    if (redacted !== text) changedByPresidio = true;
    return redactBuiltinPii(redacted);
  };

  // Anthropic system prompt
  if (typeof req.system === 'string') {
    req.system = await redactText(req.system);
  }

  // OpenAI / Anthropic messages[]
  if (Array.isArray(req.messages)) {
    for (const msg of req.messages as Array<Record<string, unknown>>) {
      if (typeof msg.content === 'string') {
        msg.content = await redactText(msg.content);
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content as Array<Record<string, unknown>>) {
          if (typeof part.text === 'string') {
            part.text = await redactText(part.text);
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
            part.text = await redactText(part.text);
          }
        }
      }
    }
  }

  if (requireNlpRedaction && !changedByPresidio) {
    throw new Error('Presidio did not remove the detected NLP-only PII type');
  }
}
