/**
 * Multi-turn prompt-injection scoring.
 *
 * Single-message scanning misses split attacks: an attacker distributes an
 * injection payload across several turns so no one message trips a pattern.
 * This module keeps a per-session score that accumulates weak injection
 * signals over time with exponential decay, and trips once the decayed sum
 * crosses a threshold - even though every individual turn looked benign.
 *
 * Scoring:
 * - full builtin injection-pattern match: weight 1.0 (the single-turn scan
 *   blocks these anyway; recording them keeps follow-up turns suspicious)
 * - weak signal (fragment that is individually innocuous but characteristic
 *   of staged injections): weight per signal, most 0.25-0.5
 * - score decays with a configurable half-life (default 10 minutes)
 *
 * Sessions are keyed by end-user (metadata user_id) when present, else the
 * whole process shares one bucket. Memory is bounded and expired entries are
 * evicted lazily.
 */

import { normalizeForMatching } from "./normalize.js";

export interface MultiTurnInjectionConfig {
  enabled?: boolean;
  /** Decayed score at which the gate trips. @default 1.0 */
  threshold?: number;
  /** Half-life of the accumulated score in ms. @default 600000 (10 min) */
  halfLifeMs?: number;
  /** What to do when the threshold trips. @default "block" */
  action?: "block" | "flag";
}

interface SessionScore {
  score: number;
  updatedAt: number;
  turns: number;
}

const sessions = new Map<string, SessionScore>();
const MAX_SESSIONS = 10_000;

/** Weak signals: innocuous alone, characteristic in combination. */
const WEAK_SIGNALS: { label: string; pattern: RegExp; weight: number }[] = [
  { label: "instruction_reference", pattern: /\b(?:previous|prior|above|original|initial)\s+(?:instructions?|prompts?|rules?|messages?)\b/i, weight: 0.35 },
  { label: "ignore_fragment", pattern: /\b(?:ignore|disregard|forget|don'?t\s+follow)\b.{0,40}\b(?:that|this|it|them|everything)\b/i, weight: 0.35 },
  { label: "system_prompt_probe", pattern: /\b(?:system|hidden|secret|internal)\s+(?:prompt|instructions?|message|configuration)\b/i, weight: 0.4 },
  { label: "role_reassignment", pattern: /\b(?:you\s+are\s+now|from\s+now\s+on\s+you|your\s+new\s+(?:role|task|instructions?))\b/i, weight: 0.4 },
  { label: "constraint_probe", pattern: /\b(?:restrictions?|limitations?|filters?|guidelines?|guardrails?)\b.{0,40}\b(?:remove|without|disable|off|bypass|free)\b/i, weight: 0.4 },
  { label: "reverse_constraint_probe", pattern: /\b(?:remove|without|disable|bypass|lift)\b.{0,40}\b(?:restrictions?|limitations?|filters?|guardrails?|safety)\b/i, weight: 0.4 },
  { label: "delimiter_spoof", pattern: /(?:<\/?(?:system|assistant|instructions?)>|\[\/?(?:SYSTEM|INST)\]|###\s*(?:system|instruction))/i, weight: 0.5 },
  { label: "encoded_blob", pattern: /\b[A-Za-z0-9+/]{120,}={0,2}\b/, weight: 0.25 },
  { label: "continuation_marker", pattern: /\b(?:as\s+(?:i|we)\s+(?:said|discussed|agreed)\s+(?:before|earlier)|continuing\s+from\s+(?:before|my\s+last)|remember\s+what\s+i\s+told\s+you)\b/i, weight: 0.25 },
];

function decayed(entry: SessionScore, now: number, halfLifeMs: number): number {
  const dt = now - entry.updatedAt;
  if (dt <= 0) return entry.score;
  return entry.score * Math.pow(0.5, dt / halfLifeMs);
}

function evictIfNeeded(now: number, halfLifeMs: number): void {
  if (sessions.size < MAX_SESSIONS) return;
  // Drop entries whose decayed score is negligible; if still over budget,
  // drop the oldest half. Both passes are O(n) and rare.
  for (const [k, v] of sessions) {
    if (decayed(v, now, halfLifeMs) < 0.05) sessions.delete(k);
  }
  if (sessions.size >= MAX_SESSIONS) {
    const entries = [...sessions.entries()].sort((a, b) => a[1].updatedAt - b[1].updatedAt);
    for (let i = 0; i < entries.length / 2; i++) sessions.delete(entries[i][0]);
  }
}

export interface MultiTurnResult {
  tripped: boolean;
  /** Decayed score after this turn's signals were added. */
  score: number;
  /** Weak-signal labels found in this turn. */
  signals: string[];
  turns: number;
}

/**
 * Score one turn for a session and report whether the accumulated decayed
 * score crossed the threshold. `hadFullMatch` marks that the single-turn
 * scanner already found a full injection pattern in this prompt.
 */
export function scoreTurn(
  sessionKey: string,
  promptText: string,
  hadFullMatch: boolean,
  config: Required<Pick<MultiTurnInjectionConfig, "threshold" | "halfLifeMs">>,
): MultiTurnResult {
  const now = Date.now();
  evictIfNeeded(now, config.halfLifeMs);

  const signals: string[] = [];
  let turnScore = hadFullMatch ? 1.0 : 0;
  // Normalize before matching (homoglyph/zero-width/bidi fold), so a staged
  // injection spelled with confusables can't accrue zero weak-signal score.
  const normText = normalizeForMatching(promptText);
  for (const s of WEAK_SIGNALS) {
    if (s.pattern.test(normText)) {
      signals.push(s.label);
      turnScore += s.weight;
    }
  }

  const existing = sessions.get(sessionKey);
  const base = existing ? decayed(existing, now, config.halfLifeMs) : 0;
  const next: SessionScore = {
    score: base + turnScore,
    updatedAt: now,
    turns: (existing?.turns ?? 0) + 1,
  };
  sessions.set(sessionKey, next);

  // A single weak signal on the very first turn must not trip the gate -
  // the whole point is accumulation. Require either history or 2+ signals.
  const tripped =
    next.score >= config.threshold &&
    (next.turns > 1 || signals.length >= 2 || hadFullMatch);

  return { tripped, score: next.score, signals, turns: next.turns };
}

/** Current decayed score for a session (0 when unknown). For tests/inspection. */
export function getSessionScore(sessionKey: string, halfLifeMs = 600_000): number {
  const entry = sessions.get(sessionKey);
  return entry ? decayed(entry, Date.now(), halfLifeMs) : 0;
}

/** @internal test hook */
export function _resetInjectionSessions(): void {
  sessions.clear();
}
