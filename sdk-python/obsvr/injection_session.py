"""Multi-turn prompt-injection scoring (parity with injection-session.ts).

Single-message scanning misses split attacks: an injection payload spread
across several turns where no one message trips a pattern. This module
keeps a per-session score that accumulates weighted weak signals with
exponential decay, and trips once the decayed sum crosses a threshold.

Weights, patterns, decay math, and the first-turn guard mirror the
TypeScript SDK so both SDKs render the same verdicts.
"""

import math
import re
import threading
import time
from typing import Any, Dict, List

from .normalize import normalize_for_matching

MAX_SESSIONS = 10_000

# Weak signals: innocuous alone, characteristic in combination.
WEAK_SIGNALS: List[Dict[str, Any]] = [
    {"label": "instruction_reference", "pattern": re.compile(r"\b(?:previous|prior|above|original|initial)\s+(?:instructions?|prompts?|rules?|messages?)\b", re.I), "weight": 0.35},
    {"label": "ignore_fragment", "pattern": re.compile(r"\b(?:ignore|disregard|forget|don'?t\s+follow)\b.{0,40}\b(?:that|this|it|them|everything)\b", re.I), "weight": 0.35},
    {"label": "system_prompt_probe", "pattern": re.compile(r"\b(?:system|hidden|secret|internal)\s+(?:prompt|instructions?|message|configuration)\b", re.I), "weight": 0.4},
    {"label": "role_reassignment", "pattern": re.compile(r"\b(?:you\s+are\s+now|from\s+now\s+on\s+you|your\s+new\s+(?:role|task|instructions?))\b", re.I), "weight": 0.4},
    {"label": "constraint_probe", "pattern": re.compile(r"\b(?:restrictions?|limitations?|filters?|guidelines?|guardrails?)\b.{0,40}\b(?:remove|without|disable|off|bypass|free)\b", re.I), "weight": 0.4},
    {"label": "reverse_constraint_probe", "pattern": re.compile(r"\b(?:remove|without|disable|bypass|lift)\b.{0,40}\b(?:restrictions?|limitations?|filters?|guardrails?|safety)\b", re.I), "weight": 0.4},
    {"label": "delimiter_spoof", "pattern": re.compile(r"(?:</?(?:system|assistant|instructions?)>|\[/?(?:SYSTEM|INST)\]|###\s*(?:system|instruction))", re.I), "weight": 0.5},
    {"label": "encoded_blob", "pattern": re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b"), "weight": 0.25},
    {"label": "continuation_marker", "pattern": re.compile(r"\b(?:as\s+(?:i|we)\s+(?:said|discussed|agreed)\s+(?:before|earlier)|continuing\s+from\s+(?:before|my\s+last)|remember\s+what\s+i\s+told\s+you)\b", re.I), "weight": 0.25},
]

_sessions: Dict[str, Dict[str, float]] = {}
_lock = threading.Lock()


def _decayed(entry: Dict[str, float], now: float, half_life_s: float) -> float:
    dt = now - entry["updated_at"]
    if dt <= 0:
        return entry["score"]
    return entry["score"] * math.pow(0.5, dt / half_life_s)


def _evict_if_needed(now: float, half_life_s: float) -> None:
    if len(_sessions) < MAX_SESSIONS:
        return
    for k in [k for k, v in _sessions.items() if _decayed(v, now, half_life_s) < 0.05]:
        del _sessions[k]
    if len(_sessions) >= MAX_SESSIONS:
        oldest = sorted(_sessions.items(), key=lambda kv: kv[1]["updated_at"])
        for k, _ in oldest[: len(oldest) // 2]:
            del _sessions[k]


def score_turn(
    session_key: str,
    prompt_text: str,
    had_full_match: bool,
    threshold: float = 1.0,
    half_life_s: float = 600.0,
) -> Dict[str, Any]:
    """Score one turn; report whether the accumulated decayed score tripped.

    had_full_match marks that the single-turn scanner already found a full
    injection pattern in this prompt (weight 1.0 toward the session score).
    """
    now = time.time()
    signals: List[str] = []
    turn_score = 1.0 if had_full_match else 0.0
    # Normalize before matching (homoglyph/zero-width/bidi fold), so a staged
    # injection spelled with confusables can't accrue zero weak-signal score.
    norm_text = normalize_for_matching(prompt_text)
    for s in WEAK_SIGNALS:
        if s["pattern"].search(norm_text):
            signals.append(s["label"])
            turn_score += s["weight"]

    with _lock:
        _evict_if_needed(now, half_life_s)
        existing = _sessions.get(session_key)
        base = _decayed(existing, now, half_life_s) if existing else 0.0
        turns = int(existing["turns"]) + 1 if existing else 1
        entry = {"score": base + turn_score, "updated_at": now, "turns": float(turns)}
        _sessions[session_key] = entry

    # A single weak signal on the very first turn must not trip the gate;
    # the whole point is accumulation. Require history, 2+ signals, or a
    # full match (parity with the TS SDK).
    tripped = entry["score"] >= threshold and (turns > 1 or len(signals) >= 2 or had_full_match)
    return {"tripped": tripped, "score": entry["score"], "signals": signals, "turns": turns}


def get_session_score(session_key: str, half_life_s: float = 600.0) -> float:
    with _lock:
        entry = _sessions.get(session_key)
        return _decayed(entry, time.time(), half_life_s) if entry else 0.0


def _reset_injection_sessions() -> None:
    with _lock:
        _sessions.clear()
