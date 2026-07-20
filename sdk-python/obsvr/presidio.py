"""Presidio integration (parity with sdk/src/policy/presidio.ts).

NLP-level PII detection and redaction via the Microsoft Presidio analyzer
and anonymizer services. Every function is failure-safe: network errors and
timeouts return empty results / None so the caller falls back to the
built-in regex scanner. Entity mappings and typed placeholders mirror the
TypeScript SDK exactly, so both SDKs produce identical detected_types and
redacted output for the same Presidio deployment.
"""

import json
import re
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

# Presidio entity type -> internal PII label (parity with presidio.ts)
PRESIDIO_TO_LABEL: Dict[str, str] = {
    "PERSON": "name",
    "EMAIL_ADDRESS": "email",
    "US_SSN": "ssn",
    "PHONE_NUMBER": "phone",
    "IP_ADDRESS": "ip_address",
    "CREDIT_CARD": "credit_card",
    "LOCATION": "location",
    "US_BANK_NUMBER": "bank_account",
    "IBAN_CODE": "iban",
    "MEDICAL_LICENSE": "medical",
    "NRP": "national_id",
    "DATE_TIME": "date",
}

# Typed placeholders sent to the anonymizer per entity type
ENTITY_PLACEHOLDERS: Dict[str, str] = {
    "PERSON": "[REDACTED_PERSON]",
    "EMAIL_ADDRESS": "[REDACTED_EMAIL]",
    "US_SSN": "[REDACTED_SSN]",
    "PHONE_NUMBER": "[REDACTED_PHONE]",
    "IP_ADDRESS": "[REDACTED_IP]",
    "CREDIT_CARD": "[REDACTED_CC]",
    "LOCATION": "[REDACTED_LOCATION]",
}

_WORD_START = re.compile(r"\b[a-z]")


def _normalize_for_ner(text: str) -> str:
    """Capitalize word starts so spaCy NER catches lowercase proper nouns.

    Case-only change: character positions are identical to the original, so
    analyzer spans apply to the original text as-is.
    """
    return _WORD_START.sub(lambda m: m.group(0).upper(), text)


def _post_json(url: str, payload: Dict[str, Any], timeout_s: float) -> Optional[Any]:
    try:
        req = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urlopen(req, timeout=timeout_s)
        return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _analyze(text: str, analyzer_url: str, timeout_s: float) -> List[Dict[str, Any]]:
    """Call /analyze; [] on any error."""
    data = _post_json(
        f"{analyzer_url}/analyze",
        {"text": _normalize_for_ner(text), "language": "en"},
        timeout_s,
    )
    return data if isinstance(data, list) else []


def presidio_scan(
    text: str, analyzer_url: str, timeout_s: float = 0.5
) -> Dict[str, List[str]]:
    """Scan text with the Presidio analyzer.

    Returns {"detected_types": [...]} using internal labels; empty on error.
    """
    results = _analyze(text, analyzer_url, timeout_s)
    seen: List[str] = []
    for r in results:
        label = PRESIDIO_TO_LABEL.get(r.get("entity_type", ""))
        if label and label not in seen:
            seen.append(label)
    return {"detected_types": seen}


def presidio_redact_text(
    text: str,
    analyzer_url: str,
    anonymizer_url: str,
    timeout_s: float = 0.5,
) -> Optional[str]:
    """Redact one string via analyze + anonymize.

    Returns the anonymized string, the original when nothing was detected,
    or None on failure (caller should fall back to regex redaction).
    """
    results = _analyze(text, analyzer_url, timeout_s)
    if not results:
        return text
    # Per-entity replace anonymizers with typed placeholders. Presidio
    # anonymizer expects the key "anonymizers", NOT "operators".
    anonymizers = {
        r["entity_type"]: {"type": "replace", "new_value": ENTITY_PLACEHOLDERS[r["entity_type"]]}
        for r in results
        if r.get("entity_type") in ENTITY_PLACEHOLDERS
    }
    data = _post_json(
        f"{anonymizer_url}/anonymize",
        {"text": text, "analyzer_results": results, "anonymizers": anonymizers},
        timeout_s,
    )
    if isinstance(data, dict) and isinstance(data.get("text"), str):
        return data["text"]
    return None


def presidio_redact_kwargs(
    kwargs: Dict[str, Any],
    analyzer_url: str,
    anonymizer_url: str,
    timeout_s: float = 0.5,
) -> None:
    """Walk structured LLM request kwargs and redact each text node in place.

    Falls back to the built-in regex redactor per node on Presidio failure.
    Handles system (Anthropic), messages[].content (OpenAI/Anthropic, string
    or parts[]), and contents[].parts[].text (Gemini).
    """
    from .policy import redact_builtin_pii

    def _redact(text: str) -> str:
        out = presidio_redact_text(text, analyzer_url, anonymizer_url, timeout_s)
        return out if out is not None else redact_builtin_pii(text)

    if isinstance(kwargs.get("system"), str):
        kwargs["system"] = _redact(kwargs["system"])

    if isinstance(kwargs.get("messages"), list):
        for msg in kwargs["messages"]:
            if not isinstance(msg, dict):
                continue
            if isinstance(msg.get("content"), str):
                msg["content"] = _redact(msg["content"])
            elif isinstance(msg.get("content"), list):
                for part in msg["content"]:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        part["text"] = _redact(part["text"])

    if isinstance(kwargs.get("contents"), list):
        for content in kwargs["contents"]:
            if isinstance(content, dict) and isinstance(content.get("parts"), list):
                for part in content["parts"]:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        part["text"] = _redact(part["text"])
