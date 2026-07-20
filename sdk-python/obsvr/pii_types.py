"""Shared PII type constants — single source of truth for Python SDK.
Mirrors sdk/src/policy/pii-types.ts exactly.
"""
from typing import Dict, List, Literal

PII_TYPES: List[str] = [
    "email",
    "phone",
    "ssn",
    "credit_card",
    "ip_address",
    "api_key",
    "aws_access_key",
    "jwt",
    "uuid",
    "name",
    "address",
    "person",
    "location",
    "medical",
    "national_id",
    "private_key",
    "github_token",
    "slack_webhook",
    "prompt_injection",
]

PiiPolicyAction = Literal["block", "redact", "detect_only"]

# Built-in severity defaults
BUILTIN_SEVERITY: Dict[str, str] = {
    "ssn":              "block",
    "credit_card":      "block",
    "api_key":          "block",
    "aws_access_key":   "block",
    "jwt":              "block",
    # redact (not block) — the regex matches ANY dotted quad, so blocking
    # hard-fails calls that merely mention an IP. Redaction masks it instead.
    "ip_address":       "redact",
    "private_key":      "block",
    "github_token":     "block",
    "slack_webhook":    "block",
    "prompt_injection": "block",
    "email":            "redact",
    "phone":            "redact",
    # uuid, name, address -> implicit detect_only
}
