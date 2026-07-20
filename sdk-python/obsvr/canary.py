"""Canary-leak detection (honeytoken tripwire).

EXACT parity with sdk/src/policy/canary.ts.

The app MINTS a canary token and PLANTS it where only the model should ever
see it -- a system prompt, a retrieved document, a tool description, a
secret-looking config value. If that exact token later appears on a surface it
must never reach -- the model's OUTPUT, a tool-call ARGUMENT (exfil attempt), a
tool RESULT, or echoed back in USER input -- the planted context has leaked.
That is a CRITICAL, unsuppressible signal.

Hygiene (the design goal naive honeytokens miss): the raw token is
returned to the app exactly once, at mint. The registry stores only
SHA-256(token). Detection is candidate-extraction + hash-compare: a prefix
regex finds candidate tokens in text, each candidate is hashed, and the hash
is looked up in the active-canary set. So the raw secret never lives at rest,
never rides an event, and never appears in a log -- events carry only a public
token-id and a short hash prefix.

Detection runs over the de-obfuscation VIEWS as well as the raw text, so a
token exfiltrated base64/hex-encoded or split by zero-width characters is still
caught.

Honest boundary (SECURITY.md): a canary is a tripwire, not prevention. On the
response surface the tokens have already been produced; the SDK records the
leak and (where the surface is pre-delivery, e.g. a tool call or tool result)
blocks it, but it cannot un-send what a streamed response already emitted. Do
NOT plant canaries on a scanned surface -- that is a self-inflicted true
positive.
"""

import re
import secrets
import threading
from typing import Any, Dict, List, Optional

from .decision_record import sha256_hex
from .deobfuscate import deobfuscate

# Distinctive, regex-findable prefix. Lowercase; the body is lowercase hex.
CANARY_PREFIX = "obsvr-cnry-"
# 16 random bytes -> 32 lowercase hex chars = 128 bits of entropy.
_CANARY_BODY_BYTES = 16
_CANARY_BODY_LEN = _CANARY_BODY_BYTES * 2

# Candidate matcher: the prefix followed by exactly 32 hex chars. Case is
# tolerated on the hex; the canonical form is lower-cased before hashing.
_CANARY_CANDIDATE_RE = re.compile(
    CANARY_PREFIX + "[0-9a-f]{%d}" % _CANARY_BODY_LEN, re.IGNORECASE
)

MAX_CANARIES = 10_000

# Process-global registry (a canary planted anywhere leaks anywhere, so the
# scope is the process, not a per-client store). Keyed by the FULL sha256 of
# the canonical token; the value never contains the raw token.
_registry: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()
_id_counter = 0
_saturated = False


def _reset_canaries() -> None:
    """Test hook -- clears the canary registry."""
    global _id_counter, _saturated
    with _lock:
        _registry.clear()
        _id_counter = 0
        _saturated = False


def canary_registry_size() -> int:
    """Number of active canaries (the pipeline scan is skipped when 0)."""
    with _lock:
        return len(_registry)


def canary_registry_saturated() -> bool:
    """True once a mint was refused because the registry was full."""
    with _lock:
        return _saturated


def _canonical_token(raw: str) -> str:
    return raw.lower()


# Whole-text placeholder for a stored copy on a canary hit. The surface text
# contains the raw token (and possibly an encoded form), so the stored copy is
# replaced wholesale rather than splicing out every encoding -- the audit trail
# must never carry the secret it is hunting for.
CANARY_REDACTION_PLACEHOLDER = "[REDACTED:canary_leak]"


def canary_leak_telemetry(hits: List[Dict[str, Any]], surface: str) -> Dict[str, Any]:
    """Non-secret evidence bundle for a leak event (ids + hash prefixes + the
    views that surfaced it + the surface label). Rides
    ``metadata.obsvr_telemetry.canary_leak`` -- a reserved channel that
    survives metadata trimming. Never contains the raw token.
    """
    seen_via = []
    for h in hits:
        if h["via"] not in seen_via:
            seen_via.append(h["via"])
    bundle = {
        "surface": surface,
        "ids": [h["id"] for h in hits],
        "hash_prefixes": [h["hash_prefix"] for h in hits],
        "via": seen_via,
    }
    # Surface registry saturation on the leak event: when true, some minted
    # canaries were never registered (dead tripwires).
    with _lock:
        if _saturated:
            bundle["registry_saturated"] = True
    return {"canary_leak": bundle}


def mint_canary(label: Optional[str] = None) -> Dict[str, str]:
    """Mint a canary: generate a fresh token, register only its hash, and
    return the raw token to the caller exactly once.

    Returns ``{"token", "id", "hash_prefix", "registered"}``. ``token`` is the
    raw value to plant (never stored by the SDK, never on events); ``id`` and
    ``hash_prefix`` are non-secret identifiers safe to log. ``registered`` is
    False only when the registry is at its cap: the token is returned but will
    NEVER be detected (a loud warning is logged), so a dead canary is never
    silently trusted.
    """
    global _id_counter, _saturated
    body = secrets.token_hex(_CANARY_BODY_BYTES)
    token = CANARY_PREFIX + body
    full = sha256_hex(token)
    hash_prefix = full[:12]
    registered = True
    with _lock:
        idx = _id_counter
        _id_counter += 1
        cnry_id = "cnry_%s_%s" % (_to_base36(idx), hash_prefix[:6])
        if len(_registry) >= MAX_CANARIES and full not in _registry:
            # Refuse rather than evict -- evicting a planted canary silently
            # disables its tripwire. But the NEW token is then dead, so warn.
            _saturated = True
            registered = False
        else:
            rec: Dict[str, Any] = {"id": cnry_id, "hash_prefix": hash_prefix}
            if label is not None:
                rec["label"] = label
            _registry[full] = rec
    if not registered:
        import logging
        logging.getLogger("obsvr").warning(
            "canary registry is full (%d); minted canary %s is NOT active and "
            "will never be detected. Reduce live canaries or start a fresh "
            "process.",
            MAX_CANARIES,
            cnry_id,
        )
    return {
        "token": token,
        "id": cnry_id,
        "hash_prefix": hash_prefix,
        "registered": registered,
    }


def _to_base36(n: int) -> str:
    if n == 0:
        return "0"
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = digits[r] + out
    return out


def canary_candidates(text: str) -> List[Dict[str, str]]:
    """Registry-INDEPENDENT candidate extraction (pinned in canary.json).

    Finds every ``obsvr-cnry-<32hex>`` in the raw text and in each
    de-obfuscation view, reduces each to the SHA-256 of its canonical
    (lower-cased) form, and de-dupes by hash keeping the FIRST via (raw before
    views). Returns ``[{"hash", "via"}]`` -- the raw material of detection;
    the token itself is never returned.
    """
    if not text:
        return []
    seen = set()
    out: List[Dict[str, str]] = []

    def scan_surface(surface: str, via: str) -> None:
        for m in _CANARY_CANDIDATE_RE.finditer(surface):
            full = sha256_hex(_canonical_token(m.group(0)))
            if full in seen:
                continue
            seen.add(full)
            out.append({"hash": full, "via": via})

    scan_surface(text, "raw")
    for v in deobfuscate(text):
        scan_surface(v["text"], v["method"])
    return out


def scan_for_canary(text: str) -> Dict[str, Any]:
    """Scan ``text`` (and its de-obfuscation views) for any active canary.

    Returns ``{"leaked": bool, "hits": [{"id", "hash_prefix", "label"?,
    "via"}]}`` -- only non-secret identifiers, never the matched token. A no-op
    (empty result) when no canaries are registered, so the pipeline pays
    nothing until a canary is minted.
    """
    with _lock:
        if not _registry or not text:
            return {"leaked": False, "hits": []}
        active = dict(_registry)

    hits: List[Dict[str, Any]] = []
    for cand in canary_candidates(text):
        rec = active.get(cand["hash"])
        if rec is not None:
            hit = {"id": rec["id"], "hash_prefix": rec["hash_prefix"], "via": cand["via"]}
            if "label" in rec:
                hit["label"] = rec["label"]
            hits.append(hit)
    return {"leaked": bool(hits), "hits": hits}
