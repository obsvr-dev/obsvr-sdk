"""Where did this call actually go? - the one place that decides.

Twin: sdk-typescript/src/proxy/provider-attribution.ts.

THE DEFECT THIS REPLACES. ``_detect_provider`` duck-types on the client's
shape: anything exposing ``chat.completions`` is labelled "openai", whatever
host it points at. Measured against a local server, the front door recorded
``provider: "openai"`` next to ``model: "qwen2.5-coder:14b"`` - a model that
endpoint does not serve, beside a vendor the request never reached. The same
defect was fixed once on the TypeScript compat wrappers and left standing on
both front doors, which is how the first repair read as complete while the
defect stayed reachable through the door most callers use.

WHAT IS RECORDED. The provider is taken from the endpoint whenever the endpoint
can be read, and the duck-typed label is a fallback rather than an assertion.
Where the host is visible but cannot be named, ``unknown`` is recorded: vague is
a lesser fault than wrong. ``provider_attribution`` states which of those
happened, borrowing the trust vocabulary ``provenance_source`` already uses for
``model_resolved``, so a reader can tell a checked value from a declared one.
"""

import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

__all__ = [
    "ATTRIBUTION_OPTION_KEY",
    "RECORDED_PROVIDER_OPTION_KEY",
    "read_base_url",
    "resolve_destination",
]

#: Reserved keys on the per-wrap options dict. The options dict already reaches
#: every emit site, so carrying the decision there avoids threading two more
#: positional arguments through eleven call sites and the eight functions
#: between them.
RECORDED_PROVIDER_OPTION_KEY = "_obsvr_recorded_provider"
ATTRIBUTION_OPTION_KEY = "_obsvr_provider_attribution"

#: Hosts whose identity we can state, and what to call them.
#:
#: ``provider`` is constrained to the ingest canonical enum. A destination the
#: enum cannot express records ``provider: "unknown"`` and keeps its real
#: identity in ``provider_detail`` - the same carriage mcp already uses, rather
#: than widening a union the backend would reject.
_KNOWN_ENDPOINTS: Tuple[Tuple[Any, str, str], ...] = (
    (re.compile(r"(^|\.)together\.(xyz|ai)$", re.I), "together", "together"),
    (re.compile(r"(^|\.)openai\.azure\.com$", re.I), "azure_openai", "azure_openai"),
    (re.compile(r"(^|\.)openai\.com$", re.I), "openai", "openai"),
    (re.compile(r"(^|\.)anthropic\.com$", re.I), "anthropic", "anthropic"),
    (re.compile(r"(^|\.)googleapis\.com$", re.I), "google", "google"),
    (re.compile(r"(^|\.)cloudflare\.com$", re.I), "cloudflare", "cloudflare"),
    # Real destinations the canonical enum has no member for.
    (re.compile(r"(^|\.)groq\.com$", re.I), "unknown", "groq"),
    (re.compile(r"(^|\.)mistral\.ai$", re.I), "unknown", "mistral"),
    (re.compile(r"(^|\.)fireworks\.ai$", re.I), "unknown", "fireworks"),
    (re.compile(r"(^|\.)perplexity\.ai$", re.I), "unknown", "perplexity"),
    (re.compile(r"(^|\.)deepseek\.com$", re.I), "unknown", "deepseek"),
)

#: A local server is a destination too, and a materially different one.
_LOCAL_HOSTS = re.compile(
    r"^(localhost|127\.0\.0\.1|\[::1\]|::1|0\.0\.0\.0|host\.docker\.internal)$", re.I
)


def read_base_url(client: Any) -> Optional[str]:
    """The client's configured base URL, if it will tell us.

    Read defensively: this runs against any client shape at all, a property may
    raise, and a wrapper that crashed while working out what to call something
    would be a worse failure than a vague label. ``base_url`` on the modern
    client is a URL object rather than a string, so it is stringified.
    """
    for key in ("base_url", "baseURL", "baseUrl"):
        try:
            value = getattr(client, key, None)
        except Exception:  # noqa: BLE001 - a raising property is a non-answer
            continue
        if value is None:
            continue
        text = value if isinstance(value, str) else str(value)
        if text:
            return text
    return None


def _safe_host(base_url: str) -> Tuple[Optional[str], Optional[str]]:
    """Host and port only - never credentials, path or query.

    A base URL is a place users put secrets (``https://user:token@host/v1``),
    and this value goes into an audit record that gets shipped and stored. Only
    the destination is wanted here, and only the destination is taken.
    """
    try:
        parts = urlsplit(base_url)
        if not parts.hostname:
            return None, None
        return parts.netloc.rsplit("@", 1)[-1], parts.hostname
    except Exception:  # noqa: BLE001
        return None, None


def resolve_destination(client: Any, declared: str) -> Tuple[str, Dict[str, Any]]:
    """Decide what to record about where this call is going.

    ``declared`` is the fallback: the duck-typed detection. It is used only when
    no base URL can be read, and the record says so when it is.
    """
    base_url = read_base_url(client)
    if not base_url:
        # Nothing to check against. The declared label is all there is, and the
        # record says so rather than presenting it as verified.
        return declared, {"provider_attribution": "client_declared"}

    host, hostname = _safe_host(base_url)
    if not hostname:
        return declared, {"provider_attribution": "client_declared"}

    if _LOCAL_HOSTS.match(hostname):
        return "unknown", {
            "provider_attribution": "endpoint",
            "provider_detail": "local",
            "endpoint_host": host,
        }

    for pattern, provider, detail in _KNOWN_ENDPOINTS:
        if pattern.search(hostname):
            return provider, {
                "provider_attribution": "endpoint",
                "provider_detail": detail,
                "endpoint_host": host,
            }

    # A host we have no name for - a private gateway, a proxy, a new vendor.
    # Recording the caller's guess here is what produced the original defect.
    return "unknown", {
        "provider_attribution": "endpoint",
        "provider_detail": "unrecognized_endpoint",
        "endpoint_host": host,
    }
