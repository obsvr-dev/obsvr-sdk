"""Inbound external policy backend (ADR-4): OPA or Cedar.

Twin of sdk-typescript/src/policy/external-backend.ts. A customer points the SDK at their
existing policy-as-code engine (an OPA HTTP endpoint or a Cedar authorization
endpoint) and that engine's verdict participates in the pre-call decision.

Four guarantees (all pinned cross-language by
conformance/fixtures/external_backend.json):
  1. DENY-WINS merge with the local rules — a deny from EITHER side blocks; a
     backend "allow" never downgrades a local block.
  2. Fail-closed: a backend error OR timeout counts as DENY (enforce mode). A
     configurable shadow mode makes the backend observe-only (records what it
     WOULD have done, never blocks) for safe rollout.
  3. SSRF guard on the backend URL (see ssrf.py): non-http(s) schemes and
     private/loopback/link-local/metadata addresses are refused, resolving
     before connect. Any guard failure is an error outcome -> fail-closed.
  4. Provenance: the emitted event records which backend decided (identity + a
     hash of the effective backend policy) via the record returned here.

Zero-config default is NO backend (unchanged behavior). Stdlib only.
"""

import hashlib
import http.client
import json
import socket
import ssl
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .ssrf import (
    AllowedBackendAddress,
    AllowedBackendTarget,
    SsrfError,
    resolve_backend_url_allowed,
)

# Raw outcome before the shadow/fail-closed policy is applied. "error" and
# "timeout" are the fail-closed cases (deny in enforce mode); kept distinct from
# a genuine "deny" for provenance.
BackendOutcome = str  # "allow" | "deny" | "error" | "timeout"
LocalDecision = str  # "allow" | "redact" | "block"


def merge_external_backend_decision(
    local: LocalDecision, outcome: BackendOutcome, shadow: bool
) -> Dict[str, Any]:
    """DENY-WINS merge — the load-bearing, conformance-pinned function.

    A denial from EITHER side blocks; a backend "allow" never downgrades a local
    decision. ``error``/``timeout`` are denials in enforce mode (fail-closed). In
    shadow mode the backend NEVER changes the decision (observe-only), though the
    raw outcome is still recorded on the event.

    Returns {"decision", "blocked_by_backend"}.
    """
    backend_denies = outcome != "allow"  # deny | error | timeout
    if shadow:
        return {"decision": local, "blocked_by_backend": False}
    if backend_denies:
        return {"decision": "block", "blocked_by_backend": local != "block"}
    return {"decision": local, "blocked_by_backend": False}


def _url_host(url: str) -> str:
    """Host (with port when present), matching TS `new URL(url).host`."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    host = parts.hostname or url
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return host


def backend_provenance(cfg: Dict[str, Any]) -> Dict[str, str]:
    """Backend identity + effective-policy hash for provenance. The hash is a
    16-hex SHA-256 prefix of the configured policy text when present, else of the
    endpoint identity (``type|url``). Byte-identical to the TS twin."""
    btype = cfg["type"]
    url = cfg["url"]
    name = cfg.get("name")
    identity = name if isinstance(name, str) and name else f"{btype}:{_url_host(url)}"
    policy = cfg.get("policy")
    material = policy if isinstance(policy, str) and policy else f"{btype}|{url}"
    policy_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return {"identity": identity, "policy_hash": policy_hash}


def build_backend_input(
    *,
    operation: str,
    provider: str,
    model: str,
    environment: Optional[str] = None,
    user_id: Optional[str] = None,
    service_name: Optional[str] = None,
    tenant_id: Optional[str] = None,
    local_decision: LocalDecision,
    rules_hash: str,
    prompt_sha256: str,
) -> Dict[str, Any]:
    """Build the non-content decision-input document POSTed to the backend
    (digests, not raw prompts). Mirrors the TS buildBackendInput."""
    principal: Dict[str, str] = {}
    if user_id:
        principal["user_id"] = user_id
    if service_name:
        principal["service_name"] = service_name
    if tenant_id:
        principal["tenant_id"] = tenant_id
    doc: Dict[str, Any] = {
        "operation": operation,
        "provider": provider,
        "model": model,
    }
    if environment:
        doc["environment"] = environment
    doc["principal"] = principal
    doc["local_decision"] = local_decision
    doc["rules_hash"] = rules_hash
    doc["prompt_sha256"] = prompt_sha256
    return doc


def _normalize_opa(body: Any) -> Optional[Dict[str, Any]]:
    """Normalize an OPA ``result`` value into {"allow", "reasons"}."""
    if not isinstance(body, dict) or "result" not in body:
        return None  # an undefined document omits `result` -> caller: error
    result = body["result"]
    if isinstance(result, bool):
        return {"allow": result, "reasons": []}
    if isinstance(result, dict):
        reasons = [r for r in result.get("reasons", []) if isinstance(r, str)]
        if isinstance(result.get("allow"), bool):
            return {"allow": result["allow"], "reasons": reasons}
        if isinstance(result.get("deny"), bool):
            return {"allow": not result["deny"], "reasons": reasons}
        if isinstance(result.get("deny"), list):
            deny_reasons = [r for r in result["deny"] if isinstance(r, str)]
            return {
                "allow": len(result["deny"]) == 0,
                "reasons": deny_reasons or reasons,
            }
    return None


def _normalize_cedar(body: Any) -> Optional[Dict[str, Any]]:
    """Normalize a Cedar/AVP-style response into {"allow", "reasons"}."""
    if not isinstance(body, dict):
        return None
    decision = body.get("decision")
    if isinstance(decision, str):
        allow = decision.lower() == "allow"
        reasons: List[str] = []
        errors = body.get("errors")
        if errors is None and isinstance(body.get("diagnostics"), dict):
            errors = body["diagnostics"].get("errors")
        if isinstance(errors, list):
            for e in errors:
                if isinstance(e, str):
                    reasons.append(e)
                elif isinstance(e, dict) and isinstance(e.get("errorDescription"), str):
                    reasons.append(e["errorDescription"])
        return {"allow": allow, "reasons": reasons}
    return None


# Transport: fetch(url, headers, body, timeout_s) -> (status:int, parsed_json).
# Raises TimeoutError on timeout, any other Exception on error. This injectable
# seam is trusted to provide destination pinning equivalent to the production
# connector; the default retains the guard's approved address snapshot.
Transport = Callable[[str, Dict[str, str], str, float], Tuple[int, Any]]


def _connect_approved_socket(
    addresses: tuple[AllowedBackendAddress, ...], port: int, timeout_s: float
) -> socket.socket:
    """Connect directly to one approved numeric address without another lookup."""
    if timeout_s <= 0:
        raise TimeoutError("external backend timeout budget exhausted")
    last_error: Optional[OSError] = None
    for approved in addresses:
        sock = socket.socket(approved.family, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        endpoint = (
            (approved.address, port)
            if approved.family == socket.AF_INET
            else (approved.address, port, 0, 0)
        )
        try:
            sock.connect(endpoint)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is not None:
        raise last_error
    raise OSError("external backend has no approved address")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """One-shot HTTP connection whose socket destination is DNS-pinned."""

    def __init__(self, target: AllowedBackendTarget, timeout_s: float) -> None:
        host = target.parts.hostname or ""
        super().__init__(host, target.parts.port or 80, timeout=timeout_s)
        self._approved_addresses = target.addresses

    def connect(self) -> None:
        self.sock = _connect_approved_socket(
            self._approved_addresses, self.port, self.timeout
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """One-shot pinned HTTPS connection with origin-host TLS verification."""

    def __init__(
        self,
        target: AllowedBackendTarget,
        timeout_s: float,
        *,
        context: Optional[ssl.SSLContext] = None,
    ) -> None:
        host = target.parts.hostname or ""
        super().__init__(
            host,
            target.parts.port or 443,
            timeout=timeout_s,
            context=context,
        )
        self._approved_addresses = target.addresses

    def connect(self) -> None:
        raw_sock = _connect_approved_socket(
            self._approved_addresses, self.port, self.timeout
        )
        try:
            # The socket goes to an approved numeric address, but authentication
            # remains bound to the configured hostname (SNI + certificate check).
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
        except Exception:
            raw_sock.close()
            raise


def _host_header(target: AllowedBackendTarget) -> str:
    host = target.parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if target.parts.scheme == "https" else 80
    if target.parts.port is not None and target.parts.port != default_port:
        return f"{host}:{target.parts.port}"
    return host


def _urllib_transport(
    target: AllowedBackendTarget,
    headers: Dict[str, str],
    body: str,
    timeout_s: float,
) -> Tuple[int, Any]:
    """POST through a fresh connection pinned to the validated DNS snapshot."""
    conn: http.client.HTTPConnection
    if target.parts.scheme == "https":
        conn = _PinnedHTTPSConnection(target, timeout_s)
    else:
        conn = _PinnedHTTPConnection(target, timeout_s)

    request_headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in {"host", "connection", "content-length"}
    }
    request_headers.update(
        {
            "Host": _host_header(target),
            "Connection": "close",
            "Content-Length": str(len(body.encode("utf-8"))),
        }
    )
    path = target.parts.path or "/"
    if target.parts.query:
        path = f"{path}?{target.parts.query}"
    try:
        conn.request("POST", path, body=body.encode("utf-8"), headers=request_headers)
        response = conn.getresponse()
        status = response.status
        raw = response.read()
    except (socket.timeout, TimeoutError) as exc:
        raise TimeoutError(str(exc)) from exc
    finally:
        # Never reuse a socket across validation snapshots.
        conn.close()
    try:
        return status, json.loads(raw)
    except (ValueError, TypeError):
        return status, None


def evaluate_external_backend(
    cfg: Dict[str, Any],
    input_doc: Dict[str, Any],
    *,
    transport: Optional[Transport] = None,
    resolver: Optional[Callable[[str], List[str]]] = None,
) -> Dict[str, Any]:
    """Consult the backend. NEVER raises — every failure mode (SSRF block,
    network error, non-2xx, unparseable body, timeout) maps to an
    ``error``/``timeout`` outcome so the caller's fail-closed merge stays in
    control. Returns {"outcome", "reasons"}."""
    allow_priv = bool(cfg.get("allow_private_network"))
    try:
        target = resolve_backend_url_allowed(cfg["url"], allow_priv, resolver)
    except SsrfError:
        return {"outcome": "error", "reasons": ["ssrf_guard_blocked_backend_url"]}
    except Exception:
        return {"outcome": "error", "reasons": ["ssrf_guard_blocked_backend_url"]}

    payload = {"input": input_doc} if cfg["type"] == "opa" else input_doc
    body = json.dumps(payload)
    headers = {"content-type": "application/json", **(cfg.get("headers") or {})}
    # `is None`, never `or`: an explicit timeout_ms of 0 is the operator
    # saying "no budget" (which fails closed as a timeout), and `or` would
    # silently replace that zero with a laxer 2-second default. The TS twin
    # uses `?? 2000` and honors 0 the same way.
    _timeout_ms = cfg.get("timeout_ms")
    timeout_s = (2000 if _timeout_ms is None else _timeout_ms) / 1000.0
    try:
        if transport is not None:
            status, parsed = transport(cfg["url"], headers, body, timeout_s)
        else:
            status, parsed = _urllib_transport(target, headers, body, timeout_s)
    except (socket.timeout, TimeoutError):
        return {"outcome": "timeout", "reasons": ["backend_timeout"]}
    except Exception:
        return {"outcome": "error", "reasons": ["backend_error"]}

    if not (200 <= int(status) < 300):
        return {"outcome": "error", "reasons": [f"backend_http_{status}"]}
    if parsed is None:
        return {"outcome": "error", "reasons": ["backend_response_not_json"]}

    normalized = _normalize_opa(parsed) if cfg["type"] == "opa" else _normalize_cedar(parsed)
    if normalized is None:
        return {"outcome": "error", "reasons": ["backend_response_unrecognized"]}
    return {
        "outcome": "allow" if normalized["allow"] else "deny",
        "reasons": normalized["reasons"],
    }


def run_external_backend_step(
    cfg: Dict[str, Any],
    local_decision: LocalDecision,
    input_doc: Dict[str, Any],
    *,
    transport: Optional[Transport] = None,
    resolver: Optional[Callable[[str], List[str]]] = None,
) -> Dict[str, Any]:
    """One-call integration step used by the pre-call pipeline: evaluate the
    backend, merge deny-wins, and assemble the provenance record. Called only
    when the local decision is not already a block. Returns
    {"decision", "blocked_by_backend", "record"}."""
    shadow = cfg.get("shadow") is True
    ev = evaluate_external_backend(cfg, input_doc, transport=transport, resolver=resolver)
    prov = backend_provenance(cfg)
    merge = merge_external_backend_decision(local_decision, ev["outcome"], shadow)
    record: Dict[str, Any] = {
        "identity": prov["identity"],
        "policy_hash": prov["policy_hash"],
        "type": cfg["type"],
        "outcome": ev["outcome"],
        "shadow": shadow,
    }
    if ev["reasons"]:
        record["reasons"] = ev["reasons"]
    return {
        "decision": merge["decision"],
        "blocked_by_backend": merge["blocked_by_backend"],
        "record": record,
    }
