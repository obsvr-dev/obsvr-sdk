"""Shared benchmark library for the obsvr Python SDK harness.

Measures SDK overhead ONLY. Providers are in-process canned-response objects
and the network transport is stubbed at ``obsvr.sender.urlopen`` (the symbol
sender.py binds at import from urllib.request), so the REAL bounded queue,
batching, caller-thread HMAC signing, and drop counting all stay in the
measured path while zero provider/network time enters any number.

Honesty posture: report p50/p95/p99/mean/max, discard only the
declared warmup, and treat any crash / silent drop / chain corruption / leak as
a FINDING to record, never something to tune away.

Zero third-party deps: Python stdlib + the obsvr SDK only. Python >= 3.9.
"""

from __future__ import annotations

import array
import contextlib
import datetime
import gc
import hashlib
import hmac
import json
import math
import os
import platform
import subprocess
import sys
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── SDK bootstrap ────────────────────────────────────────────────────────────
# Repo-relative so the harness runs from any clone (this file is bench/python/bench_lib.py).
_BENCH_PY_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_REPO_ROOT = os.path.dirname(os.path.dirname(_BENCH_PY_DIR))
PUBLIC_SDK_PATH = os.path.join(PUBLIC_REPO_ROOT, "sdk-python")
SIGNING_VECTORS_PATH = os.path.join(
    PUBLIC_REPO_ROOT, "conformance", "fixtures", "signing_vectors.json"
)


def bootstrap_sdk() -> Any:
    """Import obsvr, falling back to the public tree on sys.path. Returns the
    module and asserts it resolves inside the public sdk-python tree."""
    try:
        import obsvr  # noqa: F401
    except ImportError:
        sys.path.insert(0, PUBLIC_SDK_PATH)
        import obsvr  # noqa: F811
    resolved = os.path.realpath(obsvr.__file__)
    if os.path.realpath(PUBLIC_SDK_PATH) not in resolved:
        raise RuntimeError(
            f"obsvr resolved to {resolved}, expected under {PUBLIC_SDK_PATH}"
        )
    return obsvr


# ── Streaming HMAC chain verifier (Python has no exported verifier) ──────────
class ChainVerifier:
    """Verify the SDK integrity chain on the fly, retaining nothing.

    Each event's HMAC is checked independently against a recomputation, so the
    check is correct regardless of arrival order. Ordering/linkage (seq strictly
    increments from 1; prev_sig == prior sdk_sig) is tracked with a small
    reorder buffer so a genuine out-of-order arrival is *reported*, not
    mis-counted as a failure. Fed from the single sender worker thread, so there
    are no races on this state.
    """

    def __init__(self, api_key: str) -> None:
        import obsvr.sender as sender

        self.key = sender.derive_signing_key(api_key)
        self.events = 0
        self.gaps = 0
        self.dupes = 0
        self.sig_failures = 0
        self.link_failures = 0
        self.out_of_order = 0
        self.session_mismatches = 0
        self.feed_errors = 0
        self.first_seq: Optional[int] = None
        self.session_id: Optional[str] = None
        self.sdk_version_stamped: Optional[str] = None
        self._expected_seq = 1
        self._prev_sig_expected = ""
        self._pending: Dict[int, Tuple[str, str]] = {}
        self.max_pending = 0

    def feed(self, ev: Dict[str, Any]) -> None:
        # MUST NOT raise: an exception here would propagate into sender._post,
        # be caught as "retryable", and requeue the event -> phantom dupes.
        try:
            self._feed(ev)
        except Exception:
            self.feed_errors += 1

    def _feed(self, ev: Dict[str, Any]) -> None:
        self.events += 1
        if self.sdk_version_stamped is None:
            self.sdk_version_stamped = ev.get("sdk_version")
        sess = ev.get("sdk_session_id")
        if self.session_id is None:
            self.session_id = sess
        elif sess != self.session_id:
            self.session_mismatches += 1

        prev_sig = ev.get("prev_sig") or ""
        sdk_sig = ev.get("sdk_sig")
        prompt = ev.get("prompt") or ""
        response = ev.get("response") or ""
        content_hash = hashlib.sha256((prompt + response).encode("utf-8")).hexdigest()
        payload = "|".join(
            [str(sess), str(ev.get("seq_no")), str(ev.get("timestamp_sdk")),
             content_hash, prev_sig]
        )
        expected = hmac.new(self.key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if expected != sdk_sig:
            self.sig_failures += 1

        seq = ev.get("seq_no")
        if not isinstance(seq, int):
            return
        if self.first_seq is None:
            self.first_seq = seq
        if seq < self._expected_seq or seq in self._pending:
            self.dupes += 1
            return
        if seq != self._expected_seq:
            self.out_of_order += 1
        self._pending[seq] = (prev_sig, sdk_sig or "")
        self.max_pending = max(self.max_pending, len(self._pending))
        # Drain the contiguous run and check prev_sig linkage in seq order.
        while self._expected_seq in self._pending:
            p_prev, p_sig = self._pending.pop(self._expected_seq)
            if p_prev != self._prev_sig_expected:
                self.link_failures += 1
            self._prev_sig_expected = p_sig
            self._expected_seq += 1

    def finalize(self) -> None:
        # Events left in the reorder buffer never got their predecessor: each
        # is an orphan (a real chain gap), so count them as gaps.
        self.gaps += len(self._pending)
        self._pending.clear()

    @property
    def clean(self) -> bool:
        return (
            self.gaps == 0 and self.dupes == 0 and self.sig_failures == 0
            and self.link_failures == 0 and self.session_mismatches == 0
            and self.feed_errors == 0
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "events": self.events,
            "first_seq": self.first_seq,
            "gaps": self.gaps,
            "dupes": self.dupes,
            "sig_failures": self.sig_failures,
            "link_failures": self.link_failures,
            "out_of_order": self.out_of_order,
            "session_mismatches": self.session_mismatches,
            "feed_errors": self.feed_errors,
            "max_reorder_pending": self.max_pending,
            "clean": self.clean,
        }


# ── Transport stub (patched over obsvr.sender.urlopen) ───────────────────────
class _StubResponse:
    """Minimal stand-in for the urllib response sender._post reads:
    it only looks at ``.status`` (then ``.getcode()``) and never the body."""

    def __init__(self, status: int = 200, body: bytes = b"{}") -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self.status

    def __enter__(self) -> "_StubResponse":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def close(self) -> None:
        pass


def make_transport_stub(verifier: ChainVerifier, delay_s: float = 0.0) -> Callable[..., _StubResponse]:
    """Return a urlopen replacement that parses the POSTed audit body, feeds
    each event to the verifier, and returns a 200. ``delay_s`` sleeps IN THE
    WORKER THREAD (this stub runs on the sender worker), modeling a slow ingest
    so the bounded queue overflows and drops are forced + counted."""

    def stub(req: Any, *args: Any, **kwargs: Any) -> _StubResponse:
        if delay_s:
            time.sleep(delay_s)
        try:
            full_url = getattr(req, "full_url", "") or ""
            data = getattr(req, "data", None)
            if data:
                raw = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
                parsed = json.loads(raw)
                if full_url.endswith("/ingest/batch"):
                    events = parsed if isinstance(parsed, list) else [parsed]
                    # Within-batch order is enqueue order already; sort by
                    # seq_no defensively (<=25 items) so the verifier sees seq
                    # order even if a future change reorders a batch.
                    events = sorted(events, key=lambda e: e.get("seq_no", 0))
                elif full_url.endswith("/ingest"):
                    events = [parsed]
                else:
                    events = []  # /policies, /approvals etc. — not audit events
                for ev in events:
                    verifier.feed(ev)
        except Exception:
            verifier.feed_errors += 1
        return _StubResponse(200)

    return stub


@contextlib.contextmanager
def capture(verifier: ChainVerifier, delay_s: float = 0.0):
    """Patch the sender transport for the duration of a capture. Callers MUST
    ``obsvr.sender.flush()`` inside this block before it exits so the worker is
    idle (no in-flight POST) when the original urlopen is restored."""
    import obsvr.sender as sender

    orig = sender.urlopen
    sender.urlopen = make_transport_stub(verifier, delay_s)
    try:
        yield
    finally:
        sender.urlopen = orig


# ── State resets between configs (never mid-capture) ─────────────────────────
def reset_all() -> None:
    """Reset all module-level SDK state. sdk_session_id survives (module const),
    so the chain simply restarts at seq 1 under the same session."""
    import obsvr
    import obsvr.sender as sender
    from obsvr import escrow, injection_session, rules

    obsvr._reset()                       # also clears remote + escrow
    sender._reset_sender()               # queue, stats, seq, last_sig, key
    rules._reset_quota()                 # request + token quota stores
    injection_session._reset_injection_sessions()
    escrow._reset_escrow()


# ── Mock OpenAI-shaped provider (in-process, canned response) ────────────────
class _Message:
    __slots__ = ("content", "role")

    def __init__(self, content: str) -> None:
        self.content = content
        self.role = "assistant"


class _Choice:
    __slots__ = ("message", "finish_reason", "index")

    def __init__(self, content: str) -> None:
        self.message = _Message(content)
        self.finish_reason = "stop"
        self.index = 0


class _Usage:
    __slots__ = ("prompt_tokens", "completion_tokens", "total_tokens")

    def __init__(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = prompt_tokens + completion_tokens


class _Response:
    __slots__ = ("choices", "usage", "id", "model", "system_fingerprint", "object")

    def __init__(self, content: str, p: int, c: int, model: str) -> None:
        self.choices = [_Choice(content)]
        self.usage = _Usage(p, c)
        self.id = "chatcmpl-bench"
        self.model = model
        self.system_fingerprint = "fp_bench"
        self.object = "chat.completion"


class _Completions:
    __slots__ = ("_content", "_p", "_c")

    def __init__(self, content: str, p: int, c: int) -> None:
        self._content = content
        self._p = p
        self._c = c

    def create(self, *, model: str, messages: Any = None, **kwargs: Any) -> _Response:
        return _Response(self._content, self._p, self._c, model)


class _Chat:
    __slots__ = ("completions",)

    def __init__(self, completions: _Completions) -> None:
        self.completions = completions


class MockOpenAI:
    """Duck-typed OpenAI client: ``.chat.completions.create`` returns an object
    with ``.choices[0].message.content`` + ``.usage`` (matches wrap.py's
    _extract_response_text / _extract_usage for provider 'openai')."""

    def __init__(self, response_text: str = "ok", prompt_tokens: int = 12,
                 completion_tokens: int = 8) -> None:
        self.chat = _Chat(_Completions(response_text, prompt_tokens, completion_tokens))


# ── Deterministic benign prompt generation ───────────────────────────────────
# Vocabulary chosen to contain NONE of the PII/secret/injection regexes nor any
# multi-turn weak-signal phrase (no pronouns/modal verbs, no digits, no
# "ignore/previous/system/instructions/restrictions/disable/reveal/..."). Joined
# with spaces so no 120+ char run can match the base64 "encoded_blob" signal.
_BENIGN_WORDS = [
    "quarterly", "revenue", "forecast", "meeting", "notes", "summary", "weather",
    "harbor", "maple", "orchard", "lantern", "compass", "meadow", "granite",
    "willow", "cobalt", "amber", "cedar", "brook", "thistle", "pebble", "canyon",
    "harvest", "pottery", "ledger", "invoice", "shipment", "warehouse", "catalog",
    "cushion", "blanket", "kettle", "teapot", "biscuit", "cinnamon", "almond",
    "picnic", "garden", "sparrow", "otter", "badger", "heron", "trellis",
    "cobblestone", "marina", "plaza", "atrium", "gallery", "mural", "fountain",
    "voyage", "compassion", "melody", "harmony", "rhythm", "canvas", "palette",
    "sketch", "bakery", "espresso", "muffin", "seminar", "workshop", "roster",
    "agenda", "milestone", "roadmap", "backlog", "sprint", "retro", "standup",
]


def benign_prompt(target_chars: int, seed: int) -> str:
    import random

    rnd = random.Random(seed)
    parts: List[str] = []
    length = 0
    while length < target_chars:
        w = rnd.choice(_BENIGN_WORDS)
        parts.append(w)
        length += len(w) + 1
    text = " ".join(parts)
    return text[:target_chars] if len(text) > target_chars else text


def benign_pool(count: int, min_chars: int = 300, max_chars: int = 500,
                seed: int = 1) -> List[str]:
    import random

    rnd = random.Random(seed)
    return [benign_prompt(rnd.randint(min_chars, max_chars), seed + i) for i in range(count)]


# ── Statistics (microseconds) ────────────────────────────────────────────────
def percentiles(samples: "array.array") -> Dict[str, float]:
    n = len(samples)
    if n == 0:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0, "max": 0.0,
                "min": 0.0, "n": 0}
    ordered = sorted(samples)  # sort once

    def rank(p: float) -> float:
        idx = int(math.ceil(p / 100.0 * n)) - 1
        idx = min(n - 1, max(0, idx))
        return ordered[idx]

    return {
        "p50": rank(50), "p95": rank(95), "p99": rank(99),
        "mean": math.fsum(ordered) / n, "max": ordered[-1], "min": ordered[0],
        "n": n,
    }


def delta_percentiles(gov: Dict[str, float], base: Dict[str, float]) -> Dict[str, float]:
    """delta-of-percentiles: governed pX minus ungoverned pX, per percentile.
    This is NOT a per-call delta (percentiles of different runs don't subtract
    per-sample); it is the shift of each percentile point, labeled as such."""
    return {k: gov[k] - base[k] for k in ("p50", "p95", "p99", "mean", "max")}


# ── Signing-vector cross-check (validate our verifier vs the shared fixture) ──
def verify_signing_vectors(path: str = SIGNING_VECTORS_PATH) -> Dict[str, Any]:
    """Recompute the SDK signature for each shared cross-language vector and
    compare to the pinned expected value; also confirm the derived key matches
    the fixture's signing_key_hex. Proves the streaming verifier's recipe is the
    SDK's own byte-for-byte recipe."""
    import obsvr.sender as sender

    result: Dict[str, Any] = {"path": path, "passed": False, "key_match": False,
                              "events_checked": 0, "mismatches": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            fx = json.load(f)
    except Exception as e:  # noqa: BLE001
        result["error"] = f"could not read fixture: {e}"
        return result

    key = sender.derive_signing_key(fx["api_key"])
    result["key_match"] = key.hex() == fx.get("signing_key_hex")
    session_id = fx["session_id"]
    for ev in fx.get("events", []):
        prompt = ev.get("prompt") or ""
        response = ev.get("response") or ""
        content_hash = hashlib.sha256((prompt + response).encode("utf-8")).hexdigest()
        payload = "|".join([session_id, str(ev["seq_no"]),
                            str(ev["timestamp_sdk"]), content_hash,
                            ev.get("prev_sig") or ""])
        got = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        result["events_checked"] += 1
        if got != ev.get("sdk_sig"):
            result["mismatches"].append({"seq_no": ev["seq_no"], "expected":
                                        ev.get("sdk_sig"), "got": got})
    result["passed"] = result["key_match"] and not result["mismatches"]
    return result


# ── Environment / meta ───────────────────────────────────────────────────────
def _sysctl(key: str) -> Optional[str]:
    try:
        return subprocess.check_output(["sysctl", "-n", key], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def _git_head(repo: str = PUBLIC_REPO_ROOT) -> Optional[str]:
    try:
        return subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"],
                                       text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def _os_version() -> str:
    try:
        v = subprocess.check_output(["sw_vers", "-productVersion"], text=True,
                                    stderr=subprocess.DEVNULL).strip()
        return f"macOS {v}"
    except Exception:
        return platform.platform()


def collect_meta(lang: str, part: str, args: Dict[str, Any]) -> Dict[str, Any]:
    import obsvr

    mem = _sysctl("hw.memsize")
    cores = _sysctl("hw.ncpu")
    return {
        "lang": lang,
        "part": part,
        "sdk_version_manifest": obsvr.__version__,
        "sdk_version_stamped": None,  # filled from a real event after first run
        "python": platform.python_version(),
        "os": _os_version(),
        "cpu": _sysctl("machdep.cpu.brand_string") or platform.processor() or "unknown",
        "cores": int(cores) if cores and cores.isdigit() else None,
        "ram_gb": round(int(mem) / (1024 ** 3)) if mem and mem.isdigit() else None,
        "date_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git_rev": _git_head(),
        "args": args,
    }


def write_json(path: str, meta: Dict[str, Any], rows: List[Dict[str, Any]]) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "rows": rows}, f, indent=2)
    return os.path.abspath(path)


# ── Memory sampling ──────────────────────────────────────────────────────────
def rss_mb(pid: Optional[int] = None) -> Optional[float]:
    pid = pid or os.getpid()
    try:
        out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)],
                                      text=True, stderr=subprocess.DEVNULL).strip()
        return int(out) / 1024.0  # ps reports KB -> MB
    except Exception:
        return None


def peak_rss_mb() -> Optional[float]:
    try:
        import resource

        ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # macOS reports bytes; Linux reports KB. Platform here is darwin.
        return ru / (1024.0 * 1024.0) if sys.platform == "darwin" else ru / 1024.0
    except Exception:
        return None


# ── Policy-rule / config builders ────────────────────────────────────────────
BASE_INIT: Dict[str, Any] = dict(
    api_key="bench-key",
    ingest_url="http://127.0.0.1:9",
    policy_refresh_interval_s=0,
    auto=False,
)

MULTI_TURN_INJECTION: Dict[str, Any] = {
    "enabled": True, "threshold": 1.0, "half_life_s": 600.0, "action": "block",
}


def _rule(rid: str, rtype: str, action: str = "flag",
          conditions: Optional[Dict[str, Any]] = None,
          mode: Optional[str] = None, applies_to: Optional[str] = None) -> Any:
    from obsvr.rules import PolicyRule

    return PolicyRule(id=rid, name=rid, enabled=True, action=action, type=rtype,
                      conditions=conditions or {}, applies_to=applies_to, mode=mode)


def _nonmatching(i: int) -> Any:
    types = ["keyword", "regex", "topic_deny", "model_gate"]
    t = types[i % len(types)]
    if t == "keyword":
        c = {"keywords": [f"nomatch_kw_{i}"]}
    elif t == "regex":
        c = {"pattern": f"nomatch_rx_{i}_[abcxyz]{{6}}"}
    elif t == "topic_deny":
        c = {"topics": [f"nomatch_topic_{i}"]}
    else:
        c = {"denied_models": [f"banned_model_{i}"]}
    return _rule(f"r{i}", t, conditions=c)


def n_rules(n: int) -> List[Any]:
    return [_nonmatching(i) for i in range(n)]


def quota_rule() -> Any:
    # High limit + long window => never blocks; measures the quota meter cost.
    return _rule("q_user", "quota", action="flag", conditions={
        "quota_limit": 10_000_000, "quota_window_ms": 60_000,
        "quota_scope": "user_id", "quota_unit": "requests",
    })


def shadow_rule() -> Any:
    return _rule("shadow1", "keyword", action="block", mode="shadow",
                 conditions={"keywords": ["nomatch_shadow_kw"]})


def _noop_pre(event: Dict[str, Any]) -> str:
    return "allow"


def _noop_post(response: str, event: Dict[str, Any]) -> str:
    return "pass"


def part_a_config(tier: str) -> Dict[str, Any]:
    """Return {init_kwargs, needs_user_id, governed} for a Part A ladder tier."""
    if tier == "U":
        return {"init_kwargs": None, "needs_user_id": False, "governed": False}
    init = dict(BASE_INIT)
    needs_user_id = False
    if tier == "A0":
        pass
    elif tier == "A1":
        init["policy_rules"] = [
            _rule("kw1", "keyword", conditions={"keywords": ["nomatch_keyword_alpha"]}),
            _rule("rx1", "regex", conditions={"pattern": r"nomatch_pattern_[qwxz]{7}"}),
            _rule("td1", "topic_deny", conditions={"topics": ["nonexistent_topic_omega"]}),
            _rule("mg1", "model_gate", conditions={"denied_models": ["banned-model-zzz"]}),
            _rule("kw2", "keyword", conditions={"keywords": ["nomatch_keyword_beta"]}),
        ]
    elif tier == "A2":
        init["policy_rules"] = part_a_config("A1")["init_kwargs"]["policy_rules"]
        init["pii_policy"] = {}
    elif tier == "A3":
        init["policy_rules"] = part_a_config("A1")["init_kwargs"]["policy_rules"] + [quota_rule()]
        init["pii_policy"] = {}
        needs_user_id = True
    elif tier == "A4":
        init["policy_rules"] = (
            part_a_config("A1")["init_kwargs"]["policy_rules"]
            + [quota_rule(), shadow_rule()]
        )
        init["pii_policy"] = {}
        init["on_pre_call"] = _noop_pre
        init["on_post_call"] = _noop_post
        init["multi_turn_injection"] = MULTI_TURN_INJECTION
        needs_user_id = True
    else:
        raise ValueError(f"unknown Part A tier {tier!r}")
    return {"init_kwargs": init, "needs_user_id": needs_user_id, "governed": True}


def part_b_config(tier: str) -> Dict[str, Any]:
    """Return {init_kwargs, needs_user_id} for a Part B stress tier."""
    init = dict(BASE_INIT)
    needs_user_id = False
    if tier == "L0":
        pass
    elif tier == "L1":
        init["policy_rules"] = [
            _rule("kw1", "keyword", conditions={"keywords": ["nomatch_keyword_alpha"]}),
            _rule("rx1", "regex", conditions={"pattern": r"nomatch_pattern_[qwxz]{7}"}),
            _rule("td1", "topic_deny", conditions={"topics": ["nonexistent_topic_omega"]}),
        ]
    elif tier == "L2":
        init["policy_rules"] = n_rules(6) + [quota_rule()]
        init["pii_policy"] = {}
        needs_user_id = True
    elif tier == "L3":
        init["policy_rules"] = n_rules(12) + [quota_rule(), shadow_rule()]
        init["pii_policy"] = {}
        init["on_pre_call"] = _noop_pre
        init["on_post_call"] = _noop_post
        init["multi_turn_injection"] = MULTI_TURN_INJECTION
        init["fail_mode"] = "closed"  # safe: staleness gate is disabled when
        needs_user_id = True          # policy_refresh_interval_s == 0
    else:
        raise ValueError(f"unknown Part B tier {tier!r}")
    return {"init_kwargs": init, "needs_user_id": needs_user_id, "governed": True}


# ── Per-call error accounting ────────────────────────────────────────────────
class ErrorLog:
    def __init__(self, keep: int = 5) -> None:
        self.count = 0
        self.tracebacks: List[str] = []
        self._keep = keep

    def record(self, exc: BaseException) -> None:
        self.count += 1
        if len(self.tracebacks) < self._keep:
            self.tracebacks.append("".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            ))

    def to_dict(self) -> Dict[str, Any]:
        return {"count": self.count, "first_tracebacks": self.tracebacks}


def load_check(uptime_warn: float = 4.0) -> Dict[str, Any]:
    la = os.getloadavg()[0] if hasattr(os, "getloadavg") else None
    return {"load_avg_1m": la, "warn": bool(la is not None and la > uptime_warn)}
