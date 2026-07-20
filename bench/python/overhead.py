#!/usr/bin/env python3
"""Part A — per-call SDK overhead micro-benchmark for the obsvr Python SDK.

Ladder U -> A0 -> A1 -> A2 -> A3 -> A4 (each delta vs the previous is that
governance stage's cost). Measures ONLY caller-thread SDK work: signing + event
build + decision record + enqueue happen synchronously in the calling thread;
the stubbed transport POST runs off-thread on the sender worker, so no
provider/network time is in any sample. Reports µs p50/p95/p99/mean/max plus the
delta-of-percentiles vs the ungoverned baseline.

Also proves fire-and-forget emission: A0 rerun with a 25ms-per-POST transport
stub (in the worker thread) must leave the caller hot-path p95 unchanged.

Usage:
  python overhead.py [--iters N] [--tier U,A0,..] [--payload small|large|both]
                     [--out FILE] [--quick]
"""

from __future__ import annotations

import argparse
import array
import os
import sys
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench_lib as bl  # noqa: E402

MODEL = "gpt-4o-mini"
RESPONSE = "This is a benign canned response used for benchmarking only."
LADDER = ["U", "A0", "A1", "A2", "A3", "A4"]
SMALL_CHARS = 100
LARGE_CHARS = 10_000
# Spec payload matrix: small for the whole ladder; 10KB for U/A0/A2/A4.
LARGE_TIERS = {"U", "A0", "A2", "A4"}


def _measure_raw(prompt: str, iters: int, warmup: int) -> Dict[str, Any]:
    """Ungoverned baseline: time the raw mock call in the same shape/loop."""
    bl.reset_all()
    client = bl.MockOpenAI(response_text=RESPONSE)
    messages = [{"role": "user", "content": prompt}]
    kwargs = {"model": MODEL, "messages": messages}
    errlog = bl.ErrorLog()
    for _ in range(warmup):
        client.chat.completions.create(**kwargs)
    samples = array.array("d")
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        try:
            client.chat.completions.create(**kwargs)
        except Exception as e:  # noqa: BLE001
            errlog.record(e)
            continue
        samples.append((time.perf_counter_ns() - t0) / 1000.0)
    return {"pct": bl.percentiles(samples), "errors": errlog}


def _measure_governed(tier: str, prompt: str, iters: int, warmup: int,
                      delay_s: float = 0.0) -> Dict[str, Any]:
    import obsvr

    cfg = bl.part_a_config(tier)
    bl.reset_all()
    obsvr.init(**cfg["init_kwargs"])
    client = obsvr.wrap(bl.MockOpenAI(response_text=RESPONSE))
    messages = [{"role": "user", "content": prompt}]
    base_kwargs = {"model": MODEL, "messages": messages}
    needs_uid = cfg["needs_user_id"]
    user_ids = [f"u{i}" for i in range(100)]
    errlog = bl.ErrorLog()
    verifier = bl.ChainVerifier(cfg["init_kwargs"]["api_key"])
    samples = array.array("d")

    with bl.capture(verifier, delay_s=delay_s):
        for i in range(warmup):
            kw = dict(base_kwargs, obsvr_metadata={"user_id": user_ids[i % 100]}) if needs_uid else base_kwargs
            try:
                client.chat.completions.create(**kw)
            except Exception as e:  # noqa: BLE001
                errlog.record(e)
        for i in range(iters):
            if needs_uid:
                kw = dict(base_kwargs, obsvr_metadata={"user_id": user_ids[i % 100]})
            else:
                kw = base_kwargs
            t0 = time.perf_counter_ns()
            try:
                client.chat.completions.create(**kw)
            except Exception as e:  # noqa: BLE001
                errlog.record(e)
                continue
            samples.append((time.perf_counter_ns() - t0) / 1000.0)
        obsvr.sender.flush(timeout=30.0)
        verifier.finalize()

    stats = obsvr.sender.get_sender_stats()
    total_calls = warmup + iters
    enqueued = stats.get("enqueued", 0)
    dropped = stats.get("dropped_overflow", 0)
    invariant_calls = (total_calls == enqueued + dropped)
    invariant_verified = (verifier.events == enqueued)
    return {
        "pct": bl.percentiles(samples), "errors": errlog, "verifier": verifier,
        "stats": stats, "total_calls": total_calls, "enqueued": enqueued,
        "dropped_overflow": dropped,
        "invariant_calls_eq_enqueued_plus_dropped": invariant_calls,
        "invariant_verified_eq_enqueued": invariant_verified,
    }


def _cells_for(tiers: List[str], payload_pref: str) -> List[Dict[str, str]]:
    cells: List[Dict[str, str]] = []
    for tier in tiers:
        want_small = payload_pref in ("small", "both")
        want_large = payload_pref in ("large", "both") and tier in LARGE_TIERS
        if payload_pref == "both":
            want_small = True
            want_large = tier in LARGE_TIERS
        if want_small:
            cells.append({"tier": tier, "payload": "small"})
        if want_large:
            cells.append({"tier": tier, "payload": "large"})
    return cells


def run(args: argparse.Namespace) -> Dict[str, Any]:
    iters = 500 if args.quick else args.iters
    warmup = 200 if args.quick else 2000
    tiers = LADDER if args.tier in (None, "all") else [t.strip() for t in args.tier.split(",")]
    payload_pref = args.payload

    prompts = {
        "small": bl.benign_prompt(SMALL_CHARS, seed=101),
        "large": bl.benign_prompt(LARGE_CHARS, seed=202),
    }
    cells = _cells_for(tiers, payload_pref)

    rows: List[Dict[str, Any]] = []
    u_pct: Dict[str, Dict[str, float]] = {}
    stamped: Optional[str] = None

    for cell in cells:
        tier, payload = cell["tier"], cell["payload"]
        prompt = prompts[payload]
        if tier == "U":
            m = _measure_raw(prompt, iters, warmup)
            u_pct[payload] = m["pct"]
            rows.append({"tier": "U", "payload": payload, "governed": False,
                         "pct_us": m["pct"], "errors": m["errors"].to_dict()})
        else:
            m = _measure_governed(tier, prompt, iters, warmup)
            if stamped is None and m["verifier"].sdk_version_stamped:
                stamped = m["verifier"].sdk_version_stamped
            base = u_pct.get(payload) or u_pct.get("small")
            rows.append({
                "tier": tier, "payload": payload, "governed": True,
                "pct_us": m["pct"],
                "delta_of_percentiles_vs_U_us": bl.delta_percentiles(m["pct"], base) if base else None,
                "chain": m["verifier"].to_dict(),
                "sender_stats": m["stats"],
                "total_calls": m["total_calls"], "enqueued": m["enqueued"],
                "dropped_overflow": m["dropped_overflow"],
                "invariant_calls_eq_enqueued_plus_dropped": m["invariant_calls_eq_enqueued_plus_dropped"],
                "invariant_verified_eq_enqueued": m["invariant_verified_eq_enqueued"],
                "errors": m["errors"].to_dict(),
            })

    # Fire-and-forget proof: A0 small, fast vs slow (25ms/POST in worker).
    faf = None
    if "A0" in tiers and payload_pref in ("small", "both", "large"):
        fast = _measure_governed("A0", prompts["small"], iters, warmup, delay_s=0.0)
        slow = _measure_governed("A0", prompts["small"], iters, warmup, delay_s=0.025)
        faf = {
            "iters": iters,
            "fast_transport": {"p95_us": fast["pct"]["p95"], "p50_us": fast["pct"]["p50"],
                               "dropped_overflow": fast["dropped_overflow"],
                               "chain_clean": fast["verifier"].clean},
            "slow_transport_25ms": {"p95_us": slow["pct"]["p95"], "p50_us": slow["pct"]["p50"],
                                    "dropped_overflow": slow["dropped_overflow"],
                                    "chain_clean": slow["verifier"].clean},
        }
        p95f = fast["pct"]["p95"] or 1.0
        faf["p95_ratio_slow_over_fast"] = round(slow["pct"]["p95"] / p95f, 3)

    meta = bl.collect_meta("py", "A", vars(args))
    meta["sdk_version_stamped"] = stamped
    meta["load_check"] = bl.load_check()
    return {"meta": meta, "rows": rows, "fire_and_forget": faf}


def _print_table(result: Dict[str, Any]) -> None:
    print("\n=== Part A: per-call overhead (microseconds) ===")
    hdr = f"{'tier':<5} {'payload':<7} {'n':>7} {'p50':>9} {'p95':>9} {'p99':>9} {'mean':>9} {'max':>10}  {'dp95vsU':>9}  chain"
    print(hdr)
    print("-" * len(hdr))
    for r in result["rows"]:
        p = r["pct_us"]
        dp = r.get("delta_of_percentiles_vs_U_us")
        dp95 = f"{dp['p95']:.2f}" if dp else "-"
        if r["governed"]:
            c = r["chain"]
            chain = f"ev={c['events']} clean={c['clean']} inv={r['invariant_calls_eq_enqueued_plus_dropped'] and r['invariant_verified_eq_enqueued']} err={r['errors']['count']}"
        else:
            chain = f"err={r['errors']['count']}"
        print(f"{r['tier']:<5} {r['payload']:<7} {p['n']:>7} {p['p50']:>9.2f} "
              f"{p['p95']:>9.2f} {p['p99']:>9.2f} {p['mean']:>9.2f} {p['max']:>10.2f}  {dp95:>9}  {chain}")
    faf = result.get("fire_and_forget")
    if faf:
        print("\n=== Fire-and-forget proof (A0 small) ===")
        f, s = faf["fast_transport"], faf["slow_transport_25ms"]
        print(f"fast POST : p95={f['p95_us']:.2f}us  dropped_overflow={f['dropped_overflow']}  chain_clean={f['chain_clean']}")
        print(f"slow 25ms : p95={s['p95_us']:.2f}us  dropped_overflow={s['dropped_overflow']}  chain_clean={s['chain_clean']}")
        print(f"p95 ratio (slow/fast) = {faf['p95_ratio_slow_over_fast']} (want ~1.0: emission is not awaited inline)")


def main() -> None:
    ap = argparse.ArgumentParser(description="obsvr Python SDK Part A overhead bench")
    ap.add_argument("--iters", type=int, default=10_000)
    ap.add_argument("--tier", type=str, default="all")
    ap.add_argument("--payload", type=str, default="both", choices=["small", "large", "both"])
    ap.add_argument("--out", type=str, default=None)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()

    bl.bootstrap_sdk()
    result = run(args)
    _print_table(result)

    out = args.out or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "results",
        f"py_overhead{'_quick' if args.quick else ''}.json"
    )
    meta = result["meta"]
    meta["fire_and_forget"] = result["fire_and_forget"]
    path = bl.write_json(out, meta, result["rows"])
    print(f"\nJSON written: {path}")


if __name__ == "__main__":
    main()
