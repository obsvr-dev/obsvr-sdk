#!/usr/bin/env python3
"""Part B — sustained stress test for the obsvr Python SDK.

Per tier (L0..L3): a sequential sync loop of governed calls (primary
throughput + latency metric), memory sampled on a cadence with a leak
assertion, streaming chain verification (retaining nothing), a signing-vector
cross-check, per-call error accounting, and a sender-stats dump. Then a burst
phase (tight loop with a 10ms-per-POST transport stub) proves bounded-queue
overflow: drops are counted, RSS stays bounded, and the chain of the events
that WERE enqueued still verifies (drops happen before signing, so they never
create chain gaps).

Usage:
  python stress.py [--calls N] [--tier L0|L1|L2|L3|all] [--burst-calls N]
                   [--out FILE] [--quick]
"""

from __future__ import annotations

import argparse
import array
import gc
import os
import sys
import time
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench_lib as bl  # noqa: E402

MODEL = "gpt-4o-mini"
RESPONSE = "This is a benign canned response used for benchmarking only."
TIERS = ["L0", "L1", "L2", "L3"]
# Slow the worker's POST so it drains ~25/BURST_POST_DELAY_S events per second
# (~500/s here) — well below every tier's sequential caller rate — so the tight
# producer loop reliably overflows the bounded queue at ALL tiers. The spec
# suggested 10ms, but at 10ms the drain (~2500/s) keeps up with the fully
# governed L2/L3 caller (which is itself only ~1800-2500/s), so the queue never
# fills. 50ms forces the counted-overflow path uniformly; the behavior proven
# (drops counted, RSS bounded, enqueued chain still verifies) is identical.
BURST_POST_DELAY_S = 0.050


def _sample_rss(curve: List[Dict[str, Any]], call: int) -> None:
    r = bl.rss_mb()
    if r is not None:
        curve.append({"call": call, "rss_mb": round(r, 2)})


def _leak_assessment(curve: List[Dict[str, Any]], total: int) -> Dict[str, Any]:
    if len(curve) < 2:
        return {"evaluated": False}
    q25_call = 0.25 * total
    baseline = next((s for s in curve if s["call"] >= q25_call), curve[0])
    end = curve[-1]
    growth = end["rss_mb"] - baseline["rss_mb"]
    threshold = max(30.0, 0.15 * baseline["rss_mb"])
    # Monotonicity eyeball: slope over the last quartile of samples.
    q75_call = 0.75 * total
    last_q = [s for s in curve if s["call"] >= q75_call] or curve[-2:]
    last_q_growth = last_q[-1]["rss_mb"] - last_q[0]["rss_mb"]
    return {
        "evaluated": True,
        "baseline_rss_mb": baseline["rss_mb"], "baseline_call": baseline["call"],
        "end_rss_mb": end["rss_mb"], "growth_mb": round(growth, 2),
        "threshold_mb": round(threshold, 2),
        "leak_ok": growth < threshold,
        "last_quartile_growth_mb": round(last_q_growth, 2),
        "last_quartile_positive_beyond_noise": last_q_growth > 5.0,
    }


def _run_sequential(tier: str, calls: int, mem_interval: int) -> Dict[str, Any]:
    import obsvr

    cfg = bl.part_b_config(tier)
    bl.reset_all()
    obsvr.init(**cfg["init_kwargs"])
    client = obsvr.wrap(bl.MockOpenAI(response_text=RESPONSE))
    needs_uid = cfg["needs_user_id"]
    user_ids = [f"u{i}" for i in range(100)]
    prompts = bl.benign_pool(1000, 300, 500, seed=7)
    base_kwargs = {"model": MODEL, "messages": None}

    verifier = bl.ChainVerifier(cfg["init_kwargs"]["api_key"])
    errlog = bl.ErrorLog()
    samples = array.array("d")
    mem_curve: List[Dict[str, Any]] = []

    gc.collect()
    _sample_rss(mem_curve, 0)

    with bl.capture(verifier, delay_s=0.0):
        wall0 = time.perf_counter()
        for i in range(calls):
            msg = [{"role": "user", "content": prompts[i % 1000]}]
            if needs_uid:
                kw = {"model": MODEL, "messages": msg, "obsvr_metadata": {"user_id": user_ids[i % 100]}}
            else:
                kw = {"model": MODEL, "messages": msg}
            t0 = time.perf_counter_ns()
            try:
                client.chat.completions.create(**kw)
            except Exception as e:  # noqa: BLE001
                errlog.record(e)
                continue
            samples.append((time.perf_counter_ns() - t0) / 1000.0)
            if (i + 1) % mem_interval == 0:
                _sample_rss(mem_curve, i + 1)
        wall = time.perf_counter() - wall0
        obsvr.sender.flush(timeout=60.0)
        verifier.finalize()
        gc.collect()
        _sample_rss(mem_curve, calls)

    stats = obsvr.sender.get_sender_stats()
    enqueued = stats.get("enqueued", 0)
    dropped = stats.get("dropped_overflow", 0)
    pct = bl.percentiles(samples)
    leak = _leak_assessment(mem_curve, calls)
    signing = bl.verify_signing_vectors()
    v = verifier
    passed = (
        v.events > 0 and v.clean and errlog.count == 0
        and (calls == enqueued + dropped) and (v.events == enqueued)
        and signing["passed"]
    )
    return {
        "tier": tier, "phase": "sequential", "calls": calls,
        "wall_s": round(wall, 4),
        "throughput_calls_per_s": round(calls / wall, 1) if wall > 0 else None,
        "latency_us": pct,
        "memory": {"curve": mem_curve, "leak": leak, "peak_rss_mb": bl.peak_rss_mb()},
        "chain": v.to_dict(),
        "signing_vectors_crosscheck": signing,
        "sender_stats": stats, "enqueued": enqueued, "dropped_overflow": dropped,
        "invariant_calls_eq_enqueued_plus_dropped": (calls == enqueued + dropped),
        "invariant_verified_eq_enqueued": (v.events == enqueued),
        "errors": errlog.to_dict(),
        "tier_pass": passed,
    }


def _run_burst(tier: str, burst_calls: int) -> Dict[str, Any]:
    """Tight loop with a slow transport stub to force counted overflow drops
    while the enqueued events' chain still verifies."""
    import obsvr

    # Reuse the tier's policy config (already initialized by the sequential
    # phase); reset only the sender so stats/seq restart cleanly for this phase.
    obsvr.sender._reset_sender()
    cfg = bl.part_b_config(tier)
    client = obsvr.wrap(bl.MockOpenAI(response_text=RESPONSE))
    needs_uid = cfg["needs_user_id"]
    prompt = bl.benign_prompt(400, seed=99)
    msg = [{"role": "user", "content": prompt}]

    verifier = bl.ChainVerifier(cfg["init_kwargs"]["api_key"])
    errlog = bl.ErrorLog()
    rss_before = bl.rss_mb()
    with bl.capture(verifier, delay_s=BURST_POST_DELAY_S):
        for i in range(burst_calls):
            if needs_uid:
                kw = {"model": MODEL, "messages": msg, "obsvr_metadata": {"user_id": f"u{i % 100}"}}
            else:
                kw = {"model": MODEL, "messages": msg}
            try:
                client.chat.completions.create(**kw)
            except Exception as e:  # noqa: BLE001
                errlog.record(e)
        obsvr.sender.flush(timeout=120.0)
        verifier.finalize()
    rss_after = bl.rss_mb()

    stats = obsvr.sender.get_sender_stats()
    enqueued = stats.get("enqueued", 0)
    dropped = stats.get("dropped_overflow", 0)
    v = verifier
    rss_growth = (rss_after - rss_before) if (rss_before and rss_after) else None
    passed = (
        dropped > 0 and v.events > 0 and v.clean and errlog.count == 0
        and (burst_calls == enqueued + dropped) and (v.events == enqueued)
        and (rss_growth is None or rss_growth < 60.0)
    )
    return {
        "tier": tier, "phase": "burst", "burst_calls": burst_calls,
        "post_delay_ms": BURST_POST_DELAY_S * 1000,
        "chain": v.to_dict(), "sender_stats": stats,
        "enqueued": enqueued, "dropped_overflow": dropped,
        "rss_before_mb": round(rss_before, 2) if rss_before else None,
        "rss_after_mb": round(rss_after, 2) if rss_after else None,
        "rss_growth_mb": round(rss_growth, 2) if rss_growth is not None else None,
        "invariant_calls_eq_enqueued_plus_dropped": (burst_calls == enqueued + dropped),
        "invariant_verified_eq_enqueued": (v.events == enqueued),
        "errors": errlog.to_dict(),
        "burst_pass": passed,
    }


def run(args: argparse.Namespace) -> Dict[str, Any]:
    calls = 5000 if args.quick else args.calls
    burst_calls = args.burst_calls if args.burst_calls else (3000 if args.quick else 10_000)
    mem_interval = 1000 if args.quick else 5000
    tiers = TIERS if args.tier in (None, "all") else [t.strip() for t in args.tier.split(",")]

    rows: List[Dict[str, Any]] = []
    for tier in tiers:
        rows.append(_run_sequential(tier, calls, mem_interval))
        rows.append(_run_burst(tier, burst_calls))

    import obsvr

    meta = bl.collect_meta("py", "B", vars(args))
    meta["sdk_version_stamped"] = f"python/{obsvr.__version__}"
    meta["load_check"] = bl.load_check()
    return {"meta": meta, "rows": rows}


def _print_table(result: Dict[str, Any]) -> None:
    print("\n=== Part B: sustained stress ===")
    for r in result["rows"]:
        if r["phase"] == "sequential":
            p = r["latency_us"]
            leak = r["memory"]["leak"]
            print(f"\n[{r['tier']}] sequential  calls={r['calls']}  "
                  f"throughput={r['throughput_calls_per_s']}/s  wall={r['wall_s']}s")
            print(f"    latency us: p50={p['p50']:.2f} p95={p['p95']:.2f} "
                  f"p99={p['p99']:.2f} max={p['max']:.2f}")
            c = r["chain"]
            print(f"    chain: events={c['events']} gaps={c['gaps']} dupes={c['dupes']} "
                  f"sig_failures={c['sig_failures']} link_failures={c['link_failures']} clean={c['clean']}")
            print(f"    invariants: calls==enq+drop={r['invariant_calls_eq_enqueued_plus_dropped']} "
                  f"verified==enq={r['invariant_verified_eq_enqueued']}  errors={r['errors']['count']}")
            sv = r["signing_vectors_crosscheck"]
            print(f"    signing_vectors: passed={sv['passed']} key_match={sv['key_match']} "
                  f"checked={sv['events_checked']}")
            if leak.get("evaluated"):
                print(f"    memory: baseline={leak['baseline_rss_mb']}MB end={leak['end_rss_mb']}MB "
                      f"growth={leak['growth_mb']}MB (<{leak['threshold_mb']}MB) leak_ok={leak['leak_ok']}")
            print(f"    TIER_PASS={r['tier_pass']}")
        else:
            c = r["chain"]
            print(f"[{r['tier']}] burst  calls={r['burst_calls']} delay={r['post_delay_ms']}ms  "
                  f"dropped_overflow={r['dropped_overflow']} enqueued={r['enqueued']}")
            print(f"    chain: events={c['events']} gaps={c['gaps']} dupes={c['dupes']} clean={c['clean']}  "
                  f"rss_growth={r['rss_growth_mb']}MB  BURST_PASS={r['burst_pass']}")


def main() -> None:
    ap = argparse.ArgumentParser(description="obsvr Python SDK Part B stress test")
    ap.add_argument("--calls", type=int, default=100_000)
    ap.add_argument("--tier", type=str, default="all")
    ap.add_argument("--burst-calls", type=int, default=0)
    ap.add_argument("--out", type=str, default=None)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()

    bl.bootstrap_sdk()
    result = run(args)
    _print_table(result)

    out = args.out or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "results",
        f"py_stress{'_quick' if args.quick else ''}.json"
    )
    path = bl.write_json(out, result["meta"], result["rows"])
    print(f"\nJSON written: {path}")


if __name__ == "__main__":
    main()
