# obsvr SDK Benchmarks

Honest, reproducible measurements of what the obsvr SDKs cost per call and how they behave
under sustained load. Every number below was produced by a script shipped in
[`bench/`](bench/) — re-run them and check us.

- **Date:** 2026-07-17 (UTC) · **SDK:** `@obsvr/sdk` 0.9.0 / `obsvr-sdk` (Python) 0.9.0 (the
  commit these ran at is not recoverable from this repository's history, so the version pair
  is the provenance; re-run against a current checkout to get numbers you can pin to a commit)
- **Machine:** Apple M3 Pro (11 cores), 18 GB RAM, macOS 26.5.1
- **Runtimes:** Node v22.23.1 · Python 3.13.2 (CPython)
- **Method:** mock in-process provider (canned response), transport stubbed in-process —
  **zero provider/network time in any number**. Warmup (2,000 calls) discarded; 10,000 timed
  calls per Part A cell; 100,000 calls per stress tier. Two full passes run back-to-back;
  both are reported. Full JSON outputs (with complete percentile sets, memory curves, and
  sender stats) are regenerated into `bench/results/` by the commands at the bottom.

**Read this first:** the SDKs sign and hash-chain every audited event and build a canonical
decision record on **every call, unconditionally** — there is no "insecure fast mode." The
BASE numbers below therefore already include HMAC-SHA256 event signing, chain linkage,
SHA-256 content hashing, and decision-record construction. That is the honest floor, not a
stripped-down best case.

## Part A — per-call overhead (vs. an ungoverned call to the same mock)

Each rung adds one governance stage. Overhead = governed − ungoverned, reported as
delta-of-percentiles. ~100-char prompts unless noted; ×2 columns show both passes.

### TypeScript (µs, p50 of 10,000 calls)

| Config | What runs | run 1 | run 2 | p95 (r1) | p99 (r1) |
| --- | --- | ---: | ---: | ---: | ---: |
| A0 BASE | wrap + event build + decision record + hash + sign + enqueue | **13.6** | 13.7 | 18.6 | 25.1 |
| A1 | + 5 rules (incl. NFKC normalization + ruleset hash) | 22.5 | 22.5 | 26.2 | 110.6 |
| A2 | + built-in PII scan | 31.5 | 31.8 | 34.3 | 116.5 |
| A3 | + quota rule | 33.3 | 33.7 | 37.8 | 114.3 |
| A4 FULL | + hooks + multi-turn injection + shadow rules | **45.1** | 45.6 | 49.7 | 72.5 |
| A0 @ 10 KB prompt | | 111.8 | 105.2 | 121.0 | 200.0 |
| A2 @ 10 KB prompt | | 654.0 | 691.1 | 890.4 | 1,203.8 |
| A4 @ 10 KB prompt | | 1,255.6 | 1,378.3 | 1,502.7 | 2,017.3 |

### Python (µs; **mean** of 10,000 calls — see note)

| Config | run 1 | run 2 | p95 (r1) | p99 (r1) |
| --- | ---: | ---: | ---: | ---: |
| A0 BASE | **91.9** | 93.3 | 146.1 | 506.5 |
| A1 | 126.2 | 118.3 | 165.5 | 182.9 |
| A2 | 144.1 | 137.6 | 189.4 | 212.6 |
| A3 | 147.2 | 146.1 | 196.8 | 226.0 |
| A4 FULL | **309.6** | 306.4 | 336.6 | 356.3 |
| A0 @ 10 KB (p50) | 2,025.0 | 2,031.9 | 2,395.8 | 4,410.8 |
| A2 @ 10 KB (p50) | 4,179.0 | 4,114.0 | 4,501.6 | 4,755.0 |
| A4 @ 10 KB (p50) | 7,220.6 | 7,207.5 | 7,402.5 | 7,528.3 |

**Python small-payload note (disclosed, not hidden):** at sub-150µs scale the Python p50s
for A0–A2 are bimodal across passes (e.g. A0 p50 measured 64.5µs then 95.5µs, while the
means agreed within 1.5%) — caused by GIL interplay with the sender worker thread. Means and
p95s are stable; we therefore publish means for those cells and do not claim clean p50-level
stage attribution between A1/A2/A3 in Python. TypeScript small-payload p50s are stable to
~1% and the ladder attribution stands. Large-payload (10 KB) cells: Python is stable (<2%
drift); the TypeScript 10 KB p50s drift 5.7–9.8% between passes (both passes printed above —
GC sensitivity under megabyte-scale string churn), so treat those cells as ±10% figures.
Python means across passes: A0 within 1.5%, A1 within 6.2%.

**What scales with payload:** SHA-256 content hashing (BASE) plus NFKC normalization and
regex scanning (A1+) are O(text length) — visible in the 10 KB rows. Budget accordingly if
you routinely ship very large prompts through scanning tiers.

## Fire-and-forget proof (ingest delivery does not block the call path)

A0 re-run with the stubbed transport artificially slowed to 25 ms per POST:

| | hot-path p95 (fast transport) | hot-path p95 (25 ms transport) | overflow drops |
| --- | ---: | ---: | ---: |
| TypeScript | 15.3 µs | 5.8 µs | 4,199 — **counted** |
| Python | 125.6 µs | 51.2 µs | 10,648 — **counted** |

A slow backend does **not** slow governed calls. (The hot path actually gets *faster* once
the bounded queue fills: overflowed events are dropped-and-counted before signing, so the
sender does less work.)

**This measures the ingest transport, and one other thing on that path is NOT
fire-and-forget.** With `otel` mirroring configured, the TypeScript sender calls
the exporter synchronously and does so BEFORE the enqueue, so a slow exporter
delays the audit event rather than trailing it — measured at 301 ms of
caller-visible block against 2 ms with the mirror off. It cannot lose the event
(the resolve and the span body are each guarded), and Python mirrors AFTER the
enqueue so only the caller's latency is exposed there. The numbers above are
with no mirror configured, which is the default.

**What a drop leaves behind.** Overflow drops happen before a sequence number is assigned,
so they leave no hole of their own — the events that survive still form a contiguous chain.
That is a property to be careful with, not a guarantee: read the wrong way it says a run
that lost most of its events verified clean. Loss is therefore recorded in two places. It is
counted in `getSenderStats()` / `get_sender_stats()`, and it is **declared in the chain
itself** by a signed gap marker — one chain-linked event, at the position the loss happened,
stating how many events were dropped there. The count sits in the signature preimage, so
editing it breaks verification like any other tamper, and `obsvr-verify` reports it:
`N event(s) declared LOST by M gap marker(s) in this chain`. A chain carrying markers is
valid and incomplete at the same time, and the tooling says both.

## Part B — sustained stress, 100,000 governed calls per tier

Sequential calls against the mock provider; full chain verification runs streaming during
the load. `thruput` = sustained governed calls/second (both passes shown).

### TypeScript

| Tier | thruput r1 | thruput r2 | p50 µs | p95 µs | p99 µs | max µs | mem Δ | chain (101,001 ev) | errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| L0 no policy | 54,443/s | 54,194/s | 17.3 | 21.2 | 28.7 | 1,527 | +19.0 MB heap¹ | ✅ 0 faults | 0 |
| L1 light (3 rules) | 31,003/s | 30,670/s | 31.0 | 35.8 | 46.9 | 1,828 | +18.8 MB¹ | ✅ 0 faults | 0 |
| L2 medium (PII+6+quota) | 17,053/s | 16,593/s | 57.0 | 65.8 | 89.1 | 3,737 | +18.7 MB¹ | ✅ 0 faults | 0 |
| L3 heavy (everything) | 9,969/s | 9,712/s | 98.5 | 113.0 | 201.4 | 4,744 | +2.6 MB | ✅ 0 faults | 0 |

¹ V8 heap growth, GC-timing dependent, flat-lining under the leak threshold and not
monotonic across sampling — not a leak (L3, the heaviest tier, grew least).

### Python

| Tier | thruput r1 | thruput r2 | p50 µs | p95 µs | p99 µs | max µs | mem Δ | chain (100,000 ev) | errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| L0 no policy | 6,131/s | 6,257/s | 163 | 208 | 264 | 1,842 | +0.65 MB | ✅ 0 faults | 0 |
| L1 light | 5,338/s | 5,435/s | 179 | 235 | 328 | 21,567² | +1.23 MB | ✅ 0 faults | 0 |
| L2 medium | 3,410/s | 3,610/s | 273 | 415 | 597 | 123,305² | +0.74 MB | ✅ 0 faults | 0 |
| L3 heavy | 1,902/s | 1,796/s | 522 | 600 | 649 | 4,167 | +0.62 MB | ✅ 0 faults | 0 |

² Single-call outliers (1 in 100,000; OS scheduling/GC pause). p99 is the honest tail
metric; maxima are disclosed, not trimmed.

**Chain integrity at volume — the number that matters for an evidence product:** across all
16 stress runs (2 languages × 4 tiers × 2 passes), every one of the **~1.6 million** signed
events captured was verified: strictly monotonic sequence numbers, correct
previous-signature linkage, and a recomputed HMAC-SHA256 signature match on every event —
**zero gaps, zero duplicates, zero signature failures**. The TypeScript streaming verifier
was cross-checked against the SDK's exported `verifyAuditChain` (1,000-event sample each
run, agreement required); the Python verifier is validated against the shared
`conformance/fixtures/signing_vectors.json`. Accounting closed exactly in every run:
`calls == enqueued + dropped_overflow` and `verified == enqueued`. (Gap markers are events
the SDK enqueues on its own behalf, with no call behind them, so the identity the bench
asserts today carries a `+ gap_markers` term on the left. These runs predate markers and
had none — the closure above is the same statement with that term at zero.)

**Burst overflow (bounded queue, deliberately saturated):** with the stubbed transport
slowed (10 ms per POST in TS, 50 ms in Python), 10,000-call bursts overflowed the
1,000-event queue as designed — 67–90% of burst events dropped, every drop **counted** in
sender stats, and RSS growth ≤ 2.3 MB.

Every drop is also **declared in the signed chain**. The burst phase asserts it as an
invariant (`gap_events_declared == dropped_overflow`), so a run that lost events and did not
say so fails the bench rather than reporting a clean chain. One marker covers a whole
contiguous gap, not one per dropped event — the cost of disclosure is one signed event per
burst, which is why the throughput and latency rows above are unaffected by it.

Measured on the current build (2026-07-27, same machine), one burst phase per language:

| | burst calls | dropped | gap markers | declared lost | chain |
| --- | ---: | ---: | ---: | ---: | --- |
| TypeScript | 10,000 | 8,999 (90%) | 1 | 8,999 | ✅ valid |
| Python | 4,000 | 2,804 (70%) | 7 | 2,804 | ✅ valid |

The marker counts differ because they track *contiguous* gaps, not drops: TypeScript's
50 × 200-wave burst saturates the queue once and stays saturated, while Python's slower
per-POST stub drains between waves and opens seven separate gaps. Both declare every
dropped event. The Part A and Part B tables above were measured before gap markers landed;
their per-call figures stand (the marker is off the hot path), and the accounting identity
is the one printed here.

## Known costs and quirks (disclosed)

1. **Python L3 is dominated by hook execution machinery**: the SDK creates (and abandons via
   `shutdown(wait=False)`) a `ThreadPoolExecutor` per governed call for the pre-call hook and
   another for the post-call hook (`policy.py:1302`, `policy.py:1796`) — ~3.4× throughput cost
   vs L0. Intentional (bounds hook wall-clock), but the biggest Python optimization target.
2. **Both SDKs recompute the policy-version hash (SHA-256 over the serialized ruleset) on
   every call**, uncached (TS `policy/rules.ts` `derivePolicyVersion`; Py `rules.py`
   `derive_policy_version`). Cost grows with rule count; part of the A0→A1 step.
3. At measurement time, TS events stamped `sdk_version: "node/2.0.0"` while the package was
   0.9.0 (stale `SDK_VERSION` constant) — cosmetic, not part of the signature preimage, zero
   perf impact. Fixed to `0.9.0` immediately after these runs; archived result JSONs record
   the old stamp in `meta.sdk_version_stamped`.
4. The optional **external policy backend** (OPA/Cedar, off by default) adds a network
   round-trip per call and is therefore excluded from these zero-network numbers; benchmark
   it against your own endpoint if you enable it.

## Environment / validity notes

- **Two independent passes bound these figures.** They agree within ±3% on all TS
  small-payload and stress cells, within ±6% on Python stress cells, and within ±10% on the
  TS 10 KB Part A cells (the noisiest); both passes are published above, and all of them
  match earlier quick smokes taken from a quieter window. The run window itself was an
  interactive desktop machine (browser etc. running) with a separate network-bound test
  suite overlapping part of it, which is what those cross-checks are there to bound. Cells
  are microbenchmarks — expect machine-to-machine variance; run `bench/run-all.sh` on your
  own hardware.
- The TS figures are a conservative **upper bound** on SDK cost: the in-process capture stub
  verifies each event's signature inside the measured window (independently measured at
  ~4.4µs of the 13.6µs A0 p50) — the SDK's true overhead is slightly *lower* than shown.
  Python's stub runs on the sender's worker thread instead (no inline inflation; it
  contributes to the GIL-related p50 bimodality disclosed above). TS uses floor-index
  percentile selection and Python nearest-rank; neither understates tails.
- Sequential-loop numbers measure per-call cost under sustained single-caller load. The TS
  burst phase additionally exercised 200-way concurrent waves (chain stayed valid — enqueue
  is atomic).

## Reproduce

```bash
cd obsvr-sdk
bench/run-all.sh --repeat 2          # full matrix, both languages, ~15 min
# or individually:
node bench/ts/overhead.mjs           # TS Part A
node --expose-gc bench/ts/stress.mjs --tier L3 --calls 100000
sdk-python/.venv/bin/python bench/python/overhead.py
sdk-python/.venv/bin/python bench/python/stress.py --tier L3 --calls 100000
```

Methodology details: [`bench/README.md`](bench/README.md).
