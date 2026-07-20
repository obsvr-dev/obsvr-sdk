# obsvr SDK benchmarks

Reproducible benchmark + stress harness for the obsvr TypeScript and Python SDKs.
Published numbers live in [../BENCHMARKS.md](../BENCHMARKS.md); every number there
is produced by a script in this directory — re-run them and check.

## What is measured (and what is not)

- **SDK overhead only.** Every benchmark calls an in-process mock provider that
  returns a canned response — zero provider latency, zero network. The transport
  layer is stubbed (TS: `global.fetch` override; Python: `urllib` patched at the
  sender's POST site), so the _real_ signing, queueing, batching, and
  drop-counting code runs, but nothing leaves the process.
- **Ungoverned vs governed.** Overhead = governed call minus the identical
  ungoverned mock call, reported as delta-of-percentiles (labeled as such).
- **"No policy" still signs.** The SDKs sign and chain every audited event
  unconditionally (there is no off switch, by design), and build a decision
  record on every call — so the L0/BASE numbers include hashing, HMAC signing,
  decision-record construction, and enqueue. That is the honest floor.

## Scripts

| Script                              | What it does                                                            |
| ----------------------------------- | ----------------------------------------------------------------------- |
| `run-all.sh [--repeat N] [--quick]` | Full serial matrix, results to `results/runN/`                          |
| `ts/overhead.mjs`                   | Part A (TS): U/A0–A4 stage ladder, payload sizes, fire-and-forget proof |
| `ts/stress.mjs --tier L0..L3`       | Part B (TS): 100k sustained calls + burst overflow phase                |
| `python/overhead.py`                | Part A (Python), same ladder/methodology                                |
| `python/stress.py --tier L0..L3`    | Part B (Python), same                                                   |

Common flags: `--quick` (smoke scale), `--out FILE` (JSON output),
`--iters` / `--calls` (override counts). Defaults: Part A ≥2,000 warmup calls
discarded + ≥10,000 timed calls per cell; Part B 100,000 calls per tier.

## Part A — per-call overhead ladder

Each rung adds one governance stage; the delta vs the previous rung attributes
cost to that stage:

| Config | Adds                                                                                   |
| ------ | -------------------------------------------------------------------------------------- |
| U      | ungoverned mock call (baseline)                                                        |
| A0     | wrap + event build + decision record + hash + HMAC-sign + enqueue (BASE)               |
| A1     | + 5 structured rules (non-matching) — incl. NFKC normalization + per-call ruleset hash |
| A2     | + built-in PII scan (regex path)                                                       |
| A3     | + quota rule (100 rotating user ids)                                                   |
| A4     | + no-op pre/post hooks + multi-turn injection + shadow rule (FULL)                     |

Payload axis: ~100-char and ~10KB prompts (content-scanning stages scale with
text length). The fire-and-forget proof re-runs A0 with the stubbed transport
delayed 25ms/POST: hot-path latency must be unchanged (emission is queued, never
awaited inline); once the bounded queue (1,000) fills, drops are **counted** in
sender stats — never silent.

## Part B — sustained stress tiers

| Tier | Policy load                                                                       |
| ---- | --------------------------------------------------------------------------------- |
| L0   | no policy (signing + decision records still on)                                   |
| L1   | 3 rules                                                                           |
| L2   | PII scan + 6 rules + quota                                                        |
| L3   | PII + 12 rules + quota + hooks + multi-turn injection + shadow rules, fail-closed |

Per tier, the harness asserts and records: throughput, p50/p95/p99/max latency,
RSS/heap sampled every 5k calls with a leak assertion, **streaming verification
of the full signed event chain** (monotonic seq, prev-sig linkage, per-event HMAC
recomputation; cross-checked against the TS SDK's exported `verifyAuditChain`
and the shared `conformance/fixtures/signing_vectors.json`), drop accounting
(`calls == enqueued + dropped_overflow`, `verified == enqueued`), and zero
unhandled errors. A burst phase deliberately slows the stubbed transport to
force queue overflow and proves drops are counted while the delivered chain
still verifies (drops happen before a sequence number is assigned, so they can
never silently hole the chain).

## Requirements

- Node ≥ 18 (SDK is ESM; `--expose-gc` optional, used for cleaner memory reads)
- Python ≥ 3.9 with the `obsvr` package importable — `sdk-python/.venv` or
  `pip install -e sdk-python` (the SDK is dependency-free)
- Run on an otherwise-quiet machine; `run-all.sh` warns if load is high. Run
  serially only — never two benchmark processes at once.

## Honesty rules baked into the harness

1. No provider/network time in any number.
2. Full percentile disclosure (p50/p95/p99/max) — never just the mean.
3. Warmup is declared and discarded; nothing else is discarded.
4. Chain corruption, leaks, silent drops, or crashes fail the run loudly —
   they are findings, not tuning targets.
5. Machine, runtime versions, SDK version, git revision, date, and full args
   are embedded in every result JSON (`meta`).
