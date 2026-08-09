# obsvr SDK benchmarks

These measurements describe the local SDK hot path and sender behavior. They are not
provider-latency measurements: providers and ingest are replaced with in-process test
transports.

- **Measured:** 2026-08-09 UTC
- **SDK:** `@obsvr/sdk` 0.11.2 and `obsvr-sdk` 0.11.2
- **Measured source revision:** `dc372d5`
- **Machine:** Apple M3 Pro, 11 cores, 18 GB RAM, macOS 26.5.2
- **Runtimes:** Node v22.23.1 and CPython 3.13.2
- **Method:** 2,000 warmup calls, 10,000 timed calls per overhead cell, and 100,000
  sequential calls plus a 10,000-call overflow burst per stress tier
- **Repetitions:** two complete back-to-back passes; both are reported

The governed rows include event construction, content hashing, decision-record construction,
HMAC signing, chain linkage, and enqueueing. Optional network policy backends and OTel exporters
are disabled, so their latency is not represented.

## Per-call overhead

Values are delta-of-percentiles against the ungoverned mock call, in microseconds. `small` is
approximately 100 bytes and `10 KB` is approximately 10,000 bytes. A percentile delta compares
the governed and ungoverned distributions; it is not a per-sample subtraction.

### TypeScript

| Configuration | Payload | p50 run 1 | p50 run 2 | p95 run 1 | p95 run 2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| A0 base | small | 24.7 | 25.1 | 32.7 | 34.2 |
| A1 + rules | small | 34.0 | 34.0 | 36.7 | 37.7 |
| A2 + PII scan | small | 48.9 | 48.6 | 52.6 | 50.8 |
| A3 + quota | small | 50.5 | 50.4 | 53.5 | 54.1 |
| A4 full local policy | small | 64.1 | 63.2 | 66.1 | 65.9 |
| A0 base | 10 KB | 122.8 | 128.4 | 125.3 | 190.3 |
| A2 + PII scan | 10 KB | 934.2 | 978.5 | 1,100.0 | 1,319.0 |
| A4 full local policy | 10 KB | 1,749.4 | 1,756.3 | 2,024.2 | 2,064.0 |

### Python

| Configuration | Payload | p50 run 1 | p50 run 2 | p95 run 1 | p95 run 2 |
| --- | ---: | ---: | ---: | ---: | ---: |
| A0 base | small | 100.0 | 97.6 | 220.8 | 103.0 |
| A1 + rules | small | 164.3 | 164.1 | 179.9 | 177.9 |
| A2 + PII scan | small | 268.7 | 286.7 | 279.7 | 306.0 |
| A3 + quota | small | 289.4 | 289.2 | 302.2 | 314.4 |
| A4 full local policy | small | 524.3 | 525.1 | 572.1 | 569.5 |
| A0 base | 10 KB | 2,201.1 | 2,218.0 | 2,393.2 | 3,288.6 |
| A2 + PII scan | 10 KB | 8,797.7 | 8,780.2 | 9,853.2 | 9,493.8 |
| A4 full local policy | 10 KB | 12,600.8 | 12,303.7 | 13,918.5 | 24,055.7 |

The Python sender shares the interpreter with the measured call path. Scheduling and queue
drain timing therefore create more tail variance than the TypeScript run. The second Python
pass also began with a one-minute load warning (4.98); the complete slower tails remain in the
table and retained JSON instead of being discarded.

## Sustained stress

Each tier runs 100,000 sequential governed calls. Throughput and latency are measured at the
call boundary. The sender then drains, and the harness verifies accounting, signatures, chain
links, declared loss, and its memory-growth threshold.

### TypeScript

| Tier | throughput run 1 | throughput run 2 | p50 run 1 | p50 run 2 | p95 run 1 | p95 run 2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| L0 base | 29,423.7/s | 30,662.3/s | 30.2 µs | 29.4 µs | 39.5 µs | 37.5 µs |
| L1 light | 21,492.7/s | 21,718.7/s | 43.2 µs | 42.2 µs | 52.9 µs | 50.5 µs |
| L2 medium | 10,559.1/s | 11,285.9/s | 90.4 µs | 85.3 µs | 109.4 µs | 97.2 µs |
| L3 heavy | 6,584.4/s | 7,146.1/s | 145.4 µs | 136.7 µs | 177.6 µs | 156.9 µs |

No TypeScript sequential stress cell overflowed. Every tier then deliberately saturated the
bounded sender with a 10,000-call burst: 8,999 calls were dropped and declared by one signed
gap marker in each pass and tier. All retained chains and official-verifier cross-checks passed.

### Python

| Tier | throughput run 1 | throughput run 2 | p50 run 1 | p50 run 2 | p95 run 1 | p95 run 2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| L0 base | 4,907.0/s | 5,905.9/s | 169.6 µs | 155.3 µs | 213.3 µs | 179.2 µs |
| L1 light | 3,921.6/s | 4,575.2/s | 219.2 µs | 206.4 µs | 272.8 µs | 231.5 µs |
| L2 medium | 1,703.6/s | 1,731.1/s | 569.7 µs | 565.5 µs | 654.5 µs | 646.9 µs |
| L3 heavy | 1,012.6/s | 1,032.0/s | 978.4 µs | 966.8 µs | 1,120.5 µs | 1,083.9 µs |

The Python in-process sender could not drain every sequential workload at the production queue
bound. Overflow ranged from 310 to 58,521 events in the affected L0-L2 cells; L3 did not
overflow because every governed event was emitted at the slower call rate. Every dropped event
was counted and declared by signed gap markers, every retained chain verified, and every
accounting invariant passed. This is a capacity result, not a loss-free guarantee.

The Python burst phase dropped 6,037-8,878 of 10,000 calls depending on tier and pass. It used
4-91 signed markers per burst because the worker intermittently drained and opened multiple
contiguous loss intervals. Declared-loss totals matched overflow totals in every cell.

## Fire-and-forget transport check

The A0 hot path was measured with a normal in-process ingest response and with each POST delayed
by 25 ms:

| Runtime | fast p95 | delayed p95 | delayed overflow | retained chain |
| --- | ---: | ---: | ---: | --- |
| TypeScript run 1 | 32.3 µs | 14.4 µs | 4,199 | valid |
| TypeScript run 2 | 33.5 µs | 15.7 µs | 4,199 | valid |
| Python run 1 | 113.8 µs | 96.5 µs | 10,494 | valid |
| Python run 2 | 101.7 µs | 91.3 µs | 10,784 | valid |

The delayed transport did not add its 25 ms delay to governed-call latency. Once the bounded
queue fills, an overflowing call completes faster because it is dropped and counted before
signing. The harness treats valid retained chains, closed accounting, and declared overflow as
the proof conditions; it does not assert a fixed latency-ratio threshold. An optional synchronous
OTel exporter is outside this measurement and can add caller-visible latency.

## Evidence and limitations

Across both passes:

- all overhead and stress cells completed with zero harness errors;
- every retained event passed sequence, link, and HMAC verification;
- TypeScript's streaming verifier agreed with the exported verifier on each sampled chain;
- Python's verifier passed the shared signing vectors;
- every overflow count matched signed gap declarations;
- all asserted memory-growth checks stayed below the 30 MB threshold.

These are local microbenchmarks on an interactive workstation. They do not predict provider or
network latency and should not be used as a universal service-capacity claim. Raw evidence is
retained in [`bench/results/run1/`](bench/results/run1/) and
[`bench/results/run2/`](bench/results/run2/). The measured revision is recorded inside every
artifact. Absolute local fixture paths were normalized to the repository-relative
`conformance/fixtures/signing_vectors.json`; no measured value was altered.

## Reproduce

```bash
bench/run-all.sh --repeat 2
```

Individual commands and tier definitions are documented in
[`bench/README.md`](bench/README.md).
