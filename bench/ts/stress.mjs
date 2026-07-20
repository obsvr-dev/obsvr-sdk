/**
 * PART B — sustained stress for the obsvr TS SDK.
 *
 * Tiers L0..L3 (non-matching rules → all calls allowed; benign prompts varied
 * over 1,000 pre-generated strings; 100 rotating user_ids). Per tier: a
 * sequential awaited loop of N governed calls (default 100,000; --calls
 * overrides), wall-clocked for throughput, per-call µs latency percentiles,
 * RSS/heap sampled every 5,000 calls, streaming chain verification + a
 * cross-check against the SDK's exported verifyAuditChain, then a burst phase
 * (Promise.all waves of 200 × 50 with a 10ms-delayed transport) to force counted
 * queue overflow while the chain still verifies.
 *
 * Flags: --calls N  --tier L0..L3  --out FILE  --quick
 * Run under `node --expose-gc` for gc-bracketed memory samples (tolerated if absent).
 *
 * Honesty: provider in-process, transport stubbed at global.fetch; the real
 * queue/batching/signing/drop-counting stay measured. Any error, gap, dupe, sig
 * failure, or leak is reported as a FINDING, never tuned away.
 */
import {
  obsvr, getSenderStats, getQueueSize,
  StreamingChainVerifier, installFetchCapture, makeMockProvider,
  resetAll, drain, partBConfig, PART_B_TIERS,
  makePromptPool, makeUserIds, percentiles, round,
  collectMeta, writeJson, printTable, parseArgs, RESULTS_DIR,
} from "./lib.mjs";
import { CrossCheckCollector } from "./lib.mjs";

const API_KEY = "bench-key";
const args = parseArgs(process.argv.slice(2));
const QUICK = !!args.quick;
const CALLS = args.calls ? parseInt(args.calls, 10) : QUICK ? 5000 : 100000;
const TIERS = args.tier ? [String(args.tier)] : PART_B_TIERS;
const OUT = args.out || `${RESULTS_DIR}/ts-stress${QUICK ? "-quick" : ""}.json`;
const MEM_INTERVAL = Math.min(5000, Math.max(1000, Math.floor(CALLS / 10)));
const BURST_WAVES = QUICK ? 10 : 50;
const BURST_WIDTH = 200;
const HAS_GC = typeof global.gc === "function";

const pool = makePromptPool(1000);
const userIds = makeUserIds(100);

function memSample(call) {
  const m = process.memoryUsage();
  return { call, rss: m.rss, heapUsed: m.heapUsed };
}

function nearestSample(curve, targetCall) {
  let best = curve[0];
  let bestD = Infinity;
  for (const s of curve) {
    const d = Math.abs(s.call - targetCall);
    if (d < bestD) { bestD = d; best = s; }
  }
  return best;
}

/** Linear slope (bytes/call) over the last quartile of the sequential curve. */
function lastQuartileSlope(curve, calls) {
  const start = calls * 0.75;
  const pts = curve.filter((s) => s.call >= start);
  if (pts.length < 2) return 0;
  const a = pts[0], b = pts[pts.length - 1];
  return (b.rss - a.rss) / Math.max(1, b.call - a.call);
}

async function runTier(tier) {
  resetAll();
  obsvr.init(partBConfig(tier));
  const client = obsvr.wrap(makeMockProvider());
  const verifier = new StreamingChainVerifier(API_KEY);
  const collector = new CrossCheckCollector(Math.min(1000, CALLS));
  const fetchHandle = installFetchCapture({ verifier, collector, delayMs: 0 });

  const errors = { count: 0, stacks: [] };
  const callOnce = async (i) => {
    const req = {
      model: "gpt-4o",
      messages: [{ role: "user", content: pool[i % pool.length] }],
      metadata: { user_id: userIds[i % userIds.length] },
    };
    try {
      await client.chat.completions.create(req);
    } catch (e) {
      errors.count++;
      if (errors.stacks.length < 5) errors.stacks.push(String(e && e.stack ? e.stack : e));
    }
  };

  // ── Sequential phase (primary metric) ──
  if (HAS_GC) global.gc();
  const memCurve = [memSample(0)];
  const samples = new Float64Array(CALLS);
  const tWall0 = performance.now();
  for (let i = 0; i < CALLS; i++) {
    const b0 = performance.now();
    await callOnce(i);
    samples[i] = (performance.now() - b0) * 1000; // µs
    if ((i + 1) % MEM_INTERVAL === 0) memCurve.push(memSample(i + 1));
  }
  const wallSec = (performance.now() - tWall0) / 1000;

  await drain();
  if (HAS_GC) global.gc();
  const rssEndSeq = memSample(CALLS);
  memCurve.push(rssEndSeq);

  const perc = percentiles(samples);
  const statsSeq = getSenderStats();

  // Leak assertion over the sequential run: RSS(end,after gc+flush) − RSS(25%).
  const rss25 = nearestSample(memCurve, CALLS * 0.25);
  const leakBytes = rssEndSeq.rss - rss25.rss;
  const leakThreshold = Math.max(30 * 1024 * 1024, rss25.rss * 0.15);
  const slope = lastQuartileSlope(memCurve, CALLS);

  // ── Burst phase: slow transport forces counted overflow; chain must hold. ──
  fetchHandle.delayMs = 10;
  let burstMade = 0;
  for (let w = 0; w < BURST_WAVES; w++) {
    await Promise.all(
      Array.from({ length: BURST_WIDTH }, () => {
        burstMade++;
        return client.chat.completions.create({
          model: "gpt-4o",
          messages: [{ role: "user", content: pool[burstMade % pool.length] }],
          metadata: { user_id: userIds[burstMade % userIds.length] },
        }).catch((e) => {
          errors.count++;
          if (errors.stacks.length < 5) errors.stacks.push(String(e && e.stack ? e.stack : e));
        });
      }),
    );
  }
  fetchHandle.delayMs = 0; // let the backlog drain fast
  await drain(120);
  const rssAfterBurst = memSample(CALLS + burstMade);

  const stats = getSenderStats();
  verifier.finalize();
  const chain = verifier.summary();
  const cross = collector.verify(API_KEY);

  const totalMade = CALLS + burstMade;
  const invariants = {
    calls_eq_enqueued_plus_overflow: totalMade === stats.enqueued + stats.dropped_overflow,
    verified_eq_enqueued: chain.events === stats.enqueued,
    chain_valid: chain.valid,
    cross_check_agrees: cross.agrees,
    no_errors: errors.count === 0,
    leak_ok: leakBytes < leakThreshold,
  };

  fetchHandle.restore();

  return {
    tier,
    calls: CALLS,
    throughput_calls_per_s: round(CALLS / wallSec, 1),
    wall_s: round(wallSec, 3),
    latency_us: {
      p50: round(perc.p50), p95: round(perc.p95), p99: round(perc.p99),
      mean: round(perc.mean), max: round(perc.max),
    },
    memory: {
      sampled_every: MEM_INTERVAL,
      gc_available: HAS_GC,
      curve: memCurve.map((s) => ({ call: s.call, rss_mb: round(s.rss / 1048576, 1), heap_mb: round(s.heapUsed / 1048576, 1) })),
      rss25_mb: round(rss25.rss / 1048576, 1),
      rss_end_seq_mb: round(rssEndSeq.rss / 1048576, 1),
      leak_bytes: leakBytes,
      leak_mb: round(leakBytes / 1048576, 2),
      leak_threshold_mb: round(leakThreshold / 1048576, 2),
      leak_ok: leakBytes < leakThreshold,
      last_quartile_slope_bytes_per_call: round(slope, 2),
      last_quartile_slope_positive: slope > 1024, // >1KB/call ≈ >100MB over 100k
      rss_after_burst_mb: round(rssAfterBurst.rss / 1048576, 1),
    },
    chain,
    cross_check: cross,
    burst: {
      waves: BURST_WAVES,
      width: BURST_WIDTH,
      made: burstMade,
      dropped_overflow_total: stats.dropped_overflow,
      chain_valid_after_burst: chain.valid,
    },
    sender_stats: stats,
    sequential_sender_stats: statsSeq,
    fetch_counts: { single: fetchHandle.singlePosts, batch: fetchHandle.batchPosts, other: fetchHandle.otherRequests },
    invariants,
    errors,
    _stamped: verifier.lastSdkVersion,
  };
}

async function main() {
  const rows = [];
  let stamped = null;
  for (const tier of TIERS) {
    const row = await runTier(tier);
    stamped = row._stamped || stamped;
    delete row._stamped;
    rows.push(row);
  }

  const meta = collectMeta("B", { quick: QUICK, calls: CALLS, tiers: TIERS, burst_waves: BURST_WAVES, gc: HAS_GC }, stamped);
  writeJson(OUT, { meta, rows });

  console.log(`\n=== PART B: sustained stress  [calls=${CALLS} burst=${BURST_WIDTH}x${BURST_WAVES} gc=${HAS_GC}] ===`);
  printTable(
    ["tier", "thruput/s", "p50µs", "p95µs", "p99µs", "maxµs", "leakMB", "leakOK", "chain", "xcheck", "burst_drop", "errs"],
    rows.map((r) => [
      r.tier, r.throughput_calls_per_s, r.latency_us.p50, r.latency_us.p95, r.latency_us.p99, r.latency_us.max,
      r.memory.leak_mb, r.memory.leak_ok ? "ok" : "LEAK",
      r.chain.valid ? "ok" : "FAIL",
      r.cross_check.agrees ? "ok" : "MISMATCH",
      r.burst.dropped_overflow_total,
      r.errors.count,
    ]),
  );

  for (const r of rows) {
    console.log(
      `\n[${r.tier}] enqueued=${r.sender_stats.enqueued} sent=${r.sender_stats.sent} ` +
      `dropped_overflow=${r.sender_stats.dropped_overflow} retries=${r.sender_stats.retries} | ` +
      `chain: events=${r.chain.events} gaps=${r.chain.gaps} dupes=${r.chain.dupes} sig_fail=${r.chain.sig_failures} ` +
      `chain_breaks=${r.chain.chain_breaks} reorder=${r.chain.reorder_observed} | ` +
      `xcheck: official=${r.cross_check.official_valid}/${r.cross_check.official_events_verified} agrees=${r.cross_check.agrees} | ` +
      `invariants: ${JSON.stringify(r.invariants)}`,
    );
  }
  console.log(`\nJSON: ${OUT}`);

  const fail = rows.some(
    (r) => r.errors.count > 0 || !r.chain.valid || !r.cross_check.agrees ||
      !r.invariants.calls_eq_enqueued_plus_overflow || !r.invariants.verified_eq_enqueued || !r.memory.leak_ok,
  );
  if (fail) {
    console.error(`\nWARNING: one or more tiers failed (errors / chain / cross-check / invariant / leak).`);
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
