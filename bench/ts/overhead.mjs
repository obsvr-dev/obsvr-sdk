/**
 * PART A — per-call overhead micro-benchmark for the obsvr TS SDK.
 *
 * Ladder U / A0 / A1 / A2 / A3 / A4 (each config's delta vs the previous = that
 * stage's cost). Payload axis: ~100 chars and ~10KB. Method: >=2,000 warmup
 * calls discarded, then >=10,000 timed awaited calls per cell, per-call
 * performance.now() bracket in microseconds; report p50/p95/p99/mean/max plus
 * overhead-vs-U per percentile (delta of percentiles). Section 2: fire-and-forget
 * proof (A0 with the transport stub delayed 25ms/POST — hot-path p95 unchanged).
 *
 * Flags: --iters N  --out FILE  --quick  --payload N[,N]
 *
 * Honesty: provider is in-process; transport stubbed at global.fetch. Only the
 * declared warmup is discarded; nothing else is dropped from the samples.
 */
import {
  obsvr, verifyAuditChain, getSenderStats,
  StreamingChainVerifier, installFetchCapture, makeMockProvider,
  resetAll, drain, partAConfig, PART_A_TIERS, seededText, makeUserIds,
  percentiles, round, collectMeta, writeJson, printTable, parseArgs, RESULTS_DIR,
} from "./lib.mjs";

const API_KEY = "bench-key";
const args = parseArgs(process.argv.slice(2));
const QUICK = !!args.quick;
const WARMUP = QUICK ? 200 : 2000;
const TIMED = args.iters ? parseInt(args.iters, 10) : QUICK ? 500 : 10000;
const PAYLOADS = QUICK
  ? [100]
  : args.payload
    ? String(args.payload).split(",").map((s) => parseInt(s, 10))
    : [100, 10000];
const SMALL = PAYLOADS[0];
const OUT = args.out || `${RESULTS_DIR}/ts-overhead${QUICK ? "-quick" : ""}.json`;

const userIds = makeUserIds(100);

/** Run one config-payload cell: warmup (discarded) + timed samples. */
async function runCell(tier, payloadChars) {
  resetAll();
  const config = partAConfig(tier);
  const prompt = seededText(payloadChars, payloadChars);
  const governed = config !== null;

  let client, verifier, fetchHandle;
  if (governed) {
    obsvr.init(config);
    client = obsvr.wrap(makeMockProvider());
    verifier = new StreamingChainVerifier(API_KEY);
    fetchHandle = installFetchCapture({ verifier });
  } else {
    client = makeMockProvider(); // raw, ungoverned
  }

  const errors = { count: 0, stacks: [] };
  const call = async (i) => {
    const req = {
      model: "gpt-4o",
      messages: [{ role: "user", content: prompt }],
      metadata: { user_id: userIds[i % userIds.length] },
    };
    try {
      await client.chat.completions.create(req);
    } catch (e) {
      errors.count++;
      if (errors.stacks.length < 5) errors.stacks.push(String(e && e.stack ? e.stack : e));
    }
  };

  for (let i = 0; i < WARMUP; i++) await call(i);

  const samples = new Float64Array(TIMED);
  for (let i = 0; i < TIMED; i++) {
    const t0 = performance.now();
    await call(WARMUP + i);
    samples[i] = (performance.now() - t0) * 1000; // µs
  }

  const perc = percentiles(samples);
  const made = WARMUP + TIMED;
  let stats = null, chain = null, invariants = null;
  if (governed) {
    await drain();
    stats = getSenderStats();
    verifier.finalize();
    chain = verifier.summary();
    invariants = {
      calls_eq_enqueued_plus_overflow: made === stats.enqueued + stats.dropped_overflow,
      verified_eq_enqueued: chain.events === stats.enqueued,
      chain_valid: chain.valid,
    };
    fetchHandle.restore();
  }

  return {
    tier,
    payload_bytes: payloadChars,
    warmup: WARMUP,
    timed: TIMED,
    us: {
      p50: round(perc.p50), p95: round(perc.p95), p99: round(perc.p99),
      mean: round(perc.mean), max: round(perc.max),
    },
    stats,
    chain,
    invariants,
    errors,
    _stamped: governed ? verifier.lastSdkVersion : null,
  };
}

/** Section 2: fire-and-forget proof — A0 fast vs A0 with 25ms/POST transport. */
async function fireAndForgetProof() {
  const N = Math.min(TIMED, 5000);
  const W = Math.min(WARMUP, 200);
  const prompt = seededText(SMALL, SMALL);

  async function runA0(delayMs) {
    resetAll();
    obsvr.init(partAConfig("A0"));
    const client = obsvr.wrap(makeMockProvider());
    const verifier = new StreamingChainVerifier(API_KEY);
    const fetchHandle = installFetchCapture({ verifier, delayMs });
    const call = async () => {
      try {
        await client.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: prompt }] });
      } catch { /* count-free: proof is about hot-path latency */ }
    };
    for (let i = 0; i < W; i++) await call();
    const samples = new Float64Array(N);
    for (let i = 0; i < N; i++) {
      const t0 = performance.now();
      await call();
      samples[i] = (performance.now() - t0) * 1000;
    }
    const perc = percentiles(samples);
    await drain();
    const stats = getSenderStats();
    verifier.finalize();
    const chain = verifier.summary();
    fetchHandle.restore();
    return { perc, stats, chain };
  }

  const fast = await runA0(0);
  const slow = await runA0(25);
  return {
    n: N,
    fast_p95_us: round(fast.perc.p95),
    slow_p95_us: round(slow.perc.p95),
    fast_p50_us: round(fast.perc.p50),
    slow_p50_us: round(slow.perc.p50),
    slow_dropped_overflow: slow.stats.dropped_overflow,
    slow_chain_valid: slow.chain.valid,
    slow_chain_events: slow.chain.events,
    p95_delta_pct: round(((slow.perc.p95 - fast.perc.p95) / Math.max(fast.perc.p95, 1e-6)) * 100, 1),
  };
}

async function main() {
  const rows = [];
  let stamped = null;
  for (const p of PAYLOADS) {
    const tiers = p === SMALL ? PART_A_TIERS : ["U", "A0", "A2", "A4"];
    for (const tier of tiers) {
      const row = await runCell(tier, p);
      if (row._stamped) stamped = row._stamped;
      delete row._stamped;
      rows.push(row);
    }
  }

  // Overhead vs U per percentile (delta of percentiles), grouped by payload.
  const overheadVsU = [];
  for (const p of PAYLOADS) {
    const u = rows.find((r) => r.tier === "U" && r.payload_bytes === p);
    if (!u) continue;
    for (const r of rows.filter((r) => r.payload_bytes === p && r.tier !== "U")) {
      overheadVsU.push({
        tier: r.tier,
        payload_bytes: p,
        overhead_us: {
          p50: round(r.us.p50 - u.us.p50),
          p95: round(r.us.p95 - u.us.p95),
          p99: round(r.us.p99 - u.us.p99),
          mean: round(r.us.mean - u.us.mean),
        },
      });
    }
  }

  const proof = await fireAndForgetProof();

  const meta = collectMeta("A", { quick: QUICK, warmup: WARMUP, timed: TIMED, payloads: PAYLOADS }, stamped);
  const output = { meta, rows, overhead_vs_u: overheadVsU, fire_and_forget_proof: proof };
  writeJson(OUT, output);

  // ── stdout tables ──
  console.log(`\n=== PART A: per-call overhead (µs)  [warmup=${WARMUP} timed=${TIMED}] ===`);
  printTable(
    ["tier", "bytes", "p50", "p95", "p99", "mean", "max", "enq", "drop_ovf", "verified", "chain", "errs"],
    rows.map((r) => [
      r.tier, r.payload_bytes, r.us.p50, r.us.p95, r.us.p99, r.us.mean, r.us.max,
      r.stats ? r.stats.enqueued : "-",
      r.stats ? r.stats.dropped_overflow : "-",
      r.chain ? r.chain.events : "-",
      r.chain ? (r.chain.valid ? "ok" : "FAIL") : "-",
      r.errors.count,
    ]),
  );

  console.log(`\n=== overhead vs U (delta of percentiles, µs) ===`);
  printTable(
    ["tier", "bytes", "d_p50", "d_p95", "d_p99", "d_mean"],
    overheadVsU.map((o) => [o.tier, o.payload_bytes, o.overhead_us.p50, o.overhead_us.p95, o.overhead_us.p99, o.overhead_us.mean]),
  );

  console.log(`\n=== fire-and-forget proof (A0, n=${proof.n}) ===`);
  printTable(
    ["variant", "p50_us", "p95_us", "dropped_overflow", "chain"],
    [
      ["fast (0ms)", proof.fast_p50_us, proof.fast_p95_us, "-", "-"],
      ["slow (25ms)", proof.slow_p50_us, proof.slow_p95_us, proof.slow_dropped_overflow, proof.slow_chain_valid ? "ok" : "FAIL"],
    ],
  );
  console.log(`p95 delta fast->slow: ${proof.p95_delta_pct}%  (expect ~unchanged; queue absorbs, drops counted)`);
  console.log(`\nJSON: ${OUT}`);

  const anyErr = rows.some((r) => r.errors.count > 0);
  const anyBadChain = rows.some((r) => r.chain && !r.chain.valid);
  const anyBadInv = rows.some((r) => r.invariants && (!r.invariants.calls_eq_enqueued_plus_overflow || !r.invariants.verified_eq_enqueued));
  if (anyErr || anyBadChain || anyBadInv) {
    console.error(`\nWARNING: errors=${anyErr} bad_chain=${anyBadChain} bad_invariant=${anyBadInv}`);
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
