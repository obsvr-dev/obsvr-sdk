/**
 * Tiny assertion helper for the flat, legible integration tests. Each check is
 * COLLECTED (not printed here) and rendered once by the runner via
 * report.mjs `printChecks`, so a check appears exactly once in the output.
 * Call done.results() at the end, or done.skip(reason) to bail early.
 *
 * (Previously check() also console.log'd live, which double-printed every line
 * because the runner re-prints the collected results. Print once, collect once.)
 */
let _results = [];

export function check(label, ok, detail) {
  _results.push({ check: label, status: ok ? "pass" : "fail", detail: ok ? undefined : detail });
}

/** Record a check that could NOT be evaluated.
 *
 *  Distinct from pass and from fail on purpose. A leg whose provider key is
 *  absent has not been proven to work and has not been proven broken, and
 *  collapsing that into either one is how a governance claim gets made without
 *  evidence: a pass would assert a gate nobody drove, a fail would read as a
 *  defect in code that was never reached. The runner renders these yellow and
 *  counts them as skipped, so "all green" cannot be claimed over them.
 *
 *  Twin: py/lib/check.py `unknown`. */
export function unknown(label, detail) {
  _results.push({ check: label, status: "skip", detail });
}

export const done = {
  results() {
    const r = _results;
    _results = [];
    return r;
  },
  skip(reason) {
    _results = [];
    return [{ check: "preconditions", status: "skip", detail: reason }];
  },
};

/** Print the signed events obsvr captured — a one-line summary plus the first
 *  event in full, so you can SEE what got sealed. */
export function showEvents(events) {
  console.log(`\n   obsvr recorded ${events.length} signed events:`);
  for (const e of events) {
    console.log(
      `     • ${String(e.event_type).padEnd(13)} model=${e.model ?? "-"}  user=${e.user_id ?? "-"}  seq=${e.seq_no}  sig=${String(e.sdk_sig).slice(0, 12)}…`,
    );
  }
  if (events[0]) {
    console.log(`\n   full first event:\n${JSON.stringify(events[0], null, 2).replace(/^/gm, "     ")}\n`);
  }
}

