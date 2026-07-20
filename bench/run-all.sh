#!/usr/bin/env bash
# Obsvr SDK benchmark orchestrator.
#
# Runs the full benchmark matrix STRICTLY SERIALLY (parallel runs contaminate
# each other's numbers): TS Part A -> TS Part B (L0..L3) -> Py Part A ->
# Py Part B (L0..L3). Writes JSON to bench/results/run<N>/.
#
# Usage:
#   bench/run-all.sh                 # one full pass (~10-20 min)
#   bench/run-all.sh --repeat 2      # two passes (stability check; published numbers)
#   bench/run-all.sh --quick         # smoke pass (small iteration counts)
set -euo pipefail
cd "$(dirname "$0")/.."

REPEAT=1
QUICK=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repeat) REPEAT="$2"; shift 2 ;;
    --quick)  QUICK="--quick"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

TIERS=(L0 L1 L2 L3)

PY="sdk-python/.venv/bin/python"
[[ -x "$PY" ]] || PY="python3"

echo "== preflight =="
echo "machine load: $(uptime)"
LOAD1=$(uptime | awk -F'load averages?: ' '{print $2}' | awk '{print $1}' | tr -d ',')
awk -v l="$LOAD1" 'BEGIN { if (l+0 > 4) print "WARNING: 1-min load average " l " > 4 — results may be noisy. Quiesce the machine for publishable numbers." }'
echo "building TS SDK (tsc)..."
(cd sdk && npm run build --silent)
echo "python: $("$PY" --version 2>&1)"

for (( r=1; r<=REPEAT; r++ )); do
  OUT="bench/results/run${r}"
  mkdir -p "$OUT"
  echo ""
  echo "================ PASS ${r}/${REPEAT} -> ${OUT} ================"

  echo "-- [1/4] TS Part A (overhead) --"
  node bench/ts/overhead.mjs $QUICK --out "$OUT/ts-overhead.json"

  echo "-- [2/4] TS Part B (stress) --"
  for t in "${TIERS[@]}"; do
    node --expose-gc bench/ts/stress.mjs --tier "$t" $QUICK --out "$OUT/ts-stress-$t.json"
  done

  echo "-- [3/4] Py Part A (overhead) --"
  "$PY" bench/python/overhead.py $QUICK --out "$OUT/py-overhead.json"

  echo "-- [4/4] Py Part B (stress) --"
  for t in "${TIERS[@]}"; do
    "$PY" bench/python/stress.py --tier "$t" $QUICK --out "$OUT/py-stress-$t.json"
  done
done

echo ""
echo "== done: $(ls bench/results/run* 2>/dev/null | wc -l | tr -d ' ') result files across ${REPEAT} pass(es) =="
echo "machine load at end: $(uptime)"
