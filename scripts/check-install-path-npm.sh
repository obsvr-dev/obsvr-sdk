#!/usr/bin/env bash
#
# Pack the npm tarball and prove the PUBLISHED ARTIFACT governs.
#
# Every other TypeScript job in CI imports from the checkout, so it exercises
# `src/` (or a `dist/` sitting next to it) and can say nothing about what an
# `npm install @obsvr/sdk` actually delivers. A subpath export that no longer
# resolves, a declaration file left out of `files`, a bin entry pointing at a
# module that was never compiled: invisible to those jobs, total for the
# caller. This builds, packs the tarball `npm publish` would upload, installs
# it into a scratch directory with its own package.json and no inherited
# node_modules, and runs the consumer check there.
#
# The consumer check itself refuses to pass for the wrong reason: it resolves
# the package out of node_modules, runs an ALLOWED tool as a positive control
# before it asserts anything about a refusal, and grades the blocked record —
# see scripts/installed-package-consumer.mjs.
#
# Usage: scripts/check-install-path-npm.sh
# Nothing is written inside the repository except sdk-typescript/dist
# (gitignored) and node_modules.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS_DIR="$REPO_ROOT/sdk-typescript"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "==> runtime: node $(node --version) / npm $(npm --version)"

# 1) `npm pack` runs neither prepublishOnly nor build, so the compile is
#    explicit here. Without it the tarball would carry whatever dist/ happened
#    to be lying around.
if [ ! -d "$TS_DIR/node_modules" ]; then
  echo "==> installing build dependencies"
  (cd "$TS_DIR" && npm ci --silent)
fi
echo "==> compiling"
(cd "$TS_DIR" && npm run build --silent >/dev/null)

echo "==> packing the publishable tarball"
(cd "$TS_DIR" && npm pack --silent --pack-destination "$WORK" >/dev/null)
TARBALL="$(ls "$WORK"/*.tgz 2>/dev/null | head -1 || true)"
[ -n "$TARBALL" ] || { echo "npm pack produced no tarball" >&2; exit 1; }
echo "    tarball: $(basename "$TARBALL")"

# 2) A scratch consumer with its own manifest. It lives outside the repository
#    so Node's upward node_modules walk cannot reach the workspace tree, and
#    nothing is linked: the tarball is the only source of the package.
echo "==> installing the tarball into a clean consumer package"
CONSUMER="$WORK/consumer"
mkdir -p "$CONSUMER"
cat > "$CONSUMER/package.json" <<'JSON'
{
  "name": "obsvr-install-path-check",
  "version": "0.0.0",
  "private": true,
  "type": "module"
}
JSON
(cd "$CONSUMER" && npm install --silent --no-fund --no-audit "$TARBALL" >/dev/null)

INSTALLED="$CONSUMER/node_modules/@obsvr/sdk"
[ -d "$INSTALLED" ] || { echo "the tarball did not install as @obsvr/sdk" >&2; exit 1; }
# A symlink here would mean a workspace link rather than a real install, which
# would put the check back on the source tree without saying so.
if [ -L "$INSTALLED" ]; then
  echo "@obsvr/sdk installed as a link, not a copy" >&2
  exit 1
fi
# The published tarball must not carry the TypeScript sources or the suites.
if [ -d "$INSTALLED/src" ] || [ -d "$INSTALLED/tests" ]; then
  echo "the packed tarball ships src/ or tests/" >&2
  exit 1
fi

# 3) Run the consumer from the scratch directory. The script is copied in so
#    every specifier it uses resolves the way a consumer's would.
echo "==> driving a governed refusal from outside the repository"
cp "$REPO_ROOT/scripts/installed-package-consumer.mjs" "$CONSUMER/consumer-check.mjs"
EXPECTED_VERSION="$(node -e 'process.stdout.write(require(process.argv[1]).version)' "$TS_DIR/package.json")"

cd "$CONSUMER"
OBSVR_REPO_ROOT="$REPO_ROOT" OBSVR_EXPECTED_VERSION="$EXPECTED_VERSION" \
  node ./consumer-check.mjs

echo "==> npm install path verified"
