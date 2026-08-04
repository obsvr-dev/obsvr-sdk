#!/usr/bin/env bash
#
# Build the Python distribution and prove the BUILT ARTIFACT governs.
#
# Every other Python job in CI runs `pip install -e .` and imports from the
# checkout, so it exercises the source tree and can say nothing about what a
# `pip install obsvr-sdk` actually delivers. A module missing from the wheel,
# a dropped `py.typed`, a dynamic version that stops resolving, or a public
# name that no longer re-exports are all invisible to those jobs and total for
# the caller. This builds the sdist and the wheel, installs the wheel into a
# virtualenv that has no editable install and no repository on `sys.path`, and
# runs the consumer check from a scratch directory outside the repository.
#
# The consumer check itself refuses to pass for the wrong reason: it locates
# the package in site-packages, runs an ALLOWED tool as a positive control
# before it asserts anything about a refusal, and requires the SDK's own typed
# error and reason code — see scripts/installed-package-consumer.py.
#
# Usage: scripts/check-install-path-python.sh [--python /path/to/pythonX.Y]
# Nothing is written inside the repository except sdk-python/dist (gitignored).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_BIN="${PYTHON:-python3}"

while [ $# -gt 0 ]; do
  case "$1" in
    --python) PY_BIN="$2"; shift 2 ;;
    --python=*) PY_BIN="${1#*=}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v "$PY_BIN" >/dev/null 2>&1 || { echo "interpreter not found: $PY_BIN" >&2; exit 2; }

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "==> interpreter: $("$PY_BIN" -c 'import sys; print(sys.executable, sys.version.split()[0])')"

# 1) Build sdist + wheel in a throwaway environment, so the ambient
#    interpreter is never mutated by this check.
echo "==> building sdist + wheel"
"$PY_BIN" -m venv "$WORK/buildenv"
"$WORK/buildenv/bin/python" -m pip install --quiet --upgrade pip
"$WORK/buildenv/bin/python" -m pip install --quiet build==1.5.0
rm -rf "$REPO_ROOT/sdk-python/dist"
# Build output is captured and shown only on failure: setuptools emits pages of
# deprecation notices that would bury the assertions this script exists to run.
if ! (cd "$REPO_ROOT/sdk-python" && "$WORK/buildenv/bin/python" -m build --outdir dist) >"$WORK/build.log" 2>&1; then
  cat "$WORK/build.log" >&2
  echo "the distribution failed to build" >&2
  exit 1
fi

WHEEL="$(ls "$REPO_ROOT"/sdk-python/dist/*.whl 2>/dev/null | head -1 || true)"
SDIST="$(ls "$REPO_ROOT"/sdk-python/dist/*.tar.gz 2>/dev/null | head -1 || true)"
[ -n "$WHEEL" ] || { echo "no wheel was produced" >&2; exit 1; }
[ -n "$SDIST" ] || { echo "no sdist was produced" >&2; exit 1; }
echo "    wheel: $(basename "$WHEEL")"
echo "    sdist: $(basename "$SDIST")"

# 2) The sdist is inspected rather than installed: installing it would pull a
#    build backend from the index, and a release gate that a registry outage
#    can turn red is a gate people learn to click past. What is checked here is
#    what an sdist can silently lose — the package itself, its typing marker
#    and the build declaration.
echo "==> inspecting the sdist contents"
"$PY_BIN" - "$SDIST" <<'PY'
import sys, tarfile
required = ("pyproject.toml", "obsvr/__init__.py", "obsvr/py.typed", "obsvr/_version.py")
with tarfile.open(sys.argv[1]) as tar:
    names = {n.split("/", 1)[1] for n in tar.getnames() if "/" in n}
missing = [r for r in required if r not in names]
if missing:
    print(f"sdist is missing: {missing}", file=sys.stderr)
    raise SystemExit(1)
print(f"    {len(names)} members, all required paths present")
PY

# 3) A clean consumer environment. --no-site-packages is the venv default;
#    what matters beyond that is that nothing is installed editable and the
#    checkout is never on the path.
echo "==> installing the wheel into a clean virtualenv"
"$PY_BIN" -m venv "$WORK/consumer"
CONSUMER_PY="$WORK/consumer/bin/python"
"$CONSUMER_PY" -m pip install --quiet --upgrade pip
"$CONSUMER_PY" -m pip install --quiet "$WHEEL"

# An editable install would defeat the entire check, so it is asserted absent
# rather than assumed. A .pth file pointing back at the checkout is exactly
# what a stray `pip install -e` leaves behind.
if "$CONSUMER_PY" -m pip list --format=freeze 2>/dev/null | grep -q '^-e '; then
  echo "the consumer environment carries an editable install" >&2
  exit 1
fi
if "$CONSUMER_PY" -c 'import sysconfig,glob,os,sys; sys.exit(1 if glob.glob(os.path.join(sysconfig.get_paths()["purelib"], "__editable__*")) else 0)'; then :; else
  echo "the consumer environment carries an editable install hook" >&2
  exit 1
fi

# 4) The console script declared in [project.scripts] exists only in an
#    installed environment, so nothing else in CI can notice it breaking.
#    Invoked with no bundle: exit 2 is the CLI's documented usage error, which
#    it can only reach by importing the package and running its own parser.
echo "==> the packaged console script resolves"
[ -x "$WORK/consumer/bin/obsvr-verify" ] || { echo "obsvr-verify was not installed" >&2; exit 1; }
set +e
CLI_OUT="$("$WORK/consumer/bin/obsvr-verify" 2>&1)"
CLI_CODE=$?
set -e
if [ "$CLI_CODE" -ne 2 ] || ! printf '%s' "$CLI_OUT" | grep -q "Usage: obsvr-verify"; then
  echo "obsvr-verify did not reach its own argument parser (exit $CLI_CODE): $CLI_OUT" >&2
  exit 1
fi

# 5) Run the consumer from OUTSIDE the repository. The script is copied so its
#    own directory - which Python puts on sys.path - is the scratch directory
#    and not scripts/.
echo "==> driving a governed refusal from outside the repository"
mkdir -p "$WORK/consumer-run"
cp "$REPO_ROOT/scripts/installed-package-consumer.py" "$WORK/consumer-run/consumer_check.py"
EXPECTED_VERSION="$(sed -n 's/^__version__ *= *"\(.*\)"/\1/p' "$REPO_ROOT/sdk-python/obsvr/_version.py")"
[ -n "$EXPECTED_VERSION" ] || { echo "could not read the version from obsvr/_version.py" >&2; exit 1; }

cd "$WORK/consumer-run"
OBSVR_REPO_ROOT="$REPO_ROOT" OBSVR_EXPECTED_VERSION="$EXPECTED_VERSION" \
  "$CONSUMER_PY" consumer_check.py

echo "==> Python install path verified"
