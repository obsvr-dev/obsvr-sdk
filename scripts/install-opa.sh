#!/usr/bin/env bash
#
# Install the Open Policy Agent binary the Rego parity test evaluates against.
#
# WHY THIS EXISTS AS A SCRIPT RATHER THAN A MARKETPLACE ACTION.
#
# tests/unit/rego-export.test.ts is the only check that the Rego bundle
# `exportToRego()` hands an operator produces the SAME verdict as the SDK's own
# evaluator. Without opa on PATH that check cannot run at all, and for its whole
# life it did not: opa was installed in no workflow, no script, no manifest, and
# the test degraded to a green placeholder whose comment asserted the parity ran
# "in CI where opa is present". It did not run anywhere.
#
# So the install is pinned by VERSION and verified by DIGEST, the same posture
# the workflows take toward every action they call (SHA-pinned, never a tag).
# A parity check is a supply-chain-shaped dependency: it decides whether the
# exported policy is trustworthy, so the thing rendering that decision has to be
# the binary this repo chose rather than whatever a floating tag resolves to.
#
#   scripts/install-opa.sh [destination-dir]     (default: /usr/local/bin)
#
set -euo pipefail

# Pinned. Bumping this means replacing the digests below from the release's
# published .sha256 files, not editing the version alone.
OPA_VERSION="v1.19.0"

DEST="${1:-/usr/local/bin}"

# The `_static` builds are used where they exist: no libc dependency, so the
# binary behaves the same on every runner image.
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)  ASSET="opa_linux_amd64_static";  DIGEST="1dd5c5591ff856f5e20a1d66bafae9511ddf3c5552ed3b5070c70b2b6580ee3f" ;;
  Linux/aarch64) ASSET="opa_linux_arm64_static";  DIGEST="06680087ed236c8c6aaa021660d83178db829a2ad30bdb3482481fada6791b2a" ;;
  Darwin/arm64)  ASSET="opa_darwin_arm64_static"; DIGEST="6de003137cc54b65cb4a6a9c7cf6b29a248f10c1c16fc34f793a8a83b5f9d004" ;;
  Darwin/x86_64) ASSET="opa_darwin_amd64";        DIGEST="a6bb096502d176a23b721e023f3ca615a0e4773fec69511143093a2281118f5c" ;;
  *)
    echo "error: no pinned opa asset for $(uname -s)/$(uname -m)." >&2
    echo "       Add one (with its digest from the release's .sha256) rather than" >&2
    echo "       falling back to an unverified download." >&2
    exit 1
    ;;
esac

URL="https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}/${ASSET}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> downloading ${ASSET} (${OPA_VERSION})"
curl -fsSL --retry 3 --retry-delay 2 -o "$TMP/opa" "$URL"

echo "==> verifying digest"
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP/opa" | cut -d' ' -f1)"
else
  ACTUAL="$(shasum -a 256 "$TMP/opa" | cut -d' ' -f1)"
fi
if [ "$ACTUAL" != "$DIGEST" ]; then
  # Never install it anyway. A parity check run against an unexpected binary
  # is not a weaker check, it is an unknown one.
  echo "error: digest mismatch for ${ASSET}" >&2
  echo "       expected ${DIGEST}" >&2
  echo "       actual   ${ACTUAL}" >&2
  exit 1
fi

chmod +x "$TMP/opa"
# Create the destination before testing writability, or a missing directory
# reads as "not writable" and falls through to sudo — which fails on a runner
# with no tty and made the failure look like a permissions problem.
mkdir -p "$DEST" 2>/dev/null || true
if [ -w "$DEST" ]; then
  mv "$TMP/opa" "$DEST/opa"
else
  sudo mv "$TMP/opa" "$DEST/opa"
fi

echo "==> installed: $("$DEST/opa" version | head -1) at $DEST/opa"
