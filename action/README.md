# obsvr Evidence Verification — GitHub Action

Verify an exported [obsvr](https://github.com/obsvr) evidence bundle as a CI/PR
check. This composite action installs a pinned `@obsvr/sdk` and runs its shipped
[`obsvr-verify`](../sdk/src/cli-verify.ts) CLI against a bundle you provide,
failing the job if the tamper-evident audit chain does not verify.

Two verification tiers, chosen by whether you supply an `api-key`:

- **Structural (keyless)** — `prev_sig` linkage, `seq_no` continuity, session
  consistency, and timestamp monotonicity are checked from the events alone.
  Detects reordering, insertion, and deletion. Cannot detect a re-signed forgery.
- **Full (with `api-key`)** — every HMAC signature is recomputed from content, so
  any content tamper breaks the check. Pass the key via a secret.

Exit status maps straight to the check: `0` verified, `1` chain broken (job
fails), `2` usage error (job fails).

## Usage

```yaml
name: Verify evidence
on: [pull_request]

jobs:
  obsvr-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Structural (keyless) verification of a committed bundle
      - uses: obsvr-dev/obsvr-sdk/action@v0.9.0
        with:
          bundle: evidence/incident-bundle.json

      # Full HMAC re-verification (recommended) — key from a secret
      - uses: obsvr-dev/obsvr-sdk/action@v0.9.0
        with:
          bundle: evidence/incident-bundle.json
          api-key: ${{ secrets.OBSVR_API_KEY }}
          version: '0.9.0'
```

> Replace `obsvr-dev/obsvr-sdk/action@v0.9.0` with the Marketplace slug/ref you publish
> the action under.

## Inputs

| Input          | Required | Default   | Description |
| -------------- | -------- | --------- | ----------- |
| `bundle`       | yes      | —         | Path (relative to the repo root) to the exported evidence file: an incident bundle (`trace.steps`), a trace bundle, or a plain JSON array of audit events. |
| `api-key`      | no       | `''`      | obsvr signing/API key. When set, signatures are recomputed (full HMAC re-verification). Always pass via a secret. When empty, only structural verification runs. |
| `version`      | no       | `0.9.0`   | `@obsvr/sdk` version to install (the `obsvr-verify` CLI ships in this package). Pin an exact version for reproducible checks. |
| `node-version` | no       | `20`      | Node.js version used to run `obsvr-verify`. |

## Notes

- The action makes no network calls to obsvr: verification is fully offline, so
  an auditor (or your CI) never has to trust obsvr's servers or UI.
- For the cross-day no-insert / no-delete guarantee, also check the daily Merkle
  root against its external anchor (git anchor / RFC 3161 token) — that is a
  separate, out-of-band step from per-bundle verification.
