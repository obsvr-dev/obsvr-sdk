# Changelog

All notable changes to `@obsvr/sdk` (npm) and `obsvr-sdk` (PyPI) are documented
here. Both packages ship from this repository on one release train and share a
version number.

Breaking changes are marked **BREAKING** and carry a migration note. Additive
changes to closed enums count as breaking, because they break exhaustive
switches in consumer code.

Nothing has been published to npm or PyPI yet. Every version below describes
code that exists in this repository's history; none of them are installable
releases. The first publish will be a 0.x release from the current line.

## [Unreleased]

Changes landed since 0.10.0. This section accumulates until the next release
cut, when it is renamed to that version.

### Added

- **Python chain verification.** `obsvr.verify_chain(events, api_key)` verifies
  an exported audit chain offline - recomputing every HMAC signature and
  checking sequence continuity, chain linkage, session consistency, and
  timestamp monotonicity - and returns the same verdicts as the TypeScript
  `verifyAuditChain` on the same input. A Python-only shop no longer needs a
  Node toolchain to check its own evidence.
- **`dropped_rejected` delivery counter.** When a batch POST returns 2xx while
  refusing individual events in the response body, those events are now counted
  in their own bucket and reported as a distinct `dropped_rejected` key on the
  `X-Obsvr-Counters` poll header. Previously they were only debug-logged and,
  worse, counted as sent. Server-refused events are no longer included in
  `sent`; the existing `dropped` aggregate is unchanged and still means
  never-delivered.
- **Failure-disposition registry.** Every governance layer now declares what it
  does in each failure state (timeout, error, degraded) in one table per
  language, pinned by `conformance/fixtures/fail_mode.json`. Descriptive only:
  no call path reads it and no behavior changed. It records, among other things,
  that eight in-process detector layers currently have no error channel, so an
  unexpected exception inside them reaches the host application.

### Changed

- The normative evaluation-semantics specification (EV-1 through EV-23) now
  lives at `conformance/SPEC-evaluation.md`, beside the fixtures that pin it.
  Semantics are unchanged; its fixture map was corrected to name only cases that
  exist and to state which EV statements have no cross-language case yet.
- `conformance/fixtures/signing_vectors.json` gained a `chain_verification`
  block: thirteen tamper cases with the verdict both verifiers must produce.
  Consumers of the existing `events` and key material are unaffected.

## [0.10.0] - 2026-07-20

Security engine and integrity hardening. Private beta.

### Added

- De-obfuscation scan views, so detection sees through encodings that hide
  payloads from a naive scan.
- MCP and tool-descriptor content-hash pinning (trust-on-first-use plus
  operator-declared pins), defending against rug-pull descriptor swaps.
- Canary honeytokens and a session-taint latch: a session compromised on an
  earlier turn has its later egress escalated.
- A non-overridable anti-tamper policy floor, evaluated before customer rules
  and excluded from customer-hook override.
- SSRF-guarded outbound endpoints for the external policy backend and Presidio,
  validated at init.

## [0.9.0] - 2026-07-17

The version benchmarked in `BENCHMARKS.md`. This repository's history was
squashed at 0.10.0, so per-change detail for 0.9.0 and earlier is not
recoverable from this repository; what is recorded of the earlier lineage is
below.

## Pre-fork history

The SDK was maintained in another repository before this one, under an internal
version line that reached 2.0.0. **That line was never published**: the npm and
PyPI names were checked and no version has ever existed on either registry, so
the current 0.x line supersedes nothing and there is no upgrade path to
describe. The security work from that period is recorded here because the code
in this repository is built on it.

### [2.0.0] - 2026-06-14 (never published)

#### Security fixes

- **Streaming bypass closed.** PII scanning, policy rules, and the `onPreCall`
  hook now run *before* the model is contacted for `stream: true` calls.
  Previously every streaming request skipped those checks entirely - the whole
  governance boundary was optional if a caller passed one flag.
- **`policy_version` derived from the active rule set.** Each audit event
  carries a hash of the enabled rules rather than a hardcoded `"v1"`, so an
  auditor can reconstruct which policy decided any given call.
- **Hook timeout enforced in the proxy wrapper.** `onPreCall` runs under
  `hookTimeoutMs` (2000 ms default); a timed-out hook logs and defaults to
  allow rather than hanging the call.
- **Server-fetched policy rules validated before being applied.** The polling
  loop discards rules that do not match the rule schema, so a malformed or
  hostile server response cannot alter enforcement.
- **GitHub token pattern corrected.** The suffix length was wrong and missed
  real personal access tokens.
- **HMAC key-derivation comment corrected** to describe what the code does
  (HMAC-Extract, RFC 5869 §2.2) rather than implying full HKDF.

#### Breaking changes

- **BREAKING: `ingest_url` / `baseUrl` is required.** The previous
  `http://localhost:3000` default was removed. Unset, a warning is logged and
  events are dropped rather than streamed to whatever is listening on a local
  port. *Migration: set `ingest_url` explicitly.* (The Python default was not
  removed at the same time; see Unreleased once that lands.)
- **BREAKING: HTTPS enforced for non-localhost `ingest_url`.** An `http://` URL
  for a non-localhost host throws at init. *Migration: use `https://`, or
  localhost for development.*
- **BREAKING: source maps excluded from the published package.** `.js.map`
  files are no longer shipped; `.d.ts.map` is retained for editor
  go-to-definition.

#### Improvements

- `generateUUID()` always uses `crypto.randomUUID()`; the `Math.random()`
  fallback was removed (Node 18+ is required anyway).
- `init()` warns when `pii_policy.rules` names PII types that have no built-in
  detector, instead of silently covering nothing.

### 1.x and earlier

Internal and pre-release builds. No changelog was kept.
