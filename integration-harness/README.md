# Integration harness (keyless group)

These suites drive **real provider client libraries** — the actual `openai`,
`together-ai`, `@aws-sdk/client-bedrock-runtime` and `@modelcontextprotocol/sdk`
packages — against local stub servers, wrap them with `@obsvr/sdk` exactly as a
consumer would, and assert what came out the other end: the signed event schema,
the HMAC chain, the policy decision, and whether the operation actually ran.

```
npm install          # resolves @obsvr/sdk from ../sdk-typescript
npm test             # == node run.mjs offline
node run.mjs list    # what is here
node run.mjs mcp     # one suite
```

`npm install` needs `../sdk-typescript` to have been built (`npm run build`
there), because `@obsvr/sdk` is an ESM package whose exports map points into
`dist/`.

## What these catch that `sdk-typescript/tests/` does not

The unit suites import TypeScript source and stub the boundary. These import the
built package through its **export map**, construct **real framework objects**,
and let the SDK's auto-discovery find them. That difference is not academic —
every defect found in the week before this group was vendored was invisible to
both SDKs' unit suites, all green throughout, and visible here.

Nothing here needs a credential or the network. Every provider client is pointed
at a stub on `127.0.0.1`, and the audit sender is pointed at an in-process mock
ingest. That is what makes the group fit to gate a merge.

## This is a vendored copy

**The upstream harness lives outside this repository** and is larger: it also
carries the keyed suites that drive live providers and real frameworks against
real credentials, plus a Python half. Only the keyless TypeScript group is
vendored here, because only it has the three properties a merge gate needs —
no credentials, no network, deterministic.

The practical consequence, stated plainly so a later reader is not surprised by
it: **this copy can drift from its source.** A suite added upstream does not
appear here by itself, and nothing in CI can detect that, because the upstream
copy is not reachable from a runner. Treat a change to the suites here as a
change that should be mirrored upstream, and vice versa.

Two things were changed while vendoring, both because the original could only
run on one machine:

- `run.mjs`'s `ORDER` declares exactly the suites present here. The runner
  fails on a declared-but-missing suite by design, so listing the keyed suites
  that were deliberately left out would fail every run rather than skip them.
- `integrations/device-seal/test.mjs` located the shipped `cli-verify.js`
  through an absolute path. It now resolves it through the `@obsvr/sdk`
  package, the same way `lib/fixtures.mjs` already resolved the conformance
  fixtures.

## Layout

| Path | What it is |
| --- | --- |
| `run.mjs` | The runner. Reports a declared-but-unwritten suite as `MISSING` and fails. |
| `lib/mock-ingest.mjs` | In-process ingest that captures the signed events. |
| `lib/assert-governance.mjs` | Chain, signature and device-seal verification. |
| `lib/fixtures.mjs` | Loads `conformance/fixtures/` through the resolved package. |
| `integrations/<name>/test.mjs` | One suite; exports `run()` and `meta`. |
