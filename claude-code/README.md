# @obsvr/claude-code

Govern a coding agent's **native** tool calls — file edits, shell, search — on
the same signed audit chain as the rest of obsvr. A `PreToolUse` hook that
refuses by obsvr policy.

## Why this package exists — measured, not assumed

obsvr's SDKs are **client-side libraries**. They govern the MCP `ClientSession`
an application constructs in its *own* process: you build the session, you wrap
it with `govern_mcp` / `obsvrGovernMCP`, and obsvr sits on that object.

A coding agent like Claude Code is a **separate binary with its own MCP
client**. obsvr is not loaded into it. So the shipped SDKs govern **none** of a
coding agent's tool traffic. This was measured, not reasoned about:

| What was driven | What happened |
|---|---|
| A real MCP server, governed by obsvr **inside a client app** | The denied tool was **refused**; its side effect never ran. This is the boundary obsvr's gate holds. |
| The same MCP server, called by **Claude Code** (obsvr not in its process) | The tool **ran**, its side effect happened, the agent saw the result. obsvr recorded nothing — it was not in the call path. |
| A **native** tool (`Write`) in Claude Code | The file was written; the configured MCP server started but its tool was **never contacted**. Native tools do not traverse MCP at all. |

So the honest name for the gap is *native tool calls in coding agents* — and
even the MCP calls are uncovered here, because obsvr's gate is client-side and
the agent's MCP client is out of process. The audit's expectation that
MCP-delivered calls are "plausibly governed today, with no new code" conflates
"obsvr can govern a client you build" with "obsvr governs the agent's client";
they are different processes.

The boundary the agent **does** expose to an outside governor is its
[pre-tool hook](https://code.claude.com/docs/en/hooks.md): a separate process
the agent invokes before each tool call, which can refuse it. This package is
that hook. It refuses by the **same obsvr policy engine** (`evaluate()`) and
records on the **same signed audit chain** as every other obsvr event, so a
coding agent's native tool calls join the evidence stream instead of sitting
outside it.

**Scope is deliberately one agent.** Eight agents means eight config formats and
eight refusal protocols, none of them a versioned contract; that surface is
entered on purpose, not by momentum.

## Install and register

```sh
npm install @obsvr/claude-code
```

Register the hook in a Claude Code `settings.json` (user, project, or local):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "node ./node_modules/@obsvr/claude-code/dist/bin/pretooluse.js",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

Configure it from the environment:

| Variable | Meaning |
|---|---|
| `OBSVR_API_KEY` | **Required.** Signs and delivers the record. Without it the hook defers to the agent's own permission flow rather than blocking blind. |
| `OBSVR_INGEST_URL` | Where signed events are delivered. |
| `OBSVR_CLAUDE_CODE_POLICY` | Path to a JSON file `{ "policyRules": [ … ] }` — the obsvr policy that decides a refusal. |
| `OBSVR_DEVICE_SIGNING_KEY_FILE` | Optional Ed25519 device seal for local non-repudiation (see the SDK's `SECURITY.md`). |
| `OBSVR_FAIL_CLOSED` | `1`/`true` to DENY when obsvr cannot render a signed decision, instead of deferring (see below). Default off. |

A minimal policy that refuses a destructive shell command:

```json
{
  "policyRules": [
    {
      "id": "no-recursive-delete",
      "name": "block recursive force delete",
      "enabled": true,
      "action": "block",
      "type": "keyword",
      "conditions": { "keywords": ["rm -rf"] }
    }
  ]
}
```

## What it enforces, and what it does not

- **It refuses, it does not merely observe.** A policy block becomes the hook's
  `permissionDecision: "deny"`, which stops the tool **before it runs**. A
  blocking deny holds even under the agent's permission-bypass modes and cannot
  be loosened by them — that is what makes a hook a real enforcement point.
- **It only ever adds a refusal.** The hook never emits `allow` as an override:
  a no-match verdict yields no output and the agent's own permission flow
  decides. A governor that could loosen a restriction would be a downgrade
  channel.
- **When it cannot decide, it DEFERS by default — it does not auto-approve.**
  If obsvr cannot render a signed decision (no `OBSVR_API_KEY`, an unreadable
  payload, an engine that threw), the hook writes nothing and exits 0. This is
  a genuine deferral, not a fail-open: an empty PreToolUse response leaves the
  call to **the agent's own permission settings**, exactly as if this hook
  were not installed. obsvr adds no refusal on that path *and grants no
  permission* — it can never turn a call the agent would have denied into an
  allowed one. The effective outcome is therefore whatever the agent's
  baseline permissions say; if that baseline is permissive (e.g. an
  accept-all mode), an un-signable call runs. Set **`OBSVR_FAIL_CLOSED=1`** to
  turn those paths into a hard deny instead — a high-assurance posture that
  would rather block a tool obsvr could not evaluate than let the agent's
  baseline decide it. It is opt-in because a hook that hard-denied whenever it
  was misconfigured (an unset `OBSVR_API_KEY`, say) would brick the agent, the
  same production hazard obsvr's own `fail_mode` defaults away from.
- **The record is per-invocation.** The hook is a short-lived process, one per
  tool call, so each invocation is its own chain session — the same property
  the SDK documents for serverless cold starts. Events verify under the shipped
  `obsvr-verify` with the API key (and the device key, if configured); a
  cross-invocation continuous chain is a deliberate non-goal here.
- **It adds latency per tool call, bounded.** The hook flushes the signed
  event before exiting so a refusal is never dropped, and the agent waits for
  the hook to exit — so every governed tool call pays up to the flush budget
  (2 s) if ingest is slow or unreachable. The *decision* is not what waits: the
  deny is written to stdout before the flush. If your ingest is remote and
  latency-sensitive, weigh this against a client-side gate for the surfaces
  that have one.
- **Hook timeout is the agent's to enforce, not ours.** If the hook exceeds
  the `timeout` you configure in `settings.json`, the agent kills it and
  applies its own timed-out-hook behavior; the hook bounds its own runtime with
  the flush budget above so it finishes well under a typical timeout, but a
  wedged ingest plus a very short configured timeout is a combination only you
  can rule out.
- **It does not close the MCP gap for the agent.** Governing the agent's MCP
  calls means governing the **server** it talks to, or the agent adopting an
  obsvr-wrapped client — neither is this hook. This package covers the native
  tools, which are the traffic nothing else can reach.

The refusal and the record are the shipped engine's — `evaluate()` runs the
identical policy pipeline the SDKs run and emits the signed event — so this
package is a thin adapter from the agent's hook contract to obsvr, not a second
policy implementation that could disagree with the first.
