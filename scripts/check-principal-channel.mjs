#!/usr/bin/env node
/**
 * Every path that consumes a principal must read the same resolved channel.
 *
 * A principal reaches a governed call by more than one channel — per-call
 * metadata, the wrap-time option, the ambient useSubject() scope — and each
 * surface resolves them ONCE into an enforcing view. A layer that reads the
 * raw metadata object instead sees only the first channel, so the view that
 * ENFORCES and the view that is RECORDED disagree about who made the call.
 *
 * That defect has been repaired four times, in four places, always the same
 * shape: the integrations seam metered the 'default' quota bucket for every
 * caller; the proxy wrapper did the same, making a per-user limit behave as a
 * global one and refusing an unrelated user's first call; the approval
 * request filed for a human reviewer carried no user_id while the blocked
 * event for that same call named one; and wrap() dropped the options on an
 * already-governed client, so a call the caller HAD attributed was refused as
 * unattributed. Nothing structural stopped the next one, because each
 * instance is one plausible line in a file where the raw object is in scope.
 *
 * So this pins the shape rather than the instances: on each surface the raw
 * channel may be read only for the purposes enumerated below, and every other
 * read must go through that surface's resolved view. A new consumer written
 * the old way fails here, naming the line and the view to use instead.
 *
 * What it does NOT catch: a principal consumer added to a file this script
 * does not know about. Adding a governed surface means adding it here — which
 * is the point at which someone is thinking about this invariant anyway.
 *
 *   node scripts/check-principal-channel.mjs
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * One entry per governed surface.
 *
 * `channel`   the raw identity object, which enforcement must not read
 * `view`      what a consumer is supposed to read instead
 * `allowed`   the purposes a raw read is legitimate for. Each needs a reason,
 *             because an allowlist nobody can audit is not a guard.
 */
const SURFACES = [
  {
    file: "sdk-typescript/src/proxy/wrapper.ts",
    channel: /audit_fields\.metadata/,
    view: "enforcingMetadata()",
    allowed: [
      {
        // The enforcing view itself, and the single identity resolution that
        // feeds it. These two ARE the channel's readers.
        why: "builds the resolved view",
        match: /^\s*\.\.\.\(\(audit_fields\.metadata \?\? \{\}\) as Record<string, unknown>\),$|^\s*const rawMeta = /,
      },
      {
        // Telemetry stamping writes the reserved obsvr_telemetry key back
        // onto the record. A write is not a principal read.
        why: "stamps telemetry onto the record",
        match: /audit_fields\.metadata = \{|\.\.\.\(\(audit_fields\.metadata as Record<string, unknown>\) \?\? \{\}\),|obsvr_telemetry as Record<string, unknown>\) \?\? \{\}\),|^\s*const md = \(audit_fields\.metadata \?\? \{\}\) as Record<string, unknown>;/,
      },
      {
        // The event carries the caller's metadata verbatim. This is the
        // RECORDED channel, which is not being resolved — it is being copied.
        why: "carries caller metadata onto the audit event",
        match: /^\s*audit_fields\.metadata as Record<string, unknown> \| undefined,$/,
      },
    ],
  },
  {
    file: "sdk-typescript/src/integrations/core.ts",
    channel: /ctx\.metadata/,
    view: "evalMetadata",
    allowed: [
      {
        why: "builds the resolved view",
        match: /^\s*const evalMetadata: Record<string, unknown> = \{ \.\.\.\(ctx\.metadata \?\? \{\}\) \};$/,
      },
      {
        // requirePrincipal runs OUTSIDE the guarded section and reads the
        // principal defensively, before the view exists; see the comment
        // there for why an unreadable metadata object counts as absent.
        why: "the require-principal gate's defensive pre-guard read",
        match: /principalForGate|config\.requirePrincipal === true && ctx\.metadata/,
      },
    ],
  },
];

/**
 * Python resolves this differently and does not need the same guard: the
 * enforcing metadata is a LOCAL rebound at the top of apply_pre_call_policy,
 * so a layer below it cannot reach the caller's dict to read it raw — the
 * language does structurally what the allowlists above do by inspection.
 * Asserted here so that property is not silently lost.
 */
const PY_FOLD = {
  file: "sdk-python/obsvr/policy.py",
  fn: "def apply_pre_call_policy(",
  fold: /metadata\[_idk\] = _ambient_subject\[_idk\]/,
};

let failures = 0;
const fail = (msg) => {
  console.error(`✗ ${msg}`);
  failures += 1;
};

for (const surface of SURFACES) {
  const path = join(root, surface.file);
  let lines;
  try {
    lines = readFileSync(path, "utf8").split("\n");
  } catch {
    fail(`${surface.file} is missing — the guard cannot check a surface it cannot read`);
    continue;
  }

  let sawView = false;
  const unexplained = [];

  lines.forEach((line, i) => {
    // Comments discuss the channel by name constantly; they enforce nothing.
    const code = line.replace(/\/\/.*$/, "").replace(/^\s*\*.*$/, "");
    if (code.includes(surface.view.replace("()", ""))) sawView = true;
    if (!surface.channel.test(code)) return;
    if (surface.allowed.some((a) => a.match.test(code))) return;
    unexplained.push({ n: i + 1, text: line.trim() });
  });

  if (!sawView) {
    fail(`${surface.file}: no ${surface.view} — the resolved view is gone, so nothing routes through it`);
  }

  for (const u of unexplained) {
    fail(
      `${surface.file}:${u.n} reads the raw identity channel:\n` +
        `      ${u.text}\n` +
        `    Enforcement must read ${surface.view}, which resolves the per-call, wrap-time\n` +
        `    and ambient channels into one view. If this read is NOT a principal consumer,\n` +
        `    add it to the allowlist in scripts/check-principal-channel.mjs with a reason.`,
    );
  }

  if (!unexplained.length) {
    console.log(`✓ ${surface.file}: every enforcement read goes through ${surface.view}`);
  }
}

{
  const src = readFileSync(join(root, PY_FOLD.file), "utf8");
  const body = src.slice(src.indexOf(PY_FOLD.fn));
  if (!PY_FOLD.fold.test(body.slice(0, 8000))) {
    fail(
      `${PY_FOLD.file}: ${PY_FOLD.fn.trim()} no longer folds the ambient subject into its\n` +
        `    local enforcing metadata. That fold is what makes every layer below it read one\n` +
        `    resolved channel by construction.`,
    );
  } else {
    console.log(`✓ ${PY_FOLD.file}: the choke-point fold is in place`);
  }
}

if (failures) {
  console.error(`\n${failures} principal-channel violation(s).`);
  process.exit(1);
}
console.log("\nprincipal channel: one resolution per surface, every consumer reading it.");
