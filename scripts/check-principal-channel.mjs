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
        // The guarded detector section first assembles the per-call and
        // wrap-time metadata channels. The rawMeta derivation immediately
        // below is still the sole resolved principal view consumed by gates.
        why: "assembles metadata inside the detector guard before resolution",
        match:
          /^\s*if \(ctx\.options\.metadata \|\| audit_fields\.metadata\) \{$|^\s*\.\.\.\(\(audit_fields\.metadata as Record<string, unknown> \| undefined\) \?\? \{\}\),$/,
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
  {
    // The tool boundary governs the most side-effecting egress there is, and
    // it resolves identity itself rather than inheriting core.ts's view — its
    // gates run before any call reaches that seam. So it needs the same
    // single-resolution property, held here for the same reason.
    file: "sdk-typescript/src/integrations/tools.ts",
    channel: /options\.metadata/,
    view: "enforcingIdentity()",
    allowed: [
      {
        // The one line inside enforcingIdentity() that seeds the view from
        // the per-call channel. It is the view's own reader, and the only
        // legitimate raw read on this surface — the audit events here build
        // their metadata from the tool fields, never by spreading the
        // caller's object, so there is no "recorded channel" exemption to
        // make and none is granted.
        why: "seeds the resolved view from the per-call channel",
        match: /^\s*\.\.\.\(\(options\.metadata \?\? \{\}\) as Record<string, unknown>\),$/,
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

/**
 * The other half of the same invariant, and the one the surface scan above
 * cannot see: the SIGNED principal must come from the channel the enforcing
 * resolution reads FIRST.
 *
 * The scans above hold enforcement to one resolved view. They say nothing
 * about what the event builder writes, and the two are different functions in
 * both languages — so a builder reading only the wrap-time options passes
 * every check above while recording a call against a principal the decision
 * was never made for. That shipped: a per-call principal override was
 * evaluated, metered and taint-keyed under the override while the event named
 * the wrap-time user. A record naming the wrong principal is worse than one
 * naming none, so this is asserted rather than left to review.
 */
const SIGNED_PRINCIPAL = [
  {
    file: "sdk-python/obsvr/events.py",
    fn: "def build_audit_event(",
    reads: /"user_id":\s*_principal_string\(\s*\(metadata or \{\}\)\.get\("user_id"\)/,
    channel: "the folded enforcing metadata",
  },
  {
    file: "sdk-typescript/src/proxy/wrapper.ts",
    fn: "function buildAuditEvent(",
    reads: /user_id:\s*\n?\s*metadataPrincipal\(auditFields\)/,
    channel: "metadataPrincipal(auditFields)",
  },
];

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

for (const site of SIGNED_PRINCIPAL) {
  let src;
  try {
    src = readFileSync(join(root, site.file), "utf8");
  } catch {
    fail(`${site.file} is missing — the guard cannot check a surface it cannot read`);
    continue;
  }
  const at = src.indexOf(site.fn);
  if (at === -1) {
    fail(`${site.file}: ${site.fn.trim()} is gone — the signing site moved without this guard`);
    continue;
  }
  if (!site.reads.test(src.slice(at, at + 12000))) {
    fail(
      `${site.file}: ${site.fn.trim()} no longer resolves the signed principal from\n` +
        `    ${site.channel} first. The enforcing resolution reads the per-call metadata\n` +
        `    channel ahead of the wrap-time option; a builder that skips it records the call\n` +
        `    against a principal the decision was not made for.`,
    );
  } else {
    console.log(`✓ ${site.file}: the signed principal comes from the enforcing channel`);
  }
}

if (failures) {
  console.error(`\n${failures} principal-channel violation(s).`);
  process.exit(1);
}
console.log("\nprincipal channel: one resolution per surface, every consumer reading it.");
