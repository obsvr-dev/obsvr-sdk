/**
 * MCP tool-descriptor content-hash pinning (rug-pull defense).
 *
 * The attack: a tool presents a benign descriptor at review/discovery time,
 * then the server swaps it later — a poisoned description the model will
 * read, or a widened input schema that exfiltrates extra arguments. Name
 * alone identifies nothing; the CONTENT of the descriptor is the identity.
 *
 * Defense: hash a canonical projection of each descriptor seen at
 * tools/list. Pins come from two sources, in precedence order:
 *   1. Config pins (`mcpToolPolicy.pinning.pins[name]`) — operator-declared,
 *      version-controlled, survive restarts. Authoritative.
 *   2. TOFU (trust-on-first-use) — the first hash seen for a name in this
 *      governed client's lifetime. A later change keeps flagging/blocking
 *      until the operator explicitly pins the new hash: the store NEVER
 *      silently re-pins (a "re-register to re-pin" pattern would let the
 *      attacker's swap ratify itself).
 *
 * Hashing reuses the SDK's cross-language-pinned canonicalization
 * (stableStringify ≡ Python _canonical_json, pinned by rules_hash.json) and
 * the full SHA-256 digest — never truncated (a 64-bit prefix is
 * birthday-collidable by an adversary who controls descriptor bytes).
 * Vectors pinned in conformance/fixtures/tool_pinning.json.
 *
 * Honest boundary: TOFU pins live in-process and die with it — a restart is
 * a fresh TOFU window. Config pins are the durable mechanism; the
 * per-tool hash is surfaced on signed inventory/call events precisely so an
 * operator can copy an observed hash into config. Pins are keyed by tool
 * name within one governed client (per-instance store), so two servers
 * governed by the same process do not collide; config pins are global by
 * name — if two servers expose the same tool name with different (both
 * legitimate) descriptors, pin per deployment instead.
 */

import { sha256Hex } from "./decision-record.js";

/** The descriptor fields the SDK sees at tools/list (MCP wire names). */
export interface McpToolDescriptor {
  name?: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: unknown;
}

/** Pinning sub-config of mcpToolPolicy (all fields optional, off by default). */
export interface ToolPinningConfig {
  enabled?: boolean;
  /** warn (default): flag violations on events; block: strip at discovery + refuse calls. */
  mode?: "warn" | "block";
  /** Operator-declared pins: tool name -> full 64-hex descriptor hash. */
  pins?: Record<string, string>;
  /** Strict mode: a tool with neither a config pin nor a TOFU sighting is a violation. */
  requirePin?: boolean;
}

/**
 * Canonical projection of a tool descriptor: the security-relevant fields
 * under FIXED canonical keys, absent/undefined/null fields OMITTED (never
 * serialized as null) — same convention as the canonical rules projection.
 * Includes title/annotations/outputSchema: MCP behavior hints
 * (readOnlyHint, destructiveHint, ...) change what a reviewer approved just
 * as much as the description does.
 */
export function canonicalToolDescriptor(
  tool: McpToolDescriptor | null | undefined,
): Record<string, unknown> {
  const t = tool ?? {};
  const out: Record<string, unknown> = {};
  if (t.annotations !== undefined && t.annotations !== null) out.annotations = t.annotations;
  if (t.description !== undefined && t.description !== null) out.description = t.description;
  if (t.inputSchema !== undefined && t.inputSchema !== null) out.input_schema = t.inputSchema;
  if (t.name !== undefined && t.name !== null) out.name = t.name;
  if (t.outputSchema !== undefined && t.outputSchema !== null) out.output_schema = t.outputSchema;
  if (t.title !== undefined && t.title !== null) out.title = t.title;
  return out;
}

/**
 * Canonical number serialization that is BYTE-IDENTICAL to the Python twin
 * (`_canonical_number`). The rules-hash canonicalizer (stableStringify /
 * _canonical_json) delegates numbers to `JSON.stringify` / `json.dumps`,
 * which DISAGREE across languages for legal JSON numbers (whole-valued
 * floats `1.0`→"1" vs "1.0", exponent forms, `-0`, ints past 2^53) — a
 * descriptor is attacker-controlled JSON, so that divergence would make the
 * same tool hash differently in the two SDKs. This dedicated formatter fixes
 * the agreeing cases and FAILS CLOSED (throws → hash_error → flag/block,
 * never a bypass) on the values the two runtimes cannot represent identically.
 *
 * Agreeing set: safe integers (|n| ≤ 2^53−1, exact in both) as a decimal
 * integer (−0 normalized to "0"); non-integers in [1e-4, 1e16) as their
 * shortest round-tripping decimal (both engines emit plain decimal here).
 * Everything else (exponent-notation extremes, ints past 2^53 where JS loses
 * precision, non-finite) is unverifiable cross-SDK → throw.
 */
function canonicalNumber(n: number): string {
  if (!Number.isFinite(n)) throw new Error("tool-pin: non-finite number in descriptor");
  if (Number.isSafeInteger(n)) return Object.is(n, -0) ? "0" : String(n);
  const a = Math.abs(n);
  if (!Number.isInteger(n) && a >= 1e-4 && a < 1e16) return String(n);
  throw new Error("tool-pin: number outside cross-SDK-stable range");
}

/**
 * Canonical JSON for hashing (dedicated to tool descriptors; NOT the frozen
 * rules-hash canonicalizer). Recursively: sorted object keys, nested nulls
 * KEPT (only the top-level projection omits absent fields), strings/keys via
 * the native JSON string serializer (identical escaping in both engines),
 * numbers via canonicalNumber. Throws on unsupported/undecidable values so
 * the caller fails closed.
 */
function canonicalJsonForHash(value: unknown): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") return canonicalNumber(value as number);
  if (t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalJsonForHash(v === undefined ? null : v)).join(",") + "]";
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJsonForHash(obj[k])).join(",") + "}";
  }
  throw new Error("tool-pin: unsupported value type in descriptor: " + t);
}

/**
 * Full SHA-256 (lowercase 64-hex) over the canonical descriptor JSON.
 * Byte-identical in both SDKs; pinned by tool_pinning.json hash_cases.
 * THROWS on a descriptor carrying a cross-SDK-unstable number (callers
 * treat a throw as hash_error and fail closed).
 */
export function toolDescriptorHash(tool: McpToolDescriptor | null | undefined): string {
  return sha256Hex(canonicalJsonForHash(canonicalToolDescriptor(tool)));
}

export type ToolPinStatus = "ok" | "mismatch" | "unpinned";

export interface ToolPinVerdict {
  status: ToolPinStatus;
  /** What the pipeline must do: none (clean/unpinned-lenient), flag, block. */
  enforcement: "none" | "flag" | "block";
  /** The pin the observed hash was compared against (absent when unpinned). */
  expected?: string;
  /** Hash of the descriptor as listed (absent when hashing failed). */
  observed?: string;
  /** Which pin source decided (absent when unpinned). */
  source?: "config" | "tofu";
  /** Machine-readable cause: descriptor_hash_mismatch | hash_error | pin_required */
  reason?: string;
}

/**
 * Pure pin decision (fixture-pinned in tool_pinning.json decision_cases).
 * Config pin wins over TOFU; a hashing failure fails CLOSED (treated as a
 * mismatch — an unhashable descriptor must not bypass the gate); an
 * unpinned tool passes unless requirePin. Hash comparison is
 * case-insensitive on the pin side (operators paste hex).
 *
 * STRICT MODE (requirePin): only an operator CONFIG pin satisfies — a TOFU
 * pin does NOT. Otherwise a brand-new/aliased tool's first listing would be
 * a pin_required violation AND record its own hash as the TOFU pin, so the
 * next listing would trust it (self-ratification). requirePin therefore
 * means "config-pinned tools only"; TOFU is disabled under it.
 */
export function evaluateToolPin(input: {
  configPin?: string;
  tofuPin?: string;
  observedHash?: string;
  mode?: "warn" | "block";
  requirePin?: boolean;
}): ToolPinVerdict {
  const enforce = input.mode === "block" ? "block" : "flag";
  const effectiveTofu = input.requirePin ? undefined : input.tofuPin;
  const pin = input.configPin ?? effectiveTofu;
  const source: ToolPinVerdict["source"] =
    input.configPin !== undefined ? "config" : effectiveTofu !== undefined ? "tofu" : undefined;

  if (input.observedHash === undefined) {
    // Fail closed: could not derive a hash for the descriptor.
    return {
      status: "mismatch",
      enforcement: enforce,
      reason: "hash_error",
      ...(pin !== undefined ? { expected: pin.toLowerCase(), source } : {}),
    };
  }
  if (pin !== undefined) {
    if (pin.toLowerCase() === input.observedHash) {
      return { status: "ok", enforcement: "none", expected: pin.toLowerCase(), observed: input.observedHash, source };
    }
    return {
      status: "mismatch",
      enforcement: enforce,
      expected: pin.toLowerCase(),
      observed: input.observedHash,
      source,
      reason: "descriptor_hash_mismatch",
    };
  }
  if (input.requirePin) {
    return { status: "unpinned", enforcement: enforce, observed: input.observedHash, reason: "pin_required" };
  }
  return { status: "unpinned", enforcement: "none", observed: input.observedHash };
}

/** Bounded per-client TOFU + verdict store. */
const MAX_PINNED_TOOLS = 10_000;

export interface ToolPinStore {
  /** First-seen hash for a name; NEVER overwritten (no silent re-pin). */
  getTofuPin(name: string): string | undefined;
  /** Record a first sighting. No-op if already pinned or the store is full. */
  recordTofuPin(name: string, hash: string): void;
  /** Latest discovery verdict, consulted by the call-time gate. */
  getVerdict(name: string): ToolPinVerdict | undefined;
  setVerdict(name: string, verdict: ToolPinVerdict): void;
  /** All names with a TOFU pin (for removal detection). */
  pinnedNames(): string[];
  /** True once the store refused a recording (cap reached). */
  saturated(): boolean;
}

export function createToolPinStore(): ToolPinStore {
  const tofu = new Map<string, string>();
  const verdicts = new Map<string, ToolPinVerdict>();
  let saturated = false;
  return {
    getTofuPin: (name) => tofu.get(name),
    recordTofuPin: (name, hash) => {
      if (tofu.has(name)) return; // no silent re-pin, ever
      if (tofu.size >= MAX_PINNED_TOOLS) {
        // Refuse rather than evict: evicting would silently DROP protection
        // for an already-pinned tool. Saturation is surfaced on events.
        saturated = true;
        return;
      }
      tofu.set(name, hash);
    },
    getVerdict: (name) => verdicts.get(name),
    setVerdict: (name, verdict) => {
      if (verdicts.size >= MAX_PINNED_TOOLS && !verdicts.has(name)) {
        saturated = true;
        return;
      }
      verdicts.set(name, verdict);
    },
    pinnedNames: () => [...tofu.keys()],
    saturated: () => saturated,
  };
}

/** Resolve the pinning sub-config (absent/disabled => undefined). */
export function resolveToolPinning(
  mcpToolPolicy: { pinning?: ToolPinningConfig } | undefined,
): Required<Pick<ToolPinningConfig, "mode">> & ToolPinningConfig | undefined {
  const p = mcpToolPolicy?.pinning;
  if (!p?.enabled) return undefined;
  return { ...p, mode: p.mode === "block" ? "block" : "warn" };
}
