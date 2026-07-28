/**
 * Destructive-capability hints read off tool descriptors.
 *
 * The session-taint latch's strongest control is the destructive-capability
 * set: a tainted session loses the tools that could do damage while ordinary
 * egress is only flagged, so one detection never bricks the session. That
 * control was operator-supplied only — an exact list of tool names in
 * `sessionTaint.destructiveTools`. An operator who configured nothing got no
 * capability gate at all, silently, which made the strongest thing in the SDK
 * the one most likely to be switched off by omission.
 *
 * MCP tool descriptors already declare `annotations.destructiveHint`, and the
 * SDK already hashes it as part of descriptor pinning. This module reads it,
 * so a discovered tool that declares itself destructive joins the set without
 * anyone having to write its name down.
 *
 * ## The hint comes from the untrusted party
 *
 * The descriptor is authored by the tool server, which is exactly the party
 * the taint latch exists to defend against. So the hint is admitted in ONE
 * direction only: it can ADD a tool to the destructive set, never remove one.
 * Concretely —
 *
 *  - `destructiveHint: true` adds the tool. An affirmative claim of danger
 *    from any source is worth acting on; the worst case is over-restriction of
 *    an already-compromised session.
 *  - `destructiveHint: false` does nothing. It is a safety claim from an
 *    untrusted author, and honouring it would be letting a hostile server talk
 *    its way out of the gate by writing one word in its own descriptor.
 *  - An ABSENT hint likewise does nothing: the tool is treated as
 *    non-destructive unless the operator listed it. This is the compatible
 *    default and it is deliberate — most deployed MCP servers publish no
 *    annotations at all, and treating silence as destructive would turn the
 *    `flag` posture into a blanket block for those servers, which is precisely
 *    what `flag` exists to avoid.
 *
 * That last point is a knowing departure from how the field is specified for
 * MCP itself, where an unspecified `destructiveHint` is read as true. That
 * reading makes sense for a client deciding how loudly to prompt a user. It
 * does not survive here, because a default of "destructive unless told
 * otherwise" only works if `destructiveHint: false` is honoured — and the
 * whole point of this module is that it must not be. Given the choice between
 * honouring a hostile server's denial and treating silence as an accusation,
 * the SDK does neither: only an affirmative claim moves anything, and the
 * operator's own list is always available for the tools that matter.
 *
 * Reading is strict (`=== true`, not truthy) so the decision is exactly
 * expressible in a fixture and identical in both languages. A server wanting
 * to escape the set can simply omit the field, so strictness costs nothing.
 *
 * All of this runs at DISCOVERY, never on the call path: the store is written
 * during `tools/list` and read with one set-membership test at the gate.
 *
 * @packageDocumentation
 */

/** The descriptor fields this module reads (MCP wire names). */
export interface HintedToolDescriptor {
  annotations?: unknown;
}

/**
 * Does this descriptor affirmatively declare itself destructive?
 *
 * True only for `annotations.destructiveHint === true`. Everything else —
 * absent annotations, absent hint, `false`, a string, a number — is false.
 * See the module docs for why this is one-directional.
 *
 * FAILS TOWARD DESTRUCTIVE. Reading a property off an attacker-supplied object
 * can throw (a getter, a Proxy trap), and a descriptor the SDK cannot read is
 * precisely the case where it does not know. Treating that as "not
 * destructive" would let a server escape the set by making the field
 * unreadable rather than by lying in it, which is the same escape with an
 * extra step. The cost of the other direction is bounded: over-adding only
 * restricts a session that is ALREADY tainted, and the descriptor pin is
 * watching the same object for the same reason.
 */
export function declaresDestructive(
  tool: HintedToolDescriptor | null | undefined,
): boolean {
  try {
    const annotations = tool?.annotations;
    if (!annotations || typeof annotations !== "object" || Array.isArray(annotations)) {
      return false;
    }
    return (annotations as Record<string, unknown>).destructiveHint === true;
  } catch {
    return true;
  }
}

/**
 * Bounded per-client record of which discovered tools declared themselves
 * destructive. Monotonic by name: once recorded, a later listing claiming the
 * tool is now harmless does NOT clear it, for the same reason the hint cannot
 * remove — that would be the rug-pull the descriptor pin already defends
 * against, arriving through the capability gate instead.
 */
const MAX_HINTED_TOOLS = 10_000;

export interface CapabilityStore {
  /** Record one discovered descriptor. Only a `true` hint has any effect. */
  record(name: string, destructive: boolean): void;
  /** Was this tool name recorded destructive by a descriptor hint? */
  isDestructive(name: string): boolean;
  /** How many names are held (test/telemetry surface). */
  size(): number;
  /** True once the store refused a recording because it was full. */
  saturated(): boolean;
  /** Every hinted-destructive name, sorted (event evidence). */
  names(): string[];
}

export function createCapabilityStore(): CapabilityStore {
  const destructive = new Set<string>();
  let saturated = false;
  return {
    record: (name, isDestructive) => {
      if (!isDestructive) return; // silence and denial are the same: no effect
      if (destructive.has(name)) return;
      if (destructive.size >= MAX_HINTED_TOOLS) {
        // Refuse rather than evict. Evicting would silently drop a capability
        // restriction, and an attacker who can flood a listing would choose
        // exactly which one to drop.
        saturated = true;
        return;
      }
      destructive.add(name);
    },
    isDestructive: (name) => destructive.has(name),
    size: () => destructive.size,
    saturated: () => saturated,
    names: () => [...destructive].sort(),
  };
}
