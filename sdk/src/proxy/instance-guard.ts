/**
 * Process-level duplicate-instance guard.
 *
 * The SDK can end up in a process twice: installed directly by the
 * application and again as a transitive dependency of something else, at two
 * versions, in two node_modules trees. Both copies are real modules with
 * their own config, their own sender, and their own polling loop. Neither
 * knows about the other, so a call wrapped by both is governed twice and
 * emitted twice - duplicate audit events for one call, two quota
 * decrements, two policy polls per interval.
 *
 * The fix is the one mechanism that survives module duplication: a slot on a
 * process-global registry keyed by `Symbol.for`, which resolves to the same
 * symbol in every copy. The first instance to initialize claims it and
 * governs. A later instance finds the slot occupied, says so once, and
 * yields.
 *
 * **What yielding means, stated plainly:** the yielded copy does not start a
 * second polling loop and does not wrap clients. A client wrapped only
 * through the yielded copy is therefore NOT governed. That is deliberate -
 * the alternative is two engines governing the same call, which produces
 * contradictory evidence about what happened - but it means the warning is
 * not cosmetic, and it names the fix: deduplicate the dependency so one copy
 * remains.
 *
 * Version stance follows opentelemetry-js: the incumbent keeps the slot. An
 * older incumbent is called out explicitly in the log, because "the copy
 * governing your traffic is older than the one you installed" is exactly the
 * surprise an operator needs told.
 *
 * @packageDocumentation
 */

/** Same symbol in every copy of the module in this process. */
const INSTANCE_SLOT = Symbol.for("obsvr.sdk.governing_instance");

export interface GoverningInstance {
  /** SDK version of the copy that holds the slot. */
  version: string;
  /** Identifies the copy within the process (not stable across restarts). */
  instanceId: string;
}

export interface ClaimResult {
  /** True when this copy holds the slot and should govern. */
  governing: boolean;
  /** The copy already holding the slot, when this claim yielded. */
  incumbent?: GoverningInstance;
  /** True when the yielded copy is NEWER than the incumbent governing it. */
  incumbentIsOlder?: boolean;
}

type SlotHolder = Record<symbol, GoverningInstance | undefined>;

function slotHolder(): SlotHolder {
  return globalThis as unknown as SlotHolder;
}

/** Numeric-ish version compare; unparseable versions compare equal. */
function isOlder(a: string, b: string): boolean {
  const parse = (v: string) => v.split(".").map((p) => Number.parseInt(p, 10));
  const [aMaj = NaN, aMin = NaN, aPatch = NaN] = parse(a);
  const [bMaj = NaN, bMin = NaN, bPatch = NaN] = parse(b);
  if ([aMaj, aMin, aPatch, bMaj, bMin, bPatch].some(Number.isNaN)) return false;
  if (aMaj !== bMaj) return aMaj < bMaj;
  if (aMin !== bMin) return aMin < bMin;
  return aPatch < bPatch;
}

/**
 * Claim the governing slot for this copy, or yield to whoever holds it.
 * Idempotent for the same instanceId: re-initializing the governing copy
 * (a re-init with new config) keeps it governing and is not a duplicate.
 */
export function claimGoverningInstance(version: string, instanceId: string): ClaimResult {
  const holder = slotHolder();
  const incumbent = holder[INSTANCE_SLOT];

  if (!incumbent) {
    holder[INSTANCE_SLOT] = { version, instanceId };
    return { governing: true };
  }
  if (incumbent.instanceId === instanceId) {
    // Same copy re-initializing: still ours, still one governing instance.
    holder[INSTANCE_SLOT] = { version, instanceId };
    return { governing: true };
  }
  return {
    governing: false,
    incumbent,
    incumbentIsOlder: isOlder(incumbent.version, version),
  };
}

/** The copy currently holding the slot, if any. */
export function governingInstance(): GoverningInstance | undefined {
  return slotHolder()[INSTANCE_SLOT];
}

/** Whether the given copy holds the slot. */
export function isGoverningInstance(instanceId: string): boolean {
  return slotHolder()[INSTANCE_SLOT]?.instanceId === instanceId;
}

/**
 * The message a yielding copy logs. Exactly one line, once per yielding
 * copy: a duplicate install is one problem, not one problem per call.
 */
export function duplicateInstanceMessage(result: ClaimResult): string {
  const incumbent = result.incumbent;
  const olderNote = result.incumbentIsOlder
    ? " The governing copy is an OLDER version than this one."
    : "";
  return (
    `[obsvr] Another copy of the SDK (version ${incumbent?.version ?? "unknown"}) is already ` +
    `governing this process, so this copy will not govern: it will not poll for policy and ` +
    `clients wrapped through it are NOT governed.${olderNote} ` +
    `Deduplicate @obsvr/sdk in your dependency tree so exactly one copy is installed.`
  );
}

/** Release the slot (tests, and any deliberate teardown). @internal */
export function _resetInstanceGuard(): void {
  delete slotHolder()[INSTANCE_SLOT];
}
