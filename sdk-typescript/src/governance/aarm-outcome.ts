import type { ActionTaken } from "./action-taken.js";

/** The outcome vocabulary pinned by the Obsvr compatibility profile. */
export const AARM_OUTCOMES = Object.freeze([
  "ALLOW",
  "DENY",
  "MODIFY",
  "STEP_UP",
  "DEFER",
] as const);

export type AarmOutcome = (typeof AARM_OUTCOMES)[number];

export const AARM_COMPATIBILITY_PROFILE_VERSION = "1.0" as const;

export interface AarmOutcomeInput {
  actionTaken: ActionTaken;
  /** The block represents an unresolved human-approval requirement. */
  approvalRequired?: boolean;
  /** The block represents an explicit deferral rather than a denial. */
  deferred?: boolean;
}

/** An existing event does not carry one unambiguous compatibility outcome. */
export class AarmOutcomeMappingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AarmOutcomeMappingError";
  }
}

/**
 * Map an existing Obsvr verdict onto compatibility profile 1.0.
 *
 * This is deliberately total only for states whose meaning is explicit.
 * Hook failures and `not_evaluated` are evidence states, not policy outcomes,
 * and conflicting flags are rejected rather than resolved by precedence.
 */
export function mapAarmOutcome(input: AarmOutcomeInput): AarmOutcome {
  const approvalRequired = input.approvalRequired === true;
  const deferred = input.deferred === true;

  if (approvalRequired && deferred) {
    throw new AarmOutcomeMappingError(
      "approval_required and deferred cannot both describe one outcome",
    );
  }

  if (input.actionTaken === "hook_error" || input.actionTaken === "hook_timeout") {
    throw new AarmOutcomeMappingError(
      `${input.actionTaken} records a hook failure, not a policy outcome`,
    );
  }
  if (input.actionTaken === "not_evaluated") {
    throw new AarmOutcomeMappingError(
      "not_evaluated records the absence of a policy outcome",
    );
  }

  if ((approvalRequired || deferred) && input.actionTaken !== "blocked") {
    throw new AarmOutcomeMappingError(
      "approval_required and deferred are valid only for a blocked action",
    );
  }

  if (deferred) return "DEFER";
  if (approvalRequired) return "STEP_UP";
  if (input.actionTaken === "allowed") return "ALLOW";
  if (input.actionTaken === "blocked") return "DENY";
  if (input.actionTaken === "redacted") return "MODIFY";

  const unreachable: never = input.actionTaken;
  throw new AarmOutcomeMappingError(`unsupported action_taken: ${String(unreachable)}`);
}
