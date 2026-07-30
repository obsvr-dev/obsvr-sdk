/**
 * The closed set of `action_taken` verdicts.
 *
 * WHY THIS FILE EXISTS. `action_taken` is the field a post-incident reader
 * consults to learn what governance did, and it was a closed enum in name only:
 * TypeScript expressed it as a string-literal union in two separate
 * declarations, Python had no enumeration of it at all, and the corpus pinned
 * three of its six values. `not_evaluated` in particular was live in BOTH SDKs,
 * emitted from several surfaces, and pinned nowhere — the two languages agreed
 * only because they had been changed in the same commit. That is the divergence
 * class the conformance corpus exists to close, and every other case of it in
 * this audit was found by a live probe rather than by a check.
 *
 * The set is pinned cross-language by `conformance/fixtures/action_taken.json`.
 * Each language asserts its own copy against that fixture, which makes the two
 * agree transitively without comparing TypeScript to Python directly.
 *
 * Adding a member is a BREAKING change for consumers: it breaks exhaustive
 * switches. Renaming one is worse — it is a wire-format change to stored
 * evidence.
 */

import type { AuditEvent } from "../proxy/types.js";
import type { ComplianceInfo } from "../integrations/core.js";

/**
 * Sorted so the fixture comparison is order-insensitive without either side
 * having to sort at assertion time — the same convention `REASON_CODES` uses.
 */
export const ACTION_TAKEN = Object.freeze([
  "allowed",
  "blocked",
  "hook_error",
  "hook_timeout",
  "not_evaluated",
  "redacted",
] as const);

// Deliberately NOT annotated `readonly string[]`, which is how the sibling
// reason-code registry declares its array. That annotation widens the literals
// to `string`, which would make the derived type `string` and turn every check
// below into a tautology that cannot fail. Caught by the compiler on the first
// run, which is the only reason it is not still here.

/** The verdict type, derived from the frozen set rather than restated. */
export type ActionTaken = (typeof ACTION_TAKEN)[number];

// ── the set and the unions must agree, checked by the compiler ───────────────
//
// The union is declared in TWO places, and neither is derived from the other. A
// member added to one and not the others would leave the frozen set — and the
// fixture it is pinned against — quietly describing a different vocabulary from
// the one the code emits. These four aliases are erased at build time and cost
// nothing at runtime; a mismatch is a type error naming this file.
//
// Both directions, because they fail differently: a union member missing from
// the set means an emitted value nothing pins, and a set member missing from a
// union means a pinned value the code cannot produce.

type Exact<A, B> = [Exclude<A, B>] extends [never]
  ? [Exclude<B, A>] extends [never]
    ? true
    : never
  : never;

// eslint-disable-next-line @typescript-eslint/no-unused-vars
type _AuditEventAgrees = Exact<AuditEvent["action_taken"], ActionTaken>;
// eslint-disable-next-line @typescript-eslint/no-unused-vars
type _ComplianceInfoAgrees = Exact<ComplianceInfo["action_taken"], ActionTaken>;

const _auditEventAgrees: _AuditEventAgrees = true;
const _complianceInfoAgrees: _ComplianceInfoAgrees = true;
void _auditEventAgrees;
void _complianceInfoAgrees;
