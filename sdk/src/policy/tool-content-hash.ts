/**
 * tool_content_hash producer (`obsvr-tool-content-v1`).
 *
 * Sealed evidence of exactly WHICH tool content and arguments an agent saw on
 * a given tool call. The hash is a single 64-hex field stamped on tool-call
 * events; the platform's ledger seals it in the v8 Merkle leaf, so a
 * descriptor swap or a rug-pulled MCP server becomes attributable after the
 * fact: the customer discloses the parts, anyone recomputes the hash, and it
 * either matches the anchored root or it does not.
 *
 * The document is deliberately reconstructable offline from disclosed parts -
 * the same replay property `decision_input_hash` has:
 *
 *   tool_content_hash = sha256hex( canonical({
 *     schema:            "obsvr-tool-content-v1",
 *     tool_name:         <the name the call targeted>,
 *     descriptor_sha256: sha256hex( canonical({name, description, input_schema}) ),
 *     args_sha256:       sha256hex( canonical(<call arguments>) ),
 *   }) )
 *
 * ## Why this is NOT the descriptor-pinning hash
 *
 * The SDK already hashes tool descriptors in tool-pinning.ts. The two hashes
 * look similar and are not interchangeable; keep them apart:
 *
 * | | `toolDescriptorHash` (tool-pinning.ts) | `tool_content_hash` (here) |
 * |---|---|---|
 * | Purpose | trust-on-first-use rug-pull DEFENSE, in-process | platform EVIDENCE contract, sealed in the ledger |
 * | Question | "did this descriptor change since we trusted it?" | "which tool content and args did this call see?" |
 * | Covers | descriptor only, 6 fields: name, title, description, input_schema, output_schema, annotations | a document binding tool_name + a 3-field descriptor digest + an ARGUMENTS digest |
 * | Owner | this SDK, free to evolve with pinning policy | the ingest/ledger wire contract; changing it is a cross-package breaking change |
 * | Consumer | the pinning store, at discovery time | the ingest schema and the v8 leaf, per call |
 *
 * The projections differ on purpose. Pinning wants everything a reviewer
 * approved (behavior hints included, since `destructiveHint` flipping matters
 * as much as the description). The evidence contract fixes a narrower,
 * platform-defined descriptor projection - `{name, description, input_schema}` -
 * and adds the arguments, which pinning never covers because arguments are
 * per-call, not per-descriptor. A tool can therefore be perfectly pinned and
 * still produce a different `tool_content_hash` on every call, which is the
 * point.
 *
 * ## Canonicalization
 *
 * Reuses `canonicalJsonForHash` from tool-pinning.ts: RFC 8785-style sorted
 * keys, no insignificant whitespace, and - critically - the cross-SDK-stable
 * number formatter. Tool descriptors and call arguments are attacker-shaped
 * JSON, and the frozen rules-hash canonicalizer delegates numbers to
 * `JSON.stringify` / `json.dumps`, which disagree across the two languages on
 * legal JSON numbers (whole-valued floats, exponent forms, -0, ints past
 * 2^53). Hashing tool content with that canonicalizer would seal a hash the
 * Python twin cannot reproduce - permanently, since sealed evidence is not
 * re-issuable. Values neither runtime can represent identically make the
 * canonicalizer throw; callers treat a throw as a hash failure and omit the
 * field rather than seal a wrong one.
 *
 * Absent optional fields are OMITTED from the descriptor projection, never
 * serialized as null - the same convention as the canonical decision-input
 * document and the canonical rule projection.
 *
 * Parity: the Python twin is a follow-on item; the byte contract of record is
 * conformance/fixtures/tool_content_hash.json. This module computes; it wires
 * nothing (attaching the field at tool boundaries is a separate change).
 *
 * @packageDocumentation
 */

import { sha256Hex } from "./decision-record.js";
import { canonicalJsonForHash } from "./tool-pinning.js";

/** Schema tag of the canonical tool-content document. */
export const TOOL_CONTENT_SCHEMA = "obsvr-tool-content-v1";

/**
 * The descriptor fields the evidence contract covers, under MCP wire names.
 * Narrower than the pinning projection on purpose (see the module docs).
 */
export interface ToolContentDescriptor {
  name?: string;
  description?: string;
  inputSchema?: unknown;
}

/** The canonical tool-content document (v1). Never contains a JSON null. */
export interface ToolContentDocument {
  schema: typeof TOOL_CONTENT_SCHEMA;
  tool_name: string;
  descriptor_sha256: string;
  args_sha256: string;
}

/** Inputs to {@link buildToolContentDocument}. */
export interface ToolContentParams {
  /**
   * The tool name the call targeted. Falls back to the descriptor's own name
   * when omitted, then to "" - a missing name is recorded as empty, never
   * guessed, so the digest still commits to what was actually seen.
   */
  toolName?: string;
  /** The descriptor the agent saw for that tool, if the caller has it. */
  descriptor?: ToolContentDescriptor | null;
  /** The call arguments. Absent arguments canonicalize as an empty object. */
  args?: unknown;
}

/**
 * Canonical projection of the descriptor for the evidence contract: exactly
 * `{name, description, input_schema}`, absent/null fields omitted.
 *
 * `input_schema` is in the projection deliberately: a wrapper can keep a
 * tool's name and description byte-identical and widen its input schema to
 * exfiltrate extra arguments, which a name+description digest would miss.
 */
export function canonicalToolContentDescriptor(
  descriptor: ToolContentDescriptor | null | undefined,
): Record<string, unknown> {
  const d = descriptor ?? {};
  const out: Record<string, unknown> = {};
  if (d.description !== undefined && d.description !== null) out.description = d.description;
  if (d.inputSchema !== undefined && d.inputSchema !== null) out.input_schema = d.inputSchema;
  if (d.name !== undefined && d.name !== null) out.name = d.name;
  return out;
}

/**
 * SHA-256 (lowercase 64-hex) over the canonical descriptor projection.
 * THROWS on descriptor content neither runtime can canonicalize identically.
 */
export function toolContentDescriptorHash(
  descriptor: ToolContentDescriptor | null | undefined,
): string {
  return sha256Hex(canonicalJsonForHash(canonicalToolContentDescriptor(descriptor)));
}

/**
 * SHA-256 (lowercase 64-hex) over the canonical call arguments. Absent or
 * null arguments hash as the empty object, so "called with no arguments" and
 * "called with {}" are the same evidence - they are the same call.
 * THROWS on arguments neither runtime can canonicalize identically.
 */
export function toolArgsHash(args: unknown): string {
  return sha256Hex(canonicalJsonForHash(args === undefined || args === null ? {} : args));
}

/**
 * Build the canonical tool-content document. Pure: no I/O, no clock, no
 * per-process state, so the same call always yields the same document.
 */
export function buildToolContentDocument(params: ToolContentParams): ToolContentDocument {
  const name =
    typeof params.toolName === "string" && params.toolName.length > 0
      ? params.toolName
      : typeof params.descriptor?.name === "string"
        ? params.descriptor.name
        : "";
  return {
    schema: TOOL_CONTENT_SCHEMA,
    tool_name: name,
    descriptor_sha256: toolContentDescriptorHash(params.descriptor),
    args_sha256: toolArgsHash(params.args),
  };
}

/**
 * Canonical serialization of a tool-content document: sorted keys, no
 * insignificant whitespace. This exact string is what gets hashed, so it is
 * the byte contract both languages must reproduce.
 */
export function canonicalizeToolContent(doc: ToolContentDocument): string {
  return canonicalJsonForHash(doc as unknown as Record<string, unknown>);
}

/**
 * `tool_content_hash` for one tool call: SHA-256 (lowercase 64-hex) of the
 * canonical document. Bounded work - four small digests over content the
 * caller already holds in memory, no parsing of untrusted text beyond the
 * canonicalizer - so it is safe on the call path.
 *
 * THROWS if any part cannot be canonicalized identically in both languages.
 * A caller on the hot path must catch and omit the field: an absent
 * `tool_content_hash` seals honestly as empty, a wrong one seals a lie.
 */
export function computeToolContentHash(params: ToolContentParams): string {
  return sha256Hex(canonicalizeToolContent(buildToolContentDocument(params)));
}
