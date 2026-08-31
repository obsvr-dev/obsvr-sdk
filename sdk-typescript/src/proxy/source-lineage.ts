/**
 * Source-lineage context for document and retrieved-content ancestry.
 *
 * This is deliberately an explicit causal envelope, not content inference.
 * A caller identifies the source at the trust boundary, then the ambient
 * context carries that identity through every governed event in the same
 * async execution. Queue/process boundaries must export and re-bind the
 * envelope on the other side.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomUUID } from "node:crypto";
import { canonicalJsonForHash } from "../policy/tool-pinning.js";

export const SOURCE_LINEAGE_SCHEMA_V1 = "obsvr-source-lineage/1" as const;
export const SOURCE_LINEAGE_METADATA_KEY = "obsvr_source_lineage" as const;
export const SOURCE_LINEAGE_HASH_DOMAIN = "obsvr-source-lineage/1" as const;

const MAX_SOURCES = 16;
const MAX_PARENTS = 32;
const MAX_TAINTS = 16;
const MAX_ID_BYTES = 256;
const MAX_REASON_BYTES = 512;
const MAX_ENVELOPE_BYTES = 6000;
const SHA256_RE = /^[0-9a-f]{64}$/;

export type SourceKind =
  | "document"
  | "retrieval"
  | "tool_result"
  | "memory"
  | "user_input"
  | "other";

export type LineageDerivation =
  | "direct"
  | "retrieved"
  | "generated"
  | "summarized"
  | "tool_result"
  | "handoff"
  | "merged"
  | "unknown";

export interface SourceReferenceV1 {
  source_id: string;
  source_kind: SourceKind;
  source_hash?: string;
  source_version?: string;
  chunk_id?: string;
  retrieval_id?: string;
}

export interface LineageTaintV1 {
  taint_id: string;
  kind: "prompt_injection" | "canary_leak" | "policy_violation" | "custom";
  reason: string;
  detected_at_ms: number;
  source_id?: string;
  detector?: string;
  trigger_event_id?: string;
}

export interface SourceLineageEnvelopeV1 {
  schema: typeof SOURCE_LINEAGE_SCHEMA_V1;
  lineage_id: string;
  derivation: LineageDerivation;
  sources: SourceReferenceV1[];
  parent_lineage_ids: string[];
  taints: LineageTaintV1[];
  lineage_hash: string;
}

export interface CreateSourceLineageV1 {
  lineage_id?: string;
  derivation?: LineageDerivation;
  sources: SourceReferenceV1[];
  parent_lineage_ids?: string[];
  taints?: LineageTaintV1[];
}

interface MutableLineageState {
  envelope: SourceLineageEnvelopeV1;
}

const storage = new AsyncLocalStorage<MutableLineageState>();

function fail(message: string): never {
  throw new TypeError(`Invalid source lineage: ${message}`);
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function compareUnicodeScalars(left: string, right: string): number {
  const a = Array.from(left, (character) => character.codePointAt(0) as number);
  const b = Array.from(right, (character) => character.codePointAt(0) as number);
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index]! - b[index]!;
  }
  return a.length - b.length;
}

function isAsciiWhitespace(character: string): boolean {
  const code = character.charCodeAt(0);
  return code === 0x20 || (code >= 0x09 && code <= 0x0d);
}

function boundedString(value: unknown, field: string, maxBytes = MAX_ID_BYTES): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || Array.from(value).every(isAsciiWhitespace)
  ) {
    fail(`${field} must be a non-empty string`);
  }
  if (hasUnpairedSurrogate(value)) fail(`${field} contains an unpaired surrogate`);
  if (Buffer.byteLength(value, "utf8") > maxBytes) {
    fail(`${field} exceeds ${maxBytes} UTF-8 bytes`);
  }
  return value;
}

function optionalString(value: unknown, field: string): string | undefined {
  return value === undefined || value === null
    ? undefined
    : boundedString(value, field);
}

function uniqueSorted(values: string[], field: string, max: number): string[] {
  if (values.length > max) fail(`${field} exceeds ${max} entries`);
  const normalized = values.map((value, index) => boundedString(value, `${field}[${index}]`));
  if (new Set(normalized).size !== normalized.length) fail(`${field} contains duplicates`);
  return normalized.sort(compareUnicodeScalars);
}

function normalizeSource(value: SourceReferenceV1, index: number): SourceReferenceV1 {
  if (!value || typeof value !== "object") fail(`sources[${index}] must be an object`);
  const allowedKinds = new Set<SourceKind>([
    "document", "retrieval", "tool_result", "memory", "user_input", "other",
  ]);
  if (!allowedKinds.has(value.source_kind)) fail(`sources[${index}].source_kind is unsupported`);
  const source_hash = optionalString(value.source_hash, `sources[${index}].source_hash`);
  const source_version = optionalString(value.source_version, `sources[${index}].source_version`);
  const chunk_id = optionalString(value.chunk_id, `sources[${index}].chunk_id`);
  const retrieval_id = optionalString(value.retrieval_id, `sources[${index}].retrieval_id`);
  if (source_hash !== undefined && !SHA256_RE.test(source_hash)) {
    fail(`sources[${index}].source_hash must be lowercase SHA-256 hex`);
  }
  return {
    source_id: boundedString(value.source_id, `sources[${index}].source_id`),
    source_kind: value.source_kind,
    ...(source_hash ? { source_hash } : {}),
    ...(source_version ? { source_version } : {}),
    ...(chunk_id ? { chunk_id } : {}),
    ...(retrieval_id ? { retrieval_id } : {}),
  };
}

function normalizeTaint(value: LineageTaintV1, index: number): LineageTaintV1 {
  if (!value || typeof value !== "object") fail(`taints[${index}] must be an object`);
  const allowedKinds = new Set<LineageTaintV1["kind"]>([
    "prompt_injection", "canary_leak", "policy_violation", "custom",
  ]);
  if (!allowedKinds.has(value.kind)) fail(`taints[${index}].kind is unsupported`);
  if (!Number.isSafeInteger(value.detected_at_ms) || value.detected_at_ms < 0) {
    fail(`taints[${index}].detected_at_ms must be a non-negative safe integer`);
  }
  const source_id = optionalString(value.source_id, `taints[${index}].source_id`);
  const detector = optionalString(value.detector, `taints[${index}].detector`);
  const trigger_event_id = optionalString(
    value.trigger_event_id,
    `taints[${index}].trigger_event_id`,
  );
  return {
    taint_id: boundedString(value.taint_id, `taints[${index}].taint_id`),
    kind: value.kind,
    reason: boundedString(value.reason, `taints[${index}].reason`, MAX_REASON_BYTES),
    detected_at_ms: value.detected_at_ms,
    ...(source_id ? { source_id } : {}),
    ...(detector ? { detector } : {}),
    ...(trigger_event_id ? { trigger_event_id } : {}),
  };
}

function bodyOf(envelope: Omit<SourceLineageEnvelopeV1, "lineage_hash">): Omit<SourceLineageEnvelopeV1, "lineage_hash"> {
  return {
    schema: SOURCE_LINEAGE_SCHEMA_V1,
    lineage_id: envelope.lineage_id,
    derivation: envelope.derivation,
    sources: envelope.sources,
    parent_lineage_ids: envelope.parent_lineage_ids,
    taints: envelope.taints,
  };
}

export function sourceLineageHash(
  envelope: Omit<SourceLineageEnvelopeV1, "lineage_hash">,
): string {
  const canonical = canonicalJsonForHash(bodyOf(envelope));
  return createHash("sha256")
    .update(SOURCE_LINEAGE_HASH_DOMAIN)
    .update(Buffer.from([0]))
    .update(canonical, "utf8")
    .digest("hex");
}

export function createSourceLineage(
  input: CreateSourceLineageV1,
): SourceLineageEnvelopeV1 {
  if (!input || typeof input !== "object") fail("input must be an object");
  if (!Array.isArray(input.sources) || input.sources.length === 0) {
    fail("sources must contain at least one source");
  }
  if (input.sources.length > MAX_SOURCES) fail(`sources exceeds ${MAX_SOURCES} entries`);
  const derivations = new Set<LineageDerivation>([
    "direct", "retrieved", "generated", "summarized", "tool_result",
    "handoff", "merged", "unknown",
  ]);
  const derivation = input.derivation ?? "direct";
  if (!derivations.has(derivation)) fail("derivation is unsupported");
  const sources = input.sources.map(normalizeSource).sort((a, b) => {
    const left = canonicalJsonForHash(a);
    const right = canonicalJsonForHash(b);
    return compareUnicodeScalars(left, right);
  });
  if (new Set(sources.map((source) => canonicalJsonForHash(source))).size !== sources.length) {
    fail("sources contains duplicates");
  }
  const taints = (input.taints ?? []).map(normalizeTaint)
    .sort((a, b) => compareUnicodeScalars(a.taint_id, b.taint_id));
  if (taints.length > MAX_TAINTS) fail(`taints exceeds ${MAX_TAINTS} entries`);
  if (new Set(taints.map((taint) => taint.taint_id)).size !== taints.length) {
    fail("taints contains duplicate taint_id values");
  }
  const body = bodyOf({
    schema: SOURCE_LINEAGE_SCHEMA_V1,
    lineage_id: boundedString(input.lineage_id ?? randomUUID(), "lineage_id"),
    derivation,
    sources,
    parent_lineage_ids: uniqueSorted(input.parent_lineage_ids ?? [], "parent_lineage_ids", MAX_PARENTS),
    taints,
  });
  if (Buffer.byteLength(canonicalJsonForHash(body), "utf8") > MAX_ENVELOPE_BYTES) {
    fail(`canonical envelope exceeds ${MAX_ENVELOPE_BYTES} UTF-8 bytes`);
  }
  return { ...body, lineage_hash: sourceLineageHash(body) };
}

export function validateSourceLineage(
  value: SourceLineageEnvelopeV1,
): SourceLineageEnvelopeV1 {
  if (!value || value.schema !== SOURCE_LINEAGE_SCHEMA_V1) fail("schema is unsupported");
  const rebuilt = createSourceLineage(value);
  if (!SHA256_RE.test(value.lineage_hash) || rebuilt.lineage_hash !== value.lineage_hash) {
    fail("lineage_hash does not match the canonical envelope");
  }
  return rebuilt;
}

function cloneEnvelope(value: SourceLineageEnvelopeV1): SourceLineageEnvelopeV1 {
  return {
    ...value,
    sources: value.sources.map((source) => ({ ...source })),
    parent_lineage_ids: [...value.parent_lineage_ids],
    taints: value.taints.map((taint) => ({ ...taint })),
  };
}

export function currentSourceLineage(): SourceLineageEnvelopeV1 | undefined {
  const state = storage.getStore();
  if (!state) return undefined;
  state.envelope.lineage_hash = sourceLineageHash(state.envelope);
  return cloneEnvelope(state.envelope);
}

export function withSourceLineage<T>(
  lineage: CreateSourceLineageV1 | SourceLineageEnvelopeV1,
  fn: () => T,
): T {
  const envelope = "lineage_hash" in lineage
    ? validateSourceLineage(lineage)
    : createSourceLineage(lineage);
  return storage.run({ envelope: cloneEnvelope(envelope) }, fn);
}

export function deriveSourceLineage(
  options: { derivation?: LineageDerivation; lineage_id?: string } = {},
): SourceLineageEnvelopeV1 {
  const parent = currentSourceLineage();
  if (!parent) fail("deriveSourceLineage requires an active source-lineage scope");
  return createSourceLineage({
    lineage_id: options.lineage_id,
    derivation: options.derivation ?? "handoff",
    sources: parent.sources,
    parent_lineage_ids: [parent.lineage_id],
    taints: parent.taints,
  });
}

export function markCurrentLineageTainted(
  input: Omit<LineageTaintV1, "taint_id" | "detected_at_ms"> & {
    taint_id?: string;
    detected_at_ms?: number;
  },
): LineageTaintV1 | undefined {
  const state = storage.getStore();
  if (!state) return undefined;
  const effectiveSourceId = input.source_id
    ?? (state.envelope.sources.length === 1 ? state.envelope.sources[0]?.source_id : undefined);
  const existing = state.envelope.taints.find((taint) =>
    taint.kind === input.kind
      && taint.reason === input.reason
      && taint.source_id === effectiveSourceId,
  );
  if (existing) return { ...existing };
  if (state.envelope.taints.length >= MAX_TAINTS) fail(`taints exceeds ${MAX_TAINTS} entries`);
  const taint = normalizeTaint({
    ...input,
    source_id: effectiveSourceId,
    taint_id: input.taint_id ?? randomUUID(),
    detected_at_ms: input.detected_at_ms ?? Date.now(),
  }, state.envelope.taints.length);
  state.envelope.taints.push(taint);
  state.envelope.taints.sort((a, b) => compareUnicodeScalars(a.taint_id, b.taint_id));
  state.envelope.lineage_hash = sourceLineageHash(state.envelope);
  return { ...taint };
}

/** Stamp the active, validated envelope on an event. Ambient lineage wins over
 * a raw metadata key; cross-process callers must re-bind a validated envelope
 * with withSourceLineage rather than injecting unvalidated metadata. */
export function withSourceLineageMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  const lineage = currentSourceLineage();
  if (!lineage) return metadata;
  return { ...(metadata ?? {}), [SOURCE_LINEAGE_METADATA_KEY]: lineage };
}

/** Validate a carried envelope and return the hash that format 5 must seal. */
export function sourceLineageHashFromMetadata(
  metadata: Record<string, unknown> | undefined,
): string | undefined {
  const value = metadata?.[SOURCE_LINEAGE_METADATA_KEY];
  if (value === undefined) return undefined;
  return validateSourceLineage(value as SourceLineageEnvelopeV1).lineage_hash;
}
