import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';
import {
  verifyStrictReceiptV21Chain,
  type StrictReceiptV21TrustOptions,
} from './strict-receipt-v2-1-verify.js';

export const STRICT_POLICY_CONTINUITY_V21_SCHEMA = 'obsvr-strict-policy-continuity-v2-1' as const;

export interface StrictPolicySnapshotV21 {
  sequence: number;
  receipt_hash: string;
  record_type: 'decision' | 'resolution';
  policy_version: string;
  policy_artifact_hash: string;
  evaluator_manifest_hash: string;
  matched_rule_ids: string[];
}

export interface StrictPolicyTransitionV21 {
  at_sequence: number;
  receipt_hash: string;
  from_policy_version: string;
  from_policy_artifact_hash: string;
  from_evaluator_manifest_hash: string;
  to_policy_version: string;
  to_policy_artifact_hash: string;
  to_evaluator_manifest_hash: string;
}

export interface StrictPolicyContinuityV21 {
  schema: typeof STRICT_POLICY_CONTINUITY_V21_SCHEMA;
  profile_version: '2.1';
  tenant_id: string;
  session_id: string;
  first_sequence: number;
  last_sequence: number;
  receipt_count: number;
  snapshots: StrictPolicySnapshotV21[];
  transitions: StrictPolicyTransitionV21[];
  timeline_hash: string;
}

export class StrictPolicyContinuityV21Error extends Error {
  constructor(public readonly errors: string[]) {
    super(`strict policy continuity requires a valid trusted chain: ${errors.join(', ')}`);
    this.name = 'StrictPolicyContinuityV21Error';
  }
}

function snapshot(receipt: StrictReceiptV21Envelope): StrictPolicySnapshotV21 {
  const policy = receipt.body.evaluation.effective_policy;
  return {
    sequence: receipt.body.sequence,
    receipt_hash: receipt.receipt_hash,
    record_type: receipt.body.record_type,
    policy_version: policy.version,
    policy_artifact_hash: policy.artifact_hash,
    evaluator_manifest_hash: receipt.body.evaluation.evaluator_manifest_hash,
    matched_rule_ids: [...policy.matched_rule_ids],
  };
}

function changed(left: StrictPolicySnapshotV21, right: StrictPolicySnapshotV21): boolean {
  return left.policy_version !== right.policy_version
    || left.policy_artifact_hash !== right.policy_artifact_hash
    || left.evaluator_manifest_hash !== right.evaluator_manifest_hash;
}

export function reconstructStrictPolicyContinuityV21(
  receipts: readonly StrictReceiptV21Envelope[],
  trust: StrictReceiptV21TrustOptions,
): StrictPolicyContinuityV21 {
  const verification = verifyStrictReceiptV21Chain(receipts, trust);
  if (!verification.valid) throw new StrictPolicyContinuityV21Error(verification.errors);
  const snapshots = receipts.map((receipt) => snapshot(receipt));
  const transitions: StrictPolicyTransitionV21[] = [];
  for (let index = 1; index < snapshots.length; index += 1) {
    const before = snapshots[index - 1];
    const after = snapshots[index];
    if (!changed(before, after)) continue;
    transitions.push({
      at_sequence: after.sequence,
      receipt_hash: after.receipt_hash,
      from_policy_version: before.policy_version,
      from_policy_artifact_hash: before.policy_artifact_hash,
      from_evaluator_manifest_hash: before.evaluator_manifest_hash,
      to_policy_version: after.policy_version,
      to_policy_artifact_hash: after.policy_artifact_hash,
      to_evaluator_manifest_hash: after.evaluator_manifest_hash,
    });
  }
  const document = {
    schema: STRICT_POLICY_CONTINUITY_V21_SCHEMA,
    profile_version: '2.1' as const,
    tenant_id: receipts[0].body.tenant_id,
    session_id: receipts[0].body.session_id,
    first_sequence: snapshots[0].sequence,
    last_sequence: snapshots.at(-1)!.sequence,
    receipt_count: snapshots.length,
    snapshots,
    transitions,
  };
  return {
    ...document,
    timeline_hash: createHash('sha256').update(canonicalJsonForHash(document)).digest('hex'),
  };
}
