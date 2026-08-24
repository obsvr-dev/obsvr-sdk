import type { DeviceSigner } from '../proxy/device-identity.js';
import type {
  IntentAlignmentV2Result, IntentPolicyV2Input, IntentV2BaseResult,
} from '../policy/intent-alignment-v2.js';
import type { ActionContextV2Input } from './action-context-v2.js';
import type { StrictReceiptV2Body, StrictReceiptV2Envelope } from './strict-receipt-v2.js';
import type { StrictApprovalVerifier } from './strict-receipt-coordinator-support.js';
import type { PreparedReceiptView } from './strict-receipt-prepared-state.js';

export type StrictCoordinatorV2ContextInput = Omit<
  ActionContextV2Input, 'prior_actions' | 'session_id'
>;
export type StrictResolutionV2Method = NonNullable<StrictReceiptV2Body['resolution']>['method'];

export interface StrictReceiptCoordinatorV2Options {
  signer: DeviceSigner;
  policy: IntentPolicyV2Input;
  sdk_language: 'typescript';
  sdk_version: string;
  tenant_id: string;
  session_id: string;
  clock: () => number;
  defer_ttl_ms: number;
  approval_verifier: StrictApprovalVerifier;
  include_public_key?: boolean;
  pid?: () => number;
  prepared_token_factory?: () => string;
}

export interface StrictDecisionV2Input {
  context: StrictCoordinatorV2ContextInput;
  base_result: IntentV2BaseResult;
  policy_version: string;
  rule_ids: string[];
  action_id: string;
}

export interface StrictDecisionV2Result {
  evaluation: IntentAlignmentV2Result;
  receipt: StrictReceiptV2Envelope;
}

export interface StrictResolutionV2Input {
  suspended_receipt_hash: string;
  method: Exclude<StrictResolutionV2Method, 'expired'>;
  resolver_principal_id?: string;
  resolution_source_hash?: string;
  context: StrictCoordinatorV2ContextInput;
  base_result: IntentV2BaseResult;
  policy_version: string;
  rule_ids: string[];
  approval_evidence?: unknown;
}

export interface StrictTimeoutV2Input {
  suspended_receipt_hash: string;
  policy_version: string;
  rule_ids: string[];
}

export type PreparedDecisionV2 = PreparedReceiptView<StrictDecisionV2Result>;
export type PreparedResolutionV2 = PreparedReceiptView<StrictReceiptV2Envelope>;

export interface StrictCoordinatorV2StateInspection {
  tenant_id: string;
  session_id: string;
  sequence: number;
  head_receipt_hash: string | null;
  frozen: boolean;
  freeze_reason?: string;
  prepared?: {
    token: string;
    receipt_hash: string;
    kind: 'decision' | 'resolution' | 'timeout';
  };
}
