import type { DeviceSigner } from '../proxy/device-identity.js';
import type {
  IntentAlignmentResult, IntentBaseResult, IntentPolicyInput,
} from '../policy/intent-alignment.js';
import type { ActionContextInput } from './action-context.js';
import type { StrictReceiptBody, StrictReceiptEnvelope } from './strict-receipt.js';
import type { StrictApprovalVerifier } from './strict-receipt-coordinator-support.js';
import type { PreparedReceiptView } from './strict-receipt-prepared-state.js';

type ResolutionMethod = NonNullable<StrictReceiptBody['resolution']>['method'];

export type StrictCoordinatorContextInput = Omit<
  ActionContextInput, 'prior_actions' | 'session_id'
>;

export interface StrictReceiptCoordinatorOptions {
  signer: DeviceSigner;
  policy: IntentPolicyInput;
  sdk_language: 'typescript';
  sdk_version: string;
  session_id: string;
  clock: () => number;
  defer_ttl_ms: number;
  approval_verifier: StrictApprovalVerifier;
  include_public_key?: boolean;
  pid?: () => number;
  session_factory?: () => string;
  prepared_token_factory?: () => string;
}

export interface StrictDecisionInput {
  context: StrictCoordinatorContextInput;
  base_result: IntentBaseResult;
  policy_version: string;
  rule_ids: string[];
  action_id: string;
}

export interface StrictDecisionResult {
  evaluation: IntentAlignmentResult;
  receipt: StrictReceiptEnvelope;
}

export interface StrictResolutionInput {
  suspended_receipt_hash: string;
  method: ResolutionMethod;
  resolver_principal_id?: string;
  resolution_source_hash?: string;
  context: StrictCoordinatorContextInput;
  base_result: IntentBaseResult;
  policy_version: string;
  rule_ids: string[];
  approval_evidence?: unknown;
}

export interface StrictTimeoutInput {
  suspended_receipt_hash: string;
  policy_version: string;
  rule_ids: string[];
}

export type PreparedDecision = PreparedReceiptView<StrictDecisionResult>;
export type PreparedResolution = PreparedReceiptView<StrictReceiptEnvelope>;

export interface StrictCoordinatorStateInspection {
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
