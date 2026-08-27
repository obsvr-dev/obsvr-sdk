import type { DeviceSigner } from '../proxy/device-identity.js';
import type {
  IntentPolicyV2Input,
  IntentV2BaseResult,
} from '../policy/intent-alignment-v2.js';
import type { ActionContextV2Document } from './action-context-v2.js';
import type {
  StrictIdentityEvidenceV21Authority,
  StrictIdentityEvidenceV21Input,
} from './strict-identity-evidence-v2-1.js';
import type {
  StrictEvaluationEvidenceV21,
  TrustedEvaluationEvidenceProviderV21,
} from './strict-evaluation-evidence-v2-1.js';
import type {
  StrictReceiptV21Envelope,
} from './strict-receipt-v2-1.js';
import type { PreparedReceiptView } from './strict-receipt-prepared-state.js';
import type { StrictApprovalVerifier } from './strict-receipt-coordinator-support.js';

export interface StrictDecisionActionV21Input {
  action_id: string;
  active_intents: string[];
  current_action: {
    kind: string;
    name: string;
    arguments_hash: string;
    target_hash: string;
    data_classifications: string[];
    requested_scopes: string[];
  };
  run_id: string;
  thread_id?: string;
}

export interface TrustedIntentDecisionProviderV21 {
  evaluate(context: ActionContextV2Document): IntentV2BaseResult;
}

export interface StrictReceiptCoordinatorV21Options {
  signer: DeviceSigner;
  policy: IntentPolicyV2Input;
  tenant_id: string;
  session_id: string;
  sdk_language: 'typescript';
  clock: () => number;
  defer_ttl_ms: number;
  identity_authority: StrictIdentityEvidenceV21Authority;
  identity_snapshot: (receiptTimeMs: number) => StrictIdentityEvidenceV21Input;
  intent_decision_provider: TrustedIntentDecisionProviderV21;
  evaluation_evidence_provider: TrustedEvaluationEvidenceProviderV21;
  approval_verifier?: StrictApprovalVerifier;
  pid?: () => number;
  prepared_token_factory?: () => string;
}

export interface StrictDecisionV21Result {
  action_context: ActionContextV2Document;
  intent_evaluation: {
    outcome: 'ALLOW' | 'DENY' | 'MODIFY' | 'STEP_UP' | 'DEFER';
    reason_code: string;
    context_hash: string;
    policy_hash: string;
  };
  evaluation_evidence: StrictEvaluationEvidenceV21;
  receipt: StrictReceiptV21Envelope;
}

export type PreparedDecisionV21 = PreparedReceiptView<StrictDecisionV21Result>;

export interface StrictApprovalResolutionV21Input {
  suspended_receipt_hash: string;
  method: 'approval_granted' | 'approval_denied';
  approval_evidence: unknown;
}

export type PreparedApprovalResolutionV21 = PreparedReceiptView<StrictReceiptV21Envelope>;

export interface StrictCoordinatorV21StateInspection {
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
