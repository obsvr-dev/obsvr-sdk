export const DEFINITIVE_NO_STORE = Object.freeze({
  status: 'definitive_no_store' as const,
});

export type DefinitiveNoStore = typeof DEFINITIVE_NO_STORE;
export type PreparedReceiptKind = 'decision' | 'resolution' | 'timeout';

export interface PreparedReceiptView<T> {
  token: string;
  receipt_hash: string;
  kind: PreparedReceiptKind;
  value: T;
}

interface PreparedReceipt<T> extends PreparedReceiptView<T> {
  fingerprint: string;
  commit: () => void;
}

export interface PreparedStateInspection {
  frozen: boolean;
  freeze_reason?: string;
  prepared?: Omit<PreparedReceiptView<unknown>, 'value'>;
}

export type PreparedReconciliation =
  | { status: 'stored'; token: string; receipt_hash: string }
  | { status: 'definitive_no_store'; token: string; receipt_hash: string;
    capability: DefinitiveNoStore }
  | { status: 'ambiguous'; token: string; receipt_hash: string; reason: string };

export class PreparedReceiptState {
  private prepared: PreparedReceipt<unknown> | undefined;
  private frozenReason: string | undefined;

  constructor(private readonly tokenFactory: () => string) {}

  retry<T>(
    fingerprint: string, kind: PreparedReceiptKind,
  ): PreparedReceiptView<T> | undefined {
    this.assertNotFrozen();
    if (!this.prepared) return undefined;
    if (this.prepared.fingerprint !== fingerprint || this.prepared.kind !== kind) {
      throw new Error('a different receipt is already prepared for this session');
    }
    return this.view(this.prepared as PreparedReceipt<T>);
  }

  prepare<T>(params: {
    fingerprint: string; receipt_hash: string; kind: PreparedReceiptKind;
    value: T; commit: () => void;
  }): PreparedReceiptView<T> {
    this.assertNotFrozen();
    if (this.prepared) throw new Error('a receipt is already prepared for this session');
    const token = this.tokenFactory();
    if (typeof token !== 'string' || token.trim().length === 0) {
      throw new Error('prepared token factory must return a nonblank string');
    }
    this.prepared = { token, ...params };
    return this.view(this.prepared as PreparedReceipt<T>);
  }

  commit<T>(token: string, receiptHash: string): T {
    const prepared = this.match(token, receiptHash);
    try {
      prepared.commit();
    } catch (error) {
      this.frozenReason = 'accepted_but_local_commit_failed';
      throw error;
    }
    this.prepared = undefined;
    this.frozenReason = undefined;
    return prepared.value as T;
  }

  abort(token: string, receiptHash: string, capability: DefinitiveNoStore): void {
    if (capability !== DEFINITIVE_NO_STORE) {
      throw new Error('abort requires the definitive_no_store capability');
    }
    this.match(token, receiptHash);
    this.prepared = undefined;
    this.frozenReason = undefined;
  }

  freeze(token: string, receiptHash: string, reason: string): void {
    this.match(token, receiptHash);
    if (typeof reason !== 'string' || reason.trim().length === 0) {
      throw new Error('freeze reason must be nonblank');
    }
    this.frozenReason = reason;
  }

  reconcile<T>(input: PreparedReconciliation): T | undefined {
    if (input.status === 'stored') return this.commit<T>(input.token, input.receipt_hash);
    if (input.status === 'definitive_no_store') {
      this.abort(input.token, input.receipt_hash, input.capability);
      return undefined;
    }
    this.freeze(input.token, input.receipt_hash, input.reason);
    return undefined;
  }

  inspect(): PreparedStateInspection {
    return {
      frozen: this.frozenReason !== undefined,
      ...(this.frozenReason === undefined ? {} : { freeze_reason: this.frozenReason }),
      ...(this.prepared === undefined ? {} : {
        prepared: {
          token: this.prepared.token, receipt_hash: this.prepared.receipt_hash,
          kind: this.prepared.kind,
        },
      }),
    };
  }

  reset(): void {
    this.prepared = undefined;
    this.frozenReason = undefined;
  }

  private assertNotFrozen(): void {
    if (this.frozenReason !== undefined) {
      throw new Error('strict receipt session is frozen pending reconciliation');
    }
  }

  private match(token: string, receiptHash: string): PreparedReceipt<unknown> {
    if (!this.prepared) throw new Error('no receipt is prepared');
    if (token !== this.prepared.token) throw new Error('prepared token mismatch');
    if (receiptHash !== this.prepared.receipt_hash) {
      throw new Error('prepared receipt hash mismatch');
    }
    return this.prepared;
  }

  private view<T>(prepared: PreparedReceipt<T>): PreparedReceiptView<T> {
    return {
      token: prepared.token, receipt_hash: prepared.receipt_hash,
      kind: prepared.kind, value: prepared.value,
    };
  }
}
