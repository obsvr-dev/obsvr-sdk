/** Runtime smoke check for a caller-owned governed factory. */

export interface EnforcementBoundarySmokeInput {
  name: string;
  invokeBlockedCall: () => unknown | Promise<unknown>;
  transportCalls: () => number;
}

export interface EnforcementBoundarySmokeResult {
  name: string;
  blocked: true;
  transport_calls: 0;
}

/**
 * Execute one caller-selected deny case and require zero downstream calls.
 * This proves the supplied factory path, not every handle in the process.
 */
export async function assertEnforcementBoundary(
  input: EnforcementBoundarySmokeInput,
): Promise<EnforcementBoundarySmokeResult> {
  if (!input || typeof input.name !== 'string' || input.name.trim() === '') {
    throw new TypeError('enforcement smoke name must be nonblank');
  }
  if (typeof input.invokeBlockedCall !== 'function' || typeof input.transportCalls !== 'function') {
    throw new TypeError('enforcement smoke requires invokeBlockedCall and transportCalls');
  }
  const before = input.transportCalls();
  let blocked = false;
  try {
    await input.invokeBlockedCall();
  } catch {
    blocked = true;
  }
  const after = input.transportCalls();
  if (after !== before) {
    throw new Error(
      `${input.name} enforcement smoke reached downstream transport ` +
      `(${after - before} call(s))`,
    );
  }
  if (!blocked) {
    throw new Error(`${input.name} enforcement smoke did not reject the deny case`);
  }
  return { name: input.name.trim(), blocked: true, transport_calls: 0 };
}
