/**
 * Small helpers for the agent tests: env-key gating + lazy optional imports.
 */
export function checkEnv(...vars) {
  const missing = vars.filter((v) => !process.env[v] || !process.env[v].trim());
  return { ok: missing.length === 0, missing };
}

export function skip(reason) {
  return [{ check: "preconditions", status: "skip", detail: reason }];
}

export async function tryImport(spec) {
  try {
    return await import(spec);
  } catch {
    return null;
  }
}
