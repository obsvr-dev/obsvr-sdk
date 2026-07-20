/**
 * Tests for model_gate (Model Routing) and token-unit quota (Cost Governance).
 * These close the two website claims that previously had no implementation.
 */
import { evaluatePolicyRules, type PolicyRule } from "../../src/policy/rules";
import {
  checkTokenBudget,
  recordTokenUsage,
  _resetAllQuotas,
} from "../../src/governance/quota";

beforeEach(() => _resetAllQuotas());

function rule(overrides: Partial<PolicyRule>): PolicyRule {
  return {
    id: "r1",
    name: "test",
    enabled: true,
    action: "block",
    type: "model_gate",
    conditions: {},
    ...overrides,
  } as PolicyRule;
}

describe("model_gate", () => {
  it("blocks a model not on the allowlist", () => {
    const r = rule({ conditions: { allowed_models: ["gpt-4o", "claude-sonnet-5"] } });
    const result = evaluatePolicyRules([r], "hi", "prompt", { model: "gpt-3.5-turbo" });
    expect(result.decision).toBe("block");
    expect(result.rule_id).toBe("r1");
  });

  it("allows a model on the allowlist (exact)", () => {
    const r = rule({ conditions: { allowed_models: ["gpt-4o"] } });
    expect(
      evaluatePolicyRules([r], "hi", "prompt", { model: "gpt-4o" }).decision,
    ).toBe("allow");
  });

  it("allowlist supports prefix matching (gpt-4 covers gpt-4o)", () => {
    const r = rule({ conditions: { allowed_models: ["gpt-4"] } });
    expect(
      evaluatePolicyRules([r], "hi", "prompt", { model: "gpt-4o" }).decision,
    ).toBe("allow");
  });

  it("denied model is blocked even when also allowed (deny wins)", () => {
    const r = rule({
      conditions: { allowed_models: ["gpt-4o"], denied_models: ["gpt-4o"] },
    });
    expect(
      evaluatePolicyRules([r], "hi", "prompt", { model: "gpt-4o" }).decision,
    ).toBe("block");
  });

  it("provider allowlist blocks unlisted providers", () => {
    const r = rule({ conditions: { allowed_providers: ["openai", "anthropic"] } });
    expect(
      evaluatePolicyRules([r], "hi", "prompt", { provider: "google", model: "gemini-2.5-flash" }).decision,
    ).toBe("block");
    expect(
      evaluatePolicyRules([r], "hi", "prompt", { provider: "openai", model: "gpt-4o" }).decision,
    ).toBe("allow");
  });

  it("never fires without model/provider context (backward compatible)", () => {
    const r = rule({ conditions: { allowed_models: ["gpt-4o"] } });
    expect(evaluatePolicyRules([r], "hi").decision).toBe("allow");
  });

  it("matching is case-insensitive", () => {
    const r = rule({ conditions: { denied_models: ["GPT-4o"] } });
    expect(
      evaluatePolicyRules([r], "hi", "prompt", { model: "gpt-4O" }).decision,
    ).toBe("block");
  });
});

describe("token-unit quota (Cost Governance)", () => {
  const budgetRule = rule({
    type: "quota",
    conditions: {
      quota_limit: 1000,
      quota_window_ms: 60_000,
      quota_scope: "user_id",
      quota_unit: "tokens",
    },
  });

  it("allows while under budget", () => {
    const result = evaluatePolicyRules([budgetRule], "hi", "prompt", {
      metadata: { user_id: "u1" },
    });
    expect(result.decision).toBe("allow");
  });

  it("blocks after recorded usage exceeds the budget", () => {
    recordTokenUsage("user_id", "u1", 600, 60_000);
    recordTokenUsage("user_id", "u1", 500, 60_000); // total 1100 > 1000
    const result = evaluatePolicyRules([budgetRule], "hi", "prompt", {
      metadata: { user_id: "u1" },
    });
    expect(result.decision).toBe("block");
    expect(result.reason).toContain("Quota exceeded");
  });

  it("budgets are per-scope-value", () => {
    recordTokenUsage("user_id", "u1", 2000, 60_000);
    const other = evaluatePolicyRules([budgetRule], "hi", "prompt", {
      metadata: { user_id: "u2" },
    });
    expect(other.decision).toBe("allow");
  });

  it("checkTokenBudget does not consume budget (pre-call check only)", () => {
    checkTokenBudget("user_id", "u1", 1000, 60_000);
    checkTokenBudget("user_id", "u1", 1000, 60_000);
    const status = checkTokenBudget("user_id", "u1", 1000, 60_000);
    expect(status.allowed).toBe(true);
    expect(status.remaining).toBe(1000); // untouched by checks
  });

  it("window expiry resets the budget", async () => {
    recordTokenUsage("user_id", "u1", 5000, 10); // 10ms window
    await new Promise((r) => setTimeout(r, 25));
    const status = checkTokenBudget("user_id", "u1", 1000, 10);
    expect(status.allowed).toBe(true);
  });

  it("request-unit quota unchanged (regression)", () => {
    const requests = rule({
      type: "quota",
      action: "block",
      conditions: { quota_limit: 2, quota_window_ms: 60_000, quota_scope: "user_id" },
    });
    const ctx = { metadata: { user_id: "u9" } };
    expect(evaluatePolicyRules([requests], "x", "prompt", ctx).decision).toBe("allow");
    expect(evaluatePolicyRules([requests], "x", "prompt", ctx).decision).toBe("allow");
    expect(evaluatePolicyRules([requests], "x", "prompt", ctx).decision).toBe("block");
  });
});
