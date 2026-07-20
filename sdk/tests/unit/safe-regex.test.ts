/**
 * Security regression tests: ReDoS guard for customer-supplied regex rules.
 */
import {
  validateRegexPattern,
  compileSafeRegex,
  safeRegexTest,
} from "../../src/utils/safe-regex";
import { evaluatePolicyRules, type PolicyRule } from "../../src/policy/rules";

describe("validateRegexPattern", () => {
  it("accepts simple safe patterns", () => {
    expect(validateRegexPattern("\\bwire transfer\\b").ok).toBe(true);
    expect(validateRegexPattern("^user_[0-9]{4}$").ok).toBe(true);
    expect(validateRegexPattern("credit\\s?card").ok).toBe(true);
  });

  it("rejects the classic nested quantifier (a+)+", () => {
    const r = validateRegexPattern("(a+)+$");
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("nested_quantifier");
  });

  it("rejects (a*)* and quantified character-class groups", () => {
    expect(validateRegexPattern("(a*)*").ok).toBe(false);
    expect(validateRegexPattern("([a-z]+)+").ok).toBe(false);
    expect(validateRegexPattern("([0-9]*){2,}").ok).toBe(false);
  });

  it("rejects brace-quantifier nesting the old [+*]-only regex missed", () => {
    // These passed the prior static check and could hang the thread for minutes
    // (the 50 KB input cap does not tame super-linear backtracking).
    expect(validateRegexPattern("(a{2,})+$").reason).toBe("nested_quantifier");
    expect(validateRegexPattern("(\\d{2,})+$").reason).toBe("nested_quantifier");
    expect(validateRegexPattern("([a-z]{3,})*$").reason).toBe("nested_quantifier");
    // Nested one paren deeper and non-capturing groups.
    expect(validateRegexPattern("((a+)b?)+$").reason).toBe("nested_quantifier");
    expect(validateRegexPattern("(?:a+)+").reason).toBe("nested_quantifier");
  });

  it("does not over-reject fixed-count or un-nested quantifiers", () => {
    expect(validateRegexPattern("(a{3})+").ok).toBe(true); // fixed inner {n} does not grow
    expect(validateRegexPattern("(abc)+").ok).toBe(true); // single quantifier on a group
    expect(validateRegexPattern("[+*]{1,5}").ok).toBe(true); // + and * are literals in the class
    expect(validateRegexPattern("\\d{3}-\\d{2}-\\d{4}").ok).toBe(true);
  });

  it("rejects quantified alternation (a|aa)+", () => {
    const r = validateRegexPattern("(a|aa)+");
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("quantified_alternation");
  });

  it("rejects WRAPPED quantified alternation the shallow regex missed", () => {
    // ((a|aa))+ hid the alternation one paren deeper, so the quantifier no
    // longer touched the alternation's own ')' and QUANTIFIED_ALTERNATION did
    // not fire — yet it backtracks exponentially just like (a|aa)+. The
    // structural scan now catches it (via the group's alternation flag).
    expect(validateRegexPattern("((a|aa))+$").ok).toBe(false);
    expect(validateRegexPattern("((a|aa))+$").reason).toBe("nested_quantifier");
    expect(validateRegexPattern("((x|xx|xxx))*").ok).toBe(false);
    expect(validateRegexPattern("(?:(a|ab))+").ok).toBe(false);
    // A quantified group whose alternation sits deeper still, plus a non-growth
    // wrapper, must not slip through.
    expect(validateRegexPattern("(z(a|aa))+").ok).toBe(false);
    // Un-quantified alternation nesting is fine — no growth quantifier on it.
    expect(validateRegexPattern("((a|aa))").ok).toBe(true);
    expect(validateRegexPattern("(foo|bar|baz)").ok).toBe(true);
  });

  it("rejects backreferences", () => {
    const r = validateRegexPattern("(a)\\1+");
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("backreferences_not_allowed");
  });

  it("rejects invalid syntax", () => {
    expect(validateRegexPattern("([unclosed").ok).toBe(false);
  });

  it("rejects empty and oversized patterns", () => {
    expect(validateRegexPattern("").ok).toBe(false);
    expect(validateRegexPattern("a".repeat(600)).ok).toBe(false);
  });

  it("rejects patterns with too many quantifiers", () => {
    const pattern = Array.from({ length: 25 }, (_, i) => `a${i}+`).join("");
    expect(validateRegexPattern(pattern).ok).toBe(false);
  });
});

describe("compileSafeRegex", () => {
  it("returns a usable RegExp for safe patterns", () => {
    const re = compileSafeRegex("hello\\s+world");
    expect(re).not.toBeNull();
    expect(re!.test("hello   world")).toBe(true);
  });

  it("returns null for dangerous patterns", () => {
    expect(compileSafeRegex("(a+)+$")).toBeNull();
  });
});

describe("safeRegexTest", () => {
  it("matches on safe patterns", () => {
    expect(safeRegexTest("secret", "this contains a secret word")).toBe(true);
    expect(safeRegexTest("secret", "nothing here")).toBe(false);
  });

  it("treats rejected patterns as no-match instead of executing them", () => {
    expect(safeRegexTest("(a+)+$", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!")).toBe(false);
  });

  it("bounds input length so large prompts cannot amplify backtracking", () => {
    const huge = "x".repeat(200_000) + "needle";
    // Pattern is safe; the match target is beyond the 50K bound — no match,
    // and the call returns quickly.
    const start = Date.now();
    expect(safeRegexTest("needle", huge)).toBe(false);
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it("completes in bounded time even for suspicious-but-passing patterns", () => {
    // a{0,10}b — passes static checks; verify bounded input keeps eval fast
    const input = "a".repeat(50_001);
    const start = Date.now();
    safeRegexTest("a{0,10}b", input);
    expect(Date.now() - start).toBeLessThan(1000);
  });
});

describe("policy rules engine with ReDoS guard", () => {
  const redosRule: PolicyRule = {
    id: "rule-redos",
    name: "malicious pattern",
    enabled: true,
    action: "block",
    type: "regex",
    conditions: { pattern: "(a+)+$" },
  };

  const safeRule: PolicyRule = {
    id: "rule-safe",
    name: "wire transfer",
    enabled: true,
    action: "block",
    type: "regex",
    conditions: { pattern: "wire\\s+transfer" },
  };

  it("does not freeze on a catastrophic pattern (treated as no-match)", () => {
    const evil = "a".repeat(40) + "!";
    const start = Date.now();
    const result = evaluatePolicyRules([redosRule], evil, "prompt");
    const elapsed = Date.now() - start;
    expect(result.decision).toBe("allow");
    expect(elapsed).toBeLessThan(1000);
  });

  it("still enforces safe regex rules normally", () => {
    const result = evaluatePolicyRules([safeRule], "please make a wire transfer now", "prompt");
    expect(result.decision).toBe("block");
    expect(result.rule_id).toBe("rule-safe");
  });
});
