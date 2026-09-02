import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import fc from "fast-check";
import {
  PolicyConfigurationError,
  evaluateRulebook,
  validateRulebook,
} from "../dist/policy.js";

const rulebook = JSON.parse(readFileSync(
  new URL("../rulebooks/v1/mandate-to-liability.v1.json", import.meta.url),
  "utf8",
));

const principalFacts = {
  input_state: "valid",
  evidence_state: "sufficient",
  policy_state: "active",
  trust_state: "pinned",
  mandate_state: "valid",
  receipt_state: "trusted",
  execution_state: "compliant",
  operator_controls: "compliant",
  operator_violation: "none",
  model_provenance: "missing",
  causation_state: "missing",
};

test("reference v1 rulebook validates and reaches every closed outcome", () => {
  assert.deepEqual(validateRulebook(rulebook), { valid: true, issues: [] });
  assert.equal(evaluateRulebook(rulebook, principalFacts).outcome, "principal");
  assert.equal(evaluateRulebook(rulebook, {
    ...principalFacts,
    mandate_state: "expired",
    execution_state: "noncompliant",
    operator_violation: "expired_mandate",
  }).outcome, "operator");
  assert.equal(evaluateRulebook(rulebook, {
    ...principalFacts,
    model_provenance: "matched",
    causation_state: "sufficient",
  }).outcome, "model_vendor");
  assert.equal(evaluateRulebook(rulebook, {
    ...principalFacts,
    evidence_state: "missing",
    receipt_state: "missing",
    execution_state: "missing",
  }).outcome, "unresolved");
});

test("priority is deterministic and independent of rule-array order", () => {
  const expected = evaluateRulebook(rulebook, principalFacts);
  const reversed = { ...rulebook, rules: [...rulebook.rules].reverse() };
  assert.deepEqual(evaluateRulebook(reversed, principalFacts), expected);
});

test("not is bounded, traced, and cannot resolve object paths", () => {
  const custom = {
    ...rulebook,
    artifactId: "rulebook-not-test",
    rules: [{
      id: "not-invalid",
      priority: 1,
      when: { op: "not", condition: { op: "eq", fact: "input_state", value: "invalid" } },
      outcome: "principal",
      reasonCode: "not_invalid",
    }],
  };
  const result = evaluateRulebook(custom, principalFacts);
  assert.equal(result.outcome, "principal");
  assert.equal(result.trace[0].conditions.some((condition) => condition.operator === "not"), true);

  const arbitraryPath = structuredClone(custom);
  arbitraryPath.rules[0].when.condition.fact = "payload.secret.path";
  assert.equal(validateRulebook(arbitraryPath).valid, false);
});

test("direct rulebook evaluation rejects inherited policy facts", () => {
  const inherited = Object.create(principalFacts);
  assert.throws(
    () => evaluateRulebook(rulebook, inherited),
    (error) => error instanceof PolicyConfigurationError
      && error.issues.some((issue) => issue.path === "$facts"),
  );
});

test("rejects executable, numeric, floating, unsupported, and open-ended DSL forms", () => {
  const mutations = [
    (value) => { value.rules[0].when = { op: "lt", fact: "input_state", value: 1 }; },
    (value) => { value.rules[0].when = { op: "exists", fact: "input_state" }; },
    (value) => { value.rules[0].when = { op: "eq", fact: "input_state", value: 1.5 }; },
    (value) => { value.rules[0].when = { op: "eq", fact: "input_state", value: "valid", script: "return true" }; },
    (value) => { value.rules[0].when = { op: "in", fact: "input_state", values: [] }; },
    (value) => { value.rules[0].when = { op: "all", conditions: [] }; },
  ];
  for (const mutate of mutations) {
    const hostile = structuredClone(rulebook);
    mutate(hostile);
    assert.equal(validateRulebook(hostile).valid, false);
    assert.throws(() => evaluateRulebook(hostile, principalFacts), PolicyConfigurationError);
  }
});

test("enforces rule identifiers, unique ids/priorities, and exact integer bounds", () => {
  const invalids = [];
  const negative = structuredClone(rulebook);
  negative.rules[0].priority = -1;
  invalids.push(negative);
  const huge = structuredClone(rulebook);
  huge.rules[0].priority = 1_000_001;
  invalids.push(huge);
  const duplicatePriority = structuredClone(rulebook);
  duplicatePriority.rules[1].priority = duplicatePriority.rules[0].priority;
  invalids.push(duplicatePriority);
  const duplicateId = structuredClone(rulebook);
  duplicateId.rules[1].id = duplicateId.rules[0].id;
  invalids.push(duplicateId);
  const unsafeId = structuredClone(rulebook);
  unsafeId.rules[0].id = "../unsafe";
  invalids.push(unsafeId);
  const longReason = structuredClone(rulebook);
  longReason.rules[0].reasonCode = `r${"x".repeat(128)}`;
  invalids.push(longReason);
  for (const candidate of invalids) assert.equal(validateRulebook(candidate).valid, false);
});

test("bounded recursion, group width, rule count, and duplicate values fail closed", () => {
  const deep = structuredClone(rulebook);
  let condition = { op: "eq", fact: "input_state", value: "valid" };
  for (let index = 0; index < 10; index += 1) condition = { op: "not", condition };
  deep.rules[0].when = condition;
  assert.equal(validateRulebook(deep).valid, false);

  const wide = structuredClone(rulebook);
  wide.rules[0].when = {
    op: "all",
    conditions: Array.from({ length: 33 }, () => ({ op: "eq", fact: "input_state", value: "valid" })),
  };
  assert.equal(validateRulebook(wide).valid, false);

  const many = structuredClone(rulebook);
  many.rules = Array.from({ length: 65 }, (_, index) => ({
    id: `rule-${index}`,
    priority: index,
    when: { op: "eq", fact: "input_state", value: "valid" },
    outcome: "unresolved",
    reasonCode: `reason-${index}`,
  }));
  assert.equal(validateRulebook(many).valid, false);

  const duplicates = structuredClone(rulebook);
  duplicates.rules[0].when = { op: "in", fact: "input_state", values: ["valid", "valid"] };
  assert.equal(validateRulebook(duplicates).valid, false);
});

test("fast-check: rule permutations preserve the selected outcome and reason", () => {
  fc.assert(fc.property(
    fc.shuffledSubarray(rulebook.rules, {
      minLength: rulebook.rules.length,
      maxLength: rulebook.rules.length,
    }),
    (rules) => {
      const candidate = { ...rulebook, rules };
      const expected = evaluateRulebook(rulebook, principalFacts);
      const actual = evaluateRulebook(candidate, principalFacts);
      assert.equal(actual.outcome, expected.outcome);
      assert.equal(actual.reasonCode, expected.reasonCode);
      assert.equal(actual.matchedRuleId, expected.matchedRuleId);
    },
  ), { numRuns: 50 });
});

test("validator reports every bounded root, rule, and condition shape branch", () => {
  for (const value of [null, [], "rulebook", 7]) {
    assert.equal(validateRulebook(value).valid, false);
  }
  const rootMutations = [
    (value) => { value.extra = true; },
    (value) => { value.schemaVersion = "2.0.0"; },
    (value) => { value.semanticsVersion = "other"; },
    (value) => { value.artifactId = "#bad"; },
    (value) => { value.artifactId = "bad/path"; },
    (value) => { value.revision = 0; },
    (value) => { value.revision = 1.5; },
    (value) => { value.defaultOutcome = "principal"; },
    (value) => { value.rules = []; },
    (value) => { value.rules = "not-an-array"; },
  ];
  for (const mutate of rootMutations) {
    const value = structuredClone(rulebook);
    mutate(value);
    assert.equal(validateRulebook(value).valid, false);
  }

  const conditionMutations = [
    (value) => { value.rules[0] = null; },
    (value) => { value.rules[0].outcome = "insurer"; },
    (value) => { value.rules[0].when = null; },
    (value) => { value.rules[0].when = {}; },
    (value) => { value.rules[0].when = { op: "eq", fact: "unknown", value: "valid" }; },
    (value) => { value.rules[0].when = { op: "eq", fact: "input_state", value: "unknown" }; },
    (value) => { value.rules[0].when = { op: "in", fact: "unknown", values: ["valid"] }; },
    (value) => { value.rules[0].when = { op: "in", fact: "input_state", values: ["unknown"] }; },
    (value) => { value.rules[0].when = { op: "in", fact: "input_state", values: ["valid"], extra: true }; },
    (value) => { value.rules[0].when = { op: "not", condition: { op: "eq", fact: "input_state", value: "valid" }, extra: true }; },
    (value) => { value.rules[0].when = { op: "all", conditions: [{ op: "eq", fact: "input_state", value: "valid" }], extra: true }; },
  ];
  for (const mutate of conditionMutations) {
    const value = structuredClone(rulebook);
    mutate(value);
    assert.equal(validateRulebook(value).valid, false);
  }
});

test("a valid rulebook with no match returns the fail-closed default trace", () => {
  const noMatch = {
    ...rulebook,
    artifactId: "rulebook-no-match",
    rules: [{
      id: "never-match",
      priority: 1,
      when: { op: "eq", fact: "input_state", value: "invalid" },
      outcome: "operator",
      reasonCode: "never_match",
    }],
  };
  const result = evaluateRulebook(noMatch, principalFacts);
  assert.equal(result.outcome, "unresolved");
  assert.equal(result.reasonCode, "unresolved_default");
  assert.equal(result.trace[0].matched, false);
});
