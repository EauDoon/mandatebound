import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCase, explainDecision } from "../dist/engine.js";
import { buildScenario } from "../dist/simulator.js";
import { validateArtifact } from "../dist/validation.js";

const expected = {
  principal: ["principal", "allocated"],
  operator: ["operator", "allocated"],
  model_vendor: ["model_vendor", "allocated"],
  unresolved: ["unresolved", "indeterminate"],
};

for (const [scenario, [outcome, disposition]] of Object.entries(expected)) {
  test(`evaluates the ${scenario} branch`, () => {
    const decision = evaluateCase(buildScenario(scenario).input);
    assert.equal(decision.outcome, outcome);
    assert.equal(decision.policyOutcome, outcome);
    assert.equal(decision.disposition, disposition);
    assert.equal(decision.legalEffect, "not-determined");
    assert.equal(decision.artifactId.length, "decision-".length + 64);
    assert.equal(validateArtifact("liability_decision", decision).ok, true);
  });
}

test("expired and replayed executions allocate to the operator", () => {
  for (const scenario of ["expiry", "replay"]) {
    const decision = evaluateCase(buildScenario(scenario).input);
    assert.equal(decision.outcome, "operator");
    assert.equal(decision.disposition, "allocated");
  }
});

test("tampering outranks every attribution and never implies model-vendor fault", () => {
  const decision = evaluateCase(buildScenario("tamper").input);
  assert.equal(decision.outcome, "unresolved");
  assert.equal(decision.disposition, "invalid");
  assert.equal(decision.allocation, undefined);
  assert.ok(decision.rejectedEvidence.some((item) => item.reasonCode.includes("digest_invalid")));
});

test("conflicting causation outranks an otherwise allocable execution", () => {
  const decision = evaluateCase(buildScenario("conflict").input);
  assert.equal(decision.outcome, "unresolved");
  assert.equal(decision.disposition, "conflicted");
  assert.ok(decision.conflictingEvidence.includes("causation_conflict"));
});

test("runtime-event input permutations replay byte-identically", () => {
  const input = buildScenario("principal").input;
  const first = evaluateCase(input);
  const permuted = { ...input, runtimeEvents: [...input.runtimeEvents].reverse() };
  const second = evaluateCase(permuted);
  assert.deepEqual(second, first);
});

test("malformed nested graphs fail closed without reflecting hostile strings", () => {
  const malformed = {
    caseId: "SECRET/../../control\ncanary",
    asOf: "not-a-time",
    pins: { asOf: "bad" },
    policy: { payload: null },
    rulebook: {},
    trustSnapshot: {},
    runtimeEvents: [null],
    priorReceipts: [],
    causationAttestations: [],
  };
  const decision = evaluateCase(malformed);
  assert.equal(decision.outcome, "unresolved");
  assert.equal(decision.disposition, "invalid");
  assert.equal(decision.caseId, "malformed-case");
  assert.equal(decision.evaluatedAt, "1970-01-01T00:00:00.000Z");
  assert.doesNotMatch(JSON.stringify(decision), /SECRET|canary|\.\.\//);
  assert.equal(validateArtifact("liability_decision", decision).ok, true);
});

test("missing nested payloads and wrong linked artifact types fail closed", () => {
  const input = buildScenario("principal").input;
  const missingPayload = { ...input, executionReceipt: { ...input.executionReceipt, payload: undefined } };
  const wrongType = { ...input, mandate: input.policy };
  for (const hostile of [missingPayload, wrongType]) {
    const decision = evaluateCase(hostile);
    assert.equal(decision.outcome, "unresolved");
    assert.equal(decision.disposition, "invalid");
  }
});

test("explanation is bounded and explicitly non-legal", () => {
  const decision = evaluateCase(buildScenario("principal").input);
  const explanation = explainDecision(decision);
  assert.match(explanation, /principal/);
  assert.match(explanation, /not-determined/);
  assert.ok(explanation.length < 512);
});
