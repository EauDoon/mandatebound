import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { sha256Digest } from "../dist/canonical.js";
import {
  diffRulebooks,
  testPolicyPack,
  validatePolicyPack,
} from "../dist/policy-tools.js";
import { buildScenario } from "../dist/simulator.js";

const referenceRulebook = JSON.parse(readFileSync(
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

function pack() {
  const policy = structuredClone(buildScenario("principal").input.policy.payload);
  policy.rulebookRef = {
    artifactType: "rulebook",
    artifactId: referenceRulebook.artifactId,
    digest: sha256Digest(referenceRulebook),
  };
  return { policy, rulebook: structuredClone(referenceRulebook) };
}

test("policy pack validation binds the policy to the exact rulebook", () => {
  const valid = validatePolicyPack(pack());
  assert.equal(valid.valid, true, JSON.stringify(valid.issues));
  assert.match(valid.policyDigest, /^sha256:/);
  assert.equal(valid.rulebookDigest, sha256Digest(referenceRulebook));

  const mismatched = pack();
  mismatched.policy.rulebookRef.digest = `sha256:${"0".repeat(64)}`;
  const report = validatePolicyPack(mismatched);
  assert.equal(report.valid, false);
  assert.equal(report.issues[0].code, "MB_POLICY_REFERENCE");
});

test("policy test runner evaluates closed facts and reports mismatches", () => {
  const candidate = pack();
  const report = testPolicyPack({
    ...candidate,
    cases: [
      {
        id: "principal-case",
        facts: principalFacts,
        expected: { outcome: "principal" },
      },
      {
        id: "intentionally-wrong",
        facts: { ...principalFacts, mandate_state: "expired" },
        expected: { outcome: "principal", reasonCode: "wrong-reason" },
      },
    ],
  });
  assert.equal(report.valid, true);
  assert.equal(report.passed, false);
  assert.equal(report.total, 2);
  assert.equal(report.passedCount, 1);
  assert.equal(report.failedCount, 1);
});

test("rulebook diff is deterministic and includes case-level behavioral impact", () => {
  const after = structuredClone(referenceRulebook);
  after.revision += 1;
  const principal = after.rules.find((rule) => rule.outcome === "principal");
  principal.outcome = "unresolved";
  principal.reasonCode = "manual_review_required";
  const input = {
    before: referenceRulebook,
    after,
    cases: [{
      id: "principal-case",
      facts: principalFacts,
      expected: { outcome: "principal" },
    }],
  };
  const first = diffRulebooks(input);
  const second = diffRulebooks(input);
  assert.deepEqual(second, first);
  assert.equal(first.valid, true);
  assert.equal(first.changed, true);
  assert.equal(first.revision.changed, true);
  assert.equal(first.rules.length, 1);
  assert.equal(first.rules[0].change, "modified");
  assert.equal(first.behaviorChanges.length, 1);
  assert.equal(first.behaviorChanges[0].after.outcome, "unresolved");
});

test("policy tooling rejects open shapes, invalid cases, and malformed rulebooks", () => {
  assert.equal(validatePolicyPack(null).valid, false);
  assert.equal(validatePolicyPack({ ...pack(), extra: true }).valid, false);
  assert.equal(validatePolicyPack({ policy: {}, rulebook: {} }).valid, false);

  const invalidFacts = testPolicyPack({
    ...pack(),
    cases: [{
      id: "bad",
      facts: { ...principalFacts, secret_fact: "leak" },
      expected: { outcome: "principal" },
    }],
  });
  assert.equal(invalidFacts.valid, false);

  const duplicateIds = testPolicyPack({
    ...pack(),
    cases: [1, 2].map(() => ({
      id: "duplicate",
      facts: principalFacts,
      expected: { outcome: "principal" },
    })),
  });
  assert.equal(duplicateIds.valid, false);

  const malformed = diffRulebooks({ before: {}, after: {} });
  assert.equal(malformed.valid, false);
  assert.equal(malformed.changed, false);
});
