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

test("policy test cases enforce the closed case, fact and expectation shapes", () => {
  const base = { ...pack(), cases: [{ id: "ok", facts: principalFacts, expected: { outcome: "principal" } }] };
  assert.equal(testPolicyPack(base).valid, true, "the reference case must be accepted");

  // A non-object input is rejected before anything is inspected.
  const notAnObject = testPolicyPack(null);
  assert.equal(notAnObject.valid, false);
  assert.equal(notAnObject.issues[0].message, "Policy test input must contain policy, rulebook, and cases");

  // The case list itself must be a bounded, non-empty array.
  for (const cases of [[], "cases", null, Array.from({ length: 257 }, () => base.cases[0])]) {
    const report = testPolicyPack({ ...pack(), cases });
    assert.equal(report.valid, false);
    assert.equal(
      report.issues.some((issue) => issue.message === "Policy tests must contain 1 to 256 cases"),
      true,
      JSON.stringify(Array.isArray(cases) ? `length ${cases.length}` : String(cases)),
    );
  }

  // Exactly 256 cases is still inside the bound.
  const atCap = Array.from({ length: 256 }, (unused, index) => ({
    id: `case-${String(index)}`,
    facts: principalFacts,
    expected: { outcome: "principal" },
  }));
  assert.equal(testPolicyPack({ ...pack(), cases: atCap }).valid, true, "256 cases must be accepted");

  const shapeIssues = (candidate) => {
    const report = testPolicyPack({ ...pack(), cases: [candidate] });
    assert.equal(report.valid, false, JSON.stringify(candidate));
    return report.issues.map((issue) => `${issue.path} ${issue.message}`);
  };

  assert.equal(
    shapeIssues({ id: "c", facts: principalFacts }).some((line) => line.includes("invalid closed shape")),
    true,
  );
  assert.equal(
    shapeIssues({ id: "c", facts: principalFacts, expected: { outcome: "principal" }, extra: 1 })
      .some((line) => line.includes("invalid closed shape")),
    true,
  );
  assert.equal(
    shapeIssues({ id: "has spaces", facts: principalFacts, expected: { outcome: "principal" } })
      .some((line) => line.includes("invalid closed shape")),
    true,
  );
  assert.equal(
    shapeIssues({ id: "c", facts: principalFacts, expected: { outcome: "settled" } })
      .some((line) => line.includes("expectation is invalid")),
    true,
  );
  assert.equal(
    shapeIssues({ id: "c", facts: principalFacts, expected: { outcome: ["principal"] } })
      .some((line) => line.includes("expectation is invalid")),
    true,
  );
  assert.equal(
    shapeIssues({ id: "c", facts: principalFacts, expected: { outcome: "principal", extra: 1 } })
      .some((line) => line.includes("expectation is invalid")),
    true,
  );
  assert.equal(
    shapeIssues({ id: "c", facts: principalFacts, expected: { outcome: "principal", reasonCode: 7 } })
      .some((line) => line.includes("expectation is invalid")),
    true,
  );

  // Facts must be a complete, closed vocabulary of allowed values.
  assert.equal(
    shapeIssues({ id: "c", facts: "none", expected: { outcome: "principal" } })
      .some((line) => line.includes("Policy facts must be an object")),
    true,
  );
  const incomplete = { ...principalFacts };
  delete incomplete.model_provenance;
  assert.equal(
    shapeIssues({ id: "c", facts: incomplete, expected: { outcome: "principal" } })
      .some((line) => line.includes("complete closed vocabulary")),
    true,
  );
  assert.equal(
    shapeIssues({
      id: "c",
      facts: { ...principalFacts, input_state: "unknown-state" },
      expected: { outcome: "principal" },
    }).some((line) => line.includes("Policy fact value is not allowed")),
    true,
  );
  assert.equal(
    shapeIssues({
      id: "c",
      facts: { ...principalFacts, input_state: 7 },
      expected: { outcome: "principal" },
    }).some((line) => line.includes("Policy fact value is not allowed")),
    true,
  );

  // A valid reasonCode is accepted and carried through to the result.
  const withReason = testPolicyPack({
    ...pack(),
    cases: [{
      id: "c",
      facts: principalFacts,
      expected: { outcome: "principal", reasonCode: "inside_mandate_without_vendor_causation" },
    }],
  });
  assert.equal(withReason.valid, true, JSON.stringify(withReason.issues));
});
