import assert from "node:assert/strict";
import test from "node:test";
import fc from "fast-check";
import { createEvidenceBundle, verifyEvidenceBundle } from "../dist/bundle.js";
import { evaluateCase } from "../dist/engine.js";
import { buildScenario } from "../dist/simulator.js";
import { deriveLiabilityDecisionId } from "../dist/validation.js";

test("fast-check: every runtime-event permutation yields the identical decision and bundle", () => {
  const source = buildScenario("principal").input;
  const { evidenceBundle: _embedded, ...input } = source;
  const expectedDecision = evaluateCase(input);
  const expectedBundle = createEvidenceBundle(input);
  fc.assert(fc.property(
    fc.shuffledSubarray(input.runtimeEvents, {
      minLength: input.runtimeEvents.length,
      maxLength: input.runtimeEvents.length,
    }),
    (runtimeEvents) => {
      const candidate = { ...input, runtimeEvents };
      assert.deepEqual(evaluateCase(candidate), expectedDecision);
      assert.deepEqual(createEvidenceBundle(candidate), expectedBundle);
    },
  ), { numRuns: 40 });
});

test("fast-check: protected payload mutations never infer model-vendor liability", () => {
  const input = buildScenario("principal").input;
  fc.assert(fc.property(
    fc.string({ minLength: 1, maxLength: 40 }),
    (target) => {
      const hostile = structuredClone(input);
      hostile.executionReceipt.payload.action.target = target;
      const decision = evaluateCase(hostile);
      assert.equal(decision.outcome, "unresolved");
      assert.equal(decision.disposition, "invalid");
      assert.notEqual(decision.outcome, "model_vendor");
    },
  ), { numRuns: 40 });
});

test("fast-check: causation-order permutations cannot resolve a conflict", () => {
  const input = buildScenario("conflict").input;
  fc.assert(fc.property(
    fc.shuffledSubarray(input.causationAttestations, {
      minLength: input.causationAttestations.length,
      maxLength: input.causationAttestations.length,
    }),
    (causationAttestations) => {
      const decision = evaluateCase({ ...input, causationAttestations });
      assert.equal(decision.outcome, "unresolved");
      assert.equal(decision.disposition, "conflicted");
    },
  ), { numRuns: 30 });
});

test("decision identities commit to all decision material", () => {
  for (const scenario of ["principal", "operator", "model_vendor", "unresolved", "tamper", "conflict"]) {
    const decision = evaluateCase(buildScenario(scenario).input);
    assert.equal(deriveLiabilityDecisionId(decision), decision.artifactId);
    const changed = { ...decision, reasonCodes: [...decision.reasonCodes, "test_mutation"] };
    assert.notEqual(deriveLiabilityDecisionId(changed), decision.artifactId);
  }
});

test("fast-check: arbitrary root changes make bundles unverifiable", () => {
  const input = buildScenario("principal").input;
  const bundle = createEvidenceBundle(input);
  const hexArbitrary = fc.array(fc.constantFrom(..."0123456789abcdef"), {
    minLength: 64,
    maxLength: 64,
  }).map((characters) => characters.join(""));
  fc.assert(fc.property(hexArbitrary, (hex) => {
    const candidate = { ...bundle, rootDigest: `sha256:${hex.toLowerCase()}` };
    const valid = verifyEvidenceBundle(candidate).valid;
    assert.equal(valid, candidate.rootDigest === bundle.rootDigest);
  }), { numRuns: 30 });
});
