import assert from "node:assert/strict";
import test from "node:test";
import {
  SIMULATION_SCENARIOS,
  buildScenario,
  simulateScenario,
} from "../dist/simulator.js";
import { validateArtifact } from "../dist/validation.js";

test("all synthetic scenarios reach their fail-closed expected state", async () => {
  const results = await simulateScenario("all");
  assert.equal(results.length, SIMULATION_SCENARIOS.length);
  assert.deepEqual(results.map((result) => result.scenario), [...SIMULATION_SCENARIOS]);
  for (const result of results) {
    assert.equal(result.passed, true, `${result.scenario}: expected ${result.expected}, observed ${result.observed}`);
    assert.equal(result.legalEffect, "not-determined");
  }
});

test("scenario keys are ephemeral and only public JWK material is returned", () => {
  const first = buildScenario("principal");
  const second = buildScenario("principal");
  const firstJson = JSON.stringify(first);
  const secondJson = JSON.stringify(second);
  assert.equal(firstJson.includes('"d":'), false);
  assert.equal(secondJson.includes('"d":'), false);
  assert.notEqual(first.input.trustRootJwk.x, second.input.trustRootJwk.x);
  assert.equal(first.input.trustRootJwk.kty, "OKP");
});

test("tamper scenario has an invalid evidence root", () => {
  const built = buildScenario("tamper");
  assert.equal(built.expected, "invalid");
  assert.notEqual(built.bundle.rootDigest, built.input.pins.trustSnapshotDigest);
});

test("unknown scenarios are rejected without reflecting input", () => {
  assert.throws(() => buildScenario("private-path-secret"), (error) => {
    assert.equal(error.code, "ALB_SCENARIO_UNKNOWN");
    assert.equal(error.message.includes("private-path-secret"), false);
    return true;
  });
});

test("appeal simulation uses a schema-valid upheld lineage and does not fabricate a superseding decision", async () => {
  const result = await simulateScenario("appeal");
  assert.equal(result.expected, "upheld");
  assert.equal(result.observed, "upheld");
  assert.equal(result.appeal.status, "upheld");
  assert.equal(result.appeal.issues.length, 0);
  assert.equal(result.decision.supersedesDecisionId, undefined);
  assert.equal(result.decision.appealId, undefined);
  assert.deepEqual(result.decision.appealPolicy, buildScenario("appeal").input.policy.payload.appeal);
  assert.equal(validateArtifact("liability_decision", result.decision).ok, true);
  for (const event of result.appeal.events) {
    assert.equal(validateArtifact("appeal_event", event).ok, true);
  }
});
