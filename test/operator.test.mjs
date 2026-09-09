import assert from "node:assert/strict";
import test from "node:test";
import { triageCase } from "../dist/operator.js";
import { operatorFixture } from "./fixtures/operator-fixture.mjs";

test("triage re-verifies evidence and never asserts source truth", () => {
  const { pack, anchors } = operatorFixture();
  const before = structuredClone(pack);
  const result = triageCase({ casePack: pack, anchors });
  assert.equal(result.valid, true);
  assert.deepEqual(result.items, []);
  assert.equal(result.sourceTruth, "unknown");
  assert.equal(result.legalEffect, "not-determined");
  pack.casePackId = "mutated";
  const invalid = triageCase({ casePack: pack, anchors });
  assert.equal(invalid.valid, false);
  assert.equal(invalid.items[0].priority, "high");
  assert.ok(invalid.findings.length > 0);
  assert.equal(before.casePackId, "casepack.case-001");
});

test("triage is deterministic and fails closed for absent evidence", () => {
  const { anchors } = operatorFixture();
  const input = { casePack: null, anchors };
  assert.deepEqual(triageCase(input), triageCase(input));
  assert.equal(triageCase(input).valid, false);
});
