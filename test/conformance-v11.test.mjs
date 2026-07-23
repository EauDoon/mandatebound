import assert from "node:assert/strict";
import test from "node:test";
import { compareCasePackStatus } from "../dist/casepack-tools.js";
import { getConformanceStatement } from "../dist/conformance.js";

test("conformance statement names the exact evidence-import profile and its limits", () => {
  const statement = getConformanceStatement();
  assert.equal(statement.release, "1.1.0");
  assert.equal(statement.evidenceProfile.ucpVersion, "2026-04-08");
  assert.equal(statement.evidenceProfile.ucpTransport, "REST");
  assert.equal(statement.evidenceProfile.ap2Version, "0.2.0");
  assert.equal(statement.claim, "bounded-evidence-profile");
  assert.equal(statement.legalEffect, "not-determined");

  const byId = new Map(statement.capabilities.map((entry) => [entry.id, entry]));
  assert.equal(byId.get("ucp_2026_04_08_rest_evidence_import").status, "supported");
  assert.equal(byId.get("ap2_0_2_0_mandates_evidence_import").status, "supported");
  assert.equal(byId.get("ucp_mcp_transport").status, "deferred");
  assert.equal(byId.get("ucp_a2a_transport").status, "deferred");
  assert.equal(byId.get("external_trust_auto_promotion").status, "unsupported");
  assert.equal(byId.get("legal_adjudication").status, "unsupported");
  assert.equal(new Set(statement.capabilities.map((entry) => entry.id)).size, statement.capabilities.length);
});

test("conformance statement is immutable to callers", () => {
  const statement = getConformanceStatement();
  assert.equal(Object.isFrozen(statement), true);
  assert.equal(Object.isFrozen(statement.capabilities), true);
  assert.equal(Object.isFrozen(statement.capabilities[0]), true);
  assert.throws(() => {
    statement.capabilities.push({ id: "extra" });
  }, TypeError);
});

test("CasePack assurance status ordering is stable", () => {
  assert.equal(compareCasePackStatus("satisfied", "satisfied"), 0);
  assert.ok(compareCasePackStatus("satisfied", "missing") < 0);
  assert.ok(compareCasePackStatus("conflicting", "unknown") > 0);
  assert.throws(() => compareCasePackStatus("other", "unknown"), TypeError);
});
