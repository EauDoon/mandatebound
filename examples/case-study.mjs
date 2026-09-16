import assert from "node:assert/strict";
import {
  buildScenario,
  evaluateCase,
  verifyEvidenceBundle,
} from "../dist/index.js";

function evidenceSummary(input) {
  return {
    mandate: input.mandate === undefined ? "missing" : "present_signed",
    runtimeEvents: input.runtimeEvents.map((event) => event.payload.eventType),
    executionReceipt: input.executionReceipt === undefined ? "missing" : "present_signed",
    incidentReport: input.incidentReport === undefined ? "missing" : "present_signed",
    causationAttestations: input.causationAttestations.length,
  };
}

function decisionSummary(decision) {
  return {
    outcome: decision.outcome,
    disposition: decision.disposition,
    reasonCodes: decision.reasonCodes,
    missingEvidence: decision.missingEvidence,
    rejectedEvidence: decision.rejectedEvidence.map((item) => item.reasonCode),
    legalEffect: decision.legalEffect,
  };
}

const complete = buildScenario("principal");
const completeBundle = complete.bundle;
assert.ok(completeBundle);
const completeDecision = evaluateCase(complete.input);
const completeVerification = verifyEvidenceBundle(completeBundle);
assert.equal(completeDecision.outcome, "principal");
assert.equal(completeDecision.disposition, "allocated");
assert.equal(completeDecision.legalEffect, "not-determined");
assert.equal(completeVerification.valid, true);

const missing = buildScenario("unresolved");
const missingDecision = evaluateCase(missing.input);
assert.equal(missingDecision.outcome, "unresolved");
assert.equal(missingDecision.disposition, "indeterminate");
assert.deepEqual(missingDecision.missingEvidence, ["execution_receipt", "incident_report", "mandate"]);

const tampered = buildScenario("tamper");
const tamperedBundle = tampered.bundle;
assert.ok(tamperedBundle);
const tamperedDecision = evaluateCase(tampered.input);
const tamperedVerification = verifyEvidenceBundle(tamperedBundle);
assert.equal(tamperedDecision.outcome, "unresolved");
assert.equal(tamperedDecision.disposition, "invalid");
assert.equal(tamperedVerification.valid, false);
assert.ok(tamperedDecision.rejectedEvidence.some((item) => item.reasonCode === "evidence_bundle_invalid"));

console.log(JSON.stringify({
  case: {
    scenario: complete.name,
    caseId: complete.input.caseId,
    purchase: complete.input.executionReceipt?.payload.action.quantity ?? null,
    mandateScope: complete.input.mandate?.payload.scope.actions[0] ?? null,
    evidence: evidenceSummary(complete.input),
    bundleVerification: {
      valid: completeVerification.valid,
      verifiedEntries: completeVerification.verifiedEntries,
      totalEntries: completeVerification.totalEntries,
      issues: completeVerification.issues.map((item) => item.code),
    },
  },
  result: decisionSummary(completeDecision),
  variants: [
    {
      scenario: missing.name,
      change: "mandate, execution receipt, and incident report omitted",
      evidence: evidenceSummary(missing.input),
      result: decisionSummary(missingDecision),
    },
    {
      scenario: tampered.name,
      change: "execution receipt payload changed after signing and bundle root changed",
      result: decisionSummary(tamperedDecision),
      bundleVerification: {
        valid: tamperedVerification.valid,
        verifiedEntries: tamperedVerification.verifiedEntries,
        totalEntries: tamperedVerification.totalEntries,
        issues: tamperedVerification.issues.map((item) => item.code),
      },
    },
  ],
}, null, 2));
