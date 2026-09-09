import type { CasePackVerificationAnchors, MandateBoundCasePack } from "./casepack.js";
import { sha256Bytes } from "./canonical.js";
import { OperatorInputError, type CaseAssessmentInput } from "./operator.js";
import { createCaseReport } from "./report.js";

function rawSnapshots(anchors: CasePackVerificationAnchors) {
  const values = anchors.rawEvidence ?? [];
  if (!Array.isArray(values) || values.length > 1_024) throw new OperatorInputError("Raw evidence count is invalid.");
  const ids = new Set<string>();
  let bytes = 0;
  return values.map((item) => {
    if (item === null || typeof item !== "object" || typeof item.referenceId !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(item.referenceId) || ids.has(item.referenceId)
      || !(item.bytes instanceof Uint8Array) || item.bytes.byteLength > 16_777_216
      || Object.keys(item).some((key) => !["referenceId", "bytes"].includes(key))) {
      throw new OperatorInputError("Raw evidence metadata is invalid.");
    }
    ids.add(item.referenceId);
    bytes += item.bytes.byteLength;
    if (bytes > 67_108_864) throw new OperatorInputError("Raw evidence total exceeds the limit.");
    return { referenceId: item.referenceId, byteLength: item.bytes.byteLength, digest: sha256Bytes(item.bytes) };
  }).sort((left, right) => left.referenceId < right.referenceId ? -1 : left.referenceId > right.referenceId ? 1 : 0);
}

/** Metadata inventory only; referenced evidence is never retrieved. */
export function inventoryCaseEvidence(input: CaseAssessmentInput) {
  const report = createCaseReport(input.casePack, input.anchors);
  const supplied = rawSnapshots(input.anchors);
  const byId = new Map(supplied.map((item) => [item.referenceId, item]));
  // The verifier exposes a digest only after the entire CasePack shape is accepted.
  const envelopes = report.casePackDigest === undefined ? [] : (input.casePack as MandateBoundCasePack).protocolEvidence;
  const references = new Set(envelopes.map((item) => item.rawEvidence.reference.referenceId));
  return {
    format: "MandateBoundEvidenceInventory/v1" as const,
    valid: report.valid, legalEffect: "not-determined" as const, sourceTruth: "unknown" as const,
    casePackDigest: report.casePackDigest ?? null,
    records: envelopes.map((item) => {
      const raw = item.rawEvidence;
      const actual = byId.get(raw.reference.referenceId);
      return { envelopeId: item.envelopeId, sourceId: item.sourceId,
        referenceId: raw.reference.referenceId, expectedDigest: raw.digest, expectedBytes: raw.byteLength,
        supplied: actual !== undefined,
        matches: actual !== undefined && actual.digest === raw.digest && actual.byteLength === raw.byteLength };
    }).sort((left, right) => left.envelopeId < right.envelopeId ? -1 : left.envelopeId > right.envelopeId ? 1 : 0),
    otherSuppliedReferences: supplied.filter((item) => !references.has(item.referenceId)).map((item) => item.referenceId),
    findings: report.findings,
  };
}

function comparisonContext(before: CaseAssessmentInput, after: CaseAssessmentInput) {
  const left = createCaseReport(before.casePack, before.anchors);
  const right = createCaseReport(after.casePack, after.anchors);
  const comparable = left.casePackId !== undefined && left.casePackId === right.casePackId
    && before.anchors.coveragePolicyDigest === after.anchors.coveragePolicyDigest
    && before.anchors.coverageContractDigest === after.anchors.coverageContractDigest;
  return { left, right, comparable };
}

/** Same-case, same-coverage-anchor changes, not a confidence score. */
export function compareCaseCoverage(before: CaseAssessmentInput, after: CaseAssessmentInput) {
  const { left, right, comparable } = comparisonContext(before, after);
  const old = new Map(left.coverage.map((item) => [item.requirementId, item]));
  const current = new Map(right.coverage.map((item) => [item.requirementId, item]));
  const changes = comparable ? [...new Set([...old.keys(), ...current.keys()])].sort().flatMap((id) => {
    const previous = old.get(id) ?? null;
    const next = current.get(id) ?? null;
    return JSON.stringify(previous) === JSON.stringify(next) ? [] : [{ requirementId: id, before: previous, after: next,
      regression: previous?.status === "satisfied" && next?.status !== "satisfied" }];
  }) : [];
  return { format: "MandateBoundCoverageComparison/v1" as const, comparable,
    legalEffect: "not-determined" as const, beforeAssessedAt: left.assessedAt, afterAssessedAt: right.assessedAt,
    beforeValid: left.valid, afterValid: right.valid, changes, hasRegression: changes.some((item) => item.regression) };
}
