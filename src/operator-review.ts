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
