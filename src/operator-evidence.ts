import type { MandateBoundCasePack } from "./casepack.js";
import { sha256Bytes } from "./canonical.js";
import type { CaseAssessmentInput } from "./operator.js";
import { inventoryCaseEvidence } from "./operator-review.js";
import { createCaseReport } from "./report.js";

function evidenceContext(input: CaseAssessmentInput) {
  const report = createCaseReport(input.casePack, input.anchors);
  const pack = report.casePackDigest === undefined ? undefined : input.casePack as MandateBoundCasePack;
  const boundary = { valid: report.valid, casePackDigest: report.casePackDigest ?? null,
    assessedAt: report.assessedAt, legalEffect: "not-determined" as const,
    sourceTruth: "unknown" as const, globalCompleteness: "not-established" as const };
  return { report, pack, boundary };
}

/** Group requests by reference ID without retrieving or exposing evidence bodies or locations. */
export function planCaseCollection(input: CaseAssessmentInput) {
  inventoryCaseEvidence(input); // Reuse the bounded raw-byte validation shared with inventory.
  const { pack, boundary } = evidenceContext(input);
  const descriptors = [
    ...(pack?.protocolEvidence ?? []).map((item) => ({ kind: "protocol", id: item.envelopeId, ...item.rawEvidence })),
    ...(pack?.externalTrustSnapshot?.discoveryMaterials ?? []).map((item) => ({ kind: "discovery", id: item.materialId, ...item.rawEvidence })),
    ...(pack?.delegationContext.evidenceReferences ?? []).map((item, index) => ({ kind: "delegation", id: String(index), byteLength: null, ...item })),
  ];
  const supplied = new Map((input.anchors.rawEvidence ?? []).map((item) => [item.referenceId,
    { digest: sha256Bytes(item.bytes), byteLength: item.bytes.byteLength }]));
  const requests = [...new Set(descriptors.map((item) => item.reference.referenceId))].sort().map((referenceId) => {
    const records = descriptors.filter((item) => item.reference.referenceId === referenceId);
    const digests = [...new Set(records.map((item) => item.digest))].sort();
    const byteLengths = [...new Set(records.flatMap((item) => item.byteLength === null ? [] : [item.byteLength]))].sort((a, b) => a - b);
    const actual = supplied.get(referenceId);
    const status = digests.length !== 1 || byteLengths.length > 1 ? "conflicting" as const
      : actual === undefined ? "missing" as const
      : actual.digest !== digests[0] || (byteLengths.length === 1 && actual.byteLength !== byteLengths[0]) ? "mismatched" as const
      : "supplied" as const;
    return { referenceId, expectedDigests: digests, expectedByteLengths: byteLengths, status,
      consumers: records.map(({ kind, id }) => ({ kind, id })).sort((a, b) => `${a.kind}:${a.id}` < `${b.kind}:${b.id}` ? -1 : 1) };
  });
  return { format: "MandateBoundCollectionPlan/v1" as const, ...boundary, requests,
    needsCollection: requests.some((item) => item.status !== "supplied"),
    note: "Collection metadata is not a retrieval instruction or proof of provenance. Conflicting descriptors require review." };
}
