import type { MandateBoundCasePack } from "./casepack.js";
import { sha256Bytes } from "./canonical.js";
import { assessCases, type CaseAssessmentInput, type NamedCaseAssessment } from "./operator.js";
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

/** Include declared-but-absent sources so collection gaps cannot disappear in a rollup. */
export function summarizeCaseSources(input: CaseAssessmentInput) {
  const { pack, report, boundary } = evidenceContext(input);
  const requirements = pack?.coverageContract.requirements ?? [];
  const envelopes = pack?.protocolEvidence ?? [];
  const coverage = new Map(report.coverage.map((item) => [item.requirementId, item]));
  const verified = new Map(report.envelopes.map((item) => [item.envelopeId, item]));
  const sources = [...new Set([...requirements, ...envelopes].map((item) => item.sourceId))].sort().map((sourceId) => {
    const items = envelopes.filter((item) => item.sourceId === sourceId);
    return { sourceId, envelopes: items.length,
      eligibleEnvelopes: items.filter((item) => verified.get(item.envelopeId)?.evidenceEligible === true).length,
      requirements: requirements.filter((item) => item.sourceId === sourceId).map((item) => ({
        requirementId: item.requirementId, eventClass: item.eventClass,
        status: coverage.get(item.requirementId)?.status ?? "unknown",
        matchedEnvelopes: coverage.get(item.requirementId)?.matchedEnvelopes ?? 0,
        minEnvelopes: item.minEnvelopes,
      })).sort((a, b) => a.requirementId < b.requirementId ? -1 : 1) };
  });
  return { format: "MandateBoundSourceSummary/v1" as const, ...boundary, sources };
}

/** Capture time is a supplied assertion, not proof of event order or settlement. */
export function createCaseCaptureTimeline(input: CaseAssessmentInput) {
  const { pack, report, boundary } = evidenceContext(input);
  const verified = new Map(report.envelopes.map((item) => [item.envelopeId, item]));
  const events = (pack?.protocolEvidence ?? []).map((item) => ({
    envelopeId: item.envelopeId, sourceId: item.sourceId, eventClass: item.eventClass,
    capturedAt: item.capturedAt, afterAssessment: Date.parse(item.capturedAt) > Date.parse(report.assessedAt),
    evidenceEligible: verified.get(item.envelopeId)?.evidenceEligible === true,
    integrityStatus: verified.get(item.envelopeId)?.integrityStatus ?? "unknown",
  })).sort((a, b) => Date.parse(a.capturedAt) - Date.parse(b.capturedAt) || (a.envelopeId < b.envelopeId ? -1 : 1));
  return { format: "MandateBoundCaptureTimeline/v1" as const, ...boundary, events,
    note: "Times are supplied capture metadata; ordering does not establish causation or actual event time." };
}

/** Trace declared mapping edges; a matching hash is not proof the transformation is truthful. */
export function traceCaseMappings(input: CaseAssessmentInput) {
  const { pack, report, boundary } = evidenceContext(input);
  const entries = new Map((pack?.nativeEvidenceBundle.manifest.entries ?? []).map((item) => [item.path, item.digest]));
  const verified = new Map(report.envelopes.map((item) => [item.envelopeId, item]));
  const links = (pack?.protocolEvidence ?? []).flatMap((item) => item.mapping.outputArtifacts.map((output) => ({
    envelopeId: item.envelopeId, sourceId: item.sourceId, mapperId: item.mapping.mapperId,
    mapperVersion: item.mapping.mapperVersion, mappingPolicyDigest: item.mapping.mappingPolicyDigest,
    traceDigest: item.mapping.traceDigest, path: output.path, expectedDigest: output.digest,
    actualDigest: entries.get(output.path) ?? null, digestMatches: entries.get(output.path) === output.digest,
    evidenceEligible: verified.get(item.envelopeId)?.evidenceEligible === true,
  }))).sort((a, b) => a.envelopeId < b.envelopeId ? -1 : a.envelopeId > b.envelopeId ? 1 : a.path < b.path ? -1 : 1);
  const referenced = new Set(links.map((item) => item.path));
  return { format: "MandateBoundMappingLineage/v1" as const, ...boundary, links,
    unreferencedPaths: [...entries.keys()].filter((path) => !referenced.has(path)).sort(),
    note: "Unreferenced native entries may be legitimate. Mapping links do not establish source truth or transformation correctness." };
}

/** Declared checkpoint contents and references are distinct from proof verification. */
export function inspectCaseCheckpoints(input: CaseAssessmentInput) {
  const { pack, boundary } = evidenceContext(input);
  const inclusions = (pack?.protocolEvidence ?? []).flatMap((item) => item.checkpointInclusion === undefined ? [] : [{
    envelopeId: item.envelopeId, sourceId: item.sourceId, checkpointId: item.checkpointInclusion.checkpointId,
    sequence: item.checkpointInclusion.sequence, leafIndex: item.checkpointInclusion.leafIndex,
  }]).sort((a, b) => a.envelopeId < b.envelopeId ? -1 : 1);
  const checkpoints = (pack?.sourceCheckpoints ?? []).map((item) => ({
    checkpointId: item.checkpointId, sourceId: item.sourceId, epoch: item.epoch, checkpointDigest: item.checkpointDigest,
    issuedAt: item.issuedAt, windowStart: item.windowStart, windowEnd: item.windowEnd,
    firstSequence: item.firstSequence, lastSequence: item.lastSequence, eventCount: item.eventCount,
    declaredGaps: item.declaredGaps.map((gap) => ({ ...gap })).sort((a, b) => a.fromSequence - b.fromSequence),
    proofCount: item.proofs.length, previousCheckpointDigest: item.previousCheckpointDigest ?? null,
    inclusions: inclusions.filter((inclusion) => inclusion.checkpointId === item.checkpointId),
  })).sort((a, b) => a.checkpointId < b.checkpointId ? -1 : 1);
  const ids = new Set(checkpoints.map((item) => item.checkpointId));
  return { format: "MandateBoundCheckpointInventory/v1" as const, ...boundary, checkpoints,
    missingCheckpointReferences: inclusions.filter((item) => !ids.has(item.checkpointId)),
    note: "Proof counts and supplied inclusion references do not establish authenticated inclusion or global completeness." };
}

/** Time-window membership is separate from cryptographic validity and authority. */
export function inspectCaseValidityWindows(input: CaseAssessmentInput) {
  const { pack, boundary } = evidenceContext(input);
  const snapshot = pack?.externalTrustSnapshot;
  const declared = pack === undefined ? [] : [
    { kind: "coverage", id: pack.coverageContract.contractId, from: pack.coverageContract.validFrom, until: pack.coverageContract.validUntil },
    { kind: "delegation", id: pack.delegationContext.delegationId, from: pack.delegationContext.validFrom, until: pack.delegationContext.validUntil },
    ...(snapshot === undefined ? [] : [
      { kind: "discovery", id: snapshot.snapshotId, from: snapshot.issuedAt, until: snapshot.expiresAt },
      ...snapshot.keys.map((key) => ({ kind: "checkpoint_key", id: key.keyId, from: key.validFrom, until: key.validUntil })),
    ]),
  ];
  const now = Date.parse(input.anchors.asOf);
  const windows = declared.map((item) => ({ ...item,
    state: !Number.isFinite(now) ? "unknown" : now < Date.parse(item.from) ? "not_yet_valid"
      : now >= Date.parse(item.until) ? "expired" : "within_window",
    remainingSeconds: Number.isFinite(now) ? Math.max(0, (Date.parse(item.until) - now) / 1_000) : null,
  })).sort((a, b) => Date.parse(a.until) - Date.parse(b.until) || (`${a.kind}:${a.id}` < `${b.kind}:${b.id}` ? -1 : 1));
  return { format: "MandateBoundValidityWindows/v1" as const, ...boundary, windows,
    note: "Windows include their start and exclude their end. Membership grants no legal authority or trust promotion." };
}

/** Repeated declared content is visible even when supplied bytes fail verification. */
export function findCaseContentReuse(input: CaseAssessmentInput) {
  const inventory = inventoryCaseEvidence(input);
  const { boundary } = evidenceContext(input);
  const byDigest = new Map<string, typeof inventory.records>();
  for (const record of inventory.records) {
    const group = byDigest.get(record.expectedDigest) ?? [];
    group.push(record);
    byDigest.set(record.expectedDigest, group);
  }
  const groups = [...byDigest.entries()].filter(([, records]) => records.length > 1).map(([digest, records]) => ({
    digest, sourceIds: [...new Set(records.map((item) => item.sourceId))].sort(),
    allSuppliedMatch: records.every((item) => item.matches), records,
  })).sort((a, b) => a.digest < b.digest ? -1 : 1);
  return { format: "MandateBoundContentReuse/v1" as const, ...boundary, groups,
    note: "Shared declared hashes identify content reuse, not independent corroboration, fraud, or source truth." };
}

/** Coordinate collection across cases without treating their coverage policies as interchangeable. */
export function findBatchCollectionBottlenecks(inputs: readonly NamedCaseAssessment[]) {
  const batch = assessCases(inputs);
  const byId = new Map(inputs.map((item) => [item.id, item]));
  const rows = batch.cases.flatMap(({ id, report }) => {
    if (report.casePackDigest === undefined) return [];
    const pack = byId.get(id)?.casePack as MandateBoundCasePack;
    const status = new Map(report.coverage.map((item) => [item.requirementId, item]));
    return pack.coverageContract.requirements.flatMap((item) => {
      const requirement = status.get(item.requirementId);
      return requirement?.status === "satisfied" || requirement?.status === "not_applicable" ? [] : [{
        caseId: id, sourceId: item.sourceId, eventClass: item.eventClass, requirementId: item.requirementId,
        status: requirement?.status ?? "unknown", matchedEnvelopes: requirement?.matchedEnvelopes ?? 0,
        minEnvelopes: item.minEnvelopes, coverageContractDigest: pack.coverageContract.contractDigest,
      }];
    });
  }).sort((a, b) => `${a.caseId}:${a.requirementId}` < `${b.caseId}:${b.requirementId}` ? -1 : 1);
  const grouped = new Map<string, typeof rows>();
  for (const row of rows) {
    const key = JSON.stringify([row.sourceId, row.eventClass]);
    const group = grouped.get(key) ?? [];
    group.push(row);
    grouped.set(key, group);
  }
  const bottlenecks = [...grouped.entries()].sort(([a], [b]) => a < b ? -1 : 1).map(([, requirements]) => ({
    sourceId: requirements[0]?.sourceId, eventClass: requirements[0]?.eventClass,
    caseIds: [...new Set(requirements.map((item) => item.caseId))].sort(), requirements,
  }));
  return { format: "MandateBoundCollectionBottlenecks/v1" as const, valid: batch.valid,
    legalEffect: "not-determined" as const, globalCompleteness: "not-established" as const,
    bottlenecks, unassessableCaseIds: batch.cases.filter(({ report }) => report.casePackDigest === undefined).map(({ id }) => id).sort(),
    cases: batch.cases.map(({ id, report }) => ({ id, valid: report.valid, casePackDigest: report.casePackDigest ?? null,
      assessedAt: report.assessedAt })).sort((a, b) => a.id < b.id ? -1 : 1),
    note: "Groups coordinate collection only. Each requirement keeps its case and coverage contract; source IDs are caller-scoped." };
}

/** Group verifier identities, not diagnostic text, for recurring issue investigation. */
export function summarizeBatchFindings(inputs: readonly NamedCaseAssessment[]) {
  const batch = assessCases(inputs);
  const groups = new Map<string, { code: string; path: string; counts: Map<string, number> }>();
  for (const { id, report } of batch.cases) {
    for (const finding of report.findings) {
      const key = JSON.stringify([finding.code, finding.path]);
      const group = groups.get(key) ?? { code: finding.code, path: finding.path, counts: new Map<string, number>() };
      group.counts.set(id, (group.counts.get(id) ?? 0) + 1);
      groups.set(key, group);
    }
  }
  const findings = [...groups.values()].map(({ code, path, counts }) => ({ code, path,
    caseCount: counts.size, occurrences: [...counts.values()].reduce((sum, count) => sum + count, 0),
    cases: [...counts.entries()].sort(([a], [b]) => a < b ? -1 : 1).map(([id, count]) => ({ id, count })),
  })).sort((a, b) => b.caseCount - a.caseCount || b.occurrences - a.occurrences
    || (JSON.stringify([a.code, a.path]) < JSON.stringify([b.code, b.path]) ? -1 : 1));
  return { format: "MandateBoundBatchFindings/v1" as const, valid: batch.valid,
    legalEffect: "not-determined" as const, sourceTruth: "unknown" as const, findings,
    cases: batch.cases.map(({ id, report }) => ({ id, valid: report.valid, assessedAt: report.assessedAt,
      casePackDigest: report.casePackDigest ?? null, findingCount: report.findings.length })).sort((a, b) => a.id < b.id ? -1 : 1),
    note: "Frequency prioritizes investigation only. Matching issue identities do not establish a common cause." };
}
