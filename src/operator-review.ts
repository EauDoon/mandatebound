import type { CasePackVerificationAnchors, MandateBoundCasePack } from "./casepack.js";
import { canonicalBytes, isSha256Digest, sha256Bytes, sha256Digest } from "./canonical.js";
import { OperatorInputError, type CaseAssessmentInput } from "./operator.js";
import { createCaseReport } from "./report.js";
import { ENGINE_VERSION, PROTOCOL_VERSION, RELEASE_VERSION } from "./version.js";

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

function anchorContext(anchors: CasePackVerificationAnchors) {
  if (typeof anchors.asOf !== "string" || !isSha256Digest(anchors.coveragePolicyDigest)
    || !isSha256Digest(anchors.coverageContractDigest)
    || (anchors.externalTrustSnapshotDigest !== undefined && !isSha256Digest(anchors.externalTrustSnapshotDigest))) {
    throw new OperatorInputError("Assessment anchor metadata is invalid.");
  }
  return { asOf: anchors.asOf, coveragePolicyDigest: anchors.coveragePolicyDigest,
    coverageContractDigest: anchors.coverageContractDigest,
    externalTrustSnapshotDigest: anchors.externalTrustSnapshotDigest ?? null, rawEvidence: rawSnapshots(anchors) };
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

/** Show eligibility transitions even when aggregate assurance is unchanged. */
export function compareCaseEnvelopes(before: CaseAssessmentInput, after: CaseAssessmentInput) {
  const { left, right, comparable } = comparisonContext(before, after);
  const old = new Map(left.envelopes.map((item) => [item.envelopeId, item]));
  const current = new Map(right.envelopes.map((item) => [item.envelopeId, item]));
  const changes = comparable ? [...new Set([...old.keys(), ...current.keys()])].sort().flatMap((id) => {
    const previous = old.get(id) ?? null;
    const next = current.get(id) ?? null;
    return JSON.stringify(previous) === JSON.stringify(next) ? [] : [{ envelopeId: id, before: previous, after: next,
      regression: (previous?.evidenceEligible === true && next?.evidenceEligible !== true)
        || (previous?.integrityStatus === "satisfied" && next?.integrityStatus !== "satisfied") }];
  }) : [];
  return { format: "MandateBoundEnvelopeComparison/v1" as const, comparable,
    legalEffect: "not-determined" as const, beforeAssessedAt: left.assessedAt, afterAssessedAt: right.assessedAt,
    beforeValid: left.valid, afterValid: right.valid, changes, hasRegression: changes.some((item) => item.regression) };
}

/** Compare verifier issue identities and multiplicities, never raw exception text. */
export function compareCaseFindings(before: CaseAssessmentInput, after: CaseAssessmentInput) {
  const { left, right, comparable } = comparisonContext(before, after);
  const counts = (report: typeof left) => {
    const entries = new Map<string, { code: string; path: string; count: number }>();
    for (const item of report.findings) {
      const key = JSON.stringify([item.code, item.path]);
      entries.set(key, { code: item.code, path: item.path, count: (entries.get(key)?.count ?? 0) + 1 });
    }
    return entries;
  };
  const old = counts(left);
  const current = counts(right);
  const changes = comparable ? [...new Set([...old.keys(), ...current.keys()])].sort().flatMap((key) => {
    const previous = old.get(key);
    const next = current.get(key);
    const identity = next ?? previous;
    if (identity === undefined || previous?.count === next?.count) return [];
    return [{ code: identity.code, path: identity.path, beforeCount: previous?.count ?? 0, afterCount: next?.count ?? 0 }];
  }) : [];
  return { format: "MandateBoundFindingComparison/v1" as const, comparable,
    legalEffect: "not-determined" as const, beforeValid: left.valid, afterValid: right.valid,
    changes, hasRegression: changes.some((item) => item.afterCount > item.beforeCount),
    note: "New occurrences require review; disappearing findings do not establish source truth or closure." };
}

/** Context drift is shown explicitly and never silently treated as evidence improvement. */
export function compareCaseAnchorContext(before: CaseAssessmentInput, after: CaseAssessmentInput) {
  const { left, right } = comparisonContext(before, after);
  const old = anchorContext(before.anchors);
  const current = anchorContext(after.anchors);
  const changes = (Object.keys(old) as (keyof typeof old)[]).filter((key) => JSON.stringify(old[key]) !== JSON.stringify(current[key]));
  return { format: "MandateBoundAnchorComparison/v1" as const,
    sameCase: left.casePackId !== undefined && left.casePackId === right.casePackId,
    valid: left.valid && right.valid, legalEffect: "not-determined" as const,
    changed: changes.length > 0, changes, before: old, after: current,
    note: "Context changes require review. Supplied anchors are not authenticated by this comparison." };
}

/** Preserve reproducible assessment metadata without including evidence bodies. */
export function createAssessmentReceipt(input: CaseAssessmentInput) {
  const report = createCaseReport(input.casePack, input.anchors);
  const material = {
    format: "MandateBoundAssessmentReceipt/v1" as const,
    releaseVersion: RELEASE_VERSION, engineVersion: ENGINE_VERSION, protocolVersion: PROTOCOL_VERSION,
    caseInputDigest: sha256Bytes(canonicalBytes(input.casePack, { maxBytes: 4 * 1024 * 1024 })),
    anchorDigest: sha256Digest(anchorContext(input.anchors)), reportDigest: sha256Digest(report),
    valid: report.valid, legalEffect: "not-determined" as const,
    sourceTruth: "unknown" as const, globalCompleteness: "not-established" as const,
  };
  return { ...material, receiptDigest: sha256Digest(material) };
}
