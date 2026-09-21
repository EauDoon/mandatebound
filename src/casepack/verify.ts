import { Buffer } from "node:buffer";
import {
  createPublicKey,
  verify as nodeVerify,
  type JsonWebKeyInput,
} from "node:crypto";
import {
  canonicalBytes,
  digestBytes,
  isSha256Digest,
  sha256Bytes,
} from "../canonical.js";
import type {
  BundleVerificationReport,
  EvidenceBundle,
  Rfc3339Timestamp,
  Sha256Digest,
  ValidationIssue,
} from "../domain.js";
import {
  addIssue,
  CHECKPOINT_DOMAIN,
  exactKeys,
  isIdentifier,
  isPlainObject,
  isTimestamp,
  MAX_PROTOCOL_EVIDENCE,
  MAX_RAW_EVIDENCE_BYTES,
  MAX_TOTAL_RAW_EVIDENCE_BYTES,
  timestampMillis,
} from "./primitives.js";
import {
  validateCasePackShape,
} from "./validate.js";
import type {
  CasePackStatus,
  CasePackVerificationAnchors,
  CasePackVerificationReport,
  CoverageRequirementResult,
  DeterministicMappingTrace,
  EnvelopeVerificationResult,
  EvidenceCoverageRequirement,
  ExternalTrustSnapshot,
  MandateBoundCasePack,
  ProtocolEvidenceEnvelope,
  SourceCheckpoint,
  SuppliedRawEvidence,
} from "./types.js";

const STATUS_PRIORITY: Readonly<Record<CasePackStatus, number>> = Object.freeze({
  not_applicable: 0,
  satisfied: 1,
  unknown: 2,
  missing: 3,
  unsupported: 4,
  conflicting: 5,
});

function combineStatuses(values: readonly CasePackStatus[], empty: CasePackStatus): CasePackStatus {
  if (values.length === 0) return empty;
  return values.reduce((worst, candidate) =>
    STATUS_PRIORITY[candidate] > STATUS_PRIORITY[worst] ? candidate : worst);
}

function mappingStatus(mapping: DeterministicMappingTrace): CasePackStatus {
  const relevant = mapping.steps
    .map((step) => step.status)
    .filter((status) => status !== "not_applicable");
  return combineStatuses(relevant, "not_applicable");
}

function rawEvidenceMap(
  values: readonly SuppliedRawEvidence[] | undefined,
  issues: ValidationIssue[],
): ReadonlyMap<string, Uint8Array> {
  const result = new Map<string, Uint8Array>();
  if (values === undefined) return result;
  let totalBytes = 0;
  if (values.length > MAX_PROTOCOL_EVIDENCE + 256) {
    addIssue(issues, "$anchors.rawEvidence", "MBCP_LIMIT_EXCEEDED", "Supplied raw evidence count is invalid");
    return result;
  }
  for (const item of values) {
    if (
      !isPlainObject(item)
      || !exactKeys(item, ["referenceId", "bytes"])
      || !isIdentifier(item.referenceId)
      || !(item.bytes instanceof Uint8Array)
      || item.bytes.byteLength > MAX_RAW_EVIDENCE_BYTES
      || result.has(item.referenceId)
    ) {
      addIssue(issues, "$anchors.rawEvidence", "MBCP_RAW_EVIDENCE_INVALID", "Supplied raw evidence metadata is invalid");
      continue;
    }
    totalBytes += item.bytes.byteLength;
    if (totalBytes > MAX_TOTAL_RAW_EVIDENCE_BYTES) {
      addIssue(issues, "$anchors.rawEvidence", "MBCP_LIMIT_EXCEEDED", "Supplied raw evidence total byte limit exceeded");
      break;
    }
    result.set(item.referenceId, item.bytes);
  }
  return result;
}

function verifyMappedOutputs(
  envelope: ProtocolEvidenceEnvelope,
  bundle: EvidenceBundle,
  issues: ValidationIssue[],
): CasePackStatus {
  if (envelope.mapping.inputDigest !== envelope.rawEvidence.digest) {
    addIssue(issues, "$.protocolEvidence[].mapping.inputDigest", "MBCP_DIGEST_MISMATCH", "Mapping input digest does not match raw evidence");
    return "conflicting";
  }
  for (const output of envelope.mapping.outputArtifacts) {
    const entry = bundle.manifest.entries.find((candidate) => candidate.path === output.path);
    if (entry === undefined) {
      addIssue(issues, "$.protocolEvidence[].mapping.outputArtifacts", "MBCP_MAPPING_MISSING", "Mapped artifact is absent from the native bundle");
      return "missing";
    }
    if (entry.digest !== output.digest) {
      addIssue(issues, "$.protocolEvidence[].mapping.outputArtifacts", "MBCP_DIGEST_MISMATCH", "Mapped artifact digest conflicts with the native bundle");
      return "conflicting";
    }
  }
  return mappingStatus(envelope.mapping);
}

function verifyCheckpointProof(
  checkpoint: SourceCheckpoint,
  snapshot: ExternalTrustSnapshot | undefined,
  snapshotTrusted: boolean,
): CasePackStatus {
  if (checkpoint.proofs.length === 0) return "missing";
  if (snapshot === undefined) return "missing";
  if (!snapshotTrusted) return "unknown";
  const instant = timestampMillis(checkpoint.issuedAt);
  for (const proof of checkpoint.proofs) {
    const key = snapshot.keys.find((candidate) =>
      candidate.keyId === proof.keyId
      && candidate.sourceId === checkpoint.sourceId
      && candidate.purposes.includes("source_checkpoint"));
    if (key === undefined) continue;
    if (instant < timestampMillis(key.validFrom) || instant >= timestampMillis(key.validUntil)) continue;
    try {
      const publicKey = createPublicKey({
        key: key.publicJwk as unknown as JsonWebKeyInput["key"],
        format: "jwk",
      });
      const input = Buffer.concat([CHECKPOINT_DOMAIN, Buffer.from(digestBytes(checkpoint.checkpointDigest))]);
      const signature = Buffer.from(proof.signature, "base64url");
      if (nodeVerify(null, input, publicKey, signature)) return "satisfied";
    } catch {
      return "conflicting";
    }
  }
  return "conflicting";
}

function verifyCheckpointInclusion(
  envelope: ProtocolEvidenceEnvelope,
  checkpoint: SourceCheckpoint,
): CasePackStatus {
  const inclusion = envelope.checkpointInclusion;
  if (inclusion === undefined) return "missing";
  const capturedAt = timestampMillis(envelope.capturedAt);
  if (
    inclusion.checkpointId !== checkpoint.checkpointId
    || checkpoint.sourceId !== envelope.sourceId
    || capturedAt < timestampMillis(checkpoint.windowStart)
    || capturedAt > timestampMillis(checkpoint.windowEnd)
    || inclusion.treeSize !== checkpoint.eventCount
    || inclusion.leafIndex >= inclusion.treeSize
    || inclusion.sequence !== checkpoint.firstSequence + inclusion.leafIndex
    || inclusion.sequence > checkpoint.lastSequence
    || (inclusion.treeSize & (inclusion.treeSize - 1)) !== 0
    || inclusion.auditPath.length !== Math.log2(inclusion.treeSize)
  ) {
    return "conflicting";
  }
  let current = computeSourceEvidenceLeaf(envelope, inclusion.sequence);
  let index = inclusion.leafIndex;
  for (const sibling of inclusion.auditPath) {
    const left = index % 2 === 0 ? current : sibling;
    const right = index % 2 === 0 ? sibling : current;
    current = sha256Bytes(Buffer.concat([
      Buffer.from([1]),
      Buffer.from(digestBytes(left)),
      Buffer.from(digestBytes(right)),
    ]));
    index = Math.floor(index / 2);
  }
  return current === checkpoint.merkleRoot ? "satisfied" : "conflicting";
}

export function computeSourceEvidenceLeaf(
  envelope: Pick<ProtocolEvidenceEnvelope, "envelopeId" | "sourceId" | "rawEvidence">,
  sequence: number,
): Sha256Digest {
  if (!Number.isSafeInteger(sequence) || sequence < 0 || sequence > Number.MAX_SAFE_INTEGER) {
    throw new TypeError("Invalid source evidence sequence");
  }
  const material = canonicalBytes({
    envelopeId: envelope.envelopeId,
    sourceId: envelope.sourceId,
    sequence,
    rawDigest: envelope.rawEvidence.digest,
  });
  return sha256Bytes(Buffer.concat([Buffer.from([0]), Buffer.from(material)]));
}

function checkpointConflicts(checkpoints: readonly SourceCheckpoint[]): ReadonlySet<string> {
  const roots = new Map<string, string>();
  const conflictedSources = new Set<string>();
  for (const checkpoint of checkpoints) {
    const key = [
      checkpoint.sourceId,
      checkpoint.epoch,
      checkpoint.lastSequence,
      checkpoint.windowEnd,
    ].join("\0");
    const previous = roots.get(key);
    if (previous !== undefined && previous !== checkpoint.merkleRoot) {
      conflictedSources.add(checkpoint.sourceId);
    } else {
      roots.set(key, checkpoint.merkleRoot);
    }
  }
  return conflictedSources;
}

function verifyCheckpointForEnvelope(
  envelope: ProtocolEvidenceEnvelope,
  requirement: EvidenceCoverageRequirement,
  checkpoints: readonly SourceCheckpoint[],
  conflictedSources: ReadonlySet<string>,
  snapshot: ExternalTrustSnapshot | undefined,
  snapshotTrusted: boolean,
  asOf: Rfc3339Timestamp,
): CasePackStatus {
  if (requirement.checkpointRequirement === "not_applicable") return "not_applicable";
  if (conflictedSources.has(requirement.sourceId)) return "conflicting";
  const inclusion = envelope.checkpointInclusion;
  if (inclusion === undefined) return requirement.checkpointRequirement === "required" ? "missing" : "not_applicable";
  const checkpoint = checkpoints.find((candidate) => candidate.checkpointId === inclusion.checkpointId);
  if (checkpoint === undefined) return "missing";
  if (checkpoint.declaredGaps.length > 0) return "missing";
  const verificationTime = timestampMillis(asOf);
  const checkpointTime = timestampMillis(checkpoint.issuedAt);
  if (checkpointTime > verificationTime) return "missing";
  const maximumAge = requirement.maxCheckpointAgeSeconds;
  if (
    maximumAge !== undefined
    && verificationTime - checkpointTime > maximumAge * 1_000
  ) {
    return "missing";
  }
  const inclusionStatus = verifyCheckpointInclusion(envelope, checkpoint);
  if (inclusionStatus !== "satisfied") return inclusionStatus;
  const proofStatus = verifyCheckpointProof(checkpoint, snapshot, snapshotTrusted);
  if (requirement.checkpointRequirement === "optional" && proofStatus === "missing") return "satisfied";
  return proofStatus;
}

function genericInvalidReport(
  nativeBundle: BundleVerificationReport,
  issues: readonly ValidationIssue[],
): CasePackVerificationReport {
  return {
    valid: false,
    integrityStatus: "conflicting",
    coverageStatus: "unknown",
    sourceTruthStatus: "not_applicable",
    upstreamValidStatus: "unknown",
    evidenceEligibilityStatus: "missing",
    externalTrustStatus: "unknown",
    delegationStatus: "unknown",
    globalCompleteness: "not-established",
    nativeBundle,
    envelopes: [],
    requirements: [],
    issues,
  };
}

/**
 * Verifies a CasePack without I/O or network access. Source truth and global
 * completeness remain unestablished even when bounded coverage is satisfied.
 */
export function verifyMandateBoundCasePack(
  value: unknown,
  anchors: CasePackVerificationAnchors,
): CasePackVerificationReport {
  const issues: ValidationIssue[] = [];
  const shape = validateCasePackShape(value, issues);
  if (!shape.valid || shape.pack === undefined) return genericInvalidReport(shape.nativeBundle, issues);
  const pack = shape.pack;
  const rawEvidence = rawEvidenceMap(anchors.rawEvidence, issues);
  let integrityStatus: CasePackStatus = issues.length === 0 ? "satisfied" : "conflicting";

  const contract = pack.coverageContract;
  let coverageTrustStatus: CasePackStatus = "satisfied";
  if (
    !isTimestamp(anchors.asOf)
    || !isSha256Digest(anchors.coveragePolicyDigest)
    || !isSha256Digest(anchors.coverageContractDigest)
  ) {
    addIssue(issues, "$anchors", "MBCP_ANCHOR_INVALID", "Coverage verification anchors are invalid");
    coverageTrustStatus = "unknown";
  } else if (
    contract.contractDigest !== anchors.coverageContractDigest
    || contract.policyDigest !== anchors.coveragePolicyDigest
    || contract.nativeBundleRootDigest !== pack.nativeEvidenceBundle.rootDigest
  ) {
    addIssue(issues, "$.coverageContract", "MBCP_COVERAGE_PIN_MISMATCH", "Coverage contract does not match caller-owned pins");
    coverageTrustStatus = "conflicting";
  } else if (
    timestampMillis(anchors.asOf) < timestampMillis(contract.validFrom)
    || timestampMillis(anchors.asOf) >= timestampMillis(contract.validUntil)
  ) {
    addIssue(issues, "$.coverageContract", "MBCP_COVERAGE_EXPIRED", "Coverage contract is not valid at the verification instant");
    coverageTrustStatus = "missing";
  }

  let externalTrustStatus: CasePackStatus = "not_applicable";
  let snapshotTrusted = false;
  if (pack.externalTrustSnapshot !== undefined) {
    const snapshot = pack.externalTrustSnapshot;
    if (anchors.externalTrustSnapshotDigest === undefined) {
      externalTrustStatus = "unknown";
    } else if (snapshot.snapshotDigest !== anchors.externalTrustSnapshotDigest) {
      externalTrustStatus = "conflicting";
      addIssue(issues, "$.externalTrustSnapshot", "MBCP_EXTERNAL_TRUST_PIN_MISMATCH", "External trust snapshot does not match caller-owned pin");
    } else if (
      timestampMillis(anchors.asOf) < timestampMillis(snapshot.issuedAt)
      || timestampMillis(anchors.asOf) >= timestampMillis(snapshot.expiresAt)
    ) {
      externalTrustStatus = "missing";
      addIssue(issues, "$.externalTrustSnapshot", "MBCP_EXTERNAL_TRUST_STALE", "External trust snapshot is not current at the verification instant");
    } else {
      externalTrustStatus = "satisfied";
      snapshotTrusted = true;
    }
  }

  let delegationStatus: CasePackStatus = "satisfied";
  if (
    timestampMillis(anchors.asOf) < timestampMillis(pack.delegationContext.validFrom)
    || timestampMillis(anchors.asOf) >= timestampMillis(pack.delegationContext.validUntil)
  ) {
    delegationStatus = "missing";
    addIssue(issues, "$.delegationContext", "MBCP_DELEGATION_EXPIRED", "Delegation context is not current at the verification instant");
  }

  const envelopeBase = new Map<string, {
    integrity: CasePackStatus;
    mapping: CasePackStatus;
  }>();
  for (const envelope of pack.protocolEvidence) {
    const supplied = rawEvidence.get(envelope.rawEvidence.reference.referenceId);
    let rawStatus: CasePackStatus = "unknown";
    if (supplied !== undefined) {
      rawStatus = supplied.byteLength === envelope.rawEvidence.byteLength
        && sha256Bytes(supplied) === envelope.rawEvidence.digest
        ? "satisfied"
        : "conflicting";
      if (rawStatus === "conflicting") {
        addIssue(issues, "$.protocolEvidence[].rawEvidence", "MBCP_RAW_DIGEST_MISMATCH", "Supplied raw evidence does not match its committed bytes");
      }
    }
    const mapped = verifyMappedOutputs(envelope, pack.nativeEvidenceBundle, issues);
    envelopeBase.set(envelope.envelopeId, {
      integrity: combineStatuses([rawStatus, mapped], "unknown"),
      mapping: mapped,
    });
  }

  const conflictedSources = checkpointConflicts(pack.sourceCheckpoints);
  if (conflictedSources.size > 0) {
    addIssue(issues, "$.sourceCheckpoints", "MBCP_CHECKPOINT_EQUIVOCATION", "Source checkpoints contain conflicting commitments");
  }

  const requirementResults: CoverageRequirementResult[] = [];
  const requirementStatus = new Map<string, CasePackStatus>();
  for (const requirement of contract.requirements) {
    const matches = pack.protocolEvidence.filter((envelope) =>
      envelope.sourceId === requirement.sourceId
      && envelope.eventClass === requirement.eventClass
      && requirement.mediaTypes.includes(envelope.mediaType)
      && timestampMillis(envelope.capturedAt) >= timestampMillis(requirement.windowStart)
      && timestampMillis(envelope.capturedAt) <= timestampMillis(requirement.windowEnd));
    let status: CasePackStatus;
    if (coverageTrustStatus !== "satisfied") {
      status = coverageTrustStatus;
    } else if (conflictedSources.has(requirement.sourceId)) {
      status = "conflicting";
    } else if (matches.length < requirement.minEnvelopes) {
      status = "missing";
    } else {
      const statuses: CasePackStatus[] = [];
      for (const envelope of matches) {
        const base = envelopeBase.get(envelope.envelopeId);
        if (base !== undefined) statuses.push(base.integrity);
        if (!envelope.upstreamValid) statuses.push("missing");
        statuses.push(verifyCheckpointForEnvelope(
          envelope,
          requirement,
          pack.sourceCheckpoints,
          conflictedSources,
          pack.externalTrustSnapshot,
          snapshotTrusted,
          anchors.asOf,
        ));
      }
      status = combineStatuses(
        statuses.filter((candidate) => candidate !== "not_applicable"),
        "satisfied",
      );
    }
    requirementStatus.set(requirement.requirementId, status);
    requirementResults.push({
      requirementId: requirement.requirementId,
      status,
      matchedEnvelopes: matches.length,
    });
  }

  const coverageStatus = combineStatuses(
    [coverageTrustStatus, ...requirementResults.map((result) => result.status)]
      .filter((status) => status !== "not_applicable"),
    "unknown",
  );
  const envelopeResults: EnvelopeVerificationResult[] = pack.protocolEvidence.map((envelope) => {
    const matchingRequirements = contract.requirements.filter((requirement) =>
      requirement.sourceId === envelope.sourceId
      && requirement.eventClass === envelope.eventClass
      && requirement.mediaTypes.includes(envelope.mediaType)
      && timestampMillis(envelope.capturedAt) >= timestampMillis(requirement.windowStart)
      && timestampMillis(envelope.capturedAt) <= timestampMillis(requirement.windowEnd));
    const envelopeCoverage = matchingRequirements.length === 0
      ? "missing"
      : combineStatuses(
        matchingRequirements.map((requirement) => requirementStatus.get(requirement.requirementId) ?? "unknown"),
        "unknown",
      );
    const base = envelopeBase.get(envelope.envelopeId);
    const envelopeIntegrity = base?.integrity ?? "unknown";
    const evidenceEligible = envelopeIntegrity === "satisfied"
      && envelope.upstreamValid
      && envelopeCoverage === "satisfied"
      && delegationStatus === "satisfied";
    return {
      envelopeId: envelope.envelopeId,
      integrityStatus: envelopeIntegrity,
      coverageStatus: envelopeCoverage,
      sourceTruthStatus: "unknown",
      upstreamValid: envelope.upstreamValid,
      evidenceEligible,
    };
  });

  const envelopeIntegrityStatus = combineStatuses(
    envelopeResults.map((result) => result.integrityStatus),
    "unknown",
  );
  integrityStatus = combineStatuses([integrityStatus, envelopeIntegrityStatus], "unknown");
  const upstreamValidStatus = pack.protocolEvidence.every((envelope) => envelope.upstreamValid)
    ? "satisfied"
    : "missing";
  const evidenceEligibilityStatus = envelopeResults.every((result) => result.evidenceEligible)
    ? "satisfied"
    : "missing";
  const valid = integrityStatus === "satisfied"
    && coverageStatus === "satisfied"
    && upstreamValidStatus === "satisfied"
    && evidenceEligibilityStatus === "satisfied"
    && delegationStatus === "satisfied"
    && (externalTrustStatus === "satisfied" || externalTrustStatus === "not_applicable");

  return {
    valid,
    casePackId: pack.casePackId,
    casePackDigest: pack.casePackDigest,
    integrityStatus,
    coverageStatus,
    sourceTruthStatus: "unknown",
    upstreamValidStatus,
    evidenceEligibilityStatus,
    externalTrustStatus,
    delegationStatus,
    globalCompleteness: "not-established",
    nativeBundle: shape.nativeBundle,
    envelopes: envelopeResults,
    requirements: requirementResults,
    issues,
  };
}
