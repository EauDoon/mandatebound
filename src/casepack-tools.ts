import type {
  CasePackStatus,
  CasePackVerificationAnchors,
  CasePackVerificationReport,
  MandateBoundCasePack,
} from "./casepack.js";
import { CASEPACK_STATUSES, verifyMandateBoundCasePack } from "./casepack.js";
import type { Sha256Digest } from "./domain.js";

export interface CasePackArtifactChange {
  readonly kind: "protocol_evidence" | "source_checkpoint";
  readonly id: string;
  readonly change: "added" | "removed" | "modified";
  readonly beforeDigest?: Sha256Digest;
  readonly afterDigest?: Sha256Digest;
}

export interface CasePackDiffReport {
  readonly comparable: boolean;
  readonly changed: boolean;
  readonly beforeDigest?: Sha256Digest;
  readonly afterDigest?: Sha256Digest;
  readonly nativeBundleChanged: boolean;
  readonly coverageContractChanged: boolean;
  readonly delegationContextChanged: boolean;
  readonly externalTrustSnapshotChanged: boolean;
  readonly statusChanged: boolean;
  readonly artifacts: readonly CasePackArtifactChange[];
  readonly beforeVerification: CasePackVerificationReport;
  readonly afterVerification: CasePackVerificationReport;
}

export interface UnpackedCasePack {
  readonly casePackId: string;
  readonly casePackDigest: Sha256Digest;
  readonly nativeEvidenceBundle: MandateBoundCasePack["nativeEvidenceBundle"];
  readonly protocolEvidence: MandateBoundCasePack["protocolEvidence"];
  readonly externalTrustSnapshot?: MandateBoundCasePack["externalTrustSnapshot"];
  readonly delegationContext: MandateBoundCasePack["delegationContext"];
  readonly coverageContract: MandateBoundCasePack["coverageContract"];
  readonly sourceCheckpoints: MandateBoundCasePack["sourceCheckpoints"];
}

export interface CasePackUnpackResult {
  readonly unpacked: boolean;
  readonly verification: CasePackVerificationReport;
  readonly contents?: UnpackedCasePack;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function comparablePack(
  value: unknown,
  report: CasePackVerificationReport,
): value is MandateBoundCasePack {
  return isRecord(value)
    && report.integrityStatus === "satisfied"
    && report.casePackId !== undefined
    && report.casePackDigest !== undefined;
}

function changedStatus(
  before: CasePackVerificationReport,
  after: CasePackVerificationReport,
): boolean {
  const fields: readonly (keyof CasePackVerificationReport)[] = [
    "valid",
    "integrityStatus",
    "coverageStatus",
    "sourceTruthStatus",
    "upstreamValidStatus",
    "evidenceEligibilityStatus",
    "externalTrustStatus",
    "delegationStatus",
  ];
  return fields.some((field) => before[field] !== after[field]);
}

function collectChanges(
  kind: CasePackArtifactChange["kind"],
  before: ReadonlyMap<string, Sha256Digest>,
  after: ReadonlyMap<string, Sha256Digest>,
): readonly CasePackArtifactChange[] {
  const changes: CasePackArtifactChange[] = [];
  const ids = [...new Set([...before.keys(), ...after.keys()])].sort();
  for (const id of ids) {
    const previous = before.get(id);
    const next = after.get(id);
    if (previous === undefined && next !== undefined) {
      changes.push({ kind, id, change: "added", afterDigest: next });
    } else if (previous !== undefined && next === undefined) {
      changes.push({ kind, id, change: "removed", beforeDigest: previous });
    } else if (previous !== next && previous !== undefined && next !== undefined) {
      changes.push({
        kind,
        id,
        change: "modified",
        beforeDigest: previous,
        afterDigest: next,
      });
    }
  }
  return changes;
}

function statusRank(status: CasePackStatus): number {
  const rank = ["satisfied", "not_applicable", "unknown", "unsupported", "missing", "conflicting"]
    .indexOf(status);
  if (!CASEPACK_STATUSES.includes(status) || rank < 0) {
    throw new TypeError("Unknown CasePack status");
  }
  return rank;
}

export function diffMandateBoundCasePacks(
  beforeValue: unknown,
  beforeAnchors: CasePackVerificationAnchors,
  afterValue: unknown,
  afterAnchors: CasePackVerificationAnchors,
): CasePackDiffReport {
  const beforeVerification = verifyMandateBoundCasePack(beforeValue, beforeAnchors);
  const afterVerification = verifyMandateBoundCasePack(afterValue, afterAnchors);
  if (
    !comparablePack(beforeValue, beforeVerification)
    || !comparablePack(afterValue, afterVerification)
  ) {
    return {
      comparable: false,
      changed: false,
      nativeBundleChanged: false,
      coverageContractChanged: false,
      delegationContextChanged: false,
      externalTrustSnapshotChanged: false,
      statusChanged: changedStatus(beforeVerification, afterVerification),
      artifacts: [],
      beforeVerification,
      afterVerification,
    };
  }

  const beforeEnvelopes = new Map(
    beforeValue.protocolEvidence.map((item) => [item.envelopeId, item.envelopeDigest]),
  );
  const afterEnvelopes = new Map(
    afterValue.protocolEvidence.map((item) => [item.envelopeId, item.envelopeDigest]),
  );
  const beforeCheckpoints = new Map(
    beforeValue.sourceCheckpoints.map((item) => [item.checkpointId, item.checkpointDigest]),
  );
  const afterCheckpoints = new Map(
    afterValue.sourceCheckpoints.map((item) => [item.checkpointId, item.checkpointDigest]),
  );
  const artifacts = [
    ...collectChanges("protocol_evidence", beforeEnvelopes, afterEnvelopes),
    ...collectChanges("source_checkpoint", beforeCheckpoints, afterCheckpoints),
  ];
  const beforeExternal = beforeValue.externalTrustSnapshot?.snapshotDigest;
  const afterExternal = afterValue.externalTrustSnapshot?.snapshotDigest;
  const statusChanged = changedStatus(beforeVerification, afterVerification);
  const changed = beforeValue.casePackDigest !== afterValue.casePackDigest;
  return {
    comparable: true,
    changed,
    beforeDigest: beforeValue.casePackDigest,
    afterDigest: afterValue.casePackDigest,
    nativeBundleChanged:
      beforeValue.nativeEvidenceBundle.rootDigest !== afterValue.nativeEvidenceBundle.rootDigest,
    coverageContractChanged:
      beforeValue.coverageContract.contractDigest !== afterValue.coverageContract.contractDigest,
    delegationContextChanged:
      beforeValue.delegationContext.contextDigest !== afterValue.delegationContext.contextDigest,
    externalTrustSnapshotChanged: beforeExternal !== afterExternal,
    statusChanged,
    artifacts,
    beforeVerification,
    afterVerification,
  };
}

export function unpackMandateBoundCasePack(
  value: unknown,
  anchors: CasePackVerificationAnchors,
): CasePackUnpackResult {
  const verification = verifyMandateBoundCasePack(value, anchors);
  if (!comparablePack(value, verification)) {
    return { unpacked: false, verification };
  }
  return {
    unpacked: true,
    verification,
    contents: {
      casePackId: value.casePackId,
      casePackDigest: value.casePackDigest,
      nativeEvidenceBundle: value.nativeEvidenceBundle,
      protocolEvidence: value.protocolEvidence,
      ...(value.externalTrustSnapshot === undefined
        ? {}
        : { externalTrustSnapshot: value.externalTrustSnapshot }),
      delegationContext: value.delegationContext,
      coverageContract: value.coverageContract,
      sourceCheckpoints: value.sourceCheckpoints,
    },
  };
}

export function compareCasePackStatus(left: CasePackStatus, right: CasePackStatus): number {
  return statusRank(left) - statusRank(right);
}
