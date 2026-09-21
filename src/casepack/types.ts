import type {
  AsciiIdentifier,
  BundleVerificationReport,
  Ed25519PublicJwk,
  EvidenceBundle,
  Rfc3339Timestamp,
  Sha256Digest,
  ValidationIssue,
} from "../domain.js";

export const CASEPACK_STATUSES = [
  "satisfied",
  "missing",
  "conflicting",
  "unsupported",
  "unknown",
  "not_applicable",
] as const;

export type CasePackStatus = (typeof CASEPACK_STATUSES)[number];

export interface RawEvidenceReference {
  readonly referenceId: AsciiIdentifier;
  readonly kind: "bundle_path" | "content_addressed";
  readonly value: string;
}

export interface RawEvidenceDescriptor {
  readonly digest: Sha256Digest;
  readonly byteLength: number;
  readonly reference: RawEvidenceReference;
}

export interface MappedArtifactReference {
  readonly path: string;
  readonly digest: Sha256Digest;
}

export interface MappingTraceStep {
  readonly index: number;
  readonly ruleId: AsciiIdentifier;
  readonly inputPointer: string;
  readonly outputPointer: string;
  readonly status: CasePackStatus;
}

export interface DeterministicMappingTrace {
  readonly mapperId: AsciiIdentifier;
  readonly mapperVersion: string;
  readonly mappingPolicyDigest: Sha256Digest;
  readonly inputDigest: Sha256Digest;
  readonly outputArtifacts: readonly MappedArtifactReference[];
  readonly steps: readonly MappingTraceStep[];
  readonly traceDigest: Sha256Digest;
}

export interface SourceCheckpointInclusion {
  readonly checkpointId: AsciiIdentifier;
  readonly sequence: number;
  readonly leafIndex: number;
  readonly treeSize: number;
  readonly auditPath: readonly Sha256Digest[];
}

export interface ProtocolEvidenceEnvelope {
  readonly format: "MandateBoundProtocolEvidenceEnvelope/v1";
  readonly envelopeId: AsciiIdentifier;
  readonly sourceId: AsciiIdentifier;
  readonly eventClass: AsciiIdentifier;
  readonly capturedAt: Rfc3339Timestamp;
  readonly mediaType: string;
  readonly rawEvidence: RawEvidenceDescriptor;
  readonly upstreamValid: boolean;
  readonly mapping: DeterministicMappingTrace;
  readonly checkpointInclusion?: SourceCheckpointInclusion;
  readonly envelopeDigest: Sha256Digest;
}

export interface ExternalDiscoveryMaterial {
  readonly materialId: AsciiIdentifier;
  readonly mediaType: string;
  readonly rawEvidence: RawEvidenceDescriptor;
}

export interface ExternalTrustKey {
  readonly keyId: AsciiIdentifier;
  readonly sourceId: AsciiIdentifier;
  readonly publicJwk: Ed25519PublicJwk;
  readonly purposes: readonly ["source_checkpoint"];
  readonly validFrom: Rfc3339Timestamp;
  readonly validUntil: Rfc3339Timestamp;
}

export interface ExternalTrustSnapshot {
  readonly format: "MandateBoundExternalTrustSnapshot/v1";
  readonly snapshotId: AsciiIdentifier;
  readonly issuedAt: Rfc3339Timestamp;
  readonly expiresAt: Rfc3339Timestamp;
  readonly trustEffect: "discovery_only";
  readonly nativeTrustPromotion: "forbidden";
  readonly discoveryMaterials: readonly ExternalDiscoveryMaterial[];
  readonly keys: readonly ExternalTrustKey[];
  readonly snapshotDigest: Sha256Digest;
}

export interface DelegationEvidenceReference {
  readonly digest: Sha256Digest;
  readonly reference: RawEvidenceReference;
}

export interface DelegationContext {
  readonly format: "MandateBoundDelegationContext/v1";
  readonly delegationId: AsciiIdentifier;
  readonly principalId: AsciiIdentifier;
  readonly delegateId: AsciiIdentifier;
  readonly mandateDigest: Sha256Digest;
  readonly scopeDigest: Sha256Digest;
  readonly validFrom: Rfc3339Timestamp;
  readonly validUntil: Rfc3339Timestamp;
  readonly evidenceReferences: readonly DelegationEvidenceReference[];
  readonly legalEffect: "not-determined";
  readonly contextDigest: Sha256Digest;
}

export interface EvidenceCoverageRequirement {
  readonly requirementId: AsciiIdentifier;
  readonly sourceId: AsciiIdentifier;
  readonly eventClass: AsciiIdentifier;
  readonly mediaTypes: readonly string[];
  readonly windowStart: Rfc3339Timestamp;
  readonly windowEnd: Rfc3339Timestamp;
  readonly minEnvelopes: number;
  readonly checkpointRequirement: "required" | "optional" | "not_applicable";
  readonly maxCheckpointAgeSeconds?: number;
}

export interface EvidenceCoverageContract {
  readonly format: "MandateBoundEvidenceCoverageContract/v1";
  readonly contractId: AsciiIdentifier;
  readonly issuedAt: Rfc3339Timestamp;
  readonly validFrom: Rfc3339Timestamp;
  readonly validUntil: Rfc3339Timestamp;
  readonly coverageScope: "declared_sources_and_windows_only";
  readonly policyDigest: Sha256Digest;
  readonly nativeBundleRootDigest: Sha256Digest;
  readonly requirements: readonly EvidenceCoverageRequirement[];
  readonly contractDigest: Sha256Digest;
}

export interface SourceCheckpointGap {
  readonly fromSequence: number;
  readonly toSequence: number;
  readonly reasonCode: AsciiIdentifier;
}

export interface SourceCheckpointProof {
  readonly suite: "Ed25519";
  readonly keyId: AsciiIdentifier;
  readonly signedDigest: Sha256Digest;
  readonly signature: string;
}

export interface SourceCheckpoint {
  readonly format: "MandateBoundSourceCheckpoint/v1";
  readonly checkpointId: AsciiIdentifier;
  readonly sourceId: AsciiIdentifier;
  readonly epoch: AsciiIdentifier;
  readonly issuedAt: Rfc3339Timestamp;
  readonly windowStart: Rfc3339Timestamp;
  readonly windowEnd: Rfc3339Timestamp;
  readonly firstSequence: number;
  readonly lastSequence: number;
  readonly eventCount: number;
  readonly merkleRoot: Sha256Digest;
  readonly previousCheckpointDigest?: Sha256Digest;
  readonly declaredGaps: readonly SourceCheckpointGap[];
  readonly checkpointDigest: Sha256Digest;
  readonly proofs: readonly SourceCheckpointProof[];
}

export interface MandateBoundCasePack {
  readonly format: "MandateBoundCasePack/v1";
  readonly casePackId: AsciiIdentifier;
  readonly createdAt: Rfc3339Timestamp;
  readonly nativeEvidenceBundle: EvidenceBundle;
  readonly protocolEvidence: readonly ProtocolEvidenceEnvelope[];
  readonly externalTrustSnapshot?: ExternalTrustSnapshot;
  readonly delegationContext: DelegationContext;
  readonly coverageContract: EvidenceCoverageContract;
  readonly sourceCheckpoints: readonly SourceCheckpoint[];
  readonly casePackDigest: Sha256Digest;
}

export interface SuppliedRawEvidence {
  readonly referenceId: AsciiIdentifier;
  readonly bytes: Uint8Array;
}

export interface CasePackVerificationAnchors {
  readonly asOf: Rfc3339Timestamp;
  readonly coveragePolicyDigest: Sha256Digest;
  readonly coverageContractDigest: Sha256Digest;
  readonly externalTrustSnapshotDigest?: Sha256Digest;
  readonly rawEvidence?: readonly SuppliedRawEvidence[];
}

export interface EnvelopeVerificationResult {
  readonly envelopeId: AsciiIdentifier;
  readonly integrityStatus: CasePackStatus;
  readonly coverageStatus: CasePackStatus;
  readonly sourceTruthStatus: "unknown";
  readonly upstreamValid: boolean;
  readonly evidenceEligible: boolean;
}

export interface CoverageRequirementResult {
  readonly requirementId: AsciiIdentifier;
  readonly status: CasePackStatus;
  readonly matchedEnvelopes: number;
}

export interface CasePackVerificationReport {
  readonly valid: boolean;
  readonly casePackId?: AsciiIdentifier;
  readonly casePackDigest?: Sha256Digest;
  readonly integrityStatus: CasePackStatus;
  readonly coverageStatus: CasePackStatus;
  readonly sourceTruthStatus: "unknown" | "not_applicable";
  readonly upstreamValidStatus: CasePackStatus;
  readonly evidenceEligibilityStatus: CasePackStatus;
  readonly externalTrustStatus: CasePackStatus;
  readonly delegationStatus: CasePackStatus;
  readonly globalCompleteness: "not-established";
  readonly nativeBundle: BundleVerificationReport;
  readonly envelopes: readonly EnvelopeVerificationResult[];
  readonly requirements: readonly CoverageRequirementResult[];
  readonly issues: readonly ValidationIssue[];
}
