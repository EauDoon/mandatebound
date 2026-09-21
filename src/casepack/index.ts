/**
 * Barrel re-export for the CasePack module. The exported surface here is
 * identical to the original src/casepack.ts so downstream consumers
 * (`from "./casepack.js"`, `from "@oonyl/mandatebound/casepack"`) see no change.
 */

export {
  CASEPACK_STATUSES,
  type CasePackStatus,
  type CasePackVerificationAnchors,
  type CasePackVerificationReport,
  type CoverageRequirementResult,
  type DelegationContext,
  type DelegationEvidenceReference,
  type DeterministicMappingTrace,
  type EnvelopeVerificationResult,
  type EvidenceCoverageContract,
  type EvidenceCoverageRequirement,
  type ExternalDiscoveryMaterial,
  type ExternalTrustKey,
  type ExternalTrustSnapshot,
  type MappedArtifactReference,
  type MandateBoundCasePack,
  type MappingTraceStep,
  type ProtocolEvidenceEnvelope,
  type RawEvidenceDescriptor,
  type RawEvidenceReference,
  type SourceCheckpoint,
  type SourceCheckpointGap,
  type SourceCheckpointInclusion,
  type SourceCheckpointProof,
  type SuppliedRawEvidence,
} from "./types.js";

export {
  sealDelegationContext,
  sealDeterministicMappingTrace,
  sealEvidenceCoverageContract,
  sealExternalTrustSnapshot,
  sealProtocolEvidenceEnvelope,
  sealSourceCheckpoint,
  createMandateBoundCasePack,
  createSourceCheckpointProof,
} from "./seal.js";

export {
  computeSourceEvidenceLeaf,
  verifyMandateBoundCasePack,
} from "./verify.js";
