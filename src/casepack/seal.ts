import {
  createPrivateKey,
  type KeyObject,
  sign as nodeSign,
} from "node:crypto";
import {
  digestBytes,
  isSha256Digest,
} from "../canonical.js";
import type {
  AsciiIdentifier,
} from "../domain.js";
import {
  CHECKPOINT_DOMAIN,
  casePackMaterial,
  delegationMaterial,
  digestCanonical,
  envelopeMaterial,
  externalTrustMaterial,
  coverageMaterial,
  checkpointMaterial,
  isIdentifier,
  mappingMaterial,
  withoutProperty,
} from "./primitives.js";
import type {
  DelegationContext,
  DeterministicMappingTrace,
  EvidenceCoverageContract,
  ExternalTrustSnapshot,
  MandateBoundCasePack,
  ProtocolEvidenceEnvelope,
  SourceCheckpoint,
  SourceCheckpointProof,
} from "./types.js";

export function sealDeterministicMappingTrace(
  value: Omit<DeterministicMappingTrace, "traceDigest">,
): DeterministicMappingTrace {
  const material = withoutProperty(
    value as Omit<DeterministicMappingTrace, "traceDigest"> & Partial<Pick<DeterministicMappingTrace, "traceDigest">>,
    "traceDigest",
  );
  return { ...material, traceDigest: digestCanonical(mappingMaterial(material)) };
}

export function sealProtocolEvidenceEnvelope(
  value: Omit<ProtocolEvidenceEnvelope, "envelopeDigest">,
): ProtocolEvidenceEnvelope {
  const material = withoutProperty(
    value as Omit<ProtocolEvidenceEnvelope, "envelopeDigest"> & Partial<Pick<ProtocolEvidenceEnvelope, "envelopeDigest">>,
    "envelopeDigest",
  );
  return { ...material, envelopeDigest: digestCanonical(envelopeMaterial(material)) };
}

export function sealExternalTrustSnapshot(
  value: Omit<ExternalTrustSnapshot, "snapshotDigest">,
): ExternalTrustSnapshot {
  const material = withoutProperty(
    value as Omit<ExternalTrustSnapshot, "snapshotDigest"> & Partial<Pick<ExternalTrustSnapshot, "snapshotDigest">>,
    "snapshotDigest",
  );
  return { ...material, snapshotDigest: digestCanonical(externalTrustMaterial(material)) };
}

export function sealDelegationContext(
  value: Omit<DelegationContext, "contextDigest">,
): DelegationContext {
  const material = withoutProperty(
    value as Omit<DelegationContext, "contextDigest"> & Partial<Pick<DelegationContext, "contextDigest">>,
    "contextDigest",
  );
  return { ...material, contextDigest: digestCanonical(delegationMaterial(material)) };
}

export function sealEvidenceCoverageContract(
  value: Omit<EvidenceCoverageContract, "contractDigest">,
): EvidenceCoverageContract {
  const material = withoutProperty(
    value as Omit<EvidenceCoverageContract, "contractDigest"> & Partial<Pick<EvidenceCoverageContract, "contractDigest">>,
    "contractDigest",
  );
  return { ...material, contractDigest: digestCanonical(coverageMaterial(material)) };
}

export function sealSourceCheckpoint(
  value: Omit<SourceCheckpoint, "checkpointDigest" | "proofs"> & {
    readonly proofs?: readonly SourceCheckpointProof[];
  },
): SourceCheckpoint {
  const {
    proofs = [],
    format,
    checkpointId,
    sourceId,
    epoch,
    issuedAt,
    windowStart,
    windowEnd,
    firstSequence,
    lastSequence,
    eventCount,
    merkleRoot,
    previousCheckpointDigest,
    declaredGaps,
  } = value;
  const unsigned = {
    format,
    checkpointId,
    sourceId,
    epoch,
    issuedAt,
    windowStart,
    windowEnd,
    firstSequence,
    lastSequence,
    eventCount,
    merkleRoot,
    ...(previousCheckpointDigest === undefined ? {} : { previousCheckpointDigest }),
    declaredGaps,
  };
  return {
    ...unsigned,
    checkpointDigest: digestCanonical(checkpointMaterial(unsigned)),
    proofs,
  };
}

export function createSourceCheckpointProof(
  checkpoint: SourceCheckpoint,
  privateKeyInput: KeyObject | string | Buffer,
  keyId: AsciiIdentifier,
): SourceCheckpointProof {
  if (!isIdentifier(keyId) || !isSha256Digest(checkpoint.checkpointDigest)) {
    throw new TypeError("Invalid source checkpoint proof binding");
  }
  const privateKey = typeof privateKeyInput === "string" || Buffer.isBuffer(privateKeyInput)
    ? createPrivateKey(privateKeyInput)
    : privateKeyInput;
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("An Ed25519 private key is required");
  }
  const input = Buffer.concat([CHECKPOINT_DOMAIN, Buffer.from(digestBytes(checkpoint.checkpointDigest))]);
  return {
    suite: "Ed25519",
    keyId,
    signedDigest: checkpoint.checkpointDigest,
    signature: nodeSign(null, input, privateKey).toString("base64url"),
  };
}

export function createMandateBoundCasePack(
  value: Omit<MandateBoundCasePack, "casePackDigest">,
): MandateBoundCasePack {
  const material = withoutProperty(
    value as Omit<MandateBoundCasePack, "casePackDigest"> & Partial<Pick<MandateBoundCasePack, "casePackDigest">>,
    "casePackDigest",
  );
  return { ...material, casePackDigest: digestCanonical(casePackMaterial(material)) };
}
